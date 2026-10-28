"""Generic, declarative probes used by the module registry.

The registry does not contain one Python file per website.  A module says
*what kind of probe* it needs and supplies a small declarative payload:

``json_api_probe``
    GET a JSON endpoint, select a list with ``items_path`` and map fields.
``http_profile_probe``
    GET a public profile page and parse title/OpenGraph metadata.
``html_search_probe``
    GET a public search page and extract result anchors.  Always fragile.
``oembed_probe``
    GET a public oEmbed endpoint and normalise the JSON.
``adapter_probe``
    Delegate to an existing keyless adapter (identity/social/searchx).
``link_out``
    Never execute automatically; build a public link for the analyst.

Every probe returns the same envelope::

    {"status": "ok|empty|blocked|not_found|error|link_out",
     "http": 200, "url": "...", "results": [...], "error": "..."}

Only ``ok`` results are usable as automatic evidence.  Scraped HTTP/HTML
results are marked fragile by the registry.
"""
from __future__ import annotations

import html as _html
import ipaddress
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import requests

UA = {
    "User-Agent": "Xaxglog-OSINT/2.0 (+public-source research; contact operator)",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
}
T = 12
MAX_BYTES = 1_500_000

BLOCK_MARKERS = (
    "captcha", "recaptcha", "hcaptcha", "are you a robot", "verify you are human",
    "verifying your browser", "unusual traffic", "just a moment", "cf-chl",
    "challenge-platform", "attention required", "access denied", "request blocked",
    "bot detection", "too many requests", "rate limit exceeded", "login required",
    "sign in to continue", "enable javascript and cookies",
)
NOT_FOUND_MARKERS = (
    "page not found", "user not found", "profile not found", "account not found",
    "doesn't exist", "does not exist", "no such user", "404 not found",
    "this page isn't available", "this account doesn't exist",
)
PRIVATE_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"}
FORBIDDEN_SCRAPE_HOSTS = {
    "google.com", "www.google.com", "bing.com", "www.bing.com",
    "googleusercontent.com",
}


def _forbidden_engine_host(host):
    host = (host or "").lower().strip(".")
    labels = host.split(".") if host else []
    return ("google" in labels or "bing" in labels
            or host.endswith(".googleusercontent.com"))
PROBE_TYPES = (
    "json_api_probe", "http_profile_probe", "html_search_probe",
    "oembed_probe", "adapter_probe", "link_out",
)


# ------------------------------------------------------------------ helpers
def _clean(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = " ".join(_clean(x) for x in value if x is not None)
    elif isinstance(value, dict):
        preferred = _first(value, ["name", "title", "family", "given",
                                   "display_name", "description", "value"])
        if preferred not in (None, "", [], {}):
            value = _clean(preferred)
        else:
            value = " ".join(_clean(x) for x in value.values() if x is not None)
    value = re.sub(r"<[^>]+>", " ", str(value))
    value = _html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def _quote(value):
    return urllib.parse.quote(str(value or ""), safe="")


def _handle(query):
    q = (query or "").strip()
    if not q:
        return ""
    if re.match(r"^[A-Za-z0-9_.\-]{1,80}$", q) and " " not in q:
        return q
    try:
        from modules.identity import identity as ID
        variants = ID.handle_variants(q)
        if variants:
            return variants[0]
    except Exception:
        pass
    return re.sub(r"[^A-Za-z0-9_.\-]+", "", q)[:80] or "user"


def _render(template, query="", extra=None):
    values = {"q": _quote(query), "u": _quote(_handle(query)),
              "query": _quote(query), "handle": _quote(_handle(query))}
    if extra:
        for key, val in extra.items():
            values[key] = _quote(val)
    out = str(template or "")
    for key, val in values.items():
        out = out.replace("{" + key + "}", val)
    return out


def _safe_url(url):
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return False, "invalid URL"
    if p.scheme not in ("http", "https"):
        return False, "only http(s) URLs are allowed"
    host = (p.hostname or "").lower()
    if not host:
        return False, "URL has no host"
    if host in PRIVATE_HOSTS or host.endswith(".local"):
        return False, "private/loopback host blocked"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, "private IP blocked"
    except ValueError:
        # Hostname: resolve and reject if every answer is private.  This is
        # cheap enough for an explicit probe and prevents SSRF via DNS.
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = {i[4][0] for i in infos if i and i[4]}
            if addrs and all(_is_private_ip(a) for a in addrs):
                return False, "host resolves only to private addresses"
        except OSError:
            pass
    return True, ""


def _is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def fetch(url, *, timeout=T, headers=None, max_bytes=MAX_BYTES):
    """Fetch a bounded public response and classify obvious walls.

    Returns a dict so probes never need to reason about requests exceptions.
    """
    ok, why = _safe_url(url)
    if not ok:
        return {"status": "error", "error": why, "url": url, "http": None}
    hdrs = dict(UA)
    hdrs.update(headers or {})
    try:
        r = requests.get(url, headers=hdrs, timeout=timeout, stream=True,
                         allow_redirects=True)
        chunks, size = [], 0
        for chunk in r.iter_content(16384):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= max_bytes:
                break
        raw = b"".join(chunks)
        text = raw.decode("utf-8", errors="replace")
        out = {
            "status": "ok",
            "http": r.status_code,
            "url": r.url or url,
            "text": text,
            "headers": dict(r.headers),
            "bytes": size,
        }
        return _classify(out)
    except Exception as e:
        return {"status": "error", "error": str(e)[:240], "url": url,
                "http": None}


def _classify(resp):
    code = resp.get("http")
    text = (resp.get("text") or "")[:20000]
    low = text.lower()
    if code in (401, 403, 407, 429, 451, 503):
        resp.update(status="blocked", error=f"HTTP {code} (blocked/rate-limited)")
        return resp
    if code == 404:
        resp.update(status="not_found", error="HTTP 404")
        return resp
    if code is None or code >= 500:
        resp.update(status="error", error=f"HTTP {code}")
        return resp
    if code >= 400:
        resp.update(status="error", error=f"HTTP {code}")
        return resp
    if any(marker in low for marker in BLOCK_MARKERS):
        resp.update(status="blocked", error="anti-bot/login wall marker in response")
        return resp
    return resp


def _pick(obj, path):
    """Read a dotted path (``data.items``) or a list of candidate paths."""
    if path is None or path == "":
        return obj
    if isinstance(path, (list, tuple)):
        for item in path:
            value = _pick(obj, item)
            if value not in (None, "", [], {}):
                return value
        return None
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, (list, tuple)):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _first(obj, names):
    for name in names:
        value = _pick(obj, name)
        if value not in (None, "", [], {}):
            return value
    return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return [value]
    return []


def _norm_row(row, *, source="", label="", category="", module_id="",
              fields=None, result_url="", fallback_name=""):
    fields = fields or {}
    name = _first(row, [fields.get("name"), "name", "title", "label",
                        "display_name", "login", "username", "author",
                        "owner", "full_name"])
    url = _first(row, [fields.get("url"), "url", "html_url", "profile_url",
                       "link", "permalink", "web_url"])
    snippet = _first(row, [fields.get("snippet"), "snippet", "description",
                           "detail", "summary", "text", "selftext"])
    author = _first(row, [fields.get("author"), "author", "owner", "username",
                          "login", "user"])
    date = _first(row, [fields.get("date"), "date", "published", "created_at",
                        "indexedAt", "first_seen", "updated_at"])
    rid = _first(row, [fields.get("id"), "id", "uuid", "key", "uri"])
    name = _clean(name) or _clean(fallback_name)
    url = _clean(url)
    if not url and result_url:
        extra = {k: _clean(v) for k, v in (row or {}).items() if isinstance(v, (str, int, float))}
        extra.update({"name": name, "title": name, "id": rid, "author": author})
        url = _render(result_url, extra=extra)
    if not url and isinstance(row, str) and row.startswith("http"):
        url = row
    if not name and not url:
        return None
    return {
        "source": source,
        "module_id": module_id,
        "source_label": label,
        "category": category,
        "title": name or url,
        "name": name,
        "url": url,
        "snippet": _clean(snippet),
        "author": _clean(author),
        "date": _clean(date),
        "id": _clean(rid),
    }


# ------------------------------------------------------------------ probes
def json_api_probe(probe, query, *, timeout=T):
    url = _render(probe.get("url"), query)
    resp = fetch(url, timeout=timeout, headers=probe.get("headers"))
    if resp.get("status") != "ok":
        return _probe_failure(resp)
    try:
        import json
        data = json.loads(resp.get("text") or "null")
    except Exception as e:
        return {"status": "error", "error": f"invalid JSON: {e}"[:240],
                "http": resp.get("http"), "url": url, "results": []}
    items = _as_list(_pick(data, probe.get("items_path")))
    rows = []
    for item in items[:int(probe.get("limit") or 20)]:
        row = _norm_row(
            item, source=probe.get("source", ""), label=probe.get("label", ""),
            category=probe.get("category", ""), module_id=probe.get("module_id", ""),
            fields=probe.get("fields"), result_url=probe.get("result_url", ""),
            fallback_name=query)
        if row:
            rows.append(row)
    return {"status": "ok" if rows else "empty", "http": resp.get("http"),
            "url": url, "results": rows, "count": len(rows)}


def http_profile_probe(probe, query, *, timeout=T):
    url = _render(probe.get("url"), query)
    resp = fetch(url, timeout=timeout, headers=probe.get("headers"))
    if resp.get("status") != "ok":
        return _probe_failure(resp)
    text = resp.get("text") or ""
    low = text.lower()
    if any(marker in low for marker in NOT_FOUND_MARKERS):
        return {"status": "not_found", "http": resp.get("http"), "url": url,
                "error": "not-found marker in profile page", "results": []}
    title = _meta(text, "og:title") or _title(text)
    desc = (_meta(text, "og:description") or _meta(text, "description")
            or _meta(text, "twitter:description"))
    image = _meta(text, "og:image") or _meta(text, "twitter:image")
    canonical = _canonical(text) or resp.get("url") or url
    if not title and not desc:
        return {"status": "empty", "http": resp.get("http"), "url": url,
                "error": "200 but no parseable profile metadata", "results": []}
    row = {
        "source": probe.get("source", ""),
        "module_id": probe.get("module_id", ""),
        "source_label": probe.get("label", ""),
        "category": probe.get("category", ""),
        "title": _clean(title) or _clean(desc) or url,
        "name": _clean(title) or query,
        "url": canonical,
        "snippet": _clean(desc),
        "image": image,
        "fragile": True,
    }
    return {"status": "ok", "http": resp.get("http"), "url": canonical,
            "results": [row], "count": 1}


def html_search_probe(probe, query, *, timeout=T):
    url = _render(probe.get("url"), query)
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if _forbidden_engine_host(host):
        return {"status": "blocked", "url": url, "http": None,
                "error": "result-page scraping for this engine is disabled; use its official API or link-out",
                "results": []}
    resp = fetch(url, timeout=timeout, headers=probe.get("headers"))
    if resp.get("status") != "ok":
        return _probe_failure(resp)
    rows = _extract_links(resp.get("text") or "", resp.get("url") or url,
                          probe, query)
    return {"status": "ok" if rows else "empty", "http": resp.get("http"),
            "url": url, "results": rows, "count": len(rows)}


def oembed_probe(probe, query, *, timeout=T):
    url = _render(probe.get("url"), query)
    resp = fetch(url, timeout=timeout, headers=probe.get("headers"))
    if resp.get("status") != "ok":
        return _probe_failure(resp)
    try:
        import json
        data = json.loads(resp.get("text") or "null")
    except Exception as e:
        return {"status": "error", "error": f"invalid oEmbed JSON: {e}"[:240],
                "http": resp.get("http"), "url": url, "results": []}
    if not isinstance(data, dict):
        return {"status": "empty", "http": resp.get("http"), "url": url,
                "error": "oEmbed response is not an object", "results": []}
    title = _clean(data.get("title") or data.get("author_name"))
    if not title:
        return {"status": "empty", "http": resp.get("http"), "url": url,
                "error": "oEmbed response has no title/author", "results": []}
    row = {
        "source": probe.get("source", ""),
        "module_id": probe.get("module_id", ""),
        "source_label": probe.get("label", ""),
        "category": probe.get("category", ""),
        "title": title,
        "name": title,
        "url": _clean(data.get("url") or query),
        "snippet": _clean(data.get("description") or data.get("provider_name")),
        "author": _clean(data.get("author_name")),
        "image": _clean(data.get("thumbnail_url")),
        "fragile": False,
    }
    return {"status": "ok", "http": resp.get("http"), "url": url,
            "results": [row], "count": 1}


def adapter_probe(probe, query, *, timeout=T):
    fn = resolve_adapter(probe.get("adapter"), probe.get("source"))
    if fn is None:
        return {"status": "error", "url": "", "http": None,
                "error": f"adapter not wired: {probe.get('adapter')}",
                "results": []}
    try:
        raw = fn(query)
    except Exception as e:
        msg = str(e)[:240]
        blocked = any(x in msg.lower() for x in
                      ("blocked", "captcha", "rate", "403", "429", "login"))
        return {"status": "blocked" if blocked else "error", "url": "",
                "http": None, "error": msg, "results": []}
    rows, status, detail = _normalise_adapter_result(raw, probe, query)
    return {"status": status, "url": "", "http": None, "error": detail,
            "results": rows, "count": len(rows)}


def link_out_probe(probe, query, *, timeout=T):
    link = build_link(probe, query)
    return {"status": "link_out", "url": link or "", "http": None,
            "error": "" if link else "no public search/profile template",
            "results": [], "link": link}


def run_probe(module, query, *, timeout=T):
    probe = dict(module.get("probe") or {})
    probe.setdefault("source", module.get("source_id") or module.get("id"))
    probe.setdefault("label", module.get("label"))
    probe.setdefault("category", module.get("category"))
    probe.setdefault("module_id", module.get("id"))
    ptype = probe.get("type")
    if ptype == "json_api_probe":
        out = json_api_probe(probe, query, timeout=timeout)
    elif ptype == "http_profile_probe":
        out = http_profile_probe(probe, query, timeout=timeout)
    elif ptype == "html_search_probe":
        out = html_search_probe(probe, query, timeout=timeout)
    elif ptype == "oembed_probe":
        out = oembed_probe(probe, query, timeout=timeout)
    elif ptype == "adapter_probe":
        out = adapter_probe(probe, query, timeout=timeout)
    elif ptype == "link_out":
        out = link_out_probe(probe, query, timeout=timeout)
    else:
        out = {"status": "error", "error": f"unknown probe type: {ptype}",
               "results": []}
    out["probe_type"] = ptype
    return out


def build_link(probe_or_module, query):
    """Build a browser link, preferring a human search/profile page.

    API probe URLs are not link-outs.  For a module we use its declared
    ``search_url``/``profile_url``/``homepage`` first and only fall back to the
    probe URL when no browser page exists.
    """
    if "probe" in probe_or_module:
        module = probe_or_module
        p = module.get("probe") or {}
        template = (module.get("search_url") or module.get("profile_url")
                    or module.get("homepage") or p.get("url") or "")
    else:
        p = probe_or_module or {}
        template = (p.get("search_url") or p.get("profile_url")
                    or p.get("homepage") or p.get("url") or "")
    if not template:
        return ""
    return _render(template, query)


# ------------------------------------------------------------------ parsing
def _meta(text, key):
    for pattern in (
        rf'<meta[^>]+(?:property|name)=["\']{re.escape(key)}["\'][^>]+content=["\']([^"\']*)',
        rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']{re.escape(key)}["\']',
    ):
        m = re.search(pattern, text or "", re.I | re.S)
        if m:
            return _html.unescape(m.group(1))
    return ""


def _title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return _clean(m.group(1)) if m else ""


def _canonical(text):
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', text or "", re.I)
    return _html.unescape(m.group(1)) if m else ""


def _extract_links(text, base_url, probe, query):
    out, seen = [], set()
    for m in re.finditer(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                         text or "", re.I | re.S):
        href = _html.unescape(m.group(1)).strip()
        label = _clean(m.group(2))
        low = href.lower()
        if not href or low.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        if any(x in low for x in ("/login", "/signin", "/signup", "/register",
                                  "accounts.google", "captcha")):
            continue
        url = urllib.parse.urljoin(base_url, href)
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            continue
        host = (p.hostname or "").lower()
        if _forbidden_engine_host(host):
            continue
        if not label:
            label = url
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "source": probe.get("source", ""),
            "module_id": probe.get("module_id", ""),
            "source_label": probe.get("label", ""),
            "category": probe.get("category", ""),
            "title": label,
            "name": label,
            "url": url,
            "snippet": "",
            "fragile": True,
        })
        if len(out) >= int(probe.get("limit") or 10):
            break
    return out


def _normalise_adapter_result(raw, probe, query):
    if isinstance(raw, dict):
        status = str(raw.get("status") or "").lower()
        if status in ("blocked", "rate_limited", "captcha"):
            return [], "blocked", raw.get("error") or status
        if status in ("error", "failed"):
            return [], "error", raw.get("error") or status
        for key in ("results", "hits", "data", "items", "matches", "rows"):
            value = raw.get(key)
            if isinstance(value, list):
                raw = value
                break
        else:
            if status == "empty":
                return [], "empty", ""
            raw = []
    rows = []
    for item in _as_list(raw)[:int(probe.get("limit") or 20)]:
        if isinstance(item, dict) and item.get("status") in ("blocked", "error"):
            continue
        row = _norm_row(item, source=probe.get("source", ""),
                        label=probe.get("label", ""),
                        category=probe.get("category", ""),
                        module_id=probe.get("module_id", ""),
                        fields=probe.get("fields"),
                        result_url=probe.get("result_url", ""),
                        fallback_name=query)
        if row:
            rows.append(row)
    return rows, ("ok" if rows else "empty"), ""


def _probe_failure(resp):
    return {"status": resp.get("status") or "error",
            "http": resp.get("http"), "url": resp.get("url"),
            "error": resp.get("error") or "probe failed", "results": []}


# ------------------------------------------------------------------ adapters
def _deep_people():
    try:
        from modules.deep_search import social as DEEP_SOCIAL
        return DEEP_SOCIAL.PEOPLE_SOURCES
    except Exception:
        return {}


def _identity_adapters():
    try:
        from modules.identity import adapters as AD
        return {
            "people": AD.PEOPLE_ADAPTERS,
            "code": AD.CODE_ADAPTERS,
            "records": AD.RECORD_ADAPTERS,
            "infra": AD.INFRA_ADAPTERS,
            "social": AD.SOCIAL_ADAPTERS,
        }
    except Exception:
        return {}


def _searchx_engines():
    try:
        from modules.searchx import searchx as SX
        return SX.ENGINE_FNS
    except Exception:
        return {}


def _procurement(source):
    def _run(query):
        from modules.procurement import procurement as P
        country = "us" if source == "usaspending" else "eu"
        out = P.search(query, country=country, limit=8)
        if out.get("status") in ("error", "blocked"):
            raise RuntimeError(out.get("error") or out.get("status"))
        return out.get("results") or []
    return _run


def _image_probe(source):
    def _run(query):
        if source == "imgverify":
            from modules.imgverify import imgverify as IV
            out = IV.reverse_links(image_url=query)
            rows = []
            for item in (out.get("links") or out.get("engines") or []):
                if isinstance(item, dict):
                    rows.append(item)
            return rows
        from modules.imgreverse import imgreverse as IR
        if source == "trace_moe":
            return [IR._trace_moe(query)]
        return []
    return _run


_ADAPTER_ALIASES = {
    "people.github": ("people", "github_users"),
    "people.gitlab": ("people", "gitlab_users"),
    "people.codeberg": ("deep", "codeberg"),
    "people.stackexchange": ("deep", "stackexchange"),
    "people.openalex": ("deep", "openalex"),
    "people.semanticscholar": ("deep", "semantic_scholar"),
    "people.orcid": ("deep", "orcid"),
    "people.openlibrary": ("deep", "openlibrary"),
    "people.crossref": ("deep", "crossref"),
    "people.arxiv": ("deep", "arxiv"),
    "people.pubmed": ("people", "pubmed"),
    "people.europepmc": ("people", "europepmc"),
    "people.openaire": ("people", "openaire"),
    "people.doaj": ("people", "doaj"),
    "people.datacite": ("people", "datacite"),
    "people.zenodo": ("people", "zenodo"),
    "people.osf": ("people", "osf_users"),
    "people.internet_archive": ("people", "internet_archive"),
    "people.viaf": ("people", "viaf"),
    "people.littlesis": ("people", "littlesis"),
    "people.dbpedia": ("people", "dbpedia"),
    "people.wikidata": ("deep", "wikidata"),
    "people.gdelt": ("deep", "gdelt"),
    "people.bluesky": ("deep", "bluesky"),
    "people.mastodon": ("deep", "mastodon"),
    "people.lemmy": ("deep", "lemmy"),
    "code.hn": ("code", "hn_algolia"),
    "code.maven": ("code", "maven"),
    "code.devto": ("code", "devto"),
    "social.telegram": ("social", "telegram_preview"),
    "social.weibo": ("social", "weibo"),
    "social.keybase": ("social", "keybase"),
    "infra.dns": ("infra", "dns_google"),
    "infra.certstream": ("infra", "certstream"),
    "records.usaspending": ("custom", "usaspending"),
    "records.ted": ("custom", "ted"),
    "image.trace_moe": ("custom", "trace_moe"),
    "image.imgverify": ("custom", "imgverify"),
}


def resolve_adapter(adapter, source_id=""):
    """Resolve a declarative adapter name to a callable (or None)."""
    adapter = (adapter or "").strip()
    source_id = (source_id or "").strip()
    if not adapter:
        return None
    if adapter.startswith("searchx."):
        return _searchx_engines().get(adapter.split(".", 1)[1])
    if adapter == "socialscrape.page":
        return None
    maps = _identity_adapters()
    deep = _deep_people()
    sx = _searchx_engines()
    alias = _ADAPTER_ALIASES.get(adapter)
    if alias:
        group, key = alias
        if group == "deep":
            return deep.get(key)
        if group == "custom":
            return _procurement(key) if key in ("usaspending", "ted") else _image_probe(key)
        return (maps.get(group) or {}).get(key)
    if "." in adapter:
        group, key = adapter.split(".", 1)
        if group in maps and key in maps[group]:
            return maps[group][key]
        if group == "people" and key in deep:
            return deep[key]
    for group, mapping in maps.items():
        if source_id in mapping:
            return mapping[source_id]
        if adapter in mapping:
            return mapping[adapter]
    if source_id in deep:
        return deep[source_id]
    if source_id in sx:
        return sx[source_id]
    if source_id == "usaspending":
        return _procurement("usaspending")
    if source_id == "ted":
        return _procurement("ted")
    if source_id == "trace_moe":
        return _image_probe("trace_moe")
    return None


def probe_supported(ptype):
    return ptype in PROBE_TYPES
