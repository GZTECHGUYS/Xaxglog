"""Xaxglog searchx — federated keyless search + OSINT dork engine.

Purpose
-------
Run one query across several independent, *keyless* public search backends,
dedupe/cluster the hits and rank them by cross-engine corroboration. On top of
that, a dork builder/runner turns a single pivot (domain / email / username /
ip / person) into classic search-engine dorks and executes them.

Sources (all public & keyless)
------------------------------
  - DuckDuckGo HTML endpoint  https://html.duckduckgo.com/html/  (POST q=)
  - Public SearXNG instances  searx.be, search.bus-hit.me, priv.au, searxng.site
                              (GET /search?q=&format=json — first OK wins)
  - Mojeek                    https://www.mojeek.com/search?q=
  - Wikipedia MediaWiki API   https://en.wikipedia.org/w/api.php (list=search)

Lawful use
----------
Public search result pages / public APIs only. Respect each source's Terms of
Service, robots.txt and rate limits; be a polite client. This module performs
no credential attacks, no auth bypass and no scraping behind logins — when an
engine presents a captcha / anti-bot wall the module degrades to
``{"status": "blocked", "mode": ...}`` and never crashes.
"""
import html as _html
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15            # seconds per request
CAP = 20          # per-engine result cap
FED_CAP = 60      # federated/dork merged-result cap

SEARX_INSTANCES = [
    "https://searx.be",
    "https://search.bus-hit.me",
    "https://priv.au",
    "https://searxng.site",
]

_BLOCK_MARKERS = (
    "captcha", "anomaly", "verifying your browser", "are you a robot",
    "unusual traffic", "just a moment", "cf-chl", "challenge-platform",
    "attention required", "access denied", "request blocked",
)


# ------------------------------------------------------------------ helpers
def _get(url, **kw):
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _post(url, **kw):
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.post(url, headers=headers, **kw)
    except Exception as e:
        return e


def _clean(s):
    """Strip markup + collapse whitespace from a scraped snippet/title."""
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def _norm_url(url):
    """Normalized URL key for cross-engine dedupe (host/scheme/tracking-insens.)."""
    try:
        p = urllib.parse.urlsplit(url or "")
        host = (p.netloc or "").lower()
        if host.startswith("www."):
            host = host[4:]
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
             if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "ref")]
        path = urllib.parse.unquote(p.path or "/").rstrip("/") or "/"
        # key ignores scheme so http/https variants of one URL cluster together
        return urllib.parse.urlunsplit(("", host, path,
                                        urllib.parse.urlencode(q), ""))
    except Exception:
        return (url or "").strip()


def _classify(r):
    """Map an HTTP response to 'ok' | 'blocked' | 'error' (never raises)."""
    try:
        if isinstance(r, Exception):
            return "error"
        if r.status_code in (403, 429, 503, 451):
            return "blocked"
        if r.status_code >= 500:
            return "error"
        head = (r.text or "")[:8000].lower()
        if any(m in head for m in _BLOCK_MARKERS):
            return "blocked"
        return "ok"
    except Exception:
        return "error"


def _engine_err(engine, e, extra=None):
    out = {"engine": engine, "status": "error", "results": [],
           "error": str(e)[:150]}
    if extra:
        out.update(extra)
    return out


def _anchors(page):
    """Yield (attrs, inner_html) for every <a> tag in the page."""
    for m in re.finditer(r"<a\b([^>]*)>(.*?)</a>", page or "", re.S | re.I):
        yield m.group(1), m.group(2)


def _attr(attrs, name):
    m = re.search(r"""\b%s\s*=\s*["']([^"']*)["']""" % re.escape(name), attrs or "", re.I)
    return _html.unescape(m.group(1)) if m else ""


def _classes(attrs):
    return (_attr(attrs, "class") or "").split()


# ------------------------------------------------------------------ engines
def ddg(query):
    """DuckDuckGo (HTML endpoint, keyless): POST q=, parse result__a/snippet."""
    out = {"engine": "ddg", "status": "ok", "results": []}
    try:
        query = (query or "").strip()
        if not query:
            out["error"] = "empty query"
            out["status"] = "error"
            return out
        r = _post("https://html.duckduckgo.com/html/", data={"q": query})
        st = _classify(r)
        if st != "ok":
            out["status"] = st
            out["mode"] = "anti_bot" if st == "blocked" else "http_error"
            return out
        page = r.text or ""
        rows = []
        for attrs, inner in _anchors(page):
            cls = _classes(attrs)
            if "result__a" in cls:
                href = _attr(attrs, "href")
                rows.append([_decode_ddg(href), _clean(inner), ""])
            elif "result__snippet" in cls and rows:
                rows[-1][2] = _clean(inner)
        if not rows:
            head = page[:4000].lower()
            if "anomaly" in head or "no results" in head:
                out["status"] = "ok" if "no results" in head else "blocked"
            # else: empty but healthy SERP
        out["results"] = [{"title": t, "url": u, "snippet": s}
                          for u, t, s in rows if u][:CAP]
        return out
    except Exception as e:
        return _engine_err("ddg", e)


def _decode_ddg(href):
    """Unwrap DuckDuckGo's /l/?uddg=<real-url> redirect parameter."""
    if not href:
        return ""
    try:
        if href.startswith("//"):
            href = "https:" + href
        p = urllib.parse.urlsplit(href)
        if "uddg" in p.query:
            qs = urllib.parse.parse_qs(p.query)
            if qs.get("uddg"):
                return qs["uddg"][0]
        return href
    except Exception:
        return href


def searx(query):
    """Public SearXNG instances (JSON API) — tried in order, first OK wins."""
    out = {"engine": "searx", "status": "error", "results": [], "tried": []}
    query = (query or "").strip()
    if not query:
        out["error"] = "empty query"
        return out
    saw_blocked = False
    for base in SEARX_INSTANCES:
        r = _get(base + "/search", params={"q": query, "format": "json"},
                 headers={"Accept": "application/json"})
        if isinstance(r, Exception):
            out["tried"].append({"instance": base, "status": "error",
                                 "detail": str(r)[:80]})
            continue
        st = _classify(r)
        if st == "blocked":
            saw_blocked = True
            out["tried"].append({"instance": base, "status": "blocked"})
            continue
        if st == "error":
            out["tried"].append({"instance": base, "status": f"http_{r.status_code}"})
            continue
        try:
            j = r.json()
            res = j.get("results") or []
        except Exception:
            out["tried"].append({"instance": base, "status": "not_json"})
            continue
        if not isinstance(res, list):
            out["tried"].append({"instance": base, "status": "bad_payload"})
            continue
        out["instance"] = base
        out["status"] = "ok"
        out["results"] = [{"title": _clean(x.get("title", "")),
                           "url": x.get("url", ""),
                           "snippet": _clean(x.get("content", x.get("snippet", "")))}
                          for x in res[:CAP] if isinstance(x, dict) and x.get("url")]
        return out
    out["status"] = "blocked" if saw_blocked else "error"
    out["mode"] = "anti_bot" if saw_blocked else "no_instance"
    return out


def mojeek(query):
    """Mojeek (independent crawler): parse <a class="title"> + abstracts."""
    out = {"engine": "mojeek", "status": "ok", "results": []}
    try:
        query = (query or "").strip()
        if not query:
            out["error"] = "empty query"
            out["status"] = "error"
            return out
        r = _get("https://www.mojeek.com/search", params={"q": query},
                 headers={"Accept": "text/html,application/xhtml+xml",
                          "Accept-Language": "en-US,en;q=0.9"})
        st = _classify(r)
        if st != "ok":
            out["status"] = st
            out["mode"] = "captcha" if st == "blocked" else "http_error"
            return out
        page = r.text or ""
        if re.search(r"<title>\s*captcha\s*</title>", page, re.I) or "captcha-wrap" in page:
            out["status"] = "blocked"
            out["mode"] = "captcha"
            return out
        rows = []
        for attrs, inner in _anchors(page):
            cls = _classes(attrs)
            if "title" in cls:                      # <a class="title" href=..>
                rows.append([_attr(attrs, "href"), _clean(inner), ""])
        # abstracts: <p class="s">abstract</p> — same order as the titles
        abstracts = [_clean(m.group(1)) for m in
                     re.finditer(r"<p[^>]*class=[\"']s[\"'][^>]*>(.*?)</p>", page, re.S | re.I)]
        for i, row in enumerate(rows):
            if i < len(abstracts):
                row[2] = abstracts[i]
        out["results"] = [{"title": t, "url": u, "snippet": s}
                          for u, t, s in rows if u][:CAP]
        return out
    except Exception as e:
        return _engine_err("mojeek", e)


def wikipedia(query):
    """Wikipedia MediaWiki search API (keyless): list=search."""
    out = {"engine": "wikipedia", "status": "ok", "results": []}
    try:
        query = (query or "").strip()
        if not query:
            out["error"] = "empty query"
            out["status"] = "error"
            return out
        r = _get("https://en.wikipedia.org/w/api.php",
                 params={"action": "query", "list": "search", "srsearch": query,
                         "format": "json", "srlimit": CAP, "srprop": "snippet"})
        st = _classify(r)
        if st != "ok":
            out["status"] = st
            out["mode"] = "anti_bot" if st == "blocked" else "http_error"
            return out
        j = r.json()
        hits = (j.get("query") or {}).get("search") or []
        out["results"] = [
            {"title": h.get("title", ""),
             "url": "https://en.wikipedia.org/wiki/" +
                    urllib.parse.quote(h.get("title", "").replace(" ", "_")),
             "snippet": _clean(h.get("snippet", ""))}
            for h in hits[:CAP]
        ]
        return out
    except Exception as e:
        return _engine_err("wikipedia", e)


ENGINE_FNS = {"ddg": ddg, "searx": searx, "mojeek": mojeek, "wikipedia": wikipedia}


# ------------------------------------------------------------------ federated
def federated(query, engines=None):
    """Run `query` on all (or selected) engines, dedupe, cross-rank.

    Ranking: number of distinct engines returning the URL (desc), then best
    (earliest) position. Every result carries ``engines`` = list of engines.
    """
    out = {"query": query, "engines": {}, "total": 0, "results": []}
    try:
        names = list(engines) if engines else list(ENGINE_FNS.keys())
        names = [n for n in names if n in ENGINE_FNS]
        if not query or not str(query).strip():
            out["error"] = "empty query"
            return out
        per = {}
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(ENGINE_FNS[n], query): n for n in names}
            for f in as_completed(futs):
                n = futs[f]
                try:
                    per[n] = f.result()
                except Exception as e:          # defensive: engine never raises
                    per[n] = _engine_err(n, e)
        clusters = {}   # norm-url -> {"title","url","snippet","engines":[],"_pos"}
        for n in names:
            res = per.get(n) or {}
            out["engines"][n] = res.get("status", "error")
            for pos, item in enumerate(res.get("results") or []):
                u = item.get("url") or ""
                if not u:
                    continue
                key = _norm_url(u)
                c = clusters.get(key)
                if c is None:
                    clusters[key] = {"title": item.get("title", ""), "url": u,
                                     "snippet": item.get("snippet", ""),
                                     "engines": [n], "_pos": pos}
                else:
                    if n not in c["engines"]:
                        c["engines"].append(n)
                    if not c.get("snippet") and item.get("snippet"):
                        c["snippet"] = item["snippet"]
                    c["_pos"] = min(c["_pos"], pos)
        ranked = sorted(clusters.values(),
                        key=lambda c: (-len(c["engines"]), c["_pos"], c["title"]))
        for c in ranked:
            c.pop("_pos", None)
        out["results"] = ranked[:FED_CAP]
        out["total"] = len(ranked)
        return out
    except Exception as e:
        out["error"] = str(e)[:150]
        return out


# ------------------------------------------------------------------ dorks
_KIND_ORDER = ("email", "ip", "person", "domain", "username")

_DORKS = {
    "domain": {
        "google": 'site:{t} -www',
        "bing": 'site:{t}',
        "ddg": 'site:{t}',
        # lead with the quoted dork (best keyless-engine support), canonical
        # site:/intitle:/inurl:/ext: dorks follow
        "all": [
            '"{t}" (backup OR dump OR sql OR config)',
            'site:{t}',
            '"{t}" filetype:pdf',
            'site:{t} intitle:"index of"',
            'inurl:login site:{t}',
            'site:{t} ext:log OR ext:sql OR ext:bak',
        ],
    },
    "email": {
        "google": '"{t}"',
        "bing": '"{t}"',
        "ddg": '"{t}"',
        "all": [
            '"{t}"',
            '"{t}" filetype:pdf',
            '"{t}" site:pastebin.com OR site:ghostbin.com',
            '"{t}" inurl:login',
            '"{t}" (dump OR breach OR leak OR paste)',
        ],
    },
    "username": {
        "google": '"{t}" site:github.com OR site:gitlab.com',
        "bing": '"{t}" site:github.com',
        "ddg": '"{t}" site:github.com',
        "all": [
            '"{t}" site:github.com OR site:gitlab.com',
            '"{t}" site:reddit.com OR site:tiktok.com',
            '"{t}" site:twitter.com OR site:x.com',
            'inurl:"{t}" login',
            '"{t}" filetype:pdf',
        ],
    },
    "ip": {
        "google": '"{t}"',
        "bing": '"{t}"',
        "ddg": '"{t}"',
        "all": [
            '"{t}"',
            '"{t}" filetype:log',
            '"{t}" (shodan OR censys OR zoomeye)',
            'inurl:ip "{t}"',
            '"{t}" (access.log OR syslog)',
        ],
    },
    "person": {
        "google": '"{t}" intitle:resume OR intitle:cv',
        "bing": '"{t}"',
        "ddg": '"{t}"',
        "all": [
            '"{t}"',
            '"{t}" filetype:pdf',
            '"{t}" intitle:"resume" OR intitle:"cv"',
            '"{t}" site:linkedin.com/in',
            '"{t}" (email OR contact OR phone)',
        ],
    },
}


def detect_kind(target):
    """Classify a pivot: email | ip | person | domain | username."""
    t = (target or "").strip()
    if not t:
        return "username"
    if re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", t):
        return "email"
    try:
        import ipaddress
        ipaddress.ip_address(t.split("%")[0])
        return "ip"
    except Exception:
        pass
    if " " in t and re.search(r"[A-Za-zА-Яа-яЁё]", t):
        return "person"
    if re.match(r"^(?:[A-Za-z0-9\-_]+\.)+[A-Za-z]{2,}$", t):
        return "domain"
    return "username"


def dork_build(target, kind=None):
    """Build classic dorks for a pivot.

    Returns ``{"target", "kind", "dorks": {"google","bing","ddg"}, "all": [...]}``
    where *all* is the ranked dork list executed by :func:`dork_run`.
    """
    try:
        target = (target or "").strip()
        kind = (kind or "").strip().lower()
        if kind not in _DORKS:
            kind = detect_kind(target)
        tpl = _DORKS.get(kind, _DORKS["username"])
        if not target:
            return {"target": "", "kind": kind,
                    "dorks": {"google": "", "bing": "", "ddg": ""}, "all": []}
        return {
            "target": target,
            "kind": kind,
            "dorks": {k: tpl[k].format(t=target) for k in ("google", "bing", "ddg")},
            "all": [d.format(t=target) for d in tpl["all"]],
        }
    except Exception as e:
        return {"target": target, "kind": kind, "error": str(e)[:150],
                "dorks": {"google": "", "bing": "", "ddg": ""}, "all": []}


def dork_run(target, kind=None, max_dorks=4):
    """Build dorks, execute the top ones on ddg+mojeek, merge with dedupe.

    Every merged hit carries ``dork`` (the query that found it) and
    ``engines`` (which engine(s) returned it). Anti-bot engines simply drop
    out with status "blocked" — the run never raises.
    """
    out = {"target": target, "kind": None, "dorks_run": 0,
           "runs": [], "total": 0, "results": []}
    try:
        built = dork_build(target, kind)
        out["kind"] = built["kind"]
        dorks = (built.get("all") or [])[:max(1, int(max_dorks or 4))]
        out["dorks_run"] = len(dorks)
        hits = {}   # norm-url -> result dict
        order = 0

        def _chain(chain_pairs):
            """Sequential per-engine chain: avoids burst rate-limits (DDG)."""
            import time as _t
            res = []
            for i, (d, e) in enumerate(chain_pairs):
                if i:
                    _t.sleep(6.0 if e == "ddg" else 1.0)   # polite pacing
                try:
                    res.append((d, e, ENGINE_FNS[e](d)))
                except Exception as ex2:
                    res.append((d, e, _engine_err(e, ex2)))
            return res

        chains = [[(d, "ddg") for d in dorks], [(d, "mojeek") for d in dorks]]
        done = []
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(_chain, ch) for ch in chains]
            for f in as_completed(futs):
                try:
                    done.extend(f.result())
                except Exception as ex3:
                    out["runs"].append({"dork": "", "engine": "?",
                                        "status": "error",
                                        "count": 0, "detail": str(ex3)[:80]})
        for d, e, res in done:
            st = res.get("status", "error")
            out["runs"].append({"dork": d, "engine": e, "status": st,
                                "count": len(res.get("results") or [])})
            if st != "ok":
                continue
            for item in res.get("results") or []:
                u = item.get("url") or ""
                if not u:
                    continue
                key = _norm_url(u)
                rec = hits.get(key)
                if rec is None:
                    hits[key] = {"title": item.get("title", ""), "url": u,
                                 "snippet": item.get("snippet", ""),
                                 "dork": d, "dorks": [d], "engines": [e],
                                 "_order": order}
                    order += 1
                else:
                    if d not in rec["dorks"]:
                        rec["dorks"].append(d)
                    if e not in rec["engines"]:
                        rec["engines"].append(e)
                    if not rec.get("snippet") and item.get("snippet"):
                        rec["snippet"] = item["snippet"]
        ranked = sorted(hits.values(),
                        key=lambda r: (-len(r["engines"]), -len(r["dorks"]), r["_order"]))
        for r in ranked:
            r.pop("_order", None)
        out["results"] = ranked[:FED_CAP]
        out["total"] = len(ranked)
        if ranked:
            out["status"] = "ok"
        elif not out["runs"]:
            out["status"] = "empty"
        elif all(r["status"] == "blocked" for r in out["runs"]):
            out["status"] = "blocked"
        else:
            out["status"] = "empty"
        return out
    except Exception as e:
        out["error"] = str(e)[:150]
        return out
