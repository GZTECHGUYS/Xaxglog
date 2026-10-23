"""Xaxglog global court-records search (keyless, ToS-respecting public endpoints).

Federates free public case-law sources behind one provider interface:
  - CourtListener (Free Law Project) REST API v4 — US federal/state opinions
    https://www.courtlistener.com/api/rest/v4/search/  (anonymous, rate-limited;
    v3 fallback is attempted only on v4 hard-failure)
  - HUDOC (European Court of Human Rights) app query API — ECHR judgments
  - AustLII — Australian case law (sinosrch.cgi)
  - BAILII — British & Irish case law (lucy_search_1.cgi)
  - Indian Kanoon — Indian judgments (Cloudflare-protected)

Lawful-use note: every source queried here is a public, official or
non-profit legal-information publisher. Queries are single, low-volume GET
requests with an identifying User-Agent and generous timeouts; no logins,
no scraping of paywalled content, no bulk mirroring. Results are used for
lawful research / due-diligence / investigative purposes only.
"""
import html
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
CL_V4 = "https://www.courtlistener.com/api/rest/v4/search/"
CL_V3 = "https://www.courtlistener.com/api/rest/v3/search/"
HUDOC = "https://hudoc.echr.coe.int/app/query/results"
AUSTLII = "https://www.austlii.edu.au/cgi-bin/sinosrch.cgi"
BAILII = "http://www.bailii.org/cgi-bin/lucy_search_1.cgi"
KANOON = "https://indiankanoon.org/search/"

PROVIDERS = ("courtlistener", "hudoc", "austlii", "bailii", "indiankanoon")


def _get(url, timeout=T, headers=None):
    """GET helper; returns requests.Response or the exception."""
    import requests
    kw = {"timeout": timeout}
    kw["headers"] = headers or UA
    try:
        return requests.get(url, **kw)
    except Exception as e:
        return e


def _strip(h):
    return html.unescape(re.sub(r"<[^>]+>", " ", h or "")).strip()


def _blocked(text):
    t = (text or "").lower()
    return ("just a moment" in t or "attention required" in t or
            "cf-chl" in t or "captcha" in t or "enable javascript" in t)


# ---------------------------------------------------------------- providers

def courtlistener(query, cap=15, timeout=20):
    """US case law via CourtListener search API v4 (anonymous, rate-limited)."""
    url = f"{CL_V4}?q={urllib.parse.quote(query)}&type=o"
    r = _get(url, timeout=timeout)
    if isinstance(r, Exception):
        return {"provider": "courtlistener", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code == 404:
        # spec: fall back to v3 (may itself require auth -> handled below)
        url = f"{CL_V3}?q={urllib.parse.quote(query)}&type=o"
        r = _get(url, timeout=timeout)
        if isinstance(r, Exception):
            return {"provider": "courtlistener", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code in (401, 403):
        return {"provider": "courtlistener", "status": "blocked",
                "error": f"HTTP {r.status_code} (API requires key at this quota level)", "results": []}
    if r.status_code == 429:
        return {"provider": "courtlistener", "status": "blocked",
                "error": "rate limited (HTTP 429), retry later", "results": []}
    if r.status_code != 200:
        return {"provider": "courtlistener", "status": "error",
                "error": f"HTTP {r.status_code}", "results": []}
    try:
        j = r.json()
    except Exception as e:
        return {"provider": "courtlistener", "status": "error", "error": f"bad json: {e}", "results": []}
    out = []
    for item in (j.get("results") or [])[:cap]:
        snippet = ""
        ops = item.get("opinions") or []
        if ops:
            snippet = _strip(ops[0].get("snippet") or "")[:400]
        u = item.get("absolute_url") or ""
        if u.startswith("/"):
            u = "https://www.courtlistener.com" + u
        out.append({
            "title": item.get("caseName") or "",
            "url": u,
            "court": item.get("court") or "",
            "date": item.get("dateFiled") or "",
            "snippet": snippet,
        })
    return {"provider": "courtlistener", "status": "ok", "query": query,
            "count": j.get("count"), "results": out}


def hudoc(query, cap=15, timeout=15):
    """ECHR case law via HUDOC app query API (JSON).

    The endpoint sits behind Cloudflare; when a JS challenge is returned we
    report status=blocked instead of crashing.
    """
    q = urllib.parse.quote(f'(contents=("{query}"))')
    url = f"{HUDOC}?query={q}&rank=RELEVANCE&format=JSON&orient=false"
    r = _get(url, timeout=timeout)
    if isinstance(r, Exception):
        return {"provider": "hudoc", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code == 403 or _blocked(r.text):
        return {"provider": "hudoc", "status": "blocked",
                "error": "Cloudflare challenge (HTTP 403) on hudoc.echr.coe.int", "results": []}
    if r.status_code != 200:
        return {"provider": "hudoc", "status": "error", "error": f"HTTP {r.status_code}", "results": []}
    try:
        j = r.json()
    except Exception:
        # some HUDOC responses wrap JSON in XSSI guard or return XML
        return {"provider": "hudoc", "status": "error", "error": "non-JSON response", "results": []}
    docs = (j.get("results") or {}).get("docs") or j.get("documents") or []
    out = []
    for d in docs[:cap]:
        appuri = d.get("appuri") or d.get("documentid") or ""
        u = ("https://hudoc.echr.coe.int/app/convention/docs/XUI/?iid=" + appuri) if appuri else ""
        out.append({
            "title": _strip(d.get("title") or "")[:300],
            "url": u,
            "court": "ECtHR",
            "date": d.get("decisiondate") or d.get("issue") or "",
            "snippet": _strip(d.get("doctype") or "") + (" " + _strip(d.get("kp") or "") if d.get("kp") else ""),
        })
    return {"provider": "hudoc", "status": "ok", "query": query, "results": out}


def austlii(query, cap=15, timeout=15):
    """Australian case law via AustLII sinosrch (Cloudflare-guarded)."""
    url = (f"{AUSTLII}?method=auto&query={urllib.parse.quote(query)}"
           f"&meta=%2Fau&mask_path=au/cases")
    r = _get(url, timeout=timeout)
    if isinstance(r, Exception):
        return {"provider": "austlii", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code != 200 or _blocked(r.text):
        return {"provider": "austlii", "status": "blocked",
                "error": f"HTTP {r.status_code} / bot protection (Cloudflare)", "results": []}
    out = []
    for m in re.finditer(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.S | re.I):
        href, title = m.group(1), _strip(m.group(2))
        if not title or len(title) < 12:
            continue
        if "/cgi-bin/" in href or href.startswith("#"):
            continue
        if not re.search(r"(cases|judgment|decisions?)/", href):
            continue
        if href.startswith("/"):
            href = "https://www.austlii.edu.au" + href
        dm = re.search(r"\((\d{1,2}\s+\w+\s+\d{4})\)", title)
        out.append({"title": title[:300], "url": href, "court": "AustLII",
                    "date": dm.group(1) if dm else "", "snippet": ""})
        if len(out) >= cap:
            break
    return {"provider": "austlii", "status": "ok", "query": query, "results": out}


def bailii(query, cap=15, timeout=15):
    """UK/Ireland case law via BAILII lucy_search (public HTML)."""
    url = f"{BAILII}?query={urllib.parse.quote(query)}&method=boolean"
    r = _get(url, timeout=timeout)
    if isinstance(r, Exception):
        return {"provider": "bailii", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code != 200 or _blocked(r.text):
        return {"provider": "bailii", "status": "blocked",
                "error": f"HTTP {r.status_code} / bot protection", "results": []}
    out = []
    for m in re.finditer(r'<li>.*?<p>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=<li>|</ol>)',
                         r.text, re.S | re.I):
        href, title, rest = m.group(1), _strip(m.group(2)), m.group(3)
        if not title:
            continue
        if href.startswith("/"):
            href = "http://www.bailii.org" + href
        snip = _strip(rest)[:300]
        dm = re.search(r"\((\d{1,2}\s+\w+\s+\d{4})\)", title)
        out.append({"title": title[:300], "url": href, "court": "BAILII",
                    "date": dm.group(1) if dm else "", "snippet": snip})
        if len(out) >= cap:
            break
    return {"provider": "bailii", "status": "ok", "query": query, "results": out}


def indiankanoon(query, cap=15, timeout=15):
    """Indian judgments via Indian Kanoon (Cloudflare-protected)."""
    url = f"{KANOON}?q={urllib.parse.quote(query)}"
    r = _get(url, timeout=timeout)
    if isinstance(r, Exception):
        return {"provider": "indiankanoon", "status": "error", "error": str(r)[:150], "results": []}
    if r.status_code != 200 or _blocked(r.text):
        return {"provider": "indiankanoon", "status": "blocked",
                "error": f"HTTP {r.status_code} / Cloudflare protection", "results": []}
    out = []
    for m in re.finditer(r'<a[^>]+href="(/doc(?:id|lc)?/[^"]+)"[^>]*>(.*?)</a>', r.text, re.S | re.I):
        href, title = m.group(1), _strip(m.group(2))
        if not title or len(title) < 10:
            continue
        out.append({"title": title[:300], "url": "https://indiankanoon.org" + href,
                    "court": "Indian Kanoon", "date": "", "snippet": ""})
        if len(out) >= cap:
            break
    return {"provider": "indiankanoon", "status": "ok", "query": query, "results": out}


_FUNCS = {
    "courtlistener": courtlistener,
    "hudoc": hudoc,
    "austlii": austlii,
    "bailii": bailii,
    "indiankanoon": indiankanoon,
}


# ------------------------------------------------------------------ search

def search(query, providers=None, jurisdiction=None, timeout=20):
    """Run `query` across selected providers in parallel; merged, date-sorted.

    Providers execute concurrently (the slow CourtListener fallback no longer
    serializes behind every other source). `timeout` is the per-provider HTTP
    timeout in seconds. Every provider dict carries its own status so callers
    can see which sources answered and which are blocked/degraded.
    """
    try:
        query = (query or "").strip()
        if not query:
            return {"query": query, "providers": {}, "results": [],
                    "error": "empty query"}
        sel = list(providers) if providers else list(PROVIDERS)
        sel = [p for p in sel if p in _FUNCS]
        # jurisdiction hints (ISO-ish) narrow provider choice when given
        j = (jurisdiction or "").upper()
        if j:
            hint = {"US": ["courtlistener"], "GB": ["bailii"], "UK": ["bailii"],
                    "AU": ["austlii"], "IN": ["indiankanoon"], "EU": ["hudoc"]}.get(j)
            if hint:
                sel = [p for p in sel if p in hint] or sel
        merged, pstat = [], {}
        _lim = int(timeout) if timeout else 20
        with ThreadPoolExecutor(max_workers=min(8, len(sel) or 1)) as ex:
            futs = {ex.submit(_FUNCS[p], query, _lim): p for p in sel}
            for fut in as_completed(futs):
                p = futs[fut]
                try:
                    res = fut.result()
                except Exception as e:  # public functions never raise
                    res = {"provider": p, "status": "error", "error": str(e)[:150], "results": []}
                pstat[p] = {k: v for k, v in res.items() if k != "results"}
                pstat[p]["n_results"] = len(res.get("results") or [])
                for item in res.get("results") or []:
                    item["provider"] = p
                    merged.append(item)

        def _key(x):
            return x.get("date") or ""
        merged.sort(key=_key, reverse=True)
        db.audit("system", "courts.search", query[:80],
                 f"providers={','.join(sel)} total={len(merged)}")
        return {"query": query, "jurisdiction": jurisdiction,
                "providers": pstat, "total": len(merged),
                "results": merged[:50]}
    except Exception as e:
        return {"error": str(e)[:150], "results": []}


def providers_status():
    """Quick probe of every provider with a tiny query; report reachability."""
    status = {}
    for p in _FUNCS:
        try:
            res = _FUNCS[p]("test", cap=1)
            status[p] = {"status": res.get("status", "?"),
                         "n_results": len(res.get("results") or []),
                         "error": res.get("error", "")}
        except Exception as e:
            status[p] = {"status": "error", "error": str(e)[:150]}
    db.audit("system", "courts.providers_status", "",
             json.dumps({k: v.get("status") for k, v in status.items()}))
    return status
