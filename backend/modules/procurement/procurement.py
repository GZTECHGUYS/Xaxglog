"""Xaxglog public-procurement intelligence — US federal awards + EU TED notices.

Free, keyless public-record sources:
  - USAspending.gov award search API (US federal contracts/grants)
  - TED (Tenders Electronic Daily) API v3 (EU public-procurement notices)

The module is deliberately a *search aid*, not an award-determination engine.
Results are normalized into a common shape (buyer, awardee, amount, date, URL)
and every source reports its own status. Rate limits, 401/403 walls and
non-JSON anti-bot pages degrade to ``blocked``/``error`` instead of false hits.

Lawful-use note: both sources are official public transparency portals. This
module makes low-volume queries with an identifying User-Agent; it does not
authenticate, bypass paywalls, solve captchas, or mirror bulk datasets.
"""
import datetime
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0", "Accept": "application/json"}
T = 25
USASPENDING = "https://api.usaspending.gov/api/v2/search/spending_by_award/"
TED = "https://api.ted.europa.eu/v3/notices/search"

SOURCES = [
    {"id": "usaspending", "label": "USAspending.gov",
     "region": "US", "what": "Federal contract and grant awards",
     "url": "https://www.usaspending.gov/search",
     "hint": "recipient / keyword"},
    {"id": "ted", "label": "TED — Tenders Electronic Daily",
     "region": "EU", "what": "EU public-procurement notices and awards",
     "url": "https://ted.europa.eu/en/",
     "hint": "buyer, supplier, or subject"},
]


def sources():
    return SOURCES


def _post_json(url, payload, timeout=T):
    import requests
    try:
        return requests.post(url, json=payload, headers=UA, timeout=timeout)
    except Exception as e:
        return e


def _blocked(code):
    return code in (401, 403, 407, 429)


def _text(v, lang="eng"):
    """Flatten a TED-style multilingual field into a short display string."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "; ".join(x for x in (_text(i, lang) for i in v) if x)[:600]
    if isinstance(v, dict):
        for key in (lang, "eng", "en", "mul"):
            if key in v:
                return _text(v[key], lang)
        for key in ("text", "value", "title", "name"):
            if key in v:
                return _text(v[key], lang)
        for val in v.values():
            out = _text(val, lang)
            if out:
                return out
    return ""


def _usaspending(query, limit, start_date, end_date):
    payload = {
        "filters": {
            "recipient_search_text": [query],
            "award_type_codes": ["A", "B", "C", "D"],
            "time_period": [{
                "start_date": start_date or "2015-10-01",
                "end_date": end_date or datetime.date.today().isoformat(),
            }],
        },
        "fields": [
            "Award ID", "Recipient Name", "Award Amount", "Awarding Agency",
            "Awarding Sub Agency", "Start Date", "End Date", "Description",
            "generated_internal_id",
        ],
        "page": 1,
        "limit": min(max(int(limit), 1), 50),
        "sort": "Award Amount",
        "order": "desc",
        "subawards": False,
    }
    r = _post_json(USASPENDING, payload)
    if isinstance(r, Exception):
        return {"source": "usaspending", "status": "error",
                "error": str(r)[:150], "results": []}
    if _blocked(r.status_code):
        return {"source": "usaspending", "status": "blocked",
                "http": r.status_code, "error": f"HTTP {r.status_code}",
                "results": []}
    if r.status_code != 200:
        return {"source": "usaspending", "status": "error",
                "http": r.status_code, "error": f"HTTP {r.status_code}",
                "results": []}
    try:
        j = r.json()
    except Exception:
        return {"source": "usaspending", "status": "error",
                "error": "non-JSON response (anti-bot page?)", "results": []}

    out = []
    for row in (j.get("results") or [])[:limit]:
        gid = row.get("generated_internal_id") or row.get("Award ID")
        url = ("https://www.usaspending.gov/award/"
               + urllib.parse.quote(str(gid))) if gid else "https://www.usaspending.gov/search"
        out.append({
            "source": "usaspending",
            "id": row.get("Award ID") or gid,
            "title": row.get("Description") or row.get("Award ID") or "Federal award",
            "buyer": row.get("Awarding Agency") or row.get("Awarding Sub Agency") or "",
            "awardee": row.get("Recipient Name") or "",
            "amount": row.get("Award Amount"),
            "date": row.get("Start Date") or "",
            "end_date": row.get("End Date") or "",
            "url": url,
            "description": row.get("Description") or "",
        })
    meta = j.get("page_metadata") or {}
    return {"source": "usaspending", "status": "ok",
            "count": len(out), "total": meta.get("total"), "results": out}


def _ted(query, limit):
    payload = {
        "query": "FT~" + json.dumps(query, ensure_ascii=False),
        "fields": [
            "publication-number", "notice-title", "buyer-name", "winner-name",
            "publication-date", "estimated-value-lot", "links",
        ],
        "page": 1,
        "limit": min(max(int(limit), 1), 50),
        "scope": "ALL",
    }
    r = _post_json(TED, payload)
    if isinstance(r, Exception):
        return {"source": "ted", "status": "error",
                "error": str(r)[:150], "results": []}
    if _blocked(r.status_code):
        return {"source": "ted", "status": "blocked",
                "http": r.status_code, "error": f"HTTP {r.status_code}",
                "results": []}
    if r.status_code != 200:
        return {"source": "ted", "status": "error",
                "http": r.status_code, "error": f"HTTP {r.status_code}",
                "results": []}
    try:
        j = r.json()
    except Exception:
        return {"source": "ted", "status": "error",
                "error": "non-JSON response (anti-bot page?)", "results": []}

    out = []
    notices = j.get("notices") or j.get("results") or []
    for n in notices[:limit]:
        pub = _text(n.get("publication-number") or n.get("publication_number")
                    or n.get("id"))
        title = _text(n.get("notice-title") or n.get("notice_title")
                      or n.get("title"))
        buyer = _text(n.get("buyer-name") or n.get("buyer_name")
                      or n.get("buyer"))
        winner = _text(n.get("winner-name") or n.get("winner_name")
                       or n.get("winner"))
        date = _text(n.get("publication-date") or n.get("publication_date")
                     or n.get("date"))
        amount = n.get("estimated-value-lot") or n.get("estimated_value_lot")
        links = n.get("links") or {}
        url = ""
        if isinstance(links, dict):
            url = _text(links.get("html") or links.get("HTML")
                        or links.get("xml") or links.get("self"))
        elif isinstance(links, list) and links:
            url = _text(links[0])
        if not url and pub:
            url = ("https://ted.europa.eu/en/notice/-/detail/"
                   + urllib.parse.quote(str(pub)))
        out.append({
            "source": "ted",
            "id": pub,
            "title": title or "EU procurement notice",
            "buyer": buyer,
            "awardee": winner,
            "amount": _text(amount) if amount is not None else "",
            "date": date,
            "url": url,
        })
    return {"source": "ted", "status": "ok", "count": len(out),
            "total": j.get("totalNoticeCount") or j.get("total"),
            "results": out}


def search(query, country="all", limit=10, start_date=None, end_date=None,
           case_id=None, user="system"):
    """Search US and/or EU public procurement records for a recipient/keyword."""
    query = (query or "").strip()
    if not query:
        return {"status": "error", "error": "query required", "results": []}
    country = (country or "all").strip().lower()
    if country not in ("all", "us", "eu"):
        return {"status": "error",
                "error": "country must be one of: all, us, eu", "results": []}
    limit = max(1, min(int(limit or 10), 50))

    jobs = []
    if country in ("all", "us"):
        jobs.append(("usaspending", lambda: _usaspending(query, limit,
                                                         start_date, end_date)))
    if country in ("all", "eu"):
        jobs.append(("ted", lambda: _ted(query, limit)))

    results, statuses = [], {}
    with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as ex:
        futures = {ex.submit(fn): name for name, fn in jobs}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                part = fut.result()
            except Exception as e:
                part = {"source": name, "status": "error",
                        "error": str(e)[:150], "results": []}
            statuses[name] = {k: part.get(k) for k in
                              ("status", "count", "total", "http", "error")
                              if part.get(k) is not None}
            results.extend(part.get("results") or [])

    results.sort(key=lambda x: (x.get("date") or ""), reverse=True)
    status = "ok"
    if statuses and all(v.get("status") == "blocked" for v in statuses.values()):
        status = "blocked"
    elif statuses and all(v.get("status") == "error" for v in statuses.values()):
        status = "error"

    out = {"status": status, "query": query, "country": country,
           "count": len(results), "results": results, "sources": statuses}
    try:
        db.audit(user, "procurement.search", query[:80],
                 f"country={country} n={len(results)}")
        if case_id:
            db.store_artifact(case_id, None, "procurement", "procurement:search",
                              out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out
