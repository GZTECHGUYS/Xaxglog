"""Xaxglog lobbying-disclosure intelligence — US Senate LDA public API.

Source:
  - Lobbying Disclosure Act (LDA) API v1 at lda.gov (formerly lda.senate.gov),
    official public filings.

Searches both **client** and **registrant** names because a person or company
can appear on either side of a filing. Results are deduplicated and normalized
to client / registrant / lobbyists / issues / amount / date / official URL.

Lawful-use note: the LDA API is an official public transparency source. This
module performs low-volume, identified GET requests; it does not authenticate,
scrape private data, or bypass rate limits. A filing is a disclosure, not proof
of wrongdoing.
"""
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0", "Accept": "application/json"}
T = 25
LDA = "https://lda.gov/api/v1/filings/"

SOURCES = [{
    "id": "us_senate_lda",
    "label": "US Lobbying Disclosure Act API (lda.gov)",
    "region": "US",
    "what": "Federal lobbying filings: client, registrant, lobbyists, issues, income/expenses",
    "url": "https://lda.gov/api/v1/filings/",
    "hint": "client or registrant name",
    "note": "lda.gov may apply network-level access controls; HTTP 403 is reported as blocked, not as no results",
}]


def sources():
    return SOURCES


def _get(url, params=None, timeout=T):
    import requests
    try:
        return requests.get(url, params=params, headers=UA, timeout=timeout)
    except Exception as e:
        return e


def _blocked(code):
    return code in (401, 403, 407, 429)


def _name(obj):
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        return str(obj.get("name") or obj.get("label") or "").strip()
    return ""


def _amount(v):
    if v is None:
        return ""
    if isinstance(v, (int, float)):
        return v
    return str(v).strip()


def _normalize(item):
    client = _name(item.get("client") or item.get("client_name"))
    registrant = _name(item.get("registrant") or item.get("registrant_name"))
    lobbyists = []
    for row in item.get("lobbyists") or []:
        if isinstance(row, dict):
            person = row.get("lobbyist") or row.get("lobbyist_name") or {}
            if isinstance(person, dict):
                nm = " ".join(x for x in (person.get("first_name"),
                                          person.get("middle_name"),
                                          person.get("last_name")) if x).strip()
            else:
                nm = str(person or "").strip()
            nm = nm or _name(row)
        else:
            nm = str(row or "").strip()
        if nm:
            lobbyists.append(nm)

    issues = []
    for act in item.get("lobbying_activities") or []:
        if not isinstance(act, dict):
            continue
        code = (act.get("general_issue_code_display")
                or act.get("general_issue_code") or "").strip()
        desc = (act.get("description") or "").strip()
        text = (code + (": " + desc if desc else "")).strip()
        if text:
            issues.append(text[:500])

    url = item.get("url") or item.get("filing_url") or ""
    if isinstance(url, str) and url.startswith("/"):
        url = "https://lda.senate.gov" + url
    fid = item.get("id") or item.get("filing_uuid") or url
    return {
        "source": "us_senate_lda",
        "id": fid,
        "title": (client + " — " + registrant).strip(" —") or "Lobbying filing",
        "client": client,
        "registrant": registrant,
        "lobbyists": lobbyists[:20],
        "issues": issues[:20],
        "amount": _amount(item.get("income") or item.get("expenses")),
        "year": item.get("filing_year"),
        "period": item.get("filing_period") or item.get("filing_type") or "",
        "date": item.get("dt_posted") or item.get("filing_date") or "",
        "url": url,
    }


def _fetch(field, query, year, limit):
    params = {field: query, "page_size": min(max(int(limit), 1), 50)}
    if year:
        params["filing_year"] = year
    r = _get(LDA, params=params)
    if isinstance(r, Exception):
        return {"source": field, "status": "error",
                "error": str(r)[:150], "results": []}
    if _blocked(r.status_code):
        return {"source": field, "status": "blocked", "http": r.status_code,
                "error": f"HTTP {r.status_code}",
                "note": "lda.gov network-level access control; try from an allowed network",
                "results": []}
    if r.status_code != 200:
        return {"source": field, "status": "error", "http": r.status_code,
                "error": f"HTTP {r.status_code}", "results": []}
    try:
        j = r.json()
    except Exception:
        return {"source": field, "status": "error",
                "error": "non-JSON response (anti-bot page?)", "results": []}
    rows = j.get("results") or j.get("data") or []
    return {"source": field, "status": "ok", "count": len(rows),
            "total": j.get("count"), "results": [_normalize(x) for x in rows]}


def search(query, year=None, limit=25, case_id=None, user="system"):
    """Search LDA filings by client name and registrant name."""
    query = (query or "").strip()
    if not query:
        return {"status": "error", "error": "query required", "results": []}
    limit = max(1, min(int(limit or 25), 50))

    year_val = str(year).strip() if year not in (None, "") else str(
        datetime.date.today().year)
    if year_val.lower() in ("all", "*"):
        year_val = None

    jobs = [("client_name", lambda: _fetch("client_name", query, year_val, limit)),
            ("registrant_name", lambda: _fetch("registrant_name", query, year_val, limit))]
    results, statuses, seen = [], {}, set()
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = {ex.submit(fn): name for name, fn in jobs}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                part = fut.result()
            except Exception as e:
                part = {"source": name, "status": "error",
                        "error": str(e)[:150], "results": []}
            statuses[name] = {k: part.get(k) for k in
                              ("status", "count", "total", "http", "error", "note")
                              if part.get(k) is not None}
            for row in part.get("results") or []:
                key = row.get("id") or (row.get("client"), row.get("registrant"),
                                        row.get("date"), row.get("period"))
                if key in seen:
                    continue
                seen.add(key)
                results.append(row)

    results.sort(key=lambda x: (x.get("date") or ""), reverse=True)
    status = "ok"
    if statuses and all(v.get("status") == "blocked" for v in statuses.values()):
        status = "blocked"
    elif statuses and all(v.get("status") == "error" for v in statuses.values()):
        status = "error"

    out = {"status": status, "query": query, "year": year_val,
           "count": len(results), "results": results, "sources": statuses}
    try:
        db.audit(user, "lobbying.search", query[:80],
                 f"year={year_val} n={len(results)}")
        if case_id:
            db.store_artifact(case_id, None, "lobbying", "lobbying:search",
                              out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out
