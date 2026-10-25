"""Xaxglog nonprofit intelligence — ProPublica Nonprofit Explorer (IRS data).

Sources:
  - ProPublica Nonprofit Explorer API v2 (free, keyless)
      search: /api/v2/search.json
      org:    /api/v2/organizations/<EIN>.json
    Data is derived from IRS Form 990 filings and the IRS exempt-organization
    master file. It is public-record data, not a private database.

The module exposes organization search (name, optional state) and an EIN
lookup with recent filing summaries. Financial figures are the filer's
reported values; verify against the original Form 990 before relying on them.

Lawful-use note: low-volume identified requests to an official public
transparency API. No authentication, scraping behind walls, or bulk mirroring.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0", "Accept": "application/json"}
T = 25
BASE = "https://projects.propublica.org/nonprofits/api/v2"
SEARCH = BASE + "/search.json"
ORG = BASE + "/organizations/{ein}.json"

SOURCES = [{
    "id": "propublica_nonprofit",
    "label": "ProPublica Nonprofit Explorer",
    "region": "US",
    "what": "IRS-registered nonprofits, Form 990 financial summaries, EIN lookup",
    "url": "https://projects.propublica.org/nonprofits/",
    "hint": "organization name or 9-digit EIN",
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


def _org_url(ein):
    return "https://projects.propublica.org/nonprofits/organizations/" + str(ein)


def _summary(org):
    ein = org.get("ein") or org.get("strein") or ""
    return {
        "source": "propublica_nonprofit",
        "ein": str(ein),
        "name": org.get("name") or "",
        "city": org.get("city") or "",
        "state": org.get("state") or "",
        "ntee_code": org.get("ntee_code") or "",
        "subsection": org.get("subseccd") or org.get("subsection_code") or "",
        "ruling_date": org.get("ruling_date") or "",
        "score": org.get("score"),
        "url": _org_url(ein) if ein else "",
    }


def search(query, state=None, limit=20, case_id=None, user="system"):
    """Search IRS-registered nonprofits by name, optionally filtered by state."""
    query = (query or "").strip()
    if not query:
        return {"status": "error", "error": "query required", "results": []}
    limit = max(1, min(int(limit or 20), 50))
    params = {"q": query}
    if state:
        params["state[id]"] = str(state).strip().upper()[:2]

    r = _get(SEARCH, params=params)
    if isinstance(r, Exception):
        return {"status": "error", "error": str(r)[:150], "results": []}
    if _blocked(r.status_code):
        return {"status": "blocked", "http": r.status_code,
                "error": f"HTTP {r.status_code}", "results": []}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code,
                "error": f"HTTP {r.status_code}", "results": []}
    try:
        j = r.json()
    except Exception:
        return {"status": "error", "error": "non-JSON response", "results": []}

    rows = [_summary(x) for x in (j.get("organizations") or [])[:limit]]
    out = {"status": "ok", "query": query, "state": params.get("state[id]", ""),
           "count": len(rows), "total": j.get("total_results"),
           "results": rows}
    try:
        db.audit(user, "nonprofit.search", query[:80],
                 f"state={params.get('state[id]', '')} n={len(rows)}")
        if case_id:
            db.store_artifact(case_id, None, "nonprofit", "nonprofit:search",
                              out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out


def organization(ein, case_id=None, user="system"):
    """Fetch one nonprofit by 9-digit EIN, including recent Form 990 summaries."""
    raw = str(ein or "").strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return {"status": "error",
                "error": "EIN must contain exactly 9 digits", "ein": raw}
    r = _get(ORG.format(ein=digits))
    if isinstance(r, Exception):
        return {"status": "error", "error": str(r)[:150], "ein": digits}
    if r.status_code == 404:
        return {"status": "not_found", "error": "EIN not found", "ein": digits}
    if _blocked(r.status_code):
        return {"status": "blocked", "http": r.status_code,
                "error": f"HTTP {r.status_code}", "ein": digits}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code,
                "error": f"HTTP {r.status_code}", "ein": digits}
    try:
        j = r.json()
    except Exception:
        return {"status": "error", "error": "non-JSON response", "ein": digits}

    org = _summary(j.get("organization") or {})
    org["ein"] = digits
    filings = []
    for f in (j.get("filings_with_data") or [])[:12]:
        filings.append({
            "year": f.get("tax_prd_yr"),
            "form": f.get("formtype"),
            "revenue": f.get("totrevenue"),
            "expenses": f.get("totfuncexpns"),
            "assets": f.get("totassetsend"),
            "pdf_url": f.get("pdf_url") or "",
        })
    out = {"status": "ok", "ein": digits, "organization": org,
           "filings": filings,
           "filings_without_data": len(j.get("filings_without_data") or [])}
    try:
        db.audit(user, "nonprofit.organization", digits,
                 f"filings={len(filings)}")
        if case_id:
            db.store_artifact(case_id, None, "nonprofit", "nonprofit:org",
                              out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out
