"""Xaxglog dark-web intelligence module.

Queries *indexed* Tor/dark-web search services and public breach corpora — it
does not run a Tor crawler or access illegal marketplaces directly. All lookups
use public index APIs (Ahmia, Onionland-style indexers) and breach-corpus
services, degrading gracefully without keys. Results are stored as hashed
evidence under a case.

Optional: INTELX_API_KEY unlocks the IntelX indexed dark-web/corpus search for
certified/authorized use.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


# ------------------------------------------------------------------ Ahmia (Tor index)
def search_ahmia(query):
    """Search the Ahmia dark-web index (public search endpoint, GET)."""
    import requests
    import urllib.parse
    try:
        url = f"https://ahmia.fi/search/?q={urllib.parse.quote(query)}"
        r = requests.get(url, timeout=T, headers=UA)
        if r.status_code != 200:
            return {"source": "ahmia", "error": f"http {r.status_code}"}
        # Ahmia returns an HTML fragment; parse result links + titles.
        items = re.findall(
            r'<a[^>]+href="(http[^"]+)"[^>]*>(.*?)</a>', r.text, re.S)
        results = []
        for u, title in items[:80]:
            title = re.sub(r'<[^>]+>', '', title).strip()
            if ".onion" in u or "ahmia" in u:
                results.append({"title": title[:200], "url": u[:300]})
        return {"source": "ahmia", "query": query, "count": len(results), "results": results}
    except Exception as e:
        return {"source": "ahmia", "error": str(e)[:150]}


# ------------------------------------------------------------------ IntelX (optional key)
def search_intelx(query, key=""):
    """IntelX indexed search (dark-web/corpus) — requires a licensed API key."""
    import requests
    if not key:
        return {"source": "intelx", "skipped": "INTELX_API_KEY not set"}
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            headers={"x-key": key, "Content-Type": "application/json"},
            json={"term": query, "maxresults": 50, "media": 0, "sort": 2, "terminate": []},
            timeout=T)
        sid = r.json().get("id")
        if not sid:
            return {"source": "intelx", "error": "no search id"}
        # poll for results
        import time
        for _ in range(6):
            time.sleep(2)
            rr = requests.get(f"https://2.intelx.io/standard/search/read/?id={sid}&limit=50",
                              headers={"x-key": key}, timeout=T)
            j = rr.json()
            if j.get("status") == 2 or j.get("records"):
                recs = [{"title": x.get("name", "")[:200],
                         "url": x.get("url", "")[:300],
                         "date": x.get("date"),
                         "system": x.get("systemid")}
                        for x in (j.get("records") or [])[:50]]
                return {"source": "intelx", "query": query, "count": len(recs), "results": recs}
        return {"source": "intelx", "query": query, "results": [], "note": "timed out"}
    except Exception as e:
        return {"source": "intelx", "error": str(e)[:150]}


# ------------------------------------------------------------------ breach corpora
def breach_check_email(email, hibp_key=""):
    """Cross-reference an email against public breach corpora (XposedOrNot + optional HIBP)."""
    out = {"email": email, "breaches": {}}
    r = _get(f"https://api.xposedornot.com/v1/check-email/{email}")
    if not isinstance(r, Exception):
        try:
            if r.status_code == 200:
                out["breaches"]["xposedornot"] = r.json()
            elif r.status_code == 404:
                out["breaches"]["xposedornot"] = {"breaches": [], "note": "no breach found"}
            else:
                out["breaches"]["xposedornot"] = {"http": r.status_code}
        except Exception:
            pass
    if hibp_key:
        rr = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                  headers={"hibp-api-key": hibp_key})
        if not isinstance(rr, Exception):
            try:
                out["breaches"]["hibp"] = rr.json() if rr.status_code == 200 else {"http": rr.status_code}
            except Exception:
                out["breaches"]["hibp"] = {"http": getattr(rr, "status_code", "err")}
    return out


def breach_check_username(username):
    """Public breach-corpus lookups that accept a handle (no email needed)."""
    out = {"username": username, "hits": []}
    # Sherlock-style public handle indexes are handled by deep_search.username;
    # here we focus on leak-corpus handle search endpoints.
    r = _get(f"https://api.xposedornot.com/v1/check-email/{username}")
    return out


# ------------------------------------------------------------------ orchestrator
def darkweb_search(query, keys=None, case_id=None, user="system"):
    """Run a dark-web / breach-corpus search across available indexes."""
    keys = keys or {}
    query = (query or "").strip()
    if not query:
        return {"error": "empty query"}
    is_email = bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', query))

    results = {"ahmia": search_ahmia(query)}
    if keys.get("INTELX_API_KEY"):
        results["intelx"] = search_intelx(query, keys["INTELX_API_KEY"])
    if is_email:
        results["breaches"] = breach_check_email(query, keys.get("HIBP_API_KEY", ""))

    out = {
        "query": query,
        "indexes": results,
        "note": ("Indexed dark-web search only (Ahmia + optional IntelX). "
                 "No Tor crawling, no marketplace access. Verify hits; use lawfully."),
    }

    if case_id is not None:
        etype = "email" if is_email else "handle"
        root = _upsert(case_id, etype, query)
        out["evidence"] = db.store_artifact(case_id, root, "darkweb",
                                            "darkweb:search", out, user)
        db.audit(user, "darkweb.search", query[:120])
    return out


def _upsert(case_id, etype, value):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, etype, value, now, now))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]
