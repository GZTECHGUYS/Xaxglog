"""Xaxglog filings — corporate disclosure trail from SEC EDGAR (keyless).

Open, keyless sources:
  - SEC EDGAR full-text search (efts.sec.gov) — 2001+ filings, JSON.
  - SEC EDGAR company/submissions API (data.sec.gov) — filing history by
    CIK, with SEC's required User-Agent and self-throttling.

Queries: company name/ticker -> CIK, recent filings by form type, and
full-text search for a name/domain/keyword inside filings (8-Ks, 10-Ks,
S-1s, Form 4 insider transactions). Complements corporate (ownership
graph via GLEIF/Wikidata) and worldcorp (LEI/VAT) with the US disclosure
axis: who wrote what, when, under signature.

Lawful-use note: SEC publishes these documents for public inspection.
Respect SEC fair-access policy: declared User-Agent, <=10 req/s.
"""
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (research; contact ops@localhost)"}
T = 25
TICKERS = "https://www.sec.gov/files/company_tickers.json"
FULLTEXT = "https://efts.sec.gov/LATEST/search-index"
SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
_last = [0.0]


def _sec_get(url, params=None):
    import requests
    wait = 0.12 - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    r = requests.get(url, headers=UA, params=params, timeout=T)
    _last[0] = time.time()
    if r.status_code == 429:
        return {"status": "throttled", "error": "SEC rate limit — slow down"}
    if r.status_code != 200:
        return {"status": "error", "error": f"HTTP {r.status_code}"}
    return {"status": "ok", "data": r.json()}


def company(q):
    """Resolve company name or ticker -> EDGAR CIK + metadata (keyless)."""
    try:
        q = (q or "").strip()
        if not q:
            return {"status": "error", "error": "empty query"}
        out = _sec_get(TICKERS)
        if out["status"] != "ok":
            return out
        ql = q.lower()
        hits = []
        for row in out["data"].values():
            title = (row.get("title") or "").lower()
            if ql.isalnum() and len(ql) <= 6 and row.get("ticker", "").lower() == ql:
                hits.append({"cik": row.get("cik_str"), "ticker": row.get("ticker"),
                             "title": row.get("title")})
            elif ql in title:
                hits.append({"cik": row.get("cik_str"), "ticker": row.get("ticker"),
                             "title": row.get("title")})
            if len(hits) >= 15:
                break
        return {"status": "ok", "query": q, "count": len(hits), "companies": hits}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "companies": []}


def filings(cik, forms=None, limit=25):
    """Recent filings for a CIK (optionally filtered by form type)."""
    try:
        cik = int(cik)
        out = _sec_get(SUBMISSIONS.format(cik=cik))
        if out["status"] != "ok":
            return out
        j = out["data"]
        recent = j.get("filings", {}).get("recent", {})
        forms_f = recent.get("form", [])
        dates = recent.get("filingDate", [])
        accns = recent.get("accessionNumber", [])
        docs = recent.get("primaryDocument", [])
        desc = recent.get("primaryDocDescription", [])
        want = {f.upper() for f in forms} if forms else None
        rows = []
        for i, form in enumerate(forms_f):
            if want and form.upper() not in want:
                continue
            accn = accns[i].replace("-", "")
            rows.append({
                "form": form, "filed": dates[i], "accession": accns[i],
                "description": desc[i] if i < len(desc) else None,
                "document": f"https://www.sec.gov/Archives/edgar/data/{cik}/{accn}/{docs[i]}"
                if i < len(docs) else None,
                "index": f"https://www.sec.gov/Archives/edgar/data/{cik}/{accn}/",
            })
            if len(rows) >= int(limit):
                break
        db.audit("system", "filings.filings", str(cik), f"n={len(rows)}")
        return {"status": "ok", "cik": cik, "name": j.get("name"),
                "sic": j.get("sicDescription"), "count": len(rows), "filings": rows}
    except ValueError:
        return {"status": "error", "error": "CIK must be numeric"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "filings": []}


def fulltext(q, forms=None, date_range=None, limit=25):
    """EDGAR full-text search: name/domain/keyword inside filings (keyless).

    date_range = "YYYYMMDD-YYYYMMDD"; forms = e.g. ["8-K","10-K"].
    """
    try:
        q = (q or "").strip()
        if not q:
            return {"status": "error", "error": "empty query"}
        params = {"q": q}
        if forms:
            if isinstance(forms, str):
                forms = [forms]
            params["forms"] = ",".join(forms)
        if date_range:
            params["dateRange"] = "custom"
            params["startdt"] = date_range.split("-")[0]
            params["enddt"] = date_range.split("-")[1]
        out = _sec_get(FULLTEXT, params)
        if out["status"] != "ok":
            return out
        j = out["data"]
        hits = []
        for h in (j.get("hits", {}).get("hits") or [])[:limit]:
            src = h.get("_source", {})
            hits.append({
                "form": src.get("file_type"),
                "filed": src.get("file_date"),
                "company": (src.get("display_names") or [None])[0],
                "cik": src.get("ciks", [None])[0] if src.get("ciks") else None,
                "score": h.get("_score"),
            })
        db.audit("system", "filings.fulltext", q, f"n={len(hits)}")
        return {"status": "ok", "query": q, "total": j.get("hits", {}).get("total"),
                "count": len(hits), "results": hits}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "results": []}


def insider(q, limit=20):
    """Shortcut: full-text search restricted to Form 4 (insider transactions)."""
    return fulltext(q, forms=["4"], limit=limit)
