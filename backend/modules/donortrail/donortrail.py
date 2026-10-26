"""Xaxglog donortrail — political finance trails (FEC + disclosure portals).

Optional (env FEC_API_KEY — free at api.open.fec.gov): full FEC campaign
finance API — candidate/committee receipts, individual contributions by
zip/employer, independent expenditures.

Keyless core:
  - FEC bulk data file index (bulk file listing, no key) — shows what
    datasets exist for offline mirror pulls (via ops module).
  - Jurisdiction directory: which regulator publishes donor data per
    country (US FEC, UK Electoral Commission, EU Transparency Register,
    CA Elections Canada, AU AEC, etc.) with deep links.

Output: donor/recipient edges + aggregation (top employers, zip
concentration, PAC flows), stored as case artifacts when case_id given.

Lawful-use note: political finance records are published for
transparency. Use per the regulator's terms; donations data is personal
data in some jurisdictions — proportionality applies.
"""
import os

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
FEC_SEARCH = "https://api.open.fec.gov/v1/"
BULK_INDEX = "https://www.fec.gov/files/bulk-data/"

JURISDICTIONS = {
    "US": {"regulator": "Federal Election Commission",
           "portal": "https://www.fec.gov/data/", "api": "https://api.open.fec.gov/v1/",
           "key_required": True, "datasets": ["candidate", "committee", "individual",
                                              "expenditure", "independent_expenditure"]},
    "GB": {"regulator": "Electoral Commission",
           "portal": "https://www.electoralcommission.org.uk/campaigning-and-political-people/political-registers-and-donations",
           "key_required": False, "datasets": ["donations", "loans", "permissible"]},
    "EU": {"regulator": "EU Transparency Register",
           "portal": "https://ec.europa.eu/transparencyregister/",
           "key_required": False, "datasets": ["meetings", "interest-representatives"]},
    "CA": {"regulator": "Elections Canada",
           "portal": "https://www.elections.ca/content.aspx?section=res&dir=rep/fin&document=index&lang=e",
           "key_required": False, "datasets": ["returns", "contributions"]},
    "AU": {"regulator": "Australian Electoral Commission",
           "portal": "https://www.aec.gov.au/Party_and_Candidate_Disclosure/",
           "key_required": False, "datasets": ["donor-report", "candidate-donations"]},
    "DE": {"regulator": "Bundesregister für politische Vereine / Bundestag",
           "portal": "https://www.bundestag.de/services/parteien",
           "key_required": False, "datasets": ["party-finance"]},
    "FR": {"regulator": "Haute Autorité pour la transparence de la vie publique",
           "portal": "https://www.hatvp.fr", "key_required": False,
           "datasets": ["declarations", "interests"]},
    "IN": {"regulator": "Election Commission of India (CFMS)",
           "portal": "https://cfms.eci.gov.in", "key_required": False,
           "datasets": ["candidate-affidavits", "party-accounts"]},
    "BR": {"regulator": "TSE - Divulgação de Candidaturas",
           "portal": "https://divulgacandcontas.tse.jus.br", "key_required": False,
           "datasets": ["campaign-finance", "donors"]},
}


def _fec(path, params):
    import requests
    key = os.getenv("FEC_API_KEY")
    if not key:
        return None
    params = dict(params, api_key=key)
    r = requests.get(FEC_SEARCH + path, headers=UA, params=params, timeout=T)
    if r.status_code != 200:
        raise RuntimeError(f"FEC HTTP {r.status_code}")
    return r.json()


def candidate(q):
    """Search FEC candidates by name/ticker (FEC key required)."""
    try:
        if not os.getenv("FEC_API_KEY"):
            return {"status": "unconfigured",
                    "error": "FEC_API_KEY required (free: api.open.fec.gov signup)",
                    "keyless_hint": "use directory() for jurisdiction portals"}
        j = _fec("candidates/search", {"q": q, "per_page": 10})
        if not j:
            return {"status": "error", "error": "FEC unavailable"}
        rows = [{
            "name": r.get("name"), "candidate_id": r.get("candidate_id"),
            "party": r.get("party"), "office": r.get("office_full"),
            "state": r.get("state"), "incumbent": r.get("incumbent_challenge"),
            "cycles": r.get("cycles"),
        } for r in j.get("results", [])]
        db.audit("system", "donortrail.candidate", q, f"n={len(rows)}")
        return {"status": "ok", "query": q, "count": len(rows), "candidates": rows}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "candidates": []}


def receipts(candidate_id, cycle=2024, per_page=40):
    """Top receipts for a candidate — employers/zips/contributors (FEC key)."""
    try:
        if not os.getenv("FEC_API_KEY"):
            return {"status": "unconfigured", "error": "FEC_API_KEY required"}
        j = _fec("candidate/{cid}/receipts".format(cid=candidate_id),
                 {"two_year_transaction_period": cycle, "per_page": per_page,
                  "sort": "-contribution_receipt_amount"})
        if not j:
            return {"status": "error", "error": "FEC unavailable"}
        rows = [{
            "donor": r.get("contributor_name"),
            "employer": r.get("contributor_employer"),
            "city": r.get("contributor_city"), "state": r.get("contributor_state"),
            "zip": r.get("contributor_zip"),
            "amount": r.get("contribution_receipt_amount"),
            "date": r.get("contribution_receipt_date"),
            "committee": r.get("committee_name"),
        } for r in j.get("results", [])]
        # aggregate: employer concentration + zip concentration
        employers, zips = {}, {}
        for r in rows:
            if r["employer"]:
                employers[r["employer"]] = employers.get(r["employer"], 0) + 1
            if r["zip"]:
                zips[str(r["zip"])[:5]] = zips.get(str(r["zip"])[:5], 0) + 1
        report = {
            "count": len(rows), "receipts": rows,
            "top_employers": sorted(employers.items(), key=lambda x: -x[1])[:10],
            "top_zips": sorted(zips.items(), key=lambda x: -x[1])[:10],
        }
        return {"status": "ok", "candidate_id": candidate_id, **report}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def committee_flows(committee_id, cycle=2024, limit=40):
    """Committee -> committee transfers (PAC influence map), FEC key."""
    try:
        if not os.getenv("FEC_API_KEY"):
            return {"status": "unconfigured", "error": "FEC_API_KEY required"}
        j = _fec("schedules/schedule_b",
                 {"committee_id": committee_id, "cycle": cycle,
                  "per_page": limit, "sort": "-disbursement_amount"})
        if not j:
            return {"status": "error", "error": "FEC unavailable"}
        rows = [{"recipient": r.get("recipient_name"),
                 "recipient_committee": r.get("recipient_committee_id"),
                 "amount": r.get("disbursement_amount"),
                 "date": r.get("disbursement_date"),
                 "purpose": r.get("disbursement_purpose_description")}
                for r in j.get("results", [])]
        db.audit("system", "donortrail.committee_flows", committee_id, f"n={len(rows)}")
        return {"status": "ok", "committee_id": committee_id,
                "count": len(rows), "flows": rows}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "flows": []}


def bulk_index():
    """FEC bulk-data file index (keyless page listing)."""
    try:
        import requests
        r = requests.get(BULK_INDEX, headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        links = sorted(set(__import__("re").findall(
            r'href="([^"]*(?: bulk|/bulk)[^"]*\.zip)"', r.text)))[:40]
        return {"status": "ok", "index_url": BULK_INDEX, "files": links,
                "note": "download via ops module mirrors for offline analysis"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def directory():
    return {"status": "ok", "count": len(JURISDICTIONS), "jurisdictions": JURISDICTIONS}
