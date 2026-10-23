"""Xaxglog corporate intelligence — GLEIF LEI registry, EU VAT (VIES), UK Companies House.

Free, keyless corporate data:
  - GLEIF (Global Legal Entity Identifier Foundation) LEI records:
      search by legal name, fetch by LEI, and resolve direct-parent /
      direct-child relationships (probed live: the `filter[direct.*.lei]`
      query filters return HTTP 400 on the public API, so relationships are
      resolved via the record's `relationships` block + the
      /lei-records/<lei>/direct-children endpoint, which works keyless).
  - EU VIES VAT validation SOAP service (works for EU-27; GB left VIES
    post-Brexit and returns an INVALID_INPUT fault — handled gracefully).
  - UK Companies House search — only with optional CH_API_KEY env var,
    otherwise skipped (no key = no request).

Lawful-use note: GLEIF, VIES and Companies House all publish this data
officially and free of charge for legitimate due-diligence. Requests are
low-volume, identified via User-Agent and cache-friendly; no credentials,
scraping or bulk mirroring of paywalled registries.
"""
import os
import re
import xml.etree.ElementTree as ET

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
GLEIF = "https://api.gleif.org/api/v1/lei-records"
VIES_PRODS = [
    "https://ec.europa.eu/taxation_customs/vies/services/checkVatService",
    "http://ec.europa.eu/taxation_customs/vies/services/checkVatService",
]
VIES_SANDBOX = "https://ec.europa.eu/taxation_customs/vies/checkVatTestService"
CH = "https://api.company-information.service.gov.uk"

# EU member-state ISO codes currently in VIES (GB left post-Brexit).
VIES_CC = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
           "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
           "RO", "SK", "SI", "ES", "SE", "XI"}  # XI = Northern Ireland


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _parse_record(rec):
    """GLEIF JSON:API record -> flat dict."""
    a = (rec or {}).get("attributes", {}) or {}
    ent = a.get("entity", {}) or {}
    legal = ent.get("legalAddress", {}) or {}
    hq = ent.get("headquartersAddress", {}) or {}
    rel = (rec or {}).get("relationships", {}) or {}

    def _rel_lei(key):
        try:
            return rel.get(key, {}).get("data", {}).get("id")
        except Exception:
            return None
    return {
        "lei": rec.get("id"),
        "name": (ent.get("legalName") or {}).get("name"),
        "status": ent.get("status"),
        "jurisdiction": ent.get("jurisdiction"),
        "category": ent.get("category"),
        "legal_form": ent.get("legalForm"),
        "legal_country": legal.get("country"),
        "legal_city": legal.get("city"),
        "legal_address": ", ".join(legal.get("addressLines") or []) + (
            f", {legal.get('postalCode')}" if legal.get("postalCode") else ""),
        "hq_country": hq.get("country"),
        "hq_city": hq.get("city"),
        "parent_lei": _rel_lei("direct-parent"),
        "ultimate_parent_lei": _rel_lei("ultimate-parent"),
        "source": "gleif",
    }


def gleif_search(name, cap=15):
    """Search GLEIF LEI records by legal name (keyless)."""
    url = f"{GLEIF}?filter%5Bentity.legalName%5D={_q(name)}&page%5Bsize%5D={int(cap)}"
    r = _get(url)
    if isinstance(r, Exception):
        return {"error": str(r)[:150], "results": []}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}", "results": []}
    try:
        j = r.json()
    except Exception as e:
        return {"error": f"bad json: {e}", "results": []}
    recs = [_parse_record(x) for x in (j.get("data") or [])]
    total = (j.get("meta", {}) or {}).get("pagination", {}).get("total")
    return {"query": name, "total": total, "count": len(recs), "results": recs}


def _q(s):
    import urllib.parse
    return urllib.parse.quote(str(s or ""))


def gleif_by_lei(lei):
    """Fetch one GLEIF record by LEI (keyless)."""
    r = _get(f"{GLEIF}/{_q(lei)}")
    if isinstance(r, Exception):
        return {"error": str(r)[:150]}
    if r.status_code == 404:
        return {"error": "LEI not found", "lei": lei}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}", "lei": lei}
    try:
        j = r.json()
    except Exception as e:
        return {"error": f"bad json: {e}", "lei": lei}
    return _parse_record(j.get("data") or {})


def gleif_relationships(lei, cap=25):
    """Direct parent + direct children of a LEI.

    Probed live: `filter[direct.parent.lei]` / `filter[direct.child.lei]`
    return 400 on the public API, so children are resolved via the
    /lei-records/<lei>/direct-children endpoint and the parent via the
    record's relationships block (then a lookup fetch for name/country).
    """
    out = {"lei": lei, "parents": [], "children": [], "notes": []}
    try:
        rec = gleif_by_lei(lei)
        if rec.get("error"):
            out["error"] = rec["error"]
            return out
        for key, label in (("direct-parent", "direct_parent"),
                           ("ultimate-parent", "ultimate_parent")):
            pid = rec.get("parent_lei") if key == "direct-parent" else rec.get("ultimate_parent_lei")
            if pid:
                p = gleif_by_lei(pid)
                out["parents"].append({"lei": pid, "name": p.get("name"),
                                       "country": p.get("legal_country"),
                                       "relationship": label})
        r = _get(f"{GLEIF}/{_q(lei)}/direct-children?page%5Bsize%5D={int(cap)}")
        if not isinstance(r, Exception) and r.status_code == 200:
            j = r.json()
            for d in (j.get("data") or []):
                ent = (d.get("attributes", {}) or {}).get("entity", {}) or {}
                out["children"].append({
                    "lei": d.get("id"),
                    "name": (ent.get("legalName") or {}).get("name"),
                    "country": (ent.get("legalAddress") or {}).get("country"),
                })
            total = (j.get("meta", {}) or {}).get("pagination", {}).get("total")
            out["children_total"] = total
        else:
            st = getattr(r, "status_code", "err")
            out["notes"].append(f"direct-children endpoint HTTP {st}")
        db.audit("system", "worldcorp.gleif_relationships", lei,
                 f"parents={len(out['parents'])} children={len(out['children'])}")
        return out
    except Exception as e:
        return {"error": str(e)[:150], "lei": lei}


def vies_vat(vat, sandbox=False):
    """Validate an EU VAT number against VIES (SOAP, keyless).

    Accepts "NL812345678B01" or ("NL","812345678B01"). GB numbers are
    reported as no-longer-served (post-Brexit); VIES faults such as
    MS_UNAVAILABLE / TIMEOUT are surfaced, never raised.
    """
    vat = (vat or "").strip().upper().replace(" ", "").replace("-", "")
    m = re.match(r"^([A-Z]{2})(\d.*)$", vat)
    if not m:
        return {"error": "unrecognised VAT format — expected <ISO-country><number>", "input": vat}
    cc, num = m.group(1), m.group(2)
    if cc == "GB":
        return {"valid": None, "country_code": "GB", "vat_number": num,
                "note": "GB left VIES on 2020-01-01 (post-Brexit); numbers can no longer be validated here",
                "status": "unsupported_country"}
    if cc not in VIES_CC:
        return {"valid": None, "country_code": cc, "vat_number": num,
                "note": f"{cc} is not a VIES-served country", "status": "unsupported_country"}
    ns = "urn:ec.europa.eu:taxud:vies:services:checkVat:types"
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
           f'xmlns:urn="{ns}">'
           "<soap:Body>"
           f"<urn:checkVat><urn:countryCode>{cc}</urn:countryCode>"
           f"<urn:vatNumber>{num}</urn:vatNumber></urn:checkVat>"
           "</soap:Body></soap:Envelope>")
    import requests
    urls = ([VIES_SANDBOX] if sandbox else VIES_PRODS + [VIES_SANDBOX])
    last_err = None
    for url in urls:
        try:
            r = requests.post(url, data=xml.encode("utf-8"),
                              headers={**UA, "Content-Type": "text/xml; charset=utf-8",
                                       "SOAPAction": ""},
                              timeout=T)
        except Exception as e:
            last_err = str(e)[:150]
            continue
        text = r.text
        if "<soap:Fault>" in text or "<env:Fault>" in text or "Fault>" in text:
            fm = re.search(r"<faultstring>([^<]+)</faultstring>", text)
            fault = fm.group(1) if fm else "SOAP_FAULT"
            if fault in ("INVALID_INPUT", "INVALID_COUNTRY"):
                note = ("GB left VIES post-Brexit — validation unavailable"
                        if cc == "GB" else f"VIES rejected input: {fault}")
                return {"valid": None, "country_code": cc, "vat_number": num,
                        "status": "invalid_input", "note": note}
            if fault in ("MS_UNAVAILABLE", "TIMEOUT", "SERVICE_UNAVAILABLE"):
                last_err = f"VIES member-state unavailable ({fault})"
                continue  # try next endpoint
            return {"valid": None, "country_code": cc, "vat_number": num,
                    "status": "fault", "error": fault[:150]}
        if r.status_code != 200:
            last_err = f"HTTP {r.status_code} at {url}"
            continue
        def _f(tag):
            m2 = re.search(rf"<(?:\w+:)?{tag}>([^<]*)</(?:\w+:)?{tag}>", text)
            return m2.group(1).strip() if m2 else None
        valid = _f("valid")
        result = {
            "valid": (valid == "true") if valid is not None else None,
            "country_code": _f("countryCode") or cc,
            "vat_number": _f("vatNumber") or num,
            "company_name": (_f("name") or "") or None,
            "address": (_f("address") or "") or None,
            "request_date": _f("requestDate"),
            "source": url,
        }
        db.audit("system", "worldcorp.vies_vat", f"{cc}{num}",
                 f"valid={result['valid']}")
        return result
    return {"error": last_err or "VIES unreachable", "country_code": cc,
            "vat_number": num, "status": "error"}


def companies_house(name):
    """UK Companies House search — requires CH_API_KEY (HTTP basic auth)."""
    key = os.environ.get("CH_API_KEY", "")
    if not key:
        return {"skipped": "CH_API_KEY not set"}
    import requests
    from requests.auth import HTTPBasicAuth
    try:
        r = requests.get(f"{CH}/search/companies", params={"q": name, "items_per_page": 15},
                         auth=HTTPBasicAuth(key, ":"), headers=UA, timeout=T)
        if r.status_code == 401:
            return {"error": "CH_API_KEY rejected (HTTP 401)"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        j = r.json()
        out = []
        for it in (j.get("items") or []):
            addr = it.get("address") or {}
            out.append({
                "title": it.get("title"),
                "company_number": it.get("company_number"),
                "company_status": it.get("company_status"),
                "company_type": it.get("company_type"),
                "jurisdiction": it.get("jurisdiction"),
                "address": ", ".join([addr.get("line_1") or "", addr.get("city") or "",
                                      addr.get("country") or ""]),
                "url": it.get("links", {}).get("self"),
            })
        db.audit("system", "worldcorp.companies_house", name[:80], f"n={len(out)}")
        return {"query": name, "count": len(out), "results": out}
    except Exception as e:
        return {"error": str(e)[:150]}


# ------------------------------------------------------------- case linking

def _upsert(case_id, etype, value, meta=None):
    import json
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, etype, value, now, now, json.dumps(meta or {})))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def _edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()))
    c.commit()


def link_to_case(case_id, gleif_result, user="system"):
    """Attach a GLEIF record (search item or gleif_by_lei dict) to a case.

    Upserts the company entity plus its registered-country geo entity and,
    where known, the parent company; emits subsidiary_of / office_in edges
    and stores a hashed evidence artifact.
    """
    try:
        if not gleif_result or gleif_result.get("error") or not gleif_result.get("name"):
            return {"error": "no usable GLEIF record (expect gleif_search item or gleif_by_lei dict)"}
        name = gleif_result["name"]
        cid = _upsert(case_id, "company", name, {
            "lei": gleif_result.get("lei"),
            "jurisdiction": gleif_result.get("jurisdiction"),
            "status": gleif_result.get("status"),
        })
        geo_id = None
        cc = gleif_result.get("legal_country")
        if cc:
            geo_val = f"{gleif_result.get('legal_city') or ''} ({cc})".strip(" (")
            geo_id = _upsert(case_id, "geo", geo_val, {"country": cc})
            _edge(case_id, cid, geo_id, "office_in", 1.0, "worldcorp:gleif")
        parent_id = None
        if gleif_result.get("parent_lei"):
            plei = gleif_result["parent_lei"]
            prec = gleif_by_lei(plei)
            pname = prec.get("name") or plei
            parent_id = _upsert(case_id, "company", pname, {"lei": plei})
            _edge(case_id, cid, parent_id, "subsidiary_of", 1.0, "worldcorp:gleif")
        art = db.store_artifact(case_id, cid, "corporate", "worldcorp:gleif",
                                dict(gleif_result), user)
        db.audit(user, "worldcorp.link_to_case", name[:80],
                 f"case={case_id} artifact={art['id']} parent={bool(parent_id)} geo={bool(geo_id)}")
        return {"linked": True, "entity_id": cid, "geo_entity_id": geo_id,
                "parent_entity_id": parent_id, "artifact": art}
    except Exception as e:
        return {"error": str(e)[:150]}
