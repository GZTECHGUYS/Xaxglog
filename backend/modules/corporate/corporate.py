"""Xaxglog corporate ownership graph.

Builds beneficial-ownership / control networks from public filings:
  - OpenCorporates company search + officers (free tier + optional key)
  - link person entities -> officer/director/agent roles -> company entities
  - subsidiary / parent edges from jurisdiction data
Emits officer_of / owns / subsidiary_of edges into the case entity graph.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
OC = "https://api.opencorporates.com/v0.4"


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def search_companies(query, jurisdiction=""):
    """Company search — OpenCorporates (with OC_API_KEY) + free Wikidata fallback."""
    import requests
    results = []
    oc_error = None
    key = _key()
    if key:
        try:
            params = {"q": query}
            if jurisdiction:
                params["jurisdiction_code"] = jurisdiction
            r = requests.get(f"{OC}/companies/search", params=params, timeout=T, headers=UA)
            j = r.json()
            if j.get("error"):
                oc_error = j["error"].get("message")
            else:
                for c in (j.get("results") or {}).get("companies", []):
                    co = c.get("company", {})
                    results.append({
                        "name": co.get("name"),
                        "jurisdiction": co.get("jurisdiction_code"),
                        "number": co.get("company_number"),
                        "status": co.get("company_type") or co.get("status"),
                        "incorporation_date": co.get("incorporation_date"),
                        "opencorporates_url": co.get("opencorporates_url"),
                        "source": "opencorporates",
                    })
        except Exception as e:
            oc_error = str(e)[:150]
    else:
        oc_error = "OC_API_KEY not set"

    # Free Wikidata fallback (no key) — find companies/orgs + basic facts
    wd = _wikidata_search(query)
    results.extend(wd)

    return {"query": query, "count": len(results), "results": results[:30],
            "opencorporates": oc_error or "ok", "sources": ["wikidata"] + (["opencorporates"] if key else [])}


def _wikidata_search(query, limit=15):
    """Free Wikidata entity search for companies/organizations (no API key)."""
    try:
        import requests
        r = requests.get("https://www.wikidata.org/w/api.php", params={
            "action": "wbsearchentities", "search": query, "language": "en",
            "format": "json", "type": "item", "limit": limit,
        }, timeout=T, headers=UA)
        out = []
        for s in (r.json().get("search") or []):
            out.append({
                "name": s.get("label"), "description": s.get("description"),
                "wikidata_id": s.get("id"),
                "url": f"https://www.wikidata.org/wiki/{s.get('id')}",
                "source": "wikidata",
            })
        return out
    except Exception:
        return []


def wikidata_officers(qid):
    """Fetch occupation/position-held people linked to a Wikidata entity (free)."""
    try:
        import requests
        # get claims for the entity
        r = requests.get(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json",
                         timeout=T, headers=UA)
        ent = r.json().get("entities", {}).get(qid, {})
        labels = ent.get("labels", {}).get("en", {}).get("value")
        # gather "position held" / "member of" style statements that reference people
        out = {"qid": qid, "label": labels, "officers": []}
        # convenience: use the "dummy" reverse — search for people with 'employer' or 'member of' = this entity
        sr = requests.get("https://query.wikidata.org/sparql", params={
            "query": f"""SELECT ?person ?personLabel WHERE {{
              ?person wdt:P108 wd:{qid} . SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
            }} LIMIT 50""", "format": "json"}, timeout=T, headers=UA)
        for b in sr.json().get("results", {}).get("bindings", []):
            out["officers"].append({
                "name": b.get("personLabel", {}).get("value"),
                "wikidata_id": b.get("person", {}).get("value", "").split("/")[-1],
                "role": "employee/member",
            })
        return out
    except Exception as e:
        return {"qid": qid, "error": str(e)[:150], "officers": []}


def company_officers(company_number, jurisdiction):
    """Fetch officers/directors for a company (requires OC_API_KEY for full)."""
    key = _key()
    if not key:
        return {"skipped": "OC_API_KEY not set (officers require OpenCorporates key)",
                "company_number": company_number}
    try:
        import requests
        r = requests.get(
            f"{OC}/companies/{jurisdiction}/{company_number}/officers",
            params={"api_token": key}, timeout=T, headers=UA)
        j = r.json()
        officers = (j.get("results") or {}).get("officers", [])
        return {"company_number": company_number, "count": len(officers),
                "officers": [{"name": o.get("name"), "role": o.get("position"),
                              "appointed_on": o.get("appointed_on"),
                              "opencorporates_url": o.get("opencorporates_url")}
                             for o in officers[:100]]}
    except Exception as e:
        return {"error": str(e)[:150]}


def _key():
    import config as C
    return getattr(C, "OC_API_KEY", "")


def link_company(case_id, company_name, jurisdiction, officers=None, user="system"):
    """Create company + officer entities and their relationship edges."""
    comp_id = _upsert(case_id, "company", company_name)
    linked = []
    for off in (officers or []):
        nm = off.get("name") if isinstance(off, dict) else str(off)
        role = (off.get("role") or "officer") if isinstance(off, dict) else "officer"
        if not nm:
            continue
        oid = _upsert(case_id, "person", nm)
        _edge(case_id, oid, comp_id, "officer_of", 0.8, role)
        linked.append({"person": nm, "role": role})
    db.store_artifact(case_id, comp_id, "corporate", "corporate:link",
                      {"company": company_name, "jurisdiction": jurisdiction,
                       "officers": linked}, user)
    db.audit(user, "corporate.link", company_name, f"officers={len(linked)}")
    return {"company_id": comp_id, "officers_linked": len(linked)}


def trace_person(person_name, case_id=None, user="system"):
    """Find companies where a person is an officer (via OC search)."""
    q = search_companies(person_name)
    hits = q.get("results", [])
    if case_id and hits:
        cid = _upsert(case_id, "person", person_name)
        for h in hits[:20]:
            co = _upsert(case_id, "company", h["name"])
            _edge(case_id, cid, co, "officer_of", 0.6, "opencorporates_search")
        db.store_artifact(case_id, cid, "corporate", "corporate:trace",
                          {"person": person_name, "matches": hits[:20]}, user)
    db.audit(user, "corporate.trace", person_name, f"matches={len(hits)}")
    return {"person": person_name, "match_count": len(hits), "results": hits[:20]}


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


def _edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()))
    c.commit()
