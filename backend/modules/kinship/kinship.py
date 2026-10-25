"""Xaxglog kinship — family/associate graph from public records.

Open, keyless sources:
  - Wikidata SPARQL (query.wikidata.org) — relative relations: father,
    mother, child, sibling, spouse/partner, parent-in-law, business
    associates (keyless, polite pool, self-throttled).
  - Obituary/discovery dorks via searchx (keyless) — "obituary <name>
    <place>" style queries surface family naming in news.

Output: person -> typed relative edges with source URLs, ready to merge
into the case entity graph (cases module) as entities + edges.

Lawful-use note: relations that subjects/public records publish. Inference
is labelled with its source; no private-registry access, no doxxing of
non-public individuals beyond what the sources already publish.
"""
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
WIKIDATA = "https://query.wikidata.org/sparql"
_last = [0.0]

REL_PROPS = {
    "father": "P22", "mother": "P25", "child": "P40", "sibling": "P3373",
    "spouse": "P26", "partner": "P451", "relative": "P1038",
}
PROP_LABEL = {v: k for k, v in REL_PROPS.items()}


def _sparql(query):
    import requests
    wait = 2.0 - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    try:
        r = requests.get(WIKIDATA,
                         headers={**UA,
                                 "Accept": "application/sparql-results+json"},
                         params={"query": query}, timeout=T)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Wikidata unreachable: {type(e).__name__}")
    _last[0] = time.time()
    if r.status_code == 429:
        raise RuntimeError("Wikidata rate limit")
    if r.status_code != 200:
        raise RuntimeError(f"SPARQL HTTP {r.status_code}")
    return r.json().get("results", {}).get("bindings", [])


def _label(item):
    return item.get("value", "").rsplit("/", 1)[-1]


def resolve(name, birth_year=None, limit=5):
    """Find Wikidata Q-ids for a person name (disambiguation via year)."""
    safe = name.replace('"', "").replace("\\", "")[:120]
    year_clause = ""
    if birth_year:
        year_clause = f"OPTIONAL {{ ?p wdt:P569 ?bd . FILTER(YEAR(?bd) = {int(birth_year)}) }}"
    q = f"""
    SELECT ?p ?pLabel ?pDescription ?bd WHERE {{
      ?p wdt:P31 wd:Q5 ;
         rdfs:label ?pLabel .
      FILTER(LANG(?pLabel) = "en")
      FILTER(CONTAINS(LCASE(?pLabel), LCASE("{safe}")))
      {year_clause}
      OPTIONAL {{ ?p schema:description ?pDescription . FILTER(LANG(?pDescription)="en") }}
    }} LIMIT {int(limit)}
    """
    try:
        rows = _sparql(q)
    except RuntimeError as e:
        return {"status": "error", "error": str(e)[:150], "results": []}
    out = []
    for b in rows:
        out.append({"qid": _label(b.get("p", {})),
                    "label": b.get("pLabel", {}).get("value"),
                    "description": b.get("pDescription", {}).get("value"),
                    "birth_year": b.get("bd", {}).get("value", "")[:4] or None})
    return out


def relatives(qid, max_depth=1):
    """Typed relative edges for a Wikidata Q-id (depth 1 edges)."""
    props = ", ".join(f"wdt:{p}" for p in REL_PROPS.values())
    q = f"""
    SELECT ?rel ?prop ?relLabel WHERE {{
      OPTIONAL {{ wd:{qid} {props} ?rel . ?rel ?propO . }}
      wd:{qid} ?prop ?rel .
      FILTER(?prop IN ({', '.join('wdt:' + p for p in REL_PROPS.values())}))
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }} LIMIT 200
    """
    try:
        rows = _sparql(q)
    except RuntimeError:
        return {"status": "error", "error": "Wikidata unavailable"}
    edges = []
    seen = set()
    for b in rows:
        prop_uri = b.get("prop", {}).get("value", "").rsplit("/", 1)[-1]
        rel_label = PROP_LABEL.get(prop_uri)
        if not rel_label:
            continue
        rel_qid = _label(b.get("rel", {}))
        rel_name = b.get("relLabel", {}).get("value") or rel_qid
        key = (rel_label, rel_qid)
        if key in seen:
            continue
        seen.add(key)
        edges.append({"relation": rel_label, "qid": rel_qid, "name": rel_name,
                      "url": f"https://www.wikidata.org/wiki/{rel_qid}"})
    return {"status": "ok", "qid": qid, "count": len(edges), "edges": edges}


def graph_for(name, birth_year=None, case_id=None, queried_by="system"):
    """Resolve a name + pull its relatives; store as case entities/edges."""
    try:
        cands = resolve(name, birth_year)
        if not isinstance(cands, list):
            return cands  # structured error from resolve (Wikidata down)
        if not cands:
            return {"status": "ok", "matches": 0,
                    "note": "no Wikidata person match — try disambiguation or a second name"}
        root = cands[0]
        rel = relatives(root["qid"])
        edges = rel.get("edges", []) if rel.get("status") == "ok" else []
        out = {"status": "ok", "root": root, "candidates": cands,
               "count": len(edges), "edges": edges}
        if case_id is not None and edges:
            con = db.get_db()
            import json as _json
            cur = con.execute(
                "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta)"
                " VALUES (?,?,?,?,?,?)",
                (case_id, "person", root["label"], db.utcnow(), db.utcnow(),
                 _json.dumps({"qid": root["qid"]})))
            con.commit()
            eid = cur.lastrowid
            for e in edges:
                cur2 = con.execute(
                    "INSERT OR IGNORE INTO entities (case_id,type,value,first_seen,last_seen,meta)"
                    " VALUES (?,?,?,?,?,?)",
                    (case_id, "person", e["name"], db.utcnow(), db.utcnow(),
                     _json.dumps({"qid": e["qid"], "source": "wikidata"})))
                con.commit()
                if cur2.lastrowid:
                    con.execute(
                        "INSERT OR IGNORE INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (case_id, eid, cur2.lastrowid, e["relation"], 1.0,
                         "wikidata", db.utcnow()))
                    con.commit()
            art = db.store_artifact(case_id, eid, "kinship", "wikidata", out, queried_by)
            out["artifact"] = art
        db.audit(queried_by, "kinship.graph_for", name, f"edges={len(edges)}")
        return out
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def obituary_dorks(name, place=None):
    """Build+run obituary discovery queries via searchx (keyless)."""
    try:
        q = f'"{name}" obituary'
        if place:
            q += f' "{place}"'
        out = {"status": "ok", "queries": [
            q,
            f'"{name}" "survived by"',
            f'"{name}" "was preceded in death"',
        ], "engine": "searchx"}
        try:
            import modules.searchx.searchx as SX
            results = []
            for query in out["queries"][:2]:
                r = SX.federated(query, limit=8) if hasattr(SX, "federated") else None
                if r and r.get("status") == "ok":
                    results.extend(r.get("results", [])[:8])
            out["results"] = results
        except Exception as e:
            out["results"] = []
            out["note"] = f"searchx unavailable: {str(e)[:80]}"
        return out
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
