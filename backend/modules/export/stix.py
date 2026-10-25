"""Xaxglog STIX 2.1 export — standard threat-intel interchange.

Converts a case's entities + edges into a STIX 2.1 bundle so Xaxglog output
plugs into other agency/security tools (OpenCTI, MISP, Splunk, etc.).
"""
import uuid

import db

STIX_VERSION = "2.1"


def _stix_id(stix_type, name):
    h = uuid.uuid5(uuid.NAMESPACE_URL, f"xaxglog:{stix_type}:{name}")
    return f"{stix_type}--{h}"


TYPE_MAP = {
    "email": ("email-addr", "value"),
    "domain": ("domain-name", "value"),
    "ip": ("ipv4-addr", "value"),
    "username": ("identity", "name"),
    "person": ("identity", "name"),
    "company": ("identity", "name"),
    "handle": ("identity", "name"),
}


def export_case(case_id):
    import modules.cases.cases as CASES
    c = db.get_db()
    case = CASES.get_case(case_id)
    if not case:
        return {"error": "case not found"}

    objects = []
    created_by = _stix_id("identity", "Xaxglog")
    objects.append({
        "type": "identity", "spec_version": STIX_VERSION, "id": created_by,
        "created": db.utcnow(), "modified": db.utcnow(),
        "name": "Xaxglog OSINT Platform", "identity_class": "system",
    })

    nodes = [dict(r) for r in c.execute(
        "SELECT * FROM entities WHERE case_id=?", (case_id,)).fetchall()]
    idmap = {}
    for n in nodes:
        stix_type, prop = TYPE_MAP.get(n["type"], ("identity", "name"))
        sid = _stix_id(stix_type, f"{n['type']}:{n['value']}")
        idmap[n["id"]] = sid
        obj = {"type": stix_type, "spec_version": STIX_VERSION, "id": sid,
               "created": n["first_seen"], "modified": n["last_seen"],
               "created_by_ref": created_by}
        obj[prop] = n["value"]
        if stix_type == "identity":
            obj["identity_class"] = "individual" if n["type"] in ("person", "username") else "organization"
        objects.append(obj)

    for e in c.execute("SELECT * FROM edges WHERE case_id=?", (case_id,)).fetchall():
        if e["src_id"] in idmap and e["dst_id"] in idmap:
            objects.append({
                "type": "relationship", "spec_version": STIX_VERSION,
                "id": _stix_id("relationship", f"{e['id']}"),
                "created": e["created_at"], "modified": e["created_at"],
                "created_by_ref": created_by,
                "relationship_type": e["relation"],
                "source_ref": idmap[e["src_id"]], "target_ref": idmap[e["dst_id"]],
            })

    for a in [dict(r) for r in c.execute("SELECT * FROM artifacts WHERE case_id=?", (case_id,)).fetchall()]:
        objects.append({
            "type": "note", "spec_version": STIX_VERSION,
            "id": _stix_id("note", str(a["id"])),
            "created": a["queried_at"], "modified": a["queried_at"],
            "created_by_ref": created_by,
            "abstract": f"{a['type']} evidence from {a['source']}",
            "content": f"[SHA-256 {a['content_hash']}] by {a['queried_by']} at {a['queried_at']}",
            "object_refs": [idmap.get(a.get("entity_id"), created_by)],
        })

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    db.audit(None, "stix.export", str(case_id), f"objects={len(objects)}")
    return {"bundle": bundle, "object_count": len(objects),
            "case_number": case["case_number"]}
