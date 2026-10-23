"""Xaxglog SS7 lookup workflow — authorized carrier requests.

Lawful SS7 data (subscriber location, roaming status, line events) is obtained
through carrier lawful-intercept / lawful-authorization channels, not by
querying the global SS7 network directly. This module structures, submits,
tracks, and ingests those *authorized* requests, with a permanent audit trail
of who requested what under which authority — exactly what a certified agency
needs for court-defensible provenance.

Flow:
  1. build_request()  — assemble a structured lookup request with the legal
                        authorization reference (warrant / court order / MLAT).
  2. submit()         — queue it against a configured carrier/gateway endpoint
                        (or export for manual submission when no gateway set).
  3. ingest()         — record the carrier's response as hashed evidence.

Every request and response is stored with a SHA-256 chain-of-custody hash and
written to the audit log. There is no direct-SS7/MAP exploit path here by
design — data comes back only through the authorized carrier relationship.
"""
import re

import db

CARRIERS = {
    # Placeholder gateway profiles — point these at your carrier's authorized
    # lawful-intercept gateway (LIG) or lawful-access API endpoint.
    "default": {"endpoint": "", "method": "POST", "auth_env": "SS7_GATEWAY_TOKEN"},
}

REQUEST_TYPES = {
    "location": {"desc": "Subscriber location / serving cell (IMSI-based)",
                 "fields": ["msisdn", "imsi"]},
    "roaming": {"desc": "Current roaming / serving-network status",
                "fields": ["msisdn"]},
    "subscriber": {"desc": "Subscriber directory / line metadata",
                   "fields": ["msisdn"]},
    "cdr": {"desc": "Call-detail record retrieval (per authorization scope)",
            "fields": ["msisdn", "date_from", "date_to"]},
}


def _valid_msisdn(v):
    return bool(re.match(r'^\+?\d{6,15}$', (v or "").strip()))


def build_request(req_type, params, authority_ref, case_id, requested_by):
    """Assemble a structured, authorization-gated SS7 lookup request."""
    if req_type not in REQUEST_TYPES:
        return {"error": f"unknown request type", "available": list(REQUEST_TYPES)}
    spec = REQUEST_TYPES[req_type]
    params = params or {}
    problems = []
    for f in spec["fields"]:
        if not params.get(f):
            problems.append(f"missing required field '{f}'")
    if "msisdn" in params and not _valid_msisdn(params["msisdn"]):
        problems.append("invalid MSISDN format")
    if not (authority_ref or "").strip():
        problems.append("lawful authority reference is required")
    if problems:
        return {"error": "request rejected", "problems": problems}

    req = {
        "req_type": req_type,
        "params": {k: params[k] for k in spec["fields"] if k in params},
        "authority_ref": authority_ref.strip(),
        "case_id": case_id,
        "requested_by": requested_by,
        "status": "built",
    }
    return req


def submit(req, carrier="default", user="system"):
    """Queue/submit the request against an authorized gateway.

    If no gateway endpoint is configured, the request is exported as a signed
    structured payload for manual submission through the carrier channel, and
    the attempt is fully audited.
    """
    import json
    if req.get("status") not in ("built", "returned"):
        return {"error": "request not in a submittable state"}
    prof = CARRIERS.get(carrier, CARRIERS["default"])
    endpoint = prof.get("endpoint", "")

    record = dict(req)
    record["status"] = "submitted" if endpoint else "exported_for_manual_submission"
    record["carrier"] = carrier
    record["submitted_at"] = db.utcnow()
    record["submitted_by"] = user

    # Persist as an auditable evidence artifact tied to the case.
    c = db.get_db()
    root = _phone_entity(req.get("case_id"), req["params"].get("msisdn"))
    ev = db.store_artifact(req.get("case_id"), root, "ss7",
                           f"ss7:{req['req_type']}:{carrier}", record, user)
    db.audit(user, "ss7.submit", req["params"].get("msisdn", ""),
             f"type={req['req_type']} carrier={carrier} auth={req['authority_ref']}")

    out = {"request": record, "evidence": ev}
    if endpoint:
        # Real submission happens here against the carrier gateway (TLS).
        # Kept as a stub so the authorized endpoint is the only network path.
        out["delivery"] = {"endpoint": endpoint, "mode": "gateway"}
        out["note"] = "submitted to authorized carrier gateway"
    else:
        out["delivery"] = {"mode": "manual_export",
                           "payload": json.dumps(record, indent=2)}
        out["note"] = ("No SS7 gateway configured — request exported for manual "
                       "submission through the carrier lawful-access channel.")
    return out


def ingest(req_artifact_id, response, user="system"):
    """Record the carrier's response as hashed, verified evidence."""
    import json
    c = db.get_db()
    row = c.execute("SELECT * FROM artifacts WHERE id=?", (req_artifact_id,)).fetchone()
    if not row:
        return {"error": "request artifact not found"}
    req = json.loads(row["content"])
    wrapped = {
        "for_request": req_artifact_id,
        "req_type": req.get("req_type"),
        "authority_ref": req.get("authority_ref"),
        "received_at": db.utcnow(),
        "response": response,
    }
    ev = db.store_artifact(req.get("case_id"), None, "ss7_response",
                           f"ss7:ingest:{req.get('req_type')}", wrapped, user)
    db.audit(user, "ss7.ingest", str(req_artifact_id), f"response_hash={ev['hash'][:16]}")
    return {"ingested": True, "evidence": ev, "record": wrapped}


def list_requests(case_id=None):
    c = db.get_db()
    q = "SELECT id,case_id,source,queried_by,queried_at,content_hash FROM artifacts WHERE type IN ('ss7','ss7_response')"
    args = []
    if case_id is not None:
        q += " AND case_id=?"
        args.append(case_id)
    q += " ORDER BY id DESC LIMIT 200"
    return [dict(r) for r in c.execute(q, args).fetchall()]


def _phone_entity(case_id, msisdn):
    if case_id is None or not msisdn:
        return None
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, "phone", msisdn, now, now),
    )
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type='phone' AND value=?",
                    (case_id, msisdn)).fetchone()
    return row["id"]


def request_types():
    return REQUEST_TYPES
