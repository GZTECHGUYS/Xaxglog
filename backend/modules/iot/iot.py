"""Xaxglog IoT device register + exposure monitoring.

The "access back anytime" capability, done lawfully:

  - DEVICE REGISTRY   : catalogue every discovered/known device — type, IP,
                        ports, firmware banner, geo, owner, exposure status,
                        first/last seen. A permanent asset register.
  - PASSIVE RE-SCAN   : "access back" = re-check a device's PUBLIC exposure
                        state over time (unauthenticated banner/port check on
                        public endpoints — the Shodan/research model) and diff
                        it against the last snapshot.
  - CHANGE DETECTION  : alert when firmware/ports/geo/exposure changes.
  - LAWFUL-ACCESS HOOK: for a device you are AUTHORIZED to engage, route
                        through an authority-gated gateway (SS7 model).

NO login, NO credential reuse, NO exploitation of private device functions.
Re-scan reads publicly-exposed state only.
"""
import json
import re
import socket
import ssl
import threading

import db

EXPOSURE_TIMEOUT = 6


def register(name, itype, ip, port=None, meta=None, case_id=None, user="system"):
    """Add/update a device in the register (metadata + last-seen)."""
    c = db.get_db()
    now = db.utcnow()
    value = ip if port is None else f"{ip}:{port}"
    m = dict(meta or {})
    m.update({"name": name, "type": itype, "ip": ip, "port": port})
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, "iot_device", value, now, now, json.dumps(m)))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type='iot_device' AND value=?",
                    (case_id, value)).fetchone()
    if case_id and row:
        db.store_artifact(case_id, row["id"], "iot", "iot:register",
                          {"name": name, "type": itype, "value": value, "meta": m}, user)
    db.audit(user, "iot.register", value, f"{name} ({itype})")
    return {"id": row["id"] if row else None, "value": value}


def list_devices(case_id=None, limit=500):
    c = db.get_db()
    q = "SELECT id,case_id,value,meta,first_seen,last_seen FROM entities WHERE type='iot_device'"
    args = []
    if case_id is not None:
        q += " AND case_id=?"
        args.append(case_id)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    rows = []
    for r in c.execute(q, args).fetchall():
        d = dict(r)
        try:
            d["meta"] = json.loads(d.get("meta") or "{}")
        except Exception:
            d["meta"] = {}
        rows.append(d)
    return rows


def _probe(ip, port):
    """Public exposure probe: unauthenticated banner grab on an open port.

    Reads only what any anonymous internet survey would see (the Shodan model).
    No auth, no exploitation, no private function access.
    """
    state = {"open": False, "banner": "", "tls": None, "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=EXPOSURE_TIMEOUT) as s:
            state["open"] = True
            try:
                if port in (443, 8443, 554):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        cert = ss.getpeercert(binary_form=False)
                        try:
                            der = ss.getpeercert(binary_form=True)
                            import hashlib
                            state["tls"] = {"cert_sha256": hashlib.sha256(der).hexdigest()}
                        except Exception:
                            state["tls"] = {"present": True}
                        ss.settimeout(EXPOSURE_TIMEOUT)
                        try:
                            ss.send(b"\r\n")
                            state["banner"] = ss.recv(512).decode("utf-8", "replace").strip()[:300]
                        except Exception:
                            pass
                else:
                    s.settimeout(EXPOSURE_TIMEOUT)
                    try:
                        data = s.recv(512)
                        if data:
                            state["banner"] = data.decode("utf-8", "replace").strip()[:300]
                        else:
                            s.send(b"\r\n")
                            data = s.recv(512)
                            state["banner"] = (data or b"").decode("utf-8", "replace").strip()[:300]
                    except Exception:
                        pass
            except Exception as e:
                state["error"] = str(e)[:120]
    except Exception as e:
        state["error"] = str(e)[:120]
    return state


def scan_device(entity_id, user="system"):
    """Re-scan a registered device's public exposure state; store snapshot."""
    c = db.get_db()
    row = c.execute("SELECT * FROM entities WHERE id=? AND type='iot_device'",
                    (entity_id,)).fetchone()
    if not row:
        return {"error": "device not found"}
    try:
        meta = json.loads(row["meta"] or "{}")
    except Exception:
        meta = {}
    ip = meta.get("ip")
    port = int(meta.get("port") or 80)
    if not ip:
        return {"error": "device has no IP to probe"}
    snap = _probe(ip, port)
    snap.update({"entity_id": entity_id, "ip": ip, "port": port,
                 "scanned_at": db.utcnow()})
    # compare against previous exposure state -> change detection
    prev = _last_snapshot(entity_id)
    changes = _diff(prev, snap) if prev else []
    # persist snapshot
    c.execute(
        "INSERT INTO artifacts (case_id,entity_id,type,source,content,content_hash,queried_by,queried_at,verified)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (row["case_id"], entity_id, "iot", "iot:scan", json.dumps(snap),
         db.hash_content(json.dumps(snap, sort_keys=True)), user, db.utcnow()))
    c.commit()
    alert = None
    if changes and row["case_id"]:
        alert = {"severity": "medium",
                 "message": f"device {ip}:{port} exposure changed: "
                            + ", ".join(ch.get("field") for ch in changes)}
        c.execute(
            "INSERT INTO alerts (watchlist_id,case_id,ts,severity,message,detail) VALUES (?,?,?,?,?,?)",
            (None, row["case_id"], db.utcnow(), alert["severity"], alert["message"],
             json.dumps({"changes": changes})))
        c.commit()
    db.audit(user, "iot.scan", f"{ip}:{port}", f"open={snap['open']} changes={len(changes)}")
    return {"snapshot": snap, "changes": changes, "alert": alert}


def scan_all(case_id=None, user="system", max_workers=8):
    """Re-scan every registered device; returns change summary."""
    devices = list_devices(case_id, limit=500)
    scanned, changed, errors = 0, 0, 0
    results = []
    for d in devices:
        try:
            r = scan_device(d["id"], user)
            if r.get("error"):
                errors += 1
            else:
                scanned += 1
                if r.get("changes"):
                    changed += 1
                    results.append({"device": d["value"], "changes": r["changes"]})
        except Exception:
            errors += 1
    return {"scanned": scanned, "changed": changed, "errors": errors,
            "details": results}


def _last_snapshot(entity_id):
    c = db.get_db()
    row = c.execute(
        "SELECT content FROM artifacts WHERE entity_id=? AND source='iot:scan'"
        " ORDER BY id DESC LIMIT 1", (entity_id,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["content"])
    except Exception:
        return None


def _diff(prev, cur):
    changes = []
    for f in ("open", "banner", "error"):
        if prev.get(f) != cur.get(f):
            changes.append({"field": f, "from": str(prev.get(f))[:80],
                            "to": str(cur.get(f))[:80]})
    # TLS cert change
    pt = (prev.get("tls") or {}).get("cert_sha256")
    ct = (cur.get("tls") or {}).get("cert_sha256")
    if pt != ct:
        changes.append({"field": "tls_cert", "from": (pt or "")[:16], "to": (ct or "")[:16]})
    return changes


def lawful_access_request(entity_id, authority_ref, action, requested_by):
    """Route an AUTHORIZED engagement of a device through a gated gateway.

    Requires a lawful authority reference. Exports a structured request until a
    gateway is configured. This is the ONLY path to device engagement.
    """
    if not (authority_ref or "").strip():
        return {"error": "request rejected",
                "problems": ["lawful authority reference is required"]}
    c = db.get_db()
    row = c.execute("SELECT * FROM entities WHERE id=? AND type='iot_device'",
                    (entity_id,)).fetchone()
    if not row:
        return {"error": "device not found"}
    req = {"type": "iot_lawful_access", "entity_id": entity_id,
           "target": row["value"], "action": action,
           "authority_ref": authority_ref.strip(),
           "requested_by": requested_by, "status": "exported_for_manual_submission"}
    ev = db.store_artifact(row["case_id"], entity_id, "iot", "iot:lawful_access",
                           req, requested_by)
    db.audit(requested_by, "iot.lawful_access", row["value"],
             f"action={action} auth={req['authority_ref']}")
    return {"request": req, "evidence": ev,
            "note": "No gateway configured — exported for lawful-access channel."}
