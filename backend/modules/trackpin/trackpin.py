"""TrackPin — lawful location workflow (consent check-in + authority request).

What this module does
---------------------
* creates a case-linked operation for a phone/email/name/device identifier
* issues a **one-time, expiring consent link**; the subject explicitly opens
  it and presses "share my location" in their own browser
* stores location points with provenance, accuracy, consent flag and a
  SHA-256 evidence artifact
* generates a formal authority-request packet for carrier/emergency location
  (the operator must submit it through the agency's lawful channel)

What it deliberately does not do
--------------------------------
* no covert call/SMS interception, silent SMS, SS7/MAP exploitation
* no malware, spyware, device compromise or location tracking without consent
* no automated carrier access. Precise real-time location is only lawful with
  explicit consent or a valid legal process handled by the provider/authority.
"""
import datetime
import json
import secrets

import db

MODES = {"consent_checkin", "authority_request", "manual_ingest"}
SOURCES = {"consent_link", "manual", "authority", "open_source"}
MAX_TTL_HOURS = 168  # 7 days


def _row(row):
    return dict(row) if row else None


def _op(op_id):
    c = db.get_db()
    return _row(c.execute("SELECT * FROM trackpin_ops WHERE id=?", (op_id,)).fetchone())


def _can_access(op, user, role):
    if not op:
        return False
    if role == "admin" or op.get("created_by") == user:
        return True
    case_id = op.get("case_id")
    if case_id:
        c = db.get_db()
        row = c.execute(
            "SELECT 1 FROM case_members WHERE case_id=? AND username=?",
            (case_id, user)).fetchone()
        return bool(row)
    return False


def _points(op_id):
    c = db.get_db()
    return [dict(r) for r in c.execute(
        "SELECT * FROM trackpin_points WHERE op_id=? ORDER BY captured_at, id",
        (op_id,)).fetchall()]


def _upsert_entity(case_id, etype, value, meta=None):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta)"
        " VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET"
        " last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, etype, value, now, now,
         json.dumps(meta or {}, sort_keys=True)))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def _store_point(op, point, user):
    if not op.get("case_id"):
        return None
    root = _upsert_entity(
        op["case_id"], "geo",
        "%.6f,%.6f" % (point["lat"], point["lon"]),
        {"trackpin_op": op["id"], "source": point["source"],
         "accuracy_m": point.get("accuracy_m"), "consent": point.get("consent")})
    return db.store_artifact(op["case_id"], root, "trackpin",
                             "trackpin:%s" % point["source"], point, user)


def _public_op(op):
    return {
        "id": op["id"],
        "label": op["label"],
        "target": op["target"],
        "mode": op["mode"],
        "status": op["status"],
        "legal_basis": op["legal_basis"],
        "created_by": op["created_by"],
        "created_at": op["created_at"],
        "consent_expires": op["consent_expires"],
        "consent_used": bool(op["consent_used"]),
        "consent_token": op["consent_token"],
        "authority_ref": op["authority_ref"],
        "notes": op["notes"],
        "case_id": op["case_id"],
    }


def create_operation(label, target, mode="consent_checkin", case_id=None,
                     legal_basis="", notes="", user="system", ttl_hours=24,
                     role="analyst"):
    label = (label or "").strip()[:160]
    target = (target or "").strip()[:200]
    mode = (mode or "consent_checkin").strip()
    legal_basis = (legal_basis or "").strip()[:500]
    notes = (notes or "").strip()[:1000]
    if not label or not target:
        return {"error": "label and target required"}
    if mode not in MODES:
        return {"error": "mode must be one of: " + ", ".join(sorted(MODES))}
    if mode == "authority_request" and not legal_basis:
        return {"error": "legal_basis is required for authority_request mode"}
    try:
        case_id = int(case_id) if case_id not in (None, "", 0) else None
    except (TypeError, ValueError):
        return {"error": "case_id must be an integer"}
    if case_id is not None:
        c = db.get_db()
        case = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            return {"error": "case not found"}
        if role != "admin" and case["created_by"] != user:
            member = c.execute(
                "SELECT 1 FROM case_members WHERE case_id=? AND username=?",
                (case_id, user)).fetchone()
            if not member:
                return {"error": "not authorized for this case"}
    try:
        ttl_hours = max(1, min(int(ttl_hours or 24), MAX_TTL_HOURS))
    except (TypeError, ValueError):
        ttl_hours = 24
    token = secrets.token_urlsafe(32) if mode == "consent_checkin" else None
    expires = None
    if token:
        expires = (datetime.datetime.now(datetime.timezone.utc)
                   + datetime.timedelta(hours=ttl_hours)).isoformat().replace("+00:00", "Z")
    c = db.get_db()
    cur = c.execute(
        "INSERT INTO trackpin_ops (case_id,label,target,mode,status,legal_basis,"
        "created_by,created_at,consent_token,consent_expires,consent_used,"
        "authority_ref,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (case_id, label, target, mode, "open", legal_basis, user,
         db.utcnow(), token, expires, 0, "", notes))
    c.commit()
    db.audit(user, "trackpin.create", target[:120],
             "op=%s mode=%s case=%s" % (cur.lastrowid, mode, case_id))
    op = _op(cur.lastrowid)
    return {"status": "ok", "operation": _public_op(op),
            "consent_token": token, "ttl_hours": ttl_hours}


def list_operations(user="system", role="analyst", case_id=None):
    c = db.get_db()
    case_filter = int(case_id) if case_id not in (None, "", 0) else None
    if role == "admin":
        sql = "SELECT o.* FROM trackpin_ops o"
        params = []
        if case_filter is not None:
            sql += " WHERE o.case_id=?"
            params.append(case_filter)
    else:
        sql = ("SELECT DISTINCT o.* FROM trackpin_ops o"
               " LEFT JOIN case_members cm ON cm.case_id=o.case_id"
               " AND cm.username=?")
        params = [user]  # join parameter first
        where = []
        if case_filter is not None:
            where.append("o.case_id=?")
            params.append(case_filter)
        where.append("(o.created_by=? OR cm.username IS NOT NULL)")
        params.append(user)
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY o.id DESC LIMIT 200"
    return [dict(r) for r in c.execute(sql, params).fetchall()]


def get_operation(op_id, user="system", role="analyst", include_points=True):
    op = _op(op_id)
    if not op:
        return {"error": "operation not found"}
    if not _can_access(op, user, role):
        return {"error": "not authorized for this operation"}
    out = _public_op(op)
    if include_points:
        out["points"] = _points(op_id)
        out["point_count"] = len(out["points"])
        out["last_point"] = out["points"][-1] if out["points"] else None
    out["expired"] = bool(out["consent_expires"] and
                          out["consent_expires"] < db.utcnow())
    return {"status": "ok", "operation": out}


def _valid_coords(lat, lon):
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return None, None, "lat and lon must be numbers"
    if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        return None, None, "lat/lon out of range"
    return lat, lon, None


def add_point(op_id, lat, lon, accuracy_m=None, source="manual",
              consent=False, note="", user="system", role="analyst",
              ip="", user_agent="", captured_at=None, meta=None):
    op = _op(op_id)
    if not op:
        return {"error": "operation not found"}
    if not _can_access(op, user, role):
        return {"error": "not authorized for this operation"}
    lat, lon, err = _valid_coords(lat, lon)
    if err:
        return {"error": err}
    if source not in SOURCES or source == "consent_link":
        return {"error": "operator points must use manual/authority/open_source"}
    try:
        accuracy_m = float(accuracy_m) if accuracy_m not in (None, "") else None
    except (TypeError, ValueError):
        accuracy_m = None
    point = {
        "op_id": op_id, "case_id": op.get("case_id"),
        "lat": lat, "lon": lon, "accuracy_m": accuracy_m,
        "source": source, "consent": 1 if consent else 0, "consent_ref": "",
        "captured_at": captured_at or db.utcnow(), "received_at": db.utcnow(),
        "ip": ip[:120], "user_agent": user_agent[:300],
        "note": (note or "")[:500],
        "meta": json.dumps(meta or {}, sort_keys=True),
    }
    c = db.get_db()
    cur = c.execute(
        "INSERT INTO trackpin_points (op_id,case_id,lat,lon,accuracy_m,source,"
        "consent,consent_ref,captured_at,received_at,ip,user_agent,note,meta)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (point["op_id"], point["case_id"], point["lat"], point["lon"],
         point["accuracy_m"], point["source"], point["consent"],
         point["consent_ref"], point["captured_at"], point["received_at"],
         point["ip"], point["user_agent"], point["note"], point["meta"]))
    point["id"] = cur.lastrowid
    c.commit()
    point["evidence"] = _store_point(op, point, user)
    db.audit(user, "trackpin.point", op.get("target", "")[:120],
             "op=%s source=%s consent=%s" % (op_id, source, point["consent"]))
    return {"status": "ok", "point": point}


def create_consent_link(op_id, user="system", role="analyst", ttl_hours=24):
    op = _op(op_id)
    if not op:
        return {"error": "operation not found"}
    if not _can_access(op, user, role):
        return {"error": "not authorized for this operation"}
    if op["mode"] != "consent_checkin":
        return {"error": "operation mode is not consent_checkin"}
    if op["status"] in ("closed", "expired"):
        return {"error": "operation is %s" % op["status"]}
    try:
        ttl_hours = max(1, min(int(ttl_hours or 24), MAX_TTL_HOURS))
    except (TypeError, ValueError):
        ttl_hours = 24
    token = secrets.token_urlsafe(32)
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(hours=ttl_hours)).isoformat().replace("+00:00", "Z")
    c = db.get_db()
    c.execute("UPDATE trackpin_ops SET consent_token=?, consent_expires=?,"
              " consent_used=0, status='open' WHERE id=?",
              (token, expires, op_id))
    c.commit()
    db.audit(user, "trackpin.consent_link", op.get("target", "")[:120],
             "op=%s ttl=%sh" % (op_id, ttl_hours))
    return {"status": "ok", "consent_token": token, "expires": expires,
            "ttl_hours": ttl_hours,
            "path": "/trackpin/consent/" + token}


def consent_info(token):
    c = db.get_db()
    op = _row(c.execute("SELECT * FROM trackpin_ops WHERE consent_token=?",
                        (token,)).fetchone())
    if not op:
        return {"valid": False, "error": "invalid or revoked consent link"}
    if op["mode"] != "consent_checkin":
        return {"valid": False, "error": "not a consent operation"}
    if op["status"] in ("closed", "expired"):
        return {"valid": False, "error": "operation is closed"}
    if op["consent_expires"] and op["consent_expires"] < db.utcnow():
        return {"valid": False, "error": "consent link expired"}
    if op["consent_used"]:
        return {"valid": False, "error": "consent link already used"}
    return {"valid": True, "label": op["label"], "expires": op["consent_expires"],
            "mode": op["mode"],
            "notice": ("This is a one-time location check-in. Nothing is shared "
                       "until you press the button and allow browser location.")}


def submit_consent(token, lat, lon, accuracy_m=None, consent=False,
                   ip="", user_agent="", note=""):
    if not consent:
        return {"error": "explicit consent is required", "consent": False}
    info = consent_info(token)
    if not info.get("valid"):
        return {"error": info.get("error", "invalid consent link"),
                "consent": False}
    c = db.get_db()
    op = _row(c.execute("SELECT * FROM trackpin_ops WHERE consent_token=?",
                        (token,)).fetchone())
    lat, lon, err = _valid_coords(lat, lon)
    if err:
        return {"error": err, "consent": False}
    try:
        accuracy_m = float(accuracy_m) if accuracy_m not in (None, "") else None
    except (TypeError, ValueError):
        accuracy_m = None
    now = db.utcnow()
    point = {
        "op_id": op["id"], "case_id": op["case_id"],
        "lat": lat, "lon": lon, "accuracy_m": accuracy_m,
        "source": "consent_link", "consent": 1,
        "consent_ref": token[:10] + "…",
        "captured_at": now, "received_at": now,
        "ip": (ip or "")[:120], "user_agent": (user_agent or "")[:300],
        "note": (note or "consent link check-in")[:500],
        "meta": json.dumps({"consent": True, "one_time": True}, sort_keys=True),
    }
    cur = c.execute(
        "INSERT INTO trackpin_points (op_id,case_id,lat,lon,accuracy_m,source,"
        "consent,consent_ref,captured_at,received_at,ip,user_agent,note,meta)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (point["op_id"], point["case_id"], point["lat"], point["lon"],
         point["accuracy_m"], point["source"], point["consent"],
         point["consent_ref"], point["captured_at"], point["received_at"],
         point["ip"], point["user_agent"], point["note"], point["meta"]))
    point["id"] = cur.lastrowid
    c.execute("UPDATE trackpin_ops SET consent_used=1, status='consented'"
              " WHERE id=?", (op["id"],))
    c.commit()
    point["evidence"] = _store_point(op, point, "consent:" + token[:10])
    db.audit("consent:" + token[:10], "trackpin.consent_submit",
             op.get("target", "")[:120], "op=%s" % op["id"])
    return {"status": "ok", "consent": True,
            "message": "Location shared with explicit consent.",
            "point": {k: point[k] for k in
                      ("id", "lat", "lon", "accuracy_m", "captured_at", "source")}}


def request_authority(op_id, agency, reference, legal_basis="",
                      user="system", role="analyst", notes=""):
    op = _op(op_id)
    if not op:
        return {"error": "operation not found"}
    if not _can_access(op, user, role):
        return {"error": "not authorized for this operation"}
    agency = (agency or "").strip()[:200]
    reference = (reference or "").strip()[:200]
    legal_basis = (legal_basis or op.get("legal_basis") or "").strip()[:500]
    if not agency or not reference:
        return {"error": "agency and reference/case authority number required"}
    if not legal_basis:
        return {"error": "legal_basis required"}
    packet = (
        "LAWFUL LOCATION / CARRIER REQUEST PACKET\n"
        "Xaxglog TrackPin operation #%s\n"
        "Case ID: %s\n"
        "Subject/identifier: %s\n"
        "Requested from: %s\n"
        "Agency reference: %s\n"
        "Legal basis: %s\n"
        "Requested records: current/emergency location, call detail and cell-site "
        "records as authorized by the referenced legal process.\n\n"
        "Handling: submit through the agency's lawful channel to the carrier or "
        "emergency-location provider. Xaxglog does not access carrier systems and "
        "does not perform SS7/MAP exploitation, silent SMS or call interception.\n"
        "Chain of custody: operation, consent/authority reference and all points "
        "are audited and hashed when attached to a case.\n"
        % (op["id"], op.get("case_id") or "none", op.get("target"),
           agency, reference, legal_basis)
    )
    c = db.get_db()
    c.execute("UPDATE trackpin_ops SET status='requested', authority_ref=?,"
              " legal_basis=?, notes=? WHERE id=?",
              (reference, legal_basis, (notes or packet)[:4000], op_id))
    c.commit()
    evidence = None
    if op.get("case_id"):
        root = _upsert_entity(op["case_id"], "authority_request",
                              "%s:%s" % (agency, reference),
                              {"trackpin_op": op_id})
        evidence = db.store_artifact(op["case_id"], root, "trackpin_request",
                                     "trackpin:authority", packet, user)
    db.audit(user, "trackpin.authority", op.get("target", "")[:120],
             "op=%s agency=%s ref=%s" % (op_id, agency[:60], reference[:60]))
    return {"status": "ok", "packet": packet, "evidence": evidence,
            "notice": "Packet generated. Submit it through your lawful channel; "
                      "no carrier access is automated."}


def geojson(op_id, user="system", role="analyst"):
    res = get_operation(op_id, user, role)
    if res.get("error"):
        return res
    op = res["operation"]
    features = []
    for p in op.get("points") or []:
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point",
                         "coordinates": [p["lon"], p["lat"]]},
            "properties": {
                "id": p["id"], "source": p["source"],
                "consent": bool(p["consent"]), "accuracy_m": p["accuracy_m"],
                "captured_at": p["captured_at"], "note": p["note"],
            },
        })
    return {
        "type": "FeatureCollection",
        "name": "trackpin-%s" % op_id,
        "features": features,
    }
