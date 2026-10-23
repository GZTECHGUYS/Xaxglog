"""Xaxglog CCTV / sensor infrastructure module.

Two clearly separated capabilities:

  1. CAMERA MAPPER  : discover + catalogue publicly-exposed camera endpoints
                      for SITUATIONAL AWARENESS of sensor coverage (mapping
                      only — reads public banners/exposure state, never logs
                      into or controls a device).
  2. AUTHORIZED FEED CUSTODY : ingest camera stills/frames the agency is
                      AUTHORIZED to use (agreement-based), stored with
                      SHA-256 chain of custody for evidentiary handling.

No camera login, no stream hijacking, no unauthorized device access.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 12


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


# ---------------------------------------------------------------- discovery (public banners)
def discover_cameras(query="", key="", limit=50):
    """Discover exposed camera endpoints via public internet-survey APIs.

    Uses Shodan (if SHODAN_API_KEY present) camera/product search, or a
    keyless camera-directory query. Read-only exposure mapping: returns
    metadata (IP, geo, product, ports) — NOT device access.
    """
    out = {"query": query, "results": [], "mode": "none"}
    if key:
        try:
            import requests
            q = query or "has-screenshot:true product:camera"
            r = requests.get(f"https://api.shodan.io/shodan/host/search",
                             params={"key": key, "query": q, "limit": limit},
                             timeout=T, headers=UA)
            j = r.json()
            out["total"] = j.get("total")
            out["mode"] = "shodan"
            for m in (j.get("matches") or [])[:limit]:
                loc = (m.get("location") or {})
                out["results"].append({
                    "ip": m.get("ip_str"), "port": m.get("port"),
                    "product": m.get("product"), "org": m.get("org"),
                    "hostnames": m.get("hostnames", []),
                    "city": loc.get("city"), "country": loc.get("country_name"),
                    "lat": loc.get("latitude"), "lon": loc.get("longitude"),
                    "banner": (m.get("data") or "")[:200],
                })
        except Exception as e:
            out["error"] = str(e)[:150]
    else:
        out["mode"] = "keyless_directory"
        out["note"] = ("Set SHODAN_API_KEY for live camera discovery. Keyless mode "
                       "provides the directory structure only.")
        # Seed known public camera-directory indexes (metadata, not access)
        out["sources"] = ["insecam.org directory (metadata)", "Shodan (with key)",
                          "Censys (with key)"]
    return out


def register_camera(ip, port, label, lat, lon, case_id=None, user="system",
                    meta=None):
    """Register a discovered/known camera as an entity (metadata only)."""
    c = db.get_db()
    now = db.utcnow()
    value = f"{ip}:{port}"
    m = dict(meta or {})
    m.update({"ip": ip, "port": port, "label": label, "lat": lat, "lon": lon})
    import json
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, "camera", value, now, now, json.dumps(m)))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type='camera' AND value=?",
                    (case_id, value)).fetchone()
    if case_id and lat is not None and lon is not None:
        try:
            from modules.geo import geo as GEO
            GEO.add_geo_entity(case_id, f"cam {label or ip}", float(lat), float(lon))
        except Exception:
            pass
    if case_id and row:
        db.store_artifact(case_id, row["id"], "cctv", "cctv:register",
                          {"ip": ip, "port": port, "label": label, "meta": m}, user)
    db.audit(user, "cctv.register", value, label)
    return {"id": row["id"] if row else None, "value": value}


def list_cameras(case_id=None, limit=200):
    c = db.get_db()
    q = "SELECT id,case_id,value,meta,last_seen FROM entities WHERE type='camera'"
    args = []
    if case_id is not None:
        q += " AND case_id=?"
        args.append(case_id)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    import json
    rows = []
    for r in c.execute(q, args).fetchall():
        d = dict(r)
        try:
            d["meta"] = json.loads(d.get("meta") or "{}")
        except Exception:
            d["meta"] = {}
        rows.append(d)
    return rows


# ---------------------------------------------------------------- authorized feed custody
def ingest_frame(camera_ref, case_id, custodian, filename, data_b64=None,
                 source="authorized_feed", note=""):
    """Store a camera still/frame from an AUTHORIZED feed with chain of custody.

    `data_b64` is optional base64 of the frame (or omit to store metadata only).
    Every ingest is SHA-256 hashed + custodian-logged for evidentiary handling.
    """
    import base64
    import hashlib
    record = {"camera_ref": camera_ref, "filename": filename, "source": source,
              "note": note, "custodian": custodian, "ingested_at": db.utcnow()}
    if data_b64:
        try:
            raw = base64.b64decode(data_b64)
            record["bytes"] = len(raw)
            record["sha256"] = hashlib.sha256(raw).hexdigest()
        except Exception as e:
            record["decode_error"] = str(e)[:100]
    root = _upsert(case_id, "camera", camera_ref) if case_id else None
    ev = db.store_artifact(case_id, root, "cctv", f"cctv:ingest:{source}", record, custodian)
    db.audit(custodian, "cctv.ingest", camera_ref, filename)
    return {"ingested": True, "evidence": ev, "record": record}


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
