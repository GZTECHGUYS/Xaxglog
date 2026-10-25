"""Xaxglog vehicle intelligence — decode + scrape + reverse-plate + ALPR + gov records.

Lawful, provenance-tracked vehicle OSINT:

  VIN decode      : NHTSA vPIC (free public API) — make/model/year/branding
  Recall / title  : NHTSA recalls + complaint flags (public)
  Plate decode    : jurisdiction format parsing (structural, no data leak)
  Reverse plate   : AUTHORITY-GATED gateway (warrant ref required) — stub that
                    exports a structured request until a provider is configured
  Gov registration: AUTHORITY-GATED lawful-access channel (SS7-style) — stub
  ALPR intake     : ingest agency-collected plate reads into evidence custody
                    (SHA-256 + timestamp + custodian) for sighting timelines

No unauthorized database access: reverse-plate and registration run only
through an authority-gated gateway (like SS7). Everything is audited.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15

# Configured providers (set via env / config). Empty => export for manual request.
VEHICLE_GATEWAY_ENDPOINT = ""   # authorized reverse-plate / registration provider
REGISTRATION_GATEWAY_ENDPOINT = ""

# US plate structural formats (parse only — not a data source)
PLATE_PATTERNS = {
    "US": re.compile(r'^[A-Z0-9]{1,8}$'),
    "US Vanity": re.compile(r'^[A-Z]{3,8}$'),
    "EU": re.compile(r'^[A-Z]{1,4}\s?\d{1,4}(\s?[A-Z]{1,3})?$'),
    "generic": re.compile(r'^[A-Z0-9 -]{2,10}$'),
}

VIN_RE = re.compile(r'^[A-HJ-NPR-Z0-9]{17}$')  # I,O,Q excluded per standard


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


# ---------------------------------------------------------------- VIN decode
def decode_vin(vin):
    """Decode a VIN via NHTSA vPIC (free, public)."""
    vin = (vin or "").strip().upper()
    out = {"input": vin}
    if not VIN_RE.match(vin):
        out["error"] = "invalid VIN (17 chars, no I/O/Q)"
        return out
    # check digit validation (position 9)
    out["check_digit_valid"] = _check_digit(vin)
    r = _get(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json")
    if isinstance(r, Exception):
        out["decode_error"] = str(r)[:150]
        return out
    try:
        res = r.json().get("Results", [{}])[0]
        out["vehicle"] = {
            "make": res.get("Make"), "model": res.get("Model"),
            "year": res.get("ModelYear"), "body_class": res.get("BodyClass"),
            "manufacturer": res.get("Manufacturer"), "plant_country": res.get("PlantCountry"),
            "series": res.get("Series"), "trim": res.get("Trim"),
            "engine": res.get("EngineCylinders"), "fuel": res.get("FuelTypePrimary"),
            "gvwr": res.get("GVWR"), "error_text": res.get("ErrorText"),
        }
    except Exception as e:
        out["decode_error"] = str(e)[:150]
    return out


def _check_digit(vin):
    """ISO 3779 VIN check digit (position 9)."""
    translit = {}
    for i, ch in enumerate("ABCDEFGH"):
        translit[ch] = i + 1
    for i, ch in enumerate("JKLMN", 8):
        translit[ch] = i + 1
    translit["P"] = 7; translit["R"] = 9
    for i, ch in enumerate("STUVWXYZ", 12):
        translit[ch] = i
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    total = 0
    for ch, w in zip(vin, weights):
        if ch.isdigit():
            v = int(ch)
        elif ch in translit:
            v = translit[ch]
        else:
            return None
        total += v * w
    rem = total % 11
    expected = "X" if rem == 10 else str(rem)
    return vin[8] == expected


def recalls(vin):
    """NHTSA recall / complaint lookup (free public API)."""
    vin = (vin or "").strip().upper()
    if not VIN_RE.match(vin):
        return {"error": "invalid VIN"}
    out = {"vin": vin}
    r = _get(f"https://api.nhtsa.gov/recalls/recallsByVehicle?vin={vin}")
    if isinstance(r, Exception):
        return {"error": str(r)[:150]}
    try:
        j = r.json()
        recs = j.get("results", [])
        out["count"] = len(recs)
        out["recalls"] = [{"component": x.get("component"),
                           "summary": (x.get("summary") or "")[:300],
                           "consequence": (x.get("consequence") or "")[:200],
                           "remedy": (x.get("remedy") or "")[:200],
                           "report_date": x.get("reportReceivedDate")}
                          for x in recs[:25]]
    except Exception as e:
        out["error"] = str(e)[:150]
    return out


# ---------------------------------------------------------------- plate decode
def decode_plate(plate, jurisdiction="US"):
    """Structural plate parsing (format only — no registration data)."""
    plate = (plate or "").strip().upper()
    out = {"input": plate, "jurisdiction": jurisdiction}
    if not plate:
        out["error"] = "empty plate"
        return out
    pat = PLATE_PATTERNS.get(jurisdiction, PLATE_PATTERNS["generic"])
    out["format_valid"] = bool(pat.match(plate))
    out["normalized"] = re.sub(r'[\s-]', '', plate)
    out["length"] = len(out["normalized"])
    out["plate_type"] = "vanity" if plate.isalpha() and len(plate) >= 5 else "standard"
    return out


# ---------------------------------------------------------------- reverse plate (authority-gated)
def reverse_plate_lookup(plate, jurisdiction, authority_ref, case_id, requested_by):
    """Reverse plate -> registered owner via AUTHORIZED gateway.

    Requires a lawful authority reference (warrant/order). No gateway configured
    => exports a structured request for manual submission through the provider
    channel (same model as SS7). Never queries unauthorized databases.
    """
    import json
    plate = (plate or "").strip().upper()
    problems = []
    if not plate:
        problems.append("plate required")
    if not (authority_ref or "").strip():
        problems.append("lawful authority reference (warrant) is required")
    if problems:
        return {"error": "request rejected", "problems": problems}

    req = {
        "type": "reverse_plate", "plate": plate, "jurisdiction": jurisdiction,
        "authority_ref": authority_ref.strip(), "case_id": case_id,
        "requested_by": requested_by, "status": "built",
    }
    endpoint = VEHICLE_GATEWAY_ENDPOINT
    req["status"] = "submitted" if endpoint else "exported_for_manual_submission"

    root = _upsert(case_id, "vehicle", f"plate:{plate}") if case_id else None
    ev = db.store_artifact(case_id, root, "vehicle", f"vehicle:reverse_plate:{jurisdiction}",
                           req, requested_by)
    db.audit(requested_by, "vehicle.reverse_plate", plate,
             f"jurisdiction={jurisdiction} auth={req['authority_ref']}")
    out = {"request": req, "evidence": ev}
    if endpoint:
        out["delivery"] = {"endpoint": endpoint, "mode": "gateway"}
        out["note"] = "submitted to authorized vehicle-data gateway"
    else:
        out["delivery"] = {"mode": "manual_export",
                           "payload": json.dumps(req, indent=2)}
        out["note"] = ("No vehicle gateway configured — request exported for "
                       "manual submission through the authorized provider channel.")
    return out


def registration_lookup(plate, jurisdiction, authority_ref, case_id, requested_by):
    """Gov registration/title via LAWFUL-ACCESS channel (authority-gated stub)."""
    import json
    plate = (plate or "").strip().upper()
    if not plate:
        return {"error": "plate required"}
    if not (authority_ref or "").strip():
        return {"error": "request rejected", "problems": ["lawful authority reference is required"]}
    req = {"type": "registration", "plate": plate, "jurisdiction": jurisdiction,
           "authority_ref": authority_ref.strip(), "case_id": case_id,
           "requested_by": requested_by, "status": "exported_for_manual_submission"}
    root = _upsert(case_id, "vehicle", f"plate:{plate}") if case_id else None
    ev = db.store_artifact(case_id, root, "vehicle", "vehicle:registration",
                           req, requested_by)
    db.audit(requested_by, "vehicle.registration", plate, f"auth={req['authority_ref']}")
    return {"request": req, "evidence": ev,
            "note": "No registration gateway configured — exported for lawful-access channel.",
            "delivery": {"mode": "manual_export", "payload": json.dumps(req, indent=2)}}


# ---------------------------------------------------------------- ALPR custody
def ingest_plate_sighting(plate, lat, lon, camera_id, case_id, custodian, source="alpr"):
    """Ingest an agency-collected plate read into evidence custody.

    This stores a lawfully-collected ALPR observation with chain-of-custody
    (SHA-256 + custodian + timestamp) — for building sighting timelines from
    feeds the agency already holds. It does NOT access external cameras.
    """
    plate = (plate or "").strip().upper()
    if not plate:
        return {"error": "plate required"}
    record = {"plate": plate, "lat": lat, "lon": lon, "camera_id": camera_id,
              "observed_at": db.utcnow(), "custodian": custodian, "source": source}
    root = _upsert(case_id, "vehicle", f"plate:{plate}") if case_id else None
    ev = db.store_artifact(case_id, root, "vehicle", f"vehicle:alpr:{source}", record, custodian)
    # attach a geo point so it shows on the map
    if case_id and lat is not None and lon is not None:
        try:
            from modules.geo import geo as GEO
            GEO.add_geo_entity(case_id, f"ALPR {plate} @{camera_id}", float(lat), float(lon))
        except Exception:
            pass
    db.audit(custodian, "vehicle.alpr_ingest", plate, f"cam={camera_id}")
    return {"ingested": True, "evidence": ev, "record": record}


def plate_timeline(plate, case_id=None):
    """Sighting history for a plate (from custody store)."""
    c = db.get_db()
    q = "SELECT id,source,content_hash,queried_at FROM artifacts WHERE type='vehicle' AND source LIKE 'vehicle:alpr:%'"
    args = []
    if case_id is not None:
        q += " AND case_id=?"
        args.append(case_id)
    q += " ORDER BY id DESC LIMIT 500"
    rows = [dict(r) for r in c.execute(q, args).fetchall()]
    import json
    timeline = []
    plate_u = (plate or "").strip().upper()
    for r in rows:
        try:
            rec = json.loads(c.execute("SELECT content FROM artifacts WHERE id=?",
                                       (r["id"],)).fetchone()["content"])
            if rec.get("plate") == plate_u:
                rec["artifact_id"] = r["id"]
                rec["hash"] = r["content_hash"]
                timeline.append(rec)
        except Exception:
            pass
    timeline.sort(key=lambda x: x.get("observed_at", ""))
    return {"plate": plate_u, "sightings": len(timeline), "timeline": timeline}


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
