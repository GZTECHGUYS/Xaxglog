"""Xaxglog location pins — persistent coordinates, bundle intel, geofence diff.

  create/list pins (case-attached or global)
  bundle(pin)  — one call: reverse geocode + buildings + POIs + aerial +
                 street-level imagery + Shodan OT exposure (key) +
                 OpenCelliD towers (token) + label news (GDELT)
  check(pin)   — re-bundle, digest-diff, raise typed alert on change
  passes(pin)  — SGP4 satellite pass schedule over the coordinate (sgp4 +
                 Celestrak TLEs) with Open-Meteo cloud cover ("next clear look")

Trackers consume fingerprint()/diff() as the `geo_pin` kind.
"""
import json
import math
import re
from datetime import datetime, timedelta, timezone

import config as C
import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15

_ready = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS geo_pins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  label TEXT NOT NULL,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  radius_m INTEGER NOT NULL DEFAULT 500,
  interval_min INTEGER NOT NULL DEFAULT 1440,
  last_check TEXT,
  created_by TEXT DEFAULT 'system',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS geo_pin_state (
  pin_id INTEGER PRIMARY KEY,
  digest TEXT DEFAULT '[]',
  detail TEXT DEFAULT '{}',
  checked_at TEXT
);
"""


def _ensure():
    global _ready
    if _ready:
        return
    c = db.get_db()
    c.executescript(SCHEMA)
    c.commit()
    _ready = True


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


# ---------------------------------------------------------------- pins CRUD
def create_pin(label, lat, lon, radius_m=500, case_id=None,
               interval_min=1440, user="system"):
    _ensure()
    try:
        lat, lon = float(lat), float(lon)
    except Exception:
        return {"error": "lat/lon must be numeric"}
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return {"error": "coordinate out of range"}
    if not str(label or "").strip():
        return {"error": "label required"}
    c = db.get_db()
    cur = c.execute(
        "INSERT INTO geo_pins (case_id,label,lat,lon,radius_m,interval_min,created_by,created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (case_id, str(label).strip()[:120], lat, lon, max(50, int(radius_m)),
         max(15, int(interval_min)), user, _now()))
    c.commit()
    c.execute("INSERT OR IGNORE INTO geo_pin_state (pin_id, digest, detail, checked_at)"
              " VALUES (?,'[]','{}',NULL)", (cur.lastrowid,))
    c.commit()
    # spatial anchor into the case graph
    if case_id is not None:
        try:
            import modules.geo.geo as GEO
            GEO.add_geo_entity(case_id, label, lat, lon)
        except Exception:
            pass
    db.audit(user, "geo.pin_create", label, f"{lat},{lon} r={radius_m}")
    return {"id": cur.lastrowid, "label": label, "lat": lat, "lon": lon,
            "radius_m": radius_m, "case_id": case_id}


def list_pins(case_id=None):
    _ensure()
    c = db.get_db()
    if case_id is not None:
        rows = c.execute("SELECT * FROM geo_pins WHERE case_id=? ORDER BY id DESC",
                         (case_id,)).fetchall()
    else:
        rows = c.execute("SELECT * FROM geo_pins ORDER BY id DESC LIMIT 200").fetchall()
    return {"count": len(rows), "pins": [dict(r) for r in rows]}


def get_pin(pin_id):
    _ensure()
    row = db.get_db().execute("SELECT * FROM geo_pins WHERE id=?", (pin_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------- bundle
def _shodan_geo(lat, lon, radius):
    key = getattr(C, "SHODAN_API_KEY", None)
    if not key:
        return {"status": "skipped", "reason": "no SHODAN_API_KEY"}
    r = _get(f"https://api.shodan.io/shodan/host/search?key={key}"
             f"&query=geo:{lat},{lon}")
    if isinstance(r, Exception) or r.status_code != 200:
        return {"status": "error", "http": getattr(r, "status_code", None)}
    try:
        matches = (r.json() or {}).get("matches") or []
        hosts = [{"ip": m.get("ip_str"), "port": m.get("port"),
                  "product": m.get("product"), "org": m.get("org")}
                 for m in matches[:40]]
        return {"status": "ok", "count": len(matches), "hosts": hosts}
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}


def _opencellid(lat, lon):
    import os
    token = os.getenv("OPENCELLID_TOKEN") or getattr(C, "OPENCELLID_TOKEN", None)
    if not token:
        return {"status": "skipped", "reason": "no OPENCELLID_TOKEN"}
    r = _get(f"https://opencellid.org/cell/getCurrentByLatLon?lat={lat}&lon={lon}"
             f"&token={token}&limit=50")
    if isinstance(r, Exception) or r.status_code != 200:
        return {"status": "error", "http": getattr(r, "status_code", None)}
    try:
        cells = (r.json() or {}).get("cells") or []
        return {"status": "ok", "count": len(cells),
                "cells": [{"mcc": c.get("mcc"), "mnc": c.get("mnc"),
                           "lac": c.get("lac"), "cid": c.get("cellId"),
                           "range_m": c.get("range")} for c in cells[:30]]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}


def _news(label, radius_km):
    if not label:
        return {"status": "skipped", "reason": "no label to search"}
    try:
        import modules.risk.risk as RISK
        r = RISK.gdelt_news(f'"{label}"', "1week", maxrecords=15)
        arts = r.get("articles") or []
        return {"status": "ok", "count": len(arts),
                "titles": [a.get("title", "")[:120] for a in arts[:10]]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}


def bundle(pin):
    """Full intel sweep for one pin — every source degrades independently."""
    lat, lon, radius = pin["lat"], pin["lon"], pin.get("radius_m") or 500
    out = {"pin": {"id": pin["id"], "label": pin["label"], "lat": lat,
                   "lon": lon, "radius_m": radius}}
    try:
        import modules.geo.geo as GEO
        out["reverse_geocode"] = GEO.reverse_geocode(lat, lon)
    except Exception as e:
        out["reverse_geocode"] = {"error": str(e)[:120]}
    for key, fn in (("buildings", lambda: _geoext("buildings_at", lat, lon, radius)),
                    ("pois", lambda: _geoext("pois_at", lat, lon, radius)),
                    ("aerial", lambda: _geoext("openaerial_search", lat, lon, radius)),
                    ("street_imagery", lambda: _geoext("mapillary_images", lat, lon, min(radius, 300)))):
        try:
            out[key] = fn()
        except Exception as e:
            out[key] = {"status": "error", "error": str(e)[:120]}
    out["shodan"] = _shodan_geo(lat, lon, radius)
    out["cell_towers"] = _opencellid(lat, lon)
    out["news"] = _news(pin.get("label"), radius / 1000.0)
    return out


def _geoext(fn, lat, lon, radius):
    import modules.geoext.geoext as GX
    return getattr(GX, fn)(lat, lon, radius)


def _digest(b):
    """Stable identity set across bundles — what actually changed."""
    items = []
    for key in ("buildings", "pois", "aerial", "street_imagery"):
        src = b.get(key) or {}
        if src.get("status") not in (None, "ok"):
            continue
        for it in (src.get(key if key != "street_imagery" else "images") or [])[:400]:
            ident = it.get("id") or it.get("osm_id") or it.get("url") or json.dumps(it)[:120]
            items.append(f"{key}:{ident}")
    sh = b.get("shodan") or {}
    for h in (sh.get("hosts") or [])[:100]:
        items.append(f"shodan:{h.get('ip')}:{h.get('port')}")
    ct = b.get("cell_towers") or {}
    for c in (ct.get("cells") or [])[:80]:
        items.append(f"cell:{c.get('mcc')}/{c.get('mnc')}/{c.get('lac')}/{c.get('cid')}")
    return sorted(set(str(x) for x in items))


def fingerprint(pin_id, case_id=None):
    """Tracker-facing snapshot of a pin (used by geo_pin kind)."""
    pin = get_pin(pin_id) if not isinstance(pin_id, dict) else pin_id
    if not pin:
        # allow "id" strings / bare ints from tracker targets
        try:
            pin = get_pin(int(str(pin_id)))
        except Exception:
            pin = None
    if not pin:
        return {"status": "error", "error": f"pin {pin_id} not found"}
    b = bundle(pin)
    items = _digest(b)
    counts = {k: (b.get(k) or {}).get("count") for k in
              ("buildings", "pois", "aerial", "street_imagery", "shodan", "cell_towers", "news")}
    return {"status": "ok", "pin_id": pin["id"], "label": pin["label"],
            "items": items[:600], "counts": {k: v for k, v in counts.items() if v is not None},
            "checked_at": _now()}


def diff(old, new, target=""):
    """Alerts for the trackers registry + standalone check()."""
    o = set((old or {}).get("items") or [])
    n = set((new or {}).get("items") or [])
    added, removed = sorted(n - o), sorted(o - n)
    alerts = []
    if o and added:
        alerts.append({"severity": "medium",
                       "message": f"geo_pin [{target}]: {len(added)} new items in radius",
                       "detail": {"added": added[:10], "removed_count": len(removed)}})
    elif o and removed:
        alerts.append({"severity": "low",
                       "message": f"geo_pin [{target}]: {len(removed)} items disappeared",
                       "detail": {"removed": removed[:10]}})
    return alerts


def check(pin_id, user="system"):
    """Standalone geofence check: bundle -> digest -> diff -> alert -> state."""
    _ensure()
    pin = get_pin(int(pin_id))
    if not pin:
        return {"status": "error", "error": "pin not found"}
    fp = fingerprint(pin)
    if fp.get("status") != "ok":
        return fp
    c = db.get_db()
    row = c.execute("SELECT digest FROM geo_pin_state WHERE pin_id=?", (pin["id"],)).fetchone()
    try:
        old_items = set(json.loads(row["digest"])) if row else set()
    except Exception:
        old_items = set()
    alerts = diff({"items": sorted(old_items)}, fp, pin["label"]) if old_items else []
    c.execute(
        "INSERT INTO geo_pin_state (pin_id, digest, detail, checked_at) VALUES (?,?,?,?)"
        " ON CONFLICT(pin_id) DO UPDATE SET digest=excluded.digest, detail=excluded.detail,"
        " checked_at=excluded.checked_at",
        (pin["id"], json.dumps(fp["items"]), json.dumps(fp.get("counts") or {}), _now()))
    c.execute("UPDATE geo_pins SET last_check=? WHERE id=?", (_now(), pin["id"]))
    c.commit()
    for a in alerts:
        try:
            import modules.cases.cases as CASES
            CASES.raise_alert(None, pin["case_id"], a["severity"], a["message"], a["detail"])
        except Exception:
            pass
    db.audit(user, "geo.pin_check", pin["label"], f"items={len(fp['items'])} alerts={len(alerts)}")
    return {"status": "ok", "pin": {"id": pin["id"], "label": pin["label"]},
            "items": len(fp["items"]), "counts": fp.get("counts"),
            "previous_items": len(old_items), "alerts": alerts,
            "changed": bool(alerts)}


# ---------------------------------------------------------------- satellite passes
TLE_SOURCES = [
    ("SENTINEL-2A", "https://celestrak.org/NORAD/elements/gp.php?NAME=SENTINEL-2A&FORMAT=tle"),
    ("SENTINEL-2B", "https://celestrak.org/NORAD/elements/gp.php?NAME=SENTINEL-2B&FORMAT=tle"),
    # Celestrak catalog names use a space, and CATNR (not NORAD_CAT_ID) for ids —
    # NAME=ISS would substring-match the "UME (ISS)" ham satellites instead
    ("LANDSAT 8", "https://celestrak.org/NORAD/elements/gp.php?NAME=LANDSAT%208&FORMAT=tle"),
    ("LANDSAT 9", "https://celestrak.org/NORAD/elements/gp.php?NAME=LANDSAT%209&FORMAT=tle"),
    ("ISS (ZARYA)", "https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=tle"),
]


def _fetch_tles():
    import time
    tles = []
    for name, url in TLE_SOURCES:
        r = _get(url)
        if isinstance(r, Exception) or getattr(r, "status_code", None) != 200:
            time.sleep(0.5)  # Celestrak throttles bursts — pace politely
            continue
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
        triples = []
        for i, ln in enumerate(lines):
            if ln.startswith("1 ") and i + 1 < len(lines) and lines[i + 1].startswith("2 "):
                nm = lines[i - 1] if i > 0 and not lines[i - 1].startswith(("1 ", "2 ")) else name
                triples.append((nm, ln, lines[i + 1]))
        if triples:
            # prefer a returned name that actually contains the requested one
            pick = next((t for t in triples if name.lower() in t[0].lower()), triples[0])
            tles.append({"name": pick[0], "l1": pick[1], "l2": pick[2]})
        time.sleep(0.5)
    return tles


def _gmst(jd):
    """Greenwich mean sidereal time (radians) — USNO approximation."""
    t = (jd - 2451545.0) / 36525.0
    g = (280.46061837 + 360.98564736629 * (jd - 2451545.0)
         + 0.000387933 * t * t - t * t * t / 38710000.0)
    return math.radians(g % 360.0)


def _look_angles(sat_rec, lat, lon, when, days=5, step_s=60):
    """SGP4 propagate + geodetic topocentric look angles, 60s grid.
    SGP4 returns TEME coordinates — rotate into ECEF with GMST before
    differencing against the site, otherwise elevations are garbage."""
    from sgp4.api import Satrec, jday
    a, f = 6378137.0, 1 / 298.257223563
    e2 = f * (2 - f)
    latr, lonr = math.radians(lat), math.radians(lon)
    sin_l, cos_l = math.sin(latr), math.cos(latr)
    sin_o, cos_o = math.sin(lonr), math.cos(lonr)
    N = a / math.sqrt(1 - e2 * sin_l * sin_l)
    X = N * cos_l * cos_o
    Y = N * cos_l * sin_o
    Z = N * (1 - e2) * sin_l
    samples = []
    t = when
    end = when + timedelta(days=max(1, min(int(days), 10)))
    while t <= end:
        jd, fr = jday(t.year, t.month, t.day, t.hour, t.minute,
                      t.second + t.microsecond / 1e6)
        err, r, _v = sat_rec.sgp4(jd, fr)
        if err == 0:
            rot = _gmst(jd + fr)
            cs, sn = math.cos(rot), math.sin(rot)
            sx, sy = (r[0] * cs + r[1] * sn) * 1000, (-r[0] * sn + r[1] * cs) * 1000
            sz = r[2] * 1000
            dx, dy, dz = sx - X, sy - Y, sz - Z
            east = -sin_o * dx + cos_o * dy
            north = -sin_l * cos_o * dx - sin_l * sin_o * dy + cos_l * dz
            up = cos_l * cos_o * dx + cos_l * sin_o * dy + sin_l * dz
            horiz = math.sqrt(east * east + north * north)
            el = math.degrees(math.atan2(up, horiz))
            az = (math.degrees(math.atan2(east, north)) + 360) % 360
            samples.append((t.isoformat(), round(el, 1), round(az, 1)))
        t += timedelta(seconds=step_s)
    return samples


def _segment_passes(samples, min_elev):
    runs, cur = [], None
    for iso, el, az in samples:
        if el >= min_elev:
            if cur is None:
                cur = {"start": iso, "start_az": az, "max_elev": el, "end": iso, "end_az": az}
            else:
                cur["end"] = iso
                cur["end_az"] = az
                cur["max_elev"] = max(cur["max_elev"], el)
        elif cur is not None:
            runs.append(cur)
            cur = None
    if cur:
        runs.append(cur)
    return runs


def _cloud_forecast(lat, lon, days=5):
    r = _get(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
             f"&hourly=cloud_cover&forecast_days={min(days, 7)}&timezone=UTC")
    if isinstance(r, Exception) or r.status_code != 200:
        return {}
    try:
        hours = (r.json() or {}).get("hourly") or {}
        out = {}
        for t, cc in zip(hours.get("time") or [], hours.get("cloud_cover") or []):
            # Open-Meteo returns "2026-10-22T23:00" -> normalise to the same
            # "2026-10-22T23:00Z" key the pass windows use
            out[str(t)[:13] + ":00Z"] = cc
        return out
    except Exception:
        return {}


def passes(pin_or_lat=None, lon=None, days=5, min_elev=30.0, user="system"):
    """Next satellite passes over a coordinate — SGP4 + Celestrak TLEs +
    Open-Meteo cloud cover. `pin_or_lat` is a pin id (via bundle) or lat."""
    _ensure()
    try:
        from sgp4.api import Satrec  # noqa: F401
    except Exception:
        return {"status": "missing_dependency",
                "error": "sgp4 not installed — satellite math needs it",
                "install": "pip install sgp4"}
    if lon is None:
        pin = get_pin(int(pin_or_lat))
        if not pin:
            return {"status": "error", "error": "pin not found"}
        lat, lon, label = pin["lat"], pin["lon"], pin["label"]
    else:
        lat, label = float(pin_or_lat), f"{pin_or_lat},{lon}"
    tles = _fetch_tles()
    if not tles:
        return {"status": "error", "error": "no TLEs reachable (Celestrak down?)"}
    from sgp4.api import Satrec
    start = datetime.now(timezone.utc).replace(microsecond=0)
    cloud = _cloud_forecast(lat, lon, days)
    results = []
    for t in tles:
        try:
            sat = Satrec.twoline2rv(t["l1"], t["l2"])
            samples = _look_angles(sat, float(lat), float(lon), start, days=days)
            for p in _segment_passes(samples, min_elev)[:6]:
                hour_key = (p["start"] or "")[:13] + ":00Z"
                cc = cloud.get(hour_key)
                p["satellite"] = t["name"]
                p["cloud_cover_pct"] = cc
                p["view"] = "clear" if (cc is not None and cc < 40) else (
                    "overcast" if cc is not None else "unknown")
                results.append(p)
        except Exception as e:
            results.append({"satellite": t["name"], "error": str(e)[:100]})
    results.sort(key=lambda p: p.get("start") or "9999")
    db.audit(user, "geo.passes", label, f"passes={len([r for r in results if r.get('start')])}")
    return {"status": "ok", "lat": lat, "lon": lon, "label": label,
            "window_days": days, "min_elevation": min_elev,
            "tle_count": len(tles), "passes": [r for r in results if r.get("start")][:15],
            "errors": [r for r in results if r.get("error")]}
