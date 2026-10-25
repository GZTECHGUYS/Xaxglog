"""Xaxglog flight — civil aircraft tracking from OpenSky (keyless).

Open sources:
  - OpenSky Network REST API (opensky-network.org) — anonymous access works
    with per-IP rate limits (~10s resolution anonymously). The module
    self-throttles and degrades with a clear note when throttled.

Queries: current state by ICAO24 hex address, aircraft within a bounding box,
and recently departed/arrived flights at an airport (when the anonymous
quota allows). Results land as custody artifacts when a case_id is given.

Lawful-use note: OpenSky publishes ADS-B as received from voluntary receivers.
Passive civil-aviation awareness only — no transponder interrogation.
"""
import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
OPENSKY = "https://opensky-network.org/api"
_last = [0.0]
MIN_GAP = 10.0  # anonymous OpenSky guidance: keep ~10s between calls


def _get(path, params=None):
    import time
    import requests
    wait = MIN_GAP - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    r = requests.get(f"{OPENSKY}{path}", headers=UA, params=params, timeout=T)
    _last[0] = time.time()
    if r.status_code == 429:
        return {"status": "throttled", "error": "OpenSky rate limit — retry in a minute"}
    if r.status_code != 200:
        return {"status": "error", "error": f"HTTP {r.status_code}"}
    return {"status": "ok", "data": r.json()}


def _state(s):
    return {
        "icao24": s.get("icao24"), "callsign": (s.get("callsign") or "").strip(),
        "origin_country": s.get("originCountry"),
        "lon": s.get("longitude"), "lat": s.get("latitude"),
        "baro_altitude": s.get("baroAltitude"), "geo_altitude": s.get("geoAltitude"),
        "velocity": s.get("velocity"), "true_track": s.get("trueTrack"),
        "vertical_rate": s.get("verticalRate"),
        "on_ground": s.get("onGround"),
        "last_contact": s.get("lastContact"),
        "squawk": s.get("squawk"), "spi": s.get("spi"),
    }


def aircraft(icao24):
    """Current state of one aircraft by ICAO24 hex address."""
    try:
        icao24 = (icao24 or "").strip().lower()
        if not icao24 or len(icao24) > 6:
            return {"status": "error", "error": "invalid ICAO24 (1-6 hex)"}
        out = _get(f"/states/all?icao24={icao24}")
        if out["status"] != "ok":
            return out
        states = (out["data"].get("states") or [])
        if not states:
            return {"status": "notfound", "icao24": icao24,
                    "note": "aircraft not currently broadcasting"}
        st = _state(states[0])
        db.audit("system", "flight.aircraft", icao24, st.get("callsign") or "")
        return {"status": "ok", "aircraft": st}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def area(lamin, lomin, lamax, lomax, limit=100):
    """All broadcasting aircraft inside a bounding box (max ~10 deg wide)."""
    try:
        lamin, lomin, lamax, lomax = map(float, (lamin, lomin, lamax, lomax))
        if lamax - lamin > 10 or lomax - lomin > 10:
            return {"status": "error", "error": "bbox larger than 10 degrees — narrow it"}
        out = _get(f"/states/all?lamin={lamin}&lomin={lomin}&lamax={lamax}&lomax={lomax}")
        if out["status"] != "ok":
            return out
        states = [_state(s) for s in (out["data"].get("states") or [])[:limit]]
        return {"status": "ok", "count": len(states), "aircraft": states}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "aircraft": []}


def airport(icao, kind="departure", begin=None, end=None):
    """Departures/arrivals at an ICAO airport code (anonymous quota may 403)."""
    try:
        icao = (icao or "").strip().upper()
        if len(icao) != 4:
            return {"status": "error", "error": "invalid ICAO airport code"}
        if kind not in ("departure", "arrival"):
            return {"status": "error", "error": "kind must be departure|arrival"}
        import time as _t
        now = int(_t.time())
        params = [f"airport={icao}", f"begin={begin or now - 7200}", f"end={end or now}"]
        out = _get(f"/flights/{kind}?" + "&".join(params))
        if out["status"] != "ok":
            return out
        flights = [{
            "icao24": f.get("icao24"), "callsign": f.get("callsign"),
            "first_seen": f.get("firstSeen"), "last_seen": f.get("lastSeen"),
            "est_departure": f.get("estDepartureAirport"),
            "est_arrival": f.get("estArrivalAirport"),
        } for f in out["data"]]
        return {"status": "ok", "airport": icao, "kind": kind,
                "count": len(flights), "flights": flights}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "flights": []}


def attach(case_id, icao24, queried_by="system"):
    """Store current aircraft state as a case artifact (chain of custody)."""
    out = aircraft(icao24)
    if out.get("status") != "ok":
        return out
    art = db.store_artifact(case_id, None, "flight", "opensky",
                            out["aircraft"], queried_by)
    return {"status": "ok", "aircraft": out["aircraft"], "artifact": art}
