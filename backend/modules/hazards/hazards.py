"""Xaxglog hazards — disaster/emergency overlay for ops context.

Open, keyless sources:
  - USGS earthquakes (earthquake.usgs.gov geojson feeds) — M4.5+ worldwide
    (hour/day/week), by-bbox queries. No key, generous limits.
  - GDACS (gdacs.org API) — significant disaster alerts (EQ, TC, FL, VO...)
    with alert levels (Green/Orange/Red), affected population estimates.
  - NWS/NOAA alerts (api.weather.gov, US only) — active watches/warnings
    by point or zone. No key (they ask for a contact UA — provided).

Use: attach to a case's geo footprint — is there a natural event affecting
the area of interest (evacuation, comms outage, border closure)? Pairs with
geo/geoext radius queries; results become custody artifacts and can feed
trackers alerts.

Lawful-use note: public government/emergency feeds. Advisory only — not an
authoritative warning source (always defer to national met services).
"""
import json

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (ops contact: ops@localhost)"}
T = 25
USGS_WEEK = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_week.geojson"
USGS_DAY = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.geojson"
USGS_BBOX = ("https://earthquake.usgs.gov/fdsnws/event/1/query?"
             "format=geojson&minmagnitude={minm}&starttime={start}"
             "&bbox={bbox}&limit=200")
GDACS = "https://www.gdacs.org/gdacsapi/api/events/geteventlist/MAP"
NWS_POINT = "https://api.weather.gov/alerts/active?point={lat},{lon}"
NWS_AREA = "https://api.weather.gov/alerts/active?area={state}"


def quakes(min_magnitude=4.5, window="week", bbox=None, limit=100):
    """Earthquakes: global feed or bbox-restricted FDSN query (keyless)."""
    try:
        import requests
        min_magnitude = float(min_magnitude)
        if bbox:
            url = USGS_BBOX.format(
                minm=min_magnitude,
                start=__import__("datetime").datetime.utcnow().date().isoformat()
                if bbox else "",
                bbox=",".join(str(v) for v in bbox))
        else:
            url = USGS_WEEK if window == "week" else USGS_DAY
        r = requests.get(url, headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"USGS HTTP {r.status_code}"}
        feats = (r.json().get("features") or [])[:limit]
        out = []
        for f in feats:
            p = f.get("properties", {})
            g = (f.get("geometry") or {}).get("coordinates") or [None, None, None]
            out.append({
                "mag": p.get("mag"), "place": p.get("place"),
                "time": p.get("time"), "tsunami": p.get("tsunami"),
                "alert": p.get("alert"), "felt": p.get("felt"),
                "lon": g[0], "lat": g[1], "depth_km": g[2],
                "detail": p.get("detail"),
            })
        out.sort(key=lambda x: -(x["time"] or 0))
        db.audit("system", "hazards.quakes",
                 "bbox" if bbox else window, f"n={len(out)} m>={min_magnitude}")
        return {"status": "ok", "count": len(out),
                "min_magnitude": min_magnitude, "window": "bbox" if bbox else window,
                "quakes": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "quakes": []}


def gdacs(alert_level=None, event_types=None, limit=100):
    """GDACS significant-disaster alerts (keyless)."""
    try:
        import requests
        r = requests.get(GDACS, headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"GDACS HTTP {r.status_code}"}
        j = r.json()
        rows = j.get("features") or []
        out = []
        for f in rows:
            props = f.get("properties") or {}
            etype = (props.get("eventtype") or "").upper()
            level = (props.get("alertlevel") or "").capitalize()
            if alert_level and level.lower() != str(alert_level).lower():
                continue
            if event_types and etype not in {str(t).upper() for t in event_types}:
                continue
            geom = (f.get("geometry") or {}).get("coordinates") or [None, None]
            out.append({
                "event_id": props.get("eventid"), "type": etype,
                "alert_level": level, "country": props.get("country"),
                "headline": props.get("headline"),
                "from_date": props.get("fromdate"), "to_date": props.get("todate"),
                "population": props.get("population"),
                "lon": geom[0], "lat": geom[1],
            })
            if len(out) >= limit:
                break
        db.audit("system", "hazards.gdacs", alert_level or "-", f"n={len(out)}")
        return {"status": "ok", "count": len(out), "events": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "events": []}


def nws_alerts(lat=None, lon=None, state=None):
    """US NWS active alerts by point or state code (keyless)."""
    try:
        import requests
        if lat is not None and lon is not None:
            url = NWS_POINT.format(lat=float(lat), lon=float(lon))
        elif state:
            url = NWS_AREA.format(state=state.upper()[:2])
        else:
            return {"status": "error", "error": "provide lat+lon or a state code"}
        r = requests.get(url, headers=UA, timeout=T)
        if r.status_code == 204:
            return {"status": "ok", "count": 0, "alerts": []}
        if r.status_code != 200:
            return {"status": "error", "error": f"NWS HTTP {r.status_code}"}
        feats = (r.json().get("features") or [])[:80]
        out = [{
            "event": f2.get("properties", {}).get("event"),
            "severity": f2.get("properties", {}).get("severity"),
            "headline": (f2.get("properties", {}).get("headline") or "")[:240],
            "onset": f2.get("properties", {}).get("onset"),
            "expires": f2.get("properties", {}).get("expires"),
            "area": f2.get("properties", {}).get("areaDesc"),
        } for f2 in feats]
        return {"status": "ok", "count": len(out), "alerts": out,
                "note": "US only (NOAA/NWS)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "alerts": []}


def area_brief(lat, lon, radius_km=100, min_magnitude=4.0, case_id=None,
               queried_by="system"):
    """Combined brief for a point: nearby quakes (7d) + GDACS near + NWS.

    bbox derived as +/- (radius/111) degrees (rough, fine for briefs).
    """
    try:
        lat, lon = float(lat), float(lon)
        d = max(0.5, float(radius_km) / 111.0)
        bbox = [lon - d, lat - d, lon + d, lat + d]
        eq = quakes(min_magnitude=min_magnitude, bbox=bbox, limit=50)
        gd = gdacs(limit=200)
        # GDACS near filter by haversine
        import math
        near = []
        for ev in (gd.get("events") or []):
            if ev.get("lat") is None or ev.get("lon") is None:
                continue
            dlat = math.radians(ev["lat"] - lat)
            dlon = math.radians(ev["lon"] - lon)
            a = (math.sin(dlat / 2) ** 2
                 + math.cos(math.radians(lat)) * math.cos(math.radians(ev["lat"]))
                 * math.sin(dlon / 2) ** 2)
            dist = 6371 * 2 * math.asin(math.sqrt(a))
            if dist <= float(radius_km):
                ev["distance_km"] = round(dist, 1)
                near.append(ev)
        nw = nws_alerts(lat=lat, lon=lon)
        brief = {
            "point": [lat, lon], "radius_km": radius_km,
            "quakes": (eq.get("quakes") or [])[:20],
            "gdacs_near": near[:20],
            "nws_alerts": (nw.get("alerts") or [])[:10],
            "advisory": "advisory overlay only — defer to national services",
        }
        total_events = len(brief["quakes"]) + len(near) + len(brief["nws_alerts"])
        brief["operational_note"] = (
            "active natural events in area — review logistics/comms assumptions"
            if total_events else "no significant natural events in area/window")
        db.audit(queried_by, "hazards.area_brief", f"{lat},{lon}",
                 f"events={total_events}")
        if case_id is not None:
            art = db.store_artifact(case_id, None, "hazard", "gdacs+usgs+nws",
                                    brief, queried_by)
            brief["artifact"] = art
        return {"status": "ok", "brief": brief}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def sources():
    return {"status": "ok", "feeds": {
        "usgs": "earthquake.usgs.gov geojson feeds (keyless)",
        "gdacs": "gdacs.org disaster alert API (keyless)",
        "nws": "api.weather.gov active alerts (keyless, US)"}}
