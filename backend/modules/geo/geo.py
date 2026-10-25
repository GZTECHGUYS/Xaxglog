"""Xaxglog GEOINT module — geospatial intelligence.

Turns scattered geo signals into a spatial picture:
  - geocode / reverse-geocode (OSM Nominatim, free)
  - extract every mappable point from a case (geo entities, IP geo, places)
  - spatial query: "everything within N metres of a coordinate"
  - GeoJSON / KML export for GIS teams

The map consumes /api/geo/case/<id> to plot nodes on the Leaflet view.
"""
import json
import math
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 12
NOMINATIM = "https://nominatim.openstreetmap.org"

COORD_RE = re.compile(r'^(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)$')


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def geocode(place):
    """Forward geocode a place name -> coordinates."""
    r = _get(f"{NOMINATIM}/search?q={_q(place)}&format=json&limit=5")
    if isinstance(r, Exception):
        return {"input": place, "error": str(r)[:150]}
    try:
        return {"input": place, "results": [
            {"name": x.get("display_name"), "lat": float(x.get("lat")),
             "lon": float(x.get("lon")), "type": x.get("type"),
             "class": x.get("class")} for x in r.json()[:5]]}
    except Exception as e:
        return {"input": place, "error": str(e)[:150]}


def reverse_geocode(lat, lon):
    r = _get(f"{NOMINATIM}/reverse?lat={lat}&lon={lon}&format=json")
    if isinstance(r, Exception):
        return {"error": str(r)[:150]}
    try:
        j = r.json()
        return {"lat": lat, "lon": lon, "address": j.get("display_name"),
                "type": j.get("type"), "boundingbox": j.get("boundingbox")}
    except Exception as e:
        return {"error": str(e)[:150]}


def _q(s):
    import urllib.parse
    return urllib.parse.quote(s or "")


# ---------------------------------------------------------------- case map points
def case_points(case_id, max_points=800):
    """Pull every mappable point from a case's entities for the map view."""
    c = db.get_db()
    rows = [dict(r) for r in c.execute(
        "SELECT id,type,value,meta,first_seen FROM entities WHERE case_id=? LIMIT ?",
        (case_id, max_points)).fetchall()]
    points = []
    for r in rows:
        pt = _extract_point(r)
        if pt:
            points.append({**pt, "entity_id": r["id"], "type": r["type"],
                           "value": r["value"]})
    return {"case_id": case_id, "count": len(points), "points": points}


def _extract_point(entity):
    """Best-effort coordinate extraction from an entity value/meta."""
    meta = {}
    try:
        meta = json.loads(entity.get("meta") or "{}")
    except Exception:
        pass
    # explicit lat/lon in meta
    if "lat" in meta and "lon" in meta:
        try:
            return {"lat": float(meta["lat"]), "lon": float(meta["lon"]),
                    "label": meta.get("label", entity["value"])}
        except Exception:
            pass
    val = entity["value"]
    # value is a coordinate pair
    m = COORD_RE.match(val.strip())
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return {"lat": lat, "lon": lon, "label": val}
    # value embeds coordinates (e.g. "lat,lon something")
    m = re.search(r'(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)', val)
    if m:
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return {"lat": lat, "lon": lon, "label": val[:60]}
    return None


def add_geo_entity(case_id, label, lat, lon, etype="geo"):
    """Attach a coordinate as a geo entity to the graph."""
    c = db.get_db()
    now = db.utcnow()
    value = f"{lat},{lon}"
    meta = json.dumps({"lat": lat, "lon": lon, "label": label})
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, etype, value, now, now, meta))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


# ---------------------------------------------------------------- spatial query
def _haversine(lat1, lon1, lat2, lon2):
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))


def within_radius(case_id, lat, lon, radius_m=1000):
    """All case entities within `radius_m` of a coordinate."""
    pts = case_points(case_id)["points"]
    hits = []
    for p in pts:
        d = _haversine(lat, lon, p["lat"], p["lon"])
        if d <= radius_m:
            p["distance_m"] = round(d, 1)
            hits.append(p)
    hits.sort(key=lambda x: x["distance_m"])
    return {"center": {"lat": lat, "lon": lon}, "radius_m": radius_m,
            "count": len(hits), "results": hits}


# ---------------------------------------------------------------- GIS export
def export_geojson(case_id):
    pts = case_points(case_id)["points"]
    features = [{
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [p["lon"], p["lat"]]},
        "properties": {"entity_id": p["entity_id"], "entity_type": p["type"],
                       "value": p["value"], "label": p.get("label", p["value"])},
    } for p in pts]
    return {"type": "FeatureCollection", "features": features}


def export_kml(case_id):
    pts = case_points(case_id)["points"]
    placemarks = "".join(
        f"<Placemark><name>{_xml(p.get('label', p['value']))}</name>"
        f"<description>{p['type']}</description>"
        f"<Point><coordinates>{p['lon']},{p['lat']},0</coordinates></Point></Placemark>"
        for p in pts)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            f"{placemarks}</Document></kml>")


def _xml(s):
    import html
    return html.escape(str(s))


def geocode_to_case(place, case_id, user="system"):
    """Geocode a place and attach it to the case graph as a geo entity."""
    g = geocode(place)
    if not g.get("results"):
        return g
    top = g["results"][0]
    eid = add_geo_entity(case_id, top["name"], top["lat"], top["lon"])
    db.store_artifact(case_id, eid, "geo", "geo:geocode", top, user)
    db.audit(user, "geo.geocode", place, f"lat={top['lat']} lon={top['lon']}")
    return {"entity_id": eid, "result": top}
