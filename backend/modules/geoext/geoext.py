"""Xaxglog GEOEXT module — global buildings/POIs + addressing (keyless GEOINT).

Purpose
-------
Extend the local geo picture with keyless, public map data:

  - buildings_at()      : building footprints (tags + centre) around a coordinate
                          from OpenStreetMap via the Overpass API.
  - pois_at()           : POIs (amenity|shop|tourism|office|leisure|industrial)
                          around a coordinate, each tagged with a category.
  - landuse_at()        : landuse + building coverage summary counts by tag.
  - footprints_geojson() : building ways as a GeoJSON FeatureCollection
                          (Polygon from `out geom`, centre Point fallback) for
                          the map view.
  - mapillary_images()  : street-level imagery near a point — ONLY when
                          MAPILLARY_CLIENT_TOKEN is set; otherwise skipped.
  - zip_lookup()        : postal-code → place/coordinates (zippopotam.us).
  - openaerial_search() : openly licensed aerial imagery metadata (OpenAerialMap).

Sources (public / keyless unless noted):
  https://overpass-api.de/api/interpreter  (+ https://overpass.kumi.systems fallback)
  https://graph.mapillary.com/images        (token required, optional)
  http://api.zippopotam.us/<country>/<postal>
  https://api.openaerialmap.org/meta

Lawful use: reads openly published map and imagery METADATA for OSINT /
situational awareness (building & POI context, imagery discovery). No auth
bypass, no private data, no high-volume scraping — single bounded queries with
a result cap; Overpass fallback honours the provider's fair-use policy and
OpenStreetMap data is ODbL-attributed. Public functions never raise; failures
return {"error": str(e)[:150]}.
"""
import math
import os

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
OVERPASS_URLS = ["https://overpass-api.de/api/interpreter",
                 "https://overpass.kumi.systems/api/interpreter"]
POI_KEYS = ["amenity", "shop", "tourism", "office", "leisure", "industrial"]


# ---------------------------------------------------------------- http helpers
def _overpass(query, timeout=45):
    """Run an Overpass QL query (POST), primary instance then fallback."""
    import requests
    last = ""
    for url in OVERPASS_URLS:
        try:
            r = requests.post(url, data={"data": query}, headers=UA, timeout=timeout)
            if r.status_code >= 400:
                last = f"{url.split('/')[2]} HTTP {r.status_code}"
                continue
            j = r.json()
            if isinstance(j, dict) and j.get("error"):
                last = str(j.get("error"))[:120]
                continue
            if not isinstance(j, dict) or "elements" not in j:
                last = f"{url.split('/')[2]} malformed response"
                continue
            return j
        except Exception as e:
            last = str(e)[:150]
    return {"error": last or "overpass unavailable"}


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _limit(cap, hard=500):
    try:
        return max(1, min(int(cap), hard))
    except Exception:
        return 100


def _f(v, default=None):
    try:
        return float(v)
    except Exception:
        return default


def _centre(el):
    # nodes carry top-level lat/lon; ways/relations carry a "center" object
    lat, lon = _f(el.get("lat")), _f(el.get("lon"))
    if lat is not None and lon is not None:
        return lat, lon
    c = el.get("center") or {}
    lat, lon = _f(c.get("lat")), _f(c.get("lon"))
    if lat is None and el.get("geometry"):
        pts = [p for p in el["geometry"] if _f(p.get("lat")) is not None]
        if pts:
            lat = sum(_f(p["lat"]) for p in pts) / len(pts)
            lon = sum(_f(p["lon"]) for p in pts) / len(pts)
    return lat, lon


# ---------------------------------------------------------------- buildings
def buildings_at(lat, lon, radius=300, cap=400):
    """Building ways around a point: tags + centre. Returns count/buildings/polygons."""
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates", "count": 0, "buildings": [],
                    "polygons": False}
        q = ('[out:json][timeout:25];\n'
             f'way["building"](around:{int(radius)},{lat},{lon});\n'
             f'out tags center {_limit(cap)};')
        j = _overpass(q)
        if "error" in j:
            return {"error": j["error"], "count": 0, "buildings": [],
                    "polygons": False}
        buildings = []
        for el in (j.get("elements") or [])[:int(cap)]:
            if el.get("type") != "way" and el.get("type") != "relation":
                continue
            tags = el.get("tags") or {}
            clat, clon = _centre(el)
            b = {"id": el.get("id"), "type": el.get("type"),
                 "lat": clat, "lon": clon, "center": {"lat": clat, "lon": clon},
                 "tags": tags, "name": tags.get("name"),
                 "building": tags.get("building"),
                 "levels": _f(tags.get("building:levels")),
                 "height": _f(tags.get("height"))}
            if el.get("geometry"):
                b["geometry"] = el["geometry"]
            buildings.append(b)
        return {"count": len(buildings), "buildings": buildings,
                "polygons": any(b.get("geometry") for b in buildings),
                "radius": int(radius)}
    except Exception as e:
        return {"error": str(e)[:150], "count": 0, "buildings": [],
                "polygons": False}


def pois_at(lat, lon, radius=300, cap=400):
    """POIs (amenity|shop|tourism|office|leisure|industrial) around a point."""
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates", "count": 0, "pois": []}
        stmts = []
        for key in POI_KEYS:
            for kind in ("node", "way"):
                stmts.append(f'{kind}["{key}"](around:{int(radius)},{lat},{lon});')
        q = ("[out:json][timeout:25];\n(\n" + "\n".join(stmts) +
             f"\n);\nout tags center {_limit(cap)};")
        j = _overpass(q)
        if "error" in j:
            return {"error": j["error"], "count": 0, "pois": []}
        pois = []
        for el in (j.get("elements") or [])[:int(cap)]:
            tags = el.get("tags") or {}
            cat = next((k for k in POI_KEYS if k in tags), "")
            plat, plon = _centre(el)
            pois.append({"id": el.get("id"), "type": el.get("type"),
                         "lat": plat, "lon": plon, "category": cat,
                         "category_value": tags.get(cat) if cat else None,
                         "name": tags.get("name"), "tags": tags})
        return {"count": len(pois), "pois": pois, "radius": int(radius)}
    except Exception as e:
        return {"error": str(e)[:150], "count": 0, "pois": []}


def landuse_at(lat, lon, radius=300):
    """Landuse + building coverage summary: counts by tag value."""
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates"}
        q = ('[out:json][timeout:25];\n(\n'
             f'way["landuse"](around:{int(radius)},{lat},{lon});\n'
             f'way["building"](around:{int(radius)},{lat},{lon});\n'
             f');\nout tags center {_limit(500, 1000)};')
        j = _overpass(q)
        if "error" in j:
            return {"error": j["error"]}
        landuse, buildings, others = {}, {}, {}
        for el in (j.get("elements") or []):
            tags = el.get("tags") or {}
            if "landuse" in tags:
                v = str(tags["landuse"])
                landuse[v] = landuse.get(v, 0) + 1
            elif "building" in tags:
                v = str(tags.get("building", "yes"))
                buildings[v] = buildings.get(v, 0) + 1
            else:
                for k in ("highway", "natural", "waterway", "leisure"):
                    if k in tags:
                        v = f"{k}={tags[k]}"
                        others[v] = others.get(v, 0) + 1
                        break
        return {"radius": int(radius),
                "total_elements": len(j.get("elements") or []),
                "landuse": dict(sorted(landuse.items(), key=lambda x: -x[1])),
                "buildings": dict(sorted(buildings.items(), key=lambda x: -x[1])),
                "other": dict(sorted(others.items(), key=lambda x: -x[1]))}
    except Exception as e:
        return {"error": str(e)[:150]}


def footprints_geojson(lat, lon, radius=300, cap=200):
    """GeoJSON FeatureCollection of building ways (Polygon; centre Point fallback)."""
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates"}
        q = ('[out:json][timeout:25];\n'
             f'way["building"](around:{int(radius)},{lat},{lon});\n'
             f'out geom {_limit(cap, 500)};')
        j = _overpass(q)
        if "error" in j:
            return {"error": j["error"]}
        features = []
        for el in (j.get("elements") or [])[:int(cap)]:
            tags = el.get("tags") or {}
            geom = el.get("geometry") or []
            props = {"id": el.get("id"), "name": tags.get("name"),
                     "building": tags.get("building"),
                     "building:levels": tags.get("building:levels"),
                     "height": tags.get("height"),
                     "amenity": tags.get("amenity")}
            coords = [(_f(p.get("lon")), _f(p.get("lat"))) for p in geom]
            coords = [(c[0], c[1]) for c in coords if c[0] is not None and c[1] is not None]
            if len(coords) >= 4:
                ring = list(coords)
                if ring[0] != ring[-1]:
                    ring.append(ring[0])
                features.append({"type": "Feature",
                                 "properties": props,
                                 "geometry": {"type": "Polygon",
                                              "coordinates": [ [[c[0], c[1]] for c in ring ]]}})
            else:
                clat, clon = _centre(el)
                if clat is None or clon is None:
                    continue
                features.append({"type": "Feature",
                                 "properties": dict(props, fallback="centre_point"),
                                 "geometry": {"type": "Point",
                                              "coordinates": [clon, clat]}})
        return {"type": "FeatureCollection", "features": features}
    except Exception as e:
        return {"error": str(e)[:150]}


# ---------------------------------------------------------------- imagery
def mapillary_images(lat, lon, radius=200, cap=20):
    """Street-level imagery near a point — only when MAPILLARY_CLIENT_TOKEN set."""
    token = os.environ.get("MAPILLARY_CLIENT_TOKEN") or ""
    if not token:
        return {"skipped": "MAPILLARY_CLIENT_TOKEN not set"}
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates"}
        dlat = float(radius) / 111320.0
        dlon = dlat / max(0.01, math.cos(math.radians(lat)))
        bbox = (f"{lon - dlon:.6f},{lat - dlat:.6f},"
                f"{lon + dlon:.6f},{lat + dlat:.6f}")
        r = _get("https://graph.mapillary.com/images",
                 params={"access_token": token, "bbox": bbox,
                         "fields": "id,geometry,captured_at,thumb_2048_url",
                         "limit": int(cap)})
        if isinstance(r, Exception):
            return {"error": str(r)[:150]}
        if r.status_code >= 400:
            return {"error": f"mapillary HTTP {r.status_code}"}
        j = r.json()
        data = j.get("data") or []
        images = [{"id": x.get("id"), "geometry": x.get("geometry"),
                   "captured_at": x.get("captured_at"),
                   "thumb_2048_url": x.get("thumb_2048_url")} for x in data[:int(cap)]]
        return {"count": len(images), "images": images, "bbox": bbox}
    except Exception as e:
        return {"error": str(e)[:150]}


def openaerial_search(lat, lon, radius):
    """Openly licensed aerial imagery metadata near a point (list on success)."""
    try:
        lat, lon = _f(lat), _f(lon)
        if lat is None or lon is None:
            return {"error": "invalid coordinates"}
        r = _get("https://api.openaerialmap.org/meta",
                 params={"intersects": f"{lon},{lat},{radius}", "limit": 10})
        if isinstance(r, Exception):
            return {"error": str(r)[:150]}
        if r.status_code >= 400:
            return {"error": f"openaerialmap HTTP {r.status_code}"}
        j = r.json()
        feats = (j.get("features") or []) if isinstance(j, dict) else []
        out = []
        for f in feats[:10]:
            p = f.get("properties") or {}
            out.append({"id": p.get("uid") or f.get("id"),
                        "title": p.get("title") or p.get("name"),
                        "url": p.get("tms_url") or p.get("url") or p.get("tile_url"),
                        "acquisition_date": p.get("acquisition_date"),
                        "gsd": p.get("gsd"),
                        "provider": p.get("provider"),
                        "license": p.get("license"),
                        "geometry_type": (f.get("geometry") or {}).get("type")})
        return out
    except Exception as e:
        return {"error": str(e)[:150]}


# ---------------------------------------------------------------- addressing
def zip_lookup(country, postal):
    """Postal code -> {country, place, lat, lon, state}; 404 -> {found: False}."""
    try:
        country = str(country or "").strip().lower()[:10]
        postal = str(postal or "").strip().replace(" ", "%20")[:20]
        if not country or not postal:
            return {"found": False, "error": "country and postal are required"}
        r = _get(f"http://api.zippopotam.us/{country}/{postal}")
        if isinstance(r, Exception):
            return {"found": False, "error": str(r)[:150]}
        if r.status_code == 404:
            return {"found": False, "country": country, "postal": postal}
        if r.status_code >= 400:
            return {"found": False, "error": f"HTTP {r.status_code}"}
        j = r.json()
        places = j.get("places") or []
        if not places:
            return {"found": False, "country": country, "postal": postal}
        p = places[0]
        return {"found": True,
                "country": j.get("country") or country,
                "postal": j.get("post code") or postal,
                "place": p.get("place name"),
                "state": p.get("state") or p.get("state abbreviation"),
                "lat": _f(p.get("latitude")),
                "lon": _f(p.get("longitude")),
                "places_count": len(places)}
    except Exception as e:
        return {"found": False, "error": str(e)[:150]}
