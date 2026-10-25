"""Xaxglog satellite — satellite imagery scene discovery + tile previews.

Open, keyless sources:
  - Microsoft Planetary Computer STAC (planetarycomputer.microsoft.com) —
    catalog search for Sentinel-2 L2A, Landsat C2 L2 and other public
    collections; returns real scene metadata + item URLs.
  - NASA GIBS (gibs.earthdata.nasa.gov) — WMTS tile service for daily global
    imagery (MODIS/VIIRS/Sentinel-2 layers); builds ready-to-open tile URLs
    for any point + date, keyless.

Workflow: given a point or bbox + date range, find which satellite scenes
cover it (cloud cover, sensor, provider), then get direct preview tiles.
Complements geoext (street-level via Mapillary/OpenAerial) with the orbital
axis — useful for site history, change awareness, access-route mapping.

Lawful-use note: public scientific/archival imagery only. No tasking of
live tasking satellites, no high-resolution intelligence imagery.
"""
import datetime
import math

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
STAC = "https://planetarycomputer.microsoft.com/api/stac/v1/search"
GIBS = ("https://gibs.earthdata.nasa.gov/wmts/epsg3857/best"
        "/{layer}/default/{time}/{tilematrixset}/{z}/{y}/{x}.jpg")

LAYERS = {
    "modis_truecolor": "MODIS_Terra_CorrectedReflectance_TrueColor",
    "viirs_truecolor": "VIIRS_SNPP_CorrectedReflectance_TrueColor",
    "sentinel2_l2a": "Sentinel-2_L2A_Cloudless",
    "landsat_welsh": "Landsat_WELD_CorrectedReflectance_TrueColor_Global_Annual",
}
COLLECTIONS = ["sentinel-2-l2a", "landsat-c2-l2", "modis-terra-l2g"]


def _deg2tile(lat, lon, z):
    """Web-mercator tile x/y for a point at zoom z."""
    n = 2 ** z
    x = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(lat)
    y = int((1.0 - math.asinh(math.tan(lat_r)) / math.pi) / 2.0 * n)
    return max(0, min(n - 1, x)), max(0, min(n - 1, y))


def preview(lat, lon, layer="modis_truecolor", date=None, zoom=9):
    """Build direct GIBS tile URLs for a point (default: latest daily image)."""
    try:
        lat, lon, zoom = float(lat), float(lon), int(zoom)
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return {"status": "error", "error": "coordinate out of range"}
        if layer not in LAYERS:
            return {"status": "error", "error": f"layer must be one of {list(LAYERS)}"}
        date = date or (datetime.date.today() - datetime.timedelta(days=2)).isoformat()
        datetime.date.fromisoformat(date)  # validate
        zoom = max(2, min(zoom, 12))
        x, y = _deg2tile(lat, lon, zoom)
        urls = []
        for dz in (0, 1):
            zz = min(zoom + dz, 12)
            xx, yy = _deg2tile(lat, lon, zz)
            urls.append(GIBS.format(layer=LAYERS[layer], time=date,
                                    tilematrixset="GoogleMapsCompatible_Level8"
                                    if zz <= 8 else "GoogleMapsCompatible_Level9"
                                    if zz <= 9 else "GoogleMapsCompatible_Level12"
                                    if zz <= 12 else "GoogleMapsCompatible_Level8",
                                    z=zz, x=xx, y=yy))
        return {"status": "ok", "source": "nasa_gibs", "layer": layer,
                "date": date, "point": [lat, lon], "zoom": zoom,
                "note": "daily global composites (~250m-1km); for scene-level "
                        "detail use scene_search (Sentinel-2 10m)",
                "tiles": urls}
    except ValueError:
        return {"status": "error", "error": "bad date format (YYYY-MM-DD)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def scene_search(bbox=None, point=None, datetime_range=None,
                 collection="sentinel-2-l2a", max_cloud=20, limit=20):
    """STAC search: which scenes cover this area (keyless Planetary Computer).

    bbox = [west, south, east, north]; point = [lat, lon]; datetime_range
    = "YYYY-MM-DD/YYYY-MM-DD" (default: last 30 days).
    """
    try:
        import requests
        if point and not bbox:
            lat, lon = float(point[0]), float(point[1])
            bbox = [lon - 0.05, lat - 0.05, lon + 0.05, lat + 0.05]
        if not bbox or len(bbox) != 4:
            return {"status": "error", "error": "provide bbox=[w,s,e,n] or point=[lat,lon]"}
        if collection not in COLLECTIONS:
            return {"status": "error", "error": f"collection must be one of {COLLECTIONS}"}
        if not datetime_range:
            end = datetime.date.today()
            datetime_range = f"{end - datetime.timedelta(days=30)}/{end.isoformat()}"
        body = {"collections": [collection], "bbox": [float(v) for v in bbox],
                "datetime": datetime_range, "limit": min(int(limit), 100)}
        r = requests.post(STAC, headers={**UA, "Content-Type": "application/json"},
                          json=body, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"STAC HTTP {r.status_code}"}
        feats = r.json().get("features") or []
        scenes = []
        for f in feats:
            props = f.get("properties") or {}
            clouds = props.get("eo:cloud_cover")
            if clouds is not None and float(clouds) > float(max_cloud):
                continue
            scenes.append({
                "id": f.get("id"),
                "datetime": props.get("datetime"),
                "platform": props.get("platform"),
                "cloud_cover": clouds,
                "mgrs": props.get("mgrs:utm_zone") and props.get("mgrs:grid_square"),
                "item_url": (f.get("assets") or {}).get("preview", {}).get("href")
                             or (f.get("assets") or {}).get("thumbnail", {}).get("href"),
                "catalog_url": f.get("links", [{}])[0].get("href") if f.get("links") else None,
            })
        db.audit("system", "satellite.scene_search",
                 ",".join(str(v) for v in bbox), f"{collection} n={len(scenes)}")
        return {"status": "ok", "source": "planetary_computer",
                "collection": collection, "count": len(scenes), "scenes": scenes,
                "note": "item_url opens the preview asset (public signed URL)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "scenes": []}


def layers():
    return {"status": "ok", "gibs_layers": LAYERS, "stac_collections": COLLECTIONS,
            "sources": ["NASA GIBS (keyless)", "Microsoft Planetary Computer STAC (keyless)"]}
