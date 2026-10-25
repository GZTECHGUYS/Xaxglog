"""Xaxglog wireless — Wi-Fi / cell geolocation from public radio maps.

Open sources:
  - mylnikov.org geolocation API (keyless) — BSSID (Wi-Fi MAC) -> lat/lon
    from voluntary crowd-signal databases. Rate-limited, self-throttled.
Optional (env WIGLE_BASIC_AUTH, base64 user:token from free wigle.net
account): WiGLE API — wifi search/nearby by SSID/BSSID/cell, the deepest
public radio-map index available.

Scope: looks up radio coordinates already published in public databases.
Use for locating a device the subject published about, mapping rogue APs
you are authorized to survey, or geolocating historical evidence. Does not
track live devices and cannot defeat rotated MACs.

Lawful-use note: public crowd databases only. Passive lookup.
"""
import os
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
MYLNIKOV = "https://api.mylnikov.org/geolocation/wifi?v=1.1&bssid={bssid}"
WIGLE = "https://api.wigle.net/api/v2/network/search"
_wigle_last = 0.0


def _wigle_headers():
    tok = os.getenv("WIGLE_BASIC_AUTH")
    if not tok:
        return None
    return {"Authorization": "Basic " + tok}


def wifi_lookup(bssid):
    """BSSID -> public geolocation. Keyless core, WiGLE when configured.

    Accepts MAC (aa:bb:cc:dd:ee:ff) or hex-only forms.
    """
    try:
        bssid = (bssid or "").strip().lower().replace("-", ":").replace(".", "")
        if ":" not in bssid:
            bssid = ":".join(bssid[i:i + 2] for i in range(0, 12, 2))
        parts = bssid.split(":")
        if len(parts) != 6 or any(len(p) != 2 for p in parts):
            return {"status": "error", "error": "invalid BSSID"}
        global _wigle_last
        headers = _wigle_headers()
        if headers:
            wait = 1.0 - (time.time() - _wigle_last)
            if wait > 0:
                time.sleep(wait)
            import requests
            r = requests.get(WIGLE, headers={**UA, **headers},
                             params={"netid": bssid}, timeout=T)
            _wigle_last = time.time()
            if r.status_code == 200:
                nets = (r.json().get("results") or [])
                if nets:
                    n = nets[0]
                    return {"status": "ok", "source": "wigle", "bssid": bssid,
                            "lat": n.get("lastLat"), "lon": n.get("lastLON"),
                            "ssid": n.get("ssid"), "type": n.get("type"),
                            "last_seen": n.get("lastSeen"), "range": n.get("range"),
                            "country": n.get("country"),
                            "observations": n.get("wep") is not None}
            # fall through to keyless source on any failure
        import requests
        r = requests.get(MYLNIKOV.format(bssid=bssid.replace(":", "")),
                         headers=UA, timeout=T)
        if r.status_code == 200:
            j = r.json()
            if j.get("result") == 200 and j.get("data"):
                d = j["data"]
                return {"status": "ok", "source": "mylnikov", "bssid": bssid,
                        "lat": d.get("lat"), "lon": d.get("lon"),
                        "range_m": d.get("range"), "seen": d.get("seen")}
        return {"status": "notfound", "source": "mylnikov", "bssid": bssid,
                "note": "no public record for this BSSID"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def ssid_search(ssid, lat=None, lon=None, limit=50):
    """Wi-Fi network search by SSID (WiGLE only — needs free API creds)."""
    try:
        headers = _wigle_headers()
        if not headers:
            return {"status": "unconfigured",
                    "error": "SSID search needs WiGLE creds: set WIGLE_BASIC_AUTH "
                             "(base64 of user:token from wigle.net API settings)"}
        global _wigle_last
        wait = 1.0 - (time.time() - _wigle_last)
        if wait > 0:
            time.sleep(wait)
        import requests
        params = {"ssid": ssid, "resultsPerPage": min(int(limit), 100)}
        if lat is not None and lon is not None:
            params.update({"latrange1": float(lat) - 0.5, "latrange2": float(lat) + 0.5,
                           "longrange1": float(lon) - 0.5, "longrange2": float(lon) + 0.5})
        r = requests.get(WIGLE, headers={**UA, **headers}, params=params, timeout=T)
        _wigle_last = time.time()
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        nets = []
        for n in (r.json().get("results") or []):
            nets.append({"ssid": n.get("ssid"), "netid": n.get("netid"),
                         "lat": n.get("lastLat"), "lon": n.get("lastLON"),
                         "type": n.get("type"), "last_seen": n.get("lastSeen"),
                         "country": n.get("country"), "channel": n.get("channel")})
        db.audit("system", "wireless.ssid_search", ssid, f"n={len(nets)}")
        return {"status": "ok", "source": "wigle", "ssid": ssid,
                "count": len(nets), "networks": nets}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "networks": []}


def cell_lookup(mcc, mnc, lac, ci):
    """Cell tower -> public location (mylnikov keyless)."""
    try:
        params = {"v": "1.2", "mcc": int(mcc), "mnc": int(mnc),
                  "lac": int(lac), "cid": int(ci)}
        import requests
        r = requests.get("https://api.mylnikov.org/geolocation/cell",
                         headers=UA, params=params, timeout=T)
        if r.status_code == 200:
            j = r.json()
            if j.get("result") == 200 and j.get("data"):
                d = j["data"]
                return {"status": "ok", "source": "mylnikov",
                        "lat": d.get("lat"), "lon": d.get("lon"),
                        "range_m": d.get("range")}
        return {"status": "notfound", "source": "mylnikov",
                "note": "no public record for this cell"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
