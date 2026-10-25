"""Xaxglog maritime — vessel identity + public AIS pivots.

Keyless core:
  - MMSI structure decode (ITU-R M.1371): MID country code -> flag state,
    ship/ocean-group bit, ship type class ranges. Pure local computation.
  - GDELT news search restricted to maritime terms (port incidents, seizures)
    via the same throttled public endpoint the risk module uses.

Optional (env MARINETRAFFIC_API_KEY): MarineTraffic public AIS API — vessel
search by MMSI/IMO/name, last-position, port calls.

MMSI: 9 digits — 3-digit Maritime Identification Digits (MID) identify the
flag administration; digit 1 (bit 1 of first digit) separates ship from
coastal/group stations; the remaining digits classify vessel type.

Lawful-use note: public identity decode + published AIS/news only. No AIS
spoofing, no signal interception.
"""
import os
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
MT = "https://www.marinetraffic.com/api/v2/positions"
GDELT = "https://api.gdeltproject.org/api/v2/doc/doc"
_gdelt_last = 0.0

# Maritime Identification Digits -> flag administration (common set, keyless)
MID = {
    "201": "Albania", "211": "Germany", "215": "Malta", "218": "Germany",
    "219": "Denmark", "220": "Denmark", "224": "Spain", "225": "Spain",
    "226": "Spain", "227": "Spain", "228": "Spain", "229": "France",
    "230": "Czechia", "231": "Moldova", "232": "Austria", "233": "Hungary",
    "235": "United Kingdom", "236": "Gibraltar", "237": "Greece",
    "238": "Croatia", "239": "Greece", "240": "Greece", "241": "Greece",
    "242": "Greece", "243": "Greece", "244": "Netherlands", "245": "Netherlands",
    "246": "Netherlands", "247": "Netherlands", "248": "Malta", "249": "Malta",
    "250": "Ireland", "251": "Ireland", "252": "Luxembourg", "253": "Luxembourg",
    "254": "Monaco", "255": "Portugal", "256": "Portugal", "257": "Portugal",
    "258": "Portugal", "259": "Norway", "261": "Poland", "262": "Montenegro",
    "263": "Portugal", "264": "Germany", "265": "Sweden", "266": "Sweden",
    "268": "Lithuania", "269": "Germany", "271": "Turkey", "273": "Russia",
    "274": "North Macedonia", "275": "Ukraine", "277": "Ukraine",
    "278": "Ukraine", "279": "Russia", "301": "United States",
    "303": "United States", "304": "Antigua and Barbuda", "305": "Antigua and Barbuda",
    "306": "Netherlands", "307": "Aruba", "308": "Bahamas", "309": "Bahamas",
    "310": "Bermuda", "312": "Belize", "314": "Barbados", "316": "Canada",
    "319": "Cayman Islands", "321": "Costa Rica", "323": "Cuba",
    "325": "Dominica", "327": "Dominican Republic", "329": "Guadeloupe",
    "330": "Grenada", "331": "Guadeloupe", "338": "United States",
    "339": "Jamaica", "341": "Saint Kitts and Nevis", "343": "Saint Lucia",
    "344": "United States", "345": "Mexico", "348": "United States",
    "349": "Montserrat", "350": "Nicaragua", "352": "Panama", "353": "Panama",
    "354": "Panama", "355": "Panama", "356": "Panama", "357": "Panama",
    "359": "United States", "361": "Saint Vincent and the Grenadines",
    "364": "United States", "366": "United States", "367": "United States",
    "368": "United States", "369": "United States", "370": "Panama",
    "371": "Panama", "372": "Panama", "373": "Panama", "375": "Venezuela",
    "376": "Venezuela", "377": "Anguilla", "378": "Virgin Islands (UK)",
    "379": "Virgin Islands (US)", "401": "Afghanistan", "403": "Saudi Arabia",
    "405": "Bangladesh", "408": "Bahrain", "410": "Bhutan", "412": "China",
    "413": "China", "414": "China", "416": "Taiwan", "417": "Sri Lanka",
    "419": "India", "421": "India", "422": "Iran", "423": "Azerbaijan",
    "425": "Israel", "427": "Japan", "428": "Jordan", "429": "Kuwait",
    "431": "Japan", "432": "Japan", "434": "Kazakhstan", "435": "Lebanon",
    "436": "Uzbekistan", "437": "Uzbekistan", "438": "Jordan", "440": "Korea",
    "441": "Korea", "443": "Palestine", "445": "Kuwait", "447": "Macau",
    "450": "Maldives", "451": "Maldives", "452": "Mongolia", "453": "Nepal",
    "454": "Oman", "455": "Pakistan", "456": "Qatar", "457": "Syria",
    "458": "Singapore", "459": "Singapore", "461": "Philippines",
    "463": "Singapore", "466": "Taiwan", "469": "Thailand", "470": "Thailand",
    "472": "Tajikistan", "473": "Turkmenistan", "475": "Yemen",
    "477": "Hong Kong", "478": "Bosnia and Herzegovina", "481": "Belarus",
    "482": "Ukraine", "483": "Georgia", "484": "Moldova", "485": "Russia",
    "487": "Russia", "488": "Russia", "501": "France", "503": "Australia",
    "506": "Belgium", "507": "Cambodia", "508": "Brunei", "510": "Indonesia",
    "511": "Indonesia", "512": "New Zealand", "514": "Cambodia",
    "515": "Cambodia", "518": "New Zealand", "520": "Thailand",
    "521": "Bangladesh", "523": "Australia", "525": "Singapore",
    "529": "Kiribati", "531": "Malaysia", "532": "Malaysia", "533": "Malaysia",
    "536": "Northern Mariana Islands", "538": "Indonesia", "540": "France",
    "542": "New Zealand", "544": "Tuvalu", "546": "France", "547": "France",
    "548": "Philippines", "553": "Papua New Guinea", "555": "France",
    "557": "Solomon Islands", "559": "Vanuatu", "561": "France",
    "563": "Singapore", "564": "Singapore", "565": "Singapore",
    "566": "Singapore", "570": "Samoa", "572": "Tonga", "574": "Vietnam",
    "576": "Vietnam", "577": "Vietnam", "578": "France", "601": "Argentina",
    "603": "Brazil", "605": "Brazil", "607": "Brazil", "608": "Brazil",
    "609": "Brazil", "611": "Brazil", "612": "Brazil", "613": "Brazil",
    "615": "Congo", "616": "Djibouti", "617": "Benin", "618": "France",
    "619": "Cameroon", "620": "Cape Verde", "621": "Congo", "622": "Egypt",
    "624": "Libya", "625": "Morocco", "626": "Gabon", "627": "Ghana",
    "631": "Guinea-Bissau", "633": "Burkina Faso", "634": "Kenya",
    "635": "Mauritius", "636": "Nigeria", "637": "Uganda", "642": "Senegal",
    "644": "Seychelles", "645": "Mauritius", "647": "Mauritius",
    "649": "Namibia", "650": "Cape Verde", "654": "Madagascar",
    "656": "Nigeria", "657": "Togo", "659": "Sao Tome and Principe",
    "660": "South Africa", "661": "South Africa", "662": "South Africa",
    "663": "South Africa", "664": "Democratic Republic of the Congo",
    "666": "Somalia", "667": "Tanzania", "668": "Sudan", "669": "Zambia",
    "670": "Angola", "701": "Argentina", "710": "Colombia", "720": "Ecuador",
    "725": "Chile", "730": "Chile", "735": "Chile", "740": "Colombia",
    "745": "Colombia", "747": "Colombia", "750": "Cuba", "755": "Brazil",
    "756": "Brazil", "759": "Venezuela", "760": "Peru", "762": "Uruguay",
    "764": "Venezuela", "767": "Bolivia", "768": "Panama", "770": "Ecuador",
    "773": "Uruguay", "775": "Ecuador", "776": "Mexico", "777": "Mexico",
}

SHIP_TYPES = {
    (30, 39): "Cargo", (40, 49): "Cargo (hazardous)", (50, 59): "Special craft",
    (60, 69): "Passenger", (70, 79): "Cargo + tanker", (80, 89): "Tanker",
}


def decode_mmsi(mmsi):
    """Decode a 9-digit MMSI: flag state, station class, vessel-type class."""
    try:
        mmsi = (mmsi or "").strip()
        if not mmsi.isdigit() or len(mmsi) != 9:
            return {"status": "error", "error": "MMSI must be 9 digits"}
        mid = mmsi[:3]
        first_digit = int(mmsi[0])
        flag = MID.get(mid, "unknown")
        if first_digit == 0:
            kind = "coastal station / group of ships (not a vessel MMSI)"
        elif first_digit == 8:
            kind = "aircraft (AIS search and rescue aircraft MMSI)"
        else:
            t = int(mmsi[3:5]) if mmsi[3:5].isdigit() else -1
            vtype = next((v for (lo, hi), v in SHIP_TYPES.items() if lo <= t <= hi),
                         "Not in use / other")
            kind = f"ship — class: {vtype}"
        return {"status": "ok", "mmsi": mmsi, "mid": mid, "flag": flag,
                "station": kind, "dcs": "AIS" if first_digit != 8 else "AIS (aircraft)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def vessel_search(q):
    """Search vessels via MarineTraffic (needs free API key)."""
    key = os.getenv("MARINETRAFFIC_API_KEY")
    if not key:
        return {"status": "unconfigured",
                "error": "AIS search needs MARINETRAFFIC_API_KEY (free tier at "
                         "marinetraffic.com api) — MMSI decode is keyless",
                "hint": "keyless alternative: decode_mmsi + GDELT news search"}
    try:
        import requests
        r = requests.get(MT, headers=UA,
                         params={"APIKEY": key, "MMSI": q if q.isdigit() else "",
                                 "NAME": "" if q.isdigit() else q},
                         timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        data = r.json().get("data") or []
        vessels = [{
            "mmsi": v.get("MMSI"), "imo": v.get("IMO"), "name": v.get("SHIPNAME"),
            "lat": v.get("LAT"), "lon": v.get("LON"),
            "speed": v.get("SPEED"), "course": v.get("COG"),
            "destination": v.get("DESTINATION"), "eta": v.get("ETA"),
            "last_seen": v.get("LASTPOS"), "ship_type": v.get("SHIPTYPE"),
        } for v in data[:50]]
        db.audit("system", "maritime.vessel_search", q, f"n={len(vessels)}")
        return {"status": "ok", "query": q, "count": len(vessels), "vessels": vessels}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "vessels": []}


def maritime_news(query, timespan="3month", maxrecords=25):
    """GDELT news search for vessel/port/incident terms (keyless, throttled)."""
    try:
        query = (query or "").strip()
        if not query:
            return {"status": "error", "error": "empty query", "articles": []}
        global _gdelt_last
        import urllib.parse
        import requests
        wait = 5.0 - (time.time() - _gdelt_last)
        if wait > 0:
            time.sleep(wait)
        params = {"query": query, "mode": "artlist",
                  "maxrecords": str(min(int(maxrecords), 250)),
                  "timespan": timespan, "format": "json"}
        r = requests.get(GDELT + "?" + urllib.parse.urlencode(params),
                         headers=UA, timeout=T)
        _gdelt_last = time.time()
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}", "articles": []}
        try:
            j = r.json()
        except ValueError:
            return {"status": "error", "error": "non-JSON", "articles": []}
        arts = [{"title": a.get("title"), "url": a.get("url"),
                 "domain": a.get("domain"), "country": a.get("sourcecountry"),
                 "seendate": a.get("seendate")}
                for a in (j.get("articles") or [])]
        return {"status": "ok", "query": query, "count": len(arts), "articles": arts}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "articles": []}
