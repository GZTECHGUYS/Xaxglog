"""Xaxglog trade — international trade flows (UN Comtrade, keyless).

Open, keyless sources:
  - UN Comtrade public preview (comtradeapi.un.org, keyless preview quota)
    — merchandise trade by partner/product for a reporter country; the
    preview tier needs no registration and self-throttles (429 -> retry
    note). No key, polite pacing.
  - World Bank WITS' open endpoints now redirect/403 without a registered
    token, so flows come from Comtrade's keyless preview.

Use: given two countries (or one), pull who trades with whom, top products,
and concentration — the economic-interdependence axis for sanctions
impact, supply-chain risk, and influence-mapping (who profits from the
relationship).

Lawful-use note: official statistics published by UN/World Bank. Attribution
of source expected in reports.
"""
import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
COMTRADE = ("https://comtradeapi.un.org/public/v1/preview/C/A/HS"
            "?reporterCode={r}&period={y}&cmdCode={c}&flowCode={f}"
            "{partner}&maxRecords=500")

# ISO2 -> UN M49 numeric code. Comtrade's preview tier requires numeric
# codes (alpha codes are rejected), so the common economies are mapped
# here; anything else gets a clear "unsupported" error instead of a 400.
ISO2_M49 = {
    "DE": "276", "US": "842", "CN": "156", "JP": "392", "GB": "826",
    # note: Comtrade uses UN M49, where France is 251 (not ISO-numeric 250)
    "FR": "251", "IT": "380", "IN": "356", "CA": "124", "BR": "76",
    "RU": "643", "KR": "410", "MX": "484", "AU": "036", "ES": "724",
    "NL": "528", "CH": "756", "PL": "616", "SE": "752", "BE": "056",
    "AT": "040", "IE": "372", "DK": "208", "NO": "578", "FI": "246",
    "PT": "620", "GR": "300", "CZ": "203", "RO": "642", "HU": "348",
    "TR": "792", "SA": "682", "AE": "784", "ZA": "710", "AR": "032",
    "CL": "152", "CO": "170", "PE": "604", "EG": "818", "NG": "566",
    "KE": "404", "MA": "504", "TH": "764", "VN": "704", "ID": "360",
    "MY": "458", "PH": "608", "SG": "702", "NZ": "554", "PK": "586",
    "BD": "050", "LK": "144", "IR": "364", "IL": "376", "UA": "804",
    "KZ": "398", "RS": "688", "SK": "703", "BG": "100", "HR": "191",
    "LT": "440", "SI": "705", "LV": "428", "EE": "233", "LU": "442",
    "IS": "352", "CY": "196", "MT": "470",
}
M49_ISO2 = {v: k for k, v in ISO2_M49.items()}
# display names for the most common partner codes (preview rows carry
# numeric codes only — partnerISO is null on the keyless tier)
M49_NAME = {
    "0": "WORLD", "842": "United States", "156": "China", "276": "Germany",
    "392": "Japan", "826": "United Kingdom", "251": "France", "380": "Italy",
    "356": "India", "643": "Russia", "410": "Korea, Rep.", "724": "Spain",
    "528": "Netherlands", "124": "Canada", "76": "Brazil", "484": "Mexico",
    "036": "Australia", "756": "Switzerland", "616": "Poland", "752": "Sweden",
    "056": "Belgium", "792": "Turkey", "682": "Saudi Arabia", "784": "UAE",
    "710": "South Africa", "360": "Indonesia", "704": "Viet Nam",
    "348": "Hungary", "203": "Czechia", "642": "Romania", "578": "Norway",
    "208": "Denmark", "372": "Ireland", "705": "Slovenia", "703": "Slovakia",
    "050": "Bangladesh", "586": "Pakistan", "364": "Iran", "376": "Israel",
    "804": "Ukraine", "246": "Finland",
}


def _comtrade_flows(iso2, mode, year, limit):
    """All-partner merchandise flows for a reporter (keyless preview)."""
    import datetime
    import requests
    m49 = ISO2_M49.get(iso2)
    if not m49:
        raise RuntimeError(f"no M49 code mapped for {iso2} "
                           f"({len(ISO2_M49)} common economies supported)")
    flow = "X" if mode == "export" else "M"
    # omitting partnerCode returns every partner (incl. world aggregate)
    url = COMTRADE.format(r=m49, y=int(year), c="TOTAL", f=flow, partner="")
    r = requests.get(url, headers=UA, timeout=T)
    if r.status_code == 429:
        raise RuntimeError("Comtrade preview rate limit — retry in a few seconds")
    if r.status_code != 200:
        raise RuntimeError(f"Comtrade HTTP {r.status_code}")
    try:
        rows = r.json().get("data") or []
    except ValueError:
        raise RuntimeError("Comtrade non-JSON")
    out = []
    for row in rows:
        pc = str(row.get("partnerCode"))
        if pc == "0":  # "world" aggregate row — we want individual partners
            continue
        out.append({
            "partner": M49_NAME.get(pc) or M49_ISO2.get(pc, f"M49:{pc}"),
            "partner_code": pc,
            "year": row.get("refYear"),
            "value_usd": row.get("primaryValue"),
            "product": "TOTAL (all goods)",
        })
    out.sort(key=lambda x: (x["value_usd"] or 0), reverse=True)
    return out[:limit]


def flows(country_iso2, mode="export", year=None, limit=25):
    """Top trading partners for a country (UN Comtrade, keyless preview).

    mode: "export" (who do they sell to) or "import" (who do they buy from).
    """
    try:
        iso2 = (country_iso2 or "").strip().upper()
        if len(iso2) != 2:
            return {"status": "error", "error": "provide ISO2 country code"}
        if mode not in ("export", "import"):
            return {"status": "error", "error": "mode must be export|import"}
        import datetime
        year = int(year) if year else datetime.date.today().year - 1
        out = _comtrade_flows(iso2, mode, year, int(limit))
        db.audit("system", "trade.flows", f"{iso2}:{mode}:{year}", f"n={len(out)}")
        return {"status": "ok", "country": iso2, "mode": mode,
                "year": year, "count": len(out), "flows": out,
                "source": "UN Comtrade public preview"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "flows": []}


def comtrade(reporter, partner, year=None, cmd="TOTAL"):
    """UN Comtrade preview: bilateral trade (keyless preview quota)."""
    try:
        r_iso = (reporter or "").strip().upper()
        p_iso = (partner or "").strip().upper()
        r_m49 = ISO2_M49.get(r_iso)
        p_m49 = ISO2_M49.get(p_iso)
        if not r_m49 or not p_m49:
            return {"status": "error",
                    "error": "ISO2 codes required (supported: "
                             f"{len(ISO2_M49)} common economies)"}
        import datetime
        import requests
        year = int(year) if year else datetime.date.today().year - 1
        url = COMTRADE.format(r=r_m49, y=year, c=cmd, f="X",
                              partner=f"&partnerCode={p_m49}")
        resp = requests.get(url, headers=UA, timeout=T)
        if resp.status_code == 429:
            return {"status": "throttled",
                    "error": "Comtrade preview quota exceeded — retry later"}
        if resp.status_code != 200:
            return {"status": "error", "error": f"Comtrade HTTP {resp.status_code}"}
        rows = resp.json().get("data") or []
        out = [{
            "period": r.get("period"), "value": r.get("primaryValue"),
            "qty": r.get("qty"), "netweight": r.get("netWgt"),
            "commodity": r.get("cmdDesc") or r.get("cmdCode"),
            "flow": r.get("flowCode"),
        } for r in rows[:40]]
        return {"status": "ok", "reporter": r_iso, "partner": p_iso,
                "year": year, "count": len(out), "records": out,
                "source": "UN Comtrade public preview"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "records": []}


def concentration(country_iso2, year=None):
    """How dependent is this country on its top partners? (HHI-style)."""
    out = flows(country_iso2, mode="export", year=year, limit=15)
    if out.get("status") != "ok":
        return out
    vals = [f.get("value_usd") for f in out["flows"] if f.get("value_usd")]
    try:
        vals = [float(v) for v in vals]
    except (TypeError, ValueError):
        return {"status": "error", "error": "WITS values unavailable for math",
                "flows": out["flows"]}
    total = sum(vals)
    if not total:
        return {"status": "ok", "country": country_iso2,
                "note": "no value data returned", "flows": out["flows"]}
    shares = [v / total for v in vals]
    hhi = round(sum(s * s for s in shares) * 10000, 1)
    top3 = sorted(shares, reverse=True)[:3]
    return {"status": "ok", "country": (country_iso2 or "").upper(),
            "partners_measured": len(shares),
            "hhi": hhi,
            "top3_share": round(sum(top3) * 100, 1),
            "interpretation": ("highly concentrated" if hhi >= 2500 else
                               "moderately concentrated" if hhi >= 1500 else
                               "diversified"),
            "source": "derived from World Bank WITS"}
