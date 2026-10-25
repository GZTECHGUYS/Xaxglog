"""Xaxglog property — land/registry ownership pivots (public portals).

Keyless core:
  - UK HM Land Registry Price Paid API (prodapi.landregistry.gov.uk) —
    property transfers by postcode + street, with price, date, type and
    tenant-type. Fully open data, no key.
  - Registry *directory* for 30+ other countries (which portal answers
    "who owns X" per jurisdiction) — reference data + deep links, so the
    analyst knows where the record lives and what it costs.

Output: address -> transaction history; owner names are NOT in UK PPD
(masked for data protection) — the module says so plainly rather than
implying otherwise; jurisdictions where owner names are public are listed
in the directory.

Lawful-use note: public land registries only. Cross-jurisdiction privacy
law applies to owner data — check the jurisdiction card (risk module)
before using owner fields commercially.
"""
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
UK_PPD = "https://prodapi.landregistry.gov.uk/price-paid/offset"

# Public registry directory: jurisdiction -> (portal, note, owner_names_public)
REGISTRY = {
    "GB": {"portal": "https://www.gov.uk/government/collections/price-paid-data",
           "api": UK_PPD, "owner_names_public": False,
           "note": "UK PPD: address+price+date, owner names withheld"},
    "US": {"portal": "https://www.census.gov/programs-surveys/geography/technical-documentation/complete-place-files.html",
           "owner_names_public": "county-dependent",
           "note": "County assessor/recorder portals; owner names typically public "
                   "at county level (fees vary)"},
    "DE": {"portal": "https://www.katasteramt.de", "owner_names_public": False,
           "note": "Grundbuch: access restricted to legitimate interest"},
    "FR": {"portal": "https://www.service-public.fr/particuliers/vosdroits/F34628",
           "owner_names_public": False,
           "note": "Cadastre: transactions via DGFIP; owner names restricted"},
    "NL": {"portal": "https://www.kadaster.nl", "owner_names_public": False,
           "note": "Kadaster: owner data for legitimate interest only"},
    "ES": {"portal": "https://www.sedecatastro.gob.es", "owner_names_public": False,
           "note": "Catastro: ownership restricted; transactions via Colegio Registral"},
    "IT": {"portal": "https://www.agenziaentrate.gov.it/portale/web/english/nse/real-estate",
           "owner_names_public": False,
           "note": "Visura catastale: property data open, owner names restricted"},
    "IE": {"portal": "https://www.propertyregistrationauthority.ie",
           "owner_names_public": True, "note": "Land Registry folio: owner public"},
    "SE": {"portal": "https://www.lantmateriet.se", "owner_names_public": "partly",
           "note": "Fastighetsregistret; person data partially open"},
    "NO": {"portal": "https://www.kartverket.no/en/api/Products-and-services/Register-of-real-estate",
           "owner_names_public": False, "note": "Matrikkelen: restricted"},
    "DK": {"portal": "https://www.ejendomsinfo.dk", "owner_names_public": "partly",
           "note": "BBR/EGR open, ownership via paid services"},
    "FI": {"portal": "https://www.kiintokeskus.fi", "owner_names_public": False,
           "note": "MRR: owner data restricted"},
    "PL": {"portal": "https://ekw.ms.gov.pl", "owner_names_public": False,
           "note": "KW extracts: owner requires interest proof (pay per fetch)"},
    "CH": {"portal": "https://www.zh.ch/de/immobilien-und-bau/grundbuch.html",
           "owner_names_public": False, "note": "Grundbuch restricted"},
    "AT": {"portal": "https://www.bmdw.gv.at/Steuern/Grundbuch/Transparenz.html",
           "owner_names_public": False, "note": "Transparenzregister for companies"},
    "PT": {"portal": "https://justica.gov.pt/Registos/Registo-Predial",
           "owner_names_public": "partly", "note": "Conservatoria: certificates paid"},
    "GR": {"portal": "https://www.geoyst.gr", "owner_names_public": False,
           "note": "Cadastre: ownership restricted"},
    "CA": {"portal": "https://www.landregistry.bc.ca / provincial registries",
           "owner_names_public": "province-dependent",
           "note": "Land titles: owner usually on title (fees)"},
    "AU": {"portal": "https://www.nswlrs.com.au / state land registries",
           "owner_names_public": False,
           "note": "Titles office: owner names not in public searches; sales open"},
    "NZ": {"portal": "https://www.linz.govt.nz/products-services/land-records/land-records-search",
           "owner_names_public": False, "note": "Record of Title: owner redacted online"},
    "IN": {"portal": "https://dilrmp.gov.in / state portals",
           "owner_names_public": "state-dependent",
           "note": "Registry data digitising; fees vary by state"},
    "SG": {"portal": "https://www.sla.gov.sg", "owner_names_public": False,
           "note": "INLIS: ownership restricted to investigators"},
    "AE": {"portal": "https://dubailand.gov.ae / emirate portals",
           "owner_names_public": False, "note": "Title deeds restricted"},
    "ZA": {"portal": "https://www.deeds.gov.za", "owner_names_public": True,
           "note": "Deeds Office: owner names public (republic benefit)"},
    "BR": {"portal": "https://www.gov.br/cnf/pt-br", "owner_names_public": False,
           "note": "Matrícula: owner on official certificate (paid, legit interest)"},
    "MX": {"portal": "https://www.registropublico", "owner_names_public": False,
           "note": "RPP: certificates via notary/office"},
    "JP": {"portal": "https://www.mlit.go.jp", "owner_names_public": False,
           "note": "登記: owner only for legitimate interest"},
    "KR": {"portal": "https://www.iros.go.kr", "owner_names_public": False,
           "note": "Registry: access for interested parties (paid)"},
    "IL": {"portal": "https://gov.il/en/departments/govil-landing-page", "owner_names_public": False,
           "note": "Tabu: access restricted"},
    "UA": {"portal": "https://map.land.gov.ua", "owner_names_public": False,
           "note": "Cadastre: plot data open, ownership restricted"},
}


def uk_transactions(postcode, limit=50):
    """HM Land Registry price-paid transactions for a UK postcode (keyless)."""
    try:
        postcode = (postcode or "").strip().upper()
        if not postcode or " " not in postcode:
            return {"status": "error",
                    "error": "provide full UK postcode (e.g. SW1A 1AA)"}
        import requests
        # offset API: search by postcode, newest first
        url = UK_PPD + "?" + urllib.parse.urlencode(
            {"postcode": postcode, "pageSize": min(int(limit), 1000),
             "sortDirection": "Descending"})
        r = requests.get(url, headers=UA, timeout=T)
        if r.status_code == 404:
            return {"status": "notfound", "postcode": postcode,
                    "note": "no transactions for this postcode"}
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        rows = j.get("data") or j.get("transactions") or []
        tx = []
        for row in rows:
            tx.append({
                "price": row.get("price") or row.get("pricePaid"),
                "date": row.get("transactionDate") or row.get("date"),
                "type": row.get("propertyType") or row.get("type"),
                "new_build": row.get("newBuild"),
                "duration": row.get("duration") or row.get("tenure"),
                "address": row.get("address") or row.get("fullAddress"),
                "ppd_category": row.get("ppdCategoryType"),
            })
        db.audit("system", "property.uk_transactions", postcode, f"n={len(tx)}")
        return {"status": "ok", "jurisdiction": "GB", "postcode": postcode,
                "count": len(tx), "transactions": tx,
                "note": "UK price-paid: owner names are withheld by HM Land Registry"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "transactions": []}


def where(iso2):
    """Which registry answers ownership in this jurisdiction?"""
    iso2 = (iso2 or "").strip().upper()
    entry = REGISTRY.get(iso2)
    if not entry:
        return {"status": "notfound", "iso2": iso2,
                "known": sorted(REGISTRY)}
    return {"status": "ok", "iso2": iso2, **entry}


def directory():
    return {"status": "ok", "count": len(REGISTRY),
            "jurisdictions": {k: v["note"] for k, v in REGISTRY.items()}}
