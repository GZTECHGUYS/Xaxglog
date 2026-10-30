"""Xaxglog extra-module route registration (Parts 1-6).

Keeps app.py stable: instead of ~110 route definitions inside the
monolith, each route group lives here and registers itself onto the
existing Flask app with the same AUTH.require RBAC + lazy-import house
pattern. CAPS flags are flipped per module on successful import so
/api/health and /api/modules reflect reality.
"""
import importlib
import logging

from flask import jsonify

import auth as AUTH

log = logging.getLogger("xaxglog")


def _mod(modpath, cap, CAPS):
    """Import a module file, flipping its CAPS flag. Never raises."""
    try:
        m = importlib.import_module(modpath)
        CAPS[cap] = True
        return m
    except Exception as e:
        CAPS[cap] = False
        log.warning("module %s unavailable: %s", modpath, e)
        return None


def unavailable(name):
    return jsonify({"error": f"{name} module unavailable"}), 503


def register_all(app, CAPS, user_fn):
    from . import p1a, p1b, p1c, p2a, p2b, p3, p4, p5, p6, p7, p8, p9
    ok = 0
    groups = (p1a, p1b, p1c, p2a, p2b, p3, p4, p5, p6, p7, p8, p9)
    for grp in groups:
        try:
            grp.register(app, CAPS, user_fn, AUTH, _mod, unavailable)
            ok += 1
        except Exception as e:
            log.error("route group %s failed: %s", grp.__name__, e)
    log.info("extra module routes: %d/%d groups registered", ok, len(groups))


# descriptions for /api/modules (name -> desc)
EXTRA_META = {
    "certstream": "Certificate-transparency watch: new TLS certs for watched domains -> alerts",
    "hostwatch": "Host exposure drift: Shodan InternetDB ports/CPE fingerprint + diff alerts",
    "wireless": "Wi-Fi/cell geolocation from public radio maps (BSSID/SSID/tower, keyless)",
    "darknet": "Anonymizer exposure: Tor exit/VPN/proxy + threat blocklists, watch + alerts",
    "flight": "Civil aircraft tracking via OpenSky (state by ICAO24, area, airport)",
    "maritime": "Vessel identity: MMSI decode (flag/type) + AIS lookup + maritime news",
    "satellite": "Satellite scene discovery (Planetary Computer STAC) + NASA GIBS previews",
    "exposure": "Public exposure monitoring: breaches, web posture, code leaks -> alerts",
    "imgverify": "Image provenance: perceptual hashes, near-dup detection, reverse-search links",
    "synthetic": "Media authenticity triage: EXIF/software signals + prior-art hash check",
    "brandguard": "Typosquat/lookalike domain generator + DNS/RDAP sweep for a brand",
    "docintel": "Document metadata extraction: PDF/OOXML authorship, timeline, red flags",
    "filings": "SEC EDGAR: company->CIK, filing history, full-text search, Form 4 insider",
    "feedstream": "Streaming threat-feed ingest (URLhaus/OpenPhish/blocklist.de/Feodo/OTX)",
    "browserrender": "Selenium-rendered public pages for anti-bot walls (SSRF-guarded)",
    "identitytimeline": "Handle/profile existence timeline via Wayback CDX first/last seen",
    "kinship": "Family/associate graph via Wikidata relatives + obituary dorks",
    "property": "Land registry pivots: UK price-paid API + 30-country registry directory",
    "donortrail": "Political finance: FEC receipts/flows (key) + regulator directory (keyless)",
    "langintel": "Multilingual pivots: translation, transliteration, confusable folding",
    "malintel": "Malware hash intel: MalwareBazaar/URLhaus/OTX + local hashing + YARA hook",
    "phishkit": "Phishing intel + takedown workflow: OpenPhish/PhishTank/URLhaus + deadlines",
    "supplychain": "Package-registry typosquat watch: PyPI/npm/crates/Go -> alerts",
    "opsecaudit": "Authorized external posture audit (passive, authorization-gated, scored)",
    "adwatch": "Ad transparency: Meta/Google ad-library deep links + GDELT ad news",
    "coordcheck": "Coordinated-behaviour indicators: bursts, near-dup copy, cadence (analysis)",
    "broadcast": "Radio/podcast/stream mention capture: Radio Browser + feed scan + ICY probe",
    "community": "Public community mapping: Discord widget/invites, Matrix rooms, drift watch",
    "onchain": "ENS resolution + ETH account depth + NFT pivots (public RPC)",
    "trade": "International trade flows via World Bank WITS/UN Comtrade + concentration HHI",
    "marketplace": "Counterfeit/diversion listing watch: federated search + listing drift",
    "graphstudio": "Interactive force-directed entity graph layout + standalone viewer page",
    "foia": "Public-records (FOIA/RTI/ATIP) drafting + SLA tracking + overdue alerts",
    "dsar": "Data-subject/takedown workflow (GDPR/CCPA) with statutory deadline alerts",
    "hazards": "Disaster overlay: USGS quakes + GDACS alerts + NWS warnings near a point",
    "pattern": "Social pattern tracker: public interaction ingest, entity links, frequent-contact ranking, active-hours/timezone, URL/IP ledgers, email thread graph",
    "broker": "Public data-broker exposure sweep: people-search catalog checks with honest hit/blocked/no-signal statuses and exposure score",
    "procurement": "Public procurement intelligence: USAspending federal awards + EU TED notices with normalized buyer/awardee/amount/date",
    "lobbying": "US Senate LDA lobbying disclosures: client/registrant search, lobbyists, issues, income/expenses",
    "nonprofit": "ProPublica Nonprofit Explorer: IRS-registered nonprofits, EIN lookup, Form 990 financial summaries",
    "countryscope": "Country-scoped search: selected-country registry/procurement/court/charity links plus GLEIF, USAspending/TED, nonprofit/lobbying and domain/IP country checks",
    "socialscrape": "Broad international public social-media search/scrape: 187-platform catalog, federated/regional engines, public-page metadata, media URLs and case evidence",
    "imgreverse": "Public reverse-image lookup: 14 public engines (11 link-out) plus keyless Trace.moe and optional-key APIs; face-search engines excluded",
    "identity": "Identity intelligence: comma/suffix normalization, always-on variants, extra keyless people/academic/archive/code indexes, public-record pass, dedupe, confidence and per-source coverage",
    "source_registry": "Unified 402-source public registry with access mode, adapter, key requirement, verified/adapter/optional-key/link-out/blocked/error status and public link-out builder",
    "module_registry": "Declarative module registry: generic JSON/profile/search/oEmbed/adapter/link-out probes, live verification overlay, dedupe/ranking and honest coverage",
    "operator_compat": "Legacy dashboard compatibility: operator key store, /api/lookup deep-search view, breach lookup, deterministic briefing and Snort/YARA rule helpers",
    "platform_ops": "Phase 1-12 platform services: evidence graph/timeline/provenance, social coverage, source health, runtime/self-test, signed module packs, offline cache, security posture, team workspaces, performance, plugin SDK, compliance and observability",
}
