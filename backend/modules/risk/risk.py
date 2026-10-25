"""Xaxglog risk intelligence — GDELT news/timeline, country risk profiles,
jurisdiction legal-orientation cards and sanctions overlay for travel plans.

Open, keyless sources:
  - GDELT DOC 2.0 API (api.gdeltproject.org) for global news articles and
    volume timelines (rate-limited: ~1 req/5s — the module self-throttles
    and retries once on 429).
  - World Bank API (api.worldbank.org) for GDP per-capita, internet
    penetration and (where still served) political-stability estimates.
    PV.EST is archived in the WDI Database Archives and returns null with a
    note when the API no longer serves it.

The static risk snapshot (CPI / press-freedom / rule-of-law scores, data-
protection regimes, scraping posture, PI licensing, data-localisation) and
the jurisdiction cards are embedded reference data, clearly labelled as an
approximate snapshot — verify against the primary source before relying on
it.

Lawful-use note: uses only free public APIs and published indexes for
orientation and risk-awareness. Nothing here is legal advice; jurisdiction
cards are general orientation for lawful research planning.
"""
import time
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
GDELT = "https://api.gdeltproject.org/api/v2/doc/doc"
WB = "https://api.worldbank.org/v2/country/{cc}/indicator/{ind}?format=json&mrnev=1"
_gdelt_last = 0.0  # self-throttle: >=5s between calls (GDELT public policy)


# ------------------------------------------------------------------ GDELT

def _gdelt_get(params):
    """One GDELT DOC call with self-throttle + single 429 backoff."""
    import requests
    global _gdelt_last
    try:
        wait = 5.0 - (time.time() - _gdelt_last)
        if wait > 0:
            time.sleep(wait)
        url = GDELT + "?" + urllib.parse.urlencode(params)
        r = requests.get(url, headers=UA, timeout=T)
        _gdelt_last = time.time()
        if r.status_code == 429:
            time.sleep(15)
            r = requests.get(url, headers=UA, timeout=T)
            _gdelt_last = time.time()
        return r
    except Exception as e:
        return e


def gdelt_news(query, timespan="3month", maxrecords=30):
    """Global news articles from GDELT DOC 2.0 (artlist mode, keyless)."""
    try:
        query = (query or "").strip()
        if not query:
            return {"error": "empty query", "articles": []}
        params = {"query": query, "mode": "artlist",
                  "maxrecords": str(min(int(maxrecords), 250)),
                  "timespan": timespan, "format": "json"}
        r = _gdelt_get(params)
        if isinstance(r, Exception):
            return {"status": "error", "error": str(r)[:150], "articles": []}
        if r.status_code == 429:
            return {"status": "blocked", "error": "GDELT rate limit (429) persists — retry later",
                    "articles": []}
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}", "articles": []}
        try:
            j = r.json()
        except Exception:
            return {"status": "error", "error": "non-JSON response (captcha/HTML?)",
                    "articles": []}
        arts = []
        for a in (j.get("articles") or []):
            arts.append({
                "title": (a.get("title") or "").strip(),
                "url": a.get("url"),
                "sourcecountry": a.get("sourcecountry"),
                "domain": a.get("domain"),
                "language": a.get("language"),
                "seendate": a.get("seendate"),
                "socialimage": a.get("socialimage"),
            })
        db.audit("system", "risk.gdelt_news", query[:80],
                 f"timespan={timespan} n={len(arts)}")
        return {"status": "ok", "query": query, "timespan": timespan,
                "count": len(arts), "articles": arts}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "articles": []}


def gdelt_timeline(query, timespan="3month"):
    """GDELT coverage-volume timeline (timelinevol mode)."""
    try:
        query = (query or "").strip()
        if not query:
            return {"error": "empty query", "timeline": []}
        params = {"query": query, "mode": "timelinevol",
                  "timespan": timespan, "format": "json"}
        r = _gdelt_get(params)
        if isinstance(r, Exception):
            return {"status": "error", "error": str(r)[:150], "timeline": []}
        if r.status_code == 429:
            return {"status": "blocked", "error": "GDELT rate limit (429) persists", "timeline": []}
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}", "timeline": []}
        try:
            j = r.json()
        except Exception:
            return {"status": "error", "error": "non-JSON response", "timeline": []}
        tl = [{"date": t.get("date"), "value": t.get("value")}
              for t in (j.get("timeline") or [])]
        return {"status": "ok", "query": query, "timespan": timespan,
                "count": len(tl), "timeline": tl}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "timeline": []}


# ------------------------------------------------------------- World Bank

def _wb(iso2, indicator):
    import requests
    try:
        r = requests.get(WB.format(cc=iso2, ind=indicator), headers=UA, timeout=T)
        if r.status_code != 200:
            return {"value": None, "note": f"HTTP {r.status_code}"}
        j = r.json()
        if not isinstance(j, list) or len(j) < 2 or not j[1]:
            msg = ""
            if isinstance(j, list) and j and isinstance(j[0], dict) and j[0].get("message"):
                msg = j[0]["message"][0].get("value", "")
            return {"value": None, "note": msg or "no data"}
        row = j[1][0]
        return {"value": row.get("value"), "year": row.get("date")}
    except Exception as e:
        return {"value": None, "note": str(e)[:100]}


# --------------------------------------------------- static risk snapshot
# Approximate, embedded snapshot — verify against Transparency International
# (CPI), RSF (press freedom), WJP (rule of law) and local counsel.

def _snap(cpi, rsf, wjp, dp, scrape, pi, loc):
    return {"corruption_index_cpi": cpi, "press_freedom_rank": rsf,
            "rule_of_law_wjp": wjp, "data_protection_regime": dp,
            "scraping_note": scrape, "pi_license_note": pi,
            "data_localization_note": loc}


RISK_SNAPSHOT = {
    "US": _snap(65, 57, 0.72, "Sectoral: no federal privacy law; CCPA/CPRA (CA), VCDPA (VA) etc.; FTC Act unfairness",
                "Generally tolerated for public data; CFAA/hiQ line limits access-control circumvention; honour robots.txt",
                "PI licensing varies by state (e.g. NY PI license); corporate investigators mostly registration-free",
                "Sectoral (HIPAA/GLBA); no general localisation"),
    "GB": _snap(71, 23, 0.77, "UK GDPR + Data Protection Act 2018 + PECR",
                "Public-data scraping tolerated subject to UK GDPR/PECR; ToS breaches actionable",
                "No general PI licensing; SIA licences for investigator businesses",
                "No general localisation; UK-IDTA for transfers"),
    "DE": _snap(75, 29, 0.81, "EU GDPR + Bundesdatenschutzgesetz (BDSG); state DPAs + BfDI",
                "Strict: GDPR applies to scraping personal data; legitimate-interest test required",
                "No PI license; detective agencies (Detekteien) need trade permits",
                "No localisation; strict EU-transfer rules (Schrems II)"),
    "FR": _snap(67, 78, 0.72, "EU GDPR enforced by CNIL",
                "CNIL guidance requires legal basis + minimisation for mass collection",
                "Enquêteurs judiciaires licensed (autorisation CNAPS)",
                "No localisation; GDPR transfer regime"),
    "NL": _snap(78, 5, 0.83, "EU GDPR + UAVG (Autoriteit Persoonsgegevens)",
                "AP active enforcement; purpose-limitation applies to scraped personal data",
                "Bureau detective activity requires permit (Bibob screening)",
                "No localisation"),
    "IE": _snap(77, 6, 0.77, "EU GDPR + DPA 2018 (DPC — lead regulator for many tech firms)",
                "DPC enforces against large platforms; same GDPR basis required",
                "Garda-authorised private investigator licensing proposed/limited",
                "No localisation"),
    "ES": _snap(56, 36, 0.67, "EU GDPR + LOPDGDD (AEPD)",
                "AEPD fines for unlicensed collection of personal data",
                "Actividad de investigación privada requires Ministry of Interior licence",
                "No localisation"),
    "IT": _snap(54, 47, 0.65, "EU GDPR + Codice Privacy (Garante)",
                "Garante active on web scraping / AI training datasets",
                "Investigazioni private need licence (Ministero dell'Interno)",
                "No localisation"),
    "PL": _snap(53, 62, 0.60, "EU GDPR + UODO",
                "GDPR basis required; Polish DPA moderate enforcement",
                "Licences for legal-detection activity (MSWiA)",
                "No localisation"),
    "NO": _snap(81, 2, 0.89, "GDPR/EEA + Personal Data Act (Datatilsynet)",
                "EEA rules apply; research exemptions narrow",
                "Generally free; security-sector rules apply",
                "No localisation"),
    "CH": _snap(81, 12, 0.86, "revised Federal Act on Data Protection (revFADP, 2023)",
                "FADP + ToS/competition law; Swiss adequacy recognised by EU",
                "Private security/personal-information activity licensed by cantons",
                "No localisation"),
    "UA": _snap(35, 61, 0.49, "Law on Personal Data Protection (reform to align with GDPR pending)",
                "Wartime martial-law restrictions on data flows; enforcement weak",
                "Licensing for detective activity (Ministry of Interior)",
                "Localisation of state-data; wartime data-transfer rules"),
    "RU": _snap(22, 171, 0.28, "Federal Law 152-FZ (personal data); Roskomnadzor",
                "Localisation law (data of Russians on RU servers); blocking powers; high legal risk for foreign OSINT",
                "Licensed detective activity; FSB authorisation for security work",
                "Mandatory localisation of personal-data databases"),
    "TR": _snap(34, 158, 0.37, "KVKK Law 6689 (Data Protection Authority)",
                "KVKK consent/basis required; frequent website blocks (ICTA)",
                "Private detective licences abolished/unlicensed sector",
                "Localisation demands via ICTA for strategic data"),
    "AE": _snap(68, 160, 0.55, "Federal Decree-Law 45/2021 (UAE Data Office)",
                "Defamation/cybercrime laws (Law 34/2021) constrain aggressive collection",
                "Security/investigation services licensed (Ministry of Interior)",
                "Some health-data localisation; DIFC/ADGM free zones have own regimes"),
    "SA": _snap(59, 166, 0.50, "Personal Data Protection Law (SDAIA, 2023+)",
                "Cybercrime law restricts unauthorized collection/publication",
                "PI/security services licensed by MOI",
                "Cloud/data transfer rules (CST); health data localisation"),
    "IL": _snap(64, 112, 0.73, "Protection of Privacy Law 1981 (+ Privacy Protection Authority)",
                "Basic Law 7761 protects privacy; tort of invasion of privacy",
                "Inquiry and security services licensed (registered with Ministry of Justice?) — registry regime",
                "No general localisation"),
    "IN": _snap(38, 151, 0.50, "Digital Personal Data Protection Act 2023 (Data Protection Board)",
                "DPDP + IT Act 2000 s.43A; intermediary/robots enforcement actions",
                "No general PI licensing; police/state detective licensing states",
                "Government powers to localise/notified data; cross-border carve-outs"),
    "CN": _snap(43, 172, 0.45, "PIPL + Cybersecurity Law + DSL (CAC enforcement)",
                "Very restrictive: PIPL consent; great-law restrictions on foreign data collection",
                "Investigation services restricted; state-approved only",
                "Broad localisation (CIIO data, important data); security assessment for transfers"),
    "JP": _snap(71, 68, 0.79, "APPI (Personal Information Protection Commission)",
                "APPI amended for scraping/matching of personal information",
                "No general PI licensing; 偵探業 (tenpai-gyo) registration in some prefectures",
                "No general localisation"),
    "KR": _snap(64, 42, 0.74, "PIPA (Personal Information Protection Commission)",
                "Strict: even public-data aggregation can be 'personal information'",
                "Private detectives (cyber) restricted; licensed security firms",
                "No general localisation"),
    "SG": _snap(84, 129, 0.83, "PDPA 2012 (PDPC)",
                "Do-Not-Call + PDPA; legitimate-reason exceptions for publicly available data",
                "Compliance & surveillance industry licensed (Police licensing)",
                "Reasonable-care rules for overseas transfer"),
    "HK": _snap(76, 140, 0.79, "Personal Data (Privacy) Ordinance (PCPD)",
                "PDPO s.65 restricts use of personal data for new purpose; doxing amended",
                "Security/insurance investigator licensing (Security and Insurance Ordinance)",
                "No localisation"),
    "AU": _snap(77, 8, 0.81, "Privacy Act 1988 + Australian Privacy Principles (OAIC)",
                "Fair-information principles apply; ACCC v Google-style actions",
                "Commercial agents/investigators licensed by state agencies",
                "No general localisation"),
    "NZ": _snap(83, 19, 0.84, "Privacy Act 2020 (Privacy Commissioner)",
                "Information privacy principles apply to collection",
                "Private security/personal interest licensing under PSPLA",
                "No localisation"),
    "BR": _snap(34, 82, 0.49, "LGPD (ANPD)",
                "LGPD legal basis required; public-data scraping still 'personal data'",
                "Detetives particulares licensed (state councils)",
                "No general localisation; cloud rules under study"),
    "MX": _snap(26, 121, 0.43, "LFPDPPP (2025 reform; regulator transition post-INAI)",
                "New constitutional reform tightens consent requirements",
                "Investigación privada licensed (Registro Nacional de detectives?)",
                "No general localisation"),
    "AR": _snap(37, 66, 0.44, "Ley 25.326 de Protección de Datos Personales (AAIP)",
                "Registration/notification culture; public-data exemptions",
                "Perito privado registry with courts",
                "No localisation"),
    "CL": _snap(63, 86, 0.67, "Ley 19.628 + pending modernisation bill (SERNAC/ministry)",
                "Limited enforcement pending new law",
                "Investigadores privados register (Ministry)",
                "No localisation"),
    "CO": _snap(39, 119, 0.48, "Ley 1581 de Protección de Datos Personales (SIC)",
                "Habeas data culture; SIC guidance on public sources",
                "Detectives licensed by SIC/security statute",
                "No general localisation"),
    "ZA": _snap(41, 38, 0.56, "POPIA (Information Regulator)",
                "POPIA lawful-basis + publicly-available-source provisions",
                "PSIRA registration for private investigators",
                "No localisation; cross-border transfer conditions"),
    "NG": _snap(26, 127, 0.39, "Nigeria Data Protection Act 2023 (NDPC)",
                "NDPC enforcement emerging; journalism exemption narrow",
                "Private investigation licensing via state police permits",
                "No localisation"),
    "EG": _snap(30, 170, 0.30, "Personal Data Protection Law 151/2020",
                "Registration/breach-notification heavy; state-security carve-outs",
                "PI activity requires permit",
                "Cross-border transfer restrictions for strategic data"),
    "KE": _snap(32, 116, 0.43, "Data Protection Act 2019 (ODPC)",
                "ODPC guidance on journalism/research exemptions",
                "Private security & inquiry licensed (PSARA)",
                "No localisation"),
    "CA": _snap(75, 26, 0.80, "PIPEDA + provincial laws (OPC)",
                "PIPEDA applies; CPPA emerging",
                "Provincial private-investigator licensing (ON, BC, AB…)",
                "No general localisation"),
    "SE": _snap(80, 3, 0.85, "GDPR + Swedish Data Protection Act (IMY)",
                "EEA rules",
                "Detective activity permit (Polisen)",
                "No localisation"),
    "DK": _snap(90, 4, 0.90, "GDPR + Databeskyttelsesloven (Datatilsynet)",
                "EEA rules",
                "Security-service licences (PET oversight)",
                "No localisation"),
    "FI": _snap(88, 6, 0.87, "GDPR + Personal Data Act (Tietosuojavaltuutettu)",
                "EEA rules",
                "Security/ investigator licensing (police)",
                "No localisation"),
    "BE": _snap(69, 14, 0.76, "GDPR + Act of 30 July 2018 (APD/GBA)",
                "EEA rules; strict on dossier-building",
                "Detective bureaux licensed (Ministry of Justice)",
                "No localisation"),
    "AT": _snap(67, 32, 0.75, "GDPR + Datenschutzgesetz (DSB)",
                "EEA rules",
                "Investigation bureaux licensed (Ministry of Interior)",
                "No localisation"),
    "CZ": _snap(56, 44, 0.72, "GDPR + zákon o ochraně osobních údajů (UUOU)",
                "EEA rules",
                "Private security licensing (MV ČR)",
                "No localisation"),
    "RO": _snap(46, 99, 0.57, "GDPR + Law 190/2018 (ANSPDCP)",
                "EEA rules; journalist/research derogations in Law 190",
                "Licensed private investigator activity",
                "No localisation"),
    "VN": _snap(40, 162, 0.41, "Law on Personal Data Protection 2025 (PDPL, new)",
                "Cybersecurity law 2018 licensing; content takedowns common",
                "Security/investigation services state-permitted only",
                "Localization + CSDT local storage requirements"),
    "TH": _snap(34, 87, 0.42, "PDPA B.E. 2562 (2019)",
                "PDPA + Computer Crime Act takedown powers",
                "Private detective licensing restricted",
                "No general localisation"),
    "ID": _snap(37, 113, 0.53, "PDP Law No. 27/2022 (supervisory authority operational 2025+)",
                "Electronic Information Law historically used against journalists",
                "Security services licensed (Ministry of Manpower/Kemendagri)",
                "Private data localisation for public electronic systems"),
    "MY": _snap(50, 107, 0.59, "PDPA 2010 (amended 2024)",
                "PDPA basis required; licensing regime for data processors proposed",
                "Private investigator licensing under state laws",
                "No general localisation"),
    "PH": _snap(33, 116, 0.47, "Data Privacy Act 2012 (NPC)",
                "NPC enforcement incl. media/social scraping cases",
                "Private detective agency licensing (DILG)",
                "No localisation"),
    "PK": _snap(27, 157, 0.38, "Personal Data Protection Bill (pending) + PECA cyber laws",
                "Prevalence of blocking/censorship (PTA); legal uncertainty",
                "Unlicensed/private detective sector; PI licences via provincial govt",
                "No general localisation"),
    "BD": _snap(23, 165, 0.30, "Digital Security Act / Cyber Security Act (no comprehensive privacy law)",
                "Vague cyber laws create risk for investigative work",
                "No formal PI licensing framework",
                "Data localisation proposed for govt data"),
    "IR": _snap(23, 176, 0.17, "No comprehensive privacy law; e-commerce law + state control",
                "Heavy filtering; severe legal risk for OSINT activity",
                "No PI framework; state security controls",
                "Data localisation mandates (NITC)"),
    "VE": _snap(10, 152, 0.12, "Ley Constitucional de Protección de Datos (LOPDP new framework)",
                "LOPDP 2021 consent rules; political risk for investigative work",
                "No functional PI licensing",
                "Some public-data localisation; internet controls"),
}

# country name -> iso2 for profile lookups
NAME_TO_ISO2 = {
    "UNITED STATES": "US", "USA": "US", "UNITED KINGDOM": "GB", "UK": "GB",
    "GERMANY": "DE", "FRANCE": "FR", "NETHERLANDS": "NL", "IRELAND": "IE",
    "SPAIN": "ES", "ITALY": "IT", "POLAND": "PL", "NORWAY": "NO",
    "SWITZERLAND": "CH", "UKRAINE": "UA", "RUSSIA": "RU", "RUSSIAN FEDERATION": "RU",
    "TURKEY": "TR", "TÜRKIYE": "TR", "UNITED ARAB EMIRATES": "AE", "UAE": "AE",
    "SAUDI ARABIA": "SA", "ISRAEL": "IL", "INDIA": "IN", "CHINA": "CN",
    "JAPAN": "JP", "SOUTH KOREA": "KR", "KOREA": "KR", "SINGAPORE": "SG",
    "HONG KONG": "HK", "AUSTRALIA": "AU", "NEW ZEALAND": "NZ", "BRAZIL": "BR",
    "MEXICO": "MX", "ARGENTINA": "AR", "CHILE": "CL", "COLOMBIA": "CO",
    "SOUTH AFRICA": "ZA", "NIGERIA": "NG", "EGYPT": "EG", "KENYA": "KE",
    "CANADA": "CA", "SWEDEN": "SE", "DENMARK": "DK", "FINLAND": "FI",
    "BELGIUM": "BE", "AUSTRIA": "AT", "CZECHIA": "CZ", "CZECH REPUBLIC": "CZ",
    "ROMANIA": "RO", "VIETNAM": "VN", "THAILAND": "TH", "INDONESIA": "ID",
    "MALAYSIA": "MY", "PHILIPPINES": "PH", "PAKISTAN": "PK",
    "BANGLADESH": "BD", "IRAN": "IR", "VENEZUELA": "VE", "BELARUS": "BY",
    "SYRIA": "SY", "NORTH KOREA": "KP", "CUBA": "CU",
}


def _iso2(country):
    s = (country or "").strip().upper()
    if len(s) == 2:
        return s
    return NAME_TO_ISO2.get(s)


def country_profile(country):
    """World Bank indicators + embedded static risk snapshot for a country."""
    try:
        cc = _iso2(country)
        if not cc:
            return {"country": country, "error": "unknown country (use ISO2 or common name)"}
        indicators = {
            "gdp_per_capita_usd": _wb(cc, "NY.GDP.PCAP.CD"),
            "internet_users_pct": _wb(cc, "IT.NET.USER.ZS"),
            "political_stability_pv_est": {
                **_wb(cc, "PV.EST"),
                "note": "WGI political-stability series is archived in WDI Archives; value may be null"},
        }
        snap = RISK_SNAPSHOT.get(cc)
        profile = {"country": cc,
                   "indicators": indicators,
                   "risk": dict(snap) if snap else {"note": "no embedded snapshot for this country"}}
        if snap:
            profile["risk"]["as_of"] = "embedded snapshot — verify against TI CPI / RSF / WJP primary sources"
        db.audit("system", "risk.country_profile", cc, "")
        return profile
    except Exception as e:
        return {"country": country, "error": str(e)[:150]}


# ---------------------------------------------------- jurisdiction cards

_D = "general orientation only, not legal advice"


def _card(priv, auth, scrape, pi, loc, law):
    return {"privacy_law": priv, "enforcement_authority": auth,
            "scraping_posture": scrape, "pi_licensing": pi,
            "data_localization": loc, "lawful_access_note": law,
            "disclaimer": _D}


JURISDICTION_CARDS = {
    "US": _card("Sectoral (CCPA/CPRA + state laws); no federal omnibus law",
                "State attorneys general; FTC",
                "Public-data scraping broadly tolerated; circumventing access controls risks CFAA liability",
                "State-by-state PI licensing (e.g. NY), otherwise light",
                "Sectoral only",
                "Stored Communications Act + wiretap law governs access; preservation letters via provider"),
    "GB": _card("UK GDPR + DPA 2018 + PECR",
                "Information Commissioner's Office (ICO)",
                "Allowed with lawful basis; ToS breaches and excessive collection are the main risks",
                "No PI licence; SIA licensing for investigation businesses",
                "None general",
                "IPA 2016 / Investigatory Powers regime; RIPA authorisations for public authorities"),
    "DE": _card("GDPR + BDSG",
                "State data protection authorities + BfDI",
                "Strict — legitimate interest + minimisation required for personal-data collection",
                "Trade permit for detective agencies",
                "None (EU transfer rules apply)",
                "StPO procedural rules; Vorratsdatenspeicherung for telcos"),
    "FR": _card("GDPR (CNIL enforcement)",
                "CNIL",
                "Legal basis required; CNIL fines for mass collection of public personal data",
                "Enquêteurs judiciaires licensed (CNAPS)",
                "None (EU transfer rules)",
                "Code de procédure pénale; strict limits on covert collection"),
    "NL": _card("GDPR + UAVG", "Autoriteit Persoonsgegevens",
                "Purpose limitation applies; AIVD/MIVD oversight for state actors",
                "Bureau permits + Bibob vetting",
                "None", "Wet BOB + Intelligence and Security Act 2017"),
    "IE": _card("GDPR + DPA 2018", "Data Protection Commission (DPC)",
                "GDPR standard; DPC is EU lead regulator for many platforms",
                "Licensing emerging via Private Security & Intelligence firms regime",
                "None", "Criminal Justice (Surveillance) Act 2012"),
    "ES": _card("GDPR + LOPDGDD", "Agencia Española de Protección de Datos (AEPD)",
                "Legal basis needed; AEPD sanctions unlicensed collection",
                "Ministry of Interior licence for investigation activity",
                "None", "LOPDGDD + Ley de Enjuiciamiento Criminal limits"),
    "IT": _card("GDPR + Codice Privacy", "Garante per la protezione dei dati personali",
                "Garante actively regulates scraping/AI-training collection",
                "Ministerial licence for investigazioni private",
                "None", "Codice di Procedura Penale; strict wiretap controls"),
    "PL": _card("GDPR + DPA Act", "UODO",
                "GDPR basis required; moderate enforcement",
                "MSWiA licensing for detection activity",
                "None", "KPKK + Ustawa o policji constraints"),
    "NO": _card("GDPR/EEA + Personal Data Act", "Datatilsynet",
                "EEA standard", "Minimal; security sector regulated",
                "None", "Lov om politiet (police act) — private collection unregulated beyond PDPA"),
    "CH": _card("revFADP (2023)", "Federal Data Protection and Information Commissioner (FDPIC)",
                "FADP + ToS/competition law constraints",
                "Cantonal licensing for security/personal information services",
                "None", "Swiss criminal code art. 271/273 — extraterritorial conduct limits"),
    "UA": _card("Law on Personal Data Protection (GDPR-alignment reform pending)",
                "Ombudsperson's office (Ukrainian Parliament)",
                "Martial-law restrictions; wartime caution advised",
                "Ministry of Interior licensing",
                "State-data localisation; wartime transfer rules",
                "Criminal procedural code; SBU oversight"),
    "RU": _card("152-FZ personal data law", "Roskomnadzor (+ FSB/General Prosecutor)",
                "High legal risk for foreign OSINT; localisation and 'extremist' blocking powers",
                "Licensed detective activity under MVD/FSB oversight",
                "Mandatory localisation of Russian citizens' personal data",
                "SORM mandatory-interception infrastructure; 6-FZ data-retention law"),
    "TR": _card("KVKK (Law 6689)", "Kişisel Verileri Koruma Kurumu (KVKK) + ICTA",
                "Consent/basis required; ICTA blocking orders common",
                "No functioning PI licence regime",
                "ICTA can demand localisation of strategic data",
                "CMK + Law 5651 on internet content"),
    "AE": _card("Federal Decree-Law 45/2021 (+ DIFC/ADGM regimes)", "UAE Data Office",
                "Cybercrime Law 34/2021 constrains collecting/publishing personal data",
                "MOI licensing for security/investigation services",
                "Sectoral (health); free-zone specific regimes",
                "Federal criminal procedure; no-judicial-review interception caveats"),
    "SA": _card("PDPL (2023, SDAIA)", "SDAIA + National Data Management Office",
                "Cybercrime law restricts unauthorised collection/publication",
                "MOI licensing for investigation services",
                "Cloud-computing rules; health data localisation",
                "Criminal Procedure Law; Mabahith investigations"),
    "IL": _card("Protection of Privacy Law 1981 (+ Basic Law 7761)",
                "Privacy Protection Authority (under Justice Ministry)",
                "Basic-law privacy tort limits aggressive collection",
                "Inquiry services registry (Ministry of Justice)",
                "None", "Israel Security Agency (Shin Bet) + police lawful-access powers"),
    "IN": _card("DPDP Act 2023 (Data Protection Board), IT Act 2000",
                "Data Protection Board of India",
                "IT Act s.43A + intermediary rules; robots.txt honoured by court practice",
                "State-level detective licensing; no national PI licence",
                "Government can notify data localisation for critical data",
                "IT Act s.69 + telegraph act interception; SPARROW/CCTNS systems"),
    "CN": _card("PIPL + Cybersecurity Law + Data Security Law", "Cyberspace Administration of China (CAC)",
                "Highly restrictive: consent + purpose limits; foreign collection may breach law",
                "No private-investigation licensing (state only)",
                "Extensive localisation (CIIO/important data); security assessment for transfers",
                "National Intelligence Law 2017 compels cooperation; MPS surveillance"),
    "JP": _card("APPI", "Personal Information Protection Commission (PPC)",
                "APPI applies to scraped personal information incl. online identifiers",
                "Tenpai-gyo (探偵業) registration in prefectures",
                "None", "Wiretapping law 1999 — strict warrant requirements"),
    "KR": _card("PIPA", "Personal Information Protection Committee (PIPC)",
                "Strict interpretation: aggregated public data can still be personal information",
                "Licensed security sector; private detective activity restricted",
                "None", "Protection of Communications Secrets Act; NIS oversight"),
    "SG": _card("PDPA 2012", "Personal Data Protection Commission (PDPC)",
                "Publicly-available-data exceptions exist but purpose limits apply",
                "Police licensing for security/surveillance industry",
                "Overseas-transfer safeguard obligations",
                "Criminal Procedure Code interception warrants"),
    "HK": _card("PDPO (Ordinance 486)", "Privacy Commissioner for Personal Data (PCPD)",
                "PDPO s.65 new-purpose restriction; doxing offences added 2021",
                "Security & insurance investigator licensing",
                "None", "Interception of Communications and Surveillance Ordinance (court-ordered)"),
    "AU": _card("Privacy Act 1988 + APPs", "OAIC",
                "APPs apply to collection from public sources; journalism exemptions limited",
                "State-based licensing for commercial agents/investigators",
                "None", "Telecommunications (Interception) Act + Surveillance Devices Acts (state)"),
    "NZ": _card("Privacy Act 2020", "Office of the Privacy Commissioner",
                "IPP collection rules apply even to public data",
                "PSPLA licensing for private security/investigators",
                "None", "Law Enforcement (Surveillance) legislation — warrants required"),
    "BR": _card("LGPD", "ANPD",
                "Legal-basis required; public-source scraping of personal data still regulated",
                "Detetives particulares licensed by state councils",
                "No general localisation",
                "Marco Civil da Internet; judicial authorisation for access"),
    "MX": _card("LFPDPPP (2025 reform; post-INAI regulator transition)",
                "Federal data protection authority (post-INAI succession body)",
                "Consent-centric; constitutional reform expands obligations",
                "Investigación privada registration requirements",
                "None general", "Federal criminal procedure; CNTe lawful-access"),
    "AR": _card("Ley 25.326", "Agencia de Acceso a la Información Pública (AAIP)",
                "Registration culture; public-source exemptions apply",
                "Perito privado registration with courts",
                "None", "Código procesal; interception needs judicial order"),
    "CL": _card("Ley 19.628 (modernisation pending)", "SERNAC + Ministry",
                "Limited enforcement; new law will tighten basis requirements",
                "Investigator registration",
                "None", "Criminal procedure code warrant regime"),
    "CO": _card("Ley 1581 + decrees", "Superintendencia de Industria y Comercio (SIC)",
                "Habeas-data culture; SIC guidance tolerates public-source collection",
                "Licensed detectives (security statutes)",
                "None", "Interception requires fiscal/judicial authorisation"),
    "ZA": _card("POPIA", "Information Regulator (SA)",
                "Publicly-available-source provisions help, purpose limits remain",
                "PSIRA registration for investigators",
                "None", "RICA interception authorisation (judge + minister)"),
    "NG": _card("NDPA 2023", "Nigeria Data Protection Commission (NDPC)",
                "Emerging enforcement; journalism/research exemptions",
                "State police permits de facto",
                "None", "Cybercrimes Act 2015 interception powers"),
    "EG": _card("PDP Law 151/2020", "Data protection regulator (aggregated under RDA/IDSC)",
                "Registration-heavy; state-security carve-outs",
                "Permit required for investigation activity",
                "Strategic-data transfer restrictions",
                "Emergency-law surveillance powers"),
    "KE": _card("Data Protection Act 2019", "Office of the Data Protection Commissioner (ODPC)",
                "ODPC guidance permits some public-source processing with safeguards",
                "PSARA-licensed private security sector",
                "None", "Lawful Interception of Communications Regulations"),
    "CA": _card("PIPEDA + provincial laws", "Office of the Privacy Commissioner (OPC)",
                "PIPEDA applies; consent exceptions narrow",
                "Provincial PI licensing (ON/BC/AB...)",
                "None", "Criminal Code s.184 interception prohibitions"),
    "SE": _card("GDPR + Data Protection Act", "IMY",
                "EEA standard", "Detective permits via police",
                "None", "Signal Act (signalövervakning) judicial authorisation"),
    "DK": _card("GDPR + Databeskyttelsesloven", "Datatilsynet",
                "EEA standard", "Security-service licensing under PET oversight",
                "None", "Retteretslæg omfattende interception (judicial)"),
    "FI": _card("GDPR + Personal Data Act", "Tietosuojavaltuutettu",
                "EEA standard", "Police-supervised security sector",
                "None", "Criminal procedure interception permits"),
    "BE": _card("GDPR + Act 30 July 2018", "APD/GBA",
                "Strict on dossier-building", "Justice-ministry licensed bureaux",
                "None", "Judicial interception authorisation (chambre du conseil)"),
    "AT": _card("GDPR + DSG", "Datenschutzbehörde (DSB)",
                "EEA standard", "Bureau licensing (Interior Ministry)",
                "None", "Strafprozessordnung interception warrants"),
    "CZ": _card("GDPR + Act 110/2019", "ÚOOÚ",
                "EEA standard", "Interior Ministry security licensing",
                "None", "Trestní řádní řád interception warrants"),
    "RO": _card("GDPR + Law 190/2018", "ANSPDCP",
                "Law 190 arts. 7-8 give media/research derogations",
                "Licensed private investigation",
                "None", "Criminal procedure interception (DIICOT/judge)"),
    "VN": _card("New PDPL 2025", "Ministry of Public Security (data protection authority)",
                "Cybersecurity Law licensing; content control heavy",
                "State-permitted security services only",
                "Localization of local user data (Decree 53)",
                "Cybersecurity Law interception powers (MPS)"),
    "TH": _card("PDPA B.E. 2562", "PDPC (Thailand)",
                "PDPA + Computer Crime Act takedown risk",
                "Restricted detective licensing",
                "None", "Computer Crime Act + lèse-majesté exposure"),
    "ID": _card("PDP Law 27/2022", "Lembaga PDP (supervisory body, phasing in)",
                "EITL history of prosecutions against journalists",
                "Licensed security services",
                "Local storage for public electronic systems",
                "Law 19/2016 interception (Electronic Information & Transactions Law)"),
    "MY": _card("PDPA 2010 (+ 2024 amendments)", "Jabatan Perlindungan Data Peribadi (JPDP)",
                "Basis requirements apply; amendments expand enforcement",
                "State-level investigator licensing",
                "None", "Criminal Procedure Code + Communications multimedia interception"),
    "PH": _card("Data Privacy Act 2012", "National Privacy Commission (NPC)",
                "NPC has acted against unlicensed scraping of personal data",
                "DILG-licensed detective agencies",
                "None", "RA 10175 cybercrime + Wiretapping Act (judicial)"),
    "PK": _card("No comprehensive privacy law (PDPA bill pending)", "PTA + proposed DPA",
                "PTA blocking + legal uncertainty raise operational risk",
                "Provincial PI licensing, weakly enforced",
                "None", "PECA surveillance powers; no independent oversight body"),
    "BD": _card("No comprehensive privacy law; Cyber Security Act 2023",
                "BTRC + CERT (no dedicated DPA)",
                "Vague cyber provisions create criminal risk for investigative work",
                "No formal PI framework",
                "Government data localisation proposed",
                "DSEB/DGFI lawful-access powers; no published oversight"),
    "IR": _card("No comprehensive privacy law; e-commerce law",
                "Ministry of ICT / judicial authorities",
                "Filtered internet + severe legal risk; avoid operational activity",
                "No PI licensing framework",
                "NITC data localisation",
                "Judicial/security-agency interception; no independent oversight"),
    "VE": _card("LOPDP (Ley Orgánica de Protección de Datos Personales)",
                "APEXP (Autoridad de Protección de Datos Personales y Expurgo)",
                "LOPDP consent rules; political/legal risk for investigations",
                "No functional PI licensing",
                "Public-sector data localisation provisions",
                "SEBIN/binational police powers; limited judicial independence"),
}

def jurisdiction_card(country):
    """Concise legal-orientation card for a jurisdiction (embedded static)."""
    try:
        cc = _iso2(country)
        if not cc:
            return {"country": country, "error": "unknown country (use ISO2 or common name)"}
        card = JURISDICTION_CARDS.get(cc)
        if not card:
            return {"country": cc, "disclaimer": _D,
                    "note": "no embedded card for this jurisdiction — general principles: check local DPA + ToS"}
        return {"country": cc, **card}
    except Exception as e:
        return {"country": country, "error": str(e)[:150]}


SANCTIONS_ATTENTION = {
    "RU": {"programmes": "OFAC EO 14024 / 14066 etc. (Ukraine- and Russia-related), EU, UK, Swiss regimes",
           "note": "Broad sectoral + entity sanctions (financial, energy, tech, transport); heavy secondary-sanctions risk"},
    "BY": {"programmes": "OFAC EO 14038 (Belarus sanctions), EU, UK",
           "note": "Leadership, enterprises and sectors designated; divestment rules"},
    "IR": {"programmes": "OFAC ITSR/IFCA, Iran-sanctions (multiple EOs), EU, UK",
           "note": "Near-comprehensive embargo: energy, metals, petrochemicals, financial sector"},
    "KP": {"programmes": "OFAC NKREF / NS-PMHR (North Korea sanctions), UN, EU, UK",
           "note": "Near-total embargo; WMD/proliferation financing triggers"},
    "SY": {"programmes": "OFAC Syrian Sanctions Regulations (EO 13894 as amended), Caesar Act, UN/EU",
           "note": "Post-2024/25 transition: some easings in flux — verify current OFAC guidance"},
    "CU": {"programmes": "Cuban Assets Control Regulations (31 CFR 515), OFAC",
           "note": "Long-standing embargo; remittances/tourism heavily restricted"},
    "VE": {"programmes": "OFAC EO 13850/13884 (gold, oil, government dealings), UK/EU",
           "note": "Sanctions on PdVSA, government actors; general licences rotate frequently"},
}


def overlay(sanctioned_countries):
    """Flag sanctions/export-control attention for a list of travel/transit countries.

    Uses an embedded list of comprehensively or heavily sanctioned
    jurisdictions (RU, BY, IR, KP, SY, CU, VE) with OFAC-programme notes.
    """
    try:
        flagged, unflagged = [], []
        for c in (sanctioned_countries or []):
            cc = _iso2(c) or (c or "").strip().upper()[:2]
            info = SANCTIONS_ATTENTION.get(cc)
            if info:
                flagged.append({"country": cc, "programmes": info["programmes"],
                                "note": info["note"],
                                "action": "screen counterparties against OFAC/EU/UK lists; check general licences; expect export-control licensing"})
            else:
                unflagged.append(cc)
        return {"input": list(sanctioned_countries or []),
                "flagged_count": len(flagged), "flagged": flagged,
                "no_attention_flag": unflagged,
                "sanctioned_watchlist": sorted(SANCTIONS_ATTENTION.keys()),
                "disclaimer": "embedded snapshot of heavily sanctioned jurisdictions — verify current OFAC/EU/UK measures before travel or dealing"}
    except Exception as e:
        return {"error": str(e)[:150]}
