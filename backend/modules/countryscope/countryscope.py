"""Xaxglog country-scoped search — put a name, company, site, IP, phone or
email into a chosen country context.

The module does not invent a country for a person. It combines:
  - a country source catalog (official company registries, procurement,
    courts, charities, beneficial-ownership portals, search engines)
  - live checks where a free public API exists:
      * GLEIF jurisdiction/legal-country match (all countries)
      * USAspending federal awards (US)
      * TED EU notices (EU member states)
      * ProPublica nonprofit + LDA lobbying (US)
      * server/IP country for domains and IPs
      * phone number-plan country via libphonenumber
  - explicit match confidence and caveats. ccTLD, server location and
    registration jurisdiction are leads, not proof of a person's location.

Lawful-use note: public registries and public APIs only. No login walls,
captcha solving, private databases, or device access. Country context is
analytical scoping, not a determination of nationality or residence.
"""
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

EU = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
}

# iso2 -> (name, region, ccTLD, capital)
BASE = {
    "US": ("United States", "North America", "us", "Washington, DC"),
    "GB": ("United Kingdom", "Europe", "uk", "London"),
    "CA": ("Canada", "North America", "ca", "Ottawa"),
    "AU": ("Australia", "Oceania", "au", "Canberra"),
    "NZ": ("New Zealand", "Oceania", "nz", "Wellington"),
    "IE": ("Ireland", "Europe", "ie", "Dublin"),
    "DE": ("Germany", "Europe", "de", "Berlin"),
    "FR": ("France", "Europe", "fr", "Paris"),
    "NL": ("Netherlands", "Europe", "nl", "Amsterdam"),
    "BE": ("Belgium", "Europe", "be", "Brussels"),
    "LU": ("Luxembourg", "Europe", "lu", "Luxembourg"),
    "ES": ("Spain", "Europe", "es", "Madrid"),
    "IT": ("Italy", "Europe", "it", "Rome"),
    "PT": ("Portugal", "Europe", "pt", "Lisbon"),
    "CH": ("Switzerland", "Europe", "ch", "Bern"),
    "AT": ("Austria", "Europe", "at", "Vienna"),
    "SE": ("Sweden", "Europe", "se", "Stockholm"),
    "NO": ("Norway", "Europe", "no", "Oslo"),
    "DK": ("Denmark", "Europe", "dk", "Copenhagen"),
    "FI": ("Finland", "Europe", "fi", "Helsinki"),
    "IS": ("Iceland", "Europe", "is", "Reykjavik"),
    "PL": ("Poland", "Europe", "pl", "Warsaw"),
    "CZ": ("Czechia", "Europe", "cz", "Prague"),
    "SK": ("Slovakia", "Europe", "sk", "Bratislava"),
    "HU": ("Hungary", "Europe", "hu", "Budapest"),
    "RO": ("Romania", "Europe", "ro", "Bucharest"),
    "BG": ("Bulgaria", "Europe", "bg", "Sofia"),
    "GR": ("Greece", "Europe", "gr", "Athens"),
    "HR": ("Croatia", "Europe", "hr", "Zagreb"),
    "SI": ("Slovenia", "Europe", "si", "Ljubljana"),
    "EE": ("Estonia", "Europe", "ee", "Tallinn"),
    "LV": ("Latvia", "Europe", "lv", "Riga"),
    "LT": ("Lithuania", "Europe", "lt", "Vilnius"),
    "MT": ("Malta", "Europe", "mt", "Valletta"),
    "CY": ("Cyprus", "Europe", "cy", "Nicosia"),
    "TR": ("Türkiye", "Europe/Asia", "tr", "Ankara"),
    "UA": ("Ukraine", "Europe", "ua", "Kyiv"),
    "RU": ("Russia", "Europe/Asia", "ru", "Moscow"),
    "AE": ("United Arab Emirates", "Middle East", "ae", "Abu Dhabi"),
    "SA": ("Saudi Arabia", "Middle East", "sa", "Riyadh"),
    "IL": ("Israel", "Middle East", "il", "Jerusalem"),
    "IN": ("India", "Asia", "in", "New Delhi"),
    "SG": ("Singapore", "Asia", "sg", "Singapore"),
    "HK": ("Hong Kong", "Asia", "hk", "Hong Kong"),
    "JP": ("Japan", "Asia", "jp", "Tokyo"),
    "KR": ("South Korea", "Asia", "kr", "Seoul"),
    "CN": ("China", "Asia", "cn", "Beijing"),
    "TW": ("Taiwan", "Asia", "tw", "Taipei"),
    "MY": ("Malaysia", "Asia", "my", "Kuala Lumpur"),
    "ID": ("Indonesia", "Asia", "id", "Jakarta"),
    "PH": ("Philippines", "Asia", "ph", "Manila"),
    "TH": ("Thailand", "Asia", "th", "Bangkok"),
    "VN": ("Vietnam", "Asia", "vn", "Hanoi"),
    "BR": ("Brazil", "South America", "br", "Brasília"),
    "MX": ("Mexico", "North America", "mx", "Mexico City"),
    "AR": ("Argentina", "South America", "ar", "Buenos Aires"),
    "CL": ("Chile", "South America", "cl", "Santiago"),
    "CO": ("Colombia", "South America", "co", "Bogotá"),
    "PE": ("Peru", "South America", "pe", "Lima"),
    "ZA": ("South Africa", "Africa", "za", "Pretoria"),
    "NG": ("Nigeria", "Africa", "ng", "Abuja"),
    "KE": ("Kenya", "Africa", "ke", "Nairobi"),
    "EG": ("Egypt", "Africa", "eg", "Cairo"),
    "MA": ("Morocco", "Africa", "ma", "Rabat"),
    "GH": ("Ghana", "Africa", "gh", "Accra"),
    "PK": ("Pakistan", "Asia", "pk", "Islamabad"),
    "BD": ("Bangladesh", "Asia", "bd", "Dhaka"),
    "LK": ("Sri Lanka", "Asia", "lk", "Colombo"),
}

# Official or high-value country portals. Missing keys fall back to
# OpenCorporates / WorldLII / TED (for EU) below.
OVERRIDES = {
    "US": {
        "company_registry": ("SEC EDGAR", "https://www.sec.gov/cgi-bin/browse-edgar?company={q}&CIK=&type=10-K&action=getcompany"),
        "procurement": ("USAspending", "https://www.usaspending.gov/search?keywords={q}"),
        "courts": ("CourtListener", "https://www.courtlistener.com/?q={q}"),
        "charity": ("ProPublica Nonprofit Explorer", "https://projects.propublica.org/nonprofits/search?q={q}"),
        "lobbying": ("US LDA", "https://lda.senate.gov/api/v1/filings/?client_name={q}"),
    },
    "GB": {
        "company_registry": ("Companies House", "https://find-and-update.company-information.service.gov.uk/search?q={q}"),
        "procurement": ("Contracts Finder", "https://www.contractsfinder.service.gov.uk/Search/Results?&keywords={q}"),
        "courts": ("BAILII", "https://www.bailii.org/cgi-bin/lucy_search_1.cgi?query={q}&method=boolean"),
        "charity": ("Charity Commission", "https://register-of-charities.charitycommission.gov.uk/charity-search/-/results/page/1/delta/20?keywords={q}"),
    },
    "CA": {
        "company_registry": ("Corporations Canada", "https://www.ic.gc.ca/app/scr/cc/CorporationsCanada/fdrlCrpSrch.html?V_TOKEN=&crpNm={q}"),
        "procurement": ("CanadaBuys", "https://canadabuys.canada.ca/en/tender-opportunities?search={q}"),
        "courts": ("CanLII", "https://www.canlii.org/en/#search/text={q}"),
        "charity": ("CRA Charity Search", "https://apps.cra-arc.gc.ca/ebci/hacc/srch/pub/dsplyBscSrch?request_locale=en_CA&q.stts=0007&q.nttyNm={q}"),
    },
    "AU": {
        "company_registry": ("ASIC Connect", "https://connectonline.asic.gov.au/RegistrySearch/faces/landing/SearchRegisters.jspx"),
        "procurement": ("AusTender", "https://www.tenders.gov.au/?keyword={q}"),
        "courts": ("AustLII", "https://www.austlii.edu.au/cgi-bin/sinosrch.cgi?method=auto&query={q}"),
        "charity": ("ACNC Charity Register", "https://www.acnc.gov.au/charity/charities?search={q}"),
    },
    "NZ": {
        "company_registry": ("NZ Companies Office", "https://app.companiesoffice.govt.nz/companies/app/ui/pages/companies/search?q={q}"),
        "procurement": ("GETS", "https://www.gets.govt.nz/"),
        "courts": ("NZLII", "https://www.nzlii.org/cgi-bin/sinosrch.cgi?query={q}"),
        "charity": ("Charities Register", "https://register.charities.govt.nz/CharitiesRegister/Search?searchText={q}"),
    },
    "IE": {
        "company_registry": ("CRO", "https://core.cro.ie/search?searchText={q}"),
        "courts": ("Courts Service", "https://www.courts.ie/judgments?search_api_fulltext={q}"),
        "charity": ("Charities Regulator", "https://www.charitiesregulator.ie/en/information-for-the-public/search-the-register-of-charities?search={q}"),
    },
    "DE": {
        "company_registry": ("Unternehmensregister", "https://www.unternehmensregister.de/ureg/"),
        "courts": ("Rechtsprechung im Internet", "https://www.rechtsprechung-im-internet.de/"),
    },
    "FR": {
        "company_registry": ("Annuaire des entreprises", "https://annuaire-entreprises.data.gouv.fr/rechercher?terme={q}"),
        "courts": ("Légifrance", "https://www.legifrance.gouv.fr/search/all?query={q}"),
    },
    "NL": {
        "company_registry": ("KVK", "https://www.kvk.nl/zoeken/?source=web&q={q}"),
        "courts": ("Rechtspraak", "https://uitspraken.rechtspraak.nl/#!/zoeken?text={q}"),
    },
    "ES": {
        "company_registry": ("Registradores", "https://www.registradores.org/"),
        "courts": ("CENDOJ", "https://www.poderjudicial.es/search/indexAN.jsp"),
    },
    "IT": {
        "company_registry": ("Registro Imprese", "https://www.registroimprese.it/"),
        "courts": ("Italgiure", "https://www.italgiure.giustizia.it/"),
    },
    "CH": {
        "company_registry": ("Zefix", "https://www.zefix.ch/en/search/entity/list?name={q}"),
        "procurement": ("SIMAP", "https://www.simap.ch/"),
        "courts": ("Federal Supreme Court", "https://www.bger.ch/"),
    },
    "PL": {
        "company_registry": ("KRS", "https://wyszukiwarkaregon.stat.gov.pl/"),
        "courts": ("Supreme Court", "https://www.sn.pl/"),
    },
    "TR": {
        "company_registry": ("MERSIS", "https://mersis.ticaret.gov.tr/"),
        "procurement": ("EKAP", "https://ekap.kik.gov.tr/"),
        "courts": ("UYAP", "https://uyap.gov.tr/"),
    },
    "UA": {
        "company_registry": ("YouControl", "https://youcontrol.com.ua/"),
        "procurement": ("Prozorro", "https://prozorro.gov.ua/"),
        "courts": ("Court.gov.ua", "https://court.gov.ua/"),
    },
    "RU": {
        "company_registry": ("EGRUL", "https://egrul.nalog.ru/"),
        "procurement": ("Zakupki", "https://zakupki.gov.ru/"),
        "courts": ("Sudact", "https://sudact.ru/"),
    },
    "AE": {
        "company_registry": ("Dubai DED", "https://eservices.dubaided.gov.ae/"),
    },
    "SA": {
        "company_registry": ("MCI", "https://mc.gov.sa/"),
        "procurement": ("Etimad", "https://etimad.sa/"),
    },
    "IL": {
        "company_registry": ("Companies Registrar", "https://ica.justice.gov.il/"),
    },
    "IN": {
        "company_registry": ("MCA", "https://www.mca.gov.in/mcafoportal/viewCompanyMasterData.do"),
        "procurement": ("CPPP", "https://eprocure.gov.in/cppp/"),
        "courts": ("Indian Kanoon", "https://indiankanoon.org/search/?formInput={q}"),
    },
    "SG": {
        "company_registry": ("ACRA", "https://www.acra.gov.sg/how-to-guides/business-finding-and-managing-a-business/"),
        "procurement": ("GeBIZ", "https://www.gebiz.gov.sg/"),
    },
    "HK": {
        "company_registry": ("Companies Registry", "https://www.icris.cr.gov.hk/csci/"),
        "procurement": ("GLD Procurement", "https://pcms2.gld.gov.hk/"),
        "courts": ("Judiciary Legal Reference", "https://legalref.judiciary.hk/"),
    },
    "JP": {
        "company_registry": ("NTA Corporate Number", "https://www.houjin-bangou.nta.go.jp/"),
        "procurement": ("e-Procurement", "https://www.p-portal.go.jp/"),
        "courts": ("Courts in Japan", "https://www.courts.go.jp/app/hanrei_jp/search1"),
    },
    "KR": {
        "company_registry": ("NTS", "https://www.nts.go.kr/"),
        "procurement": ("KONEPS", "https://www.g2b.go.kr/"),
        "courts": ("Supreme Court", "https://www.scourt.go.kr/"),
    },
    "CN": {
        "company_registry": ("GSXT", "https://www.gsxt.gov.cn/"),
        "procurement": ("CCGP", "http://www.ccgp.gov.cn/"),
        "courts": ("China Judgements Online", "https://wenshu.court.gov.cn/"),
    },
    "BR": {
        "company_registry": ("Receita CNPJ", "https://solucoes.receita.fazenda.gov.br/Servicos/cnpjreva/cnpjreva_solicitacao.asp"),
        "procurement": ("ComprasNet", "https://www.gov.br/compras/"),
        "courts": ("STF", "https://portal.stf.jus.br/"),
    },
    "MX": {
        "company_registry": ("SAT RFC", "https://portalsat.plataforma.sat.gob.mx/"),
        "procurement": ("CompraNet", "https://compranet.hacienda.gob.mx/"),
        "courts": ("SCJN", "https://www.scjn.gob.mx/"),
    },
    "ZA": {
        "company_registry": ("CIPC", "https://eservices.cipc.co.za/"),
        "procurement": ("eTenders", "https://www.etenders.gov.za/"),
        "courts": ("SAFLII", "http://www.saflii.org/cgi-bin/sinosrch.cgi?query={q}"),
    },
    "NG": {
        "company_registry": ("CAC", "https://search.cac.gov.ng/"),
        "procurement": ("NOCOPO", "https://nocopo.bpp.gov.ng/"),
        "courts": ("NigeriaLII", "https://www.nigerialii.org/cgi-bin/sinosrch.cgi?query={q}"),
    },
    "KE": {
        "company_registry": ("BRS eCitizen", "https://brs.ecitizen.go.ke/"),
        "procurement": ("PPIP Tenders", "https://tenders.go.ke/"),
        "courts": ("Kenya Law", "http://kenyalaw.org/caselaw/"),
    },
}

COMMON_EMAIL = {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com",
                "hotmail.com", "live.com", "icloud.com", "me.com",
                "proton.me", "protonmail.com", "aol.com", "gmx.net",
                "web.de", "mail.ru"}


def _build_countries():
    out = {}
    for cc, (name, region, cctld, capital) in BASE.items():
        src = {
            "company_registry": (
                "OpenCorporates",
                "https://opencorporates.com/companies?q={q}&jurisdiction_code=" + cc.lower()),
            "courts": (
                "WorldLII",
                "http://www.worldlii.org/cgi-bin/sinosrch.cgi?method=auto&query={q}"),
        }
        if cc in EU:
            src["procurement"] = (
                "TED — Tenders Electronic Daily",
                "https://ted.europa.eu/en/search/result?FT={q}")
        src.update(OVERRIDES.get(cc, {}))
        live = ["gleif"]
        if cc == "US":
            live += ["usaspending", "nonprofit", "lobbying"]
        if cc in EU:
            live += ["ted"]
        out[cc] = {
            "iso2": cc, "name": name, "region": region, "ccTLD": cctld,
            "capital": capital, "eu": cc in EU, "sources": src, "live": live,
        }
    return out


COUNTRIES = _build_countries()


def countries():
    return [{"iso2": c["iso2"], "name": c["name"], "region": c["region"],
             "ccTLD": c["ccTLD"], "eu": c["eu"], "live": c["live"]}
            for c in sorted(COUNTRIES.values(), key=lambda x: x["name"])]


def _norm_country(cc):
    v = str(cc or "").strip().upper()
    if v in ("UK", "GBR"):
        return "GB"
    if v in ("USA",):
        return "US"
    if v in COUNTRIES:
        return v
    for code, c in COUNTRIES.items():
        if v and v.lower() == c["name"].lower():
            return code
    return v


def profile(cc):
    cc = _norm_country(cc)
    c = COUNTRIES.get(cc)
    if not c:
        return {"status": "error", "error": "unknown country code"}
    out = {k: v for k, v in c.items() if k != "sources"}
    out["sources"] = [{"id": k, "name": v[0], "url_template": v[1]}
                      for k, v in c["sources"].items()]
    out["status"] = "ok"
    return out


def _kind(q):
    q = (q or "").strip()
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", q):
        return "email"
    if re.match(r"^\+?\d[\d\s().-]{7,}$", q) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q):
        return "phone"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q):
        return "ip"
    if _domain(q):
        return "site"
    return "name"


def _domain(q):
    s = (q or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            s = urllib.parse.urlsplit(s).netloc
        except Exception:
            return ""
    else:
        s = s.split("/")[0]
    s = s.lower().strip(".")
    if s.startswith("www."):
        s = s[4:]
    if re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", s):
        return s
    return ""


def _url(template, q):
    if not template:
        return ""
    return template.replace("{q}", urllib.parse.quote_plus(str(q or "")))


def _sig(kind, value, source, confidence="medium", note="", url="", **extra):
    rec = {"type": kind, "value": value, "source": source,
           "confidence": confidence, "note": note}
    if url:
        rec["url"] = url
    rec.update({k: v for k, v in extra.items() if v is not None})
    return rec


def _ip_country(ip):
    try:
        import modules.infra.infra as INFRA
        return (INFRA.asn_lookup(ip).get("country_code") or "").upper()
    except Exception:
        return ""


def _infer_country(q, kind):
    if kind == "ip":
        return _ip_country(q)
    if kind == "phone":
        try:
            import phonenumbers
            p = phonenumbers.parse(q, None)
            return (phonenumbers.region_code_for_number(p) or "").upper()
        except Exception:
            return ""
    if kind in ("site", "email"):
        domain = _domain(q if kind == "site" else q.split("@", 1)[-1])
        if not domain:
            return ""
        for cc, c in COUNTRIES.items():
            if domain.endswith("." + c["ccTLD"].lower()):
                return cc
        if kind == "email" and domain in COMMON_EMAIL:
            return ""
        try:
            ip = socket.gethostbyname(domain)
            return _ip_country(ip)
        except Exception:
            return ""
    return ""


def _site_scope(query, cc):
    domain = _domain(query)
    out = {"status": "ok", "domain": domain, "signals": []}
    if not domain:
        return {"status": "error", "error": "not a domain or URL", "signals": []}
    c = COUNTRIES[cc]
    cctld = c["ccTLD"].lower()
    cc_match = domain == cctld or domain.endswith("." + cctld)
    out["ccTLD"] = cctld
    out["ccTLD_match"] = cc_match
    if cc_match:
        out["signals"].append(_sig(
            "ccTLD", "." + cctld, "domain name", "medium",
            "ccTLD is a registration choice, not proof of the operator's country"))

    ip_cc = ""
    try:
        import modules.infra.infra as INFRA
        ip = socket.gethostbyname(domain)
        out["ip"] = ip
        asn = INFRA.asn_lookup(ip)
        out["asn"] = asn
        ip_cc = (asn.get("country_code") or "").upper()
        out["ip_country"] = asn.get("country") or ""
        out["ip_country_code"] = ip_cc
        out["ip_country_match"] = ip_cc == cc
        if ip_cc:
            out["signals"].append(_sig(
                "server_country", asn.get("country") or ip_cc, "ip-api",
                "medium" if ip_cc == cc else "low",
                "server/hosting location, not the operator's location",
                lat=asn.get("lat"), lon=asn.get("lon")))
        if asn.get("org") or asn.get("isp"):
            out["signals"].append(_sig(
                "network", asn.get("org") or asn.get("isp"), "ip-api",
                "medium", "ISP/hosting organization for the server IP"))
        if asn.get("hosting"):
            out["signals"].append(_sig(
                "hosting", "hosting/datacenter IP", "ip-api", "medium"))
        out["ptr"] = INFRA.ptr_lookup(ip)
    except Exception as e:
        out["ip_error"] = str(e)[:150]

    if cc_match and ip_cc == cc:
        out["match"] = "high"
    elif cc_match or ip_cc == cc:
        out["match"] = "medium"
    elif ip_cc:
        out["match"] = "low"
    else:
        out["match"] = "unknown"
    out["caveat"] = ("ccTLD is a registration choice; IP geolocation is the "
                     "server/hosting country, not the person's location.")
    return out


def _ip_scope(query, cc):
    ip = (query or "").strip()
    out = {"status": "ok", "ip": ip, "signals": []}
    try:
        import modules.infra.infra as INFRA
        asn = INFRA.asn_lookup(ip)
        out["asn"] = asn
        out["ptr"] = INFRA.ptr_lookup(ip)
        ip_cc = (asn.get("country_code") or "").upper()
        out["ip_country"] = asn.get("country") or ""
        out["ip_country_code"] = ip_cc
        out["ip_country_match"] = ip_cc == cc
        if ip_cc:
            out["signals"].append(_sig(
                "server_country", asn.get("country") or ip_cc, "ip-api",
                "medium" if ip_cc == cc else "low",
                "server/hosting location, not a person's location"))
        if asn.get("org") or asn.get("isp"):
            out["signals"].append(_sig(
                "network", asn.get("org") or asn.get("isp"), "ip-api", "medium"))
        out["match"] = "high" if ip_cc == cc else ("low" if ip_cc else "unknown")
    except Exception as e:
        out["status"] = "error"
        out["error"] = str(e)[:150]
        out["match"] = "unknown"
    out["caveat"] = "IP geolocation is infrastructure, not a person's location."
    return out


def _phone_scope(query, cc):
    try:
        import modules.deep_search.location as LOC
        res = LOC.phone_signals(query)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "signals": [],
                "match": "unknown"}
    parsed = res.get("parsed") or {}
    iso = (parsed.get("iso_region") or "").upper()
    res["iso_region"] = iso
    res["country_match"] = iso == cc
    res["match"] = "high" if iso == cc else ("low" if iso else "unknown")
    res["caveat"] = ("Number-plan country/region only; it is not a live "
                     "location and does not prove where the phone is now.")
    return res


def _email_scope(query, cc):
    email = (query or "").strip().lower()
    domain = email.split("@", 1)[-1] if "@" in email else ""
    out = {"status": "ok", "email": email, "signals": [], "match": "unknown"}
    try:
        import modules.deep_search.location as LOC
        loc = LOC.email_signals(email, include_profiles=False)
        out["location_signals"] = loc
        out["signals"].extend(loc.get("signals") or [])
    except Exception as e:
        out["location_error"] = str(e)[:150]
    if domain:
        site = _site_scope(domain, cc)
        out["domain_scope"] = site
        out["signals"].extend(site.get("signals") or [])
        out["match"] = site.get("match") or "unknown"
        if domain in COMMON_EMAIL:
            out["match"] = "unknown"
            out["note"] = ("Common email provider: the server country belongs to "
                           "the provider, not the person. Use the profile/name "
                           "signals instead.")
    out["caveat"] = ("Email addresses do not contain a country of residence. "
                     "Profile/self-declared location and domain infrastructure "
                     "are hints, not proof.")
    return out


def _parallel(tasks):
    out = {}
    if not tasks:
        return out
    with ThreadPoolExecutor(max_workers=min(4, len(tasks))) as ex:
        futs = {ex.submit(fn): name for name, fn in tasks}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                out[name] = fut.result()
            except Exception as e:
                out[name] = {"status": "error", "error": str(e)[:150]}
    return out


def _gleif(query):
    try:
        import modules.worldcorp.worldcorp as WC
        return WC.gleif_search(query, cap=25)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "results": []}


def _procurement(query, cc):
    try:
        import modules.procurement.procurement as PR
        return PR.search(query, country="us" if cc == "US" else "eu",
                         limit=5)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "results": []}


def _nonprofit(query):
    try:
        import modules.nonprofit.nonprofit as NP
        return NP.search(query, limit=5)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "results": []}


def _lobbying(query):
    try:
        import modules.lobbying.lobbying as LB
        return LB.search(query, limit=5)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "results": []}


def _name_scope(query, cc):
    out = {"status": "ok", "signals": [], "live": {}}
    tasks = [("gleif", lambda: _gleif(query))]
    if cc == "US":
        tasks += [("procurement", lambda: _procurement(query, cc)),
                  ("nonprofit", lambda: _nonprofit(query)),
                  ("lobbying", lambda: _lobbying(query))]
    elif cc in EU:
        tasks.append(("procurement", lambda: _procurement(query, cc)))
    out["live"] = _parallel(tasks)

    gleif = out["live"].get("gleif") or {}
    matches = []
    for r in gleif.get("results") or []:
        legal = (r.get("legal_country") or "").upper()
        hq = (r.get("hq_country") or "").upper()
        jur = (r.get("jurisdiction") or "").upper()
        if legal == cc or hq == cc or jur.startswith(cc):
            matches.append(r)
    for r in matches[:8]:
        legal = (r.get("legal_country") or "").upper()
        hq = (r.get("hq_country") or "").upper()
        out["signals"].append(_sig(
            "gleif_jurisdiction", r.get("name") or r.get("lei"),
            "GLEIF", "high",
            "legal/headquarters country matches selected country",
            "https://search.gleif.org/#/record/" + str(r.get("lei") or ""),
            lei=r.get("lei"), legal_country=legal, hq_country=hq))
    out["gleif_country_matches"] = len(matches)

    proc = out["live"].get("procurement") or {}
    for row in (proc.get("results") or [])[:5]:
        out["signals"].append(_sig(
            "procurement_award", row.get("awardee") or row.get("buyer")
            or row.get("title"), row.get("source") or "procurement",
            "medium", "public award record; verify the legal entity",
            row.get("url") or ""))

    nonp = out["live"].get("nonprofit") or {}
    for row in (nonp.get("results") or [])[:5]:
        out["signals"].append(_sig(
            "nonprofit_match", row.get("name"), "ProPublica/IRS", "high",
            "IRS-registered organization; verify EIN", row.get("url") or ""))

    lob = out["live"].get("lobbying") or {}
    for row in (lob.get("results") or [])[:5]:
        out["signals"].append(_sig(
            "lobbying_filing", row.get("client") or row.get("registrant"),
            "LDA", "medium", "public lobbying disclosure", row.get("url") or ""))

    high = bool(matches) or any(
        s.get("confidence") == "high" for s in out["signals"])
    any_live = any((v or {}).get("count") for v in out["live"].values())
    out["match"] = "high" if high else ("medium" if any_live else "low")
    out["caveat"] = ("Name matches are homonym-prone. A registry country match "
                     "is not proof that the person/company is the same target; "
                     "confirm with an identifier (LEI/EIN/company number).")
    return out


def _sources(c, q, kind):
    out, seen = [], set()

    def add(sid, label, name, url, query_scoped=True):
        if not url or sid in seen:
            return
        seen.add(sid)
        out.append({"id": sid, "label": label, "name": name,
                    "url": url, "query_scoped": query_scoped})

    if kind == "site":
        domain = _domain(q) or str(q)
        add("rdap", "Domain registration", "RDAP", "https://rdap.org/domain/" +
            urllib.parse.quote(domain))
        add("crt", "Certificate transparency", "crt.sh",
            "https://crt.sh/?q=" + urllib.parse.quote_plus(domain))
        add("urlscan", "URL/domain scan", "urlscan.io",
            "https://urlscan.io/search/#" + urllib.parse.quote_plus(domain))
        add("wayback", "Historical snapshots", "Wayback Machine",
            "https://web.archive.org/web/*/" + urllib.parse.quote(domain))
    else:
        for key, label in (("company_registry", "Company registry"),
                           ("procurement", "Procurement"),
                           ("courts", "Court records"),
                           ("charity", "Charity/nonprofit register"),
                           ("beneficial_ownership", "Beneficial ownership"),
                           ("lobbying", "Lobbying disclosures")):
            s = c["sources"].get(key)
            if s:
                add(key, label, s[0], _url(s[1], q), "{q}" in s[1])
        if c["sources"].get("company_registry", ("", ""))[0] != "OpenCorporates":
            add("opencorporates", "Company registry (aggregator)",
                "OpenCorporates",
                "https://opencorporates.com/companies?q=" +
                urllib.parse.quote_plus(str(q)) +
                "&jurisdiction_code=" + c["iso2"].lower())

    add("google", "Country-scoped search", "Google",
        "https://www.google.com/search?q=" + urllib.parse.quote_plus(str(q)) +
        "&gl=" + c["iso2"].lower() + "&num=20")
    add("bing", "Country-scoped search", "Bing",
        "https://www.bing.com/search?q=" + urllib.parse.quote_plus(str(q)) +
        "&cc=" + c["iso2"].lower())
    return out


def search(query, country="", case_id=None, user="system", include_live=True):
    """Scope a target to a country and return links + live public checks."""
    q = (query or "").strip()
    if not q:
        return {"status": "error", "error": "query required", "results": []}
    kind = _kind(q)
    cc = _norm_country(country)
    inferred = False
    if not cc or cc in ("AUTO", "*", "ALL"):
        cc = _infer_country(q, kind)
        inferred = True
    if not cc:
        if kind == "name":
            return {"status": "needs_country",
                    "error": "choose a country for a name/company search",
                    "query": q, "kind": kind, "countries": countries()}
        return {"status": "error", "error": "country required",
                "query": q, "kind": kind}
    if cc not in COUNTRIES:
        return {"status": "error", "error": "unknown country code",
                "query": q, "kind": kind, "country": cc}
    c = COUNTRIES[cc]

    if not include_live:
        if kind == "name":
            scope = {"status": "ok", "match": "low", "signals": [],
                     "caveat": "live checks disabled"}
        elif kind == "site":
            scope = _site_scope(q, cc)
        elif kind == "ip":
            scope = _ip_scope(q, cc)
        elif kind == "phone":
            scope = _phone_scope(q, cc)
        else:
            scope = _email_scope(q, cc)
    elif kind == "name":
        scope = _name_scope(q, cc)
    elif kind == "site":
        scope = _site_scope(q, cc)
    elif kind == "ip":
        scope = _ip_scope(q, cc)
    elif kind == "phone":
        scope = _phone_scope(q, cc)
    else:
        scope = _email_scope(q, cc)

    sources = _sources(c, q, kind)
    out = {
        "status": "ok", "query": q, "kind": kind,
        "country": {"iso2": c["iso2"], "name": c["name"],
                    "region": c["region"], "ccTLD": c["ccTLD"],
                    "eu": c["eu"], "live": c["live"]},
        "country_inferred": inferred,
        "scope": scope,
        "sources": sources,
        "summary": {
            "match": scope.get("match") or "unknown",
            "signals": len(scope.get("signals") or []),
            "source_links": len(sources),
            "live_sources": list((scope.get("live") or {}).keys()),
        },
        "caveat": ("Country scope is an analytical lead. Registry jurisdiction, "
                   "ccTLD and server location do not prove a person's nationality "
                   "or residence."),
    }
    try:
        db.audit(user, "countryscope.search", q[:80],
                 f"country={cc} kind={kind} match={out['summary']['match']}")
        if case_id:
            db.store_artifact(case_id, None, "countryscope",
                              "countryscope:search", out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out
