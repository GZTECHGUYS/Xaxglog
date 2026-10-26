"""Xaxglog deep_search connectors — free-tier international OSINT.

All functions use only the `requests` stdlib-stack, short timeouts, and
degrade gracefully when a key or network is missing. No dark-web crawling,
no auth-bypass, no paywalled CIA/LE databases: this is open-source
intelligence aggregation only.

Sources (no key needed unless noted):
  username : live HTTP profile checks across 90+ global platforms
  email    : XposedOrNot breach API + Gravatar existence + MX records (Google DoH)
  phone    : `phonenumbers` parse (region/carrier/type) + apilayer if NUM_API_KEY
  domain   : crt.sh subdomains + Google DoH (A/AAAA/MX/TXT/NS) + RDAP + urlscan search
  ip       : ip-api.com geo/ASN + AbuseIPDB/Shodan/ipinfo when keys present
  person   : handle matrix + Bluesky/Mastodon/Keybase verification + people
             indexes (Wikidata/Wikipedia/GitHub/OpenAlex/Semantic Scholar/
             ORCID/OpenLibrary/GDELT) + social web discovery
  social   : public profile metadata scraper (OpenGraph/Twitter/JSON-LD)
  company  : OpenCorporates free search
  geo      : OSM Nominatim forward geocode
"""
import re
import socket
from concurrent.futures import ThreadPoolExecutor

import requests

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (+research use; contact admin)"}
T = 12  # per-request timeout seconds


def _get(url, **kw):
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        r = requests.get(url, headers=headers, **kw)
        return r
    except Exception as e:
        return e


# ------------------------------------------------------------------ username
from .social import (  # noqa: E402  (kept with the username section for discoverability)
    NAME_RE,
    PLATFORMS,
    SAFE_USER_RE,
    check_username,
    discover_social,
    handle_candidates,
    name_registry_search,
    normalize_people_platforms,
    scrape_profile,
    social_footprint,
    sources_catalog,
    verified_accounts,
)
from .location import (  # noqa: E402
    _signal,
    email_signals,
    infrastructure_signals,
    merge_signals,
    name_signals,
    phone_signals,
    profile_signals,
)


def username_search(username, categories=None):
    """Public profile sweep across the expanded platform matrix."""
    return check_username(username, categories=categories)


# ------------------------------------------------------------------ email
def _mx_records(domain):
    r = _get(f"https://dns.google/resolve?name={domain}&type=MX")
    if isinstance(r, Exception):
        return {"error": str(r)[:150]}
    try:
        j = r.json()
        return {"answers": [a.get("data", "") for a in j.get("Answer", [])]}
    except Exception as e:
        return {"error": str(e)[:150]}


def email_search(email, hibp_key=""):
    email = (email or "").strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return {"input": email, "error": "invalid email format"}
    out = {"input": email, "breaches": {}, "meta": {}}
    domain = email.split("@", 1)[1]
    out["meta"]["mx"] = _mx_records(domain)
    # XposedOrNot — free, no key
    r = _get(f"https://api.xposedornot.com/v1/check-email/{email}")
    if isinstance(r, Exception):
        out["breaches"]["xposedornot"] = {"error": str(r)[:150]}
    elif r.status_code == 200:
        try:
            out["breaches"]["xposedornot"] = r.json()
        except Exception:
            out["breaches"]["xposedornot"] = {"raw": r.text[:500]}
    elif r.status_code == 404:
        out["breaches"]["xposedornot"] = {"breaches": [], "note": "no breach found (404)"}
    else:
        out["breaches"]["xposedornot"] = {"http": r.status_code, "raw": r.text[:300]}
    # Gravatar existence probe (md5 hash lookup, no key)
    import hashlib
    h = hashlib.md5(email.encode()).hexdigest()
    g = _get(f"https://www.gravatar.com/{h}.json")
    if not isinstance(g, Exception) and g.status_code == 200:
        try:
            out["meta"]["gravatar"] = g.json()
        except Exception:
            out["meta"]["gravatar"] = {"exists": True}
    else:
        out["meta"]["gravatar"] = {"exists": False}
    # HaveIBeenPwned only with key (v3 requires key + UA)
    if hibp_key:
        rr = _get("https://haveibeenpwned.com/api/v3/breachedaccount/" + email,
                  headers={"hibp-api-key": hibp_key})
        if not isinstance(rr, Exception):
            try:
                out["breaches"]["hibp"] = rr.json() if rr.status_code == 200 else {"http": rr.status_code}
            except Exception:
                out["breaches"]["hibp"] = {"http": rr.status_code}
    else:
        out["breaches"]["hibp"] = {"skipped": "HIBP_API_KEY not set"}
    out["location"] = email_signals(email, gravatar=out["meta"].get("gravatar"),
                                    include_profiles=False)
    return out


# ------------------------------------------------------------------ phone
def phone_search(number, apilayer_key=""):
    number = (number or "").strip()
    out = {"input": number}
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, number_type
    except ImportError:
        out["parse_error"] = "phonenumbers lib not installed (pip install phonenumbers)"
        phonenumbers = None
    if phonenumbers:
        try:
            p = phonenumbers.parse(number, None)
            out.update({
                "valid": phonenumbers.is_valid_number(p),
                "possible": phonenumbers.is_possible_number(p),
                "e164": phonenumbers.format_in_original_format(p, None) if hasattr(phonenumbers, "format_in_original_format") else str(p),
                "international": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "country_code": p.country_code,
                "region": geocoder.description_for_number(p, "en"),
                "carrier": carrier.name_for_number(p, "en"),
                "type": str(number_type(p)),
            })
        except Exception as e:
            out["parse_error"] = str(e)[:200]
    if apilayer_key:
        r = _get(f"http://apilayer.net/api/validate?access_key={apilayer_key}&number={number}")
        if not isinstance(r, Exception):
            try:
                out["apilayer"] = r.json()
            except Exception:
                out["apilayer"] = {"raw": r.text[:300]}
    else:
        out["apilayer"] = {"skipped": "NUM_API_KEY not set"}
    out["location"] = phone_signals(number)
    return out


# ------------------------------------------------------------------ domain
def domain_search(domain):
    domain = (domain or "").strip().lower().split("/")[0].split(":")[0]
    if not re.match(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', domain):
        return {"input": domain, "error": "invalid domain"}
    out = {"input": domain}
    # crt.sh subdomains (free)
    r = _get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if isinstance(r, Exception):
        out["subdomains"] = {"error": str(r)[:150]}
    else:
        try:
            j = r.json()
            names = sorted({e.get("name_value", "") for e in j if isinstance(e, dict)})
            flat = []
            for n in names:
                flat.extend(x.strip() for x in n.splitlines() if x.strip())
            out["subdomains"] = {"count": len(set(flat)), "sample": sorted(set(flat))[:50]}
        except Exception:
            out["subdomains"] = {"raw_len": len(r.text), "note": "unparseable (rate-limit?)"}
    # DNS via Google DoH
    dns = {}
    for qtype in ("A", "AAAA", "MX", "TXT", "NS"):
        rr = _get(f"https://dns.google/resolve?name={domain}&type={qtype}")
        if isinstance(rr, Exception):
            dns[qtype] = {"error": str(rr)[:100]}
        else:
            try:
                dns[qtype] = [a.get("data") for a in rr.json().get("Answer", [])]
            except Exception:
                dns[qtype] = []
    out["dns"] = dns
    # RDAP (free, no key)
    rd = _get(f"https://rdap.org/domain/{domain}")
    if not isinstance(rd, Exception) and rd.status_code == 200:
        try:
            j = rd.json()
            out["rdap"] = {"registrar": (j.get("entities") or [{}])[0].get("vcardArray", ""),
                           "events": j.get("events", [])[:5], "nameservers": [n.get("ldhName") for n in j.get("nameservers", [])]}
        except Exception:
            out["rdap"] = {"raw_len": len(rd.text)}
    else:
        out["rdap"] = {"error": "unavailable", "http": getattr(rd, "status_code", "err")}
    # urlscan search (free, no key for search)
    us = _get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
    if not isinstance(us, Exception) and us.status_code == 200:
        try:
            j = us.json()
            out["urlscan"] = {"total": j.get("total"), "sample": [x.get("page", {}).get("url") for x in (j.get("results") or [])[:10]]}
        except Exception:
            out["urlscan"] = {"error": "parse"}
    return out


# ------------------------------------------------------------------ ip
def ip_search(ip, abuseipdb_key="", shodan_key="", ipinfo_token=""):
    ip = (ip or "").strip()
    try:
        socket.inet_aton(ip)
    except OSError:
        # try resolve hostname -> ip
        try:
            ip = socket.gethostbyname(ip)
        except Exception:
            return {"input": ip, "error": "invalid IPv4 / unresolvable hostname"}
    out = {"input": ip}
    r = _get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting")
    if not isinstance(r, Exception):
        try:
            out["geo"] = r.json()
        except Exception:
            out["geo"] = {"error": "parse"}
    if abuseipdb_key:
        rr = _get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                  headers={"Key": abuseipdb_key, "Accept": "application/json"})
        if not isinstance(rr, Exception):
            try:
                out["abuseipdb"] = rr.json()
            except Exception:
                out["abuseipdb"] = {"http": rr.status_code}
    if shodan_key:
        rr = _get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}")
        if not isinstance(rr, Exception):
            try:
                out["shodan"] = rr.json() if rr.status_code == 200 else {"http": rr.status_code}
            except Exception:
                out["shodan"] = {"http": rr.status_code}
    if ipinfo_token:
        rr = _get(f"https://ipinfo.io/{ip}/json?token={ipinfo_token}")
        if not isinstance(rr, Exception):
            try:
                out["ipinfo"] = rr.json()
            except Exception:
                pass
    return out


# ------------------------------------------------------------------ person / company / geo
def _github_profile(login):
    r = _get(f"https://api.github.com/users/{login}")
    if isinstance(r, Exception) or r.status_code != 200:
        return None
    try:
        j = r.json()
        return {k: j.get(k) for k in
                ("login", "name", "company", "blog", "location", "email",
                 "bio", "public_repos", "followers", "following",
                 "created_at", "avatar_url", "html_url")}
    except Exception:
        return None


def person_search(name_or_user, profiles=None, include_social=True):
    """Handle or full-name search across public people/social sources.

    ``profiles`` lets the caller pass an existing ``username_search`` result so
    the auto-detect path does not probe the platform matrix twice.
    """
    q = (name_or_user or "").strip().lstrip("@")
    handle_like = bool(SAFE_USER_RE.match(q))
    out = {"input": q,
           "query_type": "handle" if handle_like else "name",
           "github": None, "profiles": None, "verified": None,
           "people": None, "social": None}

    tasks = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        if handle_like:
            tasks["github"] = ex.submit(_github_profile, q)
            if profiles is None:
                tasks["profiles"] = ex.submit(username_search, q)
            tasks["verified"] = ex.submit(verified_accounts, q)
        tasks["people"] = ex.submit(name_registry_search, q)
        if include_social:
            tasks["social"] = ex.submit(discover_social, q)
        for key, fut in tasks.items():
            try:
                out[key] = fut.result()
            except Exception as e:
                out[key] = {"error": str(e)[:150]}

    if profiles is not None:
        out["profiles"] = profiles
    if handle_like and isinstance(out.get("profiles"), dict):
        out["profiles"] = {
            "checked": out["profiles"].get("checked"),
            "platforms": out["profiles"].get("platforms"),
            "hits": out["profiles"].get("hits", []),
            "by_category": out["profiles"].get("by_category", {}),
            "coverage": out["profiles"].get("coverage"),
        }

    people = out.get("people") or {}
    social = out.get("social") or {}
    # Display-name hits from platforms that expose name search. This is what
    # catches "Jane Doe" when her handle is not literally "janedoe".
    out["name_platforms"] = people.get("platforms") or {
        "checked": 0, "hits": [], "by_platform": {}, "platforms": []}
    if handle_like:
        out["coverage"] = (out.get("profiles") or {}).get("coverage") or {
            "mode": "handle", "total_platforms": len(PLATFORMS),
            "checked": 0, "not_checked": len(PLATFORMS)}
    else:
        out["coverage"] = people.get("coverage") or {
            "mode": "name", "total_platforms": len(PLATFORMS),
            "name_searchable": 0, "not_name_searchable": []}
    out["handle_candidates"] = handle_candidates(q)
    out["handle_note"] = ("Suggested public-handle spellings; they are not probed "
                          "unless an operator submits them as a handle query.")
    location_signals = name_signals(people, out["name_platforms"])
    if handle_like and isinstance(out.get("github"), dict) and out["github"].get("location"):
        location_signals.append(_signal(
            "profile_location", out["github"]["location"], "GitHub", "profile",
            "medium", "self-declared GitHub location",
            out["github"].get("html_url") or ""))
    for prof in (out.get("verified") or {}).get("verified") or []:
        if isinstance(prof, dict) and prof.get("location"):
            location_signals.append(_signal(
                "profile_location", prof["location"],
                prof.get("platform") or "public profile", "profile", "medium",
                "self-declared public profile location", prof.get("url") or ""))
    out["location_signals"] = merge_signals(location_signals)
    if not handle_like:
        if people.get("total"):
            out["note"] = ("name matches across %d public indexes; verify identity "
                           "with the social/profile URLs before attributing"
                           % len([k for k, v in (people.get("counts") or {}).items() if v]))
        elif people.get("status") == "error":
            out["note"] = "public people indexes unavailable or rate-limited; try an exact handle/email/phone"
        else:
            out["note"] = "no exact name match in keyless public indexes; try variants, initials or an exact handle"
    if social.get("status") == "blocked":
        out.setdefault("note", ("social web discovery was anti-bot walled; exact handle checks still ran"
                                if handle_like else
                                "social web discovery was anti-bot walled; use an exact handle or profile URL"))
    out["disclaimer"] = ("Public/open sources only. Profile existence and name matches "
                         "are leads, not identity proof. Respect privacy law and source ToS.")
    return out


def social_search(query, include_web=True):
    """Social footprint for a handle or full name (exact profiles + web discovery)."""
    return social_footprint(query, include_web=include_web)


def profile_lookup(url):
    """Public profile metadata scraper (OpenGraph / Twitter card / JSON-LD)."""
    return scrape_profile(url)


def source_catalog():
    """List all configured people/social sources."""
    return sources_catalog()


def _scrape_hit_locations(hits, limit=3):
    signals = []
    for hit in (hits or [])[:limit]:
        url = hit.get("final_url") or hit.get("url") or ""
        if not url:
            continue
        scraped = scrape_profile(url)
        signals.extend(profile_signals(scraped))
    return signals


def location_search(query, include_profiles=True):
    """Public location *signals* for a phone, email, name, handle or domain.

    This is not live tracking. It returns self-declared profile locations,
    coarse number-plan regions, and server/IP geolocation with explicit
    precision labels. Precise or real-time location requires consent (TrackPin)
    or a lawful carrier/emergency request.
    """
    q = (query or "").strip()
    out = {"input": q, "status": "ok", "signals": [], "precision": "none",
           "raw": {},
           "disclaimer": ("Public/self-declared signals only. A phone number, "
                          "email or profile does not provide GPS. Use consent "
                          "or a lawful authority request for precise location.")}
    if not q:
        out.update({"status": "error", "error": "query required"})
        return out
    t = detect_type(q)
    out["detected_type"] = t
    if t == "phone":
        r = phone_signals(q)
        out["signals"] = r.get("signals") or []
        out["raw"]["phone"] = r
        out["disclaimer"] = r.get("disclaimer", out["disclaimer"])
    elif t == "email":
        r = email_signals(q, include_profiles=include_profiles)
        out["signals"] = r.get("signals") or []
        out["raw"]["email"] = r
        out["disclaimer"] = r.get("disclaimer", out["disclaimer"])
    elif t == "ip":
        r = ip_search(q)
        out["signals"] = infrastructure_signals(r)
        out["raw"]["ip"] = r
    elif t == "domain":
        d = domain_search(q)
        out["raw"]["domain"] = d
        ip = None
        try:
            ip = socket.gethostbyname(q.split("/")[0])
        except Exception:
            pass
        if ip:
            r = ip_search(ip)
            out["raw"]["ip"] = r
            out["signals"] = infrastructure_signals(r)
    elif t in ("person", "username"):
        if t == "person":
            people = name_registry_search(q)
            platforms = people.get("platforms") or normalize_people_platforms(people)
            out["raw"]["people"] = people
            out["signals"].extend(name_signals(people, platforms))
            if include_profiles:
                out["signals"].extend(_scrape_hit_locations(platforms.get("hits"), 3))
        else:
            profiles = check_username(q)
            out["raw"]["profiles"] = {
                "checked": profiles.get("checked"),
                "hits": profiles.get("hits", []),
            }
            if include_profiles:
                out["signals"].extend(_scrape_hit_locations(profiles.get("hits"), 3))
            gh = _github_profile(q)
            if isinstance(gh, dict) and gh.get("location"):
                out["signals"].append(_signal(
                    "profile_location", gh["location"], "GitHub", "profile",
                    "medium", "self-declared GitHub location", gh.get("html_url") or ""))
            verified = verified_accounts(q)
            out["raw"]["verified"] = verified.get("sources") or {}
            for prof in verified.get("verified") or []:
                if prof.get("location"):
                    out["signals"].append(_signal(
                        "profile_location", prof["location"],
                        prof.get("platform") or "public profile", "profile",
                        "medium", "self-declared public profile location",
                        prof.get("url") or ""))
    elif t == "company":
        c = company_search(q)
        out["raw"]["company"] = c
        for row in (c.get("results") or [])[:5]:
            if row.get("jurisdiction"):
                out["signals"].append(_signal(
                    "company_jurisdiction", row["jurisdiction"],
                    "OpenCorporates", "organization", "medium",
                    "company registration jurisdiction, not a person's location",
                    row.get("url") or ""))
    else:
        out.update({"status": "empty", "note": "unsupported target type"})
    out["signals"] = merge_signals(out["signals"])
    order = ("exact", "profile", "coarse", "infrastructure", "organization",
             "affiliation", "none")
    precisions = {s.get("precision") for s in out["signals"]}
    out["precision"] = next((p for p in order if p in precisions), "none")
    out["counts"] = {}
    for sig in out["signals"]:
        key = sig.get("precision") or "none"
        out["counts"][key] = out["counts"].get(key, 0) + 1
    if not out["signals"]:
        out["status"] = "empty"
        out.setdefault("note", "no public location signal found")
    return out


def company_search(query):
    r = _get(f"https://api.opencorporates.com/v0.4/companies/search?q={requests.utils.quote(query or '')}")
    if isinstance(r, Exception):
        return {"input": query, "error": str(r)[:150]}
    try:
        j = r.json()
        comps = (j.get("results") or {}).get("companies", [])[:10]
        return {"input": query, "count": len(comps),
                "results": [{"name": c.get("company", {}).get("name"),
                             "jurisdiction": c.get("company", {}).get("jurisdiction_code"),
                             "number": c.get("company", {}).get("company_number"),
                             "url": c.get("company", {}).get("opencorporates_url")} for c in comps]}
    except Exception as e:
        return {"input": query, "error": str(e)[:150]}


def geo_search(place):
    r = _get(f"https://nominatim.openstreetmap.org/search?q={requests.utils.quote(place or '')}&format=json&limit=5",
             headers={"Accept": "application/json"})
    if isinstance(r, Exception):
        return {"input": place, "error": str(r)[:150]}
    try:
        return {"input": place, "results": [
            {"name": x.get("display_name"), "lat": x.get("lat"), "lon": x.get("lon"), "type": x.get("type")}
            for x in r.json()[:5]]}
    except Exception as e:
        return {"input": place, "error": str(e)[:150]}


# ------------------------------------------------------------------ orchestrator
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
PHONE_RE = re.compile(r'^\+?[0-9\s\-().]{7,20}$')
DOMAIN_RE = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', re.I)
COMPANY_RE = re.compile(
    r"\b(ltd|limited|inc|llc|plc|gmbh|ag|sa|sarl|bv|nv|pty|corp|corporation|"
    r"company|co|group|holdings|foundation|university|bank)\b", re.I)


def detect_type(q):
    q = (q or "").strip()
    if EMAIL_RE.match(q):
        return "email"
    if IP_RE.match(q):
        return "ip"
    if PHONE_RE.match(q) and any(c.isdigit() for c in q) and ("+" in q or len(re.sub(r'\D', '', q)) >= 7):
        # prefer phone when it looks like a number, unless clearly a domain/username
        if " " in q or "+" in q or q.replace("-", "").replace(" ", "").replace("(", "").replace(")", "").replace(".", "").isdigit():
            return "phone"
    if DOMAIN_RE.match(q.split("/")[0].split(":")[0]):
        # bare domains that are also valid usernames default to domain when they contain a dot-TLD
        return "domain"
    if " " in q and COMPANY_RE.search(q):
        return "company"
    if " " in q and NAME_RE.fullmatch(q):
        return "person"
    return "username"


def deep_search(query, keys=None):
    keys = keys or {}
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}
    t = detect_type(q)
    out = {"input": q, "detected_type": t, "results": {},
           "disclaimer": "OSINT aggregation only. Verify via primary sources. Use lawfully with authorization."}
    if t == "email":
        out["results"]["email"] = email_search(q, keys.get("HIBP_API_KEY", ""))
    elif t == "ip":
        out["results"]["ip"] = ip_search(q, keys.get("ABUSEIPDB_API_KEY", ""),
                                         keys.get("SHODAN_API_KEY", ""), keys.get("IPINFO_TOKEN", ""))
    elif t == "phone":
        out["results"]["phone"] = phone_search(q, keys.get("NUM_API_KEY", ""))
    elif t == "domain":
        d = domain_search(q)
        out["results"]["domain"] = d
        try:
            ip = socket.gethostbyname(q.split("/")[0])
            out["results"]["resolved_ip"] = ip_search(ip, keys.get("ABUSEIPDB_API_KEY", ""),
                                                      keys.get("SHODAN_API_KEY", ""), keys.get("IPINFO_TOKEN", ""))
        except Exception:
            pass
    elif t == "company":
        out["results"]["company"] = company_search(q)
    elif t == "person":
        out["results"]["person"] = person_search(q)
    else:
        u = username_search(q)
        out["results"]["username"] = u
        out["results"]["person"] = person_search(q, profiles=u)
    return out
