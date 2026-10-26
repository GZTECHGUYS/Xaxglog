"""Public location signals for emails, phones, names and infrastructure.

This module is deliberately *not* a live-location tracker. It collects only
self-declared or coarse public signals:

  phone  -> country/region/carrier/timezone from the number plan
  email  -> public Gravatar location, plus optional public profile metadata
  name   -> self-declared location on public profiles / affiliations
  domain -> server geolocation (never the person's location)

Precise, real-time location requires explicit consent (see TrackPin) or a
lawful carrier/emergency request. No SS7, silent SMS, call interception or
device exploitation is implemented here.
"""
import hashlib
import re

from . import social

UA = social.UA


def _signal(kind, value, source, precision, confidence, note="", url="", **extra):
    rec = {
        "type": kind,
        "value": value,
        "source": source,
        "precision": precision,
        "confidence": confidence,
        "note": note,
    }
    if url:
        rec["url"] = url
    rec.update({k: v for k, v in extra.items() if v is not None})
    return rec


def phone_signals(number):
    """Coarse number-plan location: region, carrier, timezone."""
    number = (number or "").strip()
    out = {"input": number, "status": "ok", "precision": "coarse",
           "signals": [], "disclaimer":
           "A phone number can reveal country/region and carrier, not GPS. "
           "Precise location requires consent or a lawful carrier request."}
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, number_type, timezone
    except Exception:
        out["status"] = "error"
        out["error"] = "phonenumbers library not installed"
        return out
    try:
        p = phonenumbers.parse(number, None)
    except Exception as e:
        out["status"] = "error"
        out["error"] = str(e)[:150]
        return out
    if not phonenumbers.is_valid_number(p):
        out["status"] = "partial"
        out["note"] = "number is not valid for its country plan"
    region = geocoder.description_for_number(p, "en") or ""
    carrier_name = carrier.name_for_number(p, "en") or ""
    zones = list(timezone.time_zones_for_number(p) or [])
    line_type = str(number_type(p))
    if region:
        out["signals"].append(_signal(
            "phone_region", region, "libphonenumber geocoder", "coarse",
            "high", "country/region inferred from the number plan"))
    if carrier_name:
        out["signals"].append(_signal(
            "carrier", carrier_name, "libphonenumber carrier", "coarse",
            "medium", "carrier at number allocation time; may have ported"))
    for zone in zones[:2]:
        out["signals"].append(_signal(
            "timezone", zone, "libphonenumber timezone", "coarse",
            "medium", "timezone associated with the number plan"))
    out["signals"].append(_signal(
        "line_type", line_type, "libphonenumber", "coarse", "high"))
    out["parsed"] = {
        "country_code": p.country_code,
        "national_number": str(p.national_number),
        "e164": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "region": region,
        "iso_region": phonenumbers.region_code_for_number(p),
        "carrier": carrier_name,
        "timezones": zones,
        "line_type": line_type,
    }
    return out


def _gravatar_payload(email, gravatar=None):
    if isinstance(gravatar, dict):
        if gravatar.get("entry"):
            return gravatar
        if gravatar.get("exists") is False or gravatar.get("error"):
            return None
    h = hashlib.md5((email or "").strip().lower().encode()).hexdigest()
    r = social._get("https://www.gravatar.com/%s.json" % h)
    if isinstance(r, Exception) or r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None


def email_signals(email, gravatar=None, include_profiles=False):
    """Self-declared/public location hints for an email address."""
    email = (email or "").strip().lower()
    out = {"input": email, "status": "ok", "precision": "profile",
           "signals": [], "handle_candidates": [],
           "disclaimer":
           "Email addresses do not contain GPS. These are public/self-declared "
           "hints; verify before attributing a location to a person."}
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        out["status"] = "error"
        out["error"] = "invalid email format"
        return out
    domain = email.split("@", 1)[1]
    local = email.split("@", 1)[0].split("+", 1)[0]
    payload = _gravatar_payload(email, gravatar)
    if payload:
        entry = (payload.get("entry") or [{}])[0] or {}
        location = entry.get("currentLocation") or ""
        if location:
            out["signals"].append(_signal(
                "profile_location", location, "Gravatar", "profile", "medium",
                "self-declared Gravatar location", entry.get("profileUrl") or ""))
        if entry.get("profileUrl"):
            out["signals"].append(_signal(
                "public_profile", entry.get("profileUrl"), "Gravatar", "profile",
                "high", "public Gravatar profile", entry.get("profileUrl")))
        about = entry.get("aboutMe") or ""
        if about:
            out["signals"].append(_signal(
                "profile_bio", social._clean(about)[:300], "Gravatar", "profile",
                "low", "self-declared biography"))
        for acct in (entry.get("accounts") or [])[:10]:
            short = acct.get("shortname") or acct.get("username") or ""
            url = acct.get("url") or ""
            if short or url:
                out["signals"].append(_signal(
                    "linked_account", short or url, "Gravatar", "profile",
                    "medium", "account linked from the public Gravatar profile", url))
    else:
        out["signals"].append(_signal(
            "gravatar", "no public profile", "Gravatar", "none", "high",
            "no public Gravatar record for this address"))

    common = {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com",
              "hotmail.com", "live.com", "icloud.com", "me.com", "proton.me",
              "protonmail.com", "aol.com", "gmx.net", "web.de", "mail.ru"}
    if domain not in common:
        out["signals"].append(_signal(
            "email_domain", domain, "email address", "organization", "low",
            "organization/domain affiliation, not a personal location"))
    for cand in (local, local.replace(".", ""), local.replace(".", "_"),
                 local.replace("_", ".")):
        if cand and 2 <= len(cand) <= 39 and cand not in out["handle_candidates"]:
            out["handle_candidates"].append(cand)
    out["handle_candidates"] = out["handle_candidates"][:3]

    if include_profiles and out["handle_candidates"]:
        # Public profile matrix only; no login or private data.
        try:
            hits = social.check_username(
                out["handle_candidates"][0],
                categories=("social", "professional", "code"))
            out["profile_hits"] = hits.get("hits", [])[:12]
            for hit in out["profile_hits"][:3]:
                url = hit.get("final_url") or hit.get("url")
                if not url:
                    continue
                scraped = social.scrape_profile(url)
                if scraped.get("status") == "ok":
                    out["signals"].extend(profile_signals(scraped))
        except Exception as e:
            out["profile_error"] = str(e)[:150]
    return out


def profile_signals(scraped):
    """Extract location only from public profile metadata already fetched."""
    signals = []
    if not isinstance(scraped, dict) or scraped.get("status") != "ok":
        return signals
    url = scraped.get("final_url") or scraped.get("url") or ""
    meta = {}
    meta.update(scraped.get("og") or {})
    meta.update(scraped.get("twitter") or {})
    for key in ("og:locality", "og:region", "og:country-name",
                "place:location:latitude", "place:location:longitude",
                "geo:position", "icbm"):
        if scraped.get(key):
            meta[key] = scraped[key]
    for item in scraped.get("jsonld") or []:
        if not isinstance(item, dict):
            continue
        addr = item.get("address")
        if isinstance(addr, dict):
            text = ", ".join(str(addr.get(k)) for k in
                             ("streetAddress", "addressLocality", "addressRegion",
                              "postalCode", "addressCountry") if addr.get(k))
            if text:
                signals.append(_signal(
                    "profile_address", text, "JSON-LD on public profile",
                    "profile", "medium", "self-declared public profile address", url))
        elif isinstance(addr, str) and addr.strip():
            signals.append(_signal(
                "profile_address", addr.strip(), "JSON-LD on public profile",
                "profile", "medium", "self-declared public profile address", url))
        if item.get("worksFor"):
            work = item.get("worksFor")
            if isinstance(work, dict):
                work = work.get("name") or ""
            if work:
                signals.append(_signal(
                    "affiliation", str(work), "JSON-LD on public profile",
                    "affiliation", "low", "employer/affiliation, not location", url))
    for key, label in (("og:locality", "locality"), ("og:region", "region"),
                       ("og:country-name", "country")):
        if meta.get(key):
            signals.append(_signal(
                "profile_" + label, meta[key], "OpenGraph on public profile",
                "profile", "medium", "self-declared public profile location", url))
    lat = meta.get("place:location:latitude") or meta.get("og:latitude")
    lon = meta.get("place:location:longitude") or meta.get("og:longitude")
    if lat and lon:
        signals.append(_signal(
            "profile_coordinates", "%s,%s" % (lat, lon),
            "OpenGraph on public profile", "profile", "medium",
            "coordinates published on the public profile", url,
            lat=lat, lon=lon))
    if scraped.get("name"):
        signals.append(_signal(
            "profile_name", scraped.get("name"), "public profile metadata",
            "profile", "high", "display name, not a location", url))
    return signals


def name_signals(people, platform_hits=None):
    """Self-declared locations/affiliations from public name-search rows."""
    signals = []
    seen = set()
    for src, rows in ((people or {}).get("sources") or {}).items():
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            loc = row.get("location") or ""
            if loc:
                key = ("loc", loc.lower())
                if key not in seen:
                    seen.add(key)
                    signals.append(_signal(
                        "profile_location", loc, src,
                        "profile", "medium",
                        "self-declared location on a public profile",
                        row.get("url") or ""))
            affiliations = row.get("institutions") or row.get("affiliations") or []
            for aff in affiliations[:3]:
                if isinstance(aff, dict):
                    aff = aff.get("name") or ""
                if aff:
                    key = ("aff", str(aff).lower())
                    if key not in seen:
                        seen.add(key)
                        signals.append(_signal(
                            "affiliation", str(aff), src, "affiliation", "low",
                            "institution/employer, not a personal location",
                            row.get("url") or ""))
    for hit in (platform_hits or {}).get("hits") or []:
        loc = hit.get("location") or ""
        if loc:
            key = ("loc", loc.lower())
            if key not in seen:
                seen.add(key)
                signals.append(_signal(
                    "profile_location", loc, hit.get("platform") or "public profile",
                    "profile", "medium",
                    "self-declared location on a public profile",
                    hit.get("url") or ""))
    return signals


def infrastructure_signals(ip_result):
    """Server/IP geolocation — explicitly not a person's location."""
    signals = []
    geo = (ip_result or {}).get("geo") or {}
    if not isinstance(geo, dict):
        return signals
    city = geo.get("city") or ""
    region = geo.get("regionName") or ""
    country = geo.get("country") or ""
    text = ", ".join(x for x in (city, region, country) if x)
    if text:
        signals.append(_signal(
            "ip_location", text, "ip-api", "infrastructure", "medium",
            "server/IP geolocation, not the user's location"))
    if geo.get("lat") is not None and geo.get("lon") is not None:
        signals.append(_signal(
            "ip_coordinates", "%s,%s" % (geo.get("lat"), geo.get("lon")),
            "ip-api", "infrastructure", "medium",
            "server/IP coordinates, not the user's location",
            lat=geo.get("lat"), lon=geo.get("lon")))
    if geo.get("isp") or geo.get("org"):
        signals.append(_signal(
            "network", geo.get("isp") or geo.get("org"), "ip-api",
            "infrastructure", "medium", "ISP/organization for the IP"))
    return signals


def merge_signals(*groups):
    """Flatten signal groups and remove exact duplicates."""
    out, seen = [], set()
    for group in groups:
        if isinstance(group, dict):
            group = group.get("signals") or []
        for sig in group or []:
            if not isinstance(sig, dict):
                continue
            key = (sig.get("type"), str(sig.get("value")).lower(),
                   sig.get("source"))
            if key in seen:
                continue
            seen.add(key)
            out.append(sig)
    return out
