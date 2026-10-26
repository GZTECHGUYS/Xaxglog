"""Xaxglog adwatch — political/astroturf ad transparency trail.

Keyless core:
  - Ad-library *deep links*: builds ready-to-open URLs for the Meta Ad
    Library (facebook.com/ads/library) filtered by country/keyword/adtype
    and Google Ads Transparency Center — the analyst (or browserrender)
    opens them; we do not scrape behind login walls.
  - Wayback snapshot history of a given Ad Library URL (keyless CDX) —
    gives first-seen/last-seen of an ad page and its change over time.
  - GDELT ad-tech / political-advertising news trail (keyless, throttled)
    for narrative context.

Optional (env META_ACCESS_TOKEN — Meta Graph API for Ad Library, available
for political/issue ads with approved access): structured pulls by
search_terms + ad_reached_countries + fields (page_name, spend range,
impressions, beneficiary/payer).

Output: ad intelligence records + custody artifacts; pairs with coordcheck
for coordination analysis across creatives.

Lawful-use note: political ad transparency data published by the platforms
themselves. Ads are public by design; respect platform ToS and country
political-advertising laws when reusing.
"""
import datetime
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
GDELT = "https://api.gdeltproject.org/api/v2/doc/doc"
_gdelt_last = 0.0
COUNTRIES = {"US": "US", "GB": "GB", "DE": "DE", "FR": "FR", "BR": "BR",
             "IN": "IN", "CA": "CA", "AU": "AU", "EU": "ALL", "ZZ": "ALL"}


def meta_link(keyword, country="US", ad_type="all", page=None):
    """Build a Meta Ad Library deep link (analyst opens it)."""
    try:
        cc = COUNTRIES.get((country or "US").upper(), "US")
        params = {"q": keyword or "", "country": cc, "ad_type": ad_type,
                  "active_status": "all", "media_type": "all"}
        if page:
            params["view_all_page_id"] = page
        url = "https://www.facebook.com/ads/library/?" + urllib.parse.urlencode(params)
        return {"status": "ok", "meta_library": url, "country": cc,
                "keyword": keyword,
                "note": "open in browser (or browserrender module)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def google_link(keyword, country="US"):
    """Google Ads Transparency Center deep link."""
    try:
        url = ("https://adstransparency.google.com/?region="
               + (country or "US").upper() + "&q=" + urllib.parse.quote(keyword or ""))
        return {"status": "ok", "google_transparency": url, "keyword": keyword}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def meta_api(search_terms, country="US", limit=25, ad_delivery_date_min=None):
    """Structured Meta Ad Library pull (needs META_ACCESS_TOKEN)."""
    import os
    token = os.getenv("META_ACCESS_TOKEN")
    if not token:
        return {"status": "unconfigured",
                "error": "META_ACCESS_TOKEN required (Meta Graph API "
                         "Ad Library access, political/issue ads)",
                "keyless_hint": "use meta_link() deep links instead"}
    try:
        import requests
        fields = ("id,page_name,ad_delivery_start_time,ad_delivery_stop_time,"
                  "ad_creative_bodies,ad_creative_link_titles,publisher_platforms,"
                  "impressions,spend,currency,eu_total_reach,demographic_distribution")
        params = {"search_terms": search_terms,
                  "ad_reached_countries": '["' + COUNTRIES.get(
                      (country or "US").upper(), "US") + '"]',
                  "limit": min(int(limit), 100), "fields": fields,
                  "access_token": token}
        if ad_delivery_date_min:
            params["ad_delivery_date_min"] = ad_delivery_date_min
        r = requests.get("https://graph.facebook.com/v19.0/ads_archive",
                         params=params, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"Graph API HTTP {r.status_code}"}
        rows = r.json().get("data") or []
        ads = [{
            "id": a.get("id"), "page": a.get("page_name"),
            "started": a.get("ad_delivery_start_time"),
            "stopped": a.get("ad_delivery_stop_time"),
            "body": (a.get("ad_creative_bodies") or [None])[0],
            "title": (a.get("ad_creative_link_titles") or [None])[0],
            "platforms": a.get("publisher_platforms"),
            "spend": a.get("spend"), "impressions": a.get("impressions"),
            "currency": a.get("currency"),
        } for a in rows]
        db.audit("system", "adwatch.meta_api", search_terms, f"n={len(ads)}")
        if ads:
            db.store_artifact(None, None, "adwatch", "meta_ad_library",
                              {"terms": search_terms, "ads": ads[:50]}, "adwatch")
        return {"status": "ok", "count": len(ads), "ads": ads}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "ads": []}


def ad_page_history(ad_library_url, limit=500):
    """Wayback history of an ad-library page URL (first/last seen + captures)."""
    try:
        import requests
        r = requests.get("https://web.archive.org/cdx/search/cdx",
                         headers=UA,
                         params={"url": ad_library_url, "output": "json",
                                 "fl": "timestamp,statuscode", "limit": str(limit),
                                 "collapse": "timestamp:8"}, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"CDX HTTP {r.status_code}"}
        rows = r.json()
        stamps = [row[0] for row in rows[1:]] if len(rows) > 1 else []
        return {"status": "ok", "url": ad_library_url,
                "captures": len(stamps),
                "first_seen": stamps[0][:8] if stamps else None,
                "last_seen": stamps[-1][:8] if stamps else None,
                "samples": [f"https://web.archive.org/web/{s}/{ad_library_url}"
                            for s in (stamps[:1] + stamps[-1:]) if s]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def ad_news(query, timespan="3month"):
    """Political/advertising news context via GDELT (keyless, throttled)."""
    try:
        global _gdelt_last
        import requests
        wait = 5.0 - (datetime.datetime.utcnow().timestamp() - _gdelt_last) \
            if _gdelt_last else 0
        if wait > 0:
            import time
            time.sleep(wait)
        params = {"query": f'"{query}" (advertising OR "ad campaign" OR disinformation)',
                  "mode": "artlist", "maxrecords": "30",
                  "timespan": timespan, "format": "json"}
        r = requests.get(GDELT + "?" + urllib.parse.urlencode(params),
                         headers=UA, timeout=T)
        _gdelt_last = datetime.datetime.utcnow().timestamp()
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
        return {"status": "ok", "count": len(arts), "articles": arts}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "articles": []}


def bundle(keyword, country="US"):
    """One-call bundle: deep links + news context (keyless path)."""
    out = {"status": "ok", "keyword": keyword}
    out.update(meta_link(keyword, country=country))
    g = google_link(keyword, country=country)
    out["google_transparency"] = g.get("google_transparency")
    news = ad_news(keyword)
    out["news"] = news.get("articles", [])[:10]
    return out
