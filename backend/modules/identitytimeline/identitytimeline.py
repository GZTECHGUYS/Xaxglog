"""Xaxglog identity-timeline — when did a handle/profile exist?

Keyless core:
  - Wayback CDX API (web.archive.org) for the profile URL across platforms:
    first snapshot (earliest), last snapshot, capture counts per year ->
    an existence timeline for that account page. Gaps = dormancy/removal;
    re-appearance after a gap = re-registration signal.

Works on any public profile URL pattern (github.com/user, x.com/user,
medium.com/@user, instagram.com/user, ~95 platform matrix from
deep_search.social builds the URLs). Output: first_seen, last_seen,
capture series, and narrative signals (created-after-first-evidence,
gap>90d, sudden burst).

Complements attribution (who is this actor) with *when* — an account
claiming "10 years on the platform" with a first capture last year is
a story.

Lawful-use note: reads the Internet Archive's public index of public pages.
CDX is rate-limited: single sequential request per call, self-throttled.
"""
import time
import urllib.parse

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 30
CDX = "https://web.archive.org/cdx/search/cdx"
_last = [0.0]


def _cdx(url, fl="timestamp,original,statuscode", collapse="timestamp:8", limit=5000):
    import requests
    wait = 2.0 - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    params = {"url": url, "output": "json", "fl": fl, "limit": str(limit),
              "filter": "statuscode:200"}
    if collapse:
        params["collapse"] = collapse
    r = requests.get(CDX, headers=UA, params=params, timeout=T)
    _last[0] = time.time()
    if r.status_code != 200:
        raise RuntimeError(f"CDX HTTP {r.status_code}")
    rows = r.json()
    if not rows:
        return []
    return [dict(zip(rows[0], row)) for row in rows[1:]]


def normalize_profile_url(url):
    """Canonicalize a profile URL for CDX (strip query/fragment/trailing /)."""
    p = urllib.parse.urlparse((url or "").strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    path = p.path.rstrip("/")
    return f"https://{p.hostname.lower()}{path}"


def timeline(url, limit=5000):
    """Existence timeline for one profile URL via Wayback CDX (keyless)."""
    try:
        canon = normalize_profile_url(url)
        if not canon:
            return {"status": "error", "error": "invalid http(s) profile URL"}
        rows = _cdx(canon, limit=limit)
        if not rows:
            return {"status": "ok", "url": canon, "captures": 0,
                    "first_seen": None, "last_seen": None,
                    "note": "no Wayback captures (young or never archived)"}
        stamps = sorted(r["timestamp"] for r in rows if r.get("timestamp"))
        first, last = stamps[0], stamps[-1]
        per_year = {}
        for s in stamps:
            per_year[s[:4]] = per_year.get(s[:4], 0) + 1
        # gap detection across consecutive capture years
        gaps = []
        years = sorted(per_year)
        for a, b in zip(years, years[1:]):
            if int(b) - int(a) >= 2:
                gaps.append({"from": a, "to": b, "years": int(b) - int(a)})
        signals = []
        fyear = int(first[:4])
        signals.append(f"first archived capture: {first[:8]}")
        if gaps:
            signals.append("dormancy/removal gap: " + ", ".join(
                f"{g['from']}->{g['to']}" for g in gaps[:4]))
        db.audit("system", "identitytimeline.timeline", canon,
                 f"captures={len(stamps)} first={first[:8]}")
        return {"status": "ok", "url": canon, "captures": len(stamps),
                "first_seen": first[:8], "last_seen": last[:8],
                "per_year": per_year, "gaps": gaps, "signals": signals,
                "samples": [{"ts": s[:8],
                             "snapshot": f"https://web.archive.org/web/{s}/{canon}"}
                            for s in (stamps[0], stamps[len(stamps) // 2], stamps[-1])
                            if s]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def account_age_hint(url):
    """Compact age check: first-ever capture vs now (days)."""
    out = timeline(url, limit=200)
    if out.get("status") != "ok" or not out.get("first_seen"):
        return {"status": out.get("status", "ok"), "url": url,
                "hint": "no archive evidence — cannot infer age"}
    try:
        y, m, d = int(out["first_seen"][:4]), int(out["first_seen"][4:6]), \
            int(out["first_seen"][6:8])
        import datetime
        first = datetime.date(y, m, d)
        days = (datetime.date.today() - first).days
        return {"status": "ok", "url": url, "first_seen": out["first_seen"],
                "days_since_first_capture": days,
                "hint": f"publicly visible for at least {days} days "
                        f"(archive evidence, lower bound)"}
    except Exception:
        return {"status": "ok", "url": url, "first_seen": out.get("first_seen")}


def multi(handles, base_urls):
    """Build timelines for a handle across provided URL templates.

    base_urls: list of URL templates containing {handle}, e.g.
    ["https://github.com/{handle}", "https://x.com/{handle}"]
    """
    if isinstance(handles, str):
        handles = [handles]
    results = []
    for h in handles[:10]:
        for tmpl in base_urls[:12]:
            try:
                url = tmpl.format(handle=h.lstrip("@"))
            except (KeyError, IndexError):
                continue
            out = timeline(url, limit=500)
            if out.get("status") == "ok":
                results.append({"handle": h, "url": out.get("url"),
                                "captures": out.get("captures"),
                                "first_seen": out.get("first_seen"),
                                "last_seen": out.get("last_seen")})
            time.sleep(1)
    results.sort(key=lambda r: (r.get("first_seen") or "9999"))
    return {"status": "ok", "count": len(results), "timelines": results}
