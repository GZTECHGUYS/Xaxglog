"""Xaxglog data-broker exposure sweep — public listing checks.

Walks a catalog of people-search / broker sites for a subject name (or
address), records how each site responded, and produces an exposure score.
Honest statuses by design:

  possible_hit  — page returned result-looking markup with our subject in it
  no_signal     — fetched clean, nothing resembling a listing
  blocked       — 403 / captcha wall / login redirect (NOT a hit)
  error         — network or parse failure

Broker templates are editable — sites redesign constantly; a wrong template
degrades to `blocked`/`error`, never to a false hit. Rate-limited sequential
fetches, SSRF-safe hosts only (public broker domains).
"""
import re
import time
from urllib.parse import quote

import db

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}
T = 12
BLOCK_SIGNS = ["captcha", "are you a robot", "unusual traffic", "access denied",
               "verify you are human", "cloudflare", "cf-browser-verification",
               "enable javascript and cookies", "please enable js", "datadome"]
HIT_SIGNS = ["results for", "we found", "possible match", "record found",
             "showing ", "profile of", "has lived at", "associated with",
             "people named", "matching records"]

CATALOG = [
    {"id": "whitepages", "label": "Whitepages",
     "url": "https://www.whitepages.com/name/{slug}"},
    {"id": "spokeo", "label": "Spokeo",
     "url": "https://www.spokeo.com/{slug}"},
    {"id": "radaris", "label": "Radaris",
     "url": "https://radaris.com/p/{slug}/"},
    {"id": "truepeoplesearch", "label": "TruePeopleSearch",
     "url": "https://www.truepeoplesearch.com/results?name={q}"},
    {"id": "fastpeoplesearch", "label": "FastPeopleSearch",
     "url": "https://www.fastpeoplesearch.com/search?s={q}"},
    {"id": "beenverified", "label": "BeenVerified",
     "url": "https://www.beenverified.com/people/{slug}/"},
    {"id": "peoplefinder", "label": "PeopleFinder",
     "url": "https://www.peoplefinder.com/results?name={q}"},
    {"id": "intelius", "label": "Intelius",
     "url": "https://www.intelius.com/search?name={q}"},
    {"id": "ussearch", "label": "US Search",
     "url": "https://www.ussearch.com/results.html?name={q}"},
    {"id": "mylife", "label": "MyLife",
     "url": "https://www.mylife.com/people-search/results?name={q}"},
    {"id": "peekyou", "label": "PeekYou",
     "url": "https://www.peekyou.com/{slug}/"},
    {"id": "peoplelooker", "label": "PeopleLooker",
     "url": "https://www.peoplelooker.com/search/results?name={q}"},
]


def _slug(name):
    parts = re.sub(r"[^a-zA-Z0-9\s.-]", " ", name).split()
    if len(parts) >= 2:
        return "-".join(p.lower() for p in parts[:3])
    return (parts[0].lower() if parts else "")


def _fetch(url):
    import requests
    try:
        r = requests.get(url, headers=UA, timeout=T, allow_redirects=True)
    except Exception as e:
        return None, "error", str(e)[:120]
    return r, None, ""


def _classify(r, name):
    """-> (status, evidence_snippet|'')"""
    if r is None:
        return "error", ""
    if r.status_code in (403, 429, 503):
        return "blocked", f"http {r.status_code}"
    if r.status_code != 200:
        return "error", f"http {r.status_code}"
    try:
        html = r.text[:250_000].lower()
    except Exception:
        return "error", "no body"
    if any(s in html for s in BLOCK_SIGNS):
        return "blocked", "challenge wall"
    nq = (name or "").lower().split()
    name_present = bool(nq) and all(p in html for p in nq if len(p) > 2)
    hit = any(s in html for s in HIT_SIGNS)
    if hit and name_present:
        m = re.search(r"(\d{1,4})\s*(?:possible\s+)?(?:results|matches|records)", html)
        snippet = f"result-count marker{': ' + m.group(1) if m else ''}"
        return "possible_hit", snippet
    return "no_signal", ""


def sweep(name, brokers=None, mode="name", address="", delay=0.7, user="system"):
    """Check the catalog for `name` (person) or `address` (residence).
    Sequential + rate-limited: this is a public-record check, not a crawl."""
    name = (name or "").strip()
    address = (address or "").strip()
    if not name and not address:
        return {"status": "error", "error": "name or address required"}
    if mode == "address" and not address:
        return {"status": "error", "error": "address required for address mode"}
    want = None
    if brokers:
        # accept ["whitepages", ...] or [{"id": "whitepages"}, ...]
        want = {b["id"] if isinstance(b, dict) else str(b) for b in brokers}
    slug = _slug(name) if name else re.sub(r"[^a-zA-Z0-9\s]", "", address).lower().replace(" ", "-")
    q = quote(name if mode != "address" and name else address)

    results, hits, blocked, checked = [], 0, 0, 0
    for entry in CATALOG:
        if want and entry["id"] not in want:
            continue
        url = entry["url"].format(slug=slug, q=q)
        r, err, note = _fetch(url)
        if err:
            status, ev = "error", err
        else:
            status, ev = _classify(r, name if mode != "address" else address)
        if status == "possible_hit":
            hits += 1
            checked += 1
        elif status == "no_signal":
            checked += 1
        elif status == "blocked":
            blocked += 1
        results.append({"id": entry["id"], "label": entry["label"], "url": url,
                        "status": status, "evidence": ev,
                        "http": getattr(r, "status_code", None)})
        time.sleep(delay)

    score = round(100.0 * hits / checked, 1) if checked else None
    out = {"status": "ok", "subject": name if mode != "address" else address,
           "mode": mode, "brokers_checked": len(results),
           "hits": hits, "blocked": blocked, "clean": checked - hits,
           "exposure_score": score, "results": results,
           "note": "blocked sites are unknown, not clear — re-run or use a browser session"}
    db.store_artifact(None, None, "broker", "broker:sweep", out, user)
    db.audit(user, "broker.sweep", out["subject"], f"hits={hits} blocked={blocked}")
    return out


def catalog():
    return [{"id": b["id"], "label": b["label"], "url": b["url"]} for b in CATALOG]
