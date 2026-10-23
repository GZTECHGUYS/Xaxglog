"""Xaxglog deep_search — social & people connectors.

Adds the missing "search for a person" layer on top of the username/email/
phone/domain connectors in :mod:`connectors`:

  * expanded public profile matrix (~75 platforms, grouped by category/region)
  * exact handle verification on API-backed networks (Bluesky/Mastodon/Keybase)
  * free-form name search across public people indexes (Wikidata, Wikipedia,
    GitHub, OpenAlex, Semantic Scholar, ORCID, OpenLibrary, Bluesky, Mastodon,
    GDELT news mentions)
  * social-web discovery via the keyless searchx engines
  * public profile scraper: OpenGraph / Twitter-card / schema.org metadata
    from a single public profile URL (no login, no JS, no auth bypass)

Lawful use
----------
Public pages and public APIs only. No login walls, no credential attacks, no
captcha solving, no private data. Missing profiles, anti-bot walls and rate
limits degrade to a status field instead of raising. Respect each source's
Terms of Service and applicable privacy law.
"""
import html as _html
import ipaddress
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (+research use; contact admin)"}
T = 12                       # public API timeout
PROFILE_T = 8                # per-platform profile probe timeout
MAX_PROBE = 64 * 1024        # read at most 64 KiB per profile probe
MAX_HTML = 512 * 1024        # profile scraper cap
MAX_REDIRECTS = 4

SAFE_USER_RE = re.compile(r'^[A-Za-z0-9_.\-]{2,39}$')
NAME_RE = re.compile(r"^[^\W\d_][\w'’.\-]*(?:\s+[^\W\d_][\w'’.\-]*){0,7}$", re.UNICODE)

# (name, url template, category, region)
# Categories: social, code, professional, creative, video, music, gaming,
#             shopping, academic, lifestyle, regional
PLATFORMS = [
    # --- social / microblogging -------------------------------------------
    ("X/Twitter", "https://x.com/{u}", "social", "global"),
    ("Instagram", "https://www.instagram.com/{u}/", "social", "global"),
    ("Facebook", "https://www.facebook.com/{u}", "social", "global"),
    ("Threads", "https://www.threads.net/@{u}", "social", "global"),
    ("Bluesky", "https://bsky.app/profile/{u}", "social", "global"),
    ("Mastodon", "https://mastodon.social/@{u}", "social", "global"),
    ("TikTok", "https://www.tiktok.com/@{u}", "social", "global"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "social", "global"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "social", "global"),
    ("Tumblr", "https://{u}.tumblr.com", "social", "global"),
    ("Reddit", "https://www.reddit.com/user/{u}/", "social", "global"),
    ("Quora", "https://www.quora.com/profile/{u}", "social", "global"),
    ("Medium", "https://medium.com/@{u}", "social", "global"),
    ("Substack", "https://{u}.substack.com", "social", "global"),
    ("About.me", "https://about.me/{u}", "social", "global"),
    ("Linktree", "https://linktr.ee/{u}", "social", "global"),
    ("Gravatar", "https://gravatar.com/{u}", "social", "global"),
    ("Keybase", "https://keybase.io/{u}", "social", "global"),
    ("Telegram", "https://t.me/{u}", "social", "global"),
    ("Gab", "https://gab.com/{u}", "social", "global"),
    ("Gettr", "https://gettr.com/user/{u}", "social", "global"),
    ("Truth Social", "https://truthsocial.com/@{u}", "social", "global"),
    ("VK", "https://vk.com/{u}", "regional", "RU"),
    ("OK.ru", "https://ok.ru/{u}", "regional", "RU"),
    ("Weibo", "https://weibo.com/{u}", "regional", "CN"),
    ("Douyin", "https://www.douyin.com/user/{u}", "regional", "CN"),
    ("Zhihu", "https://www.zhihu.com/people/{u}", "regional", "CN"),
    ("Douban", "https://www.douban.com/people/{u}/", "regional", "CN"),
    ("Bilibili", "https://space.bilibili.com/{u}", "regional", "CN"),
    # --- professional ------------------------------------------------------
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "professional", "global"),
    ("Fiverr", "https://www.fiverr.com/{u}", "professional", "global"),
    ("Freelancer", "https://www.freelancer.com/u/{u}", "professional", "global"),
    ("Trello", "https://trello.com/{u}", "professional", "global"),
    ("Notion", "https://{u}.notion.site", "professional", "global"),
    # --- code / developer --------------------------------------------------
    ("GitHub", "https://github.com/{u}", "code", "global"),
    ("GitLab", "https://gitlab.com/{u}", "code", "global"),
    ("Codeberg", "https://codeberg.org/{u}", "code", "global"),
    ("SourceHut", "https://git.sr.ht/~{u}", "code", "global"),
    ("DockerHub", "https://hub.docker.com/u/{u}", "code", "global"),
    ("NPM", "https://www.npmjs.com/~{u}", "code", "global"),
    ("PyPI", "https://pypi.org/user/{u}/", "code", "global"),
    ("Crates.io", "https://crates.io/users/{u}", "code", "global"),
    ("HuggingFace", "https://huggingface.co/{u}", "code", "global"),
    ("Replit", "https://replit.com/@{u}", "code", "global"),
    ("Codepen", "https://codepen.io/{u}", "code", "global"),
    ("Kaggle", "https://www.kaggle.com/{u}", "code", "global"),
    ("Dev.to", "https://dev.to/{u}", "code", "global"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "code", "global"),
    ("LeetCode", "https://leetcode.com/{u}", "code", "global"),
    ("HackerOne", "https://hackerone.com/{u}", "code", "global"),
    ("Bugcrowd", "https://bugcrowd.com/{u}", "code", "global"),
    ("TryHackMe", "https://tryhackme.com/p/{u}", "code", "global"),
    ("Exercism", "https://exercism.org/profiles/{u}", "code", "global"),
    ("FreeCodeCamp", "https://www.freecodecamp.org/{u}", "code", "global"),
    # --- creative / publishing --------------------------------------------
    ("Behance", "https://www.behance.net/{u}", "creative", "global"),
    ("Dribbble", "https://dribbble.com/{u}", "creative", "global"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "creative", "global"),
    ("500px", "https://500px.com/{u}", "creative", "global"),
    ("ArtStation", "https://www.artstation.com/{u}", "creative", "global"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "creative", "global"),
    ("Unsplash", "https://unsplash.com/@{u}", "creative", "global"),
    ("VSCO", "https://vsco.co/{u}/gallery", "creative", "global"),
    ("Wattpad", "https://www.wattpad.com/user/{u}", "creative", "global"),
    ("AO3", "https://archiveofourown.org/users/{u}/profile", "creative", "global"),
    ("WordPress", "https://{u}.wordpress.com", "creative", "global"),
    ("Blogger", "https://{u}.blogspot.com", "creative", "global"),
    # --- video / streaming -------------------------------------------------
    ("YouTube", "https://www.youtube.com/@{u}", "video", "global"),
    ("Vimeo", "https://vimeo.com/{u}", "video", "global"),
    ("Dailymotion", "https://www.dailymotion.com/{u}", "video", "global"),
    ("Twitch", "https://www.twitch.tv/{u}", "video", "global"),
    ("Rumble", "https://rumble.com/user/{u}", "video", "global"),
    ("Odysee", "https://odysee.com/@{u}", "video", "global"),
    # --- music -------------------------------------------------------------
    ("Spotify", "https://open.spotify.com/user/{u}", "music", "global"),
    ("SoundCloud", "https://soundcloud.com/{u}", "music", "global"),
    ("Last.fm", "https://www.last.fm/user/{u}", "music", "global"),
    ("Bandcamp", "https://bandcamp.com/{u}", "music", "global"),
    # --- gaming ------------------------------------------------------------
    ("Steam", "https://steamcommunity.com/id/{u}", "gaming", "global"),
    ("Xbox", "https://www.xbox.com/en-US/play/user/{u}", "gaming", "global"),
    ("Roblox", "https://www.roblox.com/users/profile?username={u}", "gaming", "global"),
    # --- shopping / support ------------------------------------------------
    ("Patreon", "https://www.patreon.com/{u}", "shopping", "global"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{u}", "shopping", "global"),
    ("Ko-fi", "https://ko-fi.com/{u}", "shopping", "global"),
    ("Gumroad", "https://{u}.gumroad.com", "shopping", "global"),
    ("Etsy", "https://www.etsy.com/shop/{u}", "shopping", "global"),
    ("eBay", "https://www.ebay.com/usr/{u}", "shopping", "global"),
    # --- academic / reading ------------------------------------------------
    ("ResearchGate", "https://www.researchgate.net/profile/{u}", "academic", "global"),
    ("Academia.edu", "https://independent.academia.edu/{u}", "academic", "global"),
    ("Goodreads", "https://www.goodreads.com/user/show/{u}", "academic", "global"),
    ("Letterboxd", "https://letterboxd.com/{u}/", "academic", "global"),
    # --- lifestyle ---------------------------------------------------------
    ("Duolingo", "https://www.duolingo.com/profile/{u}", "lifestyle", "global"),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{u}", "lifestyle", "global"),
    ("Untappd", "https://untappd.com/user/{u}", "lifestyle", "global"),
    ("Ravelry", "https://www.ravelry.com/people/{u}", "lifestyle", "global"),
]

PLATFORM_META = {name: {"category": cat, "region": region}
                 for name, _tmpl, cat, region in PLATFORMS}

# Platform detection for scraped URLs / search results.
SOCIAL_HOSTS = {
    "x.com": "X/Twitter", "twitter.com": "X/Twitter",
    "instagram.com": "Instagram", "facebook.com": "Facebook",
    "threads.net": "Threads", "bsky.app": "Bluesky",
    "mastodon.social": "Mastodon", "tiktok.com": "TikTok",
    "snapchat.com": "Snapchat", "pinterest.com": "Pinterest",
    "tumblr.com": "Tumblr", "reddit.com": "Reddit",
    "quora.com": "Quora", "medium.com": "Medium",
    "substack.com": "Substack", "about.me": "About.me",
    "linktr.ee": "Linktree", "gravatar.com": "Gravatar",
    "keybase.io": "Keybase", "t.me": "Telegram", "telegram.me": "Telegram",
    "gab.com": "Gab", "gettr.com": "Gettr", "truthsocial.com": "Truth Social",
    "vk.com": "VK", "ok.ru": "OK.ru", "weibo.com": "Weibo",
    "douyin.com": "Douyin", "zhihu.com": "Zhihu", "douban.com": "Douban",
    "bilibili.com": "Bilibili", "linkedin.com": "LinkedIn",
    "fiverr.com": "Fiverr", "freelancer.com": "Freelancer",
    "trello.com": "Trello", "notion.site": "Notion",
    "github.com": "GitHub", "gitlab.com": "GitLab", "codeberg.org": "Codeberg",
    "hub.docker.com": "DockerHub", "npmjs.com": "NPM", "pypi.org": "PyPI",
    "crates.io": "Crates.io", "huggingface.co": "HuggingFace",
    "kaggle.com": "Kaggle", "dev.to": "Dev.to",
    "news.ycombinator.com": "HackerNews", "replit.com": "Replit",
    "codepen.io": "Codepen", "leetcode.com": "LeetCode",
    "hackerone.com": "HackerOne", "bugcrowd.com": "Bugcrowd",
    "tryhackme.com": "TryHackMe", "exercism.org": "Exercism",
    "freecodecamp.org": "FreeCodeCamp",
    "youtube.com": "YouTube", "youtu.be": "YouTube", "vimeo.com": "Vimeo",
    "dailymotion.com": "Dailymotion", "twitch.tv": "Twitch",
    "rumble.com": "Rumble", "odysee.com": "Odysee",
    "spotify.com": "Spotify", "soundcloud.com": "SoundCloud",
    "last.fm": "Last.fm", "bandcamp.com": "Bandcamp",
    "steamcommunity.com": "Steam", "roblox.com": "Roblox",
    "patreon.com": "Patreon", "buymeacoffee.com": "BuyMeACoffee",
    "ko-fi.com": "Ko-fi", "gumroad.com": "Gumroad",
    "etsy.com": "Etsy", "ebay.com": "eBay",
    "behance.net": "Behance", "dribbble.com": "Dribbble",
    "flickr.com": "Flickr", "500px.com": "500px",
    "artstation.com": "ArtStation", "deviantart.com": "DeviantArt",
    "unsplash.com": "Unsplash", "vsco.co": "VSCO",
    "wattpad.com": "Wattpad", "archiveofourown.org": "AO3",
    "duolingo.com": "Duolingo", "letterboxd.com": "Letterboxd",
    "goodreads.com": "Goodreads", "researchgate.net": "ResearchGate",
}

# Prefixes used to spot anti-bot / login walls and missing-profile pages.
_BLOCK_MARKERS = (
    "captcha", "unusual traffic", "verifying your browser", "are you a robot",
    "just a moment", "cf-chl", "challenge-platform", "access denied",
    "request blocked", "client challenge", "enable javascript and cookies",
    "checking your browser", "log in to continue", "sign in to continue",
)
_MISSING_MARKERS = (
    "page not found", "profile not found", "user not found",
    "account not found", "this account doesn't exist",
    "this account does not exist", "this page isn't available",
    "this page is not available", "this page doesn't exist",
    "sorry, this page isn't available", "no such user",
    "couldn't find that page", "couldn't find this account",
)


# ------------------------------------------------------------------ helpers
def _get(url, **kw):
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _clean(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def _match_score(query, candidate):
    """Token-overlap score (0..1) used to rank homonyms."""
    q = {t for t in re.split(r"[^\w]+", (query or "").lower()) if len(t) > 1}
    c = {t for t in re.split(r"[^\w]+", (candidate or "").lower()) if len(t) > 1}
    if not q:
        return 0.0
    return round(len(q & c) / len(q), 3)


def _platform_for_host(host):
    host = (host or "").lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    for h, name in SOCIAL_HOSTS.items():
        if host == h or host.endswith("." + h):
            return name
    return ""


def platform_for_url(url):
    try:
        return _platform_for_host(urllib.parse.urlsplit(url or "").hostname or "")
    except Exception:
        return ""


def _safe_platform_template(tmpl, username):
    """Only expand templates whose placeholders are hostname/label safe."""
    return tmpl.format(u=urllib.parse.quote(username, safe=""))


def _probe(url):
    """Probe a public profile URL with a bounded body read.

    Returns (status_code, final_url, body_head, error).
    """
    try:
        r = requests.get(url, headers=UA, timeout=PROFILE_T, allow_redirects=True,
                         stream=True)
    except Exception as e:
        return None, url, "", str(e)[:120]
    try:
        chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_PROBE:
                break
        raw = b"".join(chunks)[:MAX_PROBE]
        enc = r.encoding or "utf-8"
        try:
            body = raw.decode(enc, "replace")
        except Exception:
            body = raw.decode("utf-8", "replace")
        return r.status_code, getattr(r, "url", url) or url, body, ""
    except Exception as e:
        return r.status_code, getattr(r, "url", url) or url, "", str(e)[:120]
    finally:
        try:
            r.close()
        except Exception:
            pass


def _probe_one(name, tmpl, username):
    url = _safe_platform_template(tmpl, username)
    status, final_url, body, err = _probe(url)
    meta = PLATFORM_META.get(name, {})
    rec = {"platform": name, "url": url, "final_url": final_url,
           "category": meta.get("category", "other"),
           "region": meta.get("region", "global"),
           "status": status, "exists": None}
    if err:
        rec["detail"] = err
        rec["status"] = "error"
        return rec
    if status == 404 or status == 410:
        rec["exists"] = False
        return rec
    head = (body or "")[:64000].lower()
    if any(m in head for m in _BLOCK_MARKERS):
        rec["status"] = "blocked"
        rec["detail"] = "anti-bot / login wall"
        return rec
    if any(m in head for m in _MISSING_MARKERS):
        rec["exists"] = False
        rec["detail"] = "missing-profile marker"
        return rec
    lowered_final = (final_url or "").lower()
    if any(x in lowered_final for x in ("/signup", "/sign-up", "/login", "/auth")):
        rec["exists"] = False
        rec["detail"] = "redirected to signup/login"
        return rec
    if 200 <= status < 300:
        # A bare 200 is not proof: JS shells and parked pages return 200 for
        # every handle. Require the handle to appear in the rendered HTML.
        if username.lower() not in head:
            rec["status"] = "unverified"
            rec["detail"] = "handle not present in public HTML"
            return rec
        rec["exists"] = True
        rec["confidence"] = "high" if rec["category"] in ("code", "professional") else "medium"
    return rec


# ------------------------------------------------------------------ handles
def check_username(username, categories=None, max_workers=20):
    """Check a handle across the public platform matrix.

    ``categories`` optionally limits the scan, e.g. ``["social", "regional"]``.
    Returns hits, a per-category breakdown and the full probe list.
    """
    username = (username or "").strip().lstrip("@")
    if not SAFE_USER_RE.match(username):
        return {"input": username, "error": "invalid username (2-39 chars, a-z 0-9 _ . -)",
                "hits": [], "all": [], "by_category": {}, "checked": 0,
                "platforms": len(PLATFORMS)}
    wanted = set(categories) if categories else None
    targets = [(n, t) for n, t, cat, _r in PLATFORMS
               if wanted is None or cat in wanted]
    results = []
    with ThreadPoolExecutor(max_workers=max(4, min(max_workers, len(targets) or 1))) as ex:
        futs = {ex.submit(_probe_one, n, t, username): n for n, t in targets}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"platform": futs[f], "exists": None,
                                "status": "error", "error": str(e)[:120]})
    hits = [r for r in results if r.get("exists")]
    by_cat = {}
    for h in hits:
        by_cat.setdefault(h.get("category", "other"), []).append(h)
    return {
        "input": username,
        "checked": len(results),
        "platforms": len(PLATFORMS),
        "hits": sorted(hits, key=lambda x: (x.get("category", ""), x["platform"])),
        "by_category": {k: sorted(v, key=lambda x: x["platform"])
                        for k, v in sorted(by_cat.items())},
        "all": sorted(results, key=lambda x: x["platform"]),
    }


def verified_accounts(handle):
    """Exact handle verification on API-backed networks (keyless)."""
    handle = (handle or "").strip().lstrip("@")
    out = {"input": handle, "sources": {}}
    if not SAFE_USER_RE.match(handle):
        out["error"] = "invalid handle"
        return out
    jobs = {
        "bluesky": _verify_bluesky,
        "mastodon": _verify_mastodon,
        "keybase": _verify_keybase,
    }
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {ex.submit(fn, handle): name for name, fn in jobs.items()}
        for f in as_completed(futs):
            name = futs[f]
            try:
                out["sources"][name] = f.result()
            except Exception as e:
                out["sources"][name] = {"status": "error", "error": str(e)[:120]}
    out["verified"] = [v.get("profile") for v in out["sources"].values()
                       if v.get("found") and v.get("profile")]
    if not out["verified"]:
        out.pop("verified")
    out["note"] = "Exact handle matches on API-backed networks; not identity proof."
    return out


def _verify_bluesky(handle):
    r = _get("https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors",
             params={"q": handle, "limit": 25})
    if isinstance(r, Exception):
        return {"status": "error", "error": str(r)[:120]}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code}
    try:
        actors = (r.json() or {}).get("actors") or []
    except Exception:
        return {"status": "error", "error": "unparseable"}
    for a in actors:
        h = (a.get("handle") or "").lower()
        if h == handle.lower() or h.split(".")[0] == handle.lower():
            return {"status": "ok", "found": True, "profile": {
                "platform": "Bluesky", "handle": a.get("handle"),
                "name": a.get("displayName") or "", "bio": a.get("description") or "",
                "avatar": a.get("avatar") or "",
                "url": "https://bsky.app/profile/" + (a.get("handle") or ""),
            }}
    return {"status": "ok", "found": False}


def _verify_mastodon(handle):
    r = _get("https://mastodon.social/api/v1/accounts/lookup", params={"acct": handle})
    if isinstance(r, Exception):
        return {"status": "error", "error": str(r)[:120]}
    if r.status_code == 404:
        return {"status": "ok", "found": False}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code}
    try:
        a = r.json() or {}
    except Exception:
        return {"status": "error", "error": "unparseable"}
    return {"status": "ok", "found": True, "profile": {
        "platform": "Mastodon", "handle": a.get("acct") or handle,
        "name": a.get("display_name") or a.get("username") or "",
        "bio": _clean(a.get("note") or ""),
        "avatar": a.get("avatar") or "",
        "followers": a.get("followers_count"),
        "url": a.get("url") or ("https://mastodon.social/@" + handle),
    }}


def _verify_keybase(handle):
    r = _get("https://keybase.io/_/api/1.0/user/lookup.json", params={"username": handle})
    if isinstance(r, Exception):
        return {"status": "error", "error": str(r)[:120]}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code}
    try:
        j = r.json() or {}
    except Exception:
        return {"status": "error", "error": "unparseable"}
    if (j.get("status") or {}).get("code") != 0 or not j.get("them"):
        return {"status": "ok", "found": False}
    them = j.get("them") or {}
    basics = them.get("basics") or {}
    profile = them.get("profile") or {}
    return {"status": "ok", "found": True, "profile": {
        "platform": "Keybase", "handle": basics.get("username") or handle,
        "name": profile.get("full_name") or "",
        "bio": profile.get("bio") or "",
        "location": profile.get("location") or "",
        "url": "https://keybase.io/" + (basics.get("username") or handle),
    }}


# ------------------------------------------------------------------ people indexes
def _people_wikidata(name):
    r = _get("https://www.wikidata.org/w/api.php", params={
        "action": "wbsearchentities", "search": name, "language": "en",
        "uselang": "en", "type": "item", "limit": 12, "format": "json"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    search = (r.json() or {}).get("search") or []
    ids = [x.get("id") for x in search if (x.get("id") or "").startswith("Q")]
    if not ids:
        return []
    r2 = _get("https://www.wikidata.org/w/api.php", params={
        "action": "wbgetentities", "ids": "|".join(ids[:15]),
        "props": "claims|labels|descriptions", "languages": "en", "format": "json"})
    if isinstance(r2, Exception):
        raise RuntimeError(str(r2)[:120])
    if r2.status_code != 200:
        raise RuntimeError("http %s" % r2.status_code)
    entities = (r2.json() or {}).get("entities") or {}
    out = []
    for qid in ids:
        e = entities.get(qid) or {}
        claims = e.get("claims") or {}
        p31 = [c.get("mainsnak", {}).get("datavalue", {}).get("value", {}).get("id")
               for c in claims.get("P31") or []]
        if "Q5" not in p31:
            continue
        label = ((e.get("labels") or {}).get("en") or {}).get("value") or ""
        desc = ((e.get("descriptions") or {}).get("en") or {}).get("value") or ""
        rec = {"id": qid, "name": label, "description": desc,
               "url": "https://www.wikidata.org/wiki/" + qid,
               "match": _match_score(name, label)}
        dob = _claim_time(claims, "P569")
        if dob:
            rec["born"] = dob
        country = _claim_ids(claims, "P27")
        if country:
            rec["citizenship_qids"] = country
        occ = _claim_ids(claims, "P106")
        if occ:
            rec["occupation_qids"] = occ
        img = _claim_string(claims, "P18")
        if img:
            rec["image"] = ("https://commons.wikimedia.org/wiki/Special:FilePath/"
                            + urllib.parse.quote(img.replace(" ", "_")))
        out.append(rec)
    return out[:10]


def _claim_ids(claims, prop):
    vals = []
    for c in claims.get(prop) or []:
        v = c.get("mainsnak", {}).get("datavalue", {}).get("value") or {}
        if isinstance(v, dict) and v.get("id"):
            vals.append(v["id"])
    return vals


def _claim_string(claims, prop):
    for c in claims.get(prop) or []:
        v = c.get("mainsnak", {}).get("datavalue", {}).get("value")
        if isinstance(v, str):
            return v
    return ""


def _claim_time(claims, prop):
    for c in claims.get(prop) or []:
        v = c.get("mainsnak", {}).get("datavalue", {}).get("value") or {}
        t = v.get("time") if isinstance(v, dict) else None
        if t:
            return t.lstrip("+").split("T")[0].replace("-00-00", "")
    return ""


def _people_wikipedia(name):
    r = _get("https://en.wikipedia.org/w/api.php", params={
        "action": "query", "list": "search", "srsearch": '"%s"' % name,
        "srlimit": 8, "srprop": "snippet", "format": "json"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    hits = ((r.json() or {}).get("query") or {}).get("search") or []
    return [{"title": h.get("title", ""),
             "url": "https://en.wikipedia.org/wiki/" +
                    urllib.parse.quote((h.get("title") or "").replace(" ", "_")),
             "snippet": _clean(h.get("snippet", "")),
             "match": _match_score(name, h.get("title", ""))}
            for h in hits[:8]]


def _people_github(name):
    r = _get("https://api.github.com/search/users",
             params={"q": 'fullname:"%s"' % name, "per_page": 8},
             headers={"Accept": "application/vnd.github+json"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code == 403:
        raise RuntimeError("rate limited")
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    items = (r.json() or {}).get("items") or []
    return [{"login": x.get("login"), "url": x.get("html_url"),
             "avatar": x.get("avatar_url"), "score": x.get("score"),
             "match": 1.0 if name.lower() in (x.get("login") or "").lower() else 0.5}
            for x in items[:8]]


def _people_openalex(name):
    r = _get("https://api.openalex.org/authors",
             params={"search": name, "per_page": 8})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    rows = (r.json() or {}).get("results") or []
    out = []
    for a in rows:
        inst = a.get("last_known_institutions") or []
        rec = {"id": a.get("id"), "name": a.get("display_name"),
               "orcid": a.get("orcid"), "works": a.get("works_count"),
               "citations": a.get("cited_by_count"),
               "institutions": [i.get("display_name") for i in inst if i.get("display_name")],
               "url": a.get("id"),
               "match": _match_score(name, a.get("display_name", ""))}
        out.append(rec)
    return out[:8]


def _people_semanticscholar(name):
    r = _get("https://api.semanticscholar.org/graph/v1/author/search",
             params={"query": name, "limit": 8,
                     "fields": "name,affiliations,paperCount,hIndex,url"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code == 429:
        raise RuntimeError("rate limited")
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    rows = (r.json() or {}).get("data") or []
    return [{"id": a.get("authorId"), "name": a.get("name"),
             "affiliations": a.get("affiliations") or [],
             "papers": a.get("paperCount"), "h_index": a.get("hIndex"),
             "url": a.get("url"),
             "match": _match_score(name, a.get("name", ""))}
            for a in rows[:8]]


def _people_orcid(name):
    parts = name.split()
    if len(parts) < 2:
        return []
    given, family = parts[0], parts[-1]
    q = "given-names:%s AND family-name:%s" % (given, family)
    r = _get("https://pub.orcid.org/v3.0/expanded-search/",
             params={"q": q, "rows": 8},
             headers={"Accept": "application/json"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    rows = (r.json() or {}).get("expanded-result") or []
    out = []
    for a in rows:
        oid = a.get("orcid-id")
        out.append({"orcid": oid,
                    "name": a.get("credit-name") or
                            " ".join(x for x in [a.get("given-names"), a.get("family-names")] if x),
                    "institutions": a.get("institution-name") or [],
                    "url": "https://orcid.org/" + oid if oid else "",
                    "match": _match_score(name, a.get("credit-name") or "")})
    return out[:8]


def _people_openlibrary(name):
    r = _get("https://openlibrary.org/search/authors.json",
             params={"q": name, "limit": 8})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    rows = (r.json() or {}).get("docs") or []
    return [{"key": a.get("key"), "name": a.get("name"),
             "birth_date": a.get("birth_date"), "death_date": a.get("death_date"),
             "top_subjects": (a.get("top_subjects") or [])[:5],
             "url": "https://openlibrary.org/authors/" + a.get("key", ""),
             "match": _match_score(name, a.get("name", ""))}
            for a in rows[:8]]


def _people_bluesky(name):
    r = _get("https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors",
             params={"q": name, "limit": 10})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    actors = (r.json() or {}).get("actors") or []
    out = []
    for a in actors:
        dn = a.get("displayName") or ""
        out.append({"handle": a.get("handle"), "name": dn,
                    "bio": a.get("description") or "",
                    "avatar": a.get("avatar") or "",
                    "url": "https://bsky.app/profile/" + (a.get("handle") or ""),
                    "match": _match_score(name, dn + " " + (a.get("handle") or ""))})
    return sorted(out, key=lambda x: -x["match"])[:10]


def _people_mastodon(name):
    r = _get("https://mastodon.social/api/v2/search",
             params={"q": name, "type": "accounts", "limit": 8, "resolve": "false"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    accounts = (r.json() or {}).get("accounts") or []
    out = []
    for a in accounts:
        dn = a.get("display_name") or a.get("username") or ""
        out.append({"acct": a.get("acct"), "name": dn,
                    "bio": _clean(a.get("note") or ""),
                    "followers": a.get("followers_count"),
                    "url": a.get("url"),
                    "match": _match_score(name, dn + " " + (a.get("acct") or ""))})
    return sorted(out, key=lambda x: -x["match"])[:8]


def _people_gdelt(name):
    r = _get("https://api.gdeltproject.org/api/v2/doc/doc", params={
        "query": '"%s"' % name, "mode": "artlist", "maxrecords": 8,
        "format": "json", "timespan": "2y", "sort": "datedesc"})
    if isinstance(r, Exception):
        raise RuntimeError(str(r)[:120])
    if r.status_code != 200:
        raise RuntimeError("http %s" % r.status_code)
    try:
        rows = (r.json() or {}).get("articles") or []
    except Exception:
        return []
    return [{"title": a.get("title"), "url": a.get("url"),
             "domain": a.get("domain"), "seen": a.get("seendate"),
             "language": a.get("language"), "country": a.get("sourcecountry"),
             "match": _match_score(name, a.get("title", ""))}
            for a in rows[:8]]


PEOPLE_SOURCES = {
    "wikidata": _people_wikidata,
    "wikipedia": _people_wikipedia,
    "github": _people_github,
    "openalex": _people_openalex,
    "semantic_scholar": _people_semanticscholar,
    "orcid": _people_orcid,
    "openlibrary": _people_openlibrary,
    "bluesky": _people_bluesky,
    "mastodon": _people_mastodon,
    "gdelt": _people_gdelt,
}


def name_registry_search(name):
    """Search public people indexes for a free-form full name."""
    name = re.sub(r"\s+", " ", (name or "").strip())
    out = {"input": name, "sources": {}, "counts": {}, "errors": {},
           "status": "ok"}
    if not NAME_RE.fullmatch(name) or len(name) < 2:
        return {"input": name, "status": "error",
                "error": "invalid name (2-120 chars, letters/spaces/'/-/.)",
                "sources": {}, "counts": {}, "errors": {}}
    with ThreadPoolExecutor(max_workers=len(PEOPLE_SOURCES)) as ex:
        futs = {ex.submit(fn, name): key for key, fn in PEOPLE_SOURCES.items()}
        for f in as_completed(futs):
            key = futs[f]
            try:
                rows = f.result() or []
                rows.sort(key=lambda x: -float(x.get("match") or 0))
                out["sources"][key] = rows
                out["counts"][key] = len(rows)
            except Exception as e:
                out["sources"][key] = []
                out["counts"][key] = 0
                out["errors"][key] = str(e)[:150]
    out["total"] = sum(out["counts"].values())
    if out["total"] == 0:
        out["status"] = "empty" if not out["errors"] else "error"
    elif len(out["errors"]) > len(PEOPLE_SOURCES) // 2:
        out["status"] = "partial"
    return out


# ------------------------------------------------------------------ social web discovery
SOCIAL_DORK_SITES = (
    "linkedin.com/in", "facebook.com", "instagram.com", "x.com", "twitter.com",
    "tiktok.com", "github.com", "reddit.com", "about.me", "linktr.ee",
    "medium.com", "t.me", "vk.com", "weibo.com", "threads.net", "bsky.app",
    "mastodon.social",
)


def discover_social(query, engines=None):
    """Run a constrained social-site search via the keyless searchx engines."""
    query = (query or "").strip()
    out = {"query": query, "engines": {}, "results": [], "platforms": {},
           "status": "ok"}
    if not query:
        return {"query": "", "status": "error", "error": "empty query",
                "engines": {}, "results": [], "platforms": {}}
    site_expr = " OR ".join("site:" + s for s in SOCIAL_DORK_SITES)
    dork = '"%s" (%s)' % (query.replace('"', ""), site_expr)
    out["dork"] = dork
    try:
        from modules.searchx import searchx as SEARCHX
    except Exception:
        try:
            from ..searchx import searchx as SEARCHX
        except Exception as e:
            out["status"] = "error"
            out["error"] = "searchx unavailable: %s" % str(e)[:120]
            return out
    fed = SEARCHX.federated(dork, engines=engines or ["ddg", "searx", "mojeek"])
    out["engines"] = fed.get("engines") or {}
    rows = []
    for item in fed.get("results") or []:
        url = item.get("url") or ""
        platform = platform_for_url(url)
        rec = dict(item)
        rec["platform"] = platform
        rec["is_social"] = bool(platform)
        if platform:
            out["platforms"][platform] = out["platforms"].get(platform, 0) + 1
        rows.append(rec)
    rows.sort(key=lambda r: (0 if r.get("is_social") else 1, -(len(r.get("engines") or []))))
    out["results"] = rows
    out["total"] = len(rows)
    eng = out["engines"]
    if out["total"]:
        out["status"] = "ok"
    elif eng and all(v == "blocked" for v in eng.values()):
        out["status"] = "blocked"
        out["note"] = "all search engines anti-bot walled; use exact handle checks or a profile URL"
    elif eng and any(v == "ok" for v in eng.values()):
        out["status"] = "empty"
    else:
        out["status"] = "error"
    return out


def social_footprint(query, include_web=True):
    """Standalone social footprint for a handle *or* a free-form name."""
    q = (query or "").strip().lstrip("@")
    if not q:
        return {"input": "", "status": "error", "error": "empty query"}
    if SAFE_USER_RE.match(q):
        out = {"input": q, "query_type": "handle", "status": "ok"}
        profiles = check_username(q)
        out["profiles"] = {"checked": profiles.get("checked"),
                           "platforms": profiles.get("platforms"),
                           "hits": profiles.get("hits", []),
                           "by_category": profiles.get("by_category", {})}
        out["verified"] = verified_accounts(q)
    else:
        out = {"input": q, "query_type": "name", "status": "ok"}
        people = name_registry_search(q)
        out["people"] = people
        out["status"] = people.get("status", "ok")
    if include_web:
        out["web"] = discover_social(q)
    return out


# ------------------------------------------------------------------ profile scraper
def _validate_public_url(url):
    """Reject non-http(s), credentials, localhost and non-global IP targets."""
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return False, "unparseable URL"
    if p.scheme not in ("http", "https"):
        return False, "only http/https URLs are supported"
    if not p.hostname:
        return False, "missing hostname"
    if p.username or p.password:
        return False, "URL credentials are not allowed"
    host = p.hostname.lower().rstrip(".")
    if host in ("localhost", "localhost.localdomain") or host.endswith((".local", ".internal", ".home")):
        return False, "private hostname blocked"
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as e:
        return False, "DNS resolution failed: %s" % str(e)[:80]
    if not infos:
        return False, "DNS resolution returned no addresses"
    for info in infos:
        addr = str(info[4][0]).split("%")[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False, "non-IP resolution result"
        if not ip.is_global:
            return False, "private/reserved address blocked (%s)" % addr
    return True, ""


def _meta_tags(page):
    tags = {}
    for m in re.finditer(r"<meta\b[^>]*>", page or "", re.I):
        raw = m.group(0)
        attrs = {}
        for am in re.finditer(r"""([\w:-]+)\s*=\s*["']([^"']*)["']""", raw):
            attrs[am.group(1).lower()] = _html.unescape(am.group(2))
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key and attrs.get("content"):
            tags.setdefault(key, attrs["content"])
    return tags


def _parse_profile_html(page, base_url):
    meta = _meta_tags(page)
    title_m = re.search(r"<title[^>]*>(.*?)</title>", page or "", re.S | re.I)
    title = _clean(title_m.group(1)) if title_m else ""
    canonical = ""
    for m in re.finditer(r"<link\b[^>]*>", page or "", re.I):
        raw = m.group(0)
        if re.search(r"""\brel\s*=\s*["']canonical["']""", raw, re.I):
            hm = re.search(r"""\bhref\s*=\s*["']([^"']+)["']""", raw, re.I)
            if hm:
                canonical = _html.unescape(hm.group(1))
                break
    jsonld = []
    for m in re.finditer(r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                         page or "", re.S | re.I):
        try:
            obj = json.loads(m.group(1).strip())
        except Exception:
            continue
        for item in (obj if isinstance(obj, list) else [obj]):
            if not isinstance(item, dict):
                continue
            typ = item.get("@type")
            types = typ if isinstance(typ, list) else [typ]
            if any(str(t).lower() in ("person", "profilepage") for t in types if t):
                jsonld.append({k: item.get(k) for k in
                               ("@type", "name", "alternateName", "description",
                                "image", "sameAs", "jobTitle", "worksFor",
                                "address", "alumniOf", "url")
                               if item.get(k) is not None})
    links, social_links = [], []
    seen = set()
    try:
        page_host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
        if page_host.startswith("www."):
            page_host = page_host[4:]
    except Exception:
        page_host = ""
    for m in re.finditer(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
                         page or "", re.S | re.I):
        href = _html.unescape(m.group(1)).strip()
        if not href or href.startswith(("#", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        try:
            p = urllib.parse.urlsplit(absolute)
        except Exception:
            continue
        if p.scheme not in ("http", "https"):
            continue
        key = p.scheme + "://" + p.netloc.lower() + p.path.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        rec = {"url": absolute, "text": _clean(m.group(2))[:120],
               "platform": platform_for_url(absolute)}
        if len(links) < 80:
            links.append(rec)
        host = (p.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        if rec["platform"] and host != page_host and rec not in social_links:
            social_links.append(rec)
    return {
        "title": title,
        "description": meta.get("description") or meta.get("og:description") or "",
        "og": {k: v for k, v in meta.items() if k.startswith("og:")},
        "twitter": {k: v for k, v in meta.items() if k.startswith("twitter:")},
        "canonical": urllib.parse.urljoin(base_url, canonical) if canonical else "",
        "jsonld": jsonld,
        "links": links,
        "social_links": social_links[:40],
        "name": (meta.get("og:title") or title or
                 ((jsonld[0].get("name") if jsonld else "") or "")),
    }


def scrape_profile(url):
    """Scrape public OpenGraph/Twitter/schema.org metadata from one profile URL.

    No login, no JS execution, no authenticated content. The URL (and every
    redirect hop) must resolve to a public, globally-routable IP address.
    """
    url = (url or "").strip()
    if not url:
        return {"status": "error", "error": "url required"}
    if "://" not in url:
        url = "https://" + url
    current = url
    r = None
    for hop in range(MAX_REDIRECTS + 1):
        ok, why = _validate_public_url(current)
        if not ok:
            return {"status": "error", "error": why, "url": current}
        try:
            r = requests.get(current, headers={**UA, "Accept": "text/html,application/xhtml+xml"},
                             timeout=T, allow_redirects=False, stream=True)
        except Exception as e:
            return {"status": "error", "error": str(e)[:150], "url": current}
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location") or ""
            r.close()
            if not loc:
                return {"status": "error", "error": "redirect without Location", "url": current}
            current = urllib.parse.urljoin(current, loc)
            continue
        break
    else:
        return {"status": "error", "error": "too many redirects", "url": current}
    try:
        ctype = (r.headers.get("Content-Type") or "").lower()
        if ctype and "html" not in ctype and "xhtml" not in ctype:
            return {"status": "error", "error": "not an HTML page (%s)" % ctype,
                    "url": current, "final_url": getattr(r, "url", current)}
        chunks, total = [], 0
        for chunk in r.iter_content(chunk_size=16384):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_HTML:
                break
        raw = b"".join(chunks)[:MAX_HTML]
        enc = r.encoding or "utf-8"
        try:
            page = raw.decode(enc, "replace")
        except Exception:
            page = raw.decode("utf-8", "replace")
        final_url = getattr(r, "url", current) or current
    finally:
        try:
            r.close()
        except Exception:
            pass
    parsed = _parse_profile_html(page, final_url)
    return {
        "status": "ok",
        "url": url,
        "final_url": final_url,
        "platform": platform_for_url(final_url),
        "fetched_bytes": len(page.encode("utf-8", "replace")),
        **parsed,
    }


# ------------------------------------------------------------------ catalog
def sources_catalog():
    """Describe every configured source for the UI / ops dashboards."""
    by_cat, by_region = {}, {}
    for name, _tmpl, cat, region in PLATFORMS:
        by_cat[cat] = by_cat.get(cat, 0) + 1
        by_region[region] = by_region.get(region, 0) + 1
    return {
        "profile_platforms": len(PLATFORMS),
        "by_category": by_cat,
        "by_region": by_region,
        "platforms": [{"name": n, "url": t, "category": c, "region": r}
                      for n, t, c, r in PLATFORMS],
        "people_registries": sorted(PEOPLE_SOURCES.keys()),
        "people_indexes": len(PEOPLE_SOURCES),
        "social_discovery_engines": ["ddg", "searx", "mojeek"],
        "profile_scraper": {
            "extracts": ["title", "og", "twitter", "jsonld", "links",
                         "social_links", "canonical"],
            "limits": {"max_html_bytes": MAX_HTML, "redirects": MAX_REDIRECTS,
                       "public_ip_only": True, "no_login": True},
        },
    }
