"""Xaxglog imgreverse — public reverse-image lookup.

Builds ready-to-open reverse-image search links for many public engines and
runs the keyless APIs that are available. It does not bypass logins, captchas
or rate limits, and it deliberately excludes face-search/biometric engines
(PimEyes, FaceCheck.ID and similar).

Engines
-------
Link-out (no result scraping):
  Google Lens, Bing Visual Search, Yandex Images, TinEye, SauceNAO, IQDB,
  ascii2d, Baidu image search, Sogou image search, Karma Decay, Trace.moe.

Keyless API:
  Trace.moe — anime/scene matching via https://api.trace.moe/search

Optional keyed APIs (only if the operator configured a key):
  SauceNAO, TinEye, Google Vision.

Lawful use
----------
Reverse-search links hit the provider's public pages; respect their ToS and
rate limits. A hit is a lead for provenance review, not proof of ownership or
identity. No face recognition or biometric identification is performed.
"""
import os
import urllib.parse

import requests

import db
from modules.deep_search import social as SOCIAL
from modules.imgverify import imgverify as IV

T = 20
UA = {"User-Agent": "Xaxglog-OSINT/2.0 (+public-source research)"}

ENGINES = [
    {"id": "google_lens", "label": "Google Lens", "mode": "link",
     "region": "global",
     "url": "https://lens.google.com/uploadbyurl?url={url}",
     "note": "open the link; Google may ask you to confirm the image"},
    {"id": "bing_visual", "label": "Bing Visual Search", "mode": "link",
     "region": "global",
     "url": ("https://www.bing.com/images/search?view=detailv2&iss=sbi"
             "&form=SBIVSP&q=imgurl:{url}"),
     "note": "open the link; Bing may require an upload for some images"},
    {"id": "yandex", "label": "Yandex Images", "mode": "link",
     "region": "global",
     "url": "https://yandex.com/images/search?rpt=imageview&url={url}",
     "note": "often strong for faces/places; use only for lawful provenance checks"},
    {"id": "tineye", "label": "TinEye", "mode": "link",
     "region": "global", "url": "https://tineye.com/search?url={url}",
     "note": "exact/near-duplicate web matches"},
    {"id": "saucenao", "label": "SauceNAO", "mode": "link",
     "region": "global", "url": "https://saucenao.com/search.php?url={url}",
     "note": "anime/art source matching"},
    {"id": "iqdb", "label": "IQDB", "mode": "link",
     "region": "global", "url": "https://iqdb.org/?url={url}",
     "note": "anime/image-board source matching"},
    {"id": "ascii2d", "label": "ascii2d", "mode": "link",
     "region": "JP", "url": "https://ascii2d.net/search/url/{url}",
     "note": "Japanese image-board source matching"},
    {"id": "baidu", "label": "Baidu Image Search", "mode": "link",
     "region": "CN",
     "url": "https://graph.baidu.com/details?isfromtusoupc=1&tn=pc&carousel=0&image={url}",
     "note": "may require uploading the image manually"},
    {"id": "sogou", "label": "Sogou Image Search", "mode": "link",
     "region": "CN", "url": "https://pic.sogou.com/pic/upload_pic.jsp?pic_url={url}",
     "note": "may require uploading the image manually"},
    {"id": "karma_decay", "label": "Karma Decay", "mode": "link",
     "region": "global", "url": "http://karmadecay.com/search?q={url}",
     "note": "Reddit image repost search"},
    {"id": "trace_moe", "label": "Trace.moe", "mode": "link+api",
     "region": "global", "url": "https://trace.moe/?url={url}",
     "api": "https://api.trace.moe/search",
     "note": "keyless anime scene matching"},
    {"id": "saucenao_api", "label": "SauceNAO API", "mode": "api",
     "region": "global", "key_env": ("XAXGLOG_SAUCENAO_KEY", "SAUCENAO_API_KEY"),
     "url": "https://saucenao.com/search.php?output_type=2&url={url}",
     "note": "optional key; keyless users can use the SauceNAO link"},
    {"id": "tineye_api", "label": "TinEye API", "mode": "api",
     "region": "global", "key_env": ("XAXGLOG_TINEYE_KEY", "TINEYE_API_KEY"),
     "url": "https://api.tineye.com/rest/search/",
     "note": "optional key; link-out is available without a key"},
    {"id": "google_vision", "label": "Google Vision", "mode": "api",
     "region": "global",
     "key_env": ("XAXGLOG_GOOGLE_VISION_KEY", "GOOGLE_VISION_API_KEY"),
     "url": "https://vision.googleapis.com/v1/images:annotate",
     "note": "optional key; web-detection labels, not a reverse-search result"},
]


def catalog():
    """Describe engines, modes and optional key requirements."""
    return {
        "engines": len(ENGINES),
        "link_engines": sum(1 for e in ENGINES if "link" in e["mode"]),
        "api_engines": sum(1 for e in ENGINES if "api" in e["mode"]),
        "keyless_api": ["trace_moe"],
        "optional_keyed": ["saucenao_api", "tineye_api", "google_vision"],
        "excluded": [
            {"id": "pimeyes", "reason": "face-search / biometric identification"},
            {"id": "facecheck_id", "reason": "face-search / biometric identification"},
        ],
        "engines_list": ENGINES,
        "caveat": ("Reverse-image hits are leads for provenance review, not proof "
                   "of ownership, identity or location. No face-search/biometric "
                   "engines are used. Respect provider ToS and rate limits."),
    }


def links(image_url):
    """Build encoded link-out URLs for every link-capable engine."""
    if not image_url:
        return {}
    enc = urllib.parse.quote(image_url, safe="")
    out = {}
    for e in ENGINES:
        if "link" not in e["mode"]:
            continue
        try:
            out[e["id"]] = e["url"].format(url=enc)
        except Exception:
            continue
    return out


def _env_key(names):
    for name in names:
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
    return ""


def _validate_image_url(url):
    if not url:
        return False, "image_url required"
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return False, "unparseable image URL"
    if p.scheme not in ("http", "https") or not p.hostname:
        return False, "image URL must be public http(s)"
    # Reuse the same SSRF guard as the public profile scraper: resolve every
    # address and reject private/reserved ranges.
    return SOCIAL._validate_public_url(url)


def _trace_moe(image_url):
    """Keyless Trace.moe API."""
    try:
        r = requests.get("https://api.trace.moe/search",
                         params={"url": image_url, "anilistInfo": ""},
                         headers=UA, timeout=T)
    except Exception as e:
        return {"engine": "trace_moe", "status": "error", "hits": [],
                "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"engine": "trace_moe", "status": "blocked", "hits": [],
                "http": r.status_code, "error": "rate-limited or blocked"}
    if r.status_code != 200:
        return {"engine": "trace_moe", "status": "error", "hits": [],
                "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"engine": "trace_moe", "status": "error", "hits": [],
                "error": "non-JSON response"}
    hits = []
    for item in j.get("result") or []:
        anilist = item.get("anilist") or {}
        title = anilist.get("title") or {}
        if isinstance(title, dict):
            title = title.get("romaji") or title.get("english") or title.get("native") or ""
        hits.append({
            "title": title or item.get("filename") or "Trace.moe match",
            "similarity": item.get("similarity"),
            "episode": item.get("episode"),
            "from": item.get("from"), "to": item.get("to"),
            "filename": item.get("filename") or "",
            "video": item.get("video") or "",
            "image": item.get("image") or "",
            "is_adult": item.get("isAdult"),
            "source": "trace_moe",
        })
    return {"engine": "trace_moe", "status": "ok", "hits": hits,
            "count": len(hits), "mode": "keyless_api"}


def _saucenao(image_url, key):
    if not key:
        return {"engine": "saucenao_api", "status": "unavailable",
                "hits": [], "note": "no SauceNAO API key configured"}
    try:
        r = requests.get("https://saucenao.com/search.php",
                         params={"output_type": 2, "api_key": key,
                                 "url": image_url, "numres": 10},
                         headers=UA, timeout=T)
    except Exception as e:
        return {"engine": "saucenao_api", "status": "error", "hits": [],
                "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"engine": "saucenao_api", "status": "blocked", "hits": [],
                "http": r.status_code}
    if r.status_code != 200:
        return {"engine": "saucenao_api", "status": "error", "hits": [],
                "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"engine": "saucenao_api", "status": "error", "hits": [],
                "error": "non-JSON response"}
    hits = []
    for item in j.get("results") or []:
        header = item.get("header") or {}
        data = item.get("data") or {}
        hits.append({
            "title": (data.get("source") or data.get("title") or
                      data.get("material") or "SauceNAO match"),
            "similarity": header.get("similarity"),
            "index": header.get("index_id"),
            "url": data.get("ext_urls") or data.get("url") or "",
            "author": data.get("author_name") or "",
            "source": "saucenao_api",
        })
    return {"engine": "saucenao_api", "status": "ok", "hits": hits,
            "count": len(hits), "mode": "keyed_api"}


def _google_vision(image_url, key):
    if not key:
        return {"engine": "google_vision", "status": "unavailable",
                "hits": [], "note": "no Google Vision API key configured"}
    body = {
        "requests": [{
            "image": {"source": {"imageUri": image_url}},
            "features": [{"type": "WEB_DETECTION", "maxResults": 20}],
        }]
    }
    try:
        r = requests.post("https://vision.googleapis.com/v1/images:annotate",
                          params={"key": key}, json=body, headers=UA, timeout=T)
    except Exception as e:
        return {"engine": "google_vision", "status": "error", "hits": [],
                "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"engine": "google_vision", "status": "blocked", "hits": [],
                "http": r.status_code}
    if r.status_code != 200:
        return {"engine": "google_vision", "status": "error", "hits": [],
                "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"engine": "google_vision", "status": "error", "hits": [],
                "error": "non-JSON response"}
    resp = ((j.get("responses") or [{}])[0] or {}).get("webDetection") or {}
    hits = []
    for item in (resp.get("pagesWithMatchingImages") or [])[:20]:
        hits.append({
            "title": item.get("pageTitle") or item.get("url") or "Vision match",
            "url": item.get("url") or "",
            "source": "google_vision",
        })
    for item in (resp.get("visuallySimilarImages") or [])[:10]:
        hits.append({
            "title": "visually similar image",
            "url": item.get("url") or "",
            "source": "google_vision",
        })
    return {"engine": "google_vision", "status": "ok", "hits": hits,
            "count": len(hits), "mode": "keyed_api"}


def _tineye(image_url, key):
    if not key:
        return {"engine": "tineye_api", "status": "unavailable", "hits": [],
                "note": "no TinEye API key configured"}
    try:
        r = requests.get("https://api.tineye.com/rest/search/",
                         params={"api_key": key, "image_url": image_url},
                         headers=UA, timeout=T)
    except Exception as e:
        return {"engine": "tineye_api", "status": "error", "hits": [],
                "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"engine": "tineye_api", "status": "blocked", "hits": [],
                "http": r.status_code}
    if r.status_code != 200:
        return {"engine": "tineye_api", "status": "error", "hits": [],
                "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"engine": "tineye_api", "status": "error", "hits": [],
                "error": "non-JSON response"}
    hits = []
    for item in ((j.get("results") or {}).get("matches") or []):
        hits.append({
            "title": item.get("domain") or item.get("image_url") or "TinEye match",
            "url": item.get("image_url") or item.get("backlink") or "",
            "source": "tineye_api",
        })
    return {"engine": "tineye_api", "status": "ok", "hits": hits,
            "count": len(hits), "mode": "keyed_api"}


def search(image_url=None, image_path=None, engines=None, include_api=True,
           case_id=None, user="system"):
    """Run link generation + available API lookups for one image.

    ``image_url`` is a public image URL. ``image_path`` is an optional local
    path; it is hashed with imgverify (no upload) and only links are produced.
    """
    out = {
        "status": "ok", "image_url": image_url or "",
        "image_path": image_path or "", "links": {}, "engines": {},
        "hits": [], "hashes": None,
        "summary": {"engines_checked": 0, "engines_with_hits": 0,
                    "total_hits": 0, "links": 0},
    }
    if image_path:
        try:
            h = IV.hashes(image_path)
            out["hashes"] = h
            if h.get("status") != "ok":
                out["status"] = "error"
                out["error"] = h.get("error", "could not hash image")
                return out
        except Exception as e:
            out["status"] = "error"
            out["error"] = str(e)[:150]
            return out
    if image_url:
        ok, why = _validate_image_url(image_url)
        if not ok:
            out["status"] = "error"
            out["error"] = why
            return out
    if not image_url and not image_path:
        out["status"] = "error"
        out["error"] = "image_url or image_path required"
        return out

    out["links"] = links(image_url) if image_url else {}
    out["summary"]["links"] = len(out["links"])
    if include_api and image_url:
        wanted = set(engines) if engines else None
        tasks = {}
        if wanted is None or "trace_moe" in wanted:
            tasks["trace_moe"] = lambda: _trace_moe(image_url)
        if wanted is None or "saucenao_api" in wanted:
            tasks["saucenao_api"] = lambda: _saucenao(
                image_url, _env_key(("XAXGLOG_SAUCENAO_KEY", "SAUCENAO_API_KEY")))
        if wanted is None or "tineye_api" in wanted:
            tasks["tineye_api"] = lambda: _tineye(
                image_url, _env_key(("XAXGLOG_TINEYE_KEY", "TINEYE_API_KEY")))
        if wanted is None or "google_vision" in wanted:
            tasks["google_vision"] = lambda: _google_vision(
                image_url, _env_key(("XAXGLOG_GOOGLE_VISION_KEY",
                                     "GOOGLE_VISION_API_KEY")))
        from concurrent.futures import ThreadPoolExecutor, as_completed
        if tasks:
            with ThreadPoolExecutor(max_workers=min(4, len(tasks))) as ex:
                futs = {ex.submit(fn): name for name, fn in tasks.items()}
                for f in as_completed(futs):
                    name = futs[f]
                    try:
                        out["engines"][name] = f.result()
                    except Exception as e:
                        out["engines"][name] = {
                            "engine": name, "status": "error", "hits": [],
                            "error": str(e)[:150]}
    checked = [v for v in out["engines"].values()
               if v.get("status") in ("ok", "blocked", "error", "unavailable")]
    with_hits = [v for v in out["engines"].values() if v.get("hits")]
    out["hits"] = [h for v in with_hits for h in (v.get("hits") or [])]
    out["summary"]["engines_checked"] = len(checked)
    out["summary"]["engines_with_hits"] = len(with_hits)
    out["summary"]["total_hits"] = len(out["hits"])
    statuses = [v.get("status") for v in out["engines"].values()]
    if out["hits"]:
        out["status"] = "ok"
    elif any(s == "ok" for s in statuses):
        out["status"] = "empty"
        out["note"] = "API engines returned no matches; link-out engines are available"
    elif statuses and all(s in ("blocked", "unavailable") for s in statuses):
        out["status"] = "partial"
        out["note"] = "API engines blocked or need a key; use the link-out engines"
    elif statuses and any(s == "error" for s in statuses):
        out["status"] = "partial"
    elif out["links"]:
        out["status"] = "ok"
    elif out.get("hashes", {}).get("status") == "ok":
        out["status"] = "ok"
        out["note"] = ("local image hashed; upload it to a link engine or host it "
                       "at a public URL to run reverse-image APIs")
    else:
        out["status"] = "error"
    out["caveat"] = ("Reverse-image hits are provenance leads, not proof of "
                     "ownership, identity or location. No face-search/biometric "
                     "engines are used.")
    try:
        db.audit(user, "imgreverse.search", (image_url or image_path or "")[:120],
                 "hits=%s links=%s" % (len(out["hits"]), len(out["links"])))
        if case_id:
            out["artifact"] = db.store_artifact(
                case_id, None, "image_reverse", "imgreverse:search", out, user)
    except Exception as e:
        out["artifact_error"] = str(e)[:150]
    return out
