"""Xaxglog web intelligence — offensive-surface sweep of public web pages.

  stack_fingerprint  — tracker / anti-bot / CDN inventory of a target site
  payment_addresses  — harvest BTC/ETH/XMR donation addresses from pages
  canary_scan        — tracking pixels + phone-home links in received evidence
  shortener_intel    — expand redirect chains, decode campaign parameters

All four are GET-only against public URLs with an SSRF guard: private,
loopback, link-local and reserved address space is rejected before fetch.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse, parse_qsl, urlencode, urljoin

import db

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Xaxglog-OSINT/2.0",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
T = 14

TRACKER_SIGNS = {
    "google_analytics": ["google-analytics.com/analytics.js", "google-analytics.com/collect",
                         "googletagmanager.com/gtag"],
    "google_tag_manager": ["googletagmanager.com/gtm.js"],
    "meta_pixel": ["connect.facebook.net", "fbq("],
    "hotjar": ["hotjar.com", "static.hotjar.com"],
    "microsoft_clarity": ["clarity.ms"],
    "segment": ["cdn.segment.com", "analytics.loadSegment"],
    "mixpanel": ["mixpanel.com", "mixpanel.init"],
    "amplitude": ["amplitude.com", "amplitude.log"],
    "hubspot": ["js.hs-scripts.com", "js.hsforms.net"],
    "intercom": ["intercomcdn.com", "intercom.io"],
    "tawk_to": ["tawk.to"],
    "drift": ["drift.com"],
    "fullstory": ["fullstory.com"],
    "matomo": ["matomo.js", "piwik.js"],
    "yandex_metrica": ["mc.yandex.ru"],
    "baidu_hm": ["hm.baidu.com"],
    "clarity_fpad": ["fs.clarity.ms"],
}
ANTI_BOT = {
    "cloudflare": ["cf-ray", "__cfduid", "cf_bm"],
    "datadome": ["datadome"],
    "permutive": ["permutive.com"],
    "fingerprintjs": ["fpjs", "fingerprintjs"],
    "recaptcha": ["google.com/recaptcha"],
    "hcaptcha": ["hcaptcha.com"],
    "turnstile": ["challenges.cloudflare.com/turnstile"],
}
CDN_SIGNS = {
    "cloudflare": ["cf-ray"], "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly"], "cloudfront": ["cloudfront.net", "x-amz-cf"],
    "incapsula": ["x-cdn", "incap_ses"], "google_cdn": ["gws"],
}

_BTC_RE = re.compile(r"\b(?:bc1[qpmz][ac-hj-np-z02-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.I)
_PIXEL_RE = re.compile(
    r"<img[^>]+(?:width\s*=\s*[\"']?1[\"']?|height\s*=\s*[\"']?1[\"']?)[^>]*>", re.I)
_BEACON_PATH = re.compile(
    r"(?:\/open\.aspx|\/track(?:ing)?\?|\/eurl\.ashx|\/act_delivery|\/t\.o\(e\)|"
    r"\/imp\?|\/px\?|\/pixel\.[a-z]{2,4}\?|\/mailstat|\/lt\.php|\/r\/open\?)", re.I)
_LONG_TOKEN = re.compile(r"[?&](?:u|url|c|cid|c_id|s|s1|mc_eid|recipient|member_id)="
                         r"([A-Za-z0-9_\-]{18,})", re.I)
_SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "lnkd.in", "t.me", "rb.gy", "s.id", "shorturl.at",
    "bl.ink", "soo.gd", "v.gd", "trib.al", "ift.tt", "dlvr.it",
}


def _guard(url):
    """SSRF guard — reject private/reserved targets before any fetch."""
    try:
        pr = urlparse(url if "//" in url else "http://" + url)
    except Exception:
        return None, "malformed url"
    if pr.scheme not in ("http", "https"):
        return None, "scheme not allowed"
    host = pr.hostname
    if not host:
        return None, "no host"
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return None, f"dns failed for {host}"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return None, f"blocked address {ip} (private/reserved range)"
    return pr, None


def _fetch(url, max_bytes=900_000):
    """GET with SSRF guard. Returns (final_url, status, text, headers)."""
    import requests
    pr, err = _guard(url)
    if err:
        return url, "blocked", "", {}
    target = pr.geturl()
    try:
        r = requests.get(target, headers=UA, timeout=T, allow_redirects=True,
                         stream=True)
    except Exception as e:
        return target, "error", str(e)[:150], {}
    # guard every redirect hop too
    if r.url:
        _, hop_err = _guard(r.url)
        if hop_err:
            return target, "blocked", "", {}
    status = "ok" if r.status_code == 200 else f"http_{r.status_code}"
    body = ""
    try:
        raw = r.raw.read(max_bytes, decode_content=True)
        body = raw.decode("utf-8", "replace")
    except Exception:
        try:
            body = r.text[:max_bytes]
        except Exception:
            body = ""
    return r.url, status, body, dict(r.headers or {})


_TRACKER_VENDOR = {
    "google_analytics": "Google Analytics", "google_tag_manager": "Google Tag Manager",
    "meta_pixel": "Meta Pixel", "hotjar": "Hotjar", "microsoft_clarity": "Microsoft Clarity",
    "segment": "Segment", "mixpanel": "Mixpanel", "amplitude": "Amplitude",
    "hubspot": "HubSpot", "intercom": "Intercom", "tawk_to": "Tawk.to", "drift": "Drift",
    "fullstory": "FullStory", "matomo": "Matomo", "yandex_metrica": "Yandex Metrica",
    "baidu_hm": "Baidu Tongji", "clarity_fpad": "Microsoft Clarity",
    "cloudflare": "Cloudflare", "datadome": "DataDome", "permutive": "Permutive",
    "recaptcha": "Google reCAPTCHA", "hcaptcha": "hCaptcha", "turnstile": "Cloudflare Turnstile",
    "fingerprintjs": "FingerprintJS",
}


def _emit_stack(case_id, final, found, anti, user):
    """domain -runs_tracker-> vendor  +  domain -protected_by-> vendor."""
    try:
        import modules.cases.cases as CASES
        host = urlparse(final).hostname or final
        did = CASES.add_entity(case_id, "domain", host)
        for key in list(found) + list(anti):
            vendor = _TRACKER_VENDOR.get(key)
            if not vendor:
                continue
            vid = CASES.add_entity(case_id, "company", vendor)
            CASES.link_entities(case_id, did, vid,
                                "protected_by" if key in anti else "runs_tracker",
                                0.8, "webintel")
    except Exception:
        pass


# ---------------------------------------------------------------- 1. stack fingerprint
def stack_fingerprint(url, case_id=None, user="system"):
    """Who runs on this site: analytics, anti-bot, CDN, cookies, forms."""
    if not url:
        return {"status": "error", "error": "url required"}
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    final, status, html, headers = _fetch(url)
    if status in ("blocked", "error"):
        return {"status": status, "url": url, "error": html or "fetch failed"}
    low = html.lower()
    found = {k: [s for s in sigs if s.lower() in low]
             for k, sigs in TRACKER_SIGNS.items()}
    found = {k: v for k, v in found.items() if v}
    anti = {}
    hdr_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower() + " " + low
    for k, sigs in ANTI_BOT.items():
        hits = [s for s in sigs if s.lower() in hdr_blob]
        if hits:
            anti[k] = hits
    cdn = {}
    for k, sigs in CDN_SIGNS.items():
        if any(s.lower() in hdr_blob for s in sigs):
            cdn[k] = True
    cookies = []
    raw_set = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    for part in re.split(r",(?=[^;]+=)", raw_set):
        name = part.split("=", 1)[0].strip()
        if name and len(cookies) < 30:
            cookies.append(name)
    forms = re.findall(r"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"'][^>]*>", html, re.I)[:10]
    forms = [urljoin(final, f) for f in forms]
    scripts = sorted(set(re.findall(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", html, re.I)))[:40]
    server = headers.get("Server") or headers.get("server") or ""
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    out = {"status": "ok", "url": final, "http_title": (re.search(r"<title[^>]*>(.*?)</title>",
           html, re.I | re.S).group(1).strip()[:160] if re.search(r"<title[^>]*>(.*?)</title>",
           html, re.I | re.S) else ""),
           "trackers": found, "anti_bot": anti, "cdn": cdn,
           "cookies": cookies, "form_actions": forms, "scripts": scripts,
           "server": server, "powered_by": powered,
           "counts": {"trackers": len(found), "anti_bot": len(anti), "scripts": len(scripts)}}
    if case_id is not None:
        db.store_artifact(case_id, None, "webintel", "webintel:stack", out, user)
        _emit_stack(case_id, final, found, anti, user)
    db.audit(user, "webintel.stack", url, f"trackers={len(found)} anti={len(anti)}")
    return out


# ---------------------------------------------------------------- 2. payment addresses
def payment_addresses(url, case_id=None, follow_internal=8, user="system"):
    """Harvest public crypto donation addresses from a page and its internal links."""
    if not url:
        return {"status": "error", "error": "url required"}
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    final, status, html, _ = _fetch(url)
    if status in ("blocked", "error"):
        return {"status": status, "url": url, "error": html or "fetch failed"}
    pages = [(final, html)]
    base_host = urlparse(final).hostname
    seen_links = set()
    for m in _URL_RE.findall(html)[:40]:
        if len(pages) > follow_internal:
            break
        if m in seen_links:
            continue
        seen_links.add(m)
        try:
            if urlparse(m).hostname == base_host:
                _, st2, body2, _ = _fetch(m)
                if st2 == "ok" and len(body2) > 100:
                    pages.append((m, body2))
        except Exception:
            continue

    found = {}

    def add(kind, addr, page):
        if kind == "eth" and int(addr, 16) == 0:
            return
        key = (kind, addr)
        if key not in found:
            found[key] = {"type": kind, "address": addr, "page": page}

    for page, body in pages:
        for a in set(_BTC_RE.findall(body)):
            add("btc", a, page)
        for a in set(_ETH_RE.findall(body)):
            add("eth", a, page)
        for a in set(_XMR_RE.findall(body)):
            add("xmr", a, page)
    addresses = sorted(found.values(), key=lambda x: x["type"])
    out = {"status": "ok", "url": final, "pages_scanned": len(pages),
           "count": len(addresses), "addresses": addresses[:60]}
    if case_id is not None:
        db.store_artifact(case_id, None, "webintel", "webintel:payments", out, user)
        try:
            from modules.pattern import pattern as PAT
            for a in addresses[:20]:
                PAT.add_link("domain", base_host or final, "handle",
                             a["address"], "shares_url", "webintel", 0.6, case_id, user)
        except Exception:
            pass
    db.audit(user, "webintel.payments", url, f"addresses={len(addresses)}")
    return out


# ---------------------------------------------------------------- 3. canary / pixel detector
def canary_scan(payload, source="evidence", case_id=None, user="system"):
    """Flag tracking pixels, phone-home links and long campaign tokens in
    received evidence (HTML, email body, pasted text)."""
    text = str(payload or "")
    if not text.strip():
        return {"status": "error", "error": "empty payload"}
    findings = []
    for m in _PIXEL_RE.finditer(text):
        tag = m.group(0)
        src = re.search(r"src\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        findings.append({"kind": "tracking_pixel",
                         "url": src.group(1) if src else "",
                         "why": "1x1 image in payload"})
    for m in _URL_RE.finditer(text):
        u = m.group(0)
        if _BEACON_PATH.search(u):
            findings.append({"kind": "beacon_url", "url": u,
                             "why": "phone-home path pattern"})
        elif _LONG_TOKEN.search(u):
            tok = _LONG_TOKEN.search(u)
            findings.append({"kind": "campaign_token", "url": u,
                             "why": f"recipient token: {tok.group(0)[:60]}"})
    for name in ("list-manage.com", "mailchimp.com", "sendgrid.net", "hubspot.net",
                 "marketo", "pardot", "salesforce.com"):
        if name in text.lower():
            findings.append({"kind": "esp_signature", "url": "",
                             "why": f"email service provider marker: {name}"})
    # dedupe by (kind,url)
    seen, uniq = set(), []
    for f in findings:
        k = (f["kind"], f["url"][:160])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    out = {"status": "ok", "source": source, "scanned_bytes": len(text),
           "findings": uniq[:80], "count": len(uniq),
           "risk": "high" if any(f["kind"] == "tracking_pixel" for f in uniq)
                   else ("medium" if uniq else "clean")}
    if case_id is not None:
        db.store_artifact(case_id, None, "webintel", "webintel:canary", out, user)
    db.audit(user, "webintel.canary", source, f"findings={len(uniq)}")
    return out


# ---------------------------------------------------------------- 4. shortener intel
def shortener_intel(url, max_hops=10, case_id=None, user="system"):
    """Follow a redirect chain hop by hop, decode campaign parameters."""
    if not re.match(r"^https?://", str(url or ""), re.I):
        return {"status": "error", "error": "absolute url required"}
    import requests
    chain, current = [], str(url)
    params_final = None
    for hop in range(max_hops + 1):
        pr, err = _guard(current)
        if err:
            chain.append({"url": current, "status": "blocked", "note": err})
            break
        try:
            r = requests.get(current, headers=UA, timeout=T, allow_redirects=False)
        except Exception as e:
            chain.append({"url": current, "status": "error", "note": str(e)[:120]})
            break
        entry = {"url": current, "host": pr.hostname, "http": r.status_code}
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location") or r.headers.get("location") or ""
            entry["location"] = loc[:400]
            entry["provider"] = "shortener" if (pr.hostname or "").lower() in _SHORTENER_HOSTS else None
            chain.append(entry)
            current = urljoin(current, loc)
            continue
        chain.append(entry)
        params_final = current
        break

    decoded = {}
    if params_final:
        try:
            qs = parse_qsl(urlparse(params_final).query, keep_blank_values=True)
            for k, v in qs:
                if k.lower().startswith("utm_") or k.lower() in (
                        "gclid", "fbclid", "mc_cid", "mc_eid", "igshid", "ref", "source"):
                    decoded[k] = v[:200]
        except Exception:
            pass
    final_url = chain[-1].get("location") or (chain[-1].get("url") if chain else url)
    if chain and chain[-1].get("http") == 200:
        final_url = chain[-1]["url"]
    hops = len([c for c in chain if c.get("location")])
    out = {"status": "ok", "hops": hops, "chain": chain[:12],
           "final_url": str(final_url)[:600], "campaign": decoded,
           "shortener": next((c.get("host") for c in chain if c.get("provider")), None)}
    if case_id is not None:
        db.store_artifact(case_id, None, "webintel", "webintel:shortener", out, user)
    db.audit(user, "webintel.shortener", url, f"hops={hops}")
    return out
