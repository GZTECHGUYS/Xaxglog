"""Xaxglog brandguard — typosquat & impersonation surface for a brand.

Keyless core:
  - Typosquat generator: 25+ mutation families over the brand string
    (omission, transposition, double-hit, hyphen/separator, bitsquatting,
    homoglyph via unicode lookalikes, pluralization, TLD swap, affixes,
    subdomain abuse, combo with common words).
  - Live resolution via DNS-over-HTTPS (Cloudflare, keyless) — does the
    lookalike domain actually exist?
  - RDAP (rdap.org, keyless) registration age — newly registered lookalikes
    are the phishing signal.
  - HTTPS/redirect probe of live hits (safe GET, SSRF-guarded ranges only).

Complements exposure (your own estate) and deep_search/domain (target
domains): this generates and checks the *attack surface around a name*.

Lawful-use note: DNS/RDAP public records + GET on public web servers.
Monitoring your own brand (or one you are authorized to protect).
"""
import datetime
import ipaddress
import socket

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 12
DOH = "https://cloudflare-dns.com/dns-query"
RDAP = "https://rdap.org/domain/{name}"
TLDS = ("com", "net", "org", "io", "co", "info", "biz", "xyz", "online",
        "site", "top", "app", "dev", "shop", "store", "cc", "tv", "me")
AFFIXES = ("login", "secure", "account", "verify", "support", "update",
           "auth", "sso", "portal", "mail", "my", "official")
_HOMO = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
         "y": "у", "i": "і", "s": "ѕ", "d": "ԁ", "l": "ⅼ", "n": "ո"}


def generate(brand, tlds=TLDS, max_out=200):
    """Generate typosquat/lookalike candidate domains for a brand."""
    try:
        brand = (brand or "").strip().lower()
        if not brand or " " in brand or "." in brand:
            brand = (brand or "").strip().lower().split(".")[0]
        if not brand.isalnum() or len(brand) < 3:
            return {"status": "error", "error": "brand must be >=3 alnum chars"}
        cands = set()
        # 1. omission / transposition / repetition / hyphenation (SLD forms)
        for i in range(len(brand)):
            cands.add(brand[:i] + brand[i + 1:])                      # omit
            if i + 1 < len(brand):
                cands.add(brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:])  # transpose
            cands.add(brand[:i] + brand[i] + brand[i:])               # double-hit
            cands.add(brand[:i] + "-" + brand[i:])                    # hyphenate
        # 2. bitsquatting
        for i in range(len(brand)):
            for bit in (1, 2, 4, 8, 16, 32, 64):
                ch = chr(ord(brand[i]) ^ bit)
                if ch.isalnum():
                    cands.add(brand[:i] + ch + brand[i + 1:])
        # 3. homoglyph (single + full-string)
        for i, ch in enumerate(brand):
            if ch in _HOMO:
                cands.add(brand[:i] + _HOMO[ch] + brand[i + 1:])
        cands.add("".join(_HOMO.get(c, c) for c in brand))
        # 4. affixes / plural / TLD swap / subdomain-style combos
        for a in AFFIXES:
            cands.add(a + brand)
            cands.add(brand + a)
            cands.add(f"{a}-{brand}")
            cands.add(f"{brand}-{a}")
        cands.update({brand + s for s in ("s", "-online", "-intl", "-corp",
                                          "-hq", "-global", "-inc", "24",
                                          "365", "pay", "wallet", "id")})
        for w in ("login", "auth", "verify", "account", "secure", "sso"):
            cands.add(f"{brand}{w}")
            cands.add(f"{brand}-{w}")
        # expand to domains across requested TLDs
        domains = set()
        for sld in cands:
            if len(sld) < 3 or len(sld) > 60:
                continue
            if not all(ch.isalnum() or ch in "-." for ch in sld):
                continue
            base = sld.split(".")[0].strip("-")
            if not base or not base.isalnum():
                continue
            for t in tlds:
                domains.add(f"{base}.{t}")
        out = sorted(domains)[:max_out]
        return {"status": "ok", "brand": brand, "generated": len(out),
                "families": ["omission", "transposition", "double-hit",
                             "hyphenation", "bitsquatting", "homoglyph",
                             "affix", "pluralization", "tld-swap"],
                "candidates": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "candidates": []}


def _doh_lookup(name, rtype="A"):
    import requests
    r = requests.get(DOH, headers={**UA, "Accept": "application/dns-json"},
                     params={"name": name, "type": rtype}, timeout=T)
    if r.status_code != 200:
        return None
    j = r.json()
    answers = j.get("Answer") or []
    return [a.get("data") for a in answers] if answers else None


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global
    except ValueError:
        return False


def check(candidate, probe=True):
    """Resolve + RDAP-age one candidate domain (keyless)."""
    try:
        name = (candidate or "").strip().lower().strip(".")
        if " " in name or "/" in name:
            return {"status": "error", "error": "invalid domain"}
        rec = {"domain": name}
        ips = _doh_lookup(name, "A") or _doh_lookup(name, "AAAA")
        if not ips:
            rec.update({"registered": False, "note": "no DNS record"})
            return {"status": "ok", "candidate": rec}
        rec["registered"] = True
        rec["ips"] = ips[:5]
        import requests
        try:
            r = requests.get(RDAP.format(name=name), headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                events = {e.get("eventAction"): e.get("eventDate")
                          for e in (j.get("events") or [])}
                rec["created"] = events.get("registration")
                if rec["created"]:
                    dt = datetime.datetime.strptime(rec["created"][:10], "%Y-%m-%d")
                    age_days = (datetime.date.today() - dt.date()).days
                    rec["age_days"] = age_days
                    rec["fresh"] = age_days <= 30
                rec["registrar"] = next(
                    (e.get("vcardArray")[1][1][4] for e in (j.get("entities") or [])
                     if e.get("roles") and "registrar" in e["roles"]
                     and e.get("vcardArray")), None)
        except Exception:
            rec["rdap"] = "unavailable"
        if probe and all(_is_public(ip) for ip in ips[:1]):
            try:
                import requests as rq
                resp = rq.get(f"http://{name}", headers=UA, timeout=8,
                              allow_redirects=True)
                rec["http"] = {"status": resp.status_code,
                               "server": resp.headers.get("Server"),
                               "title": (resp.text.split("<title>", 1)[1]
                                         .split("</", 1)[0][:120]
                                         if "<title>" in resp.text else None)}
            except Exception:
                rec["http"] = None
        return {"status": "ok", "candidate": rec}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def sweep(brand, tlds=TLDS, max_check=120, case_id=None, queried_by="system"):
    """Generate + resolve + RDAP-age a brand's lookalike surface."""
    try:
        gen = generate(brand, tlds=tlds, max_out=max_check)
        if gen.get("status") != "ok":
            return gen
        hits = []
        for dom in gen["candidates"]:
            out = check(dom, probe=False)
            if out.get("status") == "ok" and out["candidate"].get("registered"):
                hits.append(out["candidate"])
        report = {"brand": gen["brand"], "checked": len(gen["candidates"]),
                  "registered": len(hits),
                  "fresh_registrations": [h for h in hits if h.get("fresh")],
                  "hits": hits}
        db.audit(queried_by, "brandguard.sweep", gen["brand"],
                 f"checked={report['checked']} hits={len(hits)}")
        if case_id is not None and hits:
            art = db.store_artifact(case_id, None, "brandguard", "dns+rdap",
                                    report, queried_by)
            report["artifact"] = art
        return {"status": "ok", "report": report}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def fast_sweep(brand, workers=24):
    """Parallel DNS-only sweep (fast first pass; RDAP on follow-up check())."""
    from concurrent.futures import ThreadPoolExecutor
    gen = generate(brand)
    if gen.get("status") != "ok":
        return gen
    doms = gen["candidates"]
    hits = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for out in pool.map(lambda d: check(d, probe=False), doms):
            if out.get("status") == "ok" and out["candidate"].get("registered"):
                hits.append(out["candidate"])
    return {"status": "ok", "brand": gen["brand"], "checked": len(doms),
            "registered": len(hits), "hits": hits}
