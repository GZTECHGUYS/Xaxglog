"""Xaxglog emailintel — email deep-dive + email↔account hub anchoring.

Purpose
-------
Turn one email address into an intelligence package: format/MX validation,
disposable-domain and freemail classification, DNS auth profile
(MX / SPF / DMARC / DKIM), Gravatar presence, public breach exposure, raw
header forensics (Received hop IPs geolocated + auth results + anomalies),
and graph anchoring of the email to its other accounts inside a case.

Sources (public / keyless)
--------------------------
  - Google DNS-over-HTTPS   https://dns.google/resolve?name=&type=
  - Gravatar public JSON    https://en.gravatar.com/<md5>.json
  - XposedOrNot breach API  https://api.xposedornot.com/v1/check-email/<email>
  - ip-api.com geolocation  http://ip-api.com/json/<ip> (header-hop geo)

Lawful use
----------
Public breach *notification* data and public DNS only — this is exposure
notification, not credential access: no logins, no password spraying, no
account takeover. Respect each source's ToS and rate limits. Raw-header
analysis is for messages you lawfully possess (your own mailbox, evidence
produced under authority). Everything degrades gracefully; nothing raises.
"""
import hashlib
import html as _html
import ipaddress
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"]
IPGEO = "http://ip-api.com/json/{ip}?fields=query,city,country,as"
MAX_HOP_GEO = 10

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# ---------------------------------------------------------- disposable list
# Common throwaway / temp-mail domains (publicly documented disposable
# services) — detection only, not a blocklist of anyone's real mail.
_DISPOSABLE = {
    "10minutemail.com", "10minutemail.net", "10minutemail.co.za",
    "20minutemail.com", "33mail.com", "anonbox.net", "anonymbox.com",
    "binkmail.com", "bofthew.com", "bugmenot.com", "byom.de",
    "cool.fr.nf", "courriel.fr.nf", "crazymailing.com", "deadaddress.com",
    "dispostable.com", "dropmail.me", "einrot.com", "emailondeck.com",
    "emailias.com", "etempmail.com", "fakeinbox.com", "fakeinformation.com",
    "fakemail.net", "fakemailgenerator.com", "getnada.com", "grr.la",
    "guerrillamail.biz", "guerrillamail.com", "guerrillamail.de",
    "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "guerrillamailblock.com", "harakirimail.com", "inboxbear.com",
    "inboxkitten.com", "jetable.fr.nf", "jetable.org", "jmxmail.com",
    "jourrapide.com", "kasmail.com", "kurzepost.de", "mailcatch.com",
    "maildrop.cc", "mailforspam.com", "mailnesia.com", "mailsac.com",
    "mailtemp.de", "mailtothis.com", "meltmail.com", "mintemail.com",
    "moakt.cc", "moakt.com", "mohmal.com", "moncourrier.fr.nf",
    "monemail.fr.nf", "monmail.fr.nf", "mt2015.com", "mytemp.email",
    "mytrashmail.com", "nomail2me.com", "nospam.ze.tc", "pokemail.net",
    "proxymail.eu", "rcpt.at", "rhyta.com", "sharklasers.com", "shitmail.me",
    "slothmail.net", "spam.la", "spam4.me", "spamex.com", "spambog.com",
    "spambog.de", "spambog.ru", "superrito.com", "tafmail.com",
    "teleworm.us", "temp-mail.io", "temp-mail.org", "tempail.com",
    "tempinbox.com", "tempmail.com", "tempmailo.com", "tempr.email",
    "throwawaymail.com", "throwaway.email", "trash-mail.com", "trashmail.de",
    "trashmail.me", "trashmail.net", "trashmail.org", "trbvm.com",
    "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "yopmail.com", "yopmail.fr", "yopmail.net", "zehnminutenmail.de",
    "mailinator.com", "mailinator.net", "mailinator.org", "mailinator2.com",
    "mailsac.com", "discard.email", "discardmail.com", "mailexpire.com",
    "spamgourmet.com", "sogetthis.com", "speedytp.com", "superrito.com",
    "taoaty.com", "thetempmail.com", "tmail.ws", "trashymail.com",
    "veryrealemail.com", "wegwerfmail.com", "xagloo.com", "xoxy.net",
}

_FREEMAIL = {
    "gmail.com": "gmail", "googlemail.com": "gmail",
    "outlook.com": "outlook", "hotmail.com": "outlook", "live.com": "outlook",
    "msn.com": "outlook", "hotmail.co.uk": "outlook", "hotmail.fr": "outlook",
    "yahoo.com": "yahoo", "yahoo.co.uk": "yahoo", "yahoo.ca": "yahoo",
    "yahoo.co.jp": "yahoo", "yahoo.de": "yahoo", "yahoo.fr": "yahoo",
    "yahoo.es": "yahoo", "ymail.com": "yahoo", "rocketmail.com": "yahoo",
    "protonmail.com": "protonmail", "proton.me": "protonmail",
    "pm.me": "protonmail", "protonmail.ch": "protonmail",
    "aol.com": "aol", "icloud.com": "icloud", "me.com": "icloud",
    "mac.com": "icloud", "gmx.com": "gmx", "gmx.net": "gmx", "gmx.de": "gmx",
    "mail.com": "mail.com", "zoho.com": "zoho", "zohomail.com": "zoho",
    "yandex.com": "yandex", "yandex.ru": "yandex", "ya.ru": "yandex",
    "mail.ru": "mailru", "inbox.ru": "mailru", "list.ru": "mailru",
    "bk.ru": "mailru", "rambler.ru": "rambler",
    "qq.com": "qq", "foxmail.com": "qq",
    "163.com": "netease", "126.com": "netease", "yeah.net": "netease",
    "naver.com": "naver", "daum.net": "daum", "hanmail.net": "daum",
    "fastmail.com": "fastmail", "fastmail.fm": "fastmail",
    "tutanota.com": "tutanota", "tuta.io": "tutanota", "keemail.me": "tutanota",
    "hey.com": "hey", "seznam.cz": "seznam", "wp.pl": "wp",
    "o2.pl": "o2", "onet.pl": "onet", "web.de": "webde", "t-online.de": "tonline",
    "att.net": "att", "sbcglobal.net": "att", "bellsouth.net": "att",
    "comcast.net": "comcast", "verizon.net": "verizon",
    "laposte.fr": "laposte", "free.fr": "free", "orange.fr": "orange",
}


# ------------------------------------------------------------------ DoH
def _doh(name, rtype):
    """Keyless DNS-over-HTTPS lookup (dns.google JSON)."""
    try:
        r = requests.get("https://dns.google/resolve",
                         params={"name": name, "type": rtype},
                         headers=UA, timeout=T)
        j = r.json()
        answers = [a for a in (j.get("Answer") or []) if isinstance(a, dict)]
        return {"status": "ok", "name": name, "type": rtype,
                "rcode": j.get("Status"), "answers": answers}
    except Exception as e:
        return {"error": str(e)[:150], "name": name, "type": rtype,
                "answers": []}


def _txt_values(doh_out):
    """TXT answers -> list of joined strings (quotes stripped, chunks merged)."""
    vals = []
    for a in doh_out.get("answers") or []:
        if a.get("type") != 16:
            continue
        data = str(a.get("data") or "")
        data = "".join(re.findall(r'"([^"]*)"', data)) if '"' in data else data
        vals.append(data.strip())
    return [v for v in vals if v]


def validate(email):
    """Format + MX (DoH) + disposable-domain + freemail-provider check."""
    out = {"email": email, "format_ok": False, "domain": "", "mx": [],
           "mx_ok": False, "disposable": False, "provider": None,
           "valid": False, "status": "error"}
    try:
        e = (email or "").strip().lower()
        out["email"] = e
        if not e or "@" not in e:
            out["status"] = "invalid_format"
            return out
        out["format_ok"] = bool(_EMAIL_RE.match(e))
        domain = e.rsplit("@", 1)[-1]
        out["domain"] = domain
        out["disposable"] = domain in _DISPOSABLE
        out["provider"] = _FREEMAIL.get(domain, "custom")
        if not out["format_ok"]:
            out["status"] = "invalid_format"
            return out
        mx = _doh(domain, "MX")
        if mx.get("error"):
            out["error"] = mx["error"]
            out["status"] = "dns_error"
            return out
        for a in mx.get("answers") or []:
            if a.get("type") == 15:
                pref, exch = (str(a.get("data", "")).split(" ", 1) + [""])[:2]
                out["mx"].append({"priority": pref.strip(),
                                  "exchange": exch.strip().rstrip(".")})
        out["mx_ok"] = bool(out["mx"])
        out["status"] = "ok"
        out["valid"] = out["format_ok"] and out["mx_ok"]
        return out
    except Exception as e2:
        out["error"] = str(e2)[:150]
        return out


def dns_profile(email):
    """MX + SPF + DMARC + DKIM (common selectors) for the email's domain."""
    out = {"email": (email or "").strip().lower(), "domain": "",
           "mx": [], "spf": None, "dmarc": None, "dkim": {}, "status": "error"}
    try:
        e = out["email"]
        if "@" not in e:
            out["error"] = "invalid email"
            return out
        domain = e.rsplit("@", 1)[-1]
        out["domain"] = domain

        mx = _doh(domain, "MX")
        for a in mx.get("answers") or []:
            if a.get("type") == 15:
                pref, exch = (str(a.get("data", "")).split(" ", 1) + [""])[:2]
                out["mx"].append({"priority": pref.strip(),
                                  "exchange": exch.strip().rstrip(".")})

        txt = _txt_values(_doh(domain, "TXT"))
        for v in txt:
            if v.lower().startswith("v=spf1"):
                out["spf"] = v
                break

        dtxt = _txt_values(_doh("_dmarc." + domain, "TXT"))
        for v in dtxt:
            if v.lower().startswith("v=dmarc1"):
                out["dmarc"] = v
                break

        for sel in DKIM_SELECTORS:
            recs = _txt_values(_doh(f"{sel}._domainkey.{domain}", "TXT"))
            for v in recs:
                if "p=" in v:
                    out["dkim"][sel] = v
                    break
        out["status"] = "ok"
        return out
    except Exception as e2:
        out["error"] = str(e2)[:150]
        return out


# ------------------------------------------------------------------ gravatar
def gravatar(email):
    """Gravatar profile existence for md5(lower/strip(email)) — 404 => none."""
    out = {"email": (email or "").strip().lower(), "hash": "",
           "has_gravatar": False, "status": "error"}
    try:
        e = out["email"]
        h = hashlib.md5(e.encode("utf-8")).hexdigest()
        out["hash"] = h
        r = requests.get(f"https://en.gravatar.com/{h}.json", headers=UA, timeout=T)
        if isinstance(r, Exception):
            out["error"] = str(r)[:150]
            return out
        if r.status_code == 404:
            out["status"] = "ok"
            out["has_gravatar"] = False
            out["note"] = "no gravatar registered"
            return out
        if r.status_code in (403, 429):
            out["status"] = "blocked"
            out["mode"] = "anti_bot"
            return out
        if r.status_code >= 400:
            out["status"] = "error"
            out["error"] = f"http_{r.status_code}"
            return out
        try:
            j = r.json()
        except Exception:
            out["status"] = "error"
            out["error"] = "non-json response"
            return out
        entry = (j.get("entry") or [{}])[0] if isinstance(j, dict) else {}
        out.update({
            "status": "ok", "has_gravatar": True,
            "display_name": entry.get("displayName") or "",
            "profile_url": entry.get("profileUrl") or "",
            "avatar": ((entry.get("photos") or [{}])[0] or {}).get("value", ""),
            "location": entry.get("location") or "",
            "about": (entry.get("aboutMe") or "")[:300],
        })
        return out
    except Exception as e2:
        out["error"] = str(e2)[:150]
        return out


# ------------------------------------------------------------------ breaches
def _flatten_breaches(obj):
    names = []
    if isinstance(obj, dict):
        names.extend(str(k) for k in obj.keys())
    elif isinstance(obj, list):
        for x in obj:
            if isinstance(x, str):
                names.append(x)
            else:
                names.extend(_flatten_breaches(x))
    dedup, seen = [], set()
    for n in names:
        k = n.strip().lower()
        if n.strip() and k not in seen:
            seen.add(k)
            dedup.append(n.strip())
    return dedup


def breach_check(email):
    """Public breach exposure via XposedOrNot (exposure notification only)."""
    out = {"email": (email or "").strip().lower(), "breaches": [],
           "count": 0, "status": "error"}
    try:
        e = out["email"]
        if "@" not in e:
            out["error"] = "invalid email"
            return out
        url = "https://api.xposedornot.com/v1/check-email/" + \
            urllib.parse.quote(e, safe="@.")
        r = requests.get(url, headers=UA, timeout=T)
        if isinstance(r, Exception):
            out["error"] = str(r)[:150]
            return out
        if r.status_code == 404:
            out["status"] = "not_found"
            out["note"] = "no breach record for this address"
            return out
        if r.status_code in (403, 429):
            out["status"] = "blocked"
            out["mode"] = "rate_limited"
            return out
        if r.status_code >= 400:
            out["status"] = "error"
            out["error"] = f"http_{r.status_code}"
            return out
        try:
            j = r.json()
        except Exception:
            out["status"] = "error"
            out["error"] = "non-json response"
            return out
        if isinstance(j, dict) and j.get("Error"):
            out["status"] = "error"
            out["error"] = str(j.get("Error"))[:150]
            return out
        breaches = _flatten_breaches(j.get("breaches") if isinstance(j, dict) else j)
        out["breaches"] = breaches
        out["count"] = len(breaches)
        out["status"] = "ok"
        return out
    except Exception as e2:
        out["error"] = str(e2)[:150]
        return out


# ------------------------------------------------------------------ deep
def deep(email, case_id=None, user="system"):
    """Full email package: validate + DNS + gravatar + breaches (+ case DB)."""
    out = {"email": (email or "").strip().lower(), "checked_at": db.utcnow()}
    try:
        out["validate"] = validate(out["email"])
        out["dns"] = dns_profile(out["email"])
        out["gravatar"] = gravatar(out["email"])
        out["breach"] = breach_check(out["email"])
        out["status"] = "ok"
        if case_id:
            try:
                from modules.cases import cases as CASES
                eid = CASES.add_entity(case_id, "email", out["email"],
                                       {"source": "emailintel",
                                        "disposable": out["validate"].get("disposable"),
                                        "provider": out["validate"].get("provider")})
                out["entity_id"] = eid
                art = db.store_artifact(case_id, eid, "recon",
                                        "emailintel:deep", out, user)
                out["artifact"] = art
                db.audit(user, "emailintel.deep", out["email"],
                         f"breaches={out['breach'].get('count', 0)} "
                         f"mx={out['validate'].get('mx_ok')} "
                         f"artifact={art.get('id')}")
            except Exception as dex:
                out["db_error"] = str(dex)[:150]
                db.audit(user, "emailintel.deep", out["email"],
                         f"db_error={str(dex)[:150]}")
        else:
            db.audit(user, "emailintel.deep", out["email"],
                     f"breaches={out['breach'].get('count', 0)} (no case)")
        return out
    except Exception as e:
        return {"error": str(e)[:150], "email": out.get("email", email)}


# ------------------------------------------------------------------ headers
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*"
                   r"(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)


def _geo_ip(ip):
    """Geolocate one hop IP via ip-api (never raises)."""
    res = {"ip": ip, "city": "", "country": "", "asn": ""}
    try:
        ipaddress.ip_address(ip)
        if ipaddress.ip_address(ip).is_private or \
           ipaddress.ip_address(ip).is_reserved:
            res["note"] = "private/reserved"
            return res
    except Exception:
        res["note"] = "unparseable"
        return res
    try:
        r = requests.get(IPGEO.format(ip=ip), headers=UA, timeout=8)
        j = r.json()
        if str(j.get("status")) == "success" or j.get("query"):
            res["city"] = j.get("city") or ""
            res["country"] = j.get("country") or ""
            res["asn"] = j.get("as") or ""
        else:
            res["note"] = str(j.get("message") or "lookup_failed")[:60]
    except Exception as e:
        res["error"] = str(e)[:80]
    return res


def header_analyze(raw):
    """Forensics on a pasted raw email header block.

    Returns {hops:[{ip,city,country,asn,position}], auth:{spf,dkim,dmarc},
    message_id_domain, from_address, reply_to, reply_to_differs, anomalies}.
    Hops are listed in chronological order (position 0 = origin/earliest).
    """
    out = {"hops": [], "auth": {"spf": None, "dkim": None, "dmarc": None},
           "message_id_domain": None, "from_address": None,
           "reply_to": None, "reply_to_differs": False, "anomalies": [],
           "status": "error"}
    try:
        if not isinstance(raw, str) or not raw.strip():
            out["error"] = "empty header block"
            return out
        text = raw.replace("\r\n", "\n")
        hdr = text.split("\n\n", 1)[0]

        # ---- Received hops (document order: newest first -> reverse for chrono)
        recv_blocks = re.findall(r"^Received:[^\n]*(?:\n[ \t]+[^\n]*)*",
                                 hdr, re.M)
        doc_hops = []
        for i, blk in enumerate(recv_blocks):
            ips = _IPV4.findall(blk)
            doc_hops.append({"ip": ips[0] if ips else "",
                             "position": i, "raw": _html.unescape(blk)[:300]})
        geo_targets = [h for h in doc_hops if h["ip"]]
        geo_map = {}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(_geo_ip, h["ip"]): h["ip"]
                    for h in geo_targets[:MAX_HOP_GEO]}
            for f in as_completed(futs):
                try:
                    g = f.result()
                except Exception:
                    g = {"ip": futs[f], "city": "", "country": "", "asn": "",
                         "error": "geo_failed"}
                geo_map[g["ip"]] = g
        for h in doc_hops:
            if h["ip"] and h["ip"] in geo_map:
                g = geo_map[h["ip"]]
            elif h["ip"]:
                g = {"city": "", "country": "", "asn": "",
                     "note": "geo skipped (hop cap)"}
            else:
                g = {"city": "", "country": "", "asn": "", "note": "no ip in hop"}
            out["hops"].append({
                "ip": h["ip"],
                "city": g.get("city", ""),
                "country": g.get("country", ""),
                "asn": g.get("asn", ""),
                "note": g.get("note", g.get("error", "")),
                "position": h["position"],
            })
        # chronological order = reversed document order
        out["hops"].sort(key=lambda x: -x["position"])
        for i, h in enumerate(out["hops"]):
            h["position"] = i

        # ---- auth results
        seen_order = []
        for m in _AUTH.finditer(hdr):
            key, val = m.group(1).lower(), m.group(2).lower()
            if out["auth"].get(key) is None:
                out["auth"][key] = val
                seen_order.append(key)
        if not seen_order:
            out["anomalies"].append("no Authentication-Results found")

        # ---- Message-ID domain
        mm = re.search(r"^Message-ID:\s*<?[^<>\s]*@([^>\s,]+)>?", hdr, re.I | re.M)
        if mm:
            out["message_id_domain"] = mm.group(1).strip().rstrip(">").lower()
        else:
            out["anomalies"].append("missing Message-ID")

        # ---- From / Reply-To
        fm = re.search(r"^From:\s*(?:.*?<)?([^<>\s]+@[^<>\s>]+)>?",
                       hdr, re.I | re.M)
        rm = re.search(r"^Reply-To:\s*(?:.*?<)?([^<>\s]+@[^<>\s>]+)>?",
                       hdr, re.I | re.M)
        out["from_address"] = fm.group(1).lower() if fm else None
        out["reply_to"] = rm.group(1).lower() if rm else None
        if out["from_address"] and out["reply_to"]:
            out["reply_to_differs"] = out["from_address"] != out["reply_to"]
            if out["reply_to_differs"]:
                out["anomalies"].append(
                    "Reply-To differs from From (possible redirect/relay)")

        # ---- extra anomalies
        for k, v in out["auth"].items():
            if v in ("fail", "permerror", "temperror"):
                out["anomalies"].append(f"{k.upper()}={v}")
        if out["hops"] and all(h["note"] == "private/reserved" or not h["ip"]
                               for h in out["hops"]):
            out["anomalies"].append("all located hops are private/reserved IPs")
        if not out["hops"]:
            out["anomalies"].append("no Received hops found")
        out["hop_count"] = len(out["hops"])
        out["status"] = "ok"
        return out
    except Exception as e:
        out["error"] = str(e)[:150]
        return out


# ------------------------------------------------------------------ graph hub
def anchor_graph(case_id, email, links=None, user="system"):
    """Upsert the email node and link it to related accounts ('same_as').

    `links` = [{"type": "username"|"profile"|"domain"|..., "value": "..."}].
    Gives the email <-> account hub inside the case graph. Every write is
    audited.
    """
    out = {"email": (email or "").strip().lower(), "email_id": None,
           "linked": 0, "links": [], "status": "error"}
    try:
        if not case_id or not out["email"] or "@" not in out["email"]:
            out["error"] = "case_id and a valid email are required"
            return out
        from modules.cases import cases as CASES
        eid = CASES.add_entity(case_id, "email", out["email"],
                               {"source": "email_anchor"})
        out["email_id"] = eid
        for item in (links or []):
            if not isinstance(item, dict):
                continue
            ltype = str(item.get("type") or "").strip().lower()
            lval = str(item.get("value") or "").strip()
            if not ltype or not lval:
                continue
            if ltype == "email" and lval.lower() == out["email"]:
                continue                      # no self-loop
            oid = CASES.add_entity(case_id, ltype, lval,
                                   {"source": "email_anchor"})
            if oid == eid:
                continue
            CASES.link_entities(case_id, eid, oid, "same_as", 1.0,
                                "email_anchor")
            out["linked"] += 1
            out["links"].append({"type": ltype, "value": lval,
                                 "entity_id": oid})
        db.audit(user, "emailintel.anchor", out["email"],
                 f"case={case_id} linked={out['linked']}")
        out["status"] = "ok"
        return out
    except Exception as e:
        out["error"] = str(e)[:150]
        try:
            db.audit(user, "emailintel.anchor", out.get("email", ""),
                     f"error={str(e)[:150]}")
        except Exception:
            pass
        return out
