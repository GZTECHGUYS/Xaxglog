"""Compatibility helpers for the legacy React dashboard and operator actions.

The old dashboard called ``/api/lookup``, ``/api/keys``, ``/api/ai-summary``,
``/api/breach-lookup`` and the rule-template endpoints.  Those routes were
never registered in the unified app even though implementations existed in the
legacy donor tree.  This module provides small, dependency-light replacements:

* a server-side operator key store (Fernet when available, owner-only file),
* a compatibility ``/api/lookup`` shape over the live deep-search engine,
* deterministic AI-style briefing/rules fallbacks (no paid key required),
* breach lookup mapped to the XposedOrNot/HIBP deep-search result.

Nothing here bypasses a login wall, solves a captcha or contacts a private
database.  Optional keys only enable the public API of the named service.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import sqlite3
import tempfile

import config as C

DATA_DIR = C.DATA_DIR
KEY_PATH = os.path.join(DATA_DIR, "operator_keys.json")
FERNET_PATH = os.path.join(DATA_DIR, ".operator_keys.key")

VALID_SERVICES = (
    "gemini", "groq", "hibp", "abuseipdb", "otx", "virustotal", "shodan",
    "securitytrails", "intelx", "urlhaus", "ipinfo", "numverify",
)


def _utc_iso():
    return (datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))


SERVICE_ENV = {
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "hibp": "HIBP_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "intelx": "INTELX_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
    "ipinfo": "IPINFO_TOKEN",
    "numverify": "NUM_API_KEY",
}


# ------------------------------------------------------------------ key store
def _fernet():
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    try:
        if not os.path.exists(FERNET_PATH):
            os.makedirs(os.path.dirname(FERNET_PATH), exist_ok=True)
            fd = os.open(FERNET_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(Fernet.generate_key())
        with open(FERNET_PATH, "rb") as fh:
            return Fernet(fh.read())
    except Exception:
        return None


def _encrypt(value):
    raw = str(value or "").encode()
    f = _fernet()
    if f is not None:
        return "fernet:" + f.encrypt(raw).decode()
    # Honest fallback: the file is owner-only, but this is obfuscation rather
    # than strong encryption.  Install cryptography to get Fernet at rest.
    return "b64:" + base64.urlsafe_b64encode(raw).decode()


def _decrypt(value):
    value = str(value or "")
    if value.startswith("fernet:"):
        f = _fernet()
        if f is None:
            return ""
        try:
            return f.decrypt(value[7:].encode()).decode()
        except Exception:
            return ""
    if value.startswith("b64:"):
        try:
            return base64.urlsafe_b64decode(value[4:].encode()).decode()
        except Exception:
            return ""
    return ""


def _load_keys():
    try:
        with open(KEY_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_keys(data):
    try:
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".operator_keys_", dir=os.path.dirname(KEY_PATH))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, KEY_PATH)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return True
    except OSError:
        return False


def save_key(service, key):
    service = (service or "").strip().lower()
    if service not in VALID_SERVICES:
        raise ValueError("unknown service")
    if not str(key or "").strip():
        raise ValueError("missing key")
    data = _load_keys()
    data[service] = {"value": _encrypt(str(key).strip()),
                     "saved_at": _utc_iso()}
    if not _save_keys(data):
        raise RuntimeError("could not persist key")
    return True


def list_services():
    data = _load_keys()
    return sorted(k for k, v in data.items() if v.get("value"))


def delete_key(service):
    service = (service or "").strip().lower()
    data = _load_keys()
    if service in data:
        data.pop(service, None)
        _save_keys(data)
    return True


def get_key(service):
    service = (service or "").strip().lower()
    item = _load_keys().get(service) or {}
    return _decrypt(item.get("value")) or os.getenv(SERVICE_ENV.get(service, ""), "")


def key_status():
    saved = set(list_services())
    return {
        "services": sorted(saved),
        "env": {s: bool(os.getenv(env, "")) for s, env in SERVICE_ENV.items()},
        "configured": sorted(s for s in VALID_SERVICES
                             if s in saved or os.getenv(SERVICE_ENV.get(s, ""), "")),
        "valid_services": list(VALID_SERVICES),
        "encryption": "fernet" if _fernet() is not None else "owner-only-file",
    }


def validate_key(service, key):
    service = (service or "").strip().lower()
    key = str(key or "").strip()
    if service not in VALID_SERVICES:
        return {"valid": False, "service": service, "error": "unknown service",
                "mode": "format"}
    if not key:
        return {"valid": False, "service": service, "error": "missing key",
                "mode": "format"}
    checks = {
        "gemini": lambda k: k.startswith("AIza") and len(k) >= 20,
        "groq": lambda k: k.startswith("gsk_") and len(k) >= 20,
        "hibp": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{32,64}", k)),
        "abuseipdb": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{64,128}", k)),
        "otx": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{32,64}", k)),
        "virustotal": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{64}", k)),
        "shodan": lambda k: bool(re.fullmatch(r"[0-9a-zA-Z]{20,64}", k)),
        "securitytrails": lambda k: bool(re.fullmatch(r"[0-9a-zA-Z_-]{20,80}", k)),
        "intelx": lambda k: bool(re.fullmatch(r"[0-9a-fA-F-]{20,80}", k)),
        "urlhaus": lambda k: len(k) >= 12,
        "ipinfo": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{8,64}", k)),
        "numverify": lambda k: bool(re.fullmatch(r"[0-9a-fA-F]{20,64}", k)),
    }
    ok = checks[service](key)
    return {
        "valid": bool(ok),
        "service": service,
        "mode": "format",
        "note": ("Format accepted. This endpoint does not spend a live API call; "
                 "the first real query will confirm the key."),
        "error": "" if ok else "key does not match the expected format for this service",
    }


# ------------------------------------------------------------------ deep lookup
def _keys():
    return {
        "HIBP_API_KEY": get_key("hibp"),
        "ABUSEIPDB_API_KEY": get_key("abuseipdb"),
        "SHODAN_API_KEY": get_key("shodan"),
        "IPINFO_TOKEN": get_key("ipinfo"),
        "NUM_API_KEY": get_key("numverify"),
    }


def _local_matches(value):
    rows = []
    try:
        conn = sqlite3.connect(C.DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT * FROM threat_indicators WHERE indicator_value = ? "
            "ORDER BY threat_score DESC LIMIT 100", (value,))
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["tags"] = json.loads(d.get("tags") or "[]")
            except Exception:
                d["tags"] = []
            rows.append(d)
        conn.close()
    except Exception:
        pass
    return rows


def _vcard_name(value):
    """Extract the display name from an RDAP jCard/vCard structure."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("fn", "name", "registrarName", "registrant"):
            if value.get(key):
                return _vcard_name(value[key])
        return ""
    if isinstance(value, (list, tuple)):
        # jCard: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Name"]]]
        if value and value[0] == "vcard" and len(value) > 1:
            return _vcard_name(value[1])
        for part in value:
            if isinstance(part, (list, tuple)) and len(part) >= 3 and part[0] in (
                    "fn", "name", "registrarName", "registrant"):
                return str(part[3] if len(part) >= 4 else part[2] or "")
        for part in value:
            if isinstance(part, (list, tuple, dict)):
                found = _vcard_name(part)
                if found:
                    return found
    return ""


def _rdap_event(rdap, action):
    for event in (rdap.get("events") or []) if isinstance(rdap, dict) else []:
        if isinstance(event, dict) and str(event.get("eventAction", "")).lower() == action:
            return event.get("eventDate") or ""
    return ""


def _live_from_deep(detected, results):
    """Normalise the deep-search tree to the legacy dashboard card shapes.

    The old React cards expect flat fields such as ``confidence_score``,
    ``subdomain_count`` and ``name_servers``.  Keep the raw deep tree in
    ``lookup.deep`` while exposing those compatibility fields here.
    """
    live = {}
    if detected == "ip":
        ip = results.get("ip") or {}
        raw = ip.get("abuseipdb") or {}
        data = raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), dict) else raw
        if isinstance(data, dict) and data and not data.get("error"):
            live["abuseipdb"] = {
                "confidence_score": data.get("abuseConfidenceScore", data.get("confidence_score", 0)),
                "total_reports": data.get("totalReports", data.get("total_reports", 0)),
                "country": data.get("countryCode", data.get("country", "")),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", data.get("usage_type", "")),
                "last_reported": data.get("lastReportedAt", data.get("last_reported", "")),
                "is_whitelisted": data.get("isWhitelisted", data.get("is_whitelisted", False)),
            }
        shodan = ip.get("shodan") or {}
        if isinstance(shodan, dict) and shodan and not shodan.get("error"):
            ports = shodan.get("ports") or []
            services = []
            for item in shodan.get("data") or []:
                if isinstance(item, dict):
                    services.append({"port": item.get("port"),
                                     "product": item.get("product", ""),
                                     "version": item.get("version", "")})
            live["shodan"] = {
                "ports": ports if isinstance(ports, list) else [],
                "org": shodan.get("org", ""),
                "os": shodan.get("os") or "",
                "city": shodan.get("city", ""),
                "country_name": shodan.get("country_name", ""),
                "vulns": list((shodan.get("vulns") or {}).keys())
                if isinstance(shodan.get("vulns"), dict) else (shodan.get("vulns") or []),
                "services": services,
            }
        otx = ip.get("otx") or {}
        if isinstance(otx, dict) and otx and not otx.get("error"):
            live["otx"] = otx
        if isinstance(ip.get("ipinfo"), dict) and not ip["ipinfo"].get("error"):
            live["ipinfo"] = ip["ipinfo"]
        if isinstance(ip.get("geo"), dict):
            live["ipapi"] = ip["geo"]
    elif detected == "domain":
        dom = results.get("domain") or {}
        dns = dom.get("dns") if isinstance(dom.get("dns"), dict) else {}
        sub = dom.get("subdomains") if isinstance(dom.get("subdomains"), dict) else {}
        sample = sub.get("sample") or []
        live["crtsh"] = {
            "subdomain_count": sub.get("count", len(sample)),
            "subdomains": sample,
            "total_certs": sub.get("total", sub.get("count", len(sample))),
            "issuers": sub.get("issuers") or [],
        }
        rdap = dom.get("rdap") if isinstance(dom.get("rdap"), dict) else {}
        live["whois"] = {
            "registrar": _vcard_name(rdap.get("registrar")),
            "registrant": _vcard_name(rdap.get("registrant")),
            "creation_date": _rdap_event(rdap, "registration"),
            "expiration_date": _rdap_event(rdap, "expiration"),
            "name_servers": rdap.get("nameservers") or [],
        }
        live["securitytrails"] = {
            "subdomain_count": len(sample),
            "subdomains": sample,
            "a_records": dns.get("A") or [],
            "mx_records": dns.get("MX") or [],
            "ns_records": dns.get("NS") or [],
            "alexa_rank": None,
        }
        if isinstance(dom.get("urlscan"), dict):
            live["urlscan"] = dom["urlscan"]
    return live


def deep_lookup(value):
    value = (value or "").strip()
    if not value:
        return {"error": "value required", "found": False, "count": 0,
                "results": [], "live": {}, "matches": []}
    try:
        from modules.deep_search import connectors as DEEP
        deep = DEEP.deep_search(value, _keys())
    except Exception as e:
        deep = {"input": value, "detected_type": "unknown",
                "results": {}, "error": str(e)[:240]}
    local = _local_matches(value)
    detected = deep.get("detected_type") or "unknown"
    results = deep.get("results") or {}
    matches = []
    for group, payload in results.items():
        for row in _flatten_rows(payload):
            row = dict(row)
            row.setdefault("source", group)
            row.setdefault("indicator_type", detected)
            matches.append(row)
    return {
        "input": value,
        "value": value,
        "query": value,
        "detected_type": detected,
        "indicator_type": detected,
        "found": bool(local),
        "count": len(local),
        "results": local,
        "matches": matches[:200],
        "live": _live_from_deep(detected, results),
        "deep": deep,
        "note": ("Compatibility view over /api/deep/search. The dedicated "
                 "deep-search panel renders the full result tree."),
    }


def _flatten_rows(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("results", "hits", "matches", "items", "rows", "people",
                "accounts", "profiles"):
        if isinstance(value.get(key), list):
            return [v for v in value[key] if isinstance(v, dict)]
    # A single object with a URL/title is itself a row.
    if value.get("url") or value.get("title") or value.get("name"):
        return [value]
    out = []
    for child in value.values():
        out.extend(_flatten_rows(child))
    return out


# ------------------------------------------------------------------ breaches
def breach_lookup(email):
    email = (email or "").strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"email": email, "error": "invalid email format",
                "total_breaches": 0, "breaches": [], "xposedornot": {"breaches": []},
                "total_pastes": 0}
    try:
        from modules.deep_search import connectors as DEEP
        out = DEEP.email_search(email, get_key("hibp"))
    except Exception as e:
        return {"email": email, "error": str(e)[:240], "total_breaches": 0,
                "breaches": [], "xposedornot": {"breaches": []},
                "total_pastes": 0}
    breaches = []
    xon = (out.get("breaches") or {}).get("xposedornot") or {}
    raw = xon.get("breaches") or []
    if raw and isinstance(raw[0], list):
        raw = [item for group in raw for item in group]
    for item in raw:
        if isinstance(item, dict):
            breaches.append({
                "Name": item.get("name") or item.get("breach") or item.get("domain") or "Breach",
                "BreachDate": item.get("breach_date") or item.get("date") or "",
                "Description": item.get("description") or item.get("details") or "",
                "PwnCount": item.get("pwn_count") or item.get("accounts") or 0,
                "DataClasses": item.get("data_classes") or item.get("dataClasses") or [],
            })
        elif isinstance(item, str):
            breaches.append({"Name": item, "BreachDate": "", "Description": "",
                             "PwnCount": 0, "DataClasses": []})
    hibp = (out.get("breaches") or {}).get("hibp") or {}
    hibp_error = ""
    if isinstance(hibp, dict):
        if hibp.get("skipped"):
            hibp_error = hibp["skipped"]
        elif hibp.get("http"):
            hibp_error = f"HIBP HTTP {hibp['http']}"
        elif isinstance(hibp.get("error"), str):
            hibp_error = hibp["error"]
    return {
        "email": email,
        "total_breaches": len(breaches),
        "total_pastes": 0,
        "breaches": [],
        "xposedornot": {"breaches": breaches, "error": xon.get("error", "")},
        "hibp_error": hibp_error,
        "meta": out.get("meta") or {},
        "note": ("Breach existence is not proof of identity. XposedOrNot is "
                 "keyless; HIBP requires an operator key."),
    }


# ------------------------------------------------------------------ briefing
def _stats_snapshot():
    out = {"total": 0, "by_source": [], "by_type": []}
    try:
        conn = sqlite3.connect(C.DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        out["total"] = cur.execute("SELECT COUNT(*) c FROM threat_indicators").fetchone()["c"]
        out["by_source"] = [dict(r) for r in cur.execute(
            "SELECT source,COUNT(*) c FROM threat_indicators GROUP BY source "
            "ORDER BY c DESC LIMIT 8").fetchall()]
        out["by_type"] = [dict(r) for r in cur.execute(
            "SELECT indicator_type,COUNT(*) c FROM threat_indicators "
            "GROUP BY indicator_type ORDER BY c DESC LIMIT 8").fetchall()]
        conn.close()
    except Exception:
        pass
    return out


def ai_summary():
    stats = _stats_snapshot()
    try:
        from modules.module_registry import registry as MR
        reg = MR.summary()
    except Exception:
        reg = {}
    lines = [
        "## Xaxglog briefing",
        "",
        f"Generated: {_utc_iso()}",
        "",
        "### Threat collection",
        f"- Indicators in the local store: **{stats['total']:,}**",
    ]
    if stats["by_source"]:
        lines.append("- Top sources: " + ", ".join(
            f"{r['source']} ({r['c']})" for r in stats["by_source"][:5]))
    else:
        lines.append("- No collected threat rows yet. Trigger a public feed collection "
                     "or rely on the live deep-search path.")
    if stats["by_type"]:
        lines.append("- Types: " + ", ".join(
            f"{r['indicator_type']} ({r['c']})" for r in stats["by_type"][:6]))
    if reg:
        lines += [
            "",
            "### Module registry",
            f"- Declared modules: **{reg.get('total', 0):,}**",
            f"- Live-verified / fragile: **{reg.get('live_verified', 0):,}**",
            f"- Automatic evidence modules: **{reg.get('automatic', 0):,}**",
            f"- Link-outs / optional-key / blocked: "
            f"{reg.get('link_out', 0)} / {reg.get('optional_key', 0)} / {reg.get('blocked', 0)}",
        ]
    lines += [
        "",
        "### Recommended actions",
        "1. Treat name/profile matches as leads, not identity proof.",
        "2. Pivot verified indicators into case evidence and record source URLs.",
        "3. Respect rate limits and each source's terms; blocked sources stay catalog-only.",
        "",
        "_Deterministic fallback. Configure GROQ_API_KEY or GEMINI_API_KEY to use an "
        "external narrative model._",
    ]
    return {"summary": "\n".join(lines), "provider": "deterministic-template"}


# ------------------------------------------------------------------ rules
def _rule_name(value):
    base = re.sub(r"[^A-Za-z0-9_]+", "_", value or "indicator").strip("_")
    return (base or "indicator")[:48]


def _sid(value):
    return 1000000 + (int(hashlib.sha256(str(value).encode()).hexdigest()[:8], 16) % 8000000)


def template_rules(payload):
    value = str((payload or {}).get("indicator_value") or "").strip()
    itype = str((payload or {}).get("indicator_type") or "unknown").strip().lower()
    score = int((payload or {}).get("threat_score") or 0)
    tags = (payload or {}).get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    source = str((payload or {}).get("source") or "")
    desc = str((payload or {}).get("description") or "")
    safe = value.replace('"', '\\"')
    name = _rule_name(value)
    sid = _sid(value)
    snort = ""
    if itype == "ip":
        snort = (f'alert ip any any -> any any (msg:"Xaxglog {itype} {safe} score {score}"; '
                 f'sid:{sid}; rev:1;)')
    elif itype in ("domain", "url"):
        host = value
        if itype == "url":
            try:
                from urllib.parse import urlsplit
                host = urlsplit(value).hostname or value
            except Exception:
                host = value
        snort = (f'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
                 f'(msg:"Xaxglog {itype} {safe} score {score}"; '
                 f'content:"{host}"; http_host; sid:{sid}; rev:1;)')
    yara = (
        f'rule Xaxglog_{name} {{\n'
        f'  meta:\n'
        f'    author = "Xaxglog"\n'
        f'    source = "{source}"\n'
        f'    indicator_type = "{itype}"\n'
        f'    threat_score = "{score}"\n'
        f'    description = "{desc.replace(chr(34), chr(39))[:180]}"\n'
        f'  strings:\n'
        f'    $a = "{safe}" ascii wide nocase\n'
        f'  condition:\n'
        f'    any of them\n'
        f'}}'
    )
    firewall = ""
    if itype == "ip":
        firewall = f"iptables -A OUTPUT -d {value} -j DROP"
    elif itype in ("domain", "url"):
        firewall = f"# block at DNS/proxy: {value}"
    return {
        "indicator_value": value,
        "indicator_type": itype,
        "threat_score": score,
        "snort": snort,
        "yara": yara,
        "firewall": firewall,
        "rules": (("# Snort\n" + snort + "\n\n") if snort else "") + "# YARA\n" + yara,
        "provider": "deterministic-template",
    }


def generate_rules(payload):
    out = template_rules(payload)
    out["mode"] = "deterministic"
    out["note"] = ("Generated from the indicator only. Review before deployment; "
                   "AI rule generation is optional and disabled unless a key is set.")
    return out


def bulk_protect(payload):
    payload = payload or {}
    period = str(payload.get("period") or "1day")
    min_score = int(payload.get("min_score") or 0)
    hours = {"12hr": 12, "1day": 24, "1week": 168, "1month": 720}.get(period)
    rows = []
    try:
        conn = sqlite3.connect(C.DB_PATH)
        conn.row_factory = sqlite3.Row
        sql = "SELECT * FROM threat_indicators WHERE threat_score >= ?"
        args = [min_score]
        if hours:
            since = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()
            sql += " AND (first_seen IS NULL OR first_seen >= ?)"
            args.append(since)
        sql += " ORDER BY threat_score DESC LIMIT 500"
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
        conn.close()
    except Exception:
        rows = []
    rules, yara, snort = [], [], []
    for row in rows:
        item = template_rules(row)
        rules.append(item["rules"])
        yara.append(item["yara"])
        if item["snort"]:
            snort.append(item["snort"])
    uniq_ips = sorted({r.get("indicator_value") for r in rows
                       if (r.get("indicator_type") or "").lower() == "ip"})
    uniq_domains = sorted({r.get("indicator_value") for r in rows
                           if (r.get("indicator_type") or "").lower() in ("domain", "url")})
    return {
        "period": period,
        "min_score": min_score,
        "indicator_count": len(rows),
        "unique_ips": len(uniq_ips),
        "unique_domains": len(uniq_domains),
        "snort_rules": len(snort),
        "yara_rules": len(yara),
        "script": "\n\n".join(rules),
        "yara": "\n\n".join(yara),
        "snort": "\n".join(snort),
        "mode": "deterministic",
        "provider": "deterministic-template",
        "note": ("Generated from locally collected public indicators. "
                 "Review and test rules before deployment."),
    }
