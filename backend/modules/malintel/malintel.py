"""Xaxglog malintel — malware sample/hash intelligence (keyless core).

Open sources:
  - MalwareBazaar API (bazaar.abuse.ch) — hash lookup, tag/family info,
    signature details. Keyless POST (AUTH-KEY optional for submit).
  - URLhaus hash lookup (urlhaus-api.abuse.ch) — file hash -> URLs that
    served it. Keyless.
  - AlienVault OTX indicators (otx.alienvault.com) — pulse context for an
    IP/domain. Keyless with X-OTX-HEADERS UA.

Local:
  - sha256/md5/sha1 self-hash + type sniff of a local file (magic bytes),
    stored as custody artifact.
Optional: YARA scan if `yara-python` + rules installed (CAPS).

Lawful-use note: lookups against malware repositories. The module fetches
*metadata about* samples — it never downloads sample bodies.
"""
import hashlib
import os
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
MB = "https://mb-api.abuse.ch/api/v1/"
UH = "https://urlhaus-api.abuse.ch/v1/"
OTX_HOST = "https://otx.alienvault.com/api/v1/indicators/{type}/{val}/general"
CAPS_YARA = False
try:
    import yara  # noqa: F401
    CAPS_YARA = True
except Exception:
    pass

MAGIC = [
    (b"MZ", "PE executable (Windows)"),
    (b"\x7fELF", "ELF executable (Linux)"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound (legacy Office/doc)"),
    (b"PK\x03\x04", "ZIP/OOXML container"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
]


def sniff(blob):
    for sig, name in MAGIC:
        if blob.startswith(sig):
            return name
    return "unknown binary"


def file_hashes(path):
    """Hash + magic-sniff a local file (metadata only, no execution)."""
    try:
        if not os.path.isfile(path):
            return {"status": "error", "error": "file not found"}
        h256, hmd5, hsha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
        with open(path, "rb") as f:
            head = f.read(4096)
            h256.update(head)
            hmd5.update(head)
            hsha1.update(head)
            f.seek(0)
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h256.update(chunk)
        out = {"file": os.path.basename(path),
               "size": os.path.getsize(path),
               "sha256": h256.hexdigest(), "md5": hmd5.hexdigest(),
               "sha1": hsha1.hexdigest(), "kind": sniff(head)}
        out["yara"] = yara_scan(path) if CAPS_YARA else None
        return {"status": "ok", "hashes": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def _mb(query_type, value):
    import requests
    r = requests.post(MB, headers=UA,
                      data={"query": query_type, "hash": value}, timeout=T)
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}
    j = r.json()
    if j.get("query_status") == "no_results":
        return {"empty": True}
    return j


def hash_lookup(sha256):
    """MalwareBazaar + URLhaus hash intelligence (keyless)."""
    try:
        sha256 = (sha256 or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            return {"status": "error", "error": "provide a sha256 hex digest"}
        out = {"sha256": sha256, "malwarebazaar": None, "urlhaus": None}
        mb = _mb("get_info", sha256)
        if mb.get("empty"):
            out["malwarebazaar"] = "not known"
        elif mb.get("error"):
            out["malwarebazaar"] = mb["error"]
        else:
            data = mb.get("data", [{}])[0]
            out["malwarebazaar"] = {
                "signature": data.get("signature"),
                "file_type": data.get("file_type"),
                "file_name": data.get("file_name"),
                "file_size": data.get("file_size"),
                "tags": data.get("tags"),
                "first_seen": data.get("first_seen"),
                "delivery": data.get("delivery_method"),
                "sha256_hash": data.get("sha256_hash"),
            }
        import requests
        r = requests.post(UH + "file", headers=UA,
                          data={"sha256_hash": sha256}, timeout=T)
        if r.status_code == 200:
            j = r.json()
            st = j.get("query_status")
            if st == "ok":
                out["urlhaus"] = {
                    "urls": (j.get("urls") or [])[:20],
                    "sig": j.get("signature"),
                    "file_type": j.get("file_type"),
                }
            elif st == "no_results":
                out["urlhaus"] = "not known"
        db.audit("system", "malintel.hash_lookup", sha256[:16],
                 f"mb={type(out['malwarebazaar']).__name__}")
        known = (isinstance(out["malwarebazaar"], dict)
                 or isinstance(out["urlhaus"], dict))
        return {"status": "ok", "known_malicious": known, "report": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def ioc(ip_or_domain, otx_key=None):
    """OTX pulse context for an IP/domain (keyless anonymous works)."""
    try:
        val = (ip_or_domain or "").strip().lower()
        if not val:
            return {"status": "error", "error": "empty indicator"}
        itype = "IPv4" if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", val) \
            else "domain" if "." in val and "/" not in val else None
        if not itype:
            return {"status": "error", "error": "provide an IPv4 or domain"}
        import requests
        headers = dict(UA)
        if otx_key:
            headers["X-OTX-API-KEY"] = otx_key
        r = requests.get(OTX_HOST.format(type=itype, val=val),
                         headers=headers, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"OTX HTTP {r.status_code}"}
        j = r.json()
        pulses = [{
            "name": p.get("name"), "created": p.get("created"),
            "adversary": p.get("adversary"),
            "malware_families": p.get("malware_families"),
            "tags": p.get("tags"),
        } for p in (j.get("pulse_info", {}).get("pulses") or [])[:15]]
        return {"status": "ok", "indicator": val, "type": itype,
                "pulse_count": j.get("pulse_info", {}).get("count", 0),
                "reputation": j.get("reputation"),
                "pulses": pulses}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def yara_scan(path, rules_path=None):
    """Optional YARA scan (needs yara-python + your rule files)."""
    if not CAPS_YARA:
        return {"status": "unconfigured", "error": "yara-python not installed"}
    try:
        import yara
        rules_path = rules_path or os.getenv("YARA_RULES_DIR")
        if not rules_path or not os.path.isdir(rules_path):
            return {"status": "unconfigured",
                    "error": "set YARA_RULES_DIR to a directory of .yar files"}
        rules = yara.compile(filepath=rules_path) if os.path.isdir(rules_path) \
            else yara.compile(filepath=rules_path)
        matches = rules.match(path, timeout=30)
        return {"status": "ok", "matches": [{"rule": m.rule, "tags": m.tags,
                                             "meta": dict(m.meta)}
                                            for m in matches]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def attach(case_id, path, queried_by="system"):
    """Hash a file + look it up; store report as case artifact."""
    fh = file_hashes(path)
    if fh.get("status") != "ok":
        return fh
    intel = hash_lookup(fh["hashes"]["sha256"])
    report = {"hashes": fh["hashes"],
              "intel": intel.get("report") or intel}
    art = db.store_artifact(case_id, None, "malware", "malintel", report, queried_by)
    db.audit(queried_by, "malintel.attach", path, f"artifact={art['id']}")
    return {"status": "ok", "report": report, "artifact": art}
