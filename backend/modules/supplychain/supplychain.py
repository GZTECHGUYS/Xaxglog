"""Xaxglog supplychain — package-registry typosquat + typosquat watch.

Keyless core:
  - PyPI JSON API (pypi.org/pypi/<pkg>/json) — existence, owner, release
    dates, project URLs.
  - npm registry (registry.npmjs.org) — existence + maintainers + time.
  - crates.io (crates.io/api/v1/crates) — existence + updated_at.
  - Go modules proxy (proxy.golang.org/<path>/@latest) — existence.

Check a brand across registries: does an unexpected package share its
name space (typosquat, dependency-confusion bait, name-squat)? For each
hit: maintainer overlap, publish recency (fresh = suspicious for a
non-existent-in-your-CI name), README URL pointing off-project.

Watch mode: register brand names -> periodic sweep -> typed alerts on new
registry hits (e.g. `requests-sec` appearing on npm the week you publish
an internal `requests-sec`).

Lawful-use note: public package registries. No package installation, no
code execution — metadata only.
"""
import datetime
import json
import os
import threading
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
PYPI = "https://pypi.org/pypi/{name}/json"
NPM = "https://registry.npmjs.org/{name}"
CRATES = "https://crates.io/api/v1/crates/{name}"
GOLANG = "https://proxy.golang.org/{name}/@latest"
REGISTRIES = ("pypi", "npm", "crates", "golang")

FAMILIES = ["omission", "transposition", "hyphen", "underscore", "double-hit",
            "plural", "lookalike-tld", "affix"]


def _variants(brand):
    b = (brand or "").strip().lower().replace(" ", "-")
    if len(b) < 3:
        return []
    out = set()
    for i in range(len(b)):
        out.add(b[:i] + b[i + 1:])
        if i + 1 < len(b):
            out.add(b[:i] + b[i + 1] + b[i] + b[i + 2:])
        out.add(b[:i] + "-" + b[i:])
        out.add(b[:i] + "_" + b[i:])
    out.update({b + s for s in ("-py", "-sdk", "-client", "-js", "-go",
                                "-rust", "-cli", "-core", "2", "v2", "s")})
    out.update({b.replace("-", ""), b.replace("_", "-")})
    return sorted(v for v in out if 3 <= len(v) <= 40 and v != b)


def _probe(reg, name):
    import requests
    try:
        if reg == "pypi":
            r = requests.get(PYPI.format(name=name), headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                info = j.get("info", {})
                rel = j.get("releases") or {}
                newest = max((d for ds in rel.values() for d in ds),
                             key=lambda x: x.get("upload_time", ""),
                             default=None)
                return {"exists": True, "author": info.get("author")
                        or info.get("maintainer"),
                        "summary": (info.get("summary") or "")[:160],
                        "home": info.get("home_page") or info.get("project_url"),
                        "first_release": min((d.get("upload_time", "") for ds in
                                              rel.values() for d in ds),
                                             default=None),
                        "latest_upload": (newest or {}).get("upload_time"),
                        "versions": len(rel)}
        elif reg == "npm":
            r = requests.get(NPM.format(name=name), headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                times = j.get("time") or {}
                versions = [v for v in times if v not in ("created", "modified")]
                return {"exists": True,
                        "maintainers": [m.get("name")
                                        for m in (j.get("maintainers") or [])][:5],
                        "description": (j.get("description") or "")[:160],
                        "created": times.get("created"),
                        "modified": times.get("modified"),
                        "versions": len(versions),
                        "unpublished": j.get("time", {}).get("unpublished") is not None}
        elif reg == "crates":
            r = requests.get(CRATES.format(name=name), headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                c = (j.get("crate") or {})
                return {"exists": True, "max_version": c.get("max_version"),
                        "created": c.get("created_at"),
                        "updated": c.get("updated_at"),
                        "description": (c.get("description") or "")[:160],
                        "owner": ((j.get("versions") or [{}])[0]
                                  .get("published_by") or {}).get("username")}
        elif reg == "golang":
            r = requests.get(GOLANG.format(name=name), headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                return {"exists": True, "version": j.get("Version"),
                        "time": j.get("Time")}
    except Exception:
        return None
    return None


def check(brand, registries=None, variants=40):
    """Probe brand + generated variants across package registries."""
    try:
        registries = registries or REGISTRIES
        if not brand or " " in brand:
            return {"status": "error", "error": "provide the package/brand name"}
        names = [brand] + _variants(brand)[:variants]
        findings = []
        base_ok = {reg: bool(_probe(reg, brand)) for reg in registries}
        for name in names:
            for reg in registries:
                hit = _probe(reg, name)
                if hit:
                    hit.update({"name": name, "registry": reg,
                                "is_brand_root": name == brand})
                    findings.append(hit)
                    time.sleep(0.2)
        suspicious = [f for f in findings if not f["is_brand_root"]]
        db.audit("system", "supplychain.check", brand,
                 f"checked={len(names)} hits={len(findings)}")
        return {"status": "ok", "brand": brand,
                "brand_present": {k: bool(v) for k, v in base_ok.items()},
                "checked_names": len(names),
                "findings": findings,
                "squat_risk": ("high" if suspicious else "low"),
                "note": "unexpected variants sharing your brand are dependency-"
                        "confusion / typosquat surface"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "findings": []}


SCHEMA = """
CREATE TABLE IF NOT EXISTS supplychain_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  brand TEXT UNIQUE NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  snapshot TEXT DEFAULT '[]',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        # additive migration: last_run column (older dev DBs predate it)
        try:
            c.execute("ALTER TABLE supplychain_watch ADD COLUMN last_run TEXT")
        except Exception:
            pass
        c.commit()
    except Exception:
        pass


def watch(brand, case_id=None, created_by="system"):
    init_schema()
    try:
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO supplychain_watch (brand,case_id,created_by,created_at)"
            " VALUES (?,?,?,?)",
            ((brand or "").strip().lower(), case_id, created_by, db.utcnow()))
        c.commit()
        db.audit(created_by, "supplychain.watch", brand, f"case={case_id}")
        return {"status": "ok", "brand": brand, "watching": True}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(brand):
    try:
        c = db.get_db()
        c.execute("UPDATE supplychain_watch SET enabled=0 WHERE brand=?",
                  ((brand or "").lower(),))
        c.commit()
        return {"status": "ok", "brand": brand, "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch():
    try:
        rows = db.get_db().execute(
            "SELECT id,brand,case_id,last_run FROM supplychain_watch WHERE enabled=1"
        ).fetchall()
        return {"status": "ok", "watch": [dict(r) for r in rows]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def check_all():
    init_schema()
    rows = db.get_db().execute(
        "SELECT id,brand,case_id,snapshot FROM supplychain_watch WHERE enabled=1"
    ).fetchall()
    results = []
    for row in rows:
        out = check(row["brand"], variants=15)
        now = sorted(f"{f['registry']}:{f['name']}"
                     for f in out.get("findings", []) if not f.get("is_brand_root"))
        try:
            before = set(json.loads(row["snapshot"] or "[]"))
        except ValueError:
            before = set()
        new = sorted(set(now) - before)
        c = db.get_db()
        c.execute("UPDATE supplychain_watch SET snapshot=?, last_run=? WHERE id=?",
                  (json.dumps(now), db.utcnow(), row["id"]))
        if new:
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (row["case_id"], db.utcnow(), "high",
                 f"New registry package near {row['brand']}: {', '.join(new[:5])}",
                 json.dumps({"new": new})[:900]))
        c.commit()
        results.append({"brand": row["brand"], "new": new, "count": len(now)})
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=10800):
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="supplychain").start()
    return True
