"""Xaxglog hostwatch — host exposure drift for watched IPs (banner/port intel).

Open, keyless sources:
  - Shodan InternetDB (internetdb.shodan.io) — ports, CPE, hostnames, tags
    for an IP. Keyless, no rate-plan needed.
  - RDAP (rdap.org) — IP allocation/registration record.
Optional (env SHODAN_API_KEY): full Shodan host/banner detail + vulns.

Workflow: watch IPs or let the module resolve them from watched domains,
fingerprint what the host exposes (ports set + CPE set), diff on re-check,
alert on any drift (new port = new service = new pivot). Feeds the trackers
alert table so it rides the same operator alert stream.

Lawful-use note: passive queries against public scan databases only. No
probing of the target host itself beyond what the index already holds.
"""
import json
import os
import threading
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
INTERNETDB = "https://internetdb.shodan.io/{ip}"
RDAP = "https://rdap.org/ip/{ip}"


SCHEMA = """
CREATE TABLE IF NOT EXISTS hostwatch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT UNIQUE NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  fingerprint TEXT DEFAULT '{}',
  last_run TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        c.commit()
    except Exception:
        pass


def _fingerprint(ip):
    """Current exposure fingerprint: ports + CPE + hostnames + tags."""
    import requests
    fp = {"ip": ip, "ports": [], "cpes": [], "hostnames": [], "tags": []}
    try:
        r = requests.get(INTERNETDB.format(ip=ip), headers=UA, timeout=T)
        if r.status_code == 200:
            j = r.json()
            fp["ports"] = sorted(j.get("ports") or [])
            fp["cpes"] = sorted(j.get("cpes") or [])
            fp["hostnames"] = sorted(j.get("hostnames") or [])
            fp["tags"] = sorted(j.get("tags") or [])
        elif r.status_code == 404:
            fp["note"] = "not indexed by InternetDB"
        else:
            fp["note"] = f"InternetDB HTTP {r.status_code}"
    except Exception as e:
        fp["note"] = str(e)[:120]
    return fp


def watch(ip, case_id=None, created_by="system"):
    """Register an IP on the host-exposure watch (fingerprints on first run)."""
    try:
        init_schema()
        ip = (ip or "").strip()
        if not ip or " " in ip:
            return {"status": "error", "error": "invalid ip"}
        fp = _fingerprint(ip)
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO hostwatch (ip,case_id,fingerprint,created_by,created_at)"
            " VALUES (?,?,?,?,?)",
            (ip, case_id, json.dumps(fp), created_by, db.utcnow()),
        )
        c.commit()
        db.audit(created_by, "hostwatch.watch", ip, f"case={case_id} ports={fp.get('ports')}")
        return {"status": "ok", "ip": ip, "fingerprint": fp}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(ip):
    try:
        c = db.get_db()
        c.execute("UPDATE hostwatch SET enabled=0 WHERE ip=?", ((ip or "").strip(),))
        c.commit()
        return {"status": "ok", "ip": ip, "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        q = "SELECT id,ip,case_id,last_run,fingerprint FROM hostwatch WHERE enabled=1"
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        rows = c.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["fingerprint"] = json.loads(d.get("fingerprint") or "{}")
            except ValueError:
                d["fingerprint"] = {}
            out.append(d)
        return {"status": "ok", "watch": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def rdap(ip):
    """RDAP allocation/registration record for an IP (keyless)."""
    try:
        import requests
        r = requests.get(RDAP.format(ip=ip), headers=UA, timeout=T,
                         allow_redirects=True)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        return {"status": "ok", "ip": ip, "rdap": {
            "handle": j.get("handle"),
            "name": j.get("name"),
            "type": j.get("type"),
            "country": j.get("country"),
            "start_address": j.get("startAddress"),
            "end_address": j.get("endAddress"),
            "parent_handle": j.get("parentHandle"),
            "entities": [
                {"handle": e.get("handle"),
                 "roles": e.get("roles"),
                 "vcard": json.dumps(e.get("vcardArray"), default=str)[:400]}
                for e in (j.get("entities") or [])[:6]
            ],
        }}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def check_ip(ip):
    """Re-fingerprint a watched IP, diff vs baseline, alert on drift."""
    init_schema()
    row = db.get_db().execute(
        "SELECT id,case_id,fingerprint FROM hostwatch WHERE ip=? AND enabled=1", (ip,)
    ).fetchone()
    if not row:
        return {"status": "skipped", "ip": ip, "reason": "not watched"}
    try:
        old = json.loads(row["fingerprint"] or "{}")
    except ValueError:
        old = {}
    new = _fingerprint(ip)
    drift = {}
    for key in ("ports", "cpes", "hostnames", "tags"):
        added = sorted(set(new.get(key, [])) - set(old.get(key, [])))
        removed = sorted(set(old.get(key, [])) - set(new.get(key, [])))
        if added or removed:
            drift[key] = {"added": added, "removed": removed}
    c = db.get_db()
    c.execute("UPDATE hostwatch SET fingerprint=?, last_run=? WHERE id=?",
              (json.dumps(new), db.utcnow(), row["id"]))
    c.commit()
    if drift:
        db.store_artifact(row["case_id"], None, "hostwatch", "internetdb",
                          {"ip": ip, "drift": drift}, "hostwatch-daemon")
        c.execute(
            "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
            (row["case_id"], db.utcnow(), "medium",
             f"Host exposure drift on {ip}: " + ", ".join(drift.keys()),
             json.dumps(drift, default=str)[:900]),
        )
        c.commit()
    return {"status": "ok", "ip": ip, "drift": drift or None, "fingerprint": new}


def check_all():
    init_schema()
    rows = db.get_db().execute("SELECT ip FROM hostwatch WHERE enabled=1").fetchall()
    results = []
    for r in rows:
        results.append(check_ip(r["ip"]))
        time.sleep(1)
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=900):
    """Background host-exposure drift poller — never blocks boot."""
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="hostwatch").start()
    return True
