"""Xaxglog certstream — certificate-transparency watch for watched domains.

Open, keyless sources:
  - crt.sh JSON API (crt.sh) — CT log search, no key, self-throttled.

Workflow: register a domain to watch, the poller asks crt.sh for the latest
certificates naming it, diffs against what was already seen, stores new certs
as custody artifacts and raises alerts (same alert table the watchlist sweeper
uses). A background daemon (start_daemon) keeps the polling off the request
path. Complements the trackers module (DNS/whois/content drift) with the CT
axis: a new cert often means new infra before DNS flips.

Lawful-use note: reads only public CT logs. Passive reconnaissance.
"""
import json
import os
import threading
import time

import db
import config as C

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
CRTSH = "https://crt.sh/?q={q}&output=json"
STORE = os.path.join(C.DATA_DIR, "certstream_seen.json")


def _load_seen():
    try:
        with open(STORE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_seen(seen):
    try:
        tmp = STORE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(seen, f)
        os.replace(tmp, STORE)
    except OSError:
        pass


def search(domain, limit=200):
    """Query crt.sh for certificates naming a domain (keyless)."""
    try:
        domain = (domain or "").strip().lower().strip(".")
        if not domain or " " in domain:
            return {"status": "error", "error": "invalid domain", "certs": []}
        import requests
        r = requests.get(CRTSH.format(q="%." + domain), headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}", "certs": []}
        try:
            rows = r.json()
        except ValueError:
            return {"status": "error", "error": "non-JSON (crt.sh busy?)", "certs": []}
        certs = []
        for row in rows[:limit]:
            certs.append({
                "id": row.get("id"),
                "common_name": row.get("common_name"),
                "name_value": (row.get("name_value") or "").split("\n"),
                "issuer": row.get("issuer_name"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "seq": row.get("sequence_number"),
            })
        db.audit("system", "certstream.search", domain, f"n={len(certs)}")
        return {"status": "ok", "domain": domain, "count": len(certs), "certs": certs}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "certs": []}


def watch(domain, case_id=None, created_by="system"):
    """Register a domain on the CT watch list (idempotent)."""
    try:
        domain = (domain or "").strip().lower().strip(".")
        if not domain or " " in domain:
            return {"status": "error", "error": "invalid domain"}
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO certstream_watch (domain,case_id,enabled,created_by,created_at)"
            " VALUES (?,?,1,?,?)",
            (domain, case_id, created_by, db.utcnow()),
        )
        c.commit()
        db.audit(created_by, "certstream.watch", domain, f"case={case_id}")
        return {"status": "ok", "domain": domain, "watching": True}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(domain):
    try:
        c = db.get_db()
        c.execute("UPDATE certstream_watch SET enabled=0 WHERE domain=?", ((domain or "").lower(),))
        c.commit()
        return {"status": "ok", "domain": domain, "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        if case_id is not None:
            rows = c.execute(
                "SELECT id,domain,case_id,last_run FROM certstream_watch WHERE enabled=1 AND case_id=?",
                (case_id,),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id,domain,case_id,last_run FROM certstream_watch WHERE enabled=1"
            ).fetchall()
        return {"status": "ok", "watch": [dict(r) for r in rows]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


SCHEMA = """
CREATE TABLE IF NOT EXISTS certstream_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT UNIQUE NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
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


def check_domain(domain):
    """Poll crt.sh once for a watched domain, diff vs seen store, alert on new."""
    out = search(domain)
    if out.get("status") != "ok":
        return {"status": "skipped", "domain": domain, "reason": out.get("error")}
    seen = _load_seen()
    known = set(seen.get(domain, []))
    fresh = []
    for cert in out["certs"]:
        cid = str(cert.get("id"))
        if cid and cid not in known:
            known.add(cid)
            fresh.append(cert)
    seen[domain] = list(known)[-2000:]
    _save_seen(seen)
    if fresh:
        c = db.get_db()
        for cert in fresh[:20]:
            db.store_artifact(None, None, "cert", "certstream", cert, "certstream-daemon")
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (None, db.utcnow(), "medium",
                 f"New TLS certificate for {domain}: {cert.get('common_name')}",
                 json.dumps(cert, default=str)[:900]),
            )
        c.commit()
    c = db.get_db()
    c.execute("UPDATE certstream_watch SET last_run=? WHERE domain=?", (db.utcnow(), domain))
    c.commit()
    return {"status": "ok", "domain": domain, "new": len(fresh), "total": out["count"]}


def check_all():
    rows = db.get_db().execute("SELECT domain FROM certstream_watch WHERE enabled=1").fetchall()
    results = []
    for row in rows:
        results.append(check_domain(row["domain"]))
        time.sleep(2)  # crt.sh politeness
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=1800):
    """Background CT watch poller — never blocks boot."""
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="certstream").start()
    return True
