"""Xaxglog darknet — anonymizer-network exposure watch (Tor/VPN/proxy lists).

Open, keyless sources:
  - Tor Project bulk exit list (check.torproject.org/torbulkexitlist)
  - dan.me.uk Tor list (exit + relay variants, rate-limited: 1 req / ~30 min)
  - ipsum.lol aggregated blocklists (multiple threat categories)
  - blocklist.de (attacker IPs reported by their sensors, keyless text lists)

Use: check whether infra you care about (your own estate, a monitored target
under authorization) is an anonymizer node, or whether known-bad hosts sit
next to it. Watch an IP to get alerted when it appears on any of these lists.
Complements hostwatch (what a host exposes) and infra (PTR/ASN pivots).

Lawful-use note: passive consumption of published blocklists. Detection and
exposure awareness only — no probing, no de-anonymization attacks.
"""
import json
import os
import threading
import time

import db
import config as C

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
TOR_BULK = "https://check.torproject.org/torbulkexitlist"
DANME_EXIT = "https://www.dan.me.uk/torlist/?exit"
DANME_RELAY = "https://www.dan.me.uk/torlist/?relay"
IPSUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
BLOCKLIST_DE = "https://www.blocklist.de/downloads/iplist.txt"
STORE = os.path.join(C.DATA_DIR, "darknet_lists")


def _fetch_text(url, wait=0):
    import requests
    if wait:
        time.sleep(wait)
    r = requests.get(url, headers=UA, timeout=T)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} for {url.split('/')[2]}")
    return r.text


def tor_exits():
    """Current Tor bulk exit nodes (keyless)."""
    try:
        text = _fetch_text(TOR_BULK)
        ips = sorted({ln.strip() for ln in text.splitlines() if ln.strip()})
        db.audit("system", "darknet.tor_exits", "-", f"n={len(ips)}")
        return {"status": "ok", "source": "torproject", "count": len(ips), "ips": ips}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "ips": []}


def tor_full(wait=60):
    """Exit + relay lists from dan.me.uk — heavy rate limit, waits between calls."""
    try:
        exits = [ln.strip() for ln in _fetch_text(DANME_EXIT).splitlines() if ln.strip()]
        relays = [ln.strip() for ln in _fetch_text(DANME_RELAY, wait=wait).splitlines()
                  if ln.strip()]
        return {"status": "ok", "source": "dan.me.uk",
                "exits": len(exits), "relays": len(relays),
                "exit_ips": sorted(set(exits)), "relay_ips": sorted(set(relays))[:2000]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def ipsum(level=3):
    """ipsum aggregated blocklist — threat-category IPs by confidence level."""
    try:
        text = _fetch_text(IPSUM)
        current = 0
        buckets = {}
        for ln in text.splitlines():
            ln = ln.strip()
            if ln.startswith("#"):
                continue
            if ln.startswith("level"):
                try:
                    current = int(ln.split()[1])
                except (IndexError, ValueError):
                    current = 0
                continue
            if current == int(level) and ln:
                buckets.setdefault(current, []).append(ln)
        ips = sorted(set(buckets.get(int(level), [])))
        db.audit("system", "darknet.ipsum", f"level={level}", f"n={len(ips)}")
        return {"status": "ok", "source": "ipsum", "level": int(level),
                "count": len(ips), "ips": ips}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "ips": []}


def blocklist_de():
    """blocklist.de attacker IPs (keyless)."""
    try:
        text = _fetch_text(BLOCKLIST_DE)
        ips = sorted({ln.strip() for ln in text.splitlines()
                      if ln.strip() and not ln.startswith("#")})
        return {"status": "ok", "source": "blocklist.de", "count": len(ips), "ips": ips}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "ips": []}


def _known_set():
    """All fetched lists merged into one set (cached to data/darknet_lists)."""
    os.makedirs(STORE, exist_ok=True)
    merged = {}
    for name, fn in (("tor", tor_exits), ("ipsum", lambda: ipsum(3)),
                     ("blocklist_de", blocklist_de)):
        cache = os.path.join(STORE, name + ".json")
        fresh = False
        try:
            if os.path.getmtime(cache) < time.time() - 3600:
                raise OSError("stale")
        except OSError:
            out = fn()
            if out.get("status") == "ok":
                try:
                    with open(cache + ".tmp", "w", encoding="utf-8") as f:
                        json.dump(out.get("ips", []), f)
                    os.replace(cache + ".tmp", cache)
                except OSError:
                    pass
                fresh = True
        if not fresh:
            try:
                with open(cache, encoding="utf-8") as f:
                    out = {"status": "ok", "ips": json.load(f)}
            except (OSError, ValueError):
                continue
        for ip in out.get("ips", []):
            merged.setdefault(ip, []).append(name)
    return merged


def check_ip(ip):
    """Which anonymizer/threat lists is this IP on right now?"""
    try:
        ip = (ip or "").strip()
        merged = _known_set()
        sources = merged.get(ip)
        if not sources:
            return {"status": "ok", "ip": ip, "listed": False, "sources": []}
        db.audit("system", "darknet.check_ip", ip, f"sources={sources}")
        return {"status": "ok", "ip": ip, "listed": True, "sources": sources}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


SCHEMA = """
CREATE TABLE IF NOT EXISTS darknet_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT UNIQUE NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_sources TEXT DEFAULT '[]',
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


def watch(ip, case_id=None, created_by="system"):
    init_schema()
    try:
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO darknet_watch (ip,case_id,created_by,created_at)"
            " VALUES (?,?,?,?)",
            ((ip or "").strip(), case_id, created_by, db.utcnow()),
        )
        c.commit()
        db.audit(created_by, "darknet.watch", ip, f"case={case_id}")
        return {"status": "ok", "ip": ip, "watching": True}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(ip):
    try:
        c = db.get_db()
        c.execute("UPDATE darknet_watch SET enabled=0 WHERE ip=?", ((ip or "").strip(),))
        c.commit()
        return {"status": "ok", "ip": ip, "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        q = "SELECT id,ip,case_id,last_sources FROM darknet_watch WHERE enabled=1"
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        return {"status": "ok", "watch": [dict(r) for r in c.execute(q, args).fetchall()]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def check_all():
    init_schema()
    merged = _known_set()
    rows = db.get_db().execute("SELECT id,ip,case_id,last_sources FROM darknet_watch WHERE enabled=1").fetchall()
    results = []
    for row in rows:
        now_sources = sorted(merged.get(row["ip"], []))
        try:
            before = set(json.loads(row["last_sources"] or "[]"))
        except ValueError:
            before = set()
        new_sources = sorted(set(now_sources) - before)
        c = db.get_db()
        c.execute("UPDATE darknet_watch SET last_sources=? WHERE id=?",
                  (json.dumps(now_sources), row["id"]))
        if new_sources:
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (row["case_id"], db.utcnow(), "high",
                 f"{row['ip']} now listed on: {', '.join(new_sources)}",
                 json.dumps({"new_sources": new_sources})[:900]),
            )
            db.store_artifact(row["case_id"], None, "darknet", "blocklists",
                              {"ip": row["ip"], "sources": now_sources}, "darknet-daemon")
        c.commit()
        results.append({"ip": row["ip"], "sources": now_sources, "new": new_sources})
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=3600):
    """Background list-refresh + watch diff — never blocks boot."""
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="darknet").start()
    return True
