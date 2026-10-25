"""Xaxglog watchlist sweep engine.

Background thread that runs due watchlist checks on an interval, compares
results against the entity graph, and raises alerts on new findings (new
breach, new subdomain, new handle, threat-score change). Mirrors the existing
threat_intel collector daemon pattern — never blocks boot.
"""
import json
import threading
import time

import db

try:
    from modules.cases import cases as CASES
except Exception:
    import cases as CASES

# --------------------------------------------------------------- hook registry
# Fan-out hooks piggyback on due sweeps: other modules register a callable
# here and get invoked once per due watchlist after the standard checks run.
HOOKS = {}


def register_hook(name, fn):
    """Register a hook invoked as fn(watch) after each due sweep. Never raises."""
    try:
        if name and callable(fn):
            HOOKS[str(name)] = fn
            return True
    except Exception:
        pass
    return False


def run_hooks(watch, results=None):
    """Run every registered hook against `watch`; never raises.

    Returns [{"hook": name, "ok": bool, "summary": ...}, ...]. Hook failures
    are captured per-hook so one bad hook cannot break the sweep.
    """
    out = []
    try:
        for name in list(HOOKS.keys()):
            try:
                ret = HOOKS[name](watch)
                out.append({"hook": name, "ok": True,
                            "summary": str(ret)[:200] if ret is not None else "ok"})
            except Exception as e:
                out.append({"hook": name, "ok": False, "summary": str(e)[:150]})
    except Exception:
        pass
    return out


def _check_entity(watch):
    """Run the requested checks for a watchlist entry, return findings."""
    etype = watch["entity_type"]
    value = watch["entity_value"]
    checks = watch.get("checks") or []
    findings = []

    try:
        from modules.deep_search import connectors as DEEP
    except Exception:
        DEEP = None

    if etype == "domain" and DEEP and ("subdomains" in checks or not checks):
        d = DEEP.domain_search(value)
        subs = (d.get("subdomains") or {}).get("sample", [])
        known = _known_values(watch["case_id"], "domain")
        new = [s for s in subs if s not in known]
        if new:
            findings.append({"kind": "new_subdomains", "severity": "medium",
                             "message": f"{len(new)} new subdomain(s) on {value}",
                             "detail": {"new": new[:50]}})

    if etype == "email" and DEEP and ("breaches" in checks or not checks):
        e = DEEP.email_search(value, _key("HIBP_API_KEY"))
        br = (e.get("breaches") or {}).get("xposedornot", {})
        if isinstance(br, dict) and br.get("Success") == "true":
            names = br.get("breaches", [])
            known = _known_breaches(watch["case_id"], value)
            new = [b for b in names if b not in known]
            if new:
                findings.append({"kind": "new_breach", "severity": "high",
                                 "message": f"{value} appeared in {len(new)} new breach(es)",
                                 "detail": {"new": new}})

    if etype == "username" and DEEP and ("handles" in checks or not checks):
        u = DEEP.username_search(value)
        hits = u.get("hits", [])
        known = _known_values(watch["case_id"], "handle")
        new = [h["url"] for h in hits if h.get("url") and h["url"] not in known]
        if new:
            findings.append({"kind": "new_handle", "severity": "low",
                             "message": f"{value}: {len(new)} new platform profile(s)",
                             "detail": {"new": new[:50]}})

    return findings


def _known_values(case_id, etype):
    c = db.get_db()
    rows = c.execute("SELECT value FROM entities WHERE case_id=? AND type=?",
                     (case_id, etype)).fetchall()
    return {r["value"] for r in rows}


def _known_breaches(case_id, email):
    c = db.get_db()
    rows = c.execute(
        "SELECT content FROM artifacts WHERE case_id=? AND source LIKE 'recon:%'"
        " OR source LIKE 'deep:%'", (case_id,)).fetchall()
    known = set()
    for r in rows:
        try:
            known.update(json.loads(r["content"]).get("breaches", []))
        except Exception:
            pass
    return known


def _key(name):
    import config as C
    return getattr(C, name, "")


def run_due_sweeps():
    """Execute every due watchlist; returns number of alerts raised."""
    import config as C
    due = CASES.due_watchlists()
    raised = 0
    for watch in due:
        findings = []
        try:
            findings = _check_entity(watch)
            for f in findings:
                CASES.raise_alert(watch["id"], watch["case_id"], f["severity"],
                                  f["message"], f["detail"])
                raised += 1
                db.audit("watchlist", "alert.raise", watch["entity_value"],
                         f"{f['kind']}: {f['message']}")
        except Exception as e:
            db.audit("watchlist", "sweep.error", watch.get("entity_value", ""), str(e)[:200])
        finally:
            CASES.mark_watch_run(watch["id"])
            run_hooks(watch, findings)
    return raised


def sweep_loop(interval_sec=300):
    """Daemon loop — runs due sweeps every interval_sec. Never blocks boot."""
    while True:
        try:
            run_due_sweeps()
        except Exception:
            pass
        time.sleep(interval_sec)


def start_daemon(interval_sec=300):
    t = threading.Thread(target=sweep_loop, args=(interval_sec,), daemon=True)
    t.start()
    return t
