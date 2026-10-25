"""Xaxglog exposure — continuous public-exposure monitoring for orgs/people.

Open, keyless sources:
  - XposedOrNot (api.xposedornot.com) — email breach check, keyless.
  - Mozilla Observatory (observatory-api.mdn.mozilla.net) — public web
    security posture scan (grade + scorecard), keyless.
  - HackerTarget (api.hackertarget.com) — host search / reverse DNS, keyless
    with fair-use limits.
  - GitHub public code search — leaked config/dkim/keys mentioning a domain
    via GitHub search HTML (constrained, keyless).
Optional (env HIBP_API_KEY): Have I Been Pwned breach + paste detail.

Watch an org domain (or person email): each sweep re-checks breach corpora,
Observatory grade and public code leaks; new findings raise typed alerts and
land as custody artifacts. Complements darkweb (indexed dark-web corpora)
and threat_intel (IOC feeds) — this is the "how exposed is my estate"
axis.

Lawful-use note: public exposure databases and your own authorized targets.
Passive posture assessment — no exploitation of what is found.
"""
import json
import os
import re
import threading
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
XON_EMAIL = "https://api.xposedornot.com/v1/check/{email}"
XON_DOMAIN = "https://api.xposedornot.com/v1/check-domain/{domain}"
OBSERVATORY = "https://observatory-api.mdn.mozilla.net/api/v2/scan?host={host}"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/?q={domain}"


SCHEMA = """
CREATE TABLE IF NOT EXISTS exposure_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT UNIQUE NOT NULL,            -- domain or email
  kind TEXT NOT NULL,                     -- domain | email
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  snapshot TEXT DEFAULT '{}',
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


def _breach_email(email):
    """Breach list for an email — XposedOrNot keyless, HIBP when keyed."""
    import requests
    out = {"breaches": [], "pastes": [], "sources": []}
    try:
        r = requests.get(XON_EMAIL.format(email=email), headers=UA, timeout=T)
        if r.status_code == 200:
            j = r.json()
            out["breaches"] = (j.get("Breaches") or {}).get("breach", []) or []
            out["sources"].append("xposedornot")
        elif r.status_code == 404:
            out["sources"].append("xposedornot")
        key = os.getenv("HIBP_API_KEY")
        if key:
            r = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + email,
                headers={**UA, "hibp-api-key": key, "user-agent": "Xaxglog-OSINT"},
                params={"truncateResponse": "false"}, timeout=T)
            if r.status_code == 200:
                out["breaches"] = out["breaches"] or [b.get("Name") for b in r.json()]
                out["sources"].append("hibp")
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def _breach_domain(domain):
    import requests
    out = {"breaches": [], "sources": []}
    try:
        r = requests.get(XON_DOMAIN.format(domain=domain), headers=UA, timeout=T)
        if r.status_code == 200:
            j = r.json()
            out["breaches"] = j.get("breaches") or []
            out["sources"].append("xposedornot")
        elif r.status_code == 404:
            out["sources"].append("xposedornot")
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def _observatory(host):
    """Mozilla Observatory posture scan (async API: may return status=1)."""
    import requests
    try:
        r = requests.get(OBSERVATORY.format(host=host), headers=UA, timeout=T)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        j = r.json()
        scan = j.get("scan") or j
        return {"grade": scan.get("grade"), "score": scan.get("score"),
                "status": j.get("status"), "host": host,
                "headers": {k: v for k, v in (scan.get("response_headers") or {}).items()
                            if k.lower() in ("strict-transport-security",
                                             "content-security-policy",
                                             "x-frame-options", "x-content-type-options",
                                             "set-cookie")}}
    except Exception as e:
        return {"error": str(e)[:120]}


def _code_leaks(domain):
    """Public GitHub code search hits mentioning the domain (keyless HTML)."""
    import requests
    try:
        r = requests.get("https://github.com/search",
                         headers={**UA, "Accept": "text/html"},
                         params={"q": f'"{domain}"', "type": "code"}, timeout=T)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        # bare result-count hint from the results header if present
        m = re.search(r'([\d,]+)\s+(?:code\s+)?results?', r.text, re.I)
        return {"result_hint": int(m.group(1).replace(",", "")) if m else None,
                "note": "github may require login for code-search detail"}
    except Exception as e:
        return {"error": str(e)[:120]}


def assess(target):
    """One-shot exposure assessment for an email or domain."""
    try:
        target = (target or "").strip().lower()
        if "@" in target:
            kind = "email"
            domain = target.split("@", 1)[1]
            breaches = _breach_email(target)
            post = _observatory(domain)
            leaks = _code_leaks(domain)
        elif re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", target):
            kind = "domain"
            breaches = _breach_domain(target)
            post = _observatory(target)
            leaks = _code_leaks(target)
            try:
                import requests
                r = requests.get(HACKERTARGET.format(domain=target),
                                 headers=UA, timeout=T)
                if r.status_code == 200 and "error check" not in r.text.lower():
                    breaches["hosts"] = [ln.strip().split(",")[0]
                                         for ln in r.text.splitlines() if "," in ln][:50]
            except Exception:
                pass
        else:
            return {"status": "error", "error": "provide an email or domain"}
        # 0-100 exposure score: breaches dominate, grade fills the rest
        score = 0
        nb = len(breaches.get("breaches") or [])
        score += min(60, nb * 12)
        grade = (post or {}).get("grade")
        score += {"A+": 0, "A": 0, "B": 8, "C": 18, "D": 28, "F": 38}.get(grade, 10)
        if (leaks or {}).get("result_hint"):
            score += 10
        score = min(100, score)
        db.audit("system", "exposure.assess", target, f"score={score} breaches={nb}")
        return {"status": "ok", "target": target, "kind": kind,
                "score": score, "risk": "critical" if score >= 70 else
                "high" if score >= 45 else "medium" if score >= 20 else "low",
                "breaches": breaches, "web_posture": post, "public_code": leaks}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def watch(target, case_id=None, created_by="system"):
    init_schema()
    try:
        target = (target or "").strip().lower()
        kind = "email" if "@" in target else "domain"
        snap = assess(target)
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO exposure_watch (target,kind,case_id,snapshot,created_by,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (target, kind, case_id, json.dumps(snap.get("breaches", {}), default=str),
             created_by, db.utcnow()),
        )
        c.commit()
        db.audit(created_by, "exposure.watch", target, f"case={case_id}")
        return {"status": "ok", "target": target, "watching": True,
                "baseline": {"score": snap.get("score"),
                             "breaches": len(snap.get("breaches", {}).get("breaches") or [])}}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(target):
    try:
        c = db.get_db()
        c.execute("UPDATE exposure_watch SET enabled=0 WHERE target=?",
                  ((target or "").lower(),))
        c.commit()
        return {"status": "ok", "target": target, "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        q = "SELECT id,target,kind,case_id,last_run FROM exposure_watch WHERE enabled=1"
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        return {"status": "ok", "watch": [dict(r) for r in c.execute(q, args).fetchall()]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def check_all():
    init_schema()
    rows = db.get_db().execute(
        "SELECT id,target,case_id,snapshot FROM exposure_watch WHERE enabled=1").fetchall()
    results = []
    for row in rows:
        now = assess(row["target"])
        try:
            before = set(json.loads(row["snapshot"] or "{}").get("breaches") or [])
        except ValueError:
            before = set()
        now_set = set((now.get("breaches") or {}).get("breaches") or [])
        new = sorted(now_set - before)
        c = db.get_db()
        c.execute("UPDATE exposure_watch SET snapshot=?, last_run=? WHERE id=?",
                  (json.dumps({"breaches": sorted(now_set)}), db.utcnow(), row["id"]))
        if new:
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (row["case_id"], db.utcnow(), "high",
                 f"New breach exposure for {row['target']}: {', '.join(new[:5])}",
                 json.dumps({"new_breaches": new})[:900]),
            )
            db.store_artifact(row["case_id"], None, "exposure", "breach-corpora",
                              {"target": row["target"], "new": new}, "exposure-daemon")
        c.commit()
        results.append({"target": row["target"], "new_breaches": new,
                        "score": now.get("score")})
        time.sleep(2)
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=21600):
    """Background exposure sweep — never blocks boot."""
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="exposure").start()
    return True
