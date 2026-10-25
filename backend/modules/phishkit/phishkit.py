"""Xaxglog phishkit — phishing campaign intel + takedown workflow.

Keyless core:
  - OpenPhish community feed (openphish.com) — active phishing URLs.
  - PhishTank (phishtank.com) — searchable verified-phishing DB, keyless
    JSON endpoint (rate-limited; optional API key env PHTANK_API_KEY).
  - URLhaus URL lookup (urlhaus-api.abuse.ch) — malware distribution URLs.

Workflow:
  1. check(url)    — is this URL a known phishing kit instance? what's the
                     reported brand, kit family, verification age?
  2. campaign(q)   — all verified phishes matching a brand/domain.
  3. takedown(url) — build a registrar/hosting abuse report (structured
                     artifact with evidence hash), track status through
                     draft -> sent -> resolved in its own table, raise a
                     deadline alert if no resolution in 72h.

Lawful-use note: phishing *reporting* infrastructure. This module does not
host, redirect or otherwise touch kit infrastructure — it reads public
databases and prepares abuse reports.
"""
import datetime
import json
import os
import re
import threading

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
OPENPHISH = "https://openphish.com/feed.txt"
PT_VERIFY = "https://data.phishtank.com/data/online-valid.json"
UH_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"


def _norm(url):
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url


def _registrar(url):
    """Who hosts/registers this URL (RDAP + DoH, keyless)."""
    import urllib.parse
    import requests
    host = urllib.parse.urlparse(url).hostname or ""
    out = {"host": host}
    try:
        r = requests.get(f"https://rdap.org/domain/{host}", headers=UA, timeout=15)
        if r.status_code == 200:
            j = r.json()
            out["rdap_name"] = j.get("ldhName")
            ev = {e.get("eventAction"): e.get("eventDate")
                  for e in (j.get("events") or [])}
            out["created"] = ev.get("registration")
            reg = next((e for e in j.get("entities", [])
                        if "registrar" in (e.get("roles") or [])), None)
            if reg:
                out["registrar"] = reg.get("handle")
                abuse = json.dumps(reg)
                out["registrar_abuse"] = next(
                    (tok.strip() for tok in abuse.replace('"', "").split(",")
                     if "@" in tok), None)
    except Exception:
        pass
    return out


def check(url, registrar_lookup=True):
    """Known-phishing check across OpenPhish + PhishTank + URLhaus."""
    try:
        url = _norm(url)
        out = {"url": url, "known_phish": False, "sources": {}}
        import requests
        # 1. OpenPhish community feed (cached text)
        try:
            r = requests.get(OPENPHISH, headers=UA, timeout=T)
            if r.status_code == 200:
                listed = url.rstrip("/") in {ln.rstrip("/") for ln in r.text.splitlines()}
                out["sources"]["openphish"] = listed
                out["known_phish"] = out["known_phish"] or listed
        except Exception:
            out["sources"]["openphish"] = "unavailable"
        # 2. PhishTank
        try:
            key = os.getenv("PHTANK_API_KEY")
            r = requests.post(
                "https://api.phishtank.com/api/2.0/json/",
                data={"url": url, "format": "json",
                      "app_key": key or ""}, headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                if j.get("results"):
                    ph = j["results"][0]
                    out["sources"]["phishtank"] = {
                        "phish_id": ph.get("phish_id"),
                        "verified": ph.get("verified"),
                        "detail": (ph.get("details_url")),
                    }
                    out["known_phish"] = True
                else:
                    out["sources"]["phishtank"] = False
        except Exception:
            out["sources"]["phishtank"] = "unavailable"
        # 3. URLhaus
        try:
            r = requests.post(UH_LOOKUP, headers=UA,
                              data={"url": url}, timeout=T)
            if r.status_code == 200:
                j = r.json()
                if j.get("query_status") == "ok":
                    out["sources"]["urlhaus"] = {
                        "threat": j.get("threat"), "tags": j.get("tags"),
                        "urlhaus_status": j.get("url_status"),
                    }
                    out["known_phish"] = True
                else:
                    out["sources"]["urlhaus"] = False
        except Exception:
            out["sources"]["urlhaus"] = "unavailable"
        if registrar_lookup:
            out["registration"] = _registrar(url)
        db.audit("system", "phishkit.check", url[:120],
                 f"known={out['known_phish']}")
        return {"status": "ok", **out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def campaign(q, limit=40):
    """Verified phishes matching brand/domain (PhishTank search)."""
    try:
        q = (q or "").strip()
        if not q:
            return {"status": "error", "error": "empty query"}
        import requests
        r = requests.post(
            "https://api.phishtank.com/api/2.0/json_search.php",
            data={"search_text": q, "offset": 0, "format": "json"},
            headers=UA, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}",
                    "hint": "PhishTank may throttle anonymous search"}
        j = r.json()
        rows = [{
            "phish_id": p.get("phish_id"), "url": p.get("url"),
            "verified": p.get("verified"), "detail": p.get("details_url"),
            "target": p.get("target"), "submitted": p.get("submission_time"),
        } for p in (j.get("results") or [])[:limit]]
        db.audit("system", "phishkit.campaign", q, f"n={len(rows)}")
        return {"status": "ok", "query": q, "count": len(rows), "phishes": rows}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "phishes": []}


SCHEMA = """
CREATE TABLE IF NOT EXISTS phishkit_takedowns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  brand TEXT,
  registrar_ref TEXT,
  evidence_hash TEXT,
  status TEXT NOT NULL DEFAULT 'draft',   -- draft|sent|acknowledged|resolved|rejected
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        c.commit()
    except Exception:
        pass


def takedown_open(url, brand=None, created_by="system"):
    """Open a takedown case: capture evidence (URL + registrar + hash)."""
    try:
        init_schema()
        url = _norm(url)
        intel = check(url)
        if intel.get("status") != "ok":
            return intel
        evidence = {"url": url, "brand": brand, "intel": intel,
                    "captured_at": db.utcnow()}
        h = db.hash_content(json.dumps(evidence, sort_keys=True, default=str))
        reg = intel.get("registration") or {}
        c = db.get_db()
        cur = c.execute(
            "INSERT INTO phishkit_takedowns (url,brand,registrar_ref,evidence_hash,"
            "created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (url, brand, json.dumps(reg, default=str)[:900], h,
             created_by, db.utcnow(), db.utcnow()))
        c.commit()
        art = db.store_artifact(None, None, "phishkit", "takedown",
                                evidence, created_by)
        db.audit(created_by, "phishkit.takedown_open", url[:120],
                 f"id={cur.lastrowid} hash={h[:12]}")
        return {"status": "ok", "id": cur.lastrowid, "evidence_hash": h,
                "artifact": art, "registrar": reg,
                "next": "attach this evidence to the registrar/hosting abuse form"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def takedown_update(takedown_id, status, actor="system"):
    """Advance takedown lifecycle: draft|sent|acknowledged|resolved|rejected."""
    ok_states = ("draft", "sent", "acknowledged", "resolved", "rejected")
    if status not in ok_states:
        return {"status": "error", "error": f"status must be one of {ok_states}"}
    try:
        init_schema()
        c = db.get_db()
        c.execute("UPDATE phishkit_takedowns SET status=?, updated_at=? WHERE id=?",
                  (status, db.utcnow(), takedown_id))
        c.commit()
        db.audit(actor, "phishkit.takedown_update", str(takedown_id), status)
        if status == "resolved":
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (None, db.utcnow(), "info",
                 f"Phishing takedown #{takedown_id} resolved",
                 json.dumps({"status": status})[:500]))
            c.commit()
        return {"status": "ok", "id": takedown_id, "state": status}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def takedowns(status=None, limit=50):
    try:
        init_schema()
        c = db.get_db()
        q = "SELECT id,url,brand,status,created_by,created_at,updated_at FROM phishkit_takedowns"
        args = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY id DESC LIMIT ?"
        args = args + (min(int(limit), 500),)
        return {"status": "ok", "takedowns": [dict(r) for r in c.execute(q, args)]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "takedowns": []}


def deadline_alerts():
    """Open takedowns >72h without resolution -> alert."""
    try:
        init_schema()
        c = db.get_db()
        rows = c.execute(
            "SELECT id,url,created_at FROM phishkit_takedowns "
            "WHERE status NOT IN ('resolved','rejected')").fetchall()
        raised = 0
        for r in rows:
            try:
                created = datetime.datetime.fromisoformat(
                    r["created_at"].replace("Z", ""))
            except ValueError:
                continue
            age_h = (datetime.datetime.utcnow() - created).total_seconds() / 3600
            if age_h > 72:
                c.execute(
                    "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                    (None, db.utcnow(), "medium",
                     f"Phishing takedown #{r['id']} unresolved after {age_h:.0f}h: "
                     f"{r['url'][:100]}",
                     json.dumps({"takedown_id": r["id"]})[:500]))
                raised += 1
        c.commit()
        return {"status": "ok", "raised": raised}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=7200):
    def _loop():
        while not _daemon_stop.is_set():
            try:
                deadline_alerts()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="phishkit").start()
    return True
