"""Xaxglog archive module — Wayback CDX snapshots + change watching.

Purpose : query the Internet Archive Wayback CDX index for a URL pattern,
          list collapsed snapshot timelines, fetch raw snapshots (sha256,
          title, text head), diff two versions, and register background
          watches that raise alerts when a watched page's archived content
          digest changes.
Sources : Internet Archive Wayback Machine CDX API
          (http://web.archive.org/cdx/search/cdx) and raw snapshot endpoint
          (http://web.archive.org/web/<ts>id_/<url>). Public web archive only.
Lawful use: gather evidence about publicly archived pages relevant to an
          authorized case; digests are stored for chain-of-custody and every
          watch change is written to the audit trail.
"""
import datetime
import difflib
import json
import re
import threading
import time

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 15
CDX = "http://web.archive.org/cdx/search/cdx"

_WATCH_SCHEMA = """
CREATE TABLE IF NOT EXISTS archive_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  case_id INTEGER,
  interval_min INTEGER NOT NULL DEFAULT 720,
  last_ts TEXT,
  last_hash TEXT,
  next_check TEXT,
  created_by TEXT DEFAULT '',
  created_at TEXT NOT NULL
)
"""


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


# --------------------------------------------------------------- CDX
def _cdx(url, from_ts="20050101", to_ts="20261231", limit=50):
    """Wayback CDX query -> {"status", "rows":[{timestamp,original,statuscode,
    digest}], ...}. First JSON row is the header. Never raises; blocked or
    non-JSON responses come back as status "blocked"."""
    try:
        params = {"url": url, "output": "json", "limit": limit,
                  "fl": "timestamp,original,statuscode,digest",
                  "collapse": "digest"}
        if from_ts:
            params["from"] = str(from_ts)
        if to_ts:
            params["to"] = str(to_ts)
        r = _get(CDX, params=params)
        if isinstance(r, Exception):
            return {"error": str(r)[:150], "status": "error", "rows": []}
        code = getattr(r, "status_code", 0)
        if code in (403, 429, 503):
            return {"error": f"blocked HTTP {code}", "status": "blocked", "rows": []}
        if code != 200:
            return {"error": f"HTTP {code}", "status": "error", "rows": []}
        try:
            data = r.json()
        except Exception:
            return {"error": "non-JSON response (anti-bot?)", "status": "blocked",
                    "rows": []}
        if not isinstance(data, list) or not data:
            return {"status": "ok", "rows": [], "count": 0}
        header = [str(h).lower() for h in data[0]]
        rows = []
        for row in data[1:]:
            if isinstance(row, list) and len(row) == len(header):
                rows.append(dict(zip(header, row)))
        return {"status": "ok", "rows": rows, "count": len(rows)}
    except Exception as e:
        return {"error": str(e)[:150], "status": "error", "rows": []}


def wayback_cdx(pattern, limit=50, from_year="2005", to_year="2026"):
    """Collapsed CDX snapshots for a URL pattern between two years."""
    try:
        limit = max(1, min(int(limit), 1000))
        res = _cdx(str(pattern), from_ts=f"{from_year}0101", to_ts=f"{to_year}1231",
                   limit=limit)
        snaps = [{"ts": r.get("timestamp"), "url": r.get("original"),
                  "status": r.get("statuscode"), "digest": r.get("digest")}
                 for r in res.get("rows") or []]
        out = {"pattern": pattern, "count": len(snaps), "snapshots": snaps,
               "status": res.get("status", "ok")}
        if res.get("error"):
            out["error"] = res["error"]
        return out
    except Exception as e:
        return {"error": str(e)[:150], "pattern": pattern, "count": 0,
                "snapshots": [], "status": "error"}


def page_history(url, limit=100):
    """Collapsed snapshot timeline for one URL (newest content digests only)."""
    try:
        limit = max(1, min(int(limit), 1000))
        res = _cdx(str(url), limit=limit)
        snaps = [{"ts": r.get("timestamp"), "url": r.get("original"),
                  "status": r.get("statuscode"), "digest": r.get("digest")}
                 for r in res.get("rows") or []]
        out = {"url": url, "count": len(snaps), "snapshots": snaps,
               "status": res.get("status", "ok")}
        if res.get("error"):
            out["error"] = res["error"]
        return out
    except Exception as e:
        return {"error": str(e)[:150], "url": url, "count": 0, "snapshots": [],
                "status": "error"}


# --------------------------------------------------------------- snapshots
def _fetch_raw(url, ts):
    """GET http://web.archive.org/web/<ts>id_/<url> -> raw text, never raises."""
    try:
        ts = str(ts or "").strip()
        if not ts:
            return {"error": "timestamp required", "status": "error"}
        snap = f"http://web.archive.org/web/{ts}id_/{url}"
        r = _get(snap)
        if isinstance(r, Exception):
            return {"error": str(r)[:150], "status": "error"}
        code = getattr(r, "status_code", 0)
        if code in (403, 429):
            return {"error": f"blocked HTTP {code}", "status": "blocked"}
        if code != 200:
            return {"error": f"HTTP {code}", "status": "error"}
        raw = r.content
        text = raw.decode("utf-8", "replace")
        low = text[:4000].lower()
        if len(text) < 8000 and ("too many requests" in low or "rate limit" in low):
            return {"error": "rate-limited by archive service", "status": "blocked"}
        return {"status": "ok", "text": text, "bytes": len(raw), "http": code}
    except Exception as e:
        return {"error": str(e)[:150], "status": "error"}


def fetch_snapshot(url, timestamp):
    """Fetch one archived snapshot: sha256, byte size, <title>, text head."""
    ts = str(timestamp or "").strip()
    try:
        res = _fetch_raw(url, ts)
        if res.get("status") != "ok":
            out = {"url": url, "ts": ts, "status": res.get("status", "error")}
            if res.get("error"):
                out["error"] = res["error"]
            return out
        text = res["text"]
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""
        body = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
        body = re.sub(r"(?s)<[^>]+>", " ", body)
        body = re.sub(r"\s+", " ", body).strip()
        return {"url": url, "ts": ts, "sha256": db.hash_content(text),
                "bytes": res["bytes"], "title": title, "text_head": body[:1000],
                "status": "ok"}
    except Exception as e:
        return {"error": str(e)[:150], "status": "error", "url": url, "ts": ts}


def diff_versions(url, ts1, ts2):
    """Unified-diff line stats between two archived versions of a URL."""
    try:
        a = _fetch_raw(url, ts1)
        b = _fetch_raw(url, ts2)
        bad = [x for x in (a, b) if x.get("status") != "ok"]
        if bad:
            status = "blocked" if any(x.get("status") == "blocked"
                                      for x in bad) else "error"
            return {"url": url, "ts1": str(ts1), "ts2": str(ts2),
                    "error": "; ".join(str(x.get("error")) for x in bad)[:150],
                    "status": status, "added": 0, "removed": 0, "changed_bool": False}
        l1 = a["text"].splitlines()
        l2 = b["text"].splitlines()
        added = removed = 0
        for line in difflib.unified_diff(l1, l2, lineterm="", n=0):
            if line.startswith(("+++", "---", "@@")):
                continue
            if line.startswith("+"):
                added += 1
            elif line.startswith("-"):
                removed += 1
        return {"url": url, "ts1": str(ts1), "ts2": str(ts2), "added": added,
                "removed": removed, "changed_bool": bool(added or removed),
                "bytes1": a["bytes"], "bytes2": b["bytes"], "status": "ok"}
    except Exception as e:
        return {"error": str(e)[:150], "status": "error", "url": url,
                "ts1": str(ts1), "ts2": str(ts2), "added": 0, "removed": 0,
                "changed_bool": False}


# --------------------------------------------------------------- change watch
def _ensure_watch():
    c = db.get_db()
    c.executescript(_WATCH_SCHEMA)
    c.commit()


def _now_plus(minutes):
    try:
        minutes = int(minutes)
    except Exception:
        minutes = 720
    return (datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
            ).isoformat() + "Z"


def register_watch(url, case_id, interval_min=720, user="system"):
    """Register a URL for periodic change checks (due on the next tick)."""
    try:
        url = (url or "").strip()
        if not url:
            return {"error": "url required"}
        try:
            interval_min = max(1, int(interval_min))
        except Exception:
            interval_min = 720
        _ensure_watch()
        c = db.get_db()
        now = db.utcnow()
        cur = c.execute(
            "INSERT INTO archive_watch (url, case_id, interval_min, last_ts, last_hash,"
            " next_check, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (url, case_id, interval_min, None, None, now, user or "system", now))
        c.commit()
        wid = cur.lastrowid
        db.audit(user, "archive.watch.add", url,
                 f"id={wid} interval_min={interval_min} case={case_id}")
        return {"id": wid, "url": url, "case_id": case_id,
                "interval_min": interval_min, "next_check": now,
                "created_by": user or "system"}
    except Exception as e:
        return {"error": str(e)[:150]}


def list_watch():
    """All registered archive watches."""
    try:
        _ensure_watch()
        rows = db.get_db().execute("SELECT * FROM archive_watch ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def check_watch(id):
    """Compare the latest CDX digest against the stored baseline.

    On a real change: raises an alert (alerts table), updates the row, audits.
    Returns {changed, old_ts, new_ts, ...}; never raises.
    """
    try:
        _ensure_watch()
        c = db.get_db()
        row = c.execute("SELECT * FROM archive_watch WHERE id=?", (id,)).fetchone()
        if not row:
            return {"error": "watch not found", "id": id, "changed": False,
                    "old_ts": None, "new_ts": None}
        res = _cdx(row["url"], limit=-1)  # negative limit = last (latest) record
        if res.get("error"):
            return {"id": id, "changed": False, "old_ts": row["last_ts"],
                    "new_ts": None, "error": res["error"],
                    "status": res.get("status", "error")}
        rows = res.get("rows") or []
        if not rows:
            nxt = _now_plus(row["interval_min"])
            c.execute("UPDATE archive_watch SET next_check=? WHERE id=?", (nxt, id))
            c.commit()
            return {"id": id, "changed": False, "old_ts": row["last_ts"],
                    "new_ts": None, "note": "no snapshots yet"}
        latest = max(rows, key=lambda r: str(r.get("timestamp") or ""))
        new_ts = str(latest.get("timestamp") or "") or None
        new_hash = latest.get("digest") or None
        old_ts, old_hash = row["last_ts"], row["last_hash"]

        if old_hash and new_hash:
            changed = old_hash != new_hash
        else:
            changed = False  # first check = baseline, not a change

        nxt = _now_plus(row["interval_min"])
        c.execute("UPDATE archive_watch SET last_ts=?, last_hash=?, next_check=? WHERE id=?",
                  (new_ts, new_hash, nxt, id))
        c.commit()
        db.audit(row["created_by"] or "system", "archive.watch.check", row["url"],
                 f"id={id} changed={changed} ts={new_ts}")

        if changed:
            detail = json.dumps({"watch_id": id, "old_ts": old_ts, "new_ts": new_ts,
                                 "old_hash": old_hash, "new_hash": new_hash})
            c.execute(
                "INSERT INTO alerts (watchlist_id,case_id,ts,severity,message,detail)"
                " VALUES (?,?,?,?,?,?)",
                (id, row["case_id"], db.utcnow(), "medium",
                 f"Archived page content changed: {row['url']}", detail))
            c.commit()
            db.audit(row["created_by"] or "system", "archive.alert.change", row["url"],
                     f"watch={id} {old_ts}->{new_ts}")
        return {"id": id, "changed": changed, "old_ts": old_ts, "new_ts": new_ts,
                "old_hash": old_hash, "new_hash": new_hash, "next_check": nxt}
    except Exception as e:
        return {"error": str(e)[:150], "id": id, "changed": False,
                "old_ts": None, "new_ts": None}


def _tick():
    """Run every due watch once and reschedule it. Safe on an empty table."""
    _ensure_watch()
    c = db.get_db()
    now = db.utcnow()
    rows = c.execute(
        "SELECT id, interval_min FROM archive_watch WHERE next_check IS NULL"
        " OR next_check <= ?", (now,)).fetchall()
    checked = 0
    for r in rows:
        try:
            check_watch(r["id"])
            checked += 1
        except Exception:
            pass
        try:
            c.execute("UPDATE archive_watch SET next_check=? WHERE id=?",
                      (_now_plus(r["interval_min"]), r["id"]))
            c.commit()
            db.audit("system", "archive.watch.schedule", f"watch:{r['id']}",
                     f"next_check=+{r['interval_min']}min")
        except Exception:
            pass
    return checked


def _daemon_loop(interval_sec):
    """Infinite tick loop — every exception swallowed; never crashes process."""
    while True:
        try:
            _tick()
        except Exception:
            pass
        time.sleep(interval_sec)


def start_daemon(interval_sec=600):
    """Start (or re-arm) the archive watch daemon thread. Never blocks boot."""
    t = threading.Thread(target=_daemon_loop, args=(interval_sec,), daemon=True)
    t.start()
    return t
