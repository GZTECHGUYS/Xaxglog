"""Xaxglog community — public community mapping (Discord, Matrix, forums).

Keyless core:
  - Discord widget API (discord.com/api/v10/guilds/<id>/widget.json) —
    public server name, member count, presence counts, invite channel.
    Only servers that enabled the widget answer; private servers don't.
  - Discord invite lookups (discord.com/api/v10/invites/<code>?with_counts=true)
    — public invite metadata (server name, counts, discovery).
  - Matrix public rooms (matrix.org/_matrix/client/v3/publicRooms) —
    federated room directory search (name, topic, members), keyless.

Combine with searchx dorks (site:discord.gg/<term> etc.) to *discover*
invites, then resolve them here for structured metadata.

Lawful-use note: metadata about *public* communities only. No joining, no
scraping of member lists, no messages read. Member counts are as published.
"""
import json
import os
import re
import threading

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
DISCORD = "https://discord.com/api/v10"
MATRIX = "https://matrix.org/_matrix/client/v3/publicRooms"
DISCORD_ID_RE = re.compile(r"^\d{5,25}$")
INVITE_RE = re.compile(r"^[A-Za-z0-9-]{2,32}$")


def guild(guild_id):
    """Discord guild widget (public only, keyless)."""
    try:
        gid = (guild_id or "").strip()
        if not DISCORD_ID_RE.match(gid):
            return {"status": "error", "error": "invalid guild id"}
        import requests
        r = requests.get(f"{DISCORD}/guilds/{gid}/widget.json",
                         headers=UA, timeout=T)
        if r.status_code == 404:
            return {"status": "notfound",
                    "note": "widget disabled or guild not found (public metadata "
                            "only — private guilds do not answer)"}
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        out = {"status": "ok", "id": j.get("id"), "name": j.get("name"),
               "instant_invite": j.get("instant_invite"),
               "presence_count": j.get("presence_count"),
               "members": [{"name": m.get("username"), "id": m.get("id")}
                           for m in (j.get("members") or [])[:30]],
               "channels": [{"name": c.get("name"), "id": c.get("id")}
                            for c in (j.get("channels") or [])[:30]]}
        db.audit("system", "community.guild", gid, out.get("name") or "")
        return out
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def invite(code):
    """Resolve a public Discord invite code -> server metadata (keyless)."""
    try:
        code = (code or "").strip().split("/")[-1]
        if not INVITE_RE.match(code):
            return {"status": "error", "error": "invalid invite code"}
        import requests
        r = requests.get(f"{DISCORD}/invites/{code}",
                         headers=UA, params={"with_counts": "true",
                                             "with_expiration": "true"},
                         timeout=T)
        if r.status_code == 404:
            return {"status": "notfound", "code": code,
                    "note": "expired or private invite"}
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        g = j.get("guild") or {}
        return {"status": "ok", "code": code,
                "guild": {"id": g.get("id"), "name": g.get("name"),
                          "description": (g.get("description") or "")[:300],
                          "vanity_url": g.get("vanity_url_code"),
                          "nsfw": g.get("nsfw")},
                "approx_member_count": j.get("approximate_member_count"),
                "approx_presence": j.get("approximate_presence_count"),
                "expires": j.get("expires_at"),
                "channel": (j.get("channel") or {}).get("name")}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def matrix_rooms(query, limit=20):
    """Search the Matrix public-room directory (keyless, matrix.org)."""
    try:
        query = (query or "").strip()
        if not query:
            return {"status": "error", "error": "empty query"}
        import requests
        r = requests.post(MATRIX, headers={**UA, "Content-Type": "application/json"},
                          json={"search_term": query,
                                "limit": min(int(limit), 50)}, timeout=T)
        if r.status_code not in (200, 201):
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        rooms = [{
            "name": rm.get("name"),
            "topic": (rm.get("topic") or "")[:300],
            "alias": rm.get("canonical_alias"),
            "members": rm.get("num_members"),
            "room_id": rm.get("room_id"),
        } for rm in (j.get("chunk") or [])]
        db.audit("system", "community.matrix_rooms", query, f"n={len(rooms)}")
        return {"status": "ok", "count": len(rooms), "rooms": rooms,
                "total": j.get("total_room_count_estimate")}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "rooms": []}


SCHEMA = """
CREATE TABLE IF NOT EXISTS community_watch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                     -- discord_guild | discord_invite | matrix_room
  ref TEXT NOT NULL,
  case_id INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  snapshot TEXT DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(kind, ref)
);
"""


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        # additive migration: last_run column (older dev DBs predate it)
        try:
            c.execute("ALTER TABLE community_watch ADD COLUMN last_run TEXT")
        except Exception:
            pass
        c.commit()
    except Exception:
        pass


def watch(kind, ref, case_id=None, created_by="system"):
    """Watch a public community for member-count / name / topic drift."""
    if kind not in ("discord_guild", "discord_invite", "matrix_room"):
        return {"status": "error", "error": "kind must be discord_guild|"
                                            "discord_invite|matrix_room"}
    init_schema()
    try:
        c = db.get_db()
        c.execute(
            "INSERT OR IGNORE INTO community_watch (kind,ref,case_id,created_by,created_at)"
            " VALUES (?,?,?,?,?)",
            (kind, ref, case_id, created_by, db.utcnow()))
        c.commit()
        db.audit(created_by, "community.watch", f"{kind}:{ref}", f"case={case_id}")
        return {"status": "ok", "kind": kind, "ref": ref, "watching": True}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def unwatch(kind, ref):
    try:
        c = db.get_db()
        c.execute("UPDATE community_watch SET enabled=0 WHERE kind=? AND ref=?",
                  (kind, ref))
        c.commit()
        return {"status": "ok", "watching": False}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_watch(case_id=None):
    try:
        c = db.get_db()
        q = "SELECT id,kind,ref,case_id,last_run FROM community_watch WHERE enabled=1"
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        return {"status": "ok", "watch": [dict(r) for r in c.execute(q, args).fetchall()]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "watch": []}


def _observe(kind, ref):
    if kind == "discord_guild":
        out = guild(ref)
        if out.get("status") == "ok":
            return {"members": out.get("presence_count"),
                    "name": out.get("name"),
                    "invite": out.get("instant_invite")}
        return {"error": out.get("note") or out.get("error")}
    if kind == "discord_invite":
        out = invite(ref)
        if out.get("status") == "ok":
            return {"members": out.get("approx_member_count"),
                    "presence": out.get("approx_presence"),
                    "name": (out.get("guild") or {}).get("name")}
        return {"error": out.get("note") or out.get("error")}
    return {"error": "matrix_room watch: use matrix_rooms() to snapshot manually"}


def check_all():
    init_schema()
    rows = db.get_db().execute(
        "SELECT id,kind,ref,case_id,snapshot FROM community_watch WHERE enabled=1"
    ).fetchall()
    results = []
    for row in rows:
        now = _observe(row["kind"], row["ref"])
        try:
            before = json.loads(row["snapshot"] or "{}")
        except ValueError:
            before = {}
        drift = {}
        if before and isinstance(before, dict) and isinstance(now, dict):
            for k in set(before) | set(now):
                if before.get(k) != now.get(k):
                    drift[k] = {"was": before.get(k), "now": now.get(k)}
        c = db.get_db()
        c.execute("UPDATE community_watch SET snapshot=?, last_run=? WHERE id=?",
                  (json.dumps(now, default=str), db.utcnow(), row["id"]))
        if drift and before:
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES (?,?,?,?,?)",
                (row["case_id"], db.utcnow(), "low",
                 f"Community change {row['kind']}:{row['ref']}: "
                 + ", ".join(drift),
                 json.dumps(drift, default=str)[:900]))
        c.commit()
        results.append({"ref": row["ref"], "drift": drift or None})
    return {"status": "ok", "checked": len(results), "results": results}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=1800):
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                check_all()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="community").start()
    return True
