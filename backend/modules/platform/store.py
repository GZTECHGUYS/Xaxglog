"""SQLite persistence for the Phase 1-12 platform layer.

The base app already owns ``entities``, ``edges`` and ``artifacts``.  This
module deliberately reuses those tables for the intelligence graph and adds
only the tables the newer phases need (timeline, provenance, workspaces,
comments, assignments, module packs, plugins, settings and cache).

All writes use the shared thread-local connection from :mod:`db`; no external
database, daemon or Docker dependency is introduced.
"""
from __future__ import annotations

import difflib
import json
import re
import sqlite3
from typing import Any, Iterable

import db as DB

PLATFORM_SCHEMA = """
CREATE TABLE IF NOT EXISTS timeline_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL DEFAULT 0,
  entity_id INTEGER,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'observation',
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  source TEXT DEFAULT '',
  content_hash TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_case_ts ON timeline_events(case_id, ts);

CREATE TABLE IF NOT EXISTS provenance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL DEFAULT 0,
  artifact_id INTEGER,
  entity_id INTEGER,
  source TEXT NOT NULL,
  url TEXT DEFAULT '',
  access_mode TEXT DEFAULT 'public',
  status TEXT DEFAULT 'verified',
  retrieved_at TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  meta TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_provenance_case ON provenance(case_id);

CREATE TABLE IF NOT EXISTS workspaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  added_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, username)
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER,
  case_id INTEGER,
  artifact_id INTEGER,
  entity_id INTEGER,
  author TEXT NOT NULL,
  body TEXT NOT NULL,
  resolved INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_workspace ON comments(workspace_id, created_at);

CREATE TABLE IF NOT EXISTS assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER,
  case_id INTEGER,
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  assignee TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  due_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assignments_workspace ON assignments(workspace_id, status);

CREATE TABLE IF NOT EXISTS module_packs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  signature TEXT DEFAULT '',
  signed INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  manifest TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS plugin_registry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'source',
  manifest TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  installed_at TEXT NOT NULL,
  UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cache_entries (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retention_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy TEXT NOT NULL,
  dry_run INTEGER NOT NULL DEFAULT 1,
  deleted INTEGER NOT NULL DEFAULT 0,
  detail TEXT DEFAULT '{}',
  created_at TEXT NOT NULL
);
"""

_ready = False


def ensure_schema() -> None:
    """Create platform tables once per process (idempotent)."""
    global _ready
    if _ready:
        return
    c = DB.get_db()
    c.executescript(PLATFORM_SCHEMA)
    c.commit()
    _ready = True


def _json(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list, tuple, bool, int, float)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _dump(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True,
                      ensure_ascii=False, default=str)


def _row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out = dict(row)
    for key in ("meta", "manifest", "detail", "value"):
        if key in out and isinstance(out[key], str):
            parsed = _json(out[key])
            if parsed is not None:
                out[key] = parsed
    return out


def _case(case_id: Any) -> int:
    try:
        return max(0, int(case_id or 0))
    except (TypeError, ValueError):
        return 0


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")[:80] or "workspace"


# --------------------------------------------------------------- graph helpers
def upsert_entity(case_id: Any, entity_type: str, value: str, *,
                  label: str = "", source: str = "", confidence: float | None = None,
                  meta: dict | None = None) -> dict:
    ensure_schema()
    cid = _case(case_id)
    etype = (entity_type or "unknown").strip().lower()[:40]
    val = str(value or "").strip()[:500]
    if not val:
        raise ValueError("entity value required")
    now = DB.utcnow()
    merged = dict(meta or {})
    if label:
        merged["label"] = label
    if source:
        merged["source"] = source
    if confidence is not None:
        merged["confidence"] = float(confidence)
    c = DB.get_db()
    row = c.execute(
        "SELECT id, meta FROM entities WHERE case_id=? AND type=? AND value=?",
        (cid, etype, val),
    ).fetchone()
    if row:
        old = _json(row["meta"], {}) or {}
        old.update(merged)
        c.execute("UPDATE entities SET last_seen=?, meta=? WHERE id=?",
                  (now, _dump(old), row["id"]))
        return {"id": row["id"], "case_id": cid, "type": etype, "value": val,
                "meta": old, "created": False}
    cur = c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta)"
        " VALUES (?,?,?,?,?,?)",
        (cid, etype, val, now, now, _dump(merged)),
    )
    return {"id": cur.lastrowid, "case_id": cid, "type": etype, "value": val,
            "meta": merged, "created": True}


def add_edge(case_id: Any, src_id: int, dst_id: int, relation: str, *,
             weight: float = 1.0, source: str = "", meta: dict | None = None) -> dict:
    ensure_schema()
    cid = _case(case_id)
    c = DB.get_db()
    src = c.execute("SELECT id FROM entities WHERE id=?", (int(src_id),)).fetchone()
    dst = c.execute("SELECT id FROM entities WHERE id=?", (int(dst_id),)).fetchone()
    if not src or not dst:
        raise ValueError("both endpoint entities must exist")
    rel = (relation or "related").strip().lower()[:60]
    now = DB.utcnow()
    try:
        cur = c.execute(
            "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (cid, int(src_id), int(dst_id), rel, float(weight), source[:120], now),
        )
        return {"id": cur.lastrowid, "created": True, "relation": rel}
    except sqlite3.IntegrityError:
        row = c.execute(
            "SELECT id FROM edges WHERE case_id=? AND src_id=? AND dst_id=? AND relation=?",
            (cid, int(src_id), int(dst_id), rel),
        ).fetchone()
        if row and meta:
            c.execute("UPDATE edges SET source=?, weight=? WHERE id=?",
                      (source[:120], float(weight), row["id"]))
        return {"id": row["id"] if row else None, "created": False, "relation": rel}


def graph(case_id: Any, limit: int = 1000) -> dict:
    ensure_schema()
    cid = _case(case_id)
    c = DB.get_db()
    rows = c.execute(
        "SELECT * FROM entities WHERE case_id=? ORDER BY last_seen DESC LIMIT ?",
        (cid, max(1, min(int(limit or 1000), 5000))),
    ).fetchall()
    nodes = []
    for row in rows:
        item = dict(row)
        item["meta"] = _json(item.get("meta"), {}) or {}
        nodes.append(item)
    ids = {n["id"] for n in nodes}
    edges = []
    if ids:
        erows = c.execute(
            "SELECT * FROM edges WHERE case_id=? ORDER BY id DESC LIMIT ?",
            (cid, max(1, min(int(limit or 1000) * 2, 10000))),
        ).fetchall()
        for row in erows:
            if row["src_id"] in ids and row["dst_id"] in ids:
                edges.append(dict(row))
    return {"case_id": cid, "nodes": nodes, "edges": edges,
            "counts": {"nodes": len(nodes), "edges": len(edges)}}


def resolve_entity(query: str, case_id: Any = 0, limit: int = 20) -> list[dict]:
    """Fuzzy entity resolution using stdlib difflib (no extra dependency)."""
    ensure_schema()
    q = (query or "").strip().lower()
    if not q:
        return []
    c = DB.get_db()
    rows = c.execute(
        "SELECT * FROM entities WHERE case_id=? ORDER BY last_seen DESC LIMIT 2000",
        (_case(case_id),),
    ).fetchall()
    out = []
    for row in rows:
        value = str(row["value"] or "")
        score = difflib.SequenceMatcher(None, q, value.lower()).ratio()
        if q in value.lower() or value.lower() in q:
            score = max(score, 0.92)
        if score >= 0.55:
            item = dict(row)
            item["meta"] = _json(item.get("meta"), {}) or {}
            item["match"] = round(score, 3)
            out.append(item)
    out.sort(key=lambda x: -x["match"])
    return out[:max(1, min(int(limit or 20), 200))]


def add_artifact(case_id: Any, entity_id: int | None, atype: str, source: str,
                 content: Any, queried_by: str, *, url: str = "",
                 access_mode: str = "public", status: str = "verified",
                 meta: dict | None = None) -> dict:
    ensure_schema()
    cid = _case(case_id)
    stored = DB.store_artifact(cid, entity_id, atype, source, content, queried_by)
    prov = add_provenance(
        cid, source=source, url=url, access_mode=access_mode, status=status,
        sha256=stored["hash"], artifact_id=stored["id"], entity_id=entity_id,
        meta=meta,
    )
    return {**stored, "provenance_id": prov["id"], "case_id": cid}


def add_timeline(case_id: Any, ts: str | None, kind: str, title: str, *,
                 detail: str = "", source: str = "", entity_id: int | None = None,
                 content: Any = None) -> dict:
    ensure_schema()
    cid = _case(case_id)
    now = DB.utcnow()
    h = DB.hash_content(content if content is not None else f"{title}|{detail}") if hasattr(DB, "hash_content") else ""
    c = DB.get_db()
    cur = c.execute(
        "INSERT INTO timeline_events"
        " (case_id,entity_id,ts,kind,title,detail,source,content_hash,created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (cid, entity_id, (ts or now)[:64], (kind or "observation")[:40],
         (title or "event")[:300], (detail or "")[:8000], (source or "")[:200],
         h, now),
    )
    return {"id": cur.lastrowid, "case_id": cid, "ts": (ts or now), "kind": kind,
            "title": title, "content_hash": h}


def timeline(case_id: Any, limit: int = 500) -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    rows = c.execute(
        "SELECT * FROM timeline_events WHERE case_id=? ORDER BY ts ASC, id ASC LIMIT ?",
        (_case(case_id), max(1, min(int(limit or 500), 5000))),
    ).fetchall()
    return [dict(r) for r in rows]


def add_provenance(case_id: Any, *, source: str, url: str = "",
                   access_mode: str = "public", status: str = "verified",
                   sha256: str = "", artifact_id: int | None = None,
                   entity_id: int | None = None, meta: dict | None = None) -> dict:
    ensure_schema()
    cid = _case(case_id)
    now = DB.utcnow()
    digest = sha256 or DB.hash_content(_dump(meta or {}))
    c = DB.get_db()
    cur = c.execute(
        "INSERT INTO provenance"
        " (case_id,artifact_id,entity_id,source,url,access_mode,status,retrieved_at,sha256,meta)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (cid, artifact_id, entity_id, (source or "unknown")[:200], (url or "")[:2000],
         (access_mode or "public")[:40], (status or "verified")[:40], now,
         digest, _dump(meta or {})),
    )
    return {"id": cur.lastrowid, "case_id": cid, "sha256": digest,
            "retrieved_at": now, "status": status}


def provenance(case_id: Any, limit: int = 500) -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    rows = c.execute(
        "SELECT * FROM provenance WHERE case_id=? ORDER BY id DESC LIMIT ?",
        (_case(case_id), max(1, min(int(limit or 500), 5000))),
    ).fetchall()
    return [_row(r) for r in rows]


# ------------------------------------------------------------------ workspaces
def workspace_create(name: str, description: str, created_by: str) -> dict:
    ensure_schema()
    name = (name or "").strip()[:160]
    if not name:
        raise ValueError("workspace name required")
    base = _slug(name)
    c = DB.get_db()
    slug = base
    i = 2
    while c.execute("SELECT 1 FROM workspaces WHERE slug=?", (slug,)).fetchone():
        slug = f"{base}-{i}"
        i += 1
    now = DB.utcnow()
    cur = c.execute(
        "INSERT INTO workspaces (name,slug,description,created_by,created_at)"
        " VALUES (?,?,?,?,?)",
        (name, slug, (description or "")[:2000], created_by, now),
    )
    wid = cur.lastrowid
    c.execute(
        "INSERT OR IGNORE INTO workspace_members (workspace_id,username,role,added_at)"
        " VALUES (?,?,?,?)",
        (wid, created_by, "owner", now),
    )
    return {"id": wid, "name": name, "slug": slug, "description": description,
            "created_by": created_by, "created_at": now}


def workspace_list(username: str, role: str = "viewer") -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    if role == "admin":
        rows = c.execute("SELECT * FROM workspaces ORDER BY id DESC").fetchall()
    else:
        rows = c.execute(
            "SELECT w.* FROM workspaces w JOIN workspace_members m"
            " ON m.workspace_id=w.id WHERE m.username=? ORDER BY w.id DESC",
            (username,),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["members"] = [
            dict(x) for x in c.execute(
                "SELECT username,role,added_at FROM workspace_members"
                " WHERE workspace_id=? ORDER BY username", (row["id"],)
            ).fetchall()
        ]
        out.append(item)
    return out


def workspace_get(workspace_id: int) -> dict | None:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT * FROM workspaces WHERE id=?", (int(workspace_id),)).fetchone()
    if not row:
        return None
    item = dict(row)
    item["members"] = [dict(x) for x in c.execute(
        "SELECT username,role,added_at FROM workspace_members"
        " WHERE workspace_id=? ORDER BY username", (int(workspace_id),)
    ).fetchall()]
    return item


def workspace_add_member(workspace_id: int, username: str, role: str = "analyst") -> dict:
    ensure_schema()
    c = DB.get_db()
    user = c.execute("SELECT username FROM users WHERE username=? AND active=1",
                     (username,)).fetchone()
    if not user:
        raise ValueError("user not found")
    c.execute(
        "INSERT INTO workspace_members (workspace_id,username,role,added_at)"
        " VALUES (?,?,?,?) ON CONFLICT(workspace_id,username) DO UPDATE SET role=excluded.role",
        (int(workspace_id), username, (role or "analyst")[:20], DB.utcnow()),
    )
    return {"workspace_id": int(workspace_id), "username": username, "role": role}


# --------------------------------------------------------------- collaboration
def comment_add(workspace_id: int | None, author: str, body: str, *,
                case_id: Any = 0, artifact_id: int | None = None,
                entity_id: int | None = None) -> dict:
    ensure_schema()
    if not (body or "").strip():
        raise ValueError("comment body required")
    now = DB.utcnow()
    c = DB.get_db()
    cur = c.execute(
        "INSERT INTO comments (workspace_id,case_id,artifact_id,entity_id,author,body,created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (workspace_id, _case(case_id), artifact_id, entity_id, author,
         body.strip()[:8000], now),
    )
    return {"id": cur.lastrowid, "workspace_id": workspace_id, "author": author,
            "body": body.strip(), "created_at": now, "resolved": False}


def comments(workspace_id: int | None = None, case_id: Any = None,
             limit: int = 200) -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    q = "SELECT * FROM comments WHERE 1=1"
    args: list[Any] = []
    if workspace_id is not None:
        q += " AND workspace_id=?"
        args.append(int(workspace_id))
    if case_id is not None:
        q += " AND case_id=?"
        args.append(_case(case_id))
    q += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit or 200), 2000)))
    return [dict(r) for r in c.execute(q, args).fetchall()]


def comment_get(comment_id: int) -> dict | None:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT * FROM comments WHERE id=?", (int(comment_id),)).fetchone()
    return dict(row) if row else None


def comment_resolve(comment_id: int, resolved: bool = True) -> dict:
    ensure_schema()
    c = DB.get_db()
    now = DB.utcnow() if resolved else None
    c.execute("UPDATE comments SET resolved=?, resolved_at=? WHERE id=?",
              (1 if resolved else 0, now, int(comment_id)))
    return {"id": int(comment_id), "resolved": bool(resolved), "resolved_at": now}


def assignment_add(workspace_id: int | None, title: str, created_by: str, *,
                   case_id: Any = 0, detail: str = "", assignee: str = "",
                   due_at: str | None = None) -> dict:
    ensure_schema()
    if not (title or "").strip():
        raise ValueError("assignment title required")
    now = DB.utcnow()
    c = DB.get_db()
    cur = c.execute(
        "INSERT INTO assignments"
        " (workspace_id,case_id,title,detail,assignee,status,due_at,created_by,created_at,updated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (workspace_id, _case(case_id), title.strip()[:300], (detail or "")[:4000],
         (assignee or "")[:80], "open", due_at, created_by, now, now),
    )
    return {"id": cur.lastrowid, "workspace_id": workspace_id,
            "title": title.strip(), "assignee": assignee, "status": "open",
            "due_at": due_at, "created_at": now}


def assignments(workspace_id: int | None = None, case_id: Any = None,
                status: str | None = None, limit: int = 200) -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    q = "SELECT * FROM assignments WHERE 1=1"
    args: list[Any] = []
    if workspace_id is not None:
        q += " AND workspace_id=?"
        args.append(int(workspace_id))
    if case_id is not None:
        q += " AND case_id=?"
        args.append(_case(case_id))
    if status:
        q += " AND status=?"
        args.append(status)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit or 200), 2000)))
    return [dict(r) for r in c.execute(q, args).fetchall()]


def assignment_get(assignment_id: int) -> dict | None:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT * FROM assignments WHERE id=?", (int(assignment_id),)).fetchone()
    return dict(row) if row else None


def assignment_update(assignment_id: int, *, status: str | None = None,
                      assignee: str | None = None, due_at: str | None = None) -> dict:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT * FROM assignments WHERE id=?", (int(assignment_id),)).fetchone()
    if not row:
        raise ValueError("assignment not found")
    c.execute(
        "UPDATE assignments SET status=?, assignee=?, due_at=?, updated_at=? WHERE id=?",
        (status or row["status"], assignee if assignee is not None else row["assignee"],
         due_at if due_at is not None else row["due_at"], DB.utcnow(), int(assignment_id)),
    )
    return dict(c.execute("SELECT * FROM assignments WHERE id=?",
                          (int(assignment_id),)).fetchone())


# ------------------------------------------------------- packs / plugins / cache
def pack_upsert(manifest: dict, sha256: str, signature: str = "",
                signed: bool = False, enabled: bool = True) -> dict:
    ensure_schema()
    c = DB.get_db()
    c.execute(
        "INSERT INTO module_packs (name,version,sha256,signature,signed,enabled,manifest,installed_at)"
        " VALUES (?,?,?,?,?,?,?,?)"
        " ON CONFLICT(name,version) DO UPDATE SET sha256=excluded.sha256,"
        " signature=excluded.signature,signed=excluded.signed,"
        " enabled=excluded.enabled,manifest=excluded.manifest",
        (manifest["name"], manifest["version"], sha256, signature,
         1 if signed else 0, 1 if enabled else 0, _dump(manifest), DB.utcnow()),
    )
    return {"name": manifest["name"], "version": manifest["version"],
            "sha256": sha256, "signed": bool(signed), "enabled": bool(enabled)}


def pack_list() -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    return [_row(r) for r in c.execute(
        "SELECT * FROM module_packs ORDER BY name, installed_at DESC"
    ).fetchall()]


def pack_set_enabled(name: str, version: str, enabled: bool) -> dict:
    ensure_schema()
    c = DB.get_db()
    c.execute("UPDATE module_packs SET enabled=? WHERE name=? AND version=?",
              (1 if enabled else 0, name, version))
    return {"name": name, "version": version, "enabled": bool(enabled)}


def plugin_upsert(manifest: dict, enabled: bool = True) -> dict:
    ensure_schema()
    c = DB.get_db()
    c.execute(
        "INSERT INTO plugin_registry (name,version,kind,manifest,enabled,installed_at)"
        " VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(name,version) DO UPDATE SET kind=excluded.kind,"
        " manifest=excluded.manifest,enabled=excluded.enabled",
        (manifest["name"], manifest["version"], manifest.get("kind", "source"),
         1 if enabled else 0, _dump(manifest), DB.utcnow()),
    )
    return {"name": manifest["name"], "version": manifest["version"],
            "kind": manifest.get("kind", "source"), "enabled": bool(enabled)}


def plugin_list() -> list[dict]:
    ensure_schema()
    c = DB.get_db()
    return [_row(r) for r in c.execute(
        "SELECT * FROM plugin_registry ORDER BY name, installed_at DESC"
    ).fetchall()]


def plugin_set_enabled(name: str, version: str, enabled: bool) -> dict:
    ensure_schema()
    c = DB.get_db()
    c.execute("UPDATE plugin_registry SET enabled=? WHERE name=? AND version=?",
              (1 if enabled else 0, name, version))
    return {"name": name, "version": version, "enabled": bool(enabled)}


def setting_get(key: str, default: Any = None) -> Any:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT value FROM platform_settings WHERE key=?", (key,)).fetchone()
    return _json(row["value"], default) if row else default


def setting_set(key: str, value: Any) -> Any:
    ensure_schema()
    c = DB.get_db()
    c.execute(
        "INSERT INTO platform_settings (key,value,updated_at) VALUES (?,?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
        (key, _dump(value), DB.utcnow()),
    )
    return value


def cache_set(key: str, value: Any, expires_at: str | None = None) -> dict:
    ensure_schema()
    c = DB.get_db()
    c.execute(
        "INSERT INTO cache_entries (key,value,expires_at,created_at) VALUES (?,?,?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
        " expires_at=excluded.expires_at,created_at=excluded.created_at",
        (key, _dump(value), expires_at, DB.utcnow()),
    )
    return {"key": key, "expires_at": expires_at}


def cache_get(key: str) -> Any:
    ensure_schema()
    c = DB.get_db()
    row = c.execute("SELECT value,expires_at FROM cache_entries WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    if row["expires_at"] and row["expires_at"] < DB.utcnow():
        return None
    return _json(row["value"])


def cache_count() -> int:
    ensure_schema()
    c = DB.get_db()
    return int(c.execute("SELECT COUNT(*) c FROM cache_entries").fetchone()["c"])


def retention_record(policy: str, dry_run: bool, deleted: int, detail: dict) -> dict:
    ensure_schema()
    c = DB.get_db()
    cur = c.execute(
        "INSERT INTO retention_runs (policy,dry_run,deleted,detail,created_at)"
        " VALUES (?,?,?,?,?)",
        (policy, 1 if dry_run else 0, int(deleted), _dump(detail), DB.utcnow()),
    )
    return {"id": cur.lastrowid, "policy": policy, "dry_run": bool(dry_run),
            "deleted": int(deleted)}


# ------------------------------------------------------------------- analytics
def stats() -> dict:
    ensure_schema()
    c = DB.get_db()

    def count(table: str, where: str = "", args: Iterable[Any] = ()) -> int:
        try:
            row = c.execute(f"SELECT COUNT(*) c FROM {table} {where}", tuple(args)).fetchone()
            return int(row["c"] if row else 0)
        except sqlite3.OperationalError:
            return 0

    return {
        "entities": count("entities"),
        "edges": count("edges"),
        "artifacts": count("artifacts"),
        "timeline_events": count("timeline_events"),
        "provenance": count("provenance"),
        "workspaces": count("workspaces"),
        "comments": count("comments"),
        "assignments": count("assignments"),
        "module_packs": count("module_packs"),
        "plugins": count("plugin_registry"),
        "cache_entries": count("cache_entries"),
        "users": count("users"),
        "cases": count("cases"),
    }
