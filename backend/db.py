"""Xaxglog shared database — SQLite with FTS5 full-text search.

Single source of truth for users, cases, entities, edges, evidence artifacts,
watchlists, alerts, and the append-only audit trail. Every piece of collected
evidence is SHA-256 hashed (chain of custody) so results are court-defensible.

No Docker, no external DB server — plain SQLite file under data/.
"""
import datetime
import hashlib
import os
import sqlite3
import threading

import config as C

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',   -- admin | analyst | viewer
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_number TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  legal_basis TEXT DEFAULT '',           -- warrant / authorization reference
  status TEXT NOT NULL DEFAULT 'open',   -- open | closed | archived
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_members (
  case_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  permission TEXT NOT NULL DEFAULT 'edit',  -- edit | read
  PRIMARY KEY (case_id, username)
);

CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  type TEXT NOT NULL,                    -- email|phone|domain|ip|username|person|company|geo|handle
  value TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  meta TEXT DEFAULT '{}',
  UNIQUE(case_id, type, value)
);

CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  src_id INTEGER NOT NULL,
  dst_id INTEGER NOT NULL,
  relation TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1.0,
  source TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(case_id, src_id, dst_id, relation)
);

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  entity_id INTEGER,
  type TEXT NOT NULL,                    -- recon|darkweb|simswap|ss7|attribution|threat|forensic
  source TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,            -- SHA-256 chain of custody
  queried_by TEXT NOT NULL,
  queried_at TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0    -- 1 = hash re-checked & matches
);

CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  checks TEXT NOT NULL DEFAULT '[]',     -- json list of check names
  interval_min INTEGER NOT NULL DEFAULT 360,
  last_run TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(case_id, entity_type, entity_value)
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  watchlist_id INTEGER,
  case_id INTEGER,
  ts TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info', -- info|low|medium|high|critical
  message TEXT NOT NULL,
  detail TEXT DEFAULT '{}',
  acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  username TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT DEFAULT '',
  detail TEXT DEFAULT '',
  ip TEXT DEFAULT ''
);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS artifacts_fts USING fts5(
  content, source, type, content='artifacts', content_rowid='id'
);
"""

_conn_local = threading.local()


def utcnow():
    return datetime.datetime.utcnow().isoformat() + "Z"


def get_db():
    """Thread-local SQLite connection with WAL + foreign keys on.

    isolation_level=None -> autocommit: every execute() commits on its own.
    This codebase always follows a write with an immediate commit(), so we
    gain nothing from implicit transactions — and autocommit makes it
    structurally impossible for a failed statement (e.g. an IntegrityError)
    to leave an open write transaction that would block every other writer
    with "database is locked". .commit() calls elsewhere stay as harmless
    no-ops.
    """
    c = getattr(_conn_local, "conn", None)
    if c is None:
        c = sqlite3.connect(C.DB_PATH, timeout=30)
        c.isolation_level = None  # autocommit: no leaked write locks, ever
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        _conn_local.conn = c
    return c


def init_db():
    c = get_db()
    c.executescript(SCHEMA)
    try:
        c.executescript(FTS_SCHEMA)
        # keep the external-content FTS index in sync with the artifacts table
        c.executescript("""
        CREATE TRIGGER IF NOT EXISTS artifacts_ai AFTER INSERT ON artifacts BEGIN
          INSERT INTO artifacts_fts(rowid, content, source, type)
          VALUES (new.id, new.content, new.source, new.type);
        END;
        CREATE TRIGGER IF NOT EXISTS artifacts_ad AFTER DELETE ON artifacts BEGIN
          INSERT INTO artifacts_fts(artifacts_fts, rowid, content, source, type)
          VALUES ('delete', old.id, old.content, old.source, old.type);
        END;
        """)
    except sqlite3.OperationalError:
        pass  # FTS5 unavailable; full-text search degrades to LIKE
    c.commit()


def hash_content(content):
    if isinstance(content, (dict, list)):
        import json
        content = json.dumps(content, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()


def audit(username, action, target="", detail="", ip=""):
    try:
        c = get_db()
        c.execute(
            "INSERT INTO audit_log (ts,username,action,target,detail,ip) VALUES (?,?,?,?,?,?)",
            (utcnow(), username or "system", action, str(target)[:200], str(detail)[:500], ip),
        )
        c.commit()
    except Exception:
        pass


def store_artifact(case_id, entity_id, atype, source, content, queried_by):
    """Persist an evidence artifact with a SHA-256 chain-of-custody hash."""
    import json
    raw = json.dumps(content, sort_keys=True, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
    h = hash_content(raw)
    c = get_db()
    cur = c.execute(
        "INSERT INTO artifacts (case_id,entity_id,type,source,content,content_hash,queried_by,queried_at,verified)"
        " VALUES (?,?,?,?,?,?,?,?,1)",
        (case_id, entity_id, atype, source, raw, h, queried_by, utcnow()),
    )
    c.commit()
    return {"id": cur.lastrowid, "hash": h, "queried_at": utcnow()}


def verify_artifact(artifact_id):
    """Recompute the stored hash and confirm it matches (tamper detection)."""
    c = get_db()
    row = c.execute("SELECT content, content_hash FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
    if not row:
        return None
    recomputed = hash_content(row["content"])
    ok = recomputed == row["content_hash"]
    c.execute("UPDATE artifacts SET verified=? WHERE id=?", (1 if ok else 0, artifact_id))
    c.commit()
    return {"id": artifact_id, "valid": ok, "hash": row["content_hash"]}
