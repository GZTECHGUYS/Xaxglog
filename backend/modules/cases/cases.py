"""Xaxglog case management + entity graph + watchlists.

Case management is the operational backbone: investigators work inside a named,
audited case with a stated legal basis. Every module attaches entities, edges,
and hashed evidence to a case. The graph is the connective tissue that turns
scattered results into an intelligence picture.

Watchlists run scheduled sweeps and raise alerts on new findings.
"""
import json
import sqlite3

import db


# ------------------------------------------------------------------ cases
def create_case(name, description, legal_basis, username):
    c = db.get_db()
    today = db.utcnow()[:10]
    # Collision-safe numbering: derive the next sequence from the highest
    # numeric suffix used today (not COUNT(*), which collides after deletes),
    # and retry on the off chance of a concurrent insert racing us.
    base = c.execute(
        "SELECT MAX(CAST(SUBSTR(case_number, -4) AS INTEGER)) m FROM cases"
        " WHERE case_number LIKE ?",
        (f"XG-{today}-%",)).fetchone()["m"] or 0
    n = int(base) + 1
    for _ in range(50):
        case_number = f"XG-{today}-{n:04d}"
        try:
            cur = c.execute(
                "INSERT INTO cases (case_number,name,description,legal_basis,created_by,created_at)"
                " VALUES (?,?,?,?,?,?)",
                (case_number, name, description or "", legal_basis or "", username, db.utcnow()))
            break
        except sqlite3.IntegrityError:
            n += 1
    else:
        c.rollback()
        db.audit(username, "case.create.error", "", "numbering exhausted")
        return {"error": "could not allocate a unique case number"}
    case_id = cur.lastrowid
    c.execute("INSERT INTO case_members (case_id,username,permission) VALUES (?,?,?)",
              (case_id, username, "edit"))
    db.audit(username, "case.create", case_number, name[:120])
    return {"id": case_id, "case_number": case_number, "name": name}


def list_cases(username=None, role="analyst"):
    c = db.get_db()
    if role == "admin" or not username:
        rows = c.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    else:
        rows = c.execute(
            "SELECT ca.* FROM cases ca JOIN case_members cm ON ca.id=cm.case_id"
            " WHERE cm.username=? ORDER BY id DESC", (username,)).fetchall()
    return [dict(r) for r in rows]


def get_case(case_id):
    c = db.get_db()
    row = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        return None
    case = dict(row)
    case["members"] = [dict(r) for r in c.execute(
        "SELECT username,permission FROM case_members WHERE case_id=?", (case_id,)).fetchall()]
    case["entity_count"] = c.execute(
        "SELECT COUNT(*) c FROM entities WHERE case_id=?", (case_id,)).fetchone()["c"]
    case["artifact_count"] = c.execute(
        "SELECT COUNT(*) c FROM artifacts WHERE case_id=?", (case_id,)).fetchone()["c"]
    return case


def update_case(case_id, fields, username):
    allowed = {"name", "description", "legal_basis", "status"}
    sets, args = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k}=?")
            args.append(v)
    if not sets:
        return {"error": "no valid fields"}
    c = db.get_db()
    args.append(case_id)
    c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id=?", args)
    c.commit()
    db.audit(username, "case.update", str(case_id), json.dumps(fields)[:200])
    return {"updated": True}


def add_member(case_id, username, permission, actor):
    c = db.get_db()
    c.execute(
        "INSERT INTO case_members (case_id,username,permission) VALUES (?,?,?)"
        " ON CONFLICT(case_id,username) DO UPDATE SET permission=excluded.permission",
        (case_id, username, permission))
    c.commit()
    db.audit(actor, "case.member_add", str(case_id), f"{username}:{permission}")
    return {"added": True}


# ------------------------------------------------------------------ entity graph
def get_graph(case_id, max_nodes=500):
    """Return nodes + links for the force-directed entity graph."""
    c = db.get_db()
    nodes = [dict(r) for r in c.execute(
        "SELECT id,type,value,first_seen,last_seen FROM entities WHERE case_id=?"
        " ORDER BY id LIMIT ?", (case_id, max_nodes)).fetchall()]
    node_ids = {n["id"] for n in nodes}
    links = []
    for r in c.execute("SELECT src_id,dst_id,relation,weight,source FROM edges"
                       " WHERE case_id=?", (case_id,)).fetchall():
        if r["src_id"] in node_ids and r["dst_id"] in node_ids:
            links.append(dict(r))
    return {"nodes": nodes, "links": links,
            "node_count": len(nodes), "link_count": len(links)}


def add_entity(case_id, etype, value, meta=None):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, etype, value, now, now, json.dumps(meta or {})))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def link_entities(case_id, src_id, dst_id, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src_id, dst_id, relation, weight, source, db.utcnow()))
    c.commit()
    return {"linked": True}


# ------------------------------------------------------------------ search (FTS5)
def search_artifacts(query, case_id=None, limit=50):
    """Full-text search across every stored evidence artifact."""
    c = db.get_db()
    try:
        q = ("SELECT a.id,a.case_id,a.type,a.source,a.queried_by,a.queried_at,"
             "a.content_hash, snippet(artifacts_fts,0,'<mark>','</mark>',' … ',20) snip"
             " FROM artifacts_fts JOIN artifacts a ON a.id=artifacts_fts.rowid"
             " WHERE artifacts_fts MATCH ?")
        args = [query]
        if case_id is not None:
            q += " AND a.case_id=?"
            args.append(case_id)
        q += " ORDER BY rank LIMIT ?"
        args.append(limit)
        rows = [dict(r) for r in c.execute(q, args).fetchall()]
        return {"mode": "fts5", "results": rows}
    except Exception:
        # FTS5 unavailable -> LIKE fallback
        q = "SELECT id,case_id,type,source,queried_by,queried_at,content_hash FROM artifacts WHERE content LIKE ?"
        args = [f"%{query}%"]
        if case_id is not None:
            q += " AND case_id=?"
            args.append(case_id)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = [dict(r) for r in c.execute(q, args).fetchall()]
        return {"mode": "like", "results": rows}


# ------------------------------------------------------------------ watchlists
def add_watch(case_id, etype, value, checks, interval_min, username):
    c = db.get_db()
    c.execute(
        "INSERT INTO watchlist (case_id,entity_type,entity_value,checks,interval_min,created_by,created_at)"
        " VALUES (?,?,?,?,?,?,?)"
        " ON CONFLICT(case_id,entity_type,entity_value) DO UPDATE SET"
        " checks=excluded.checks, interval_min=excluded.interval_min, enabled=1",
        (case_id, etype, value, json.dumps(checks or []), int(interval_min or 360),
         username, db.utcnow()))
    c.commit()
    wid = c.execute(
        "SELECT id FROM watchlist WHERE case_id=? AND entity_type=? AND entity_value=?",
        (case_id, etype, value)).fetchone()["id"]
    db.audit(username, "watchlist.add", value[:120], f"checks={checks}")
    return {"id": wid}


def list_watchlists(case_id=None):
    c = db.get_db()
    q = "SELECT * FROM watchlist"
    args = []
    if case_id is not None:
        q += " WHERE case_id=?"
        args.append(case_id)
    q += " ORDER BY id DESC"
    rows = [dict(r) for r in c.execute(q, args).fetchall()]
    for r in rows:
        r["checks"] = json.loads(r.get("checks") or "[]")
    return rows


def due_watchlists():
    """Watchlists whose interval has elapsed since last_run (or never run)."""
    import datetime
    c = db.get_db()
    rows = [dict(r) for r in c.execute("SELECT * FROM watchlist WHERE enabled=1").fetchall()]
    now = datetime.datetime.utcnow()
    due = []
    for r in rows:
        if not r.get("last_run"):
            due.append(r)
            continue
        try:
            last = datetime.datetime.fromisoformat(r["last_run"].replace("Z", ""))
            if (now - last).total_seconds() >= r["interval_min"] * 60:
                due.append(r)
        except Exception:
            due.append(r)
    return due


def mark_watch_run(wid):
    c = db.get_db()
    c.execute("UPDATE watchlist SET last_run=? WHERE id=?", (db.utcnow(), wid))
    c.commit()


def raise_alert(watchlist_id, case_id, severity, message, detail=None):
    c = db.get_db()
    c.execute(
        "INSERT INTO alerts (watchlist_id,case_id,ts,severity,message,detail) VALUES (?,?,?,?,?,?)",
        (watchlist_id, case_id, db.utcnow(), severity, message, json.dumps(detail or {})))
    c.commit()


def list_alerts(case_id=None, unack_only=False, limit=100):
    c = db.get_db()
    q = "SELECT * FROM alerts"
    args = []
    if case_id is not None:
        q += " WHERE case_id=?"
        args.append(case_id)
    if unack_only:
        q += (" AND" if "WHERE" in q else " WHERE") + " acknowledged=0"
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in c.execute(q, args).fetchall()]


def acknowledge_alert(alert_id):
    c = db.get_db()
    c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    c.commit()
