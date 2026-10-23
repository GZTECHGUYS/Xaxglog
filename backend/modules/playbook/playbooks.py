"""Xaxglog playbook engine — saved auto-pivot chains (reusable OSINT workflows).

Purpose : define, seed, list, run and delete "playbooks" — ordered chains of
          module steps ("pkg.module:function", restricted to the modules.*
          package) executed against a target inside a case. Each step is
          lazily imported, called with only the kwargs its signature accepts
          (target / case_id / user plus optional per-step "args"), and its
          summary is stored as a chain-of-custody artifact. Run progress is
          recorded in the playbook_runs table.
Sources : none directly — playbooks only orchestrate existing local modules
          (modules.infra, modules.recon, modules.corporate, modules.crypto).
Lawful use: run playbooks only against targets covered by an active case
          authorization; every run and step is written to the audit trail.
"""
import importlib
import inspect
import json
import time

import db

# --------------------------------------------------------------- schema
_SCHEMA = """
CREATE TABLE IF NOT EXISTS playbooks (
  name TEXT PRIMARY KEY,
  description TEXT DEFAULT '',
  steps_json TEXT NOT NULL,
  created_by TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS playbook_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  playbook TEXT NOT NULL,
  target TEXT,
  case_id INTEGER,
  started_at TEXT,
  finished_at TEXT,
  status TEXT DEFAULT 'running',
  result_json TEXT DEFAULT '{}'
);
"""

# Seed chains (module strings MUST start with "modules."). Signatures verified
# against the live modules: pivot_domain(domain, case_id, user),
# run_pipeline(target, ptype, case_id, user, ...), pivot_ip(ip, ...),
# trace_person(person_name, ...), address_overview(addr, ...).
DEFAULTS = [
    {"name": "domain_pivot",
     "description": "Domain infrastructure pivot: DNS/ASN/shared-hosting, then full recon pipeline.",
     "steps": [{"module": "modules.infra.infra:pivot_domain"},
               {"module": "modules.recon.pipeline:run_pipeline"}]},
    {"name": "ip_pivot",
     "description": "IP attribution pivot: PTR, ASN/operator, co-hosted domains.",
     "steps": [{"module": "modules.infra.infra:pivot_ip"}]},
    {"name": "person_pivot",
     "description": "Person -> company/officer links via OpenCorporates + Wikidata search.",
     "steps": [{"module": "modules.corporate.corporate:trace_person"}]},
    {"name": "crypto_pivot",
     "description": "Crypto address overview (BTC/ETH balance, tx summary, counterparties).",
     "steps": [{"module": "modules.crypto.crypto:address_overview"}]},
]


def _ensure():
    """Create playbook tables on first use (db.py is never modified)."""
    c = db.get_db()
    c.executescript(_SCHEMA)
    c.commit()


# --------------------------------------------------------------- CRUD
def save_playbook(name, steps, user, description=""):
    """Create or update a playbook (steps = [{"module": "...", ...}, ...])."""
    try:
        name = (name or "").strip()
        if not name:
            return {"error": "playbook name required"}
        if not isinstance(steps, (list, tuple)):
            return {"error": "steps must be a list of dicts"}
        clean = []
        for s in steps:
            if not isinstance(s, dict) or not s.get("module"):
                return {"error": "each step needs a 'module' key ('pkg.module:function')"}
            clean.append(dict(s))
        _ensure()
        c = db.get_db()
        now = db.utcnow()
        c.execute(
            "INSERT INTO playbooks (name, description, steps_json, created_by, created_at)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET description=excluded.description,"
            " steps_json=excluded.steps_json, created_by=excluded.created_by",
            (name, str(description or ""), json.dumps(clean, ensure_ascii=False),
             user or "system", now))
        c.commit()
        db.audit(user, "playbook.save", name, f"steps={len(clean)}")
        return {"name": name, "steps": len(clean), "created_by": user or "system",
                "created_at": now}
    except Exception as e:
        return {"error": str(e)[:150]}


def list_playbooks():
    """All saved playbooks with parsed steps."""
    try:
        _ensure()
        rows = db.get_db().execute(
            "SELECT name, description, steps_json, created_by, created_at"
            " FROM playbooks ORDER BY name").fetchall()
        out = []
        for r in rows:
            try:
                steps = json.loads(r["steps_json"])
            except Exception:
                steps = []
            out.append({"name": r["name"], "description": r["description"],
                        "steps": steps, "step_count": len(steps),
                        "created_by": r["created_by"], "created_at": r["created_at"]})
        return out
    except Exception:
        return []


def get_playbook(name):
    """Single playbook dict, or None when absent/unreadable."""
    try:
        _ensure()
        r = db.get_db().execute("SELECT * FROM playbooks WHERE name=?", (name,)).fetchone()
        if not r:
            return None
        try:
            steps = json.loads(r["steps_json"])
        except Exception:
            steps = []
        return {"name": r["name"], "description": r["description"], "steps": steps,
                "created_by": r["created_by"], "created_at": r["created_at"]}
    except Exception:
        return None


def delete_playbook(name):
    """Remove a playbook by name."""
    try:
        _ensure()
        c = db.get_db()
        cur = c.execute("DELETE FROM playbooks WHERE name=?", (name,))
        c.commit()
        deleted = bool(cur.rowcount)
        db.audit("system", "playbook.delete", name, f"deleted={deleted}")
        return {"name": name, "deleted": deleted}
    except Exception as e:
        return {"error": str(e)[:150], "name": name, "deleted": False}


def seed_defaults():
    """Idempotently insert the four built-in pivot chains (never overwrites)."""
    try:
        _ensure()
        c = db.get_db()
        seeded = []
        for d in DEFAULTS:
            row = c.execute("SELECT 1 FROM playbooks WHERE name=?", (d["name"],)).fetchone()
            if row:
                continue
            c.execute(
                "INSERT INTO playbooks (name, description, steps_json, created_by, created_at)"
                " VALUES (?,?,?,?,?)",
                (d["name"], d["description"], json.dumps(d["steps"], ensure_ascii=False),
                 "system", db.utcnow()))
            c.commit()
            db.audit("system", "playbook.seed", d["name"], f"steps={len(d['steps'])}")
            seeded.append(d["name"])
        return {"seeded": seeded, "total": len(list_playbooks())}
    except Exception as e:
        return {"error": str(e)[:150]}


# --------------------------------------------------------------- execution
def _load(module_str):
    """Import 'pkg.module:function' (only modules.* allowed) -> callable."""
    mod_path, sep, fn_name = str(module_str).partition(":")
    if not sep or not mod_path or not fn_name:
        raise ValueError("step module must look like 'pkg.module:function'")
    if not mod_path.startswith("modules."):
        raise ValueError("only modules.* steps are allowed")
    mod = importlib.import_module(mod_path)
    fn = getattr(mod, fn_name, None)
    if not callable(fn):
        raise ValueError(f"function '{fn_name}' not found in {mod_path}")
    return fn


def _bind(fn, target, case_id, user, step):
    """Assemble kwargs from {target, case_id, user} filtered to fn's signature.

    A single unfilled required parameter receives `target` (so domain/ip/addr/
    person_name style signatures work). Per-step "args" are merged verbatim.
    """
    params = inspect.signature(fn).parameters
    base = {"target": target, "case_id": case_id, "user": user}
    kwargs = {k: v for k, v in base.items() if k in params}
    for k, v in (step.get("args") or {}).items():
        kwargs[k] = v
    missing = [n for n, p in params.items()
               if n not in kwargs
               and p.default is inspect.Parameter.empty
               and p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                              inspect.Parameter.KEYWORD_ONLY)]
    if len(missing) == 1:
        kwargs[missing[0]] = target
    return kwargs


def _summarize(out, limit=400):
    try:
        if isinstance(out, (dict, list)):
            txt = json.dumps(out, ensure_ascii=False, default=str)
        else:
            txt = str(out)
    except Exception:
        txt = repr(out)
    return txt[:limit]


def run_playbook(name, target, case_id, user):
    """Run a playbook sequentially; never raises.

    Returns {playbook, target, steps:[{i, module, status, summary, error}],
    elapsed}. Stops at the first failed step unless that step sets
    "continue_on_error": true.
    """
    t0 = time.monotonic()
    started_at = db.utcnow()
    run_id = None

    def _finish(status, steps_out):
        elapsed = round(time.monotonic() - t0, 3)
        result = {"playbook": name, "target": target, "steps": steps_out,
                  "elapsed": elapsed}
        try:
            if run_id is not None:
                c = db.get_db()
                payload = json.dumps(result, ensure_ascii=False, default=str)
                c.execute("UPDATE playbook_runs SET finished_at=?, status=?, result_json=?"
                          " WHERE id=?",
                          (db.utcnow(), status, payload[:20000], run_id))
                c.commit()
        except Exception:
            pass
        return result

    try:
        _ensure()
        pb = get_playbook(name)
        if not pb:
            db.audit(user, "playbook.run.missing", str(name), f"target={target}")
            res = _finish("missing", [])
            res["error"] = f"playbook '{name}' not found"
            return res

        c = db.get_db()
        cur = c.execute(
            "INSERT INTO playbook_runs (playbook, target, case_id, started_at, status)"
            " VALUES (?,?,?,?, 'running')",
            (name, str(target), case_id, started_at))
        c.commit()
        run_id = cur.lastrowid
        db.audit(user, "playbook.run.start", name, f"target={target}")

        steps_out = []
        stopped = False
        for i, step in enumerate(pb["steps"]):
            if stopped:
                break
            mod_str = step.get("module")
            rec = {"i": i, "module": mod_str, "status": "ok", "summary": "", "error": None}
            try:
                fn = _load(mod_str)
                kwargs = _bind(fn, target, case_id, user, step)
                out = fn(**kwargs)
                rec["summary"] = _summarize(out)
                if isinstance(out, dict) and out.get("error"):
                    rec["status"] = "error"
                    rec["error"] = str(out["error"])[:150]
            except Exception as e:
                rec["status"] = "error"
                rec["error"] = str(e)[:150]
                rec["summary"] = f"error: {rec['error']}"

            # chain-of-custody artifact for this step (summary text)
            try:
                db.store_artifact(case_id, None, "playbook",
                                  f"playbook:{name}:{i}", rec["summary"] or "", user)
                db.audit(user, "playbook.step", f"{name}:{i}",
                         f"status={rec['status']}")
            except Exception:
                pass

            steps_out.append(rec)
            if rec["status"] == "error" and not step.get("continue_on_error"):
                stopped = True

        status = "ok" if all(r["status"] == "ok" for r in steps_out) else "error"
        result = _finish(status, steps_out)
        db.audit(user, "playbook.run.finish", name,
                 f"status={status} steps={len(steps_out)} elapsed={result['elapsed']}")
        return result
    except Exception as e:
        res = _finish("error", [])
        res["error"] = str(e)[:150]
        return res
