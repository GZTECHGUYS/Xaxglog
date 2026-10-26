"""Xaxglog dsar — data-subject request / takedown workflow (GDPR-style).

Keyless, fully local:
  - Templates: GDPR Art.15 access (copy of personal data), Art.17 erasure,
    Art.21 objection, Art.20 portability, CCPA/CPRA "right to know/delete",
    plus a platform-abuse takedown variant (fake account / impersonation /
    non-consensual image) addressed to a platform's trust & safety channel.
  - Deadlines: GDPR Art.12(3) = one month (extendable +2 months, must
    *justify* the extension); CCPA = 45 days (+45). The tracker computes
    both and alerts at 75% and at expiry.
  - Lifecycle: draft -> sent -> acknowledged -> fulfilled_partial ->
    fulfilled -> extension_declared -> complaint_filed -> closed. Every
    transition audited; correspondence hash-chained into the artifact store.

Scope note: this module helps a *data subject or their representative*
exercise rights and helps analysts manage legitimate requests. It does not
falsely assert legal representation — the operator fills in their standing.

Lawful-use note: your own rights (or a client's mandate). Platform ToS and
local law govern.
"""
import datetime
import json
import threading

import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS dsar_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  regime TEXT NOT NULL,                    -- GDPR | CCPA | PLATFORM
  kind TEXT NOT NULL,                      -- access|delete|portability|objection|takedown
  target_org TEXT NOT NULL,
  data_subject TEXT NOT NULL,
  standing TEXT DEFAULT '',                -- who the requester is / mandate
  body_md TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  deadline TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  sent_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""

# default statutory windows (days)
REGIMES = {
    "GDPR": {"label": "EU/UK GDPR", "sla_days": 30, "extension_days": 60,
             "article": "Art.12(3) — one month, extendable by two further "
                        "months where necessary (must inform within one month)"},
    "CCPA": {"label": "CCPA/CPRA (California)", "sla_days": 45,
             "extension_days": 45,
             "article": "45 days, one 45-day extension with notice"},
    "PLATFORM": {"label": "Platform abuse process", "sla_days": 14,
                 "extension_days": 0,
                 "article": "platform ToS/trust-and-safety SLA (varies)"},
}

KIND_TITLES = {
    "access": "Request for access to personal data (right of access)",
    "delete": "Request for erasure of personal data (right to be forgotten)",
    "portability": "Request for portability of personal data",
    "objection": "Objection to processing of personal data",
    "takedown": "Abuse report: impersonation / fake account / unlawful content",
}


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        c.commit()
    except Exception:
        pass


def regimes():
    return {"status": "ok", "regimes": REGIMES, "kinds": KIND_TITLES}


def _deadline(regime, sent=None):
    spec = REGIMES[regime]
    base = (datetime.date.fromisoformat(sent[:10]) if sent
            else datetime.date.today())
    return (base + datetime.timedelta(days=spec["sla_days"])).isoformat()


def _body(regime, kind, target_org, data_subject, standing, details):
    spec = REGIMES[regime]
    title = KIND_TITLES.get(kind, kind)
    today = datetime.date.today().isoformat()
    lines = [
        f"# {title}",
        "",
        f"**Date:** {today}",
        f"**To:** {target_org} — Data Protection Officer / Trust & Safety",
        f"**Regime:** {spec['label']} ({spec['article']})",
        "",
        "Dear Sir or Madam,",
        "",
        f"I am **{data_subject}**. " +
        (f"I act in the capacity of: {standing}. " if standing else "") +
        f"I exercise my rights under {spec['label']} regarding my personal "
        "data held by " + target_org + ".",
        "",
        "## Requested action",
    ]
    if kind == "access":
        lines += [
            "Provide a copy of all personal data relating to me that you "
            "process, including: sources of collection, purposes, categories, "
            "recipients, retention periods, and any automated decision-making "
            "or profiling.",
            "",
            "Provide the data in a structured, commonly used, machine-readable "
            "format (JSON/CSV) as per Art.20 where applicable.",
        ]
    elif kind == "delete":
        lines += [
            "Erase all personal data relating to me and inform me + any "
            "recipients of the erasure, as per Art.17.",
            "",
            "If you claim an exemption (legal obligation, freedom of "
            "expression, public interest archiving, legal claims), identify "
            "each category withheld and the specific ground relied upon.",
        ]
    elif kind == "portability":
        lines += [
            "Provide personal data you hold, provided by me or observed in "
            "the course of providing the service, in a structured, commonly "
            "used, machine-readable format, and transmit it directly to "
            "another controller where technically feasible (Art.20).",
        ]
    elif kind == "objection":
        lines += [
            "Cease processing my personal data for direct marketing and for "
            "any processing based on legitimate interests or public task, "
            "unless you demonstrate compelling legitimate grounds that "
            "override my interests (Art.21).",
        ]
    elif kind == "takedown":
        lines += [
            "Remove the following account/content that impersonates me or "
            "publishes unlawful material concerning me, and confirm the "
            "action taken:",
        ]
    if details:
        lines += ["", "## Details", str(details)[:4000]]
    lines += [
        "",
        "## Verification",
        "To verify my identity you may contact me at the address below; "
        "please do not require more data than strictly necessary for "
        "verification.",
        "",
        "## Deadline",
        f"Your statutory response window is **{spec['sla_days']} days** "
        f"(deadline: {_deadline(regime)}). " +
        ("Any extension must be justified within the initial period. "
         if spec["extension_days"] else "") +
        "If you do not respond, I may complain to the competent supervisory "
        "authority / regulator.",
        "",
        "**Contact:** (fill in)",
        "**Signed:** (fill in)",
    ]
    return "\n".join(lines)


def draft(regime, kind, target_org, data_subject, details=None,
          standing=None, created_by="system", case_id=None):
    """Draft a DSAR/abuse-takedown letter; custody-hashed + tracked."""
    try:
        init_schema()
        regime = (regime or "GDPR").upper()
        if regime not in REGIMES:
            return {"status": "error", "error": f"regime must be one of "
                                                f"{sorted(REGIMES)}"}
        if kind not in KIND_TITLES:
            return {"status": "error", "error": f"kind must be one of "
                                                f"{sorted(KIND_TITLES)}"}
        if not target_org or not data_subject:
            return {"status": "error",
                    "error": "target_org and data_subject are required"}
        body = _body(regime, kind, target_org, data_subject, standing or "",
                     details)
        h = db.hash_content(body)
        deadline = _deadline(regime)
        c = db.get_db()
        cur = c.execute(
            "INSERT INTO dsar_requests (regime,kind,target_org,data_subject,"
            "standing,body_md,body_hash,deadline,created_by,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (regime, kind, target_org, data_subject, standing or "", body, h,
             deadline, created_by, db.utcnow(), db.utcnow()))
        c.commit()
        art = db.store_artifact(case_id, None, "dsar", "draft-letter",
                                {"regime": regime, "kind": kind,
                                 "target": target_org, "body": body,
                                 "hash": h}, created_by)
        db.audit(created_by, "dsar.draft", f"{regime}:{kind}:{target_org}",
                 f"id={cur.lastrowid}")
        return {"status": "ok", "id": cur.lastrowid, "deadline": deadline,
                "hash": h, "body": body, "artifact": art,
                "regime": REGIMES[regime]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def set_status(request_id, status, actor="system", sent_at=None):
    ok = ("draft", "sent", "acknowledged", "extension_declared",
          "fulfilled_partial", "fulfilled", "complaint_filed", "closed",
          "refused")
    if status not in ok:
        return {"status": "error", "error": f"status must be one of {ok}"}
    try:
        init_schema()
        c = db.get_db()
        row = c.execute("SELECT id FROM dsar_requests WHERE id=?",
                        (request_id,)).fetchone()
        if not row:
            return {"status": "error", "error": "unknown request id"}
        if status == "sent":
            when = sent_at or db.utcnow()
            reg = c.execute("SELECT regime FROM dsar_requests WHERE id=?",
                            (request_id,)).fetchone()
            c.execute("UPDATE dsar_requests SET status=?, sent_at=?, "
                      "deadline=?, updated_at=? WHERE id=?",
                      (status, when, _deadline(reg["regime"], when),
                       db.utcnow(), request_id))
        else:
            c.execute("UPDATE dsar_requests SET status=?, updated_at=? WHERE id=?",
                      (status, db.utcnow(), request_id))
        c.commit()
        db.audit(actor, "dsar.set_status", str(request_id), status)
        if status == "complaint_filed":
            c.execute(
                "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES "
                "(?,?,?,?,?)",
                (None, db.utcnow(), "high",
                 f"DSAR #{request_id} escalated to regulator complaint",
                 json.dumps({"dsar_id": request_id})[:500]))
            c.commit()
        return {"status": "ok", "id": request_id, "state": status}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_requests(status=None, limit=50):
    try:
        init_schema()
        c = db.get_db()
        q = ("SELECT id,regime,kind,target_org,data_subject,deadline,status,"
             "created_at,sent_at FROM dsar_requests")
        args = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY id DESC LIMIT ?"
        args = args + (min(int(limit), 300),)
        return {"status": "ok",
                "requests": [dict(r) for r in c.execute(q, args)]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "requests": []}


def get_request(request_id):
    try:
        init_schema()
        row = db.get_db().execute(
            "SELECT * FROM dsar_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            return {"status": "error", "error": "unknown request id"}
        return {"status": "ok", "request": dict(row)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def deadline_alerts():
    """Alert at 75% of SLA + expiry for open requests."""
    try:
        init_schema()
        c = db.get_db()
        rows = c.execute(
            "SELECT id,target_org,kind,deadline,status,regime FROM dsar_requests "
            "WHERE status IN ('sent','acknowledged','extension_declared')").fetchall()
        raised = 0
        today = datetime.date.today()
        for r in rows:
            if not r["deadline"]:
                continue
            try:
                dl = datetime.date.fromisoformat(r["deadline"])
            except ValueError:
                continue
            if today > dl:
                c.execute(
                    "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES "
                    "(?,?,?,?,?)",
                    (None, db.utcnow(), "high",
                     f"DSAR #{r['id']} statutory deadline passed "
                     f"({dl.isoformat()}): {r['target_org']}",
                     json.dumps({"dsar_id": r["id"], "kind": "dsar_expired"})[:500]))
                raised += 1
            else:
                total = REGIMES.get(r["regime"], {}).get("sla_days", 30)
                elapsed = (today - dl).days + total
                if elapsed >= int(total * 0.75):
                    c.execute(
                        "INSERT INTO alerts (case_id,ts,severity,message,detail) "
                        "VALUES (?,?,?,?,?)",
                        (None, db.utcnow(), "medium",
                         f"DSAR #{r['id']} at 75% of window (due {dl.isoformat()})",
                         json.dumps({"dsar_id": r["id"], "kind": "dsar_due"})[:500]))
                    raised += 1
        c.commit()
        return {"status": "ok", "raised": raised}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=21600):
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                deadline_alerts()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="dsar").start()
    return True
