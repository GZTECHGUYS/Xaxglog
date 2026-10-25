"""Xaxglog foia — public-records request drafting + tracking.

Keyless, fully local:
  - Jurisdiction templates: US FOIA (federal agency), US state public
    records acts (CA/PRA, NY/FOIL, TX/PIA, FL/ch.119 — structural
    differences noted), UK FOI 2000, EU Aarhus/Access-to-docs, CA ATIP,
    AU FOI Act, IN RTI 2005. Each: where to send, response deadline,
    fee-waiver hooks, exemptions to anticipate.
  - Request letter generator: fills template with subject/scope/fee
    preferences -> markdown artifact (SHA-256 for the case file).
  - Tracker: draft -> submitted -> agency-ack -> overdue-alert (deadline
    computed from jurisdiction SLA) -> received -> appeal. Stored in own
    table; alert raised at 80% of deadline and past it.

Workflow tie-in: response documents land as case artifacts (docintel can
then parse them).

Lawful-use note: drafting tooling for lawful access to *public* records.
It composes your request — it does not file anything automatically, and it
does not circumvent any process.
"""
import datetime
import json
import re
import threading

import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS foia_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  jurisdiction TEXT NOT NULL,
  agency TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  letter_md TEXT NOT NULL,
  letter_hash TEXT NOT NULL,
  deadline TEXT,
  status TEXT NOT NULL DEFAULT 'draft',  -- draft|submitted|acknowledged|received|overdue|appeal|closed
  submitted_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""

# SLA in days + submission channel notes per jurisdiction
JURISDICTIONS = {
    "US-FOIA": {"label": "US federal FOIA", "sla_days": 20,
                "channel": "agency FOIA portal or FOIA.gov request",
                "fee_note": "fee waiver if disclosure is in the public interest "
                            "(16 CFR/agency regs) — include a waiver paragraph",
                "exemptions": ["(b)(1) national security", "(b)(4) trade secrets",
                               "(b)(6) personal privacy", "(b)(7) law enforcement"]},
    "US-CA": {"label": "California CPRA (PRA)", "sla_days": 10,
              "channel": "agency CPRA coordinator (email accepted)",
              "fee_note": "cost-based fee waiver possible; 14-day extension typical",
              "exemptions": ["CPRA 6254 privacy", "6255 safety"]},
    "US-NY": {"label": "New York FOIL", "sla_days": 5,
              "channel": "agency records access officer (email/portal)",
              "fee_note": "copy fees; 5 business days to acknowledge",
              "exemptions": ["FOIL 87(2) law enforcement", "87(2)(b) interagency"]},
    "US-TX": {"label": "Texas PIA (PIRA)", "sla_days": 10,
              "channel": "agency public information officer",
              "fee_note": "hourly labor after first 3 hours; AG opinions route",
              "exemptions": ["Govt Code 552.101 exceptions"]},
    "US-FL": {"label": "Florida ch.119 public records", "sla_days": 7,
              "channel": "agency custodian (email OK)",
              "fee_note": "copy cost; must state purpose is lawful",
              "exemptions": ["119.071 exemptions"]},
    "GB-FOI": {"label": "UK Freedom of Information Act 2000", "sla_days": 20,
               "channel": "authority FOI team or access portal (ICO for appeals)",
               "fee_note": "UP to £450 search/inspection cost limit",
               "exemptions": ["s.40 personal data", "s.31 law enforcement",
                              "s.38 health & safety", "s.43 commercial"]},
    "EU-ATD": {"label": "EU Regulation 1049/2001 access to documents", "sla_days": 15,
               "channel": "Commission/Council access-to-documents portal",
               "fee_note": "free for access; copy fees may apply",
               "exemptions": ["art.4 security", "art.4(1)(b) court proceedings",
                              "art.4(1)(c) international relations", "art.5 personal data"]},
    "CA-ATIP": {"label": "Canada ATIP", "sla_days": 30,
                "channel": "institution ATIP office online form",
                "fee_note": "application fee + search fees waived for research/news",
                "exemptions": ["s.19 personal info", "s.16 law enforcement",
                               "s.15 international affairs"]},
    "AU-FOI": {"label": "Australia Freedom of Information Act 1982", "sla_days": 30,
               "channel": "agency FOI officer / OAIC",
               "fee_note": "25 hr free processing first request",
               "exemptions": ["s.47 cabinet", "s.47B national security"]},
    "IN-RTI": {"label": "India RTI Act 2005", "sla_days": 30,
               "channel": "RTI portal (rtionline.gov.in) or API address",
               "fee_note": "Rs 10 application; fee waiver for BPL applicants",
               "exemptions": ["s.8 exemptions", "8(1)(d) commercial confidence"]},
    "ZA-PAIA": {"label": "South Africa PAIA", "sla_days": 30,
                "channel": "information officer at the body",
                "fee_note": "reproduction fees per schedule",
                "exemptions": ["s.6 + schedules 1-2"]},
}


def init_schema():
    try:
        c = db.get_db()
        c.executescript(SCHEMA)
        c.commit()
    except Exception:
        pass


def jurisdictions():
    return {"status": "ok", "count": len(JURISDICTIONS),
            "jurisdictions": JURISDICTIONS}


def _letter(jur, agency, subject, scope, requester, fee_waiver, extra):
    spec = JURISDICTIONS[jur]
    today = datetime.date.today().isoformat()
    deadline = (datetime.date.today()
                + datetime.timedelta(days=spec["sla_days"])).isoformat()
    parts = [
        f"# Public records request — {spec['label']}",
        "",
        f"**Date:** {today}",
        f"**To:** {agency} — Records/FOI team",
        f"**Channel:** {spec['channel']}",
        "",
        "Dear Records Officer,",
        "",
        "Under the " + spec["label"] + ", I request copies of the following "
        "records. I am willing to pay reasonable duplication fees; please "
        "notify me if fulfillment is estimated to exceed "
        + ("the applicable fee waiver threshold" if fee_waiver
           else "the standard cost limit") + ".",
        "",
        "## Subject / description",
        f"{subject}",
        "",
        "## Scope (be specific: date range, systems, file types)",
        f"{scope}",
        "",
        "## Records requested",
        "1. All records relating to the subject above, held in any format "
        "(including emails, memoranda, databases, spreadsheets, calendars, "
        "and messaging exports), for the period stated.",
        "2. Any index, register, or schedule describing those records.",
        "3. The names (role titles) of the custodians holding them.",
        "",
    ]
    if fee_waiver:
        parts += [
            "## Fee waiver request",
            "Disclosure is in the public interest and contributes to "
            "understanding of the subject matter; the request is not "
            "primarily in my commercial interest. I therefore request a "
            "full fee waiver. If denied, please provide a written "
            "explanation before incurring costs and notify me of the "
            "estimated amount.",
            "",
        ]
    parts += [
        "## Processing",
        "If any part is exempt, please release the remainder on a "
        "severable basis and cite the specific exemption applied to each "
        "withheld record. If another body holds the records, please advise "
        "and transfer this request where the scheme permits.",
        "",
        "Statutory response window: "
        f"**{spec['sla_days']} days** — deadline {deadline}.",
        "",
        f"**Requester:** {requester}",
        "Contact: (fill in)",
    ]
    if extra:
        parts += ["", "## Additional notes", str(extra)[:1500]]
    parts += ["", "Yours faithfully,", "", "(sign)"]
    return "\n".join(parts), deadline


def draft(jurisdiction, agency, subject, scope, requester="Anonymous requester",
          fee_waiver=True, extra=None, created_by="system", case_id=None):
    """Draft a request letter; stores it (custody-hashed) as a tracker row."""
    try:
        init_schema()
        jur = (jurisdiction or "").strip().upper()
        if jur not in JURISDICTIONS:
            return {"status": "error", "error": f"unknown jurisdiction",
                    "known": sorted(JURISDICTIONS)}
        if not agency or not subject or not scope:
            return {"status": "error",
                    "error": "agency, subject and scope are required"}
        md, deadline = _letter(jur, agency, subject, scope, requester,
                               fee_waiver, extra)
        h = db.hash_content(md)
        c = db.get_db()
        cur = c.execute(
            "INSERT INTO foia_requests (jurisdiction,agency,subject,scope,letter_md,"
            "letter_hash,deadline,created_by,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (jur, agency, subject, scope, md, h, deadline,
             created_by, db.utcnow(), db.utcnow()))
        c.commit()
        art = db.store_artifact(case_id, None, "foia", "draft-letter",
                                {"jurisdiction": jur, "agency": agency,
                                 "letter": md, "hash": h}, created_by)
        db.audit(created_by, "foia.draft", f"{jur}:{agency}",
                 f"id={cur.lastrowid} deadline={deadline}")
        return {"status": "ok", "id": cur.lastrowid, "deadline": deadline,
                "hash": h, "letter": md, "artifact": art,
                "channel": JURISDICTIONS[jur]["channel"]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def submit(request_id, submitted_at=None, actor="system"):
    """Mark submitted (you sent it via the jurisdiction's channel)."""
    try:
        init_schema()
        c = db.get_db()
        row = c.execute("SELECT id,deadline FROM foia_requests WHERE id=?",
                        (request_id,)).fetchone()
        if not row:
            return {"status": "error", "error": "unknown request id"}
        when = submitted_at or db.utcnow()
        c.execute("UPDATE foia_requests SET status='submitted', submitted_at=?, "
                  "updated_at=? WHERE id=?",
                  (when, db.utcnow(), request_id))
        c.commit()
        db.audit(actor, "foia.submit", str(request_id), when)
        return {"status": "ok", "id": request_id, "submitted_at": when,
                "deadline": row["deadline"]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def set_status(request_id, status, actor="system"):
    ok = ("draft", "submitted", "acknowledged", "received", "appeal", "closed")
    if status not in ok:
        return {"status": "error", "error": f"status must be one of {ok}"}
    try:
        init_schema()
        c = db.get_db()
        c.execute("UPDATE foia_requests SET status=?, updated_at=? WHERE id=?",
                  (status, db.utcnow(), request_id))
        c.commit()
        db.audit(actor, "foia.set_status", str(request_id), status)
        return {"status": "ok", "id": request_id, "state": status}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def list_requests(status=None, limit=50):
    try:
        init_schema()
        c = db.get_db()
        q = ("SELECT id,jurisdiction,agency,subject,deadline,status,"
             "created_by,created_at,submitted_at FROM foia_requests")
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
            "SELECT * FROM foia_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            return {"status": "error", "error": "unknown request id"}
        return {"status": "ok", "request": dict(row)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def deadline_alerts():
    """Alert at 80% of SLA and once overdue (open requests only)."""
    try:
        init_schema()
        c = db.get_db()
        rows = c.execute(
            "SELECT id,agency,subject,deadline,status FROM foia_requests "
            "WHERE status IN ('submitted','acknowledged','overdue')").fetchall()
        raised = 0
        today = datetime.date.today()
        for r in rows:
            if not r["deadline"]:
                continue
            try:
                dl = datetime.date.fromisoformat(r["deadline"])
            except ValueError:
                continue
            total = max(1, (dl - today).days)
            if today > dl and r["status"] != "overdue":
                c.execute("UPDATE foia_requests SET status='overdue', updated_at=? "
                          "WHERE id=?", (db.utcnow(), r["id"]))
                c.execute(
                    "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES "
                    "(?,?,?,?,?)",
                    (None, db.utcnow(), "high",
                     f"FOI request #{r['id']} OVERDUE vs {dl.isoformat()}: "
                     f"{r['agency']} — {r['subject'][:80]}",
                     json.dumps({"request_id": r["id"], "kind": "foia_overdue"})[:500]))
                raised += 1
            elif 0 <= total <= 2:
                c.execute(
                    "INSERT INTO alerts (case_id,ts,severity,message,detail) VALUES "
                    "(?,?,?,?,?)",
                    (None, db.utcnow(), "medium",
                     f"FOI request #{r['id']} deadline in {total}d "
                     f"({dl.isoformat()}): {r['agency']}",
                     json.dumps({"request_id": r["id"], "kind": "foia_deadline"})[:500]))
                raised += 1
        c.commit()
        return {"status": "ok", "raised": raised}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


_daemon_stop = threading.Event()


def start_daemon(interval_sec=43200):
    init_schema()

    def _loop():
        while not _daemon_stop.is_set():
            try:
                deadline_alerts()
            except Exception:
                pass
            _daemon_stop.wait(interval_sec)

    threading.Thread(target=_loop, daemon=True, name="foia").start()
    return True
