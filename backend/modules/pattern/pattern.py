"""Xaxglog Social Pattern Tracker — entity linkage + pattern-of-life.

Waves (ROADMAP_PART3 W3):
  1. schema + link store   — pattern_links / _interactions / _urls / _ips
  2. interaction ingest    — normalized event schema (connectors.py feeds it)
  3. scoring               — decay weights, frequent contacts, active-hours
  4. URL + IP ledgers      — share timeline, DNS/evidence-header IPs
  5. graph emission        — every link/interaction lands in the case graph
  6. tracker snapshots     — new_contact / contact_drop / cadence_change

Data honesty: no public source exposes a person's browsing history. The URL
ledger holds what they *share publicly*; the IP ledger holds disclosed IPs
(evidence headers, public posts) and infra IPs (their domains' resolution).
Every row carries its source so the graph never claims more than the evidence.
"""
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import db

from modules.pattern import scoring as SC

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 12

_ready = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS pattern_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  src_type TEXT NOT NULL,
  src_value TEXT NOT NULL,
  dst_type TEXT NOT NULL,
  dst_value TEXT NOT NULL,
  relation TEXT NOT NULL,            -- member_of|handle_of|contacts|shares_url|resolves_to
  source TEXT DEFAULT '',
  confidence REAL DEFAULT 0.5,
  evidence_id INTEGER,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pattern_interactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  actor_type TEXT NOT NULL,
  actor_value TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_value TEXT NOT NULL,
  platform TEXT NOT NULL,
  kind TEXT NOT NULL,                -- reply|mention|quote|co_comment|co_author|co_mention|thread
  ts TEXT NOT NULL,
  url TEXT DEFAULT '',
  text TEXT DEFAULT '',
  evidence_id INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pattern_urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  entity TEXT NOT NULL,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  ts TEXT NOT NULL,
  source TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS pattern_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER,
  entity TEXT NOT NULL,
  ip TEXT NOT NULL,
  source TEXT NOT NULL,              -- evidence_header|public_post|dns_history|infra|manual
  note TEXT DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS ix_pl_case   ON pattern_links (case_id, src_value, dst_value);
CREATE INDEX IF NOT EXISTS ix_pi_actor  ON pattern_interactions (actor_value, ts);
CREATE INDEX IF NOT EXISTS ix_pi_target ON pattern_interactions (target_value, ts);
CREATE INDEX IF NOT EXISTS ix_pu_entity ON pattern_urls (entity, ts);
CREATE INDEX IF NOT EXISTS ix_pp_entity ON pattern_ips (entity, ip);
"""

_RELATIONS = {"member_of", "handle_of", "contacts", "shares_url", "resolves_to",
              "affiliated", "co_worker"}
_KINDS = set(SC.WEIGHTS) | {"follow"}
_TYPES = {"person", "org", "handle", "email", "username", "domain", "ip", "phone",
          "company", "geo", "url", "channel"}


def _ensure():
    global _ready
    if _ready:
        return
    c = db.get_db()
    c.executescript(SCHEMA)
    c.executescript(INDEXES)
    c.commit()
    _ready = True


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(ts):
    return SC._parse_ts(ts) or datetime.now(timezone.utc)


def guess_type(value):
    v = (value or "").strip()
    if not v:
        return "handle"
    if "@" in v and " " not in v:
        return "email"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "ip"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", v, re.I):
        return "domain"
    if v.startswith(("#", "@")) or " " not in v:
        return "handle" if len(v) < 60 else "person"
    return "person"


def _ctx(event, key):
    """Accept {"type":..,"value":..} or a bare string for actor/target."""
    raw = (event or {}).get(key)
    if isinstance(raw, dict):
        val = str(raw.get("value") or "").strip()
        typ = str(raw.get("type") or "").strip() or guess_type(val)
    else:
        val = str(raw or "").strip()
        typ = guess_type(val)
    return typ, val


# ---------------------------------------------------------------- 1+5: links & graph
def _graph_link(case_id, src_type, src_value, dst_type, dst_value, relation, weight, source):
    """Emit both endpoints + the edge into the case entity graph."""
    if case_id is None:
        return None
    try:
        import modules.cases.cases as CASES
        sid = CASES.add_entity(case_id, src_type, src_value)
        did = CASES.add_entity(case_id, dst_type, dst_value)
        CASES.link_entities(case_id, sid, did, relation, weight, source)
        return {"src_id": sid, "dst_id": did}
    except Exception:
        return None


def add_link(src_type, src_value, dst_type, dst_value, relation="contacts",
             source="", confidence=0.5, case_id=None, user="system",
             evidence_id=None, emit_graph=True):
    _ensure()
    relation = relation if relation in _RELATIONS else "contacts"
    src_value, dst_value = str(src_value or "").strip(), str(dst_value or "").strip()
    if not src_value or not dst_value:
        return {"error": "src_value and dst_value are required"}
    src_type = src_type or guess_type(src_value)
    dst_type = dst_type or guess_type(dst_value)
    now = _now()
    c = db.get_db()
    row = c.execute(
        "SELECT id FROM pattern_links WHERE COALESCE(case_id,0)=COALESCE(?,0)"
        " AND src_type=? AND src_value=? AND dst_type=? AND dst_value=? AND relation=?",
        (case_id, src_type, src_value, dst_type, dst_value, relation)).fetchone()
    if row:
        c.execute("UPDATE pattern_links SET last_seen=?, confidence=MAX(confidence,?), source=? WHERE id=?",
                  (now, float(confidence or 0.5), source or "", row["id"]))
        c.commit()
        link_id, created = row["id"], False
    else:
        cur = c.execute(
            "INSERT INTO pattern_links (case_id,src_type,src_value,dst_type,dst_value,"
            "relation,source,confidence,evidence_id,first_seen,last_seen)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, src_type, src_value, dst_type, dst_value, relation,
             source or "", float(confidence or 0.5), evidence_id, now, now))
        c.commit()
        link_id, created = cur.lastrowid, True
    graph = _graph_link(case_id, src_type, src_value, dst_type, dst_value,
                        relation, float(confidence or 0.5), source or "pattern") if emit_graph else None
    db.audit(user, "pattern.link", f"{src_value}->{dst_value}", f"{relation} conf={confidence}")
    return {"id": link_id, "created": created, "relation": relation, "graph": graph}


def list_links(entity=None, case_id=None, limit=200):
    _ensure()
    c = db.get_db()
    q = "SELECT * FROM pattern_links"
    args = []
    conds = []
    if entity:
        conds.append("(src_value=? OR dst_value=?)")
        args += [entity, entity]
    if case_id is not None:
        conds.append("case_id=?")
        args.append(case_id)
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY last_seen DESC LIMIT ?"
    args.append(int(limit))
    rows = [dict(r) for r in c.execute(q, args).fetchall()]
    return {"count": len(rows), "links": rows}


# ---------------------------------------------------------------- 2: interaction ingest
def ingest_event(event, case_id=None, user="system"):
    """One normalized event:
    {actor:{type,value}|str, target:{type,value}|str, platform, kind, ts,
     url?, text?, case_id?}"""
    _ensure()
    if not isinstance(event, dict):
        return None
    atype, avalue = _ctx(event, "actor")
    ttype, tvalue = _ctx(event, "target")
    if not avalue or not tvalue or avalue == tvalue:
        return None
    platform = str(event.get("platform") or "manual").strip().lower()[:40]
    kind = str(event.get("kind") or "mention").strip().lower()
    if kind not in _KINDS:
        kind = "mention"
    ts = _parse_ts(event.get("ts")).isoformat().replace("+00:00", "Z")
    url = str(event.get("url") or "")[:600]
    text = str(event.get("text") or "")[:400]
    cid = event.get("case_id", case_id)
    now = _now()
    c = db.get_db()
    row = c.execute(
        "SELECT id FROM pattern_interactions WHERE COALESCE(case_id,0)=COALESCE(?,0)"
        " AND actor_value=? AND target_value=? AND platform=? AND kind=? AND ts=? AND url=?",
        (cid, avalue, tvalue, platform, kind, ts, url)).fetchone()
    if row:
        return None
    cur = c.execute(
        "INSERT INTO pattern_interactions (case_id,actor_type,actor_value,target_type,"
        "target_value,platform,kind,ts,url,text,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (cid, atype, avalue, ttype, tvalue, platform, kind, ts, url, text, now))
    c.commit()
    _graph_link(cid, atype, avalue, ttype, tvalue, "contacts",
                round(SC.WEIGHTS.get(kind, 0.5) / 1.2, 2), platform)
    if url:
        _insert_url(cid, avalue, url, ts, platform)
    return cur.lastrowid


def ingest_events(events, case_id=None, user="system"):
    _ensure()
    if isinstance(events, dict):
        events = [events]
    inserted = skipped = 0
    for ev in events or []:
        rid = ingest_event(ev, case_id=case_id, user=user)
        if rid:
            inserted += 1
        else:
            skipped += 1
    if inserted:
        db.store_artifact(case_id, None, "pattern", "pattern:ingest",
                          {"inserted": inserted, "skipped": skipped,
                           "total": inserted + skipped}, user)
    db.audit(user, "pattern.ingest", f"case={case_id}", f"inserted={inserted} skipped={skipped}")
    return {"received": inserted + skipped, "inserted": inserted, "skipped": skipped}


def interaction_rows(entity=None, case_id=None, days=None, limit=5000):
    _ensure()
    c = db.get_db()
    q = "SELECT * FROM pattern_interactions"
    conds, args = [], []
    if entity:
        conds.append("(actor_value=? OR target_value=?)")
        args += [entity, entity]
    if case_id is not None:
        conds.append("case_id=?")
        args.append(case_id)
    if days:
        conds.append("ts >= ?")
        cutoff = datetime.now(timezone.utc).timestamp() - float(days) * 86400
        args.append(datetime.fromtimestamp(cutoff, timezone.utc).isoformat().replace("+00:00", "Z"))
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    return [dict(r) for r in c.execute(q, args).fetchall()]


# ---------------------------------------------------------------- 3: scoring views
def frequent_contacts(entity, case_id=None, days=None, top=25,
                      half_life_days=SC.DEFAULT_HALF_LIFE_DAYS):
    rows = interaction_rows(entity, case_id, days)
    focused = SC.focus_rows(rows, entity)
    contacts = SC.rank_contacts(focused, half_life_days=half_life_days, top=top)
    return {"entity": entity, "sample": len(focused),
            "half_life_days": half_life_days, "count": len(contacts),
            "contacts": contacts}


def pnl(entity, case_id=None, days=None):
    """Pattern-of-life report: cadence, active hours, timezone, contact core."""
    rows = interaction_rows(entity, case_id, days)
    focused = SC.focus_rows(rows, entity)
    hist = SC.active_hours(focused)
    tz = SC.timezone_infer(hist["hours_utc"])
    cad = SC.cadence(focused)
    contacts = SC.rank_contacts(focused, top=20)
    diet = url_diet(entity, case_id, top=10)
    ips = ip_ledger(entity, case_id)
    platforms = sorted({r.get("platform") for r in focused if r.get("platform")})
    kinds = {}
    for r in focused:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    return {
        "entity": entity,
        "case_id": case_id,
        "interactions": len(focused),
        "first_seen": min((r["ts"] for r in focused), default=None),
        "last_seen": max((r["ts"] for r in focused), default=None),
        "platforms": platforms,
        "kind_breakdown": kinds,
        "cadence": cad,
        "active_hours": hist,
        "timezone": tz,
        "peak_hour_utc": SC.hour_peak(hist["hours_utc"]),
        "frequent_contacts": contacts,
        "top_domains": diet.get("domains", [])[:10],
        "ips": ips.get("ips", [])[:10],
    }


def org_view(org, case_id=None, top=40):
    """Everything linked to an org: members, handles, shared domains."""
    _ensure()
    c = db.get_db()
    members, handles, domains = [], [], []
    rows = c.execute(
        "SELECT * FROM pattern_links WHERE COALESCE(case_id,0)=COALESCE(?,0)"
        " AND (dst_value=? OR src_value=?) ORDER BY confidence DESC LIMIT 300",
        (case_id, org, org)).fetchall()
    for r in rows:
        d = dict(r)
        other_type = d["src_type"] if d["dst_value"] == org else d["dst_type"]
        other = d["src_value"] if d["dst_value"] == org else d["dst_value"]
        if d["relation"] == "member_of" and other_type in ("person", "handle", "username", "email"):
            members.append({"value": other, "type": other_type,
                            "confidence": d["confidence"], "source": d["source"]})
        elif other_type in ("handle", "username"):
            handles.append({"value": other, "relation": d["relation"], "source": d["source"]})
        elif other_type in ("domain", "url"):
            domains.append({"value": other, "relation": d["relation"]})
    member_contacts = []
    for m in members[:12]:
        fc = frequent_contacts(m["value"], case_id, top=5)
        if fc["contacts"]:
            member_contacts.append({"member": m["value"], "contacts": fc["contacts"]})
    return {"org": org, "members": members[:top], "handles": handles[:top],
            "domains": domains[:top], "member_contacts": member_contacts}


def tracker_snapshot(entity, case_id=None):
    """Compact fingerprint for new_contact / contact_drop / cadence_change."""
    fc = frequent_contacts(entity, case_id, top=60)
    rows = interaction_rows(entity, case_id, days=30)
    focused = SC.focus_rows(rows, entity)
    cad = SC.cadence(focused, days=30)
    hist = SC.active_hours(focused)
    contacts = sorted(c["value"] for c in fc["contacts"] if c["qualified"])
    return {"status": "ok", "contacts": contacts,
            "per_day": cad["per_day"],
            "peak_hour_utc": SC.hour_peak(hist["hours_utc"]),
            "sample": fc["sample"]}


def tracker_diff(old, new, mode="new_contact"):
    """Diff consumed by the trackers registry."""
    o = set((old or {}).get("contacts") or [])
    n = set((new or {}).get("contacts") or [])
    alerts = []
    if mode == "new_contact":
        added = sorted(n - o)
        if added and o:  # first run only establishes the baseline
            alerts.append({"severity": "medium",
                           "message": f"new_contact: {len(added)} new frequent contacts",
                           "detail": {"added": added[:8]}})
    elif mode == "contact_drop":
        removed = sorted(o - n)
        if removed:
            alerts.append({"severity": "low",
                           "message": f"contact_drop: {len(removed)} contacts fell off the frequent list",
                           "detail": {"removed": removed[:8]}})
    elif mode == "cadence_change":
        od, nd = (old or {}).get("per_day"), (new or {}).get("per_day")
        if isinstance(od, (int, float)) and isinstance(nd, (int, float)) and od > 0:
            shift = abs(nd - od) / od
            if shift >= 0.5:
                alerts.append({"severity": "low",
                               "message": f"cadence_change: activity {od}/day -> {nd}/day ({shift:.0%})",
                               "detail": {"old": od, "new": nd}})
        oh, nh = (old or {}).get("peak_hour_utc"), (new or {}).get("peak_hour_utc")
        if oh is not None and nh is not None and oh != nh and nd and nd > 3:
            alerts.append({"severity": "info",
                           "message": f"cadence_change: peak hour moved {oh}:00Z -> {nh}:00Z",
                           "detail": {"old_hour": oh, "new_hour": nh}})
    return alerts


# ---------------------------------------------------------------- 4: URL + IP ledgers
def _registrable(url):
    try:
        host = urlparse(url if "//" in url else "http://" + url).hostname or ""
        parts = [p for p in host.lower().split(".") if p]
        if len(parts) >= 2:
            return ".".join(parts[-2:]) if parts[-1] not in (
                "uk", "au", "jp", "br", "in") or len(parts) < 3 else ".".join(parts[-3:])
        return host
    except Exception:
        return ""


def _insert_url(case_id, entity, url, ts, source):
    c = db.get_db()
    domain = _registrable(url)
    row = c.execute(
        "SELECT id FROM pattern_urls WHERE COALESCE(case_id,0)=COALESCE(?,0)"
        " AND entity=? AND url=? AND ts=?",
        (case_id, entity, url, ts)).fetchone()
    if row:
        return None
    cur = c.execute(
        "INSERT INTO pattern_urls (case_id,entity,url,domain,ts,source) VALUES (?,?,?,?,?,?)",
        (case_id, entity, url, domain, ts, source or ""))
    c.commit()
    return cur.lastrowid


def record_urls(entity, urls, case_id=None, source="manual", ts=None, user="system"):
    _ensure()
    if isinstance(urls, str):
        urls = [urls]
    ts = ts or _now()
    inserted = 0
    for u in urls or []:
        u = str(u).strip()
        if not u or not re.match(r"^https?://", u, re.I):
            continue
        if _insert_url(case_id, entity, u, ts, source):
            inserted += 1
    if inserted and case_id is not None:
        _graph_link(case_id, "handle", entity, "domain",
                    _registrable(next((str(u) for u in urls if u), "")),
                    "shares_url", 0.5, source)
    db.audit(user, "pattern.urls", entity, f"inserted={inserted} source={source}")
    return {"entity": entity, "inserted": inserted, "received": len(urls or [])}


def url_diet(entity, case_id=None, top=20):
    """Public URL-share timeline grouped by registrable domain."""
    _ensure()
    c = db.get_db()
    rows = c.execute(
        "SELECT url,domain,ts,source FROM pattern_urls"
        " WHERE entity=? AND COALESCE(case_id,0)=COALESCE(?,0) ORDER BY ts DESC LIMIT 1000",
        (entity, case_id)).fetchall()
    groups = {}
    for r in rows:
        g = groups.setdefault(r["domain"] or "?", {"domain": r["domain"] or "?",
                                                   "count": 0, "first": r["ts"],
                                                   "last": r["ts"], "urls": []})
        g["count"] += 1
        g["first"] = min(g["first"], r["ts"])
        g["last"] = max(g["last"], r["ts"])
        if len(g["urls"]) < 3:
            g["urls"].append(r["url"])
    domains = sorted(groups.values(), key=lambda x: -x["count"])[:top]
    return {"entity": entity, "total": len(rows), "domains": domains}


def add_ips(entity, ips, case_id=None, source="manual", note="", user="system"):
    _ensure()
    if isinstance(ips, str):
        ips = [ips]
    now = _now()
    inserted = 0
    c = db.get_db()
    for item in ips or []:
        if isinstance(item, dict):
            ip, src, n = str(item.get("ip") or "").strip(), item.get("source") or source, item.get("note") or ""
        else:
            ip, src, n = str(item).strip(), source, note
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,45}$", ip):
            continue
        row = c.execute(
            "SELECT id FROM pattern_ips WHERE COALESCE(case_id,0)=COALESCE(?,0)"
            " AND entity=? AND ip=? AND source=?",
            (case_id, entity, ip, src)).fetchone()
        if row:
            c.execute("UPDATE pattern_ips SET last_seen=?, note=? WHERE id=?", (now, n or "", row["id"]))
            continue
        cur = c.execute(
            "INSERT INTO pattern_ips (case_id,entity,ip,source,note,first_seen,last_seen)"
            " VALUES (?,?,?,?,?,?,?)",
            (case_id, entity, ip, src, n, now, now))
        c.commit()
        inserted += 1
        if case_id is not None and src in ("dns_history", "infra"):
            _graph_link(case_id, "domain", entity, "ip", ip, "resolves_to", 0.7, src)
    db.audit(user, "pattern.ips", entity, f"inserted={inserted} source={source}")
    return {"entity": entity, "inserted": inserted}


def ip_ledger(entity, case_id=None):
    _ensure()
    c = db.get_db()
    rows = [dict(r) for r in c.execute(
        "SELECT ip,source,note,first_seen,last_seen FROM pattern_ips"
        " WHERE entity=? AND COALESCE(case_id,0)=COALESCE(?,0)"
        " ORDER BY last_seen DESC LIMIT 200", (entity, case_id)).fetchall()]
    by_source = {}
    for r in rows:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    return {"entity": entity, "count": len(rows), "by_source": by_source, "ips": rows}


def ingest_header_ips(raw_headers, entity=None, case_id=None, user="system"):
    """Pull client/peer IPs out of raw email headers (Received: chain)."""
    _ensure()
    found = []
    for m in re.finditer(r"from\s+\[?([\d]{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,45})\]?", str(raw_headers)):
        ip = m.group(1)
        if ip.startswith(("10.", "192.168.", "127.")) or ip.startswith("172.16."):
            continue  # RFC1918 / loopback — internal hop, not a public locator
        found.append(ip)
    unique = sorted(set(found))
    ent = entity or "unknown"
    res = add_ips(ent, [{"ip": ip, "source": "evidence_header"} for ip in unique],
                  case_id=case_id, user=user)
    return {"entity": ent, "ips": unique, "inserted": res["inserted"]}


def ensure():
    _ensure()
