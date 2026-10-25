"""Xaxglog tracker family — long-lived watchers over any subject.

"Tracker" = named, re-checkable watch over a target so the platform reacts to
*change*, not just to a single lookup. One engine, eleven tracker kinds; each
kind fingerprints its target on every check, diffs that fingerprint against
the previous one, and raises typed alerts into the shared alerts pipeline.

    kind            | watches                                   | source
    ----------------|-------------------------------------------|---------
    dns_watch       | A/AAAA/MX/NS/TXT record sets              | dns.google (DoH)
    whois_watch     | registrar / expiry / EPP status flags     | rdap.org
    port_drift      | opened/closed common TCP ports on an IP   | local connect sweep
    site_content    | live homepage content hash + title        | direct fetch
    crypto_watch    | BTC address balance + confirmed tx count  | blockstream.info
    vehicle_sights  | ALPR custody sightings for a plate        | own custody store
    person_exposure | breach entries + best sanctions score     | XposedOrNot + sanx
    company_watch   | LEI record status / legal name            | api.gleif.org
    news_watch      | GDELT article volume for a query          | api.gdeltproject.org
    telegram_watch  | public-channel post ids                   | t.me/s/<channel>
    sanctions_watch | presence on multi-list sanctions          | OFAC+UN+OFSI+EU (sanx)
    new_contact     | new frequent contact on an entity           | pattern interaction store
    contact_drop    | contact left the frequent-contact list     | pattern interaction store
    cadence_change  | posting cadence / peak-hour shift           | pattern interaction store

Lawful-use note: every tracker reads public sources or Xaxglog's own custody
store; no credential logins, no authority-gated lookups are performed here.
Checks are single polite GETs with the platform User-Agent and are audited.
"""
import datetime
import json
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import db

_UA = {"User-Agent": "Xaxglog-OSINT/2.0"}


def _ensure_tables():
    c = db.get_db()
    c.execute(
        "CREATE TABLE IF NOT EXISTS trackers ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " kind TEXT NOT NULL,"
        " target TEXT NOT NULL,"
        " case_id INTEGER,"
        " interval_min INTEGER NOT NULL DEFAULT 720,"
        " baseline TEXT, last_state TEXT,"
        " last_check TEXT, last_status TEXT, last_error TEXT,"
        " fails INTEGER NOT NULL DEFAULT 0,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_by TEXT, created_at TEXT)")
    # migrate pre-existing tables that lack last_status
    cols = [r[1] for r in c.execute("PRAGMA table_info(trackers)").fetchall()]
    if cols and "last_status" not in cols:
        c.execute("ALTER TABLE trackers ADD COLUMN last_status TEXT")
    c.commit()


# ================================================================ helpers
def _get(url, **kw):
    import requests
    kw.setdefault("headers", _UA)
    kw.setdefault("timeout", 15)
    try:
        return requests.get(url, **kw)
    except Exception as e:
        return e


def _doh(name, rtype):
    """DNS answer list via Google DoH (keyless)."""
    r = _get("https://dns.google/resolve", params={"name": name, "type": rtype})
    if isinstance(r, Exception) or r.status_code != 200:
        return None
    try:
        j = r.json()
        return sorted(str(a.get("data")) for a in (j.get("Answer") or []))
    except Exception:
        return None


def _alert(severity, message, detail):
    return {"severity": severity, "message": message, "detail": detail}


def _list_diff(old, new):
    """(added, removed) between two lists."""
    o, n = set(old or []), set(new or [])
    return sorted(n - o), sorted(o - n)


def _dict_diff(old, new):
    """scalar field changes between two dicts of primitives."""
    out = []
    for k in sorted(set(list(old or {}) + list(new or []))):
        a, b = (old or {}).get(k), (new or {}).get(k)
        if a != b:
            out.append({"field": k, "old": a, "new": b})
    return out


# ================================================================ fingerprints
def _fp_dns(domain, case_id=None):
    rtypes = ("A", "AAAA", "MX", "NS", "TXT")
    res = {}
    for rt in rtypes:
        ans = _doh(domain, rt)
        if ans is None:
            return {"status": "error", "error": f"DoH failed for {domain}/{rt}"}
        res[rt] = ans
    return {"status": "ok", "records": res}


def _fp_dns_diff(old, new, target):
    alerts = []
    o, n = (old or {}).get("records", {}), (new or {}).get("records", {})
    for rt in sorted(set(list(o) + list(n))):
        added, removed = _list_diff(o.get(rt, []), n.get(rt, []))
        if added or removed:
            sev = "high" if rt in ("A", "AAAA", "NS") else "medium"
            alerts.append(_alert(sev, f"dns_watch [{target}]: {rt} records changed",
                                 {"type": rt, "added": added, "removed": removed}))
    if alerts:
        alerts.insert(0, _alert("info", f"dns_watch [{target}]: infrastructure shift detected",
                                {a["message"] for a in alerts}))
    return alerts


def _fp_whois(domain, case_id=None):
    r = _get(f"https://rdap.org/domain/{domain}")
    if isinstance(r, Exception):
        return {"status": "error"}
    if r.status_code != 200:
        return {"status": "blocked", "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"status": "error"}
    expires = None
    registrar_name = ""
    status = sorted(j.get("status") or [])
    for ev in j.get("events") or []:
        if ev.get("eventAction") == "expiration":
            expires = ev.get("eventDate")
    for ent in j.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            for ev in ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []:
                if ev and ev[0] == "fn":
                    registrar_name = ev[3]
    return {"status": "ok", "registrar": registrar_name, "expires": expires,
            "flags": status}


def _fp_whois_diff(old, new, target):
    alerts = []
    dd = _dict_diff({k: old.get(k) for k in ("registrar", "expires", "flags")},
                    {k: new.get(k) for k in ("registrar", "expires", "flags")})
    for d in dd:
        f, a, b = d["field"], d.get("old"), d.get("new")
        if f == "registrar":
            alerts.append(_alert("high", f"whois_watch [{target}]: registrar transfer "
                                              f"({a!r} -> {b!r})", d))
        elif f == "flags":
            alerts.append(_alert("medium", f"whois_watch [{target}]: status flags changed", d))
        elif f == "expires":
            alerts.append(_alert("low", f"whois_watch [{target}]: expiry changed", d))
    exp = new.get("expires") or ""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", str(exp))
    if m:
        try:
            ed = datetime.date.fromisoformat(m.group(1))
            days = (ed - datetime.datetime.now(datetime.timezone.utc).date()).days
            if 0 <= days <= 30:
                alerts.append(_alert("medium", f"whois_watch [{target}]: expires in {days} days",
                                     {"expires": exp}))
        except Exception:
            pass
    return alerts


# ---------------------------------------------------------------- port drift
def _fp_ports(target, case_id=None):
    try:
        import modules.deeprecon.deeprecon as DEEP
        r = DEEP.port_sweep(target)
        if isinstance(r, Exception):
            return {"status": "error"}
        return {"status": "ok", "ports": sorted(r.get("open_ports") or [])}
    except Exception:
        return {"status": "error"}


def _fp_ports_diff(old, new, target):
    alerts = []
    opened, closed = _list_diff((old or {}).get("ports", []),
                                (new or {}).get("ports", []))
    hot = {22, 23, 445, 3389, 5900, 6379, 27017}
    if opened:
        sev = "high" if any(p in hot for p in opened) else "medium"
        alerts.append(_alert(sev, f"port_drift [{target}]: ports opened {opened}",
                            {"opened": opened}))
    if closed:
        alerts.append(_alert("low", f"port_drift [{target}]: ports closed {closed}",
                             {"closed": closed}))
    return alerts


# ---------------------------------------------------------------- site content
def _fp_site(target, case_id=None):
    host = re.sub(r"^https?://", "", (target or "").strip()).strip("/")
    for scheme in ("https", "http"):
        r = _get(f"{scheme}://{host}/", timeout=12)
        if not isinstance(r, Exception) and r.status_code < 500:
            import hashlib
            body = r.content or b""
            tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", r.text or "")
            title = re.sub(r"\s+", " ", tm.group(1)).strip()[:200] if tm else ""
            return {"status": "ok", "hash": hashlib.sha256(body).hexdigest()[:16],
                    "title": title, "bytes": len(body), "code": r.status_code}
        if not isinstance(r, Exception) and r.status_code >= 500:
            return {"status": "ok", "hash": "", "title": "", "bytes": 0,
                    "code": r.status_code}
    return {"status": "error"}


def _fp_site_diff(old, new, target):
    alerts = []
    o, n = (old or {}).get("hash"), (new or {}).get("hash")
    if old and new and o != n and n:  # empty hash = fetch quirk, don't alarm
        alerts.append(_alert("medium", f"site_content [{target}]: homepage content changed",
                             {"old_digest": o, "new_digest": n,
                              "title": new.get("title"), "bytes": new.get("bytes")}))
    return alerts


# ---------------------------------------------------------------- crypto
def _fp_crypto(target, case_id=None):
    r = _get(f"https://blockstream.info/api/address/{target}")
    if isinstance(r, Exception):
        return {"status": "error"}
    if r.status_code != 200:
        return {"status": "blocked", "http": r.status_code}
    try:
        j = r.json()
        cs = j.get("chain_stats") or {}
        funded = cs.get("funded_txo_sum", 0)
        spent = cs.get("spent_txo_sum", 0)
        return {"status": "ok", "balance_sats": funded - spent,
                "tx_count": cs.get("tx_count", 0)}
    except Exception:
        return {"status": "error"}


def _fp_crypto_diff(old, new, target):
    alerts = []
    ob, nb = (old or {}).get("balance_sats"), (new or {}).get("balance_sats")
    ot, nt = (old or {}).get("tx_count"), (new or {}).get("tx_count")
    if isinstance(ob, int) and isinstance(nb, int) and ob != nb:
        alerts.append(_alert("high", f"crypto_watch [{target}]: balance changed "
                                      f"({ob} -> {nb} sats, delta {nb - ob})",
                             {"old": ob, "new": nb}))
    if isinstance(ot, int) and isinstance(nt, int) and nt > ot:
        alerts.append(_alert("medium", f"crypto_watch [{target}]: {nt - ot} new "
                                       f"confirmed transactions",
                             {"old": ot, "new": nt}))
    return alerts


# ---------------------------------------------------------------- vehicle
def _fp_vehicle(target, case_id=None):
    try:
        import modules.vehicle.vehicle as VEH
        tl = VEH.plate_timeline(target, case_id)
        sightings = tl.get("timeline") or []
        last = sightings[-1] if sightings else {}
        return {"status": "ok",
                "count": tl.get("sightings", len(sightings)),
                "last_seen": last.get("observed_at"),
                "last_camera": last.get("camera_id"),
                "last_loc": [last.get("lat"), last.get("lon")]}
    except Exception:
        return {"status": "error"}


def _fp_vehicle_diff(old, new, target):
    alerts = []
    oc, nc = (old or {}).get("count", 0), (new or {}).get("count", 0)
    if isinstance(nc, int) and nc > (oc or 0):
        sev = "high" if nc - oc >= 3 else "medium"
        alerts.append(_alert(sev, f"vehicle_sights [{target}]: {nc - oc} new ALPR "
                                  f"sightings (total {nc})",
                             {"old": oc, "new": nc,
                              "last_camera": new.get("last_camera"),
                              "last_loc": new.get("last_loc"),
                              "last_seen": new.get("last_seen")}))
    return alerts


# ---------------------------------------------------------------- person
def _fp_person(target, case_id=None):
    out = {"status": "ok", "breaches": None, "sanctions": None, "score": None}
    seed = (target or "").strip()
    if "@" in seed:
        try:
            import modules.emailintel.emailintel as EI
            r = EI.breach_check(seed)
            out["breaches"] = int(r.get("count") or 0)
        except Exception:
            pass
    try:
        import modules.sanx.sanx as SANX
        r = SANX.search(seed, 0.75)
        out["sanctions"] = bool(r.get("hit"))
        best = r.get("best") or {}
        out["score"] = best.get("score")
    except Exception:
        pass
    return out


def _fp_person_diff(old, new, target):
    alerts = []
    ob, nb = (old or {}).get("breaches"), (new or {}).get("breaches")
    if isinstance(ob, int) and isinstance(nb, int) and nb > ob:
        alerts.append(_alert("high", f"person_exposure [{target}]: breach exposure "
                                     f"increased ({ob} -> {nb})",
                             {"old": ob, "new": nb}))
    osan, nsan = (old or {}).get("sanctions"), (new or {}).get("sanctions")
    if osan is False and nsan is True:
        alerts.append(_alert("critical", f"person_exposure [{target}]: NOW MATCHES "
                                         f"sanctions screening", {"prior_hit": False}))
    oscore, nscore = (old or {}).get("score"), (new or {}).get("score")
    if isinstance(nscore, (int, float)) and (oscore or 0) < nscore and nsan:
        alerts.append(_alert("medium", f"person_exposure [{target}]: sanctions match "
                                       f"score rose ({oscore} -> {nscore})",
                             {"old": oscore, "new": nscore}))
    return alerts


# ---------------------------------------------------------------- company
def _fp_company(target, case_id=None):
    try:
        import modules.worldcorp.worldcorp as WC
        seed = (target or "").strip()
        if re.match(r"^[A-Z0-9]{20}$", seed.upper()):
            rec = WC.gleif_by_lei(seed.upper())
        else:
            res = WC.gleif_search(seed)
            rec = ((res.get("results") or []) + [{}])[0]
        if not rec:
            return {"status": "no_match"}
        return {"status": "ok", "lei": rec.get("lei"),
                "name": rec.get("name"), "entity_status": rec.get("status"),
                "jurisdiction": rec.get("jurisdiction")}
    except Exception:
        return {"status": "error"}


def _fp_company_diff(old, new, target):
    alerts = []
    o, n = (old or {}).get("entity_status"), (new or {}).get("entity_status")
    if o and n and o != n:
        sev = "high" if (n in ("RETIRED", "ANNULLED", "LIQUIDATED")) else "medium"
        alerts.append(_alert(sev, f"company_watch [{target}]: LEI entity status "
                                  f"change ({o} -> {n})", {"old": o, "new": n}))
    on, nn = (old or {}).get("name"), (new or {}).get("name")
    if on and nn and on != nn:
        alerts.append(_alert("medium", f"company_watch [{target}]: legal name changed",
                             {"old": on, "new": nn}))
    oj, nj = (old or {}).get("jurisdiction"), (new or {}).get("jurisdiction")
    if oj and nj and oj != nj:
        alerts.append(_alert("medium", f"company_watch [{target}]: jurisdiction changed",
                             {"old": oj, "new": nj}))
    return alerts


# ---------------------------------------------------------------- news
def _fp_news(target, case_id=None):
    try:
        import modules.risk.risk as RISK
        r = RISK.gdelt_news(target, "1week", maxrecords=40)
        if r.get("status") not in (None, "ok"):
            return {"status": r["status"], "error": (r.get("error") or "")[:120]}
        arts = r.get("articles") or []
        titles = sorted({(a.get("title") or "")[:120] for a in arts if a.get("title")})[:40]
        return {"status": "ok", "n": len(arts), "titles": titles}
    except Exception:
        return {"status": "error"}


def _fp_news_diff(old, new, target):
    alerts = []
    added, _ = _list_diff((old or {}).get("titles", []), (new or {}).get("titles", []))
    if added and (new.get("n") if isinstance(new, dict) else None) not in (None, 0):
        alerts.append(_alert("medium", f"news_watch [{target}]: {len(added)} new "
                                       f"articles this cycle",
                             {"new_titles": added[:5]}))
    return alerts


# ---------------------------------------------------------------- telegram
def _fp_telegram(target, case_id=None):
    try:
        import modules.regional.regional as REG
        r = REG.telegram_channel(target)
        status = r.get("status") or ("error" if r.get("error") else "ok")
        posts = r.get("posts") or []
        ids = sorted(str(p.get("id")) for p in posts if p.get("id") is not None)
        last_text = ""
        if posts:
            last_text = str(posts[-1].get("text") or "")[:220]
        return {"status": status, "ids": ids[:25], "last_post": last_text}
    except Exception:
        return {"status": "error"}


def _fp_telegram_diff(old, new, target):
    alerts = []
    added, removed = _list_diff((old or {}).get("ids", []), (new or {}).get("ids", []))
    added = [a for a in added if a.isdigit()]
    if added:
        alerts.append(_alert("medium", f"telegram_watch [{target}]: {len(added)} new "
                                       f"posts in public channel",
                             {"new_ids": added[:10], "latest_text": new.get("last_post")}))
    return alerts


# ---------------------------------------------------------------- sanctions
def _fp_sanctions(target, case_id=None):
    try:
        import modules.sanx.sanx as SANX
        r = SANX.search(target, 0.9)
        best = r.get("best") or {}
        return {"status": "ok", "hit": bool(r.get("hit")),
                "score": best.get("score"), "match_name": best.get("name")}
    except Exception:
        return {"status": "error"}


def _fp_sanctions_diff(old, new, target):
    alerts = []
    oh, nh = bool((old or {}).get("hit")), bool((new or {}).get("hit"))
    if nh and not oh:
        alerts.append(_alert("critical", f"sanctions_watch [{target}]: NOW matches "
                                         f"sanctions lists — immediate review required",
                             {"match": new.get("match_name"), "score": new.get("score")}))
    os_, ns = (old or {}).get("score"), (new or {}).get("score")
    if nh and oh and isinstance(ns, (int, float)) and isinstance(os_, (int, float)) \
            and ns > os_:
        alerts.append(_alert("medium", f"sanctions_watch [{target}]: match score "
                                       f"strengthened ({os_} -> {ns})",
                             {"old": os_, "new": ns, "match": new.get("match_name")}))
    return alerts


# ---------------------------------------------------------------- pattern
def _fp_new_contact(target, case_id=None):
    try:
        import modules.pattern.pattern as PAT
        snap = PAT.tracker_snapshot(target, case_id)
        if snap.get("status") != "ok":
            return snap
        return {"status": "ok", "contacts": snap.get("contacts", []),
                "per_day": snap.get("per_day"), "sample": snap.get("sample")}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def _fp_new_contact_diff(old, new, target):
    alerts = []
    added, _ = _list_diff((old or {}).get("contacts", []),
                          (new or {}).get("contacts", []))
    if added and (old or {}).get("contacts"):  # first run establishes baseline
        alerts.append(_alert("medium",
                             f"new_contact [{target}]: {len(added)} new frequent contacts",
                             {"added": added[:8]}))
    return alerts


def _fp_contact_drop(target, case_id=None):
    return _fp_new_contact(target, case_id)


def _fp_contact_drop_diff(old, new, target):
    alerts = []
    _, removed = _list_diff((old or {}).get("contacts", []),
                            (new or {}).get("contacts", []))
    if removed:
        alerts.append(_alert("low",
                             f"contact_drop [{target}]: {len(removed)} contacts left the frequent list",
                             {"removed": removed[:8]}))
    return alerts


def _fp_cadence_change(target, case_id=None):
    try:
        import modules.pattern.pattern as PAT
        snap = PAT.tracker_snapshot(target, case_id)
        if snap.get("status") != "ok":
            return snap
        return {"status": "ok", "per_day": snap.get("per_day"),
                "peak_hour_utc": snap.get("peak_hour_utc")}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def _fp_cadence_change_diff(old, new, target):
    try:
        import modules.pattern.pattern as PAT
        alerts = PAT.tracker_diff(old, new, mode="cadence_change")
        for a in alerts:
            a["message"] = f"cadence_change [{target}]: {a['message'].split(':', 1)[-1].strip()}"
        return alerts
    except Exception:
        return []


# ================================================================ registry
TRACKERS = {
    "dns_watch":       {"label": "DNS infrastructure", "target_hint": "domain", "interval": 720,
                        "fp": _fp_dns, "diff": _fp_dns_diff},
    "whois_watch":     {"label": "WHOIS / RDAP registrar + expiry", "target_hint": "domain", "interval": 1440,
                        "fp": _fp_whois, "diff": _fp_whois_diff},
    "port_drift":      {"label": "TCP port drift (top services)", "target_hint": "ip", "interval": 720,
                        "fp": _fp_ports, "diff": _fp_ports_diff},
    "site_content":    {"label": "Homepage content hash", "target_hint": "domain", "interval": 360,
                        "fp": _fp_site, "diff": _fp_site_diff},
    "crypto_watch":    {"label": "BTC balance + tx count", "target_hint": "btc address", "interval": 360,
                        "fp": _fp_crypto, "diff": _fp_crypto_diff},
    "vehicle_sights":  {"label": "ALPR custody sightings", "target_hint": "plate (+case)", "interval": 60,
                        "fp": _fp_vehicle, "diff": _fp_vehicle_diff},
    "person_exposure": {"label": "Breach count + sanctions match", "target_hint": "email or name", "interval": 720,
                        "fp": _fp_person, "diff": _fp_person_diff},
    "company_watch":   {"label": "GLEIF status / legal name", "target_hint": "company name or LEI", "interval": 1440,
                        "fp": _fp_company, "diff": _fp_company_diff},
    "news_watch":      {"label": "GDELT news volume", "target_hint": "query (people/place/event)", "interval": 360,
                        "fp": _fp_news, "diff": _fp_news_diff},
    "telegram_watch":  {"label": "Public Telegram channel posts", "target_hint": "channel (t.me/s/<c>)", "interval": 60,
                        "fp": _fp_telegram, "diff": _fp_telegram_diff},
    "sanctions_watch": {"label": "Multi-list sanctions presence", "target_hint": "name (no confusion)", "interval": 1440,
                        "fp": _fp_sanctions, "diff": _fp_sanctions_diff},
    "new_contact":     {"label": "Pattern: new frequent contact", "target_hint": "entity (handle/person)", "interval": 720,
                        "fp": _fp_new_contact, "diff": _fp_new_contact_diff},
    "contact_drop":    {"label": "Pattern: contact left frequent list", "target_hint": "entity (handle/person)", "interval": 1440,
                        "fp": _fp_contact_drop, "diff": _fp_contact_drop_diff},
    "cadence_change":  {"label": "Pattern: posting cadence / peak-hour shift", "target_hint": "entity (handle/person)", "interval": 720,
                        "fp": _fp_cadence_change, "diff": _fp_cadence_change_diff},
}


def registry():
    out = []
    for k, m in TRACKERS.items():
        out.append({"kind": k, "label": m["label"], "target_hint": m["target_hint"],
                    "interval_min": m["interval"]})
    return out


def _safe_fp(meta, target, case_id):
    try:
        fp = meta["fp"](target, case_id)
        if not isinstance(fp, dict):
            return {"status": "error", "error": "bad fingerprint type"}
        return fp
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


# ================================================================ engine
def _ensure():
    _ensure_tables()


def register(kind, target, case_id=None, interval_min=None, user="system"):
    _ensure()
    kind = (kind or "").strip()
    target = (target or "").strip()
    meta = TRACKERS.get(kind)
    if not meta:
        return {"error": f"unknown tracker kind '{kind}'", "available": [r["kind"] for r in registry()]}
    if not target:
        return {"error": "target required"}
    try:
        interval = int(interval_min) if interval_min else int(meta["interval"])
        if interval < 15:
            interval = 15  # politeness floor
    except Exception:
        interval = int(meta["interval"])
    c = db.get_db()
    dup = c.execute("SELECT id FROM trackers WHERE kind=? AND target=? "
                    "AND COALESCE(case_id,0)=COALESCE(?,0)",
                    (kind, target, case_id)).fetchone()
    if dup:
        return {"error": "tracker already registered", "id": dup["id"]}
    fp = _safe_fp(meta, target, case_id)
    now = db.utcnow()
    cur = c.execute(
        "INSERT INTO trackers (kind,target,case_id,interval_min,baseline,last_state,"
        "created_by,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (kind, target, case_id, interval, json.dumps(fp), json.dumps(fp),
         user, now))
    c.commit()
    db.audit(user, "trackers.register", target,
             f"kind={kind} case={case_id} interval={interval} fp={fp.get('status')}")
    return {"id": cur.lastrowid, "kind": kind, "target": target,
            "case_id": case_id, "interval_min": interval,
            "baseline_status": fp.get("status")}


def remove(tid, user="system"):
    _ensure()
    c = db.get_db()
    row = c.execute("SELECT kind,target FROM trackers WHERE id=?", (tid,)).fetchone()
    if not row:
        return {"error": "not found"}
    c.execute("DELETE FROM trackers WHERE id=?", (tid,))
    c.commit()
    db.audit(user, "trackers.remove", row["target"], f"kind={row['kind']}")
    return {"removed": tid, "kind": row["kind"], "target": row["target"]}


def _load_json(s):
    try:
        return json.loads(s) if s else None
    except Exception:
        return None


def _raise_alerts(kind, target, case_id, alerts):
    """Write typed alerts into the shared pipeline; returns count."""
    if not alerts:
        return 0
    c = db.get_db()
    now = db.utcnow()
    for a in alerts:
        c.execute(
            "INSERT INTO alerts (watchlist_id,case_id,ts,severity,message,detail) "
            "VALUES (NULL,?,?,?,?,?)",
            (case_id, now, a.get("severity", "info"),
             f"[tracker:{kind}] {a.get('message', '')}"[:280],
             json.dumps(a.get("detail") or {})))
    c.commit()
    return len(alerts)


def check_tracker(tid, user="system"):
    _ensure()
    c = db.get_db()
    row = c.execute("SELECT * FROM trackers WHERE id=?", (tid,)).fetchone()
    if not row:
        return {"error": "not found"}
    row = dict(row)
    meta = TRACKERS.get(row["kind"])
    if not meta:
        return {"error": f"unknown kind '{row['kind']}'"}
    fp = _safe_fp(meta, row["target"], row["case_id"])
    now = db.utcnow()

    # failure path: bump counter, auto-alert on 3 consecutive failures
    if fp.get("status") != "ok":
        newfails = (row["fails"] or 0) + 1
        err = str(fp.get("error") or (f"HTTP {fp.get('http')}" if fp.get("http")
                                      else fp.get("status")))[:200]
        c.execute("UPDATE trackers SET last_check=?, last_status=?, last_error=?, "
                  "fails=? WHERE id=?",
                  (now, fp.get("status"), err, newfails, tid))
        c.commit()
        raised = []
        if newfails == 3:
            raised = [_alert("info",
                             f"tracker source offline for {row['target']} "
                             f"({newfails} consecutive failures)", {"error": err})]
            _raise_alerts(row["kind"], row["target"], row["case_id"], raised)
        db.audit(user, "tracker.check", f"{row['kind']}:{row['target']}",
                 f"status={fp.get('status')} fails={newfails}")
        return {"id": tid, "status": fp.get("status"), "fails": newfails,
                "raised": len(raised)}

    old = _load_json(row["last_state"])
    alerts = []
    note = None
    if not old or old.get("status") != "ok":
        # (re)baseline: first good fingerprint, no diff yet
        old = None
        note = "baseline stored"
    else:
        try:
            alerts = meta["diff"](old, fp, row["target"]) or []
        except Exception as e:
            alerts = []
            note = f"diff error: {str(e)[:120]}"

    n = _raise_alerts(row["kind"], row["target"], row["case_id"], alerts)
    c.execute("UPDATE trackers SET last_state=?, baseline=COALESCE(baseline,?), "
              "last_check=?, last_status='ok', last_error=NULL, fails=0 WHERE id=?",
              (json.dumps(fp), json.dumps(fp), now, tid))
    c.commit()
    db.audit(user, "tracker.check", f"{row['kind']}:{row['target']}",
             f"alerts={n}{' ' + note if note else ''}")
    return {"id": tid, "kind": row["kind"], "status": "ok", "changed": n > 0,
            "alerts_raised": n, "changes": [a["message"] for a in alerts],
            "note": note}


def run_due(limit=20):
    _ensure()
    c = db.get_db()
    now = datetime.datetime.now(datetime.timezone.utc)
    rows = [dict(r) for r in c.execute(
        "SELECT id, kind, target, case_id, interval_min, last_check FROM "
        "trackers WHERE enabled=1")]
    due = []
    for r in rows:
        if not r["last_check"]:
            due.append(r["id"])
            continue
        try:
            last = datetime.datetime.fromisoformat(str(r["last_check"]).replace(" ", "T"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=datetime.timezone.utc)
            if last + datetime.timedelta(minutes=r["interval_min"]) <= now:
                due.append(r["id"])
        except Exception:
            due.append(r["id"])
    results = []
    for tid in due[:max(1, int(limit))]:
        try:
            results.append(check_tracker(tid, user="daemon"))
        except Exception as e:
            results.append({"id": tid, "status": "error", "error": str(e)[:150]})
    return {"due": len(due), "checked": len(results), "results": results}


def _summarize(st):
    if not isinstance(st, dict):
        return {}
    s = {k: v for k, v in st.items() if k != "status"}
    for k, v in list(s.items()):
        if isinstance(v, list) and len(v) > 6:
            s[k] = v[:6] + [f"... +{len(v) - 6} more"]
    return s


def list_trackers(limit=200):
    _ensure()
    c = db.get_db()
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM trackers ORDER BY id DESC LIMIT ?", (int(limit),))]
    for r in rows:
        meta = TRACKERS.get(r["kind"]) or {}
        r["label"] = meta.get("label", r["kind"])
        st = _load_json(r.get("last_state"))
        r["state_summary"] = _summarize(st)
        r.pop("last_state", None)
        r.pop("baseline", None)
    return {"registry": registry(), "trackers": rows}

def recent_alerts(limit=100):
    _ensure()
    c = db.get_db()
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM alerts WHERE message LIKE '[tracker:%' "
        "ORDER BY id DESC LIMIT ?", (int(limit),))]
    return {"alerts": rows, "count": len(rows)}


def start_daemon(interval_sec=300):
    _ensure()

    def loop():
        while True:
            try:
                run_due(limit=15)
            except Exception as e:
                try:
                    db.audit("system", "trackers.daemon_error", str(e)[:80], "")
                except Exception:
                    pass
            time.sleep(max(30, int(interval_sec)))

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t
