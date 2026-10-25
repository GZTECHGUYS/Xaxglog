"""Xaxglog pattern scoring — decay weights, frequent-contact ranking,
active-hours / timezone inference, cadence and corroboration.

Pure functions over normalized interaction rows (dicts with actor_value,
target_value, platform, kind, ts). No DB access — pattern.py feeds them.
"""
import math
from datetime import datetime, timezone

WEIGHTS = {
    "co_author": 1.2,
    "reply": 1.0,
    "quote": 0.8,
    "mention": 0.7,
    "co_mention": 0.6,
    "co_comment": 0.5,
    "thread": 0.9,
}
DEFAULT_HALF_LIFE_DAYS = 90.0


def _parse_ts(ts):
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        s = str(ts).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _age_days(ts, now=None):
    dt = _parse_ts(ts)
    if not dt:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400.0)


def decay(age_days, half_life_days=DEFAULT_HALF_LIFE_DAYS):
    if age_days is None:
        return 0.0
    return math.pow(0.5, age_days / float(half_life_days or DEFAULT_HALF_LIFE_DAYS))


def rank_contacts(rows, half_life_days=DEFAULT_HALF_LIFE_DAYS, now=None,
                  top=25, min_interactions=3, min_sources=2):
    """Time-decayed contact ranking for one side of the interaction graph.

    A row counts toward `entity` when it is the actor OR the target; the
    contact is whoever sits on the other side. Corroboration: distinct
    platforms raise confidence (x1.25 each extra platform, cap x1.75).
    """
    buckets = {}
    for r in rows:
        a = (r.get("actor_value") or "").strip()
        t = (r.get("target_value") or "").strip()
        if not a or not t or a == t:
            continue
        contact = t if r.get("_focus") == a else a
        kind = r.get("kind") or "mention"
        w = WEIGHTS.get(kind, 0.5)
        age = _age_days(r.get("ts"), now)
        contrib = w * decay(age, half_life_days)
        b = buckets.setdefault(contact, {
            "value": contact, "type": r.get("_contact_type") or "handle",
            "weight": 0.0, "interactions": 0, "platforms": set(),
            "kinds": {}, "last_seen": None,
        })
        b["weight"] += contrib
        b["interactions"] += 1
        b["platforms"].add(r.get("platform") or "?")
        b["kinds"][kind] = b["kinds"].get(kind, 0) + 1
        ts = r.get("ts")
        if ts and (b["last_seen"] is None or str(ts) > str(b["last_seen"])):
            b["last_seen"] = ts

    out = []
    for b in buckets.values():
        n_platforms = len(b["platforms"])
        boost = min(1.75, 1.0 + 0.25 * max(0, n_platforms - 1))
        b["weight"] = round(b["weight"] * boost, 4)
        b["boost"] = round(boost, 3)
        b["platforms"] = sorted(b["platforms"])
        b["sources"] = n_platforms
        b["qualified"] = (
            b["interactions"] >= min_interactions
            and (n_platforms >= min_sources or b["interactions"] >= 5)
        )
        out.append(b)
    out.sort(key=lambda x: (-x["weight"], -x["interactions"]))
    return out[:top]


def active_hours(rows, focus=None):
    """24-bin UTC histogram of interaction timestamps (+ weekday counts)."""
    hours = [0] * 24
    weekdays = [0] * 7
    used = 0
    for r in rows:
        if focus and focus not in (r.get("actor_value"), r.get("target_value")):
            continue
        dt = _parse_ts(r.get("ts"))
        if not dt:
            continue
        hours[dt.hour] += 1
        weekdays[dt.weekday()] += 1
        used += 1
    return {"hours_utc": hours, "weekdays": weekdays, "sample": used}


def timezone_infer(hours_utc):
    """Phase-shift correlation: find the UTC offset that pushes activity
    into local waking hours (07:00-22:00, weighted toward 09:00-18:00).
    Confidence = day-mass share minus night-mass share."""
    total = sum(hours_utc or [])
    if not total or total < 6:
        return {"utc_offset": None, "confidence": 0.0, "note": "insufficient sample"}
    best = {"utc_offset": None, "confidence": -1.0}
    for off in range(-12, 15):  # UTC-12 .. UTC+14
        day = night = 0
        for h, c in enumerate(hours_utc):
            local = (h + off) % 24
            if 7 <= local <= 22:
                day += c
            else:
                night += c
        # prefer offsets that also concentrate mass in core working hours
        core = sum(c for h, c in enumerate(hours_utc) if 9 <= (h + off) % 24 <= 18)
        score = (day - night) / total + 0.15 * (core / total)
        if score > best.get("confidence", -1):
            best = {"utc_offset": off, "confidence": round(score, 3)}
    best["confidence"] = max(0.0, min(1.0, best["confidence"]))
    best["local_label"] = f"UTC{best['utc_offset']:+d}" if best["utc_offset"] is not None else "—"
    return best


def cadence(rows, now=None, days=30):
    """Interactions/day over the trailing window + peak posting hour (UTC)."""
    now = now or datetime.now(timezone.utc)
    cutoff = now.timestamp() - days * 86400
    n = 0
    latest = None
    for r in rows:
        dt = _parse_ts(r.get("ts"))
        if not dt:
            continue
        latest = max(latest, dt) if latest else dt
        if dt.timestamp() >= cutoff:
            n += 1
    return {"window_days": days, "interactions": n,
            "per_day": round(n / float(days), 3),
            "last_interaction": latest.isoformat() if latest else None}


def hour_peak(hours_utc):
    if not hours_utc or max(hours_utc) == 0:
        return None
    return hours_utc.index(max(hours_utc))


def focus_rows(rows, entity):
    """Tag rows where `entity` participates so rank_contacts knows the focus."""
    ent = (entity or "").strip()
    out = []
    for r in rows:
        if ent in (r.get("actor_value"), r.get("target_value")):
            r = dict(r)
            r["_focus"] = ent
            out.append(r)
    return out
