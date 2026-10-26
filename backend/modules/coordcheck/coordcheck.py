"""Xaxglog coordcheck — coordinated inauthentic behaviour indicators.

Pure computation over *public* post samples the operator supplies (or that
sit in the case store). No platform scraping — bring your own export or
use searchx/GDELT output. Inputs are lists of items:

  {"account": "handle", "ts": "2026-01-01T12:00:00Z", "text": "...",
   "url": "https://...", "followers": 123, "created": "2025-11-01"}

Signals computed (each explainable, no black box):
  - temporal burstiness: how many posts land in the same 60s/5m window
    (coordinated posting windows)
  - text similarity: shingle (3-gram) Jaccard clusters of near-identical
    copy (cross-posting networks)
  - account freshness: accounts created <N days ago posting identical text
    (throwaway cohort)
  - account-actor diversity: ratio of unique accounts to posts per cluster
  - cadence entropy: regular-interval posting (automation hint)

Scores 0-100 with an interpretation: "consistent with coordination" is a
*lead*, not proof — bot-vs-organised-human is genuinely hard; the report
lists the raw evidence behind every number.

Lawful-use note: analysis of posts already public. Never auto-labels
accounts as bots; output feeds the analyst's assessment only.
"""
import datetime
import re

import db


def _parse_ts(ts):
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def _shingles(text, k=3):
    words = re.findall(r"[\w']+",
                       re.sub(r"http\S+|@\w+|#\w+", " ", (text or "").lower()))
    if len(words) < k:
        return {tuple(words)} if words else set()
    return {tuple(words[i:i + k]) for i in range(len(words) - k + 1)}


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / len(a | b)


def analyze(items, burst_window_sec=300, similarity=0.72, fresh_days=30):
    """Run all coordination signals over a list of public posts."""
    try:
        if not isinstance(items, list) or not items:
            return {"status": "error",
                    "error": "provide a non-empty list of post objects"}
        rows = []
        for it in items[:5000]:
            if not isinstance(it, dict):
                continue
            rows.append({
                "account": (it.get("account") or it.get("handle") or "?").strip(),
                "dt": _parse_ts(it.get("ts") or it.get("timestamp")),
                "text": (it.get("text") or it.get("content") or "").strip(),
                "url": it.get("url"),
                "created": _parse_ts(it.get("created") or it.get("account_created")),
                "followers": it.get("followers"),
            })
        rows = [r for r in rows if r["dt"] or r["text"]]
        if not rows:
            return {"status": "error", "error": "no parseable posts"}

        # 1. temporal burst clusters
        timed = sorted([r for r in rows if r["dt"]], key=lambda r: r["dt"])
        bursts, cur = [], []
        for r in timed:
            if cur and (r["dt"] - cur[-1]["dt"]).total_seconds() > burst_window_sec:
                bursts.append(cur)
                cur = []
            cur.append(r)
        if cur:
            bursts.append(cur)
        burst_clusters = [{
            "window_start": b[0]["dt"].isoformat(),
            "posts": len(b),
            "accounts": len({x["account"] for x in b}),
            "same_account_dominance":
                max((sum(1 for x in b if x["account"] == acc)
                     for acc in {x["account"] for x in b}), default=0) / len(b),
        } for b in bursts if len(b) >= 4]
        max_burst = max((b["posts"] for b in burst_clusters), default=0)

        # 2. near-duplicate text clusters (greedy)
        sh = [(_shingles(r["text"]), r) for r in rows if len(r["text"]) >= 40]
        clusters, used = [], set()
        for i, (si, ri) in enumerate(sh):
            if i in used or not si:
                continue
            members = [ri]
            used.add(i)
            for j in range(i + 1, len(sh)):
                if j in used or not sh[j][0]:
                    continue
                if _jaccard(si, sh[j][0]) >= similarity:
                    members.append(sh[j][1])
                    used.add(j)
            if len(members) >= 3:
                clusters.append(members)
        text_clusters = []
        for members in clusters:
            accounts = {m["account"] for m in members}
            fresh = [m for m in members
                     if m["created"] and (m["dt"] or datetime.datetime.utcnow())
                     and m["dt"] and (m["dt"] - m["created"]).days <= fresh_days]
            text_clusters.append({
                "posts": len(members),
                "accounts": len(accounts),
                "account_list": sorted(accounts)[:20],
                "fresh_accounts": len(fresh),
                "sample_text": members[0]["text"][:160],
                "sample_url": next((m["url"] for m in members if m["url"]), None),
                "span": (min(m["dt"] for m in members if m["dt"]).isoformat()
                         if any(m["dt"] for m in members) else None),
            })

        # 3. cadence regularity per account (automation hint)
        cadence = {}
        for r in timed:
            cadence.setdefault(r["account"], []).append(r["dt"])
        robotic = []
        for acc, dts in cadence.items():
            if len(dts) < 6:
                continue
            gaps = [(b - a).total_seconds()
                    for a, b in zip(dts, dts[1:]) if (b - a).total_seconds() > 0]
            if not gaps:
                continue
            mean = sum(gaps) / len(gaps)
            sd = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5
            cv = sd / mean if mean else 999
            if cv < 0.15 and mean < 600:
                robotic.append({"account": acc, "median_gap_sec": round(mean, 1),
                                "cv": round(cv, 3), "posts": len(dts)})

        # composite score
        accounts_total = len({r["account"] for r in rows})
        copy_score = min(40, sum(c["accounts"] * 6
                                 for c in text_clusters if c["accounts"] >= 3))
        burst_score = min(30, len(burst_clusters) * 7 + (10 if max_burst >= 10 else 0))
        fresh_score = min(15, sum(1 for c in text_clusters
                                  if c["fresh_accounts"] >= 2) * 5)
        cadence_score = min(15, len(robotic) * 5)
        total = min(100, copy_score + burst_score + fresh_score + cadence_score)

        report = {
            "posts_analyzed": len(rows), "accounts": accounts_total,
            "signals": {
                "burst_clusters": burst_clusters[:10],
                "near_duplicate_clusters": text_clusters[:10],
                "cadence_outliers": robotic[:10],
            },
            "score": total,
            "interpretation": (
                "strong coordination indicators — review clusters manually"
                if total >= 65 else
                "moderate indicators — some shared content/timing to verify"
                if total >= 35 else
                "weak indicators — mostly organic spread pattern"),
            "caveat": "indicators are leads; organised humans can mimic "
                      "these patterns and vice versa",
        }
        db.audit("system", "coordcheck.analyze", "-",
                 f"posts={len(rows)} score={total}")
        return {"status": "ok", "report": report}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def from_case(case_id, limit=1000, artifact_types=None):
    """Pull stored artifacts as post-like items + run analysis.

    Heuristic mapping: content JSON with url+text/title becomes an item;
    account defaults to source field. Keeps the module useful without a
    manual export.
    """
    import json
    try:
        c = db.get_db()
        q = "SELECT id,type,source,content,queried_at FROM artifacts WHERE case_id=?"
        args = (case_id,)
        if artifact_types:
            q += " AND type IN (%s)" % ",".join("?" * len(artifact_types))
            args = args + tuple(artifact_types)
        q += " ORDER BY id DESC LIMIT ?"
        args = args + (min(int(limit), 5000),)
        items = []
        for r in c.execute(q, args).fetchall():
            try:
                content = json.loads(r["content"])
            except ValueError:
                continue
            blobs = content if isinstance(content, list) else [content]
            for b in blobs:
                if isinstance(b, dict):
                    items.append({
                        "account": b.get("account") or b.get("author")
                        or b.get("domain") or r["source"],
                        "ts": b.get("seendate") or b.get("ts") or b.get("filed")
                        or b.get("queried_at") or r["queried_at"],
                        "text": b.get("text") or b.get("title") or b.get("body")
                        or json.dumps(b, default=str)[:3000],
                        "url": b.get("url"),
                        "created": b.get("created") or b.get("first_seen"),
                    })
        if not items:
            return {"status": "ok", "items": 0,
                    "note": "no post-like artifacts in this case yet",
                    "report": None}
        out = analyze(items)
        if out.get("status") == "ok":
            out["items"] = len(items)
        return out
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
