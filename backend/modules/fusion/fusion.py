"""Xaxglog case fusion — master timeline + entity resolution.

Purpose : (1) master_timeline() merges artifacts, entities and alerts of a
          case into one chronological event stream; (2) resolve_entities()
          fuzzy-matches near-duplicate entities (normalized equality,
          token-set Jaccard, substring rule) into union-find clusters and —
          when not a dry run — emits weighted "same_as" edges into the graph;
          (3) find_across_cases() locates the same value in other cases.
Sources : none — pure computation over local SQLite tables (entities, edges,
          artifacts, alerts).
Lawful use: entity resolution only rewrites links inside already-authorized
          cases; every real merge is written to the audit trail.
"""
import re
import unicodedata

import db

MAX_PAIR_ENTITIES = 3000  # O(n^2) pairwise cap


# --------------------------------------------------------------- timeline
def master_timeline(case_id, limit=500):
    """Union artifacts + entities + alerts into one ascending event list."""
    try:
        limit = max(1, min(int(limit), 5000))
        c = db.get_db()
        events = []
        counts = {"artifact": 0, "entity": 0, "alert": 0}

        for r in c.execute(
                "SELECT id, type, source, content_hash, queried_at FROM artifacts"
                " WHERE case_id=? ORDER BY queried_at DESC LIMIT ?",
                (case_id, limit)):
            events.append({"ts": r["queried_at"], "kind": "artifact",
                           "label": f"{r['type']}:{r['source']}", "source": r["source"],
                           "ref_id": r["id"], "hash": r["content_hash"]})
            counts["artifact"] += 1

        for r in c.execute(
                "SELECT id, type, value, first_seen, last_seen FROM entities"
                " WHERE case_id=? ORDER BY id LIMIT ?", (case_id, limit)):
            label = f"{r['type']}:{r['value']}"
            h = db.hash_content(f"{r['type']}|{r['value']}")
            events.append({"ts": r["first_seen"], "kind": "entity", "label": label,
                           "source": "entity", "ref_id": r["id"], "hash": h})
            counts["entity"] += 1
            if r["last_seen"] and r["last_seen"] != r["first_seen"]:
                events.append({"ts": r["last_seen"], "kind": "entity", "label": label,
                               "source": "entity", "ref_id": r["id"], "hash": h})

        for r in c.execute(
                "SELECT id, ts, severity, message, detail FROM alerts"
                " WHERE case_id=? ORDER BY ts DESC LIMIT ?", (case_id, limit)):
            events.append({"ts": r["ts"], "kind": "alert", "label": r["message"],
                           "source": f"alert:{r['severity']}", "ref_id": r["id"],
                           "hash": db.hash_content(f"{r['message']}|{r['detail'] or ''}")})
            counts["alert"] += 1

        events.sort(key=lambda e: e.get("ts") or "")
        counts["fetched"] = len(events)
        counts["returned"] = min(len(events), limit)
        return {"case_id": case_id, "counts": counts, "events": events[:limit]}
    except Exception as e:
        return {"error": str(e)[:150], "case_id": case_id, "counts": {}, "events": []}


# --------------------------------------------------------------- normalization
def _norm(s):
    """Lowercase, NFKD-strip combining marks, keep [a-z0-9] only."""
    try:
        s = unicodedata.normalize("NFKD", str(s or ""))
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        return re.sub(r"[^a-z0-9]", "", s.lower())
    except Exception:
        return ""


def _tokens(s):
    """Accent-stripped lowercase alnum tokens of length >= 2 (Jaccard input)."""
    try:
        s = unicodedata.normalize("NFKD", str(s or ""))
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if len(t) >= 2}
    except Exception:
        return set()


def _pair_score(na, nb, ta, tb):
    """max(normalized equality, token-set Jaccard, boosted substring rule)."""
    if na == nb:
        return 1.0
    jac = (len(ta & tb) / len(ta | tb)) if (ta and tb) else 0.0
    sub = 0.0
    short, long_ = (na, nb) if len(na) <= len(nb) else (nb, na)
    if len(short) >= 6 and short in long_:
        sub = 0.5 + 0.5 * (len(short) / len(long_))
    return max(jac, sub)


class _UF:
    def __init__(self, ids):
        self.p = {i: i for i in ids}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def resolve_entities(case_id, threshold=0.86, dry_run=True):
    """Pairwise fuzzy entity resolution for one case.

    dry_run=True  -> {pairs:[{a_id,a_value,b_id,b_value,score}], count, ...}
    dry_run=False -> emits same_as edges (weight 0.95, source
                     "entity_resolution"), audits, returns {"merged": n, ...}.
    """
    try:
        threshold = float(threshold)
    except Exception:
        threshold = 0.86
    try:
        c = db.get_db()
        rows = c.execute(
            "SELECT id, type, value FROM entities WHERE case_id=? ORDER BY id LIMIT ?",
            (case_id, MAX_PAIR_ENTITIES)).fetchall()
        ents = [{"id": r["id"], "type": r["type"], "value": r["value"]} for r in rows]
        meta = [(_norm(e["value"]), _tokens(e["value"])) for e in ents]

        uf = _UF([e["id"] for e in ents])
        pairs = []
        n = len(ents)
        for i in range(n):
            na, ta = meta[i]
            if not na:
                continue
            for j in range(i + 1, n):
                nb, tb = meta[j]
                if not nb:
                    continue
                if ents[i]["type"] != ents[j]["type"]:
                    # cross-type links require an exact normalized match
                    score = 1.0 if na == nb else 0.0
                else:
                    score = _pair_score(na, nb, ta, tb)
                if score >= threshold and ents[i]["id"] != ents[j]["id"]:
                    pairs.append({"a_id": ents[i]["id"], "a_value": ents[i]["value"],
                                  "b_id": ents[j]["id"], "b_value": ents[j]["value"],
                                  "score": round(score, 4)})
                    uf.union(ents[i]["id"], ents[j]["id"])

        clusters = {}
        for e in ents:
            clusters.setdefault(uf.find(e["id"]), []).append(e["id"])
        multi = [sorted(v) for v in clusters.values() if len(v) > 1]

        if dry_run:
            return {"case_id": case_id, "threshold": threshold, "dry_run": True,
                    "entity_count": n, "count": len(pairs), "pairs": pairs,
                    "clusters": multi}

        now = db.utcnow()
        merged = 0
        added = 0
        for members in multi:
            center = members[0]
            for m in members[1:]:
                cur = c.execute(
                    "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
                    " VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
                    (case_id, m, center, "same_as", 0.95, "entity_resolution", now))
                merged += 1
                if cur.rowcount:
                    added += 1
            c.commit()
        db.audit("system", "fusion.resolve", f"case:{case_id}",
                 f"merged={merged} edges_added={added} pairs={len(pairs)}")
        return {"case_id": case_id, "threshold": threshold, "dry_run": False,
                "entity_count": n, "pairs": len(pairs), "clusters": len(multi),
                "merged": merged, "edges_added": added}
    except Exception as e:
        return {"error": str(e)[:150], "case_id": case_id, "merged": 0,
                "pairs": 0, "edges_added": 0}


def find_across_cases(value):
    """Cases that already contain this exact entity value."""
    try:
        c = db.get_db()
        rows = c.execute(
            "SELECT case_id, value FROM entities WHERE value=? AND case_id IS NOT NULL"
            " GROUP BY case_id", (value,)).fetchall()
        out = []
        for r in rows:
            cnt = c.execute("SELECT COUNT(*) AS n FROM entities WHERE case_id=? AND value=?",
                            (r["case_id"], value)).fetchone()["n"]
            out.append({"case_id": r["case_id"], "value": r["value"], "entities": cnt})
        return {"value": value, "count": len(out), "cases": out}
    except Exception as e:
        return {"error": str(e)[:150], "value": value, "count": 0, "cases": []}
