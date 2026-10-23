"""Xaxglog NARRATIVE module — evidence-cited case briefings (LLM + fallback).

Purpose
-------
Turn a case's structured evidence (entities, artifacts with SHA-256 hashes,
alerts, edges) into a concise analyst narrative:

  - digest(case_id)             : structured summary of the case straight from
                                  the SQLite tables.
  - _template_narrative(...)    : deterministic Markdown generator that ALWAYS
                                  works (no network, no key) with real numbers
                                  and SHA-256 evidence citations.
  - _groq(prompt) / _gemini(..) : optional LLM polish when GROQ_API_KEY or
                                  GEMINI_API_KEY is present in the environment;
                                  a missing key raises and is caught upstream.
  - generate(case_id, user, ...)  : tries the requested/auto engine order
          (groq -> gemini), falls back to the deterministic template on any API
          failure, appends a provenance footer listing every cited artifact
          hash, stores a "report" artifact + audit row.

Sources:
  https://api.groq.com/openai/v1/chat/completions  (llama-3.3-70b-versatile)
  https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent
  Local: SQLite tables cases / entities / artifacts / alerts / edges.

Lawful use: produces internal analytical briefings from evidence already
lawfully collected into an audited case; cites SHA-256 artifact hashes so any
claim can be traced to stored evidence. LLM prompts carry case metadata and
hashes only as provided by the analyst's case — no key values are ever logged
or embedded in output. Public functions never raise; a failed API call degrades
to the deterministic template.
"""
import json
import os

import db

LLM_TIMEOUT = 30
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
GEMINI_URL = ("https://generativelanguage.googleapis.com/v1beta/models/"
              "gemini-1.5-flash:generateContent")
SYSTEM_ROLE = ("You are an intelligence analyst writing a concise "
               "evidence-cited briefing.")
MAX_CITATIONS = 10


# ---------------------------------------------------------------- digest
def digest(case_id):
    """Structured case digest: case row, entity/artifact counts, alerts, edges.

    Returns a dict (or {"error": ...}); never raises.
    """
    try:
        c = db.get_db()
        row = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        case = dict(row) if row else None
        entities = [dict(r) for r in c.execute(
            "SELECT type, COUNT(*) AS count FROM entities WHERE case_id=?"
            " GROUP BY type ORDER BY count DESC", (case_id,)).fetchall()]
        artifacts = [dict(r) for r in c.execute(
            "SELECT type AS atype, COUNT(*) AS count FROM artifacts WHERE case_id=?"
            " GROUP BY type ORDER BY count DESC", (case_id,)).fetchall()]
        alerts = [dict(r) for r in c.execute(
            "SELECT id,ts,severity,message FROM alerts WHERE case_id=?"
            " ORDER BY id DESC LIMIT 10", (case_id,)).fetchall()]
        recent = [dict(r) for r in c.execute(
            "SELECT type, source, content_hash, queried_at, queried_by FROM artifacts"
            " WHERE case_id=? ORDER BY id DESC LIMIT 40", (case_id,)).fetchall()]
        edges = c.execute("SELECT COUNT(*) AS n FROM edges WHERE case_id=?",
                          (case_id,)).fetchone()["n"]
        return {
            "case": case,
            "case_id": case_id,
            "entity_counts": entities,
            "entity_total": sum(e["count"] for e in entities),
            "artifact_counts": artifacts,
            "artifact_total": sum(a["count"] for a in artifacts),
            "alerts": alerts,
            "recent_artifacts": recent,
            "edge_count": int(edges or 0),
            "digested_at": db.utcnow(),
        }
    except Exception as e:
        return {"error": str(e)[:150]}


# ---------------------------------------------------------------- deterministic narrative
def _citations(d):
    """Up to MAX_CITATIONS notable artifact hashes (most recent first)."""
    seen, out = set(), []
    for a in (d.get("recent_artifacts") or []):
        h = a.get("content_hash")
        if h and h not in seen:
            seen.add(h)
            out.append({"hash": h, "source": a.get("source", ""),
                        "type": a.get("type", ""), "queried_at": a.get("queried_at", "")})
        if len(out) >= MAX_CITATIONS:
            break
    return out


def _template_narrative(d, focus=""):
    """Deterministic Markdown briefing that always works (no key/network)."""
    case = d.get("case") or {}
    ents, arts = d.get("entity_counts") or [], d.get("artifact_counts") or []
    alerts, recent = d.get("alerts") or [], d.get("recent_artifacts") or []
    cites = _citations(d)

    def _fmt_counts(items, key, total_key):
        if not items:
            return "none recorded"
        top = ", ".join(f"{i.get(key)} ({i.get('count')})" for i in items[:8])
        return f"{d.get(total_key, 0)} total — {top}"

    lines = []
    lines.append(f"# Case Briefing — {case.get('name', 'unnamed case')}")
    lines.append("")
    lines.append(f"- Generated: {db.utcnow()}  |  Engine: deterministic template"
                 + (f"  |  Focus: {focus}" if focus else ""))
    lines.append(f"- Case number: {case.get('case_number', 'n/a')}  |  "
                 f"Status: {case.get('status', 'n/a')}  |  "
                 f"Opened: {case.get('created_at', 'n/a')} by "
                 f"{case.get('created_by', 'n/a')}")
    lines.append("")

    lines.append("## Case Overview")
    desc = (case.get("description") or "").strip()
    lines.append(f"Case **{case.get('name', 'n/a')}** ({case.get('case_number', 'n/a')}) "
                 f"is **{case.get('status', 'unknown')}**.")
    if desc:
        lines.append(f"Description: {desc[:400]}")
    lb = (case.get("legal_basis") or "").strip()
    lines.append(f"Legal basis on file: **{lb}**" if lb else
                 "Legal basis on file: _not recorded_ (add a warrant/authorization "
                 "reference before dissemination).")
    lines.append("")

    lines.append("## Scope & Volume")
    lines.append(f"- Entities: **{d.get('entity_total', 0)}** "
                 f"({_len(ents)} types) — {_fmt_counts(ents, 'type', 'entity_total')}")
    lines.append(f"- Evidence artifacts: **{d.get('artifact_total', 0)}** — "
                 f"{_fmt_counts(arts, 'atype', 'artifact_total')}")
    lines.append(f"- Relationship edges: **{d.get('edge_count', 0)}**")
    lines.append(f"- Recent artifacts reviewed: **{len(recent)}** "
                 f"(last 40 by insertion)")
    lines.append(f"- Alerts raised: **{len(alerts)}** shown (most recent 10)")
    lines.append("")

    lines.append("## Key Entities")
    if ents:
        lines.append("| Type | Count |")
        lines.append("| --- | ---: |")
        for e in ents[:12]:
            lines.append(f"| {e.get('type')} | {e.get('count')} |")
    else:
        lines.append("No entities have been attached to this case yet — start "
                     "with recon/entity ingestion to give the narrative substance.")
    lines.append("")

    lines.append("## Evidence Highlights")
    if cites:
        lines.append("Each item below is traceable to a stored artifact via its "
                     "SHA-256 content hash:")
        for i, a in enumerate(cites, 1):
            lines.append(f"{i}. `{a['hash']}` — {a['source'] or 'unknown source'} "
                         f"({a['type'] or 'n/a'}) at {a['queried_at'] or 'n/a'}")
    else:
        lines.append("No evidence artifacts stored yet — run a collection module "
                     "against this case to populate cited evidence.")
    lines.append("")

    lines.append("## Alerts")
    if alerts:
        for a in alerts[:10]:
            lines.append(f"- [{a.get('severity', 'info')}] {a.get('ts', '')} — "
                         f"{str(a.get('message', ''))[:200]}")
    else:
        lines.append("No alerts raised for this case in the current window.")
    lines.append("")

    lines.append("## Recommended Next Steps")
    steps = []
    if not d.get("entity_total"):
        steps.append("Ingest initial identifiers (email/domain/IP/phone) so the "
                     "entity graph can expand.")
    if not d.get("artifact_total"):
        steps.append("Run at least one collection module (recon, darkweb, "
                     "threat-intel) and store hashed artifacts as evidence.")
    if d.get("entity_total") and not d.get("edge_count"):
        steps.append("Correlate entities into edges — link shared infrastructure, "
                     "handlers and companies to surface the network picture.")
    if any(a.get("severity") in ("high", "critical") for a in alerts):
        steps.append("Triage the high/critical alert(s) above and acknowledge or "
                     "escalate them in the watchlist queue.")
    if len(recent) >= 40:
        steps.append("Artifact volume is high — consider a focus pass (report "
                     "generation or export) to prioritise the newest evidence.")
    if focus:
        steps.append(f"Analyst focus is '{str(focus)[:120]}' — re-run generation "
                     "with this focus once additional evidence lands.")
    if not steps:
        steps.append("Maintain the evidence chain: keep collecting, verify stored "
                     "hashes, and review alerts before dissemination.")
    for i, s in enumerate(steps, 1):
        lines.append(f"{i}. {s}")
    lines.append("")
    return "\n".join(lines)


def _len(x):
    try:
        return len(x)
    except Exception:
        return 0


def _provenance(d, cites, engine, focus=""):
    """Footer listing every artifact hash cited (chain of custody)."""
    lines = ["", "---", "", "## Provenance",
             f"- Engine: `{engine}` | Case: {d.get('case_id')} | "
             f"Generated: {db.utcnow()}"]
    if focus:
        lines.append(f"- Focus: {str(focus)[:200]}")
    lines.append("- Evidence artifacts cited (SHA-256):")
    if cites:
        for a in cites:
            lines.append(f"  - `{a['hash']}` ({a['source'] or 'unknown source'})")
    else:
        lines.append("  - _none — no artifacts stored for this case yet_")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- LLM engines
def _groq(prompt):
    """Groq chat completion; raises if no GROQ_API_KEY or the API fails."""
    key = os.environ.get("GROQ_API_KEY") or ""
    if not key:
        raise RuntimeError("GROQ_API_KEY not set")
    import requests
    r = requests.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "User-Agent": "Xaxglog-OSINT/2.0"},
        json={"model": GROQ_MODEL,
              "messages": [{"role": "system", "content": SYSTEM_ROLE},
                           {"role": "user", "content": prompt}],
              "temperature": 0.3},
        timeout=LLM_TIMEOUT)
    if r.status_code >= 400:
        raise RuntimeError(f"groq HTTP {r.status_code}")
    j = r.json()
    text = j["choices"][0]["message"]["content"]
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("groq empty response")
    return text.strip()


def _gemini(prompt):
    """Gemini flash completion; raises if no GEMINI_API_KEY or the API fails."""
    key = os.environ.get("GEMINI_API_KEY") or ""
    if not key:
        raise RuntimeError("GEMINI_API_KEY not set")
    import requests
    r = requests.post(
        f"{GEMINI_URL}?key={key}",
        headers={"Content-Type": "application/json", "User-Agent": "Xaxglog-OSINT/2.0"},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=LLM_TIMEOUT)
    if r.status_code >= 400:
        raise RuntimeError(f"gemini HTTP {r.status_code}")
    j = r.json()
    text = j["candidates"][0]["content"]["parts"][0]["text"]
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("gemini empty response")
    return text.strip()


def _prompt(d, focus):
    case = d.get("case") or {}
    cites = _citations(d)
    payload = {
        "case": {k: case.get(k) for k in
                 ("case_number", "name", "description", "legal_basis", "status",
                  "created_by", "created_at")},
        "entity_counts": d.get("entity_counts"),
        "entity_total": d.get("entity_total"),
        "artifact_counts": d.get("artifact_counts"),
        "artifact_total": d.get("artifact_total"),
        "edge_count": d.get("edge_count"),
        "recent_alerts": [{"severity": a.get("severity"), "ts": a.get("ts"),
                           "message": a.get("message")} for a in d.get("alerts") or []],
        "recent_artifacts": d.get("recent_artifacts"),
        "artifact_hashes_cited": [a["hash"] for a in cites],
    }
    return (
        "Write a concise intelligence briefing in Markdown for the case below. "
        "Use ONLY the facts provided; never invent entities or events. Cite "
        "evidence inline with the SHA-256 hashes from artifact_hashes_cited. "
        "Sections: Case Overview / Scope & Volume / Key Entities / Evidence "
        "Highlights / Alerts / Recommended Next Steps. Flag uncertainty plainly."
        + (f"\nAnalyst focus: {str(focus)[:300]}" if focus else "")
        + "\n\nCASE DIGEST (JSON):\n"
        + json.dumps(payload, ensure_ascii=False, default=str)[:12000]
    )


# ---------------------------------------------------------------- entry point
def generate(case_id, user, focus="", engine="auto"):
    """Generate an evidence-cited narrative for a case.

    engine: auto (groq -> gemini -> template) | groq | gemini | template.
    Returns {narrative, engine, words, citations} or {"error": ...}. Never raises.
    """
    try:
        d = digest(case_id)
        if d.get("error"):
            return {"error": d["error"]}
        if not d.get("case"):
            return {"error": f"case {case_id} not found"}

        eng = str(engine or "auto").lower()
        order = {"auto": ["groq", "gemini"], "groq": ["groq"],
                 "gemini": ["gemini"], "template": []}.get(eng)
        if order is None:
            order = ["groq", "gemini"]

        prompt = _prompt(d, focus)
        used, text = "template", None
        for e in order:
            try:
                text = _groq(prompt) if e == "groq" else _gemini(prompt)
                used = e
                break
            except Exception:
                text = None

        cites = _citations(d)
        if not text:
            used = "template"
            body = _template_narrative(d, focus)
        else:
            body = text.rstrip() + "\n"
        narrative = body + _provenance(d, cites, used, focus)
        words = len(narrative.split())

        try:
            db.store_artifact(case_id, None, "report", "narrative:generate",
                              {"engine": used, "words": words, "focus": focus}, user)
            db.audit(user, "narrative.generate", str(case_id),
                     f"engine={used} words={words} focus={str(focus)[:200]}"[:500])
        except Exception:
            pass

        return {"narrative": narrative, "engine": used, "words": words,
                "citations": [a["hash"] for a in cites]}
    except Exception as e:
        return {"error": str(e)[:150]}
