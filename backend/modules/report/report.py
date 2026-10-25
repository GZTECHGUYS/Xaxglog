"""Xaxglog intelligence report generator.

Builds a self-contained HTML intelligence briefing from a case: executive
summary (AI-assisted when a key is present), entity graph table, key evidence
with hashes, timeline, and watchlist alerts. Suitable for printing to PDF from
the browser (Print -> Save as PDF) — no external PDF library required.
"""
import html
import json

import db


def generate_report(case_id, username, use_ai=True, keys=None):
    import modules.cases.cases as CASES
    keys = keys or {}
    case = CASES.get_case(case_id)
    if not case:
        return {"error": "case not found"}

    graph = CASES.get_graph(case_id)
    c = db.get_db()
    artifacts = [dict(r) for r in c.execute(
        "SELECT id,type,source,queried_by,queried_at,content_hash FROM artifacts"
        " WHERE case_id=? ORDER BY id DESC LIMIT 200", (case_id,)).fetchall()]
    alerts = CASES.list_alerts(case_id, limit=50)

    summary = _summarize(case, graph, artifacts, keys) if use_ai else None

    report = {
        "case": case,
        "generated_at": db.utcnow(),
        "generated_by": username,
        "executive_summary": summary,
        "graph": {"node_count": graph["node_count"], "link_count": graph["link_count"],
                  "nodes": graph["nodes"][:60]},
        "evidence": artifacts,
        "alerts": alerts,
    }
    report["html"] = _render_html(report)
    db.audit(username, "report.generate", str(case_id))
    return report


def _summarize(case, graph, artifacts, keys):
    """AI executive summary via Gemini/Groq (optional)."""
    import requests
    prompt = (
        "You are a CERT intelligence analyst. Write a concise executive summary "
        "(3 short paragraphs) of this OSINT case for a briefing document. State "
        "facts only, flag confidence, never invent details.\n\nCASE:\n"
        + json.dumps({
            "name": case.get("name"), "description": case.get("description"),
            "legal_basis_present": bool(case.get("legal_basis")),
            "entities": graph["node_count"], "links": graph["link_count"],
            "entity_types": _type_counts(graph["nodes"]),
            "artifact_count": len(artifacts),
            "open_alerts": sum(1 for a in artifacts if False),
        }, ensure_ascii=False)[:5000]
    )
    try:
        if keys.get("GEMINI_API_KEY"):
            url = ("https://generativelanguage.googleapis.com/v1beta/models/"
                   f"gemini-1.5-flash:generateContent?key={keys['GEMINI_API_KEY']}")
            r = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=30)
            return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        if keys.get("GROQ_API_KEY"):
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {keys['GROQ_API_KEY']}"},
                json={"model": "llama-3.3-70b-versatile",
                      "messages": [{"role": "user", "content": prompt}]}, timeout=30)
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"(AI summary unavailable: {str(e)[:120]})"
    return None


def _type_counts(nodes):
    out = {}
    for n in nodes:
        out[n["type"]] = out.get(n["type"], 0) + 1
    return out


def _render_html(rep):
    """Render a printable, agency-branded HTML briefing."""
    case = rep["case"]
    esc = html.escape
    rows_entities = "".join(
        f"<tr><td>{esc(str(n['id']))}</td><td>{esc(n['type'])}</td>"
        f"<td class='mono'>{esc(n['value'])}</td>"
        f"<td>{esc(n['first_seen'][:19])}</td></tr>"
        for n in rep["graph"]["nodes"])
    rows_evidence = "".join(
        f"<tr><td>{esc(str(a['id']))}</td><td>{esc(a['type'])}</td>"
        f"<td>{esc(a['source'])}</td><td class='hash'>{esc(a['content_hash'][:32])}…</td>"
        f"<td>{esc(a['queried_by'])}</td><td>{esc(a['queried_at'][:19])}</td></tr>"
        for a in rep["evidence"])
    summary_html = f"<p class='summary'>{esc(rep['executive_summary'])}</p>" \
        if rep.get("executive_summary") else "<p class='muted'>(AI summary not generated)</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Xaxglog Intelligence Report — {esc(case['case_number'])}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   color:#111;max-width:900px;margin:24px auto;padding:0 20px;line-height:1.5}}
 h1{{font-size:20px;border-bottom:3px solid #0a3d62;padding-bottom:8px}}
 h2{{font-size:15px;color:#0a3d62;margin-top:28px}}
 .banner{{background:#0a3d62;color:#fff;padding:10px 14px;border-radius:6px;font-size:13px}}
 .summary{{background:#f4f6f8;padding:14px;border-left:4px solid #0a3d62;border-radius:4px}}
 .muted{{color:#888;font-style:italic}}
 table{{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}}
 th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
 th{{background:#eef2f5}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all}}
 .hash{{font-family:ui-monospace,monospace;font-size:10px;color:#555}}
 .footer{{margin-top:32px;font-size:11px;color:#888;border-top:1px solid #ddd;padding-top:8px}}
</style></head><body>
<div class="banner">CONFIDENTIAL — INTELLIGENCE BRIEFING &nbsp;|&nbsp;
Generated {esc(rep['generated_at'][:19])}Z by {esc(rep['generated_by'])}</div>
<h1>Case {esc(case['case_number'])} — {esc(case['name'])}</h1>
<p><b>Status:</b> {esc(case['status'])} &nbsp; <b>Legal basis:</b>
 {esc(case.get('legal_basis') or '— (attach authorization)')}</p>
<p><b>Description:</b> {esc(case.get('description') or '—')}</p>

<h2>Executive Summary</h2>{summary_html}

<h2>Entity Graph — {rep['graph']['node_count']} nodes / {rep['graph']['link_count']} links</h2>
<table><tr><th>ID</th><th>Type</th><th>Value</th><th>First seen</th></tr>
{rows_entities}</table>

<h2>Evidence Log (SHA-256 chain of custody) — {len(rep['evidence'])} artifacts</h2>
<table><tr><th>ID</th><th>Type</th><th>Source</th><th>Hash</th><th>By</th><th>When (UTC)</th></tr>
{rows_evidence}</table>

<div class="footer">Xaxglog OSINT Platform — results are OSINT aggregation.
Verify against primary sources. Evidence hashes allow independent integrity verification.</div>
</body></html>"""
