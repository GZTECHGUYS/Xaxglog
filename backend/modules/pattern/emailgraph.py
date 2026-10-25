"""Xaxglog email relationship graph — conversation threads from headers.

Parses raw RFC-822 headers (paste one or many), reconstructs threads via
Message-ID / In-Reply-To / References, ranks participants by send volume,
flags auto-responder patterns (OOO / bulk) that leak absences.

Ingests thread edges into the pattern store as `thread` interactions so the
frequent-contact ranking picks mailing relationships up automatically.
"""
import re
from datetime import datetime, timezone

AUTO_SUBJECT = re.compile(
    r"^(auto:|automated|out of (the )?office|ooo|away from|automatic reply|"
    r"undeliverable|delivery (status|failure)|mailbox (full|unavailable)|"
    r"re: auto|no longer monitored)", re.I)
AUTO_HEADERS = ("auto-submitted", "x-auto-response-suppress", "x-autoreply",
                "x-autorespond", "precedence")
BULK_PRECEDENCE = {"bulk", "list", "junk", "auto_reply"}


def _parse_one(raw):
    """Split a raw header block into a normalized dict."""
    if not raw or not str(raw).strip():
        return None
    text = str(raw).replace("\r\n", "\n")
    # unfold continuation lines
    text = re.sub(r"\n[ \t]+", " ", text)
    # keep only headers if a body snuck in
    if "\n\n" in text:
        text = text.split("\n\n", 1)[0]
    hdrs = {}
    for line in text.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    def _msgs(val):
        return re.findall(r"<([^>]+)>", val) or ([val.strip()] if val.strip() else [])

    msg_ids = _msgs(hdrs.get("message-id", ""))
    refs = _msgs(hdrs.get("references", "")) + _msgs(hdrs.get("in-reply-to", ""))
    frm = hdrs.get("from", "")
    tos = hdrs.get("to", "") + "," + hdrs.get("cc", "")
    date_raw = hdrs.get("date", "")
    dt = None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_raw)
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        dt = None
    emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", frm)
    to_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", tos)
    subject = hdrs.get("subject", "")
    auto = bool(AUTO_SUBJECT.search(subject))
    for h in AUTO_HEADERS:
        if h in hdrs:
            auto = True
            break
    if (hdrs.get("precedence") or "").strip().lower() in BULK_PRECEDENCE:
        auto = True
    return {
        "message_id": msg_ids[0] if msg_ids else "",
        "refs": refs,
        "from": emails[0] if emails else (frm[:120] or "unknown"),
        "from_raw": frm[:160],
        "to": to_emails,
        "date": dt.isoformat().replace("+00:00", "Z") if dt else None,
        "subject": subject[:200],
        "auto": auto,
    }


def parse_headers(raws):
    if isinstance(raws, str):
        raws = [raws]
    out = [h for h in (_parse_one(r) for r in (raws or [])) if h]
    return out


def thread_map(parsed):
    """Group messages into threads via Message-ID ancestry."""
    by_id = {m["message_id"]: m for m in parsed if m["message_id"]}
    roots = {}
    for m in parsed:
        root = None
        for ref in m["refs"]:
            if ref in by_id:
                root = ref
        if root is None:
            for mid in by_id:
                if mid and mid in m["refs"]:
                    root = mid
        if root is None:
            root = m["message_id"] or f"__anon_{id(m)}"
        roots.setdefault(root, []).append(m)

    threads, participants = [], {}
    for root, msgs in roots.items():
        msgs.sort(key=lambda x: x.get("date") or "")
        people = sorted({m["from"] for m in msgs if m.get("from")})
        for m in msgs:
            p = participants.setdefault(m["from"], {"email": m["from"], "sends": 0,
                                                    "receives": 0, "auto_replies": 0,
                                                    "subjects": set()})
            p["sends"] += 1
            p["receives"] += len(m.get("to") or [])
            if m["auto"]:
                p["auto_replies"] += 1
            if m.get("subject"):
                p["subjects"].add(m["subject"][:80])
        threads.append({
            "root": root[:120],
            "size": len(msgs),
            "participants": people,
            "subjects": sorted({m["subject"] for m in msgs if m.get("subject")})[:5],
            "first": msgs[0].get("date"), "last": msgs[-1].get("date"),
            "has_auto": any(m["auto"] for m in msgs),
        })
    threads.sort(key=lambda t: -(t["size"] or 0))
    for p in participants.values():
        p["subjects"] = sorted(p["subjects"])[:6]
    return threads, list(participants.values())


def analyze(raws, case_id=None, ingest=True, user="system"):
    """Full pass: parse -> threads -> participants -> (optional) ingest."""
    parsed = parse_headers(raws)
    if not parsed:
        return {"status": "error", "error": "no parseable headers found"}
    threads, participants = thread_map(parsed)
    ooo = [p for p in participants if p["auto_replies"] > 0]

    # thread participant pairs -> reply interactions (thread A talks to thread B members)
    events = []
    if ingest:
        from modules.pattern import pattern as PAT
        PAT.ensure()
        for t in threads:
            people = t["participants"]
            base_ts = t["first"] or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            for i, a in enumerate(people):
                for b in people[i + 1:]:
                    events.append({"actor": a, "target": b, "platform": "email",
                                   "kind": "thread", "ts": base_ts,
                                   "text": (t["subjects"] or [""])[0],
                                   "case_id": case_id})
        ing = PAT.ingest_events(events, case_id=case_id, user=user) if events else None
    else:
        ing = None

    # adjacency for the graph: who corresponds with whom
    edges = {}
    for t in threads:
        people = t["participants"]
        for i, a in enumerate(people):
            for b in people[i + 1:]:
                key = tuple(sorted((a, b)))
                edges[key] = edges.get(key, 0) + 1
    graph = [{"a": k[0], "b": k[1], "weight": w} for k, w in
             sorted(edges.items(), key=lambda x: -x[1])[:80]]

    return {
        "status": "ok",
        "messages": len(parsed),
        "threads": threads[:40],
        "thread_count": len(threads),
        "participants": sorted(participants, key=lambda p: -p["sends"])[:50],
        "auto_repliers": ooo[:20],
        "ooo_signal": bool(ooo),
        "graph_edges": graph,
        "ingested": ing,
    }
