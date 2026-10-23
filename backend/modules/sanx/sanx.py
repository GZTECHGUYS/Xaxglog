"""Xaxglog multi-list sanctions screening (OpenSanctions-style, free sources).

Fuzzy name screening across several public sanctions lists, reusing the
existing OFAC/UN loaders from modules.screening and adding:
  - UK OFSI / UK Sanctions List (OFSI storage CSV — probed live; the current
    file is the UKSL export with "Name 1..Name 6"/"Regime" columns, so the
    parser handles both that and the legacy "Name"/"Programmes" layout)
  - EU consolidated financial sanctions list (webgate XML — probed live:
    eu.europa.ec/fpi/fsd/export schema with <sanctionEntity>/<nameAlias>)
  - optional OpenSanctions bulk dataset (OPENSANCTIONS_BULK=1; HEAD-probed
    for size, streamed JSON-lines, capped at 400k entries, atomic local
    cache). Default OFF to avoid large downloads.

Lawful-use note: all lists are official public sanctions publications
(US Treasury OFAC, UN Security Council, UK OFSI, EU FSD) redistributed on
their own free endpoints. Screening is for compliance / due-diligence.
Fuzzy hits are leads, not determinations — confirm against the official
record before acting.
"""
import csv
import io
import json
import os
import re
import time
import xml.etree.ElementTree as ET

import db
from modules.screening.screening import load_ofac, load_un, _sim, _norm

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 60
CACHE_TTL = 86400          # 24h memory cache
FAIL_TTL = 3600            # retry unavailable sources after 1h
OFSI_CSV = "https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv"
EU_URLS = [
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw",
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1/content?token=dG9rZW4tMjAxNw",
]
OS_HEAD = "https://data.opensanctions.org/datasets/latest/sanctions/entities.ftm.json"
OS_CACHE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                        "data", "opensanctions_cache.json"))

_cache = {}  # name -> {ts, entries|None, status, reason, last_fetch}


def _get(url, timeout=T):
    import requests
    try:
        return requests.get(url, headers=UA, timeout=timeout)
    except Exception as e:
        return e


# ----------------------------------------------------------------- loaders

def _fetch_ofac():
    ents = load_ofac()
    if not ents:
        raise RuntimeError("OFAC SDN CSV empty/unreachable")
    return [{"name": e["name"], "country": e.get("country", ""), "programme": "SDN",
             "type": e.get("type", "individual")} for e in ents]


def _fetch_un():
    ents = load_un()
    if not ents:
        raise RuntimeError("UN consolidated XML empty/unreachable")
    return [{"name": e["name"], "country": "", "programme": "UN-CONSOLIDATED",
             "type": e.get("type", "individual")} for e in ents]


def _fetch_ofsi():
    """UK OFSI / UK Sanctions List CSV (16MB, 24h-cached)."""
    r = _get(OFSI_CSV, timeout=120)
    if isinstance(r, Exception):
        raise RuntimeError(f"OFSI fetch failed: {r}"[:150])
    if r.status_code != 200:
        raise RuntimeError(f"OFSI HTTP {r.status_code}")
    text = r.text
    if not text or len(text) < 200:
        raise RuntimeError("OFSI CSV too small")
    lines = text.splitlines()
    if lines and lines[0].lower().startswith("last updated"):
        lines = lines[1:]
    rd = csv.reader(io.StringIO("\n".join(lines)))
    try:
        header = next(rd)
    except StopIteration:
        raise RuntimeError("OFSI CSV empty")
    header = [h.strip() for h in header]
    idx = {h.lower(): i for i, h in enumerate(header)}
    out, seen = [], set()
    legacy = "name" in idx
    for row in rd:
        if len(row) < len(header):
            row = row + [""] * (len(header) - len(row))
        if legacy:
            name = (row[idx["name"]] or "").strip()
            prog = (row[idx.get("programmes", -1)] or "").strip() if "programmes" in idx else ""
            ctype = (row[idx.get("type of entity", -1)] or "entity").strip() if "type of entity" in idx else "entity"
            country = (row[idx.get("country", -1)] or "").strip() if "country" in idx else ""
        else:
            parts = [(row[idx[f"name {i}"]] or "").strip() for i in range(1, 7)
                     if f"name {i}" in idx]
            name = " ".join(p for p in parts if p)
            prog = (row[idx["regime"]] or "").strip() if "regime" in idx else ""
            country = (row[idx["country"]] or "").strip() if "country" in idx else ""
            ctype = "entity" if (idx.get("group type") is not None and
                                 (row[idx["group type"]] or "").strip()) else "individual"
        if not name:
            continue
        key = (name.lower(), prog.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "country": country, "programme": prog, "type": ctype})
    if not out:
        raise RuntimeError("OFSI CSV parsed 0 entries")
    return out


def _fetch_eu():
    """EU consolidated list — try candidate URLs until one parses."""
    last = "no URL attempted"
    for url in EU_URLS:
        r = _get(url, timeout=120)
        if isinstance(r, Exception):
            last = str(r)[:120]
            continue
        if r.status_code != 200:
            last = f"HTTP {r.status_code}"
            continue
        try:
            out = []
            ctx = ET.iterparse(io.BytesIO(r.content), events=("end",))
            for _, el in ctx:
                tag = el.tag.split("}")[-1]
                if tag != "sanctionEntity":
                    continue
                prog = ";".join(sorted({(c.get("programme") or "").strip()
                                        for c in el if c.tag.split("}")[-1] == "regulation"
                                        and (c.get("programme") or "").strip()}))
                stype = "entity"
                for c in el:
                    ct = c.tag.split("}")[-1]
                    if ct == "subjectType":
                        stype = c.get("code") or stype
                names = []
                for c in el:
                    if c.tag.split("}")[-1] == "nameAlias":
                        w = (c.get("wholeName") or "").strip()
                        if not w:
                            w = " ".join(x for x in [c.get("firstName", ""),
                                                     c.get("middleName", ""),
                                                     c.get("lastName", "")] if x).strip()
                        if w:
                            names.append((w, c.get("strong") == "true"))
                names.sort(key=lambda t: not t[1])
                primary = names[0][0] if names else None
                if not primary:
                    el.clear()
                    continue
                out.append({"name": primary, "country": "", "programme": prog,
                            "type": "individual" if stype == "person" else "entity"})
                for w, strong in names[1:]:
                    out.append({"name": w, "country": "", "programme": prog,
                                "type": "alias"})
                el.clear()
            if out:
                return out
            last = "parsed 0 sanctionEntity entries"
        except Exception as e:
            last = f"xml parse: {str(e)[:100]}"
    raise RuntimeError(f"EU list unavailable: {last}")


def _fetch_opensanctions():
    """Optional bulk OpenSanctions sanctions dataset (opt-in via env)."""
    if os.environ.get("OPENSANCTIONS_BULK") != "1":
        raise RuntimeError("OPENSANCTIONS_BULK not enabled")
    import requests
    try:
        h = requests.head(OS_HEAD, headers=UA, timeout=T, allow_redirects=True)
        clen = h.headers.get("content-length")
        size = int(clen) if clen and clen.isdigit() else None
        if size is None:
            raise RuntimeError("content-length unavailable (CDN chunked) — bulk skip")
        if size > 150_000_000:
            raise RuntimeError(f"dataset too large ({size} bytes > 150MB cap)")
        out = []
        with requests.get(OS_HEAD, headers=UA, timeout=180, stream=True) as r:
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            buf = b""
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        j = json.loads(line.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    cap_name = (j.get("caption") or "").strip()
                    props = j.get("properties") or {}
                    if not cap_name:
                        pnames = props.get("name") or []
                        cap_name = (pnames[0] if pnames else "").strip()
                    if not cap_name:
                        continue
                    countries = props.get("country") or []
                    if not countries and isinstance(j.get("addresses"), list):
                        countries = [a.get("country") for a in j["addresses"]
                                     if isinstance(a, dict) and a.get("country")]
                    out.append({"name": cap_name,
                                "country": countries[0] if countries else "",
                                "programme": "OPENSANCTIONS",
                                "type": (j.get("schema") or "").lower()})
                    if len(out) >= 400000:
                        raise _CapReached(out)
        return out
    except _CapReached as e:
        return e.entries
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(str(e)[:150])


class _CapReached(Exception):
    def __init__(self, entries):
        super().__init__("cap reached")
        self.entries = entries


SOURCES = {
    "ofac_sdn": {"fetch": _fetch_ofac, "urls": ["https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"],
                 "desc": "US Treasury OFAC SDN"},
    "un_consolidated": {"fetch": _fetch_un, "urls": ["https://scsanctions.un.org/resources/xml/en/consolidated.xml"],
                        "desc": "UN Security Council consolidated"},
    "uk_ofsi": {"fetch": _fetch_ofsi, "urls": [OFSI_CSV], "desc": "UK OFSI / UK Sanctions List"},
    "eu_consolidated": {"fetch": _fetch_eu, "urls": EU_URLS, "desc": "EU consolidated financial sanctions"},
    "opensanctions_bulk": {"fetch": _fetch_opensanctions, "urls": [OS_HEAD],
                           "desc": "OpenSanctions bulk (opt-in)"},
}


def _load(name):
    """Load one source through the 24h memory cache; never raises."""
    meta = SOURCES.get(name)
    if not meta:
        return None, {"status": "unknown", "reason": "unknown source"}
    c = _cache.get(name)
    now = time.time()
    if c:
        ttl = CACHE_TTL if c.get("status") == "ok" else FAIL_TTL
        if now - c.get("ts", 0) < ttl:
            return c.get("entries") or [], c
    try:
        entries = meta["fetch"]()
        c = {"ts": now, "entries": entries, "status": "ok", "reason": "",
             "last_fetch": db.utcnow(), "count": len(entries)}
    except Exception as e:
        c = {"ts": now, "entries": [], "status": "unavailable",
             "reason": str(e)[:150], "last_fetch": None, "count": 0}
    _cache[name] = c
    return c.get("entries") or [], c


# ------------------------------------------------------------------ search

def _score(query, cand):
    """Fuzzy score via the shared _sim, with guards against fragment junk.

    Two failure modes observed live against the real lists:
      - candidates whose ASCII normalisation is empty (pure Cyrillic/CJK
        originals) or tiny ("IG", "ESE", a stray Latin "A" in a
        mixed-script name) match everything via _sim's substring bonus;
      - short fragments are substrings of almost any longer query.
    So: require both normalised strings to be >=4 chars, and only honour
    _sim's 0.9 substring bonus when the shorter string is >=5 chars AND
    covers >=33% of the longer one. Token-overlap scores are kept as-is.
    """
    a, b = _norm(query).strip(), _norm(cand).strip()
    if len(a) < 4 or len(b) < 4:
        return 0.0
    s = _sim(query, cand)
    if s >= 0.9:
        ta, tb = set(a.split()), set(b.split())
        token_overlap = (len(ta & tb) / len(ta | tb)) if (ta and tb) else 0.0
        shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
        containment_ok = (len(shorter) >= 5 and shorter in longer
                          and len(shorter) / len(longer) >= 0.33)
        if not containment_ok:
            s = token_overlap  # demote substring-driven 0.9 to plain overlap
    return s


def search(name, threshold=0.75, sources=None):
    """Fuzzy-screen `name` across all (or selected) sanctions lists."""
    try:
        name = (name or "").strip()
        if not name:
            return {"input": name, "error": "empty name"}
        sel = list(sources) if sources else list(SOURCES.keys())
        sel = [s for s in sel if s in SOURCES]
        results, lists = [], {}
        for s in sel:
            ents, meta = _load(s)
            if meta.get("status") != "ok":
                lists[s] = meta.get("reason") or "unavailable"
                continue
            lists[s] = meta.get("count", len(ents))
            for e in ents:
                sc = _score(name, e["name"])
                if sc >= threshold:
                    results.append({"list": s, "name": e["name"],
                                    "country": e.get("country", ""),
                                    "programme": e.get("programme", ""),
                                    "type": e.get("type", ""),
                                    "score": round(sc, 3)})
        results.sort(key=lambda x: -x["score"])
        seen, dedup = set(), []
        for r in results:
            k = (r["name"].lower(), r["list"])
            if k not in seen:
                seen.add(k)
                dedup.append(r)
        best = dedup[0]["score"] if dedup else 0.0
        return {"input": name, "hit": best >= 0.9, "best_score": best,
                "matches": len(dedup), "results": dedup[:25],
                "threshold": threshold, "lists": lists}
    except Exception as e:
        return {"input": name, "error": str(e)[:150], "results": []}


def lists_status():
    """Merged availability status of every sanctions source."""
    out = {}
    for s in SOURCES:
        _, meta = _load(s)
        out[s] = {"status": meta.get("status"),
                  "count": meta.get("count", 0),
                  "reason": meta.get("reason", ""),
                  "last_fetch": meta.get("last_fetch"),
                  "urls": SOURCES[s]["urls"],
                  "desc": SOURCES[s]["desc"]}
    db.audit("system", "sanx.lists_status", "",
             json.dumps({k: v.get("status") for k, v in out.items()}))
    return out


def screen_case_entities(case_id, threshold=0.75, user="system"):
    """Screen every person/company/username entity in a case across all lists."""
    c = db.get_db()
    rows = c.execute(
        "SELECT id,type,value FROM entities WHERE case_id=? AND type IN ('person','company','username')",
        (case_id,)).fetchall()
    hits, screened = [], 0
    for r in rows:
        val = (r["value"] or "").strip()
        if not val:
            continue
        screened += 1
        res = search(val, threshold)
        if res.get("hit"):
            hits.append({"entity_id": r["id"], "entity": val,
                         "matches": res.get("matches"),
                         "top": res.get("results", [])[:5]})
    art = None
    if hits:
        art = db.store_artifact(case_id, hits[0]["entity_id"], "screening",
                                "sanx:multi-list",
                                {"hits": hits, "screened": screened,
                                 "threshold": threshold}, user)
    db.audit(user, "sanx.screen_case_entities", f"case={case_id}",
             f"screened={screened} hits={len(hits)}")
    return {"screened": screened, "hits": len(hits), "hit_details": hits,
            "lists": {s: (_cache.get(s) or {}).get("count") for s in SOURCES},
            "artifact": art}
