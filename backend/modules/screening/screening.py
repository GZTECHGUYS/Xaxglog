"""Xaxglog sanctions / PEP / watchlist screening.

Batch-screen entities against public sanctions and watchlists:
  - OFAC SDN list (US Treasury, public XML/CSV)
  - consolidated non-SDN lists (public)
  - UN Security Council consolidated list (public)
  - fuzzy name matching (token + substring similarity)

Free, public data sources. Used for compliance/counter-party screening.
"""
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 25
OFAC_SDN_CSV = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"
OFAC_SDN_XML = "https://www.treasury.gov/ofac/downloads/sdn.xml"
UN_LIST = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"

_cache = {"ts": 0, "entries": None}


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def load_ofac(max_entries=20000):
    """Load OFAC SDN names (CSV) into memory with caching.

    A failed/empty fetch is NOT cached (retry on next call).
    """
    import time
    if _cache["entries"] and time.time() - _cache["ts"] < 86400:
        return _cache["entries"]
    entries = []
    r = _get(OFAC_SDN_CSV)
    if not isinstance(r, Exception) and r.status_code == 200 and r.text:
        # OFAC CSV: num,"name",addr_type,"country",...
        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in _split_csv(line)]
            if len(parts) >= 4:
                name = parts[1].strip('"').strip()
                country = parts[3].strip('"').strip()
                if name and name.upper() != "NAME":
                    entries.append({"name": name, "country": country,
                                    "type": "individual", "source": "OFAC_SDN"})
    else:
        # fallback XML
        rx = _get(OFAC_SDN_XML)
        if not isinstance(rx, Exception):
            for m in re.finditer(r'<sdnName>(.*?)</sdnName>', rx.text):
                entries.append({"name": m.group(1), "type": "individual",
                                "source": "OFAC_SDN"})
    if entries:  # only cache a successful non-empty load
        _cache["ts"] = time.time()
        _cache["entries"] = entries[:max_entries]
        return _cache["entries"]
    return []


def _split_csv(line):
    """Split an OFAC CSV line respecting double-quoted fields."""
    out, cur, in_q = [], "", False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            cur += ch
        elif ch == ',' and not in_q:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def load_un():
    entries = []
    r = _get(UN_LIST)
    if isinstance(r, Exception):
        return entries
    # individuals: combine FIRST/SECOND/THIRD names within each INDIVIDUAL block
    for block in re.findall(r'<INDIVIDUAL>(.*?)</INDIVIDUAL>', r.text, re.S):
        parts = re.findall(r'<(?:FIRST|SECOND|THIRD|FOURTH)_NAME>(.*?)</(?:FIRST|SECOND|THIRD|FOURTH)_NAME>', block)
        name = " ".join(p.strip() for p in parts if p.strip()).strip()
        if name:
            entries.append({"name": name, "type": "individual", "source": "UN"})
    # entities: name lives in FIRST_NAME (single field)
    for block in re.findall(r'<ENTITY>(.*?)</ENTITY>', r.text, re.S):
        m = re.search(r'<FIRST_NAME>(.*?)</FIRST_NAME>', block)
        if m and m.group(1).strip():
            entries.append({"name": m.group(1).strip(), "type": "entity", "source": "UN"})
    return entries


def _norm(s):
    return re.sub(r'[^a-z0-9 ]', '', (s or "").lower()).strip()


def _sim(a, b):
    """Token-overlap + substring similarity 0..1."""
    ta, tb = set(_norm(a).split()), set(_norm(b).split())
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    union = ta | tb
    jacc = len(inter) / len(union)
    sub = 1.0 if (_norm(a) in _norm(b)) or (_norm(b) in _norm(a)) else 0.0
    return max(jacc, sub * 0.9)


def screen_name(name, threshold=0.75):
    """Screen one name against OFAC + UN lists; returns fuzzy matches."""
    results = []
    for e in load_ofac():
        s = _sim(name, e["name"])
        if s >= threshold:
            results.append({**e, "score": round(s, 3)})
    for e in load_un():
        s = _sim(name, e["name"])
        if s >= threshold:
            results.append({**e, "score": round(s, 3)})
    results.sort(key=lambda x: -x["score"])
    # dedupe by name+source
    seen, dedup = set(), []
    for r in results:
        k = (r["name"], r["source"])
        if k not in seen:
            seen.add(k)
            dedup.append(r)
    return {"input": name, "matches": len(dedup), "results": dedup[:25],
            "hit": dedup[0]["score"] >= 0.9 if dedup else False,
            "threshold": threshold}


def screen_batch(names, threshold=0.75, case_id=None, user="system"):
    """Screen many names at once (OFAC/UN loaded once, cached)."""
    load_ofac()
    out = []
    hits = 0
    for n in names:
        n = (n or "").strip()
        if not n:
            continue
        r = screen_name(n, threshold)
        out.append(r)
        if r["hit"]:
            hits += 1
    if case_id and out:
        db.store_artifact(case_id, None, "screening", "screening:batch",
                          {"results": out, "hits": hits}, user)
        db.audit(user, "screening.batch", f"n={len(out)}", f"hits={hits}")
    return {"screened": len(out), "hits": hits, "results": out,
            "lists": ["OFAC_SDN", "UN"]}


def screen_case_entities(case_id, threshold=0.75, user="system"):
    """Screen every person/company entity in a case."""
    c = db.get_db()
    rows = c.execute(
        "SELECT id,type,value FROM entities WHERE case_id=? AND type IN ('person','company','username')",
        (case_id,)).fetchall()
    names = [r["value"] for r in rows]
    res = screen_batch(names, threshold, case_id, user)
    res["entity_count"] = len(names)
    return res


def lists_status():
    """What lists are available + sizes."""
    ofac = load_ofac()
    un = load_un()
    return {"OFAC_SDN": len(ofac), "UN": len(un),
            "note": "public sanctions lists; refreshed every 24h"}
