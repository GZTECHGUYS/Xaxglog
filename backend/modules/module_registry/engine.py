"""Execution, dedupe/ranking, coverage and live verification for modules."""
from __future__ import annotations

import difflib
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import probes, registry


def _list(value):
    if value is None:
        return None
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return list(value)


def _detect(query):
    try:
        from modules.deep_search import connectors as DEEP
        return DEEP.detect_type(query)
    except Exception:
        return "unknown"


def _norm_url(url):
    try:
        p = urllib.parse.urlsplit(url or "")
        host = (p.netloc or "").lower()
        if host.startswith("www."):
            host = host[4:]
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
             if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid", "ref")]
        path = urllib.parse.unquote(p.path or "/").rstrip("/") or "/"
        return urllib.parse.urlunsplit(("", host, path,
                                        urllib.parse.urlencode(q), ""))
    except Exception:
        return (url or "").strip().lower()


def _match_score(query, row):
    q = (query or "").strip().lower()
    if not q:
        return 0.0
    text = " ".join(str(row.get(k) or "") for k in
                    ("title", "name", "snippet", "url", "author")).lower()
    if q in text:
        return 1.0
    qt = set(re.findall(r"[a-z0-9@._-]+", q))
    tt = set(re.findall(r"[a-z0-9@._-]+", text))
    if qt and tt:
        overlap = len(qt & tt) / len(qt)
    else:
        overlap = 0.0
    seq = difflib.SequenceMatcher(None, q, text[:400]).ratio()
    return round(min(1.0, 0.65 * overlap + 0.35 * seq), 3)


def _rank(results):
    out = []
    for row in results:
        score = float(row.get("_match") or 0)
        score += 0.35 if row.get("_verified") else 0
        score += min(0.45, 0.12 * max(0, int(row.get("_corroboration") or 1) - 1))
        if row.get("fragile"):
            score -= 0.05
        row["rank_score"] = round(score, 3)
        out.append(row)
    out.sort(key=lambda r: (-r["rank_score"], -int(r.get("_corroboration") or 1),
                            r.get("source_label", ""), r.get("title", "")))
    return out


def _dedupe(results):
    merged = {}
    for row in results:
        key = _norm_url(row.get("url")) if row.get("url") else (
            row.get("module_id"), (row.get("title") or "").lower())
        cur = merged.get(key)
        if not cur:
            row["_corroboration"] = 1
            row["sources"] = [row.get("source_label") or row.get("source")]
            merged[key] = row
            continue
        cur["_corroboration"] = int(cur.get("_corroboration") or 1) + 1
        label = row.get("source_label") or row.get("source")
        if label and label not in cur["sources"]:
            cur["sources"].append(label)
        if not cur.get("snippet") and row.get("snippet"):
            cur["snippet"] = row["snippet"]
        if not cur.get("title") and row.get("title"):
            cur["title"] = row["title"]
        if row.get("_match", 0) > cur.get("_match", 0):
            cur["_match"] = row["_match"]
    return list(merged.values())


def _public(row):
    out = {k: v for k, v in row.items() if not k.startswith("_")}
    return out


def _diagnostics(by_source, results):
    if results:
        return {"reason": "", "blocked": [], "error": [], "empty": []}
    blocked = [k for k, v in by_source.items() if v.get("status") == "blocked"]
    errors = [k for k, v in by_source.items() if v.get("status") == "error"]
    empty = [k for k, v in by_source.items() if v.get("status") == "empty"]
    if blocked and len(blocked) == len(by_source):
        reason = "All selected modules were blocked by anti-bot/login walls."
    elif errors and len(errors) == len(by_source):
        reason = "All selected modules returned endpoint errors."
    elif empty and len(empty) == len(by_source):
        reason = "All selected modules responded but returned no usable rows for this query."
    else:
        reason = ("No automatic result. Check blocked/error/empty sources below; "
                  "link-out and optional-key sources are not automatic evidence.")
    return {"reason": reason, "blocked": blocked[:40], "error": errors[:40],
            "empty": empty[:40]}


def search(query, *, types=None, categories=None, statuses=None, probe_types=None,
           region=None, limit=40, timeout=8, max_workers=8,
           include_link_out=True, module_ids=None, include_unverified=False):
    """Run verified/fragile modules and return deduped, ranked evidence.

    ``include_unverified`` is for operator testing only.  Such rows are marked
    ``verified: false`` and are not part of the automatic-evidence count.
    """
    q = (query or "").strip()
    started = time.time()
    if not q:
        return {"query": "", "status": "error", "error": "query required",
                "results": [], "coverage": {}, "diagnostics": {}}
    allowed = _list(statuses) or list(registry.AUTOMATIC_STATUSES)
    if include_unverified:
        allowed = list(dict.fromkeys(allowed + ["adapter", "candidate"]))
    if module_ids:
        wanted = set(module_ids)
        mods = [m for m in registry.modules() if m["id"] in wanted]
        if not include_unverified:
            mods = [m for m in mods if m["status"] in allowed]
    else:
        mods = registry.select(types=_list(types), categories=_list(categories),
                               statuses=allowed, probe_types=_list(probe_types),
                               region=region)
    mods = [m for m in mods if m["probe_type"] != "link_out"]
    mods.sort(key=lambda m: (0 if m["status"] == "verified" else 1,
                             m["category"], m["label"].lower()))
    max_modules = max(1, min(int(limit or 40), 120))
    mods = mods[:max_modules]

    results, by_source = [], {}
    if mods:
        with ThreadPoolExecutor(max_workers=max(1, min(int(max_workers or 8), 16))) as ex:
            futs = {ex.submit(probes.run_probe, m, q, timeout=timeout): m for m in mods}
            for fut in as_completed(futs):
                mod = futs[fut]
                try:
                    pr = fut.result()
                except Exception as e:
                    pr = {"status": "error", "error": str(e)[:240], "results": []}
                status = pr.get("status") or "error"
                by_source[mod["id"]] = {
                    "label": mod["label"],
                    "status": status,
                    "probe_type": mod["probe_type"],
                    "count": len(pr.get("results") or []),
                    "error": pr.get("error") or "",
                }
                if status != "ok":
                    continue
                for row in pr.get("results") or []:
                    row = dict(row)
                    row["source"] = row.get("source") or mod["source_id"]
                    row["source_label"] = row.get("source_label") or mod["label"]
                    row["category"] = row.get("category") or mod["category"]
                    row["module_id"] = row.get("module_id") or mod["id"]
                    row["fragile"] = bool(row.get("fragile") or mod["fragile"])
                    row["verified"] = bool(mod["verified"])
                    row["_verified"] = bool(mod["verified"])
                    row["_match"] = _match_score(q, row)
                    results.append(row)

    results = _dedupe(results)
    results = _rank(results)
    public = [_public(r) for r in results[:max(1, int(limit or 40))]]

    link_outs = []
    if include_link_out:
        link_outs = build_links(q, types=_list(types), categories=_list(categories),
                                region=region, limit=min(100, int(limit or 40) * 2))

    planned = len(mods)
    ok = sum(1 for v in by_source.values() if v["status"] == "ok")
    blocked = sum(1 for v in by_source.values() if v["status"] == "blocked")
    errors = sum(1 for v in by_source.values() if v["status"] == "error")
    empty = sum(1 for v in by_source.values() if v["status"] == "empty")
    not_checked = 0 if mods else len(registry.select(types=_list(types), categories=_list(categories),
                                                     statuses=["adapter", "candidate"],
                                                     probe_types=_list(probe_types), region=region))
    coverage = {
        "planned": planned,
        "executed": len(by_source),
        "ok": ok,
        "empty": empty,
        "blocked": blocked,
        "error": errors,
        "not_checked": not_checked,
        "link_out": len(link_outs),
        "by_source": by_source,
        "coverage_pct": round(100.0 * len(by_source) / planned, 1) if planned else 0.0,
    }
    diag = _diagnostics(by_source, public)
    return {
        "query": q,
        "detected_type": _detect(q),
        "status": "ok" if public else "empty",
        "results": public,
        "count": len(public),
        "link_outs": link_outs,
        "coverage": coverage,
        "diagnostics": diag,
        "elapsed_ms": int((time.time() - started) * 1000),
        "note": ("Automatic results come only from verified/fragile modules. "
                 "Fragile public-page results can change or disappear; verify "
                 "against the primary source before attribution."),
    }


def build_links(query, *, types=None, categories=None, region=None, limit=100):
    q = (query or "").strip()
    if not q:
        return []
    out, seen = [], set()
    mods = registry.select(types=_list(types), categories=_list(categories), region=region)
    for mod in mods:
        link = probes.build_link(mod, q)
        if not link or link in seen:
            continue
        seen.add(link)
        out.append({
            "module_id": mod["id"],
            "label": mod["label"],
            "category": mod["category"],
            "access": mod["access"],
            "status": mod["status"],
            "probe_type": mod["probe_type"],
            "url": link,
        })
        if len(out) >= max(1, int(limit or 100)):
            break
    return out


def _combine_status(statuses, fragile):
    if all(s == "ok" for s in statuses):
        return "fragile" if fragile else "verified"
    if any(s == "ok" for s in statuses):
        # One successful run proves the probe works; a wall/error on another
        # run is instability, not a permanent block.
        return "unstable"
    if all(s == "blocked" for s in statuses):
        return "blocked"
    if any(s == "blocked" for s in statuses):
        return "blocked"
    if any(s == "error" for s in statuses):
        return "error"
    if any(s == "not_found" for s in statuses):
        return "not_found"
    return "empty"


def verify(ids=None, *, query="John Smith", checks=2, timeout=8,
           max_workers=4, persist=True, limit=40):
    """Live-check selected modules and optionally persist the overlay."""
    if isinstance(ids, str):
        ids = [x.strip() for x in ids.split(",") if x.strip()]
    if ids:
        mods = [registry.get(x) for x in ids]
        mods = [m for m in mods if m]
    else:
        mods = registry.select(statuses=["candidate", "adapter"], limit=limit)
        mods = [m for m in mods if m["probe_type"] != "link_out"]
    mods = [m for m in mods if m["probe_type"] != "link_out"][:max(1, int(limit or 40))]
    out = {
        "query": query,
        "checks": max(1, min(int(checks or 1), 3)),
        "checked": 0,
        "verified": 0,
        "fragile": 0,
        "blocked": 0,
        "error": 0,
        "empty": 0,
        "not_found": 0,
        "unstable": 0,
        "results": {},
        "note": ("Verification requires usable rows and a stable status across "
                 "checks. Scraped HTML modules are marked fragile, never plain "
                 "verified."),
    }
    if not mods:
        return out

    def _check(mod):
        runs = [probes.run_probe(mod, query, timeout=timeout)
                for _ in range(out["checks"])]
        statuses = [r.get("status") or "error" for r in runs]
        fragile = mod["probe_type"] in ("http_profile_probe", "html_search_probe")
        status = _combine_status(statuses, fragile)
        sample = []
        for r in runs:
            if r.get("results"):
                sample = r["results"][:2]
                break
        detail = "; ".join(dict.fromkeys(r.get("error") or "" for r in runs
                                         if r.get("error")))[:500]
        return mod, {
            "status": status,
            "runs": statuses,
            "fragile": fragile,
            "count": len(sample),
            "sample": sample,
            "detail": detail,
        }

    with ThreadPoolExecutor(max_workers=max(1, min(int(max_workers or 4), 12))) as ex:
        futs = [ex.submit(_check, m) for m in mods]
        for fut in as_completed(futs):
            mod, res = fut.result()
            out["results"][mod["id"]] = res
            out["checked"] += 1
            st = res["status"]
            if st in out:
                out[st] += 1
            if st in ("verified", "fragile", "blocked", "error", "unstable"):
                registry.set_status(
                    mod["id"], st, query=query, checks=out["checks"],
                    fragile=res["fragile"], detail=res["detail"],
                    sample=res["sample"], persist=persist)
    out["status"] = "ok" if (out["verified"] or out["fragile"]) else "empty"
    return out
