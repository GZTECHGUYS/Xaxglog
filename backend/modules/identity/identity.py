"""Xaxglog identity intelligence — name/person search with real coverage.

This is the Phase-1/2 orchestrator that fixes the old name-search gaps:

* normalizes comma forms, suffixes, initials and extra whitespace
* generates always-on variants (not only when the exact name returns zero)
* runs existing people indexes plus additional keyless academic/archive/
  public-record/code adapters
* runs public-record modules and a general web pass in parallel
* merges, deduplicates and confidence-labels every lead
* returns an explicit per-source coverage map so a blocked source is never
  mistaken for "nothing found"
* exposes public link-out engines separately from automatic hits

Public/open sources only.  Name matches are leads, not identity proof.
"""
from __future__ import annotations

import json
import re
import unicodedata
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.deep_search import connectors as DEEP
from modules.deep_search import social as SOCIAL
from modules.namevar import namevar as NV
from modules.source_registry import source_registry as SR

from . import adapters as AD

NAME_SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v", "phd", "md", "esq", "dr", "prof"}
_NAME_ALLOWED = re.compile(r"^[^\W\d_](?:[\w'’.\- ,]*[^\W\d_])?$", re.UNICODE)

EXISTING_PEOPLE_ALIASES = {
    "github_users": "github",
    "codeberg_users": "codeberg",
    "openalex_authors": "openalex",
    "semanticscholar_authors": "semantic_scholar",
    "stackexchange": "stackexchange",
}

ENGINE_ALIASES = {
    "ddg": "ddg", "searx": "searx", "mojeek": "mojeek",
    "wikipedia": "wikipedia", "marginalia": "marginalia",
    "stract": "stract", "mwmbl": "mwmbl", "wiby": "wiby",
    "metager": "metager", "qwant": "qwant", "yep": "yep",
    "ecosia": "ecosia", "startpage": "startpage", "yandex": "yandex",
    "baidu": "baidu", "sogou": "sogou", "so360": "so360",
    "naver": "naver", "daum": "daum", "yahoo_jp": "yahoo_jp",
    "goo_jp": "goo_jp", "seznam": "seznam", "uol": "uol",
    "rambler": "rambler", "mailru": "mailru",
}


# ---------------------------------------------------------------- names
def is_person_name(value):
    s = re.sub(r"\s+", " ", (value or "").strip())
    if not (2 <= len(s) <= 120):
        return False
    if not _NAME_ALLOWED.fullmatch(s):
        return False
    if re.search(r"\d", s):
        return False
    if s.count(",") > 1:
        return False
    return bool(re.search(r"[^\W\d_]", s, re.UNICODE))


def _strip_suffix(tokens):
    """Remove honorific/generational suffixes wherever they occur.

    Suffixes are often before the family name in a comma form
    (``Doe, Jane A. Jr.``), so only stripping the final token is not enough.
    """
    toks = list(tokens)
    suffixes = []
    kept = []
    for i, tok in enumerate(toks):
        if tok.strip(".").lower() in NAME_SUFFIXES and len(toks) > 1:
            suffixes.append(tok)
        else:
            kept.append(tok)
    return kept or toks, suffixes


def normalize_name(value):
    """Normalize a free-form person name without destroying the original."""
    original = re.sub(r"\s+", " ", (value or "").strip())
    s = original.strip(" \t\r\n,;")
    comma_form = ""
    if "," in s:
        last, rest = s.split(",", 1)
        last, rest = last.strip(), rest.strip()
        if last and rest:
            comma_form = last + ", " + rest
            s = rest + " " + last
    s = re.sub(r"\s+", " ", s).strip(" ,;")
    tokens = [t for t in s.split(" ") if t]
    base_tokens, suffixes = _strip_suffix(tokens)
    base = " ".join(base_tokens).strip()
    return {
        "input": original,
        "normalized": base or s,
        "base": base or s,
        "tokens": base_tokens,
        "suffixes": suffixes,
        "comma_form": comma_form,
        "script": NV.script_detect(base or s),
        "key": _name_key(base or s),
        "valid": is_person_name(base or s),
    }


def _name_key(value):
    s = unicodedata.normalize("NFKD", value or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def name_variants(value, max_variants=24, include_nicknames=True,
                  include_transliteration=True):
    """Always-on, prioritized spelling/ordering variants for a person name."""
    norm = normalize_name(value)
    base = norm["base"] or norm["normalized"]
    out, seen = [], set()

    def add(v):
        v = re.sub(r"\s+", " ", (v or "").strip(" ,;"))
        if not v or not is_person_name(v):
            return
        key = v.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(v)

    add(norm["normalized"])
    add(base)
    if norm["comma_form"]:
        add(norm["comma_form"])
    toks = [t for t in base.split() if t]
    if len(toks) >= 2:
        first, last = toks[0], toks[-1]
        add(last + " " + first)
        add(last + ", " + first)
        add(first + " " + last)
        add(first[0] + " " + last)
        add(first[0] + ". " + last)
        add(first + " " + last[0] + ".")
        add(first[0] + ". " + last[0] + ".")
        add(first + last)
        add(first[0] + last)
        add(first + last[0])
        add("".join(toks))
        if len(toks) > 2:
            add(first + " " + toks[-1])
            add(" ".join(toks[:-1]))
    for alt in SOCIAL.name_variants(base):
        add(alt)
    if include_nicknames or include_transliteration:
        try:
            for alt in NV.variants(
                    base, max_variants=80,
                    leet=False):
                if include_nicknames or alt.lower() == base.lower():
                    add(alt)
        except Exception:
            pass
    if include_transliteration:
        try:
            for alt in NV.cross_script_search_terms(base, max_terms=10):
                add(alt)
        except Exception:
            pass
    return out[:max_variants]


def handle_variants(value, max_variants=12):
    try:
        return SOCIAL.handle_candidates(value)[:max_variants]
    except Exception:
        return []


def detect_kind(query, override=None):
    q = (query or "").strip()
    if override and override not in ("auto", ""):
        return override.lower()
    if is_person_name(q) and (" " in q or "," in q):
        return "person"
    return DEEP.detect_type(q)


# ---------------------------------------------------------------- planner
def build_plan(query, *, kind=None, depth="standard", country=None,
               include_social=True, include_web=True, include_records=True,
               include_code=None, include_link_out=True):
    q = re.sub(r"\s+", " ", (query or "").strip())
    k = detect_kind(q, kind)
    norm = normalize_name(q) if k in ("person", "name", "identity") else None
    variants = name_variants(norm["base"] or q, max_variants=24) if norm else []
    handles = handle_variants(norm["base"] or q) if norm else []
    if include_code is None:
        include_code = depth == "deep"
    source_plan = SR.plan(k if k != "name" else "person", depth=depth,
                          country=country, include_social=include_social,
                          include_link_out=include_link_out)
    groups = {}
    for src in source_plan["sources"]:
        groups.setdefault(src["category"], []).append(src)
    return {
        "input": q,
        "kind": k,
        "depth": depth,
        "country": country or "all",
        "normalized": norm,
        "variants": variants,
        "handle_variants": handles,
        "source_plan": source_plan,
        "groups": groups,
        "execution": {
            "people_existing": list(SOCIAL.PEOPLE_SOURCES.keys()) if k in ("person", "name", "identity", "handle", "username") else [],
            "people_extra": list(AD.PEOPLE_ADAPTERS.keys()) if k in ("person", "name", "identity") else [],
            "variant_people": bool(variants) and depth != "quick",
            "records": include_records and k in ("person", "name", "identity", "company", "organization", "org"),
            "web": include_web,
            "social": include_social,
            "code": include_code,
            "link_out": include_link_out,
        },
        "note": ("Always-on variants + extra keyless indexes + public-record pass. "
                 "Every match is a lead; verify identity before attribution."),
    }


# ---------------------------------------------------------------- execution
def _variant_people_search(variants, depth="standard"):
    keys = ["github", "bluesky", "mastodon", "lemmy", "stackexchange", "codeberg", "crossref"]
    if depth == "deep":
        keys += ["openalex", "orcid", "openlibrary", "arxiv", "wikipedia"]
    keys = [k for k in keys if k in SOCIAL.PEOPLE_SOURCES]
    out = {"variants_tried": [], "sources": {}, "counts": {}, "errors": {}, "total": 0}
    alts = [v for v in variants[1:] if v][:1 if depth == "standard" else 2]
    if not alts:
        return out
    tasks = {}
    with ThreadPoolExecutor(max_workers=max(1, min(12, len(keys) * len(alts)))) as ex:
        for alt in alts:
            for key in keys:
                tasks[ex.submit(SOCIAL.PEOPLE_SOURCES[key], alt)] = (key, alt)
        for fut in as_completed(tasks):
            key, alt = tasks[fut]
            try:
                rows = fut.result() or []
            except Exception as e:
                out["errors"][key] = str(e)[:150]
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                rec = dict(row)
                rec["matched_variant"] = alt
                rec.setdefault("source", key)
                out["sources"].setdefault(key, []).append(rec)
    for key, rows in out["sources"].items():
        rows.sort(key=lambda r: -float(r.get("match") or 0))
        out["counts"][key] = len(rows)
    out["variants_tried"] = alts
    out["total"] = sum(out["counts"].values())
    return out


def _web_search(query, depth="standard"):
    try:
        from modules.searchx import searchx as SX
    except Exception as e:
        return {"query": query, "status": "error", "error": str(e)[:150],
                "engines": {}, "results": [], "total": 0}
    engines = ["ddg", "searx", "mojeek", "wikipedia"]
    if depth == "deep":
        engines += list(getattr(SX, "EXTENDED_ENGINES", []))
    engines = [e for e in engines if e in getattr(SX, "ENGINE_FNS", {})]
    fed = SX.federated(query, engines=engines)
    fed["status"] = "ok" if fed.get("total") else (
        "blocked" if fed.get("engines") and all(v == "blocked" for v in fed["engines"].values())
        else "empty")
    return fed


def _records_search(query, country=None, depth="standard"):
    from modules.procurement import procurement as PR
    from modules.lobbying import lobbying as LB
    from modules.nonprofit import nonprofit as NP

    jobs = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        jobs["procurement"] = ex.submit(PR.search, query, country or "all", 10)
        jobs["lobbying"] = ex.submit(LB.search, query, None, 10)
        jobs["nonprofit"] = ex.submit(NP.search, query, None, 10)
        jobs["extra_records"] = ex.submit(AD.run_adapters, query, AD.RECORD_ADAPTERS, 5, 8)
        if country and country not in ("all", "*"):
            try:
                from modules.countryscope import countryscope as CS
                jobs["countryscope"] = ex.submit(CS.search, query, country, None, "system", False)
            except Exception:
                pass
        parts = {}
        for key, fut in jobs.items():
            try:
                parts[key] = fut.result()
            except Exception as e:
                parts[key] = {"status": "error", "error": str(e)[:150], "results": []}

    out = {"sources": {}, "results": [], "errors": {}, "status": "ok", "total": 0}
    for key in ("procurement", "lobbying", "nonprofit", "countryscope"):
        part = parts.get(key) or {}
        if not part:
            continue
        out["sources"][key] = {k: part.get(k) for k in ("status", "count", "total", "error") if part.get(k) is not None}
        for row in part.get("results") or []:
            out["results"].append(_record_row(key, row))
    extra = parts.get("extra_records") or {}
    for src, rows in (extra.get("sources") or {}).items():
        out["sources"][src] = {"status": "ok" if rows else "empty", "count": len(rows)}
        out["results"].extend(rows)
    out["errors"].update(extra.get("errors") or {})
    out["total"] = len(out["results"])
    if out["total"] == 0:
        out["status"] = "empty"
    elif len(out["errors"]) > 3:
        out["status"] = "partial"
    return out


def _record_row(group, row):
    if not isinstance(row, dict):
        return {"source": group, "category": "records", "name": str(row)[:200],
                "url": "", "match": 0.0}
    if group == "procurement":
        name = row.get("awardee") or row.get("buyer") or row.get("title") or ""
        detail = " · ".join(x for x in (row.get("buyer"), row.get("awardee"),
                                        row.get("amount"), row.get("date")) if x)
        return {"source": row.get("source") or "procurement", "category": "records",
                "name": name, "url": row.get("url") or "", "match": 0.45,
                "detail": detail, "raw": row}
    if group == "lobbying":
        name = row.get("client") or row.get("registrant") or row.get("title") or ""
        detail = " · ".join(x for x in (row.get("registrant"),
                                        ", ".join(row.get("lobbyists") or []),
                                        row.get("period")) if x)
        return {"source": row.get("source") or "lobbying", "category": "records",
                "name": name, "url": row.get("url") or "", "match": 0.45,
                "detail": detail, "raw": row}
    if group == "nonprofit":
        return {"source": "propublica", "category": "records",
                "name": row.get("name") or "", "url": row.get("url") or "",
                "match": 0.45, "detail": " · ".join(x for x in (row.get("city"),
                                                                row.get("state"),
                                                                row.get("ntee_code")) if x),
                "raw": row}
    if group == "countryscope":
        return {"source": "countryscope", "category": "records",
                "name": row.get("value") or row.get("type") or "country signal",
                "url": row.get("url") or "", "match": 0.4,
                "detail": row.get("note") or row.get("source") or "",
                "raw": row}
    return {"source": group, "category": "records", "name": str(row.get("name") or ""),
            "url": row.get("url") or "", "match": 0.4, "raw": row}


def _flatten_people(person, extra, variant):
    rows = []
    people = person.get("people") or {}
    for src, items in (people.get("sources") or {}).items():
        for item in items or []:
            if not isinstance(item, dict):
                continue
            rows.append(_person_row(src, item))
    platforms = person.get("name_platforms") or {}
    for hit in platforms.get("hits") or []:
        if isinstance(hit, dict):
            rows.append({
                "source": hit.get("source") or "name_platforms",
                "category": "people",
                "name": hit.get("name") or hit.get("handle") or "",
                "url": hit.get("url") or "",
                "match": hit.get("match") if hit.get("match") is not None else 0.5,
                "detail": " · ".join(x for x in (hit.get("platform"),
                                                hit.get("handle"),
                                                hit.get("bio")) if x),
                "raw": hit,
            })
    for src, items in (extra.get("sources") or {}).items():
        for item in items or []:
            rows.append(dict(item, category=item.get("category") or "people"))
    for src, items in (variant.get("sources") or {}).items():
        for item in items or []:
            rec = _person_row(src, item)
            rec["matched_variant"] = item.get("matched_variant")
            rec["detail"] = ("variant: " + str(item.get("matched_variant")) +
                             (" · " + rec.get("detail", "") if rec.get("detail") else ""))
            rows.append(rec)
    return rows


def _person_row(src, item):
    name = (item.get("name") or item.get("title") or item.get("login") or
            item.get("handle") or item.get("acct") or "")
    url = item.get("url") or item.get("html_url") or ""
    detail = " · ".join(str(x) for x in (
        item.get("description"), item.get("bio"), item.get("location"),
        item.get("institutions") if isinstance(item.get("institutions"), str) else "",
        item.get("affiliations") if isinstance(item.get("affiliations"), str) else "",
        item.get("born"),
    ) if x)
    return {
        "source": src,
        "category": "people",
        "name": name,
        "url": url,
        "match": item.get("match") if item.get("match") is not None else 0.5,
        "detail": detail,
        "raw": item,
    }


def _dedupe(rows):
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_url = row.get("url") or ""
        if isinstance(raw_url, (list, tuple)):
            raw_url = next((x for x in raw_url if x), "")
        url = str(raw_url).strip().lower()
        key = url or (row.get("source"), _name_key(row.get("name") or ""), row.get("matched_variant"))
        if key in seen:
            continue
        seen.add(key)
        match = row.get("match")
        try:
            match = float(match)
        except (TypeError, ValueError):
            match = 0.0
        row["match"] = round(max(0.0, min(1.0, match)), 3)
        if row["match"] >= 0.85:
            row["confidence"] = "high"
        elif row["match"] >= 0.55:
            row["confidence"] = "medium"
        else:
            row["confidence"] = "lead"
        out.append(row)
    out.sort(key=lambda r: (-r.get("match", 0), r.get("source", ""), r.get("name", "")))
    return out


# ---------------------------------------------------------------- coverage
def _coverage(plan, executed):
    by_source = {}
    for src in plan["source_plan"]["sources"]:
        sid = src["id"]
        entry = {
            "id": sid, "label": src["label"], "category": src["category"],
            "access": src["access"], "planned": True, "executed": False,
            "status": "not_checked", "count": 0,
        }
        if src["access"] == "link_out":
            entry.update({"status": "link_out", "executed": False})
        elif src["access"] == "optional_key":
            entry.update({"status": "skipped_key", "executed": False})
        elif src["access"] == "blocked":
            entry.update({"status": "blocked", "executed": False})
        else:
            adapter = (src.get("adapter") or "").split(".")[-1]
            part = None
            if sid in EXISTING_PEOPLE_ALIASES:
                part = ((executed.get("person") or {}).get("people") or {}).get("sources", {}).get(
                    EXISTING_PEOPLE_ALIASES[sid])
                err = ((executed.get("person") or {}).get("people") or {}).get("errors", {}).get(
                    EXISTING_PEOPLE_ALIASES[sid])
                if part is not None:
                    entry.update({"executed": True, "status": "ok" if part else "empty",
                                  "count": len(part)})
                elif err:
                    entry.update({"executed": True,
                                  "status": "blocked" if "block" in str(err).lower() or "rate" in str(err).lower() else "error",
                                  "detail": str(err)[:120]})
            elif adapter in AD.PEOPLE_ADAPTERS:
                part = ((executed.get("extra_people") or {}).get("sources") or {}).get(adapter)
                err = ((executed.get("extra_people") or {}).get("errors") or {}).get(adapter)
                if part is not None:
                    entry.update({"executed": True, "status": "ok" if part else "empty",
                                  "count": len(part)})
                elif err:
                    entry.update({"executed": True,
                                  "status": "blocked" if "block" in str(err).lower() or "rate" in str(err).lower() else "error",
                                  "detail": str(err)[:120]})
            elif adapter in AD.RECORD_ADAPTERS:
                part = ((executed.get("records") or {}).get("sources") or {}).get(adapter)
                if part:
                    entry.update({"executed": True, "status": part.get("status", "ok"),
                                  "count": part.get("count") or 0})
            elif adapter in AD.CODE_ADAPTERS:
                part = ((executed.get("code") or {}).get("sources") or {}).get(adapter)
                err = ((executed.get("code") or {}).get("errors") or {}).get(adapter)
                if part is not None:
                    entry.update({"executed": True, "status": "ok" if part else "empty",
                                  "count": len(part)})
                elif err:
                    entry.update({"executed": True, "status": "error", "detail": str(err)[:120]})
            elif adapter in AD.SOCIAL_ADAPTERS:
                part = ((executed.get("social_extra") or {}).get("sources") or {}).get(adapter)
                if part is not None:
                    entry.update({"executed": True, "status": "ok" if part else "empty",
                                  "count": len(part)})
            elif adapter in AD.INFRA_ADAPTERS:
                part = ((executed.get("infra") or {}).get("sources") or {}).get(adapter)
                if part is not None:
                    entry.update({"executed": True, "status": "ok" if part else "empty",
                                  "count": len(part)})
            elif adapter in getattr(__import__("modules.searchx.searchx", fromlist=["ENGINE_FNS"]), "ENGINE_FNS", {}):
                eng = (executed.get("web") or {}).get("engines") or {}
                st = eng.get(adapter)
                if st:
                    entry.update({"executed": True,
                                  "status": "ok" if st == "ok" else st,
                                  "count": 0})
            elif sid in ("procurement", "lobbying", "nonprofit"):
                part = ((executed.get("records") or {}).get("sources") or {}).get(sid)
                if part:
                    entry.update({"executed": True, "status": part.get("status", "ok"),
                                  "count": part.get("count") or 0})
        by_source[sid] = entry

    counts = {}
    for entry in by_source.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    planned = len(by_source)
    executed = sum(1 for e in by_source.values() if e["executed"])
    return {
        "planned": planned,
        "executed": executed,
        "not_checked": counts.get("not_checked", 0),
        "link_out": counts.get("link_out", 0),
        "skipped_key": counts.get("skipped_key", 0),
        "ok": counts.get("ok", 0),
        "empty": counts.get("empty", 0),
        "blocked": counts.get("blocked", 0),
        "error": counts.get("error", 0),
        "coverage_pct": round(100.0 * executed / planned, 1) if planned else 0.0,
        "by_source": by_source,
        "note": ("A source marked blocked/error was not silently treated as empty. "
                 "Link-out sources require the analyst to open them; optional-key "
                 "sources were skipped because no key is configured."),
    }


# ---------------------------------------------------------------- public API
def search(query, *, kind=None, depth="standard", country=None,
           include_social=True, include_web=True, include_records=True,
           include_code=None, include_link_out=True, case_id=None,
           user="system", max_variants=24):
    q = re.sub(r"\s+", " ", (query or "").strip())
    if not q:
        return {"input": "", "status": "error", "error": "query required",
                "results": [], "coverage": {}}
    plan = build_plan(q, kind=kind, depth=depth, country=country,
                      include_social=include_social, include_web=include_web,
                      include_records=include_records, include_code=include_code,
                      include_link_out=include_link_out)
    k = plan["kind"]
    if k not in ("person", "name", "identity", "handle", "username"):
        out = DEEP.deep_search(q)
        out["identity_plan"] = plan
        out["coverage"] = {
            "note": "Non-person target routed to the existing deep-search connector.",
            "planned": plan["source_plan"]["count"],
        }
        return out

    executed = {}
    norm = plan["normalized"] or {}
    base = norm.get("base") or q
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {}
        if k in ("person", "name", "identity"):
            futures["person"] = ex.submit(DEEP.person_search, base,
                                          include_social=include_social)
            futures["extra_people"] = ex.submit(AD.run_adapters, base,
                                                AD.PEOPLE_ADAPTERS, 10, 8)
            if plan["execution"]["variant_people"]:
                futures["variant_people"] = ex.submit(_variant_people_search,
                                                      plan["variants"], depth)
            if include_records:
                futures["records"] = ex.submit(_records_search, base, country, depth)
        else:
            futures["social"] = ex.submit(DEEP.social_search, q,
                                          include_web=include_web)
            futures["extra_people"] = ex.submit(AD.run_adapters, q,
                                                AD.PEOPLE_ADAPTERS, 8, 8)
            futures["code"] = ex.submit(AD.run_adapters, q,
                                        AD.CODE_ADAPTERS, 8, 8)
            futures["social_extra"] = ex.submit(AD.run_adapters, q,
                                                AD.SOCIAL_ADAPTERS, 4, 8)
        if include_web:
            futures["web"] = ex.submit(_web_search, base, depth)
        if include_code:
            futures["code"] = ex.submit(AD.run_adapters, base,
                                        AD.CODE_ADAPTERS, 8, 8)
        if k in ("person", "name", "identity") and depth == "deep":
            futures["infra"] = ex.submit(AD.run_adapters, base,
                                         AD.INFRA_ADAPTERS, 6, 8)
        for key, fut in futures.items():
            try:
                executed[key] = fut.result()
            except Exception as e:
                executed[key] = {"status": "error", "error": str(e)[:180],
                                 "sources": {}, "results": [], "total": 0}

    rows = []
    if executed.get("person"):
        rows.extend(_flatten_people(executed["person"],
                                    executed.get("extra_people") or {},
                                    executed.get("variant_people") or {}))
    elif executed.get("extra_people"):
        for src, items in (executed["extra_people"].get("sources") or {}).items():
            rows.extend(dict(x, category="people") for x in items)
    if executed.get("records"):
        rows.extend(executed["records"].get("results") or [])
    if executed.get("web"):
        for item in executed["web"].get("results") or []:
            rows.append({
                "source": "web:" + ",".join(item.get("engines") or []),
                "category": "web",
                "name": item.get("title") or item.get("url") or "",
                "url": item.get("url") or "",
                "match": 0.35 if item.get("engines") else 0.25,
                "detail": item.get("snippet") or "",
                "raw": item,
            })
    if executed.get("social"):
        for item in executed["social"].get("results") or []:
            rows.append({
                "source": "social:" + ",".join(item.get("engines") or []),
                "category": "social",
                "name": item.get("title") or item.get("url") or "",
                "url": item.get("url") or "",
                "match": 0.4,
                "detail": item.get("snippet") or item.get("platform") or "",
                "raw": item,
            })
    for key in ("code", "social_extra", "infra"):
        part = executed.get(key) or {}
        for src, items in (part.get("sources") or {}).items():
            for item in items:
                rec = dict(item)
                rec.setdefault("category", key)
                rows.append(rec)

    rows = _dedupe(rows)
    links = SR.search_links(q, limit=250) if include_link_out else []
    coverage = _coverage(plan, executed)
    out = {
        "input": q,
        "status": "ok" if rows else "empty",
        "kind": k,
        "depth": depth,
        "country": country or "all",
        "normalized": plan["normalized"],
        "variants": plan["variants"],
        "handle_variants": plan["handle_variants"],
        "plan": {
            "count": plan["source_plan"]["count"],
            "categories": {k2: len(v) for k2, v in plan["groups"].items()},
            "execution": plan["execution"],
        },
        "results": rows,
        "total": len(rows),
        "by_category": _counts(rows, "category"),
        "by_source": _counts(rows, "source"),
        "by_confidence": _counts(rows, "confidence"),
        "coverage": coverage,
        "link_out": links,
        "sources": {
            "people": executed.get("person"),
            "extra_people": executed.get("extra_people"),
            "variant_people": executed.get("variant_people"),
            "records": executed.get("records"),
            "web": executed.get("web"),
            "social": executed.get("social"),
            "code": executed.get("code"),
            "infra": executed.get("infra"),
        },
        "note": ("Name matches are leads, not identity proof. High confidence "
                 "means a strong name/URL match, not a verified identity. Check "
                 "the coverage map: blocked or link-out sources were not counted "
                 "as automatic hits."),
        "disclaimer": ("Public/open sources only. No login walls, captcha solving, "
                       "private databases or device access. Respect privacy law, "
                       "robots/rate limits and source ToS."),
    }
    if not rows:
        out["note"] = ("No automatic hit in the executed sources. Check coverage: "
                       "some sources may be blocked, link-out, optional-key or not checked.")
    if case_id and rows:
        try:
            import db
            out["artifact"] = db.store_artifact(
                case_id, None, "identity", "identity:search", out, user)
        except Exception as e:
            out["artifact_error"] = str(e)[:150]
    return out


def _counts(rows, key):
    out = {}
    for row in rows:
        value = row.get(key) or "unknown"
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def coverage(query, **kwargs):
    return search(query, **kwargs).get("coverage") or {}


def source_catalog():
    return SR.catalog()


def source_plan(query, **kwargs):
    return build_plan(query, **kwargs)


def _adapter_for_source(source_id):
    """Resolve a registry id to a callable keyless adapter, if one exists."""
    sid = (source_id or "").strip()
    # Monitoring catalog entries are aliases of the same keyless adapters.
    sid = {
        "gdelt_news": "gdelt",
        "wayback_watch": "wayback",
        "urlscan_watch": "urlscan",
        "telegram_watch": "telegram_preview",
        "certstream_watch": "certstream",
    }.get(sid, sid)
    if sid in AD.PEOPLE_ADAPTERS:
        return "people", AD.PEOPLE_ADAPTERS[sid]
    if sid in AD.RECORD_ADAPTERS:
        return "records", AD.RECORD_ADAPTERS[sid]
    if sid in AD.CODE_ADAPTERS:
        return "code", AD.CODE_ADAPTERS[sid]
    if sid in AD.INFRA_ADAPTERS:
        return "infrastructure", AD.INFRA_ADAPTERS[sid]
    if sid in AD.SOCIAL_ADAPTERS:
        return "social", AD.SOCIAL_ADAPTERS[sid]
    alias = EXISTING_PEOPLE_ALIASES.get(sid, sid)
    if alias in SOCIAL.PEOPLE_SOURCES:
        return "people", SOCIAL.PEOPLE_SOURCES[alias]
    try:
        from modules.searchx import searchx as SX
        if sid in SX.ENGINE_FNS:
            return "web", SX.ENGINE_FNS[sid]
    except Exception:
        pass
    return None, None


def verify_sources(ids=None, query="John Smith", timeout=12):
    """Live-check selected adapters/engines from this host.

    This is intentionally explicit: a source is only marked verified when a
    live call returns usable rows.  Empty results are still a healthy source;
    blocked/error sources are reported separately.
    """
    wanted = ids or list(AD.PEOPLE_ADAPTERS) + list(AD.CODE_ADAPTERS) + list(AD.RECORD_ADAPTERS)
    wanted = list(dict.fromkeys(str(x).strip() for x in wanted if str(x).strip()))
    out = {
        "query": query,
        "timeout": timeout,
        "checked": 0,
        "ok": 0,
        "empty": 0,
        "blocked": 0,
        "error": 0,
        "no_adapter": 0,
        "results": {},
        "note": ("Only adapters/engines with code are checked. Link-out and "
                 "optional-key sources require a browser or operator key."),
    }

    def _check(sid):
        group, fn = _adapter_for_source(sid)
        if fn is None:
            return sid, {"status": "no_adapter", "count": 0,
                         "detail": "no keyless adapter; use link-out or a key"}
        try:
            rows = fn(query) or []
            rows = [r for r in rows if isinstance(r, dict)]
            return sid, {"status": "ok" if rows else "empty", "count": len(rows),
                         "group": group, "sample": rows[:2]}
        except Exception as e:
            msg = str(e)[:180]
            blocked = any(x in msg.lower() for x in ("blocked", "rate", "403", "429", "captcha"))
            return sid, {"status": "blocked" if blocked else "error",
                         "count": 0, "group": group, "detail": msg}

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(_check, sid) for sid in wanted]
        for fut in as_completed(futs):
            sid, result = fut.result()
            out["results"][sid] = result
            out["checked"] += 1
            st = result.get("status")
            if st in out:
                out[st] += 1
    out["verified"] = out["ok"]
    out["status"] = "ok" if out["ok"] else "empty"
    return out
