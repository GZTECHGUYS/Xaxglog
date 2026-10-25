"""Xaxglog attribution profiler — AI-assisted actor tracing.

Given one or more handles/profiles/identifiers, this module aggregates every
discovered profile across platforms, extracts correlating signals (shared
usernames, avatar reuse, bio text, timing patterns, linked accounts, breach
appearances), and — when an AI key is present — produces a structured actor
assessment linking the identities with a confidence score.

This is threat-actor attribution / CERT-style tracing: it correlates *public*
OSINT to answer "are these accounts the same actor, and what do they
collectively expose." It does not publish or dox private individuals.

Outputs feed the entity graph and are stored as hashed evidence under a case.
"""
import re

import db

try:
    from modules.deep_search import connectors as DEEP
except Exception:
    try:
        import connectors as DEEP
    except Exception:
        DEEP = None

# Signals that link two handles toward the same actor.
CORRELATION_SIGNALS = {
    "identical_username": 40,
    "same_platform_namespace": 15,
    "shared_avatar": 25,
    "bio_name_match": 20,
    "linked_cross_profile": 30,
    "breach_cooccurrence": 10,
    "temporal_overlap": 10,
}


def build_profile(identifiers, keys=None, case_id=None, user="system", use_ai=True):
    """Trace an actor across identifiers. `identifiers` = list of handles/emails/etc."""
    keys = keys or {}
    identifiers = [i.strip().lstrip("@") for i in (identifiers or []) if i.strip()]
    if not identifiers:
        return {"error": "at least one identifier required"}

    profiles = []
    seen_platforms = {}

    for ident in identifiers:
        entry = {"identifier": ident, "type": _detect(ident), "profiles": []}
        if entry["type"] == "username" and DEEP:
            try:
                u = DEEP.username_search(ident)
                for hit in u.get("hits", []):
                    entry["profiles"].append({
                        "platform": hit.get("platform"), "url": hit.get("url"),
                        "exists": hit.get("exists")})
                    seen_platforms.setdefault(ident, []).append(hit.get("platform"))
            except Exception as e:
                entry["error"] = str(e)[:150]
        elif entry["type"] == "email" and DEEP:
            try:
                e = DEEP.email_search(ident, keys.get("HIBP_API_KEY", ""))
                entry["email_intel"] = {"breaches": e.get("breaches", {}),
                                        "meta": e.get("meta", {})}
            except Exception as ex:
                entry["error"] = str(ex)[:150]
        elif entry["type"] == "person" and DEEP:
            try:
                p = DEEP.person_search(ident)
                entry["person_intel"] = p
            except Exception as ex:
                entry["error"] = str(ex)[:150]
        profiles.append(entry)

    # ---- correlation analysis across identifiers
    corr = _correlate(identifiers, profiles, seen_platforms)

    assessment = {
        "identifiers": identifiers,
        "profiles": profiles,
        "correlations": corr,
        "confidence": corr["overall_confidence"],
        "signals_used": corr["signals"],
    }

    # ---- AI narrative (optional, degrades gracefully)
    if use_ai and (keys.get("GEMINI_API_KEY") or keys.get("GROQ_API_KEY")):
        assessment["ai_assessment"] = _ai_assess(assessment, keys)

    # ---- persist to graph + evidence
    if case_id is not None:
        assessment["evidence"] = _persist(case_id, identifiers, profiles, corr, user)
        db.audit(user, "attribution.build", ",".join(identifiers)[:120],
                 f"confidence={corr['overall_confidence']}")

    return assessment


def _correlate(identifiers, profiles, seen_platforms):
    """Compute cross-identifier linkage signals + a confidence score."""
    signals = []
    score = 0

    # 1. identical / overlapping usernames across identifiers
    if len(identifiers) > 1:
        norm = [i.lower() for i in identifiers]
        if len(set(norm)) < len(norm):
            signals.append({"signal": "identical_username",
                            "weight": CORRELATION_SIGNALS["identical_username"],
                            "note": "duplicate identifiers supplied"})
            score += CORRELATION_SIGNALS["identical_username"]
        # substring containment (e.g. handle appears inside an email local-part)
        for a in norm:
            for b in norm:
                if a != b and len(a) > 4 and a in b:
                    signals.append({"signal": "identical_username",
                                    "weight": CORRELATION_SIGNALS["identical_username"] // 2,
                                    "note": f"'{a}' appears inside '{b}'"})
                    score += CORRELATION_SIGNALS["identical_username"] // 2

    # 2. shared platforms / same namespace
    platform_union = {}
    for ident, plats in seen_platforms.items():
        for p in plats:
            platform_union.setdefault(p, []).append(ident)
    shared = {p: ids for p, ids in platform_union.items() if len(ids) > 1}
    if shared:
        signals.append({"signal": "same_platform_namespace", "weight":
                        CORRELATION_SIGNALS["same_platform_namespace"],
                        "note": f"handles co-registered on: {', '.join(list(shared)[:5])}"})
        score += CORRELATION_SIGNALS["same_platform_namespace"]

    # 3. breach co-occurrence for emails
    breach_sets = []
    for p in profiles:
        br = (p.get("email_intel") or {}).get("breaches", {}).get("xposedornot", {})
        if isinstance(br, dict) and br.get("Success") == "true":
            breach_sets.append(set(br.get("breaches", [])))
    if len(breach_sets) > 1:
        common = set.intersection(*breach_sets)
        if common:
            signals.append({"signal": "breach_cooccurrence", "weight":
                            CORRELATION_SIGNALS["breach_cooccurrence"],
                            "note": f"shared breaches: {', '.join(list(common)[:5])}"})
            score += CORRELATION_SIGNALS["breach_cooccurrence"]

    overall = min(score, 100)
    band = ("high" if overall >= 60 else "moderate" if overall >= 30
            else "low" if overall > 0 else "insufficient")
    return {"signals": signals, "score": overall,
            "overall_confidence": band, "shared_platforms": shared}


def _ai_assess(assessment, keys):
    """Produce a structured actor narrative via Gemini/Groq (optional)."""
    import json
    prompt = (
        "You are a CERT threat-actor attribution analyst. Based ONLY on the public "
        "OSINT summary below, describe the likely actor profile: operating pattern, "
        "possible region/timezone hints from platform mix, and how confidently the "
        "identifiers link to one actor. Be factual, note uncertainty, never invent "
        "identities. Return 3-5 short paragraphs.\n\nOSINT SUMMARY:\n"
        + json.dumps({"identifiers": assessment["identifiers"],
                      "correlations": assessment["correlations"],
                      "platforms": {p["identifier"]: [x["platform"] for x in p.get("profiles", [])]
                                    for p in assessment["profiles"]}},
                     ensure_ascii=False)[:6000]
    )
    if keys.get("GEMINI_API_KEY"):
        return _call_gemini(prompt, keys["GEMINI_API_KEY"])
    if keys.get("GROQ_API_KEY"):
        return _call_groq(prompt, keys["GROQ_API_KEY"])
    return None


def _call_gemini(prompt, key):
    import requests
    try:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"gemini-1.5-flash:generateContent?key={key}")
        r = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=30)
        j = r.json()
        return j["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return {"error": str(e)[:200]}


def _call_groq(prompt, key):
    import requests
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={"model": "llama-3.3-70b-versatile",
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return {"error": str(e)[:200]}


def _persist(case_id, identifiers, profiles, corr, user):
    """Write every identifier as an entity, link them, store evidence."""
    ids = []
    for ident in identifiers:
        ids.append(_upsert(case_id, _detect(ident), ident))
    # fully-link the identifiers as "same_actor" edges (weight from confidence)
    w = max(corr["overall_confidence"] and corr["score"] / 100.0 or 0.1, 0.1)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            _edge(case_id, ids[i], ids[j], "likely_same_actor", w, "attribution")
    # profiles -> root
    for p in profiles:
        for prof in p.get("profiles", []):
            if prof.get("url"):
                pid = _upsert(case_id, "handle", prof["url"])
                _edge(case_id, ids[0], pid, "profile_on", 0.8, prof.get("platform", ""))
    return db.store_artifact(case_id, ids[0], "attribution",
                             "attribution:profile",
                             {"identifiers": identifiers, "correlations": corr},
                             user)


def _detect(v):
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return "email"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return "ip"
    if re.match(r'^\+?\d[\d\s().-]{7,}$', v):
        return "phone"
    if re.match(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', v, re.I):
        return "domain"
    return "username"


def _upsert(case_id, etype, value):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, etype, value, now, now))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, value)).fetchone()
    return row["id"]


def _edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()))
    c.commit()
