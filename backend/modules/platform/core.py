"""Phase 1-3 intelligence core: graph, source health, social recon, analytics."""
from __future__ import annotations

import datetime
import json
import os
from typing import Any

import config as C
import db as DB
from . import store

PHASES = [
    {
        "id": 1,
        "key": "intelligence_core",
        "name": "Intelligence core & evidence graph",
        "status": "implemented",
        "capabilities": ["entity graph", "timeline", "provenance", "case-scoped evidence"],
        "endpoints": ["/api/platform/graph", "/api/platform/timeline", "/api/platform/provenance"],
        "acceptance": "Every entity/edge/artifact is case-scoped, hash-linked and queryable.",
    },
    {
        "id": 2,
        "key": "verified_coverage",
        "name": "Verified source coverage & regional expansion",
        "status": "implemented",
        "capabilities": ["source health", "honest status vocabulary", "region filters", "link-outs"],
        "endpoints": ["/api/platform/sources/health", "/api/module-registry/summary"],
        "acceptance": "Only verified/fragile sources count as automatic evidence; blocked/optional/link-out stay catalog-only.",
    },
    {
        "id": 3,
        "key": "human_recon",
        "name": "Social / human recon & analytics",
        "status": "implemented",
        "capabilities": ["name coverage", "public search links", "handle candidates", "case analytics"],
        "endpoints": ["/api/platform/social/coverage", "/api/platform/social/recon", "/api/platform/analytics"],
        "acceptance": "Direct APIs, public search link-outs and handle-only platforms are reported separately.",
    },
    {
        "id": 4,
        "key": "runtime",
        "name": "Packaging & lightweight runtime",
        "status": "implemented",
        "capabilities": ["runtime profile", "self-test", "PyInstaller/Nuitka build scripts", "deb/AppImage layout"],
        "endpoints": ["/api/platform/runtime", "/api/platform/runtime/self-test"],
        "acceptance": "The app boots from a one-folder build with SQLite/FTS5 and no Docker.",
    },
    {
        "id": 5,
        "key": "module_packs",
        "name": "Module packs & signed updates",
        "status": "implemented",
        "capabilities": ["manifest validation", "SHA-256", "HMAC signatures", "enable/disable", "rollback"],
        "endpoints": ["/api/platform/packs", "/api/platform/packs/install", "/api/platform/packs/rollback"],
        "acceptance": "Unsigned/tampered packs are rejected; installs are versioned and reversible.",
    },
    {
        "id": 6,
        "key": "offline",
        "name": "Offline / air-gapped mode",
        "status": "implemented",
        "capabilities": ["offline switch", "metadata cache", "cache warm", "link-out only"],
        "endpoints": ["/api/platform/offline", "/api/platform/cache/warm"],
        "acceptance": "Offline mode never makes live requests and reports cached vs live data.",
    },
    {
        "id": 7,
        "key": "security",
        "name": "Security & trust hardening",
        "status": "implemented",
        "capabilities": ["SSRF check", "posture report", "audit trail", "secret checks", "RBAC"],
        "endpoints": ["/api/platform/security/posture", "/api/platform/security/ssrf-check", "/api/platform/audit"],
        "acceptance": "Private/loopback targets are rejected; high-risk defaults are visible.",
    },
    {
        "id": 8,
        "key": "collaboration",
        "name": "Team / collaboration server",
        "status": "implemented",
        "capabilities": ["workspaces", "members", "comments", "assignments", "case links"],
        "endpoints": ["/api/platform/workspaces", "/api/platform/comments", "/api/platform/assignments"],
        "acceptance": "Analysts share case context without duplicating evidence.",
    },
    {
        "id": 9,
        "key": "performance",
        "name": "Performance & release engineering",
        "status": "implemented",
        "capabilities": ["latency budgets", "DB/FTS benchmark", "build matrix", "reproducible flags"],
        "endpoints": ["/api/platform/performance", "/api/platform/performance/benchmark"],
        "acceptance": "Cold-start and query budgets are measured; CI produces Windows/Linux artifacts.",
    },
    {
        "id": 10,
        "key": "plugin_sdk",
        "name": "Plugin SDK & ecosystem",
        "status": "implemented",
        "capabilities": ["declarative manifests", "validation", "registry", "enable/disable", "example SDK"],
        "endpoints": ["/api/platform/plugins", "/api/platform/plugins/validate"],
        "acceptance": "Third-party sources are data, not arbitrary code; manifests are validated before install.",
    },
    {
        "id": 11,
        "key": "compliance",
        "name": "Compliance & governance",
        "status": "implemented",
        "capabilities": ["lawful-basis policy", "retention preview/run", "case export", "DSAR plan"],
        "endpoints": ["/api/platform/compliance/policy", "/api/platform/compliance/retention", "/api/platform/compliance/export"],
        "acceptance": "Retention is dry-run first, exports are hashed and DSAR requests get a documented plan.",
    },
    {
        "id": 12,
        "key": "observability",
        "name": "Observability & support",
        "status": "implemented",
        "capabilities": ["health", "Prometheus metrics", "diagnostics", "redacted support bundle"],
        "endpoints": ["/api/platform/health", "/api/platform/metrics", "/api/platform/support/bundle"],
        "acceptance": "Operators can diagnose a build without exposing secrets or personal data.",
    },
]


def phase_catalog() -> dict:
    return {
        "count": len(PHASES),
        "phases": PHASES,
        "status": "ok",
        "note": "Implemented capabilities are real endpoints; source counts remain registry-derived and are not padded.",
    }


def _module_summary() -> dict:
    try:
        from modules.module_registry import registry
        return registry.summary()
    except Exception as exc:
        return {"status": "error", "error": str(exc)[:200]}


def _source_summary() -> dict:
    try:
        from modules.source_registry import source_registry
        return source_registry.summary()
    except Exception as exc:
        return {"status": "error", "error": str(exc)[:200]}


def _social():
    from modules.deep_search import social
    return social


def social_coverage() -> dict:
    cov = _social().name_search_coverage()
    return {
        "status": "ok",
        "coverage": cov,
        "note": cov.get("note", ""),
        "automatic_evidence_rule": "Only direct API rows count; public search links are analyst-opened leads.",
    }


def social_recon(name: str, *, probe: bool = False, variants: bool = True,
                 case_id: Any = 0, user: str = "system") -> dict:
    social = _social()
    name = (name or "").strip()
    if len(name) < 2:
        return {"status": "error", "error": "name must be at least 2 characters"}
    cov = social.name_search_coverage()
    links = social.name_search_links(name)
    handles = social.handle_candidates(name)
    out = {
        "status": "ok",
        "input": name,
        "probe": bool(probe),
        "coverage": cov,
        "search_links": links,
        "handle_candidates": handles,
        "automatic_evidence": False,
        "note": "Name/profile matches are leads, not identity proof.",
    }
    if not probe:
        out["results"] = {
            "status": "not_run",
            "reason": "probe=false; no network request was made",
            "direct_api_platforms": cov.get("handle_matrix_name_searchable", []),
        }
        return out

    result = social.name_registry_search(name, variants=variants)
    out["results"] = result
    out["automatic_evidence"] = bool(result.get("total"))
    # Record one provenance row per direct source that returned rows.  Search
    # links are deliberately not recorded as evidence because they were not
    # fetched and may sit behind a wall.
    for source, rows in (result.get("sources") or {}).items():
        if not rows:
            continue
        store.add_provenance(
            case_id,
            source="social:" + source,
            url="",
            access_mode="api",
            status="fragile",
            sha256=DB.hash_content(json.dumps(rows, sort_keys=True, default=str)),
            meta={"query": name, "rows": len(rows), "probe": "name_registry_search"},
        )
    store.add_timeline(
        case_id, None, "social_recon",
        f"Social/name recon: {name}",
        detail=f"{result.get('total', 0)} rows across {len(result.get('sources') or {})} direct sources",
        source="platform.social_recon",
        content={"query": name, "total": result.get("total")},
    )
    return out


def source_health() -> dict:
    summary = _module_summary()
    statuses = summary.get("by_status") or {}
    automatic = summary.get("automatic") or 0
    return {
        "status": "ok" if summary.get("status") != "error" else "error",
        "module_registry": summary,
        "source_registry": _source_summary(),
        "automatic_evidence_count": automatic,
        "automatic_evidence_rule": "verified + fragile only",
        "status_counts": statuses,
        "note": "Blocked, optional-key, candidate, adapter and link-out entries are catalog/diagnostic only.",
    }


def analytics() -> dict:
    stats = store.stats()
    cov = _social().name_search_coverage()
    module = _module_summary()
    source = _source_summary()
    c = DB.get_db()
    try:
        recent = [dict(r) for r in c.execute(
            "SELECT kind, COUNT(*) c FROM timeline_events"
            " WHERE created_at >= datetime('now','-30 days') GROUP BY kind ORDER BY c DESC"
        ).fetchall()]
    except Exception:
        recent = []
    return {
        "status": "ok",
        "generated_at": DB.utcnow(),
        "graph": stats,
        "timeline_activity_30d": recent,
        "social_coverage": {
            "total_platforms": cov.get("total_platforms"),
            "direct_name_apis": cov.get("direct_name_apis"),
            "public_search_link_out": cov.get("public_search_link_out_count"),
            "handle_only": cov.get("handle_only_count"),
        },
        "modules": {
            "declared": module.get("total") or module.get("declared"),
            "verified": module.get("verified"),
            "fragile": module.get("fragile"),
            "automatic": module.get("automatic"),
            "link_out": module.get("link_out"),
            "blocked": module.get("blocked"),
        },
        "sources": source,
    }


def graph_bundle(case_id: Any = 0) -> dict:
    return {
        "status": "ok",
        "graph": store.graph(case_id),
        "timeline": store.timeline(case_id, 500),
        "provenance": store.provenance(case_id, 500),
    }


def export_case(case_id: Any = 0) -> dict:
    graph = store.graph(case_id, 5000)
    timeline = store.timeline(case_id, 5000)
    prov = store.provenance(case_id, 5000)
    return {
        "status": "ok",
        "exported_at": DB.utcnow(),
        "case_id": int(case_id or 0),
        "graph": graph,
        "timeline": timeline,
        "provenance": prov,
        "sha256": DB.hash_content(json.dumps(
            {"graph": graph, "timeline": timeline, "provenance": prov},
            sort_keys=True, default=str)),
        "note": "Hashes are computed over the exported JSON; verify before transfer.",
    }
