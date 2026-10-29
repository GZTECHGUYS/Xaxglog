"""Phase 10-12: plugin SDK, compliance/governance and observability/support."""
from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from typing import Any

import config as C
import db as DB
from . import core, ops, store

PLUGIN_KINDS = ("source", "probe", "link_out", "ui_panel", "report")


# ------------------------------------------------------------------- plugins
def plugin_schema() -> dict:
    return {
        "type": "object",
        "required": ["name", "version", "kind"],
        "properties": {
            "name": "lowercase plugin id",
            "version": "semver",
            "kind": "source | probe | link_out | ui_panel | report",
            "label": "display name",
            "description": "what it does",
            "author": "publisher",
            "min_app": "minimum Xaxglog version",
            "url": "public URL or template",
            "search": "optional search template",
            "probe_type": "json_api_probe | http_profile_probe | html_search_probe | oembed_probe | link_out",
            "permissions": "list of declarative permissions (network, case_read, case_write)",
            "entrypoint": "optional display entrypoint; never executed by the server",
        },
        "security": "Plugins are declarative data. The server never imports or executes plugin code.",
    }


def validate_plugin(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        return {"valid": False, "errors": ["manifest must be an object"]}
    errors = []
    name = str(manifest.get("name") or "").strip()
    version = str(manifest.get("version") or "").strip()
    kind = str(manifest.get("kind") or "source").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}", name):
        errors.append("name must be 2-64 chars: lowercase letters, digits, _ . -")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        errors.append("version must be semver")
    if kind not in PLUGIN_KINDS:
        errors.append(f"kind must be one of {', '.join(PLUGIN_KINDS)}")
    ptype = manifest.get("probe_type", "link_out")
    if ptype not in ("json_api_probe", "http_profile_probe", "html_search_probe",
                     "oembed_probe", "link_out"):
        errors.append("probe_type invalid")
    if ptype != "link_out" and not (manifest.get("url") or manifest.get("search")):
        errors.append("url or search required for a probe plugin")
    perms = manifest.get("permissions") or []
    if not isinstance(perms, list):
        errors.append("permissions must be a list")
    else:
        bad = [p for p in perms if p not in ("network", "case_read", "case_write", "link_out")]
        if bad:
            errors.append("unknown permissions: " + ", ".join(map(str, bad)))
    if manifest.get("entrypoint"):
        errors.append("entrypoint is display-only; executable plugins are not supported")
    return {"valid": not errors, "errors": errors, "manifest": manifest,
            "note": "Declarative plugin; no server-side code execution."}


def install_plugin(manifest: dict, enabled: bool = True) -> dict:
    check = validate_plugin(manifest)
    if not check["valid"]:
        return {"status": "rejected", "errors": check["errors"]}
    os.makedirs(ops.PLUGIN_DIR, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{manifest['name']}-{manifest['version']}")[:160]
    path = os.path.join(ops.PLUGIN_DIR, safe + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    record = store.plugin_upsert(manifest, enabled)
    return {"status": "installed", "path": path, **record}


def list_plugins() -> dict:
    return {"status": "ok", "plugins": store.plugin_list(),
            "plugin_dir": ops.PLUGIN_DIR, "schema": plugin_schema()}


def toggle_plugin(name: str, version: str, enabled: bool) -> dict:
    return {"status": "ok", "plugin": store.plugin_set_enabled(name, version, enabled)}


# ----------------------------------------------------------------- compliance
def policy() -> dict:
    return {
        "status": "ok",
        "public_sources_only": True,
        "prohibited": [
            "login-wall bypass", "captcha solving", "private databases",
            "paywalled law-enforcement data", "unauthorized device access",
            "doxxing or covert tracking",
        ],
        "evidence_rule": "Only verified/fragile sources are automatic evidence; name/profile matches are leads, not identity proof.",
        "retention_days": int(os.getenv("XAXGLOG_RETENTION_DAYS", "365")),
        "lawful_basis_required": True,
        "dsar_workflow": "plan -> verify -> export/delete -> record",
        "audit": "append-only audit_log with user, action, target, IP",
        "redaction": "support bundles exclude secrets and private keys",
    }


def retention_preview(days: int | None = None) -> dict:
    days = max(1, int(days or os.getenv("XAXGLOG_RETENTION_DAYS", "365")))
    cutoff = f"-{days} days"
    c = DB.get_db()
    counts = {}
    for table, col in (("artifacts", "queried_at"), ("timeline_events", "created_at"),
                       ("provenance", "retrieved_at"), ("comments", "created_at")):
        try:
            row = c.execute(
                f"SELECT COUNT(*) c FROM {table} WHERE {col} < datetime('now', ?)",
                (cutoff,),
            ).fetchone()
            counts[table] = int(row["c"] if row else 0)
        except Exception:
            counts[table] = 0
    return {"status": "ok", "days": days, "counts": counts,
            "total": sum(counts.values()), "dry_run": True,
            "note": "Preview only. Run with dry_run=false as an admin to delete."}


def retention_run(days: int | None = None, dry_run: bool = True,
                  username: str = "system") -> dict:
    days = max(1, int(days or os.getenv("XAXGLOG_RETENTION_DAYS", "365")))
    preview = retention_preview(days)
    if dry_run:
        return {**preview, "recorded": store.retention_record(f"days={days}", True, 0, preview)}
    cutoff = f"-{days} days"
    c = DB.get_db()
    deleted = {}
    for table, col in (("timeline_events", "created_at"), ("provenance", "retrieved_at"),
                       ("comments", "created_at"), ("artifacts", "queried_at")):
        try:
            cur = c.execute(f"DELETE FROM {table} WHERE {col} < datetime('now', ?)", (cutoff,))
            deleted[table] = cur.rowcount if cur.rowcount is not None else 0
        except Exception:
            deleted[table] = 0
    c.commit()
    rec = store.retention_record(f"days={days}", False, sum(deleted.values()), deleted)
    DB.audit(username, "compliance.retention", f"days={days}", json.dumps(deleted))
    return {"status": "ok", "days": days, "deleted": deleted, "total": sum(deleted.values()),
            "record": rec, "dry_run": False}


def case_export(case_id: Any = 0) -> dict:
    out = core.export_case(case_id)
    DB.audit("system", "compliance.export", str(case_id), out.get("sha256", ""))
    return out


def dsar_plan(subject: str) -> dict:
    subject = (subject or "").strip()
    if not subject:
        return {"status": "error", "error": "subject required"}
    return {
        "status": "ok",
        "subject": subject,
        "steps": [
            "Confirm the requester's identity and lawful basis.",
            "Search cases, graph entities, timeline and provenance for the subject.",
            "Classify public-source leads vs. case evidence; do not delete audit records.",
            "Export the subject's data with SHA-256 hashes.",
            "Apply deletion/rectification where legally required and record the decision.",
            "Notify the requester and close the DSAR within the statutory deadline.",
        ],
        "legal_note": "This workflow is a checklist, not legal advice. Follow GDPR/CCPA/local law.",
    }


# ---------------------------------------------------------------- observability
def health() -> dict:
    test = ops.self_test()
    disk = shutil.disk_usage(C.DATA_DIR)
    return {
        "status": "ok" if test["status"] == "ok" else "degraded",
        "version": ops.APP_VERSION,
        "phases": core.phase_catalog()["count"],
        "checks": test["checks"],
        "failed": test["failed"],
        "warnings": test["warnings"],
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free,
                 "free_pct": round(disk.free / disk.total * 100, 1) if disk.total else None},
        "time": DB.utcnow(),
    }


def metrics() -> str:
    stats = store.stats()
    lines = [
        "# HELP xaxglog_entities Total graph entities",
        "# TYPE xaxglog_entities gauge",
        f"xaxglog_entities {stats['entities']}",
        "# HELP xaxglog_artifacts Total evidence artifacts",
        "# TYPE xaxglog_artifacts gauge",
        f"xaxglog_artifacts {stats['artifacts']}",
        "# HELP xaxglog_timeline_events Total timeline events",
        "# TYPE xaxglog_timeline_events gauge",
        f"xaxglog_timeline_events {stats['timeline_events']}",
        "# HELP xaxglog_workspaces Total workspaces",
        "# TYPE xaxglog_workspaces gauge",
        f"xaxglog_workspaces {stats['workspaces']}",
        "# HELP xaxglog_module_packs Installed module packs",
        "# TYPE xaxglog_module_packs gauge",
        f"xaxglog_module_packs {stats['module_packs']}",
        "# HELP xaxglog_plugins Installed plugins",
        "# TYPE xaxglog_plugins gauge",
        f"xaxglog_plugins {stats['plugins']}",
        "# HELP xaxglog_up Platform health (1=ok)",
        "# TYPE xaxglog_up gauge",
        f"xaxglog_up {1 if health().get('status') == 'ok' else 0}",
    ]
    return "\n".join(lines) + "\n"


def diagnostics() -> dict:
    return {
        "status": "ok",
        "generated_at": DB.utcnow(),
        "runtime": ops.runtime_info(),
        "self_test": ops.self_test(),
        "security": ops.security_posture(),
        "performance": ops.performance(),
        "phases": core.phase_catalog(),
        "stats": store.stats(),
        "recent_audit": ops.audit_tail(100),
    }


def support_bundle(username: str = "system") -> dict:
    os.makedirs(ops.SUPPORT_DIR, exist_ok=True)
    stamp = DB.utcnow().replace(":", "").replace("-", "")[:15]
    name = f"xaxglog-support-{stamp}.zip"
    path = os.path.join(ops.SUPPORT_DIR, name)
    diag = diagnostics()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("diagnostics.json", json.dumps(diag, indent=2, sort_keys=True, default=str))
        zf.writestr("README.txt", (
            "Xaxglog support bundle\n"
            "This bundle contains runtime diagnostics, phase status, source/module counts,\n"
            "and the recent audit tail. Secrets, operator keys, password hashes and raw\n"
            "case evidence are not included.\n"
        ))
    DB.audit(username, "support.bundle", name, f"{os.path.getsize(path)} bytes")
    return {"status": "ok", "name": name, "path": path,
            "size": os.path.getsize(path), "diagnostics": diag}
