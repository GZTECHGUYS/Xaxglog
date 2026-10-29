"""Phase 4-7, 9: runtime, module packs, offline cache, security and performance."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import sqlite3
import sys
import time
from typing import Any

import config as C
import db as DB
from . import store

APP_VERSION = os.getenv("XAXGLOG_VERSION", "1.1.0")
PACK_DIR = os.path.join(C.DATA_DIR, "module_packs")
PLUGIN_DIR = os.path.join(C.DATA_DIR, "plugins")
SUPPORT_DIR = os.path.join(C.OUTPUT_DIR, "support")
PACK_SECRET_ENV = "XAXGLOG_PACK_SECRET"
REQUIRE_SIGNATURE_ENV = "XAXGLOG_REQUIRE_PACK_SIGNATURE"


def _semver(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(value or ""))
    return tuple(int(p) for p in parts[:4]) or (0,)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pack_path(name: str, version: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{name}-{version}")[:160]
    return os.path.join(PACK_DIR, safe + ".json")


def runtime_info() -> dict:
    return {
        "status": "ok",
        "app": "Xaxglog",
        "version": APP_VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "cwd": os.getcwd(),
        "data_dir": os.path.abspath(C.DATA_DIR),
        "db_path": os.path.abspath(C.DB_PATH),
        "sqlite": sqlite3.sqlite_version,
        "fts5": _fts5_available(),
        "offline": offline_status().get("offline", False),
        "pack_dir": os.path.abspath(PACK_DIR),
        "plugin_dir": os.path.abspath(PLUGIN_DIR),
        "budgets": {
            "cold_start_ms": int(os.getenv("XAXGLOG_BUDGET_COLD_START_MS", "2500")),
            "health_ms": int(os.getenv("XAXGLOG_BUDGET_HEALTH_MS", "250")),
            "query_ms": int(os.getenv("XAXGLOG_BUDGET_QUERY_MS", "1500")),
            "installer_mb": int(os.getenv("XAXGLOG_BUDGET_INSTALLER_MB", "120")),
        },
        "build_targets": ["windows-portable-exe", "windows-installer", "linux-deb", "appimage-optional"],
    }


def _fts5_available() -> bool:
    try:
        c = DB.get_db()
        c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x)")
        c.execute("DROP TABLE IF EXISTS _fts_probe")
        return True
    except Exception:
        return False


def self_test() -> dict:
    checks = []

    def add(name: str, ok: bool, detail: str = "", level: str = "error") -> None:
        checks.append({"name": name, "ok": bool(ok), "level": level, "detail": detail})

    try:
        stats = store.stats()
        add("sqlite", True, f"entities={stats['entities']} artifacts={stats['artifacts']}")
    except Exception as exc:
        add("sqlite", False, str(exc))
    add("fts5", _fts5_available(), "full-text index available" if _fts5_available() else "FTS5 unavailable; LIKE fallback")
    try:
        from modules.module_registry import registry
        summary = registry.summary()
        add("module_registry", bool(summary.get("total")),
            f"{summary.get('total')} declared / {summary.get('automatic')} automatic")
    except Exception as exc:
        add("module_registry", False, str(exc))
    try:
        from modules.source_registry import source_registry
        summary = source_registry.summary()
        add("source_registry", bool(summary.get("total")), f"{summary.get('total')} sources")
    except Exception as exc:
        add("source_registry", False, str(exc))
    try:
        import auth
        add("auth", bool(auth.jwt), "PyJWT available" if auth.jwt else "PyJWT missing; tokens cannot be issued")
    except Exception as exc:
        add("auth", False, str(exc))
    try:
        os.makedirs(PACK_DIR, exist_ok=True)
        probe = os.path.join(PACK_DIR, ".write-probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        add("pack_dir", True, PACK_DIR)
    except Exception as exc:
        add("pack_dir", False, str(exc))
    try:
        import cryptography  # noqa: F401
        add("cryptography", True, "optional TLS/key crypto available", level="warning")
    except Exception:
        add("cryptography", False, "optional; TLS parsing/key encryption degraded", level="warning")
    failed = [c for c in checks if not c["ok"] and c["level"] == "error"]
    warnings = [c for c in checks if not c["ok"] and c["level"] == "warning"]
    return {"status": "ok" if not failed else "degraded", "checks": checks,
            "failed": len(failed), "warnings": len(warnings), "version": APP_VERSION}


# --------------------------------------------------------------- module packs
def pack_manifest_schema() -> dict:
    return {
        "type": "object",
        "required": ["name", "version", "min_app", "modules"],
        "properties": {
            "name": "lowercase pack id",
            "version": "semver",
            "min_app": "minimum Xaxglog version",
            "max_app": "optional maximum version",
            "description": "human description",
            "modules": "list of declarative module specs (id, label, category, probe_type, url/search, status)",
            "sources": "optional list of source ids",
            "publisher": "optional publisher id",
        },
        "signature": "HMAC-SHA256 over canonical manifest when XAXGLOG_PACK_SECRET is configured",
    }


def validate_pack(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        return {"valid": False, "errors": ["manifest must be an object"]}
    errors = []
    name = str(manifest.get("name") or "").strip()
    version = str(manifest.get("version") or "").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}", name):
        errors.append("name must be 2-64 chars: lowercase letters, digits, _ . -")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
        errors.append("version must be semver (e.g. 1.2.0)")
    min_app = str(manifest.get("min_app") or "").strip()
    if not min_app:
        errors.append("min_app required")
    elif _semver(min_app) > _semver(APP_VERSION):
        errors.append(f"pack requires app >= {min_app}; running {APP_VERSION}")
    max_app = manifest.get("max_app")
    if max_app and _semver(APP_VERSION) > _semver(max_app):
        errors.append(f"pack supports app <= {max_app}; running {APP_VERSION}")
    modules = manifest.get("modules")
    if not isinstance(modules, list) or not modules:
        errors.append("modules must be a non-empty list")
    else:
        seen = set()
        for i, mod in enumerate(modules):
            if not isinstance(mod, dict):
                errors.append(f"modules[{i}] must be an object")
                continue
            mid = str(mod.get("id") or "").strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}", mid):
                errors.append(f"modules[{i}].id invalid")
            if mid in seen:
                errors.append(f"modules[{i}].id duplicated: {mid}")
            seen.add(mid)
            if not mod.get("label"):
                errors.append(f"modules[{i}].label required")
            ptype = mod.get("probe_type", "link_out")
            if ptype not in ("json_api_probe", "http_profile_probe", "html_search_probe",
                             "oembed_probe", "adapter_probe", "link_out"):
                errors.append(f"modules[{i}].probe_type invalid: {ptype}")
            if ptype != "adapter_probe" and not (mod.get("url") or mod.get("search")):
                errors.append(f"modules[{i}] needs url or search")
    return {"valid": not errors, "errors": errors,
            "manifest": manifest, "sha256": _pack_digest(manifest)}


def _pack_digest(manifest: dict) -> str:
    return hashlib.sha256(_canonical(manifest).encode("utf-8")).hexdigest()


def pack_signature(manifest: dict, secret: str | None = None) -> str:
    secret = secret if secret is not None else os.getenv(PACK_SECRET_ENV, "")
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), _pack_digest(manifest).encode("ascii"),
                    hashlib.sha256).hexdigest()


def install_pack(manifest: dict, signature: str = "", secret: str | None = None,
                 enabled: bool = True) -> dict:
    check = validate_pack(manifest)
    if not check["valid"]:
        return {"status": "rejected", "errors": check["errors"]}
    secret = secret if secret is not None else os.getenv(PACK_SECRET_ENV, "")
    signed = False
    if secret:
        expected = pack_signature(manifest, secret)
        if not hmac.compare_digest(expected, signature or ""):
            return {"status": "rejected", "errors": ["signature mismatch"]}
        signed = True
    elif signature:
        return {"status": "rejected", "errors": ["signature supplied but no pack secret configured"]}
    elif os.getenv(REQUIRE_SIGNATURE_ENV, "0").lower() in ("1", "true", "yes", "on"):
        return {"status": "rejected", "errors": ["signed packs required; set XAXGLOG_PACK_SECRET"]}
    os.makedirs(PACK_DIR, exist_ok=True)
    path = _pack_path(manifest["name"], manifest["version"])
    payload = {"manifest": manifest, "sha256": check["sha256"],
               "signature": signature, "signed": signed,
               "enabled": bool(enabled)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    record = store.pack_upsert(manifest, check["sha256"], signature, signed, enabled)
    try:
        from modules.module_registry import registry
        registry.reload()
    except Exception:
        pass
    return {"status": "installed", "signed": signed, "path": path, **record,
            "manifest": manifest}


def pack_list() -> dict:
    return {"status": "ok", "packs": store.pack_list(), "pack_dir": PACK_DIR,
            "signed_required": os.getenv(REQUIRE_SIGNATURE_ENV, "0").lower() in ("1", "true", "yes", "on")}


def set_pack_enabled(name: str, version: str, enabled: bool) -> dict:
    """Persist the enabled flag in both SQLite and the pack file.

    The registry reads pack files (not the platform DB), so the file must carry
    the flag; otherwise a disabled pack would still contribute modules after a
    restart.
    """
    store.pack_set_enabled(name, version, enabled)
    path = _pack_path(name, version)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
            payload["enabled"] = bool(enabled)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
        except Exception:
            pass
    try:
        from modules.module_registry import registry
        registry.reload()
    except Exception:
        pass
    return {"name": name, "version": version, "enabled": bool(enabled)}


def rollback_pack(name: str, to_version: str | None = None) -> dict:
    packs = [p for p in store.pack_list() if p.get("name") == name]
    if not packs:
        return {"status": "error", "error": "pack not found"}
    packs.sort(key=lambda p: _semver(p.get("version")), reverse=True)
    target = next((p for p in packs if p.get("version") == to_version), None) if to_version else (
        packs[1] if len(packs) > 1 else None)
    if not target:
        return {"status": "error", "error": "no previous version to roll back to"}
    for p in packs:
        set_pack_enabled(p["name"], p["version"], p["version"] == target["version"])
    return {"status": "ok", "active": target["version"], "name": name,
            "packs": store.pack_list()}


# ------------------------------------------------------------------- offline
def _env_offline() -> bool:
    return os.getenv("XAXGLOG_OFFLINE", "0").lower() in ("1", "true", "yes", "on")


def offline_status() -> dict:
    setting = store.setting_get("offline_mode", None)
    offline = _env_offline() if setting is None else bool(setting)
    return {"status": "ok", "offline": offline, "source": "env" if setting is None else "setting",
            "cache_entries": store.cache_count(),
            "note": "Offline mode disables live probes; only cached metadata and link-outs are returned."}


def set_offline(enabled: bool) -> dict:
    store.setting_set("offline_mode", bool(enabled))
    return offline_status()


def warm_cache() -> dict:
    written = []
    try:
        from modules.module_registry import registry
        store.cache_set("module_registry_summary", registry.summary())
        written.append("module_registry_summary")
    except Exception:
        pass
    try:
        from modules.source_registry import source_registry
        store.cache_set("source_registry_summary", source_registry.summary())
        written.append("source_registry_summary")
    except Exception:
        pass
    try:
        from modules.deep_search import social
        store.cache_set("social_coverage", social.name_search_coverage())
        written.append("social_coverage")
    except Exception:
        pass
    from . import core
    store.cache_set("phase_catalog", core.phase_catalog())
    written.append("phase_catalog")
    return {"status": "ok", "written": written, "cache_entries": store.cache_count()}


# ------------------------------------------------------------------ security
def ssrf_check(url: str) -> dict:
    try:
        from modules.module_registry.probes import _safe_url
        ok, reason = _safe_url((url or "").strip())
        return {"status": "ok", "allowed": bool(ok), "reason": reason, "url": url}
    except Exception as exc:
        return {"status": "error", "allowed": False, "reason": str(exc)[:200], "url": url}


def security_posture() -> dict:
    checks = []

    def add(name, ok, detail, severity="warning"):
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "severity": severity})

    add("flask_secret", C.FLASK_SECRET_KEY not in ("", "xaxglog-dev-change-me"),
        "FLASK_SECRET_KEY is custom" if C.FLASK_SECRET_KEY not in ("", "xaxglog-dev-change-me")
        else "default dev secret; set FLASK_SECRET_KEY", "high")
    add("admin_password", bool(os.getenv("XAXGLOG_ADMIN_PASSWORD")),
        "XAXGLOG_ADMIN_PASSWORD set" if os.getenv("XAXGLOG_ADMIN_PASSWORD")
        else "default bootstrap password may be active; set XAXGLOG_ADMIN_PASSWORD", "high")
    add("pack_signing", bool(os.getenv(PACK_SECRET_ENV)),
        "module pack signing secret configured" if os.getenv(PACK_SECRET_ENV)
        else "XAXGLOG_PACK_SECRET not set; unsigned packs allowed", "medium")
    add("signed_packs_required", os.getenv(REQUIRE_SIGNATURE_ENV, "0").lower() in ("1", "true", "yes", "on"),
        "signed pack enforcement enabled" if os.getenv(REQUIRE_SIGNATURE_ENV, "0").lower() in ("1", "true", "yes", "on")
        else "unsigned packs are accepted unless the secret is configured", "medium")
    add("offline_mode", not offline_status()["offline"], "live probes enabled" if not offline_status()["offline"] else "air-gapped mode", "info")
    try:
        import auth
        add("jwt", bool(auth.jwt), "PyJWT available" if auth.jwt else "PyJWT missing", "high")
    except Exception as exc:
        add("jwt", False, str(exc), "high")
    try:
        import cryptography  # noqa: F401
        add("cryptography", True, "crypto available", "info")
    except Exception:
        add("cryptography", False, "optional crypto package absent", "low")
    try:
        from modules.module_registry.probes import _safe_url
        add("ssrf_guard", True, "shared URL guard available", "high")
    except Exception as exc:
        add("ssrf_guard", False, str(exc), "high")
    high = [c for c in checks if not c["ok"] and c["severity"] == "high"]
    return {"status": "ok" if not high else "attention", "checks": checks,
            "high_risk": len(high), "offline": offline_status()["offline"],
            "note": "This is a posture report, not a penetration test."}


def audit_tail(limit: int = 200) -> dict:
    c = DB.get_db()
    try:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit or 200), 2000)),),
        ).fetchall()]
    except Exception:
        rows = []
    return {"status": "ok", "count": len(rows), "events": rows}


# --------------------------------------------------------------- performance
def performance() -> dict:
    t0 = time.perf_counter()
    stats = store.stats()
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    size = os.path.getsize(C.DB_PATH) if os.path.exists(C.DB_PATH) else 0
    budgets = runtime_info()["budgets"]
    return {
        "status": "ok",
        "db_size_bytes": size,
        "db_size_mb": round(size / (1024 * 1024), 2),
        "stats": stats,
        "stats_ms": elapsed,
        "fts5": _fts5_available(),
        "budgets": budgets,
        "budget_ok": elapsed <= budgets["query_ms"],
        "release_targets": ["pyinstaller one-folder", "nuitka one-folder", "deb", "appimage"],
        "note": "One-folder builds are preferred over one-file for cold-start and AV false-positive reasons.",
    }


def benchmark(iterations: int = 20) -> dict:
    n = max(1, min(int(iterations or 20), 500))
    c = DB.get_db()
    t0 = time.perf_counter()
    for _ in range(n):
        c.execute("SELECT COUNT(*) FROM entities").fetchone()
        c.execute("SELECT COUNT(*) FROM artifacts").fetchone()
        c.execute("SELECT COUNT(*) FROM timeline_events").fetchone()
    ms = round((time.perf_counter() - t0) * 1000, 2)
    return {"status": "ok", "iterations": n, "total_ms": ms,
            "per_iteration_ms": round(ms / n, 3),
            "budget_ms": runtime_info()["budgets"]["query_ms"],
            "budget_ok": (ms / n) <= runtime_info()["budgets"]["query_ms"]}


def ensure_dirs() -> None:
    for path in (PACK_DIR, PLUGIN_DIR, SUPPORT_DIR):
        os.makedirs(path, exist_ok=True)
