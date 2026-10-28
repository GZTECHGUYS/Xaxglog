"""Route group P8: declarative module registry + legacy dashboard compatibility.

The module registry is the scalable path for source coverage: one declarative
``ModuleSpec`` per public source, generic probes (JSON API, profile page, search
page, oEmbed, existing adapter, link-out) and a verification overlay.  It does
not add one Python file per website and it never counts a link-out, blocked,
optional-key or unverified source as an automatic hit.

This group also wires the legacy React endpoints that were present in the
donor tree but missing from the unified app.
"""
from __future__ import annotations

from flask import jsonify, request


def _bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("0", "false", "no", "off", "")
    return bool(value)


def _int(value, default, lo=None, hi=None):
    try:
        out = int(value)
    except (TypeError, ValueError):
        out = default
    if lo is not None:
        out = max(lo, out)
    if hi is not None:
        out = min(hi, out)
    return out


def _csv(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    MR = _mod("modules.module_registry", "module_registry", CAPS)
    OC = _mod("modules.operator_compat.operator_compat", "operator_compat", CAPS)

    # ------------------------------------------------------ registry catalog
    @app.get("/api/module-registry/summary")
    def module_registry_summary():
        if MR is None:
            return unavailable("module_registry")
        return jsonify(MR.registry.summary())

    @app.get("/api/module-registry/types")
    def module_registry_types():
        if MR is None:
            return unavailable("module_registry")
        return jsonify({
            "probe_types": MR.registry.PROBE_LABELS,
            "statuses": list(MR.registry.STATUSES),
            "automatic_statuses": list(MR.registry.AUTOMATIC_STATUSES),
            "note": MR.registry.summary().get("note", ""),
        })

    @app.get("/api/module-registry/modules")
    def module_registry_modules():
        if MR is None:
            return unavailable("module_registry")
        include_probe = _bool(request.args.get("include_probe"), False)
        mods = MR.registry.select(
            q=request.args.get("q") or request.args.get("search"),
            types=_csv(request.args.get("types") or request.args.get("type")),
            categories=_csv(request.args.get("categories") or request.args.get("category")),
            statuses=_csv(request.args.get("statuses") or request.args.get("status")),
            access=_csv(request.args.get("access")),
            probe_types=_csv(request.args.get("probe_types") or request.args.get("probe_type")),
            region=request.args.get("region"),
            automatic=request.args.get("automatic"),
            limit=_int(request.args.get("limit"), 500, 1, 2000),
            offset=_int(request.args.get("offset"), 0, 0),
        )
        return jsonify({
            "count": len(mods),
            "modules": [MR.registry.public_module(m, include_probe=include_probe) for m in mods],
            "summary": MR.registry.summary(),
        })

    @app.get("/api/module-registry/modules/<module_id>")
    def module_registry_module(module_id):
        if MR is None:
            return unavailable("module_registry")
        mod = MR.registry.get(module_id)
        if not mod:
            return jsonify({"error": "module not found", "id": module_id}), 404
        return jsonify(MR.registry.public_module(mod, include_probe=True))

    @app.post("/api/module-registry/search")
    def module_registry_search():
        if MR is None:
            return unavailable("module_registry")
        d = request.get_json(silent=True) or {}
        q = d.get("query") or d.get("q") or ""
        out = MR.engine.search(
            q,
            types=_csv(d.get("types")),
            categories=_csv(d.get("categories")),
            statuses=_csv(d.get("statuses")),
            probe_types=_csv(d.get("probe_types")),
            region=d.get("region"),
            limit=_int(d.get("limit"), 40, 1, 120),
            timeout=_int(d.get("timeout"), 8, 2, 30),
            max_workers=_int(d.get("max_workers"), 8, 1, 16),
            include_link_out=_bool(d.get("include_link_out"), True),
            module_ids=_csv(d.get("ids") or d.get("modules")),
            include_unverified=_bool(d.get("include_unverified"), False),
        )
        return jsonify(out), (200 if out.get("status") != "error" else 400)

    @app.post("/api/module-registry/verify")
    @AUTH.require("analyst")
    def module_registry_verify():
        if MR is None:
            return unavailable("module_registry")
        d = request.get_json(silent=True) or {}
        out = MR.engine.verify(
            ids=_csv(d.get("ids")),
            query=d.get("query") or d.get("q") or "John Smith",
            checks=_int(d.get("checks"), 2, 1, 3),
            timeout=_int(d.get("timeout"), 8, 2, 30),
            max_workers=_int(d.get("max_workers"), 4, 1, 12),
            persist=_bool(d.get("persist"), True),
            limit=_int(d.get("limit"), 40, 1, 80),
        )
        return jsonify(out)

    @app.get("/api/module-registry/links")
    @app.post("/api/module-registry/links")
    def module_registry_links():
        if MR is None:
            return unavailable("module_registry")
        d = request.get_json(silent=True) or {}
        q = d.get("query") or d.get("q") or request.args.get("q") or ""
        out = MR.engine.build_links(
            q,
            types=_csv(d.get("types") or request.args.get("types")),
            categories=_csv(d.get("categories") or request.args.get("categories")),
            region=d.get("region") or request.args.get("region"),
            limit=_int(d.get("limit") or request.args.get("limit"), 100, 1, 300),
        )
        return jsonify({"query": q, "count": len(out), "links": out})

    # ------------------------------------------------------ compatibility
    @app.get("/api/lookup")
    def compat_lookup():
        if OC is None:
            return unavailable("operator_compat")
        value = request.args.get("value") or request.args.get("q") or ""
        return jsonify(OC.deep_lookup(value))

    @app.get("/api/keys")
    @AUTH.require("analyst")
    def compat_keys_list():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.key_status())

    @app.post("/api/keys")
    @AUTH.require("analyst")
    def compat_keys_save():
        if OC is None:
            return unavailable("operator_compat")
        d = request.get_json(silent=True) or {}
        try:
            OC.save_key(d.get("service"), d.get("key"))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"saved": True, "service": d.get("service")})

    @app.delete("/api/keys/<service>")
    @AUTH.require("analyst")
    def compat_keys_delete(service):
        if OC is None:
            return unavailable("operator_compat")
        OC.delete_key(service)
        return jsonify({"deleted": True, "service": service})

    @app.post("/api/validate-key")
    @AUTH.require("analyst")
    def compat_validate_key():
        if OC is None:
            return unavailable("operator_compat")
        d = request.get_json(silent=True) or {}
        out = OC.validate_key(d.get("service"), d.get("key"))
        return jsonify(out), (200 if out.get("valid") else 400)

    @app.get("/api/breach-lookup")
    @AUTH.require("viewer")
    def compat_breach_lookup():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.breach_lookup(request.args.get("email") or ""))

    @app.post("/api/ai-summary")
    @AUTH.require("viewer")
    def compat_ai_summary():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.ai_summary())

    @app.post("/api/template-rules")
    @AUTH.require("viewer")
    def compat_template_rules():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.template_rules(request.get_json(silent=True) or {}))

    @app.post("/api/generate-rules")
    @AUTH.require("viewer")
    def compat_generate_rules():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.generate_rules(request.get_json(silent=True) or {}))

    @app.post("/api/bulk-protect")
    @AUTH.require("viewer")
    def compat_bulk_protect():
        if OC is None:
            return unavailable("operator_compat")
        return jsonify(OC.bulk_protect(request.get_json(silent=True) or {}))
