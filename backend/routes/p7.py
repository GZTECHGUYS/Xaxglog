"""Route group P7: identity intelligence + unified source registry.

Phase 1/2 endpoints:
  * /api/identity/plan      — show variants + planned sources before a run
  * /api/identity/search    — always-on name variants, extra indexes, records,
                              web pass, dedupe, confidence and coverage
  * /api/identity/variants  — name/handle variant preview
  * /api/sources/registry   — the unified 402-source public catalog
  * /api/sources/links      — public link-out search/profile URLs
  * /api/sources/verify     — live-check a selected set of keyless adapters
"""
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


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    ID = _mod("modules.identity.identity", "identity", CAPS)
    SR = _mod("modules.source_registry.source_registry", "source_registry", CAPS)

    @app.get("/api/identity/variants")
    def identity_variants():
        if ID is None:
            return unavailable("identity")
        q = request.args.get("q") or request.args.get("query") or ""
        return jsonify({
            "input": q,
            "normalized": ID.normalize_name(q),
            "variants": ID.name_variants(q, max_variants=_int(request.args.get("limit"), 24, 1, 80)),
            "handle_variants": ID.handle_variants(q),
        })

    @app.get("/api/identity/plan")
    def identity_plan():
        if ID is None:
            return unavailable("identity")
        q = request.args.get("q") or request.args.get("query") or ""
        plan = ID.build_plan(
            q,
            kind=request.args.get("kind"),
            depth=request.args.get("depth", "standard"),
            country=request.args.get("country") or None,
            include_social=_bool(request.args.get("include_social"), True),
            include_web=_bool(request.args.get("include_web"), True),
            include_records=_bool(request.args.get("include_records"), True),
            include_code=_bool(request.args.get("include_code"), None),
            include_link_out=_bool(request.args.get("include_link_out"), True),
        )
        return jsonify(plan)

    @app.post("/api/identity/search")
    def identity_search():
        if ID is None:
            return unavailable("identity")
        d = request.get_json(silent=True) or {}
        q = (d.get("query") or d.get("q") or "").strip()
        out = ID.search(
            q,
            kind=d.get("kind"),
            depth=d.get("depth", "standard"),
            country=d.get("country") or None,
            include_social=_bool(d.get("include_social"), True),
            include_web=_bool(d.get("include_web"), True),
            include_records=_bool(d.get("include_records"), True),
            include_code=_bool(d.get("include_code"), None),
            include_link_out=_bool(d.get("include_link_out"), True),
            case_id=d.get("case_id"),
            user=user_fn()["username"],
            max_variants=_int(d.get("max_variants"), 24, 1, 80),
        )
        return jsonify(out), (400 if out.get("status") == "error" else 200)

    @app.get("/api/sources/summary")
    def sources_summary():
        if SR is None:
            return unavailable("source_registry")
        return jsonify(SR.summary())

    @app.get("/api/sources/registry")
    def sources_registry():
        if SR is None:
            return unavailable("source_registry")
        include_sources = _bool(request.args.get("include_sources"), True)
        limit = _int(request.args.get("limit"), 0, 0, 1000) or None
        out = SR.catalog(include_sources=include_sources, limit=limit)
        return jsonify(out)

    @app.get("/api/sources/links")
    def sources_links():
        if SR is None:
            return unavailable("source_registry")
        q = request.args.get("q") or request.args.get("query") or ""
        types = request.args.get("types") or request.args.get("type")
        categories = request.args.get("categories") or request.args.get("category")
        return jsonify({
            "query": q,
            "links": SR.search_links(
                q,
                types=types.split(",") if types else None,
                categories=categories.split(",") if categories else None,
                region=request.args.get("region") or None,
                limit=_int(request.args.get("limit"), 250, 1, 500),
            ),
        })

    @app.post("/api/sources/verify")
    @AUTH.require("analyst")
    def sources_verify():
        if ID is None:
            return unavailable("identity")
        d = request.get_json(silent=True) or {}
        ids = d.get("ids")
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        out = ID.verify_sources(
            ids=ids,
            query=d.get("query") or "John Smith",
            timeout=_int(d.get("timeout"), 12, 3, 30),
        )
        return jsonify(out)
