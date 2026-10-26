"""Route group P6: broad public social-media search/scrape + image reverse lookup.

Both modules are public-source only. Social discovery uses public pages/APIs
and reports login walls as blocked. Image reverse lookup builds public engine
links and runs keyless/optional-key APIs; face-search engines are excluded.
"""
from flask import request, jsonify


def _bool(value, default=True):
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
    SS = _mod("modules.socialscrape.socialscrape", "socialscrape", CAPS)
    IR = _mod("modules.imgreverse.imgreverse", "imgreverse", CAPS)

    # --------------------------------------------------------- socialscrape
    @app.get("/api/socialscrape/catalog")
    @AUTH.require("viewer")
    def ss_catalog():
        if SS is None:
            return unavailable("socialscrape")
        return jsonify(SS.catalog())

    @app.get("/api/socialscrape/links")
    @AUTH.require("viewer")
    def ss_links():
        if SS is None:
            return unavailable("socialscrape")
        q = request.args.get("q") or request.args.get("query") or ""
        return jsonify({
            "query": q,
            "links": SS.search_links(
                q, platforms=request.args.get("platforms"),
                region=request.args.get("region", "all"),
                category=request.args.get("category", "all"),
                limit=_int(request.args.get("limit"), 250, 1, 500)),
        })

    @app.post("/api/socialscrape/search")
    @AUTH.require("viewer")
    def ss_search():
        if SS is None:
            return unavailable("socialscrape")
        d = request.get_json(silent=True) or {}
        out = SS.search(
            query=d.get("query") or d.get("q"),
            platforms=d.get("platforms"),
            region=d.get("region", "all"),
            category=d.get("category", "all"),
            language=d.get("language"),
            limit=_int(d.get("limit"), 30, 1, 100),
            scrape=_bool(d.get("scrape"), False),
            probe=_bool(d.get("probe"), False),
            case_id=d.get("case_id"),
            user=user_fn()["username"],
            engines=d.get("engines"),
        )
        return jsonify(out), (400 if out.get("status") == "error" else 200)

    @app.post("/api/socialscrape/page")
    @AUTH.require("viewer")
    def ss_page():
        if SS is None:
            return unavailable("socialscrape")
        d = request.get_json(silent=True) or {}
        out = SS.scrape_public_page(
            d.get("url") or d.get("query"),
            include_images=_bool(d.get("include_images"), True),
            include_oembed=_bool(d.get("include_oembed"), True),
        )
        if d.get("case_id") and out.get("status") == "ok":
            try:
                import db
                out["artifact"] = db.store_artifact(
                    d.get("case_id"), None, "social_scrape",
                    "socialscrape:page", out, user_fn()["username"])
            except Exception as e:
                out["artifact_error"] = str(e)[:150]
        return jsonify(out), (400 if out.get("status") == "error" else 200)

    @app.post("/api/socialscrape/oembed")
    @AUTH.require("viewer")
    def ss_oembed():
        if SS is None:
            return unavailable("socialscrape")
        d = request.get_json(silent=True) or {}
        return jsonify(SS.oembed(d.get("url") or d.get("query")))

    # ------------------------------------------------------------ imgreverse
    @app.get("/api/imgreverse/catalog")
    @AUTH.require("viewer")
    def ir_catalog():
        if IR is None:
            return unavailable("imgreverse")
        return jsonify(IR.catalog())

    @app.get("/api/imgreverse/links")
    @AUTH.require("viewer")
    def ir_links():
        if IR is None:
            return unavailable("imgreverse")
        url = request.args.get("url") or request.args.get("image_url") or ""
        return jsonify({"image_url": url, "links": IR.links(url)})

    @app.post("/api/imgreverse/search")
    @AUTH.require("viewer")
    def ir_search():
        if IR is None:
            return unavailable("imgreverse")
        d = request.get_json(silent=True) or {}
        out = IR.search(
            image_url=d.get("image_url") or d.get("url"),
            image_path=d.get("image_path") or d.get("path"),
            engines=d.get("engines"),
            include_api=_bool(d.get("include_api"), True),
            case_id=d.get("case_id"),
            user=user_fn()["username"],
        )
        return jsonify(out), (400 if out.get("status") == "error" else 200)
