"""Route group P5: country-scoped search.

Takes a name, company, domain, IP, phone or email plus a selected country and
returns country-specific public source links with live checks where available.
"""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    CS = _mod("modules.countryscope.countryscope", "countryscope", CAPS)

    @app.get("/api/countryscope/countries")
    @AUTH.require("viewer")
    def countryscope_countries():
        if CS is None:
            return unavailable("countryscope")
        return jsonify({"countries": CS.countries(), "count": len(CS.COUNTRIES)})

    @app.get("/api/countryscope/profile/<cc>")
    @AUTH.require("viewer")
    def countryscope_profile(cc):
        if CS is None:
            return unavailable("countryscope")
        out = CS.profile(cc)
        return jsonify(out), (200 if out.get("status") == "ok" else 404)

    @app.post("/api/countryscope/search")
    @AUTH.require("viewer")
    def countryscope_search():
        if CS is None:
            return unavailable("countryscope")
        d = request.get_json(silent=True) or {}
        include_live = d.get("include_live", True)
        if isinstance(include_live, str):
            include_live = include_live.strip().lower() not in ("0", "false", "no", "off")
        out = CS.search(
            query=d.get("query") or d.get("q"),
            country=d.get("country", "auto"),
            case_id=d.get("case_id"),
            user=user_fn()["username"],
            include_live=bool(include_live),
        )
        code = 200
        if out.get("status") == "needs_country":
            code = 422
        elif out.get("status") == "error":
            code = 400
        return jsonify(out), code
