"""Route group P4: public-records modules (procurement, lobbying, nonprofit)."""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    PR = _mod("modules.procurement.procurement", "procurement", CAPS)
    LB = _mod("modules.lobbying.lobbying", "lobbying", CAPS)
    NP = _mod("modules.nonprofit.nonprofit", "nonprofit", CAPS)

    # ------------------------------------------------------------ procurement
    @app.get("/api/procurement/sources")
    @AUTH.require("viewer")
    def pr_sources():
        if PR is None:
            return unavailable("procurement")
        return jsonify({"sources": PR.sources()})

    @app.post("/api/procurement/search")
    @AUTH.require("viewer")
    def pr_search():
        if PR is None:
            return unavailable("procurement")
        d = request.get_json(silent=True) or {}
        return jsonify(PR.search(
            query=d.get("query") or d.get("q"),
            country=d.get("country", "all"), limit=d.get("limit", 10),
            start_date=d.get("start_date"), end_date=d.get("end_date"),
            case_id=d.get("case_id"), user=user_fn()["username"]))

    # --------------------------------------------------------------- lobbying
    @app.get("/api/lobbying/sources")
    @AUTH.require("viewer")
    def lb_sources():
        if LB is None:
            return unavailable("lobbying")
        return jsonify({"sources": LB.sources()})

    @app.post("/api/lobbying/search")
    @AUTH.require("viewer")
    def lb_search():
        if LB is None:
            return unavailable("lobbying")
        d = request.get_json(silent=True) or {}
        return jsonify(LB.search(
            query=d.get("query") or d.get("q"), year=d.get("year"),
            limit=d.get("limit", 25), case_id=d.get("case_id"),
            user=user_fn()["username"]))

    # -------------------------------------------------------------- nonprofit
    @app.get("/api/nonprofit/sources")
    @AUTH.require("viewer")
    def np_sources():
        if NP is None:
            return unavailable("nonprofit")
        return jsonify({"sources": NP.sources()})

    @app.post("/api/nonprofit/search")
    @AUTH.require("viewer")
    def np_search():
        if NP is None:
            return unavailable("nonprofit")
        d = request.get_json(silent=True) or {}
        return jsonify(NP.search(
            query=d.get("query") or d.get("q"), state=d.get("state"),
            limit=d.get("limit", 20), case_id=d.get("case_id"),
            user=user_fn()["username"]))

    @app.get("/api/nonprofit/org/<ein>")
    @AUTH.require("viewer")
    def np_org(ein):
        if NP is None:
            return unavailable("nonprofit")
        return jsonify(NP.organization(
            ein, case_id=request.args.get("case_id", type=int),
            user=user_fn()["username"]))
