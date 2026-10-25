"""Route group P3: social pattern tracker and broker-exposure sweep.

These are public-source modules. The pattern tracker stores only interactions
that are already public (posts, follows, mentions, shared URLs, email headers
supplied by the operator). The broker sweep checks public people-search pages
and reports honest ``possible_hit`` / ``no_signal`` / ``blocked`` statuses.
"""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    PAT = _mod("modules.pattern.pattern", "pattern", CAPS)
    PCON = _mod("modules.pattern.connectors", "pattern", CAPS)
    EGRAPH = _mod("modules.pattern.emailgraph", "pattern", CAPS)
    BRK = _mod("modules.broker.broker", "broker", CAPS)

    # --------------------------------------------------------------- pattern
    @app.get("/api/pattern/sources")
    @AUTH.require("viewer")
    def pt_sources():
        if PCON is None:
            return unavailable("pattern")
        return jsonify({"sources": PCON.source_catalog()})

    @app.post("/api/pattern/link")
    @AUTH.require("analyst")
    def pt_link():
        if PAT is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(PAT.add_link(
            b.get("src_type"), b.get("src_value"), b.get("dst_type"),
            b.get("dst_value"), b.get("relation", "contacts"),
            b.get("source", "manual"), b.get("confidence", 0.5),
            b.get("case_id"), user_fn()["username"]))

    @app.get("/api/pattern/links")
    @AUTH.require("viewer")
    def pt_links():
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.list_links(
            request.args.get("entity"),
            request.args.get("case_id", type=int),
            request.args.get("limit", 200, type=int)))

    @app.post("/api/pattern/ingest")
    @AUTH.require("analyst")
    def pt_ingest():
        if PAT is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        events = b if isinstance(b, list) else (b.get("events") or [])
        cid = None if isinstance(b, list) else b.get("case_id")
        return jsonify(PAT.ingest_events(events, cid, user_fn()["username"]))

    @app.post("/api/pattern/collect")
    @AUTH.require("analyst")
    def pt_collect():
        if PCON is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(PCON.run(b.get("entity", ""), b.get("platforms"),
                                b.get("case_id"), user_fn()["username"]))

    @app.get("/api/pattern/frequent_contacts/<path:entity>")
    @AUTH.require("viewer")
    def pt_contacts(entity):
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.frequent_contacts(
            entity, request.args.get("case_id", type=int),
            request.args.get("days", type=int),
            request.args.get("top", 25, type=int)))

    @app.get("/api/pattern/pnl/<path:entity>")
    @AUTH.require("viewer")
    def pt_pnl(entity):
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.pnl(entity,
                               request.args.get("case_id", type=int),
                               request.args.get("days", type=int)))

    @app.get("/api/pattern/diet/<path:entity>")
    @AUTH.require("viewer")
    def pt_diet(entity):
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.url_diet(entity,
                                    request.args.get("case_id", type=int),
                                    request.args.get("top", 20, type=int)))

    @app.get("/api/pattern/ips/<path:entity>")
    @AUTH.require("viewer")
    def pt_ips(entity):
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.ip_ledger(entity,
                                     request.args.get("case_id", type=int)))

    @app.post("/api/pattern/urls")
    @AUTH.require("analyst")
    def pt_urls():
        if PAT is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(PAT.record_urls(
            b.get("entity", ""), b.get("urls") or [], b.get("case_id"),
            b.get("source", "manual"), b.get("ts"), user_fn()["username"]))

    @app.post("/api/pattern/ips")
    @AUTH.require("analyst")
    def pt_ips_post():
        if PAT is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(PAT.add_ips(
            b.get("entity", ""), b.get("ips") or [], b.get("case_id"),
            b.get("source", "manual"), b.get("note", ""),
            user_fn()["username"]))

    @app.post("/api/pattern/header_ips")
    @AUTH.require("analyst")
    def pt_header_ips():
        if PAT is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(PAT.ingest_header_ips(
            b.get("headers", ""), b.get("entity"), b.get("case_id"),
            user_fn()["username"]))

    @app.get("/api/pattern/org/<path:entity>")
    @AUTH.require("viewer")
    def pt_org(entity):
        if PAT is None:
            return unavailable("pattern")
        return jsonify(PAT.org_view(entity,
                                    request.args.get("case_id", type=int)))

    @app.post("/api/pattern/email_graph")
    @AUTH.require("analyst")
    def pt_email_graph():
        if EGRAPH is None:
            return unavailable("pattern")
        b = request.get_json(silent=True) or {}
        return jsonify(EGRAPH.analyze(
            b.get("headers") or b.get("raw") or "", b.get("case_id"),
            b.get("ingest", True), user_fn()["username"]))

    # ---------------------------------------------------------------- broker
    @app.get("/api/broker/catalog")
    @AUTH.require("viewer")
    def br_catalog():
        if BRK is None:
            return unavailable("broker")
        return jsonify({"brokers": BRK.catalog()})

    @app.post("/api/broker/sweep")
    @AUTH.require("analyst")
    def br_sweep():
        if BRK is None:
            return unavailable("broker")
        b = request.get_json(silent=True) or {}
        return jsonify(BRK.sweep(
            b.get("name", ""), b.get("brokers"), b.get("mode", "name"),
            b.get("address", ""), b.get("delay", 0.7),
            user_fn()["username"]))
