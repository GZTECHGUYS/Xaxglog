"""Route group P2b: adwatch, coordcheck, broadcast, community, onchain,
trade, marketplace, graphstudio, foia, dsar, hazards."""
from flask import request, Response, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    AD = _mod("modules.adwatch.adwatch", "adwatch", CAPS)
    CC = _mod("modules.coordcheck.coordcheck", "coordcheck", CAPS)
    BC = _mod("modules.broadcast.broadcast", "broadcast", CAPS)
    CM = _mod("modules.community.community", "community", CAPS)
    OC = _mod("modules.onchain.onchain", "onchain", CAPS)
    TR = _mod("modules.trade.trade", "trade", CAPS)
    MP = _mod("modules.marketplace.marketplace", "marketplace", CAPS)
    GS = _mod("modules.graphstudio.graphstudio", "graphstudio", CAPS)
    FO = _mod("modules.foia.foia", "foia", CAPS)
    DS = _mod("modules.dsar.dsar", "dsar", CAPS)
    HZ = _mod("modules.hazards.hazards", "hazards", CAPS)

    # ---------------------------------------------------------------- adwatch
    @app.post("/api/adwatch/links")
    @AUTH.require("viewer")
    def ad_links():
        if AD is None:
            return unavailable("adwatch")
        d = request.get_json(silent=True) or {}
        meta = AD.meta_link(d.get("keyword"), d.get("country", "US"),
                            d.get("ad_type", "all"), d.get("page"))
        goo = AD.google_link(d.get("keyword"), d.get("country", "US"))
        return jsonify({"status": "ok", "meta": meta.get("meta_library"),
                        "google": goo.get("google_transparency"),
                        "note": meta.get("note")})

    @app.post("/api/adwatch/api")
    @AUTH.require("analyst")
    def ad_api():
        if AD is None:
            return unavailable("adwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(AD.meta_api(d.get("search_terms"), d.get("country", "US"),
                                   d.get("limit", 25),
                                   d.get("date_min")))

    @app.post("/api/adwatch/history")
    @AUTH.require("viewer")
    def ad_history():
        if AD is None:
            return unavailable("adwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(AD.ad_page_history(d.get("url"), d.get("limit", 500)))

    @app.post("/api/adwatch/news")
    @AUTH.require("viewer")
    def ad_news():
        if AD is None:
            return unavailable("adwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(AD.ad_news(d.get("query"), d.get("timespan", "3month")))

    @app.post("/api/adwatch/bundle")
    @AUTH.require("viewer")
    def ad_bundle():
        if AD is None:
            return unavailable("adwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(AD.bundle(d.get("keyword"), d.get("country", "US")))

    # -------------------------------------------------------------- coordcheck
    @app.post("/api/coordcheck/analyze")
    @AUTH.require("analyst")
    def cc_analyze():
        if CC is None:
            return unavailable("coordcheck")
        d = request.get_json(silent=True) or {}
        return jsonify(CC.analyze(d.get("items"),
                                  d.get("burst_window_sec", 300),
                                  d.get("similarity", 0.72),
                                  d.get("fresh_days", 30)))

    @app.post("/api/coordcheck/case/<int:case_id>")
    @AUTH.require("analyst")
    def cc_case(case_id):
        if CC is None:
            return unavailable("coordcheck")
        d = request.get_json(silent=True) or {}
        return jsonify(CC.from_case(case_id, d.get("limit", 1000),
                                    d.get("artifact_types")))

    # --------------------------------------------------------------- broadcast
    @app.post("/api/broadcast/stations")
    @AUTH.require("viewer")
    def bc_stations():
        if BC is None:
            return unavailable("broadcast")
        d = request.get_json(silent=True) or {}
        return jsonify(BC.stations(d.get("q"), d.get("country"), d.get("tag"),
                                   d.get("limit", 25)))

    @app.post("/api/broadcast/stream_status")
    @AUTH.require("viewer")
    def bc_stream():
        if BC is None:
            return unavailable("broadcast")
        d = request.get_json(silent=True) or {}
        return jsonify(BC.stream_status(d.get("url")))

    @app.post("/api/broadcast/feed_mentions")
    @AUTH.require("analyst")
    def bc_feed():
        if BC is None:
            return unavailable("broadcast")
        d = request.get_json(silent=True) or {}
        return jsonify(BC.feed_mentions(d.get("feed_url"),
                                        d.get("terms") or [],
                                        d.get("limit", 100)))

    @app.post("/api/broadcast/find")
    @AUTH.require("viewer")
    def bc_find():
        if BC is None:
            return unavailable("broadcast")
        d = request.get_json(silent=True) or {}
        return jsonify(BC.find_and_scan(d.get("term"), d.get("country"),
                                        d.get("limit", 10)))

    # --------------------------------------------------------------- community
    @app.post("/api/community/guild")
    @AUTH.require("viewer")
    def cm_guild():
        if CM is None:
            return unavailable("community")
        d = request.get_json(silent=True) or {}
        return jsonify(CM.guild(d.get("guild_id")))

    @app.post("/api/community/invite")
    @AUTH.require("viewer")
    def cm_invite():
        if CM is None:
            return unavailable("community")
        d = request.get_json(silent=True) or {}
        return jsonify(CM.invite(d.get("code")))

    @app.post("/api/community/matrix")
    @AUTH.require("viewer")
    def cm_matrix():
        if CM is None:
            return unavailable("community")
        d = request.get_json(silent=True) or {}
        return jsonify(CM.matrix_rooms(d.get("query"), d.get("limit", 20)))

    @app.post("/api/community/watch")
    @AUTH.require("analyst")
    def cm_watch():
        if CM is None:
            return unavailable("community")
        d = request.get_json(silent=True) or {}
        return jsonify(CM.watch(d.get("kind"), d.get("ref"),
                                d.get("case_id"), user_fn()["username"]))

    @app.post("/api/community/unwatch")
    @AUTH.require("analyst")
    def cm_unwatch():
        if CM is None:
            return unavailable("community")
        d = request.get_json(silent=True) or {}
        return jsonify(CM.unwatch(d.get("kind"), d.get("ref")))

    @app.get("/api/community/watch")
    @AUTH.require("viewer")
    def cm_list():
        if CM is None:
            return unavailable("community")
        return jsonify(CM.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/community/check_all")
    @AUTH.require("analyst")
    def cm_check_all():
        if CM is None:
            return unavailable("community")
        return jsonify(CM.check_all())

    # ----------------------------------------------------------------- onchain
    @app.post("/api/onchain/resolve")
    @AUTH.require("viewer")
    def oc_resolve():
        if OC is None:
            return unavailable("onchain")
        d = request.get_json(silent=True) or {}
        return jsonify(OC.resolve_ens(d.get("name")))

    @app.post("/api/onchain/account")
    @AUTH.require("viewer")
    def oc_account():
        if OC is None:
            return unavailable("onchain")
        d = request.get_json(silent=True) or {}
        return jsonify(OC.eth_account(d.get("address")))

    @app.post("/api/onchain/nfts")
    @AUTH.require("viewer")
    def oc_nfts():
        if OC is None:
            return unavailable("onchain")
        d = request.get_json(silent=True) or {}
        return jsonify(OC.nfts(d.get("address")))

    @app.post("/api/onchain/anchor")
    @AUTH.require("analyst")
    def oc_anchor():
        if OC is None:
            return unavailable("onchain")
        d = request.get_json(silent=True) or {}
        return jsonify(OC.anchor(d.get("query"), d.get("case_id"),
                                 user_fn()["username"]))

    # ------------------------------------------------------------------- trade
    @app.post("/api/trade/flows")
    @AUTH.require("viewer")
    def tr_flows():
        if TR is None:
            return unavailable("trade")
        d = request.get_json(silent=True) or {}
        return jsonify(TR.flows(d.get("country"), d.get("mode", "export"),
                                d.get("year"), d.get("limit", 25)))

    @app.post("/api/trade/comtrade")
    @AUTH.require("viewer")
    def tr_comtrade():
        if TR is None:
            return unavailable("trade")
        d = request.get_json(silent=True) or {}
        return jsonify(TR.comtrade(d.get("reporter"), d.get("partner"),
                                   d.get("year", 2023), d.get("cmd", "TOTAL")))

    @app.post("/api/trade/concentration")
    @AUTH.require("viewer")
    def tr_concentration():
        if TR is None:
            return unavailable("trade")
        d = request.get_json(silent=True) or {}
        return jsonify(TR.concentration(d.get("country"), d.get("year")))

    # -------------------------------------------------------------- marketplace
    @app.post("/api/marketplace/search")
    @AUTH.require("analyst")
    def mp_search():
        if MP is None:
            return unavailable("marketplace")
        d = request.get_json(silent=True) or {}
        return jsonify(MP.search(d.get("brand"), d.get("marketplaces"),
                                 d.get("limit", 15)))

    @app.post("/api/marketplace/inspect")
    @AUTH.require("analyst")
    def mp_inspect():
        if MP is None:
            return unavailable("marketplace")
        d = request.get_json(silent=True) or {}
        return jsonify(MP.inspect(d.get("url")))

    @app.post("/api/marketplace/watch")
    @AUTH.require("analyst")
    def mp_watch():
        if MP is None:
            return unavailable("marketplace")
        d = request.get_json(silent=True) or {}
        return jsonify(MP.watch(d.get("url"), d.get("brand"),
                                d.get("case_id"), user_fn()["username"]))

    @app.post("/api/marketplace/unwatch")
    @AUTH.require("analyst")
    def mp_unwatch():
        if MP is None:
            return unavailable("marketplace")
        d = request.get_json(silent=True) or {}
        return jsonify(MP.unwatch(d.get("url")))

    @app.get("/api/marketplace/watch")
    @AUTH.require("viewer")
    def mp_list():
        if MP is None:
            return unavailable("marketplace")
        return jsonify(MP.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/marketplace/check_all")
    @AUTH.require("analyst")
    def mp_check_all():
        if MP is None:
            return unavailable("marketplace")
        return jsonify(MP.check_all())

    # ------------------------------------------------------------- graphstudio
    @app.get("/api/graph/<int:case_id>/layout")
    @AUTH.require("viewer")
    def gs_layout(case_id):
        if GS is None:
            return unavailable("graphstudio")
        return jsonify(GS.layout(case_id,
                                 width=request.args.get("width", 1200, type=int),
                                 height=request.args.get("height", 800, type=int),
                                 top=request.args.get("top", 400, type=int),
                                 seed=request.args.get("seed", 42, type=int)))

    @app.get("/graph/<int:case_id>")
    @AUTH.require("viewer")
    def gs_viewer(case_id):
        if GS is None:
            return unavailable("graphstudio")
        return Response(GS.viewer_html(case_id), mimetype="text/html")

    # -------------------------------------------------------------------- foia
    @app.get("/api/foia/jurisdictions")
    @AUTH.require("viewer")
    def fo_jurs():
        if FO is None:
            return unavailable("foia")
        return jsonify(FO.jurisdictions())

    @app.post("/api/foia/draft")
    @AUTH.require("analyst")
    def fo_draft():
        if FO is None:
            return unavailable("foia")
        d = request.get_json(silent=True) or {}
        return jsonify(FO.draft(d.get("jurisdiction"), d.get("agency"),
                                d.get("subject"), d.get("scope"),
                                d.get("requester", "Anonymous requester"),
                                d.get("fee_waiver", True), d.get("extra"),
                                user_fn()["username"], d.get("case_id")))

    @app.post("/api/foia/<int:request_id>/submit")
    @AUTH.require("analyst")
    def fo_submit(request_id):
        if FO is None:
            return unavailable("foia")
        d = request.get_json(silent=True) or {}
        return jsonify(FO.submit(request_id, d.get("submitted_at"),
                                 user_fn()["username"]))

    @app.post("/api/foia/<int:request_id>/status")
    @AUTH.require("analyst")
    def fo_status(request_id):
        if FO is None:
            return unavailable("foia")
        d = request.get_json(silent=True) or {}
        out = FO.set_status(request_id, d.get("status", ""),
                            user_fn()["username"])
        if out.get("status") == "error":
            return jsonify(out), 400
        return jsonify(out)

    @app.get("/api/foia/requests")
    @AUTH.require("viewer")
    def fo_list():
        if FO is None:
            return unavailable("foia")
        return jsonify(FO.list_requests(request.args.get("status"),
                                        request.args.get("limit", 50, type=int)))

    @app.get("/api/foia/requests/<int:request_id>")
    @AUTH.require("viewer")
    def fo_get(request_id):
        if FO is None:
            return unavailable("foia")
        out = FO.get_request(request_id)
        if out.get("status") == "error":
            return jsonify(out), 404
        return jsonify(out)

    @app.post("/api/foia/check_deadlines")
    @AUTH.require("analyst")
    def fo_deadlines():
        if FO is None:
            return unavailable("foia")
        return jsonify(FO.deadline_alerts())

    # -------------------------------------------------------------------- dsar
    @app.get("/api/dsar/regimes")
    @AUTH.require("viewer")
    def ds_regimes():
        if DS is None:
            return unavailable("dsar")
        return jsonify(DS.regimes())

    @app.post("/api/dsar/draft")
    @AUTH.require("analyst")
    def ds_draft():
        if DS is None:
            return unavailable("dsar")
        d = request.get_json(silent=True) or {}
        return jsonify(DS.draft(d.get("regime"), d.get("kind"),
                                d.get("target_org"), d.get("data_subject"),
                                d.get("details"), d.get("standing"),
                                user_fn()["username"], d.get("case_id")))

    @app.post("/api/dsar/<int:request_id>/status")
    @AUTH.require("analyst")
    def ds_status(request_id):
        if DS is None:
            return unavailable("dsar")
        d = request.get_json(silent=True) or {}
        out = DS.set_status(request_id, d.get("status", ""),
                            user_fn()["username"], d.get("sent_at"))
        if out.get("status") == "error":
            return jsonify(out), 400
        return jsonify(out)

    @app.get("/api/dsar/requests")
    @AUTH.require("viewer")
    def ds_list():
        if DS is None:
            return unavailable("dsar")
        return jsonify(DS.list_requests(request.args.get("status"),
                                        request.args.get("limit", 50, type=int)))

    @app.get("/api/dsar/requests/<int:request_id>")
    @AUTH.require("viewer")
    def ds_get(request_id):
        if DS is None:
            return unavailable("dsar")
        out = DS.get_request(request_id)
        if out.get("status") == "error":
            return jsonify(out), 404
        return jsonify(out)

    @app.post("/api/dsar/check_deadlines")
    @AUTH.require("analyst")
    def ds_deadlines():
        if DS is None:
            return unavailable("dsar")
        return jsonify(DS.deadline_alerts())

    # ----------------------------------------------------------------- hazards
    @app.post("/api/hazards/quakes")
    @AUTH.require("viewer")
    def hz_quakes():
        if HZ is None:
            return unavailable("hazards")
        d = request.get_json(silent=True) or {}
        return jsonify(HZ.quakes(d.get("min_magnitude", 4.5),
                                 d.get("window", "week"), d.get("bbox"),
                                 d.get("limit", 100)))

    @app.get("/api/hazards/gdacs")
    @AUTH.require("viewer")
    def hz_gdacs():
        if HZ is None:
            return unavailable("hazards")
        return jsonify(HZ.gdacs(request.args.get("level"),
                                request.args.get("types"),
                                request.args.get("limit", 100, type=int)))

    @app.get("/api/hazards/nws")
    @AUTH.require("viewer")
    def hz_nws():
        if HZ is None:
            return unavailable("hazards")
        return jsonify(HZ.nws_alerts(request.args.get("lat", type=float),
                                     request.args.get("lon", type=float),
                                     request.args.get("state")))

    @app.post("/api/hazards/brief")
    @AUTH.require("analyst")
    def hz_brief():
        if HZ is None:
            return unavailable("hazards")
        d = request.get_json(silent=True) or {}
        return jsonify(HZ.area_brief(d.get("lat"), d.get("lon"),
                                     d.get("radius_km", 100),
                                     d.get("min_magnitude", 4.0),
                                     d.get("case_id"),
                                     user_fn()["username"]))

    @app.get("/api/hazards/sources")
    @AUTH.require("viewer")
    def hz_sources():
        if HZ is None:
            return unavailable("hazards")
        return jsonify(HZ.sources())
