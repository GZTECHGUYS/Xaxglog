"""Route group P1a: certstream, hostwatch, wireless, darknet (network/infra)."""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    CS = _mod("modules.certstream.certstream", "certstream", CAPS)
    HW = _mod("modules.hostwatch.hostwatch", "hostwatch", CAPS)
    WL = _mod("modules.wireless.wireless", "wireless", CAPS)
    DN = _mod("modules.darknet.darknet", "darknet", CAPS)

    # ------------------------------------------------------------ certstream
    @app.get("/api/certstream/search")
    @AUTH.require("viewer")
    def cs_search():
        if CS is None:
            return unavailable("certstream")
        return jsonify(CS.search(request.args.get("domain", "")))

    @app.post("/api/certstream/watch")
    @AUTH.require("analyst")
    def cs_watch():
        if CS is None:
            return unavailable("certstream")
        d = request.get_json(silent=True) or {}
        return jsonify(CS.watch(d.get("domain"), d.get("case_id"),
                                user_fn()["username"]))

    @app.post("/api/certstream/unwatch")
    @AUTH.require("analyst")
    def cs_unwatch():
        if CS is None:
            return unavailable("certstream")
        d = request.get_json(silent=True) or {}
        return jsonify(CS.unwatch(d.get("domain")))

    @app.get("/api/certstream/watch")
    @AUTH.require("viewer")
    def cs_list():
        if CS is None:
            return unavailable("certstream")
        return jsonify(CS.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/certstream/check")
    @AUTH.require("analyst")
    def cs_check():
        if CS is None:
            return unavailable("certstream")
        d = request.get_json(silent=True) or {}
        if d.get("all"):
            return jsonify(CS.check_all())
        return jsonify(CS.check_domain(d.get("domain", "")))

    # ------------------------------------------------------------- hostwatch
    @app.post("/api/hostwatch/watch")
    @AUTH.require("analyst")
    def hw_watch():
        if HW is None:
            return unavailable("hostwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(HW.watch(d.get("ip"), d.get("case_id"),
                                user_fn()["username"]))

    @app.post("/api/hostwatch/unwatch")
    @AUTH.require("analyst")
    def hw_unwatch():
        if HW is None:
            return unavailable("hostwatch")
        d = request.get_json(silent=True) or {}
        return jsonify(HW.unwatch(d.get("ip")))

    @app.get("/api/hostwatch/watch")
    @AUTH.require("viewer")
    def hw_list():
        if HW is None:
            return unavailable("hostwatch")
        return jsonify(HW.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/hostwatch/check")
    @AUTH.require("analyst")
    def hw_check():
        if HW is None:
            return unavailable("hostwatch")
        d = request.get_json(silent=True) or {}
        if d.get("all"):
            return jsonify(HW.check_all())
        return jsonify(HW.check_ip(d.get("ip", "")))

    @app.get("/api/hostwatch/rdap")
    @AUTH.require("viewer")
    def hw_rdap():
        if HW is None:
            return unavailable("hostwatch")
        return jsonify(HW.rdap(request.args.get("ip", "")))

    # -------------------------------------------------------------- wireless
    @app.post("/api/wireless/wifi")
    @AUTH.require("viewer")
    def wl_wifi():
        if WL is None:
            return unavailable("wireless")
        d = request.get_json(silent=True) or {}
        return jsonify(WL.wifi_lookup(d.get("bssid")))

    @app.post("/api/wireless/ssid")
    @AUTH.require("analyst")
    def wl_ssid():
        if WL is None:
            return unavailable("wireless")
        d = request.get_json(silent=True) or {}
        return jsonify(WL.ssid_search(d.get("ssid"), d.get("lat"),
                                      d.get("lon"), d.get("limit", 50)))

    @app.post("/api/wireless/cell")
    @AUTH.require("viewer")
    def wl_cell():
        if WL is None:
            return unavailable("wireless")
        d = request.get_json(silent=True) or {}
        return jsonify(WL.cell_lookup(d.get("mcc"), d.get("mnc"),
                                      d.get("lac"), d.get("ci")))

    # --------------------------------------------------------------- darknet
    @app.get("/api/darknet/tor")
    @AUTH.require("viewer")
    def dn_tor():
        if DN is None:
            return unavailable("darknet")
        return jsonify(DN.tor_exits())

    @app.get("/api/darknet/ipsum")
    @AUTH.require("viewer")
    def dn_ipsum():
        if DN is None:
            return unavailable("darknet")
        return jsonify(DN.ipsum(request.args.get("level", 3, type=int)))

    @app.get("/api/darknet/blocklist")
    @AUTH.require("viewer")
    def dn_blocklist():
        if DN is None:
            return unavailable("darknet")
        return jsonify(DN.blocklist_de())

    @app.post("/api/darknet/check")
    @AUTH.require("viewer")
    def dn_check():
        if DN is None:
            return unavailable("darknet")
        d = request.get_json(silent=True) or {}
        return jsonify(DN.check_ip(d.get("ip", "")))

    @app.post("/api/darknet/watch")
    @AUTH.require("analyst")
    def dn_watch():
        if DN is None:
            return unavailable("darknet")
        d = request.get_json(silent=True) or {}
        return jsonify(DN.watch(d.get("ip"), d.get("case_id"),
                                user_fn()["username"]))

    @app.post("/api/darknet/unwatch")
    @AUTH.require("analyst")
    def dn_unwatch():
        if DN is None:
            return unavailable("darknet")
        d = request.get_json(silent=True) or {}
        return jsonify(DN.unwatch(d.get("ip")))

    @app.get("/api/darknet/watch")
    @AUTH.require("viewer")
    def dn_list():
        if DN is None:
            return unavailable("darknet")
        return jsonify(DN.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/darknet/check_all")
    @AUTH.require("analyst")
    def dn_check_all():
        if DN is None:
            return unavailable("darknet")
        return jsonify(DN.check_all())
