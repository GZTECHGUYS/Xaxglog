"""Route group P2a: kinship, property, donortrail, langintel, malintel,
phishkit, supplychain, opsecaudit."""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    KN = _mod("modules.kinship.kinship", "kinship", CAPS)
    PR = _mod("modules.property.property", "property", CAPS)
    DT = _mod("modules.donortrail.donortrail", "donortrail", CAPS)
    LI = _mod("modules.langintel.langintel", "langintel", CAPS)
    MI = _mod("modules.malintel.malintel", "malintel", CAPS)
    PK = _mod("modules.phishkit.phishkit", "phishkit", CAPS)
    SC = _mod("modules.supplychain.supplychain", "supplychain", CAPS)
    OA = _mod("modules.opsecaudit.opsecaudit", "opsecaudit", CAPS)

    # --------------------------------------------------------------- kinship
    @app.post("/api/kinship/resolve")
    @AUTH.require("viewer")
    def kn_resolve():
        if KN is None:
            return unavailable("kinship")
        d = request.get_json(silent=True) or {}
        return jsonify(KN.resolve(d.get("name"), d.get("birth_year")))

    @app.post("/api/kinship/relatives")
    @AUTH.require("viewer")
    def kn_relatives():
        if KN is None:
            return unavailable("kinship")
        d = request.get_json(silent=True) or {}
        return jsonify(KN.relatives(d.get("qid")))

    @app.post("/api/kinship/graph")
    @AUTH.require("analyst")
    def kn_graph():
        if KN is None:
            return unavailable("kinship")
        d = request.get_json(silent=True) or {}
        return jsonify(KN.graph_for(d.get("name"), d.get("birth_year"),
                                    d.get("case_id"), user_fn()["username"]))

    @app.post("/api/kinship/obituaries")
    @AUTH.require("viewer")
    def kn_obits():
        if KN is None:
            return unavailable("kinship")
        d = request.get_json(silent=True) or {}
        return jsonify(KN.obituary_dorks(d.get("name"), d.get("place")))

    # --------------------------------------------------------------- property
    @app.post("/api/property/uk")
    @AUTH.require("viewer")
    def pr_uk():
        if PR is None:
            return unavailable("property")
        d = request.get_json(silent=True) or {}
        return jsonify(PR.uk_transactions(d.get("postcode"),
                                          d.get("limit", 50)))

    @app.get("/api/property/where")
    @AUTH.require("viewer")
    def pr_where():
        if PR is None:
            return unavailable("property")
        return jsonify(PR.where(request.args.get("iso2", "")))

    @app.get("/api/property/directory")
    @AUTH.require("viewer")
    def pr_dir():
        if PR is None:
            return unavailable("property")
        return jsonify(PR.directory())

    # ------------------------------------------------------------- donortrail
    @app.post("/api/donortrail/candidate")
    @AUTH.require("viewer")
    def dt_candidate():
        if DT is None:
            return unavailable("donortrail")
        d = request.get_json(silent=True) or {}
        return jsonify(DT.candidate(d.get("q")))

    @app.post("/api/donortrail/receipts")
    @AUTH.require("viewer")
    def dt_receipts():
        if DT is None:
            return unavailable("donortrail")
        d = request.get_json(silent=True) or {}
        return jsonify(DT.receipts(d.get("candidate_id"), d.get("cycle", 2024),
                                   d.get("per_page", 40)))

    @app.post("/api/donortrail/flows")
    @AUTH.require("viewer")
    def dt_flows():
        if DT is None:
            return unavailable("donortrail")
        d = request.get_json(silent=True) or {}
        return jsonify(DT.committee_flows(d.get("committee_id"),
                                          d.get("cycle", 2024)))

    @app.get("/api/donortrail/bulk")
    @AUTH.require("viewer")
    def dt_bulk():
        if DT is None:
            return unavailable("donortrail")
        return jsonify(DT.bulk_index())

    @app.get("/api/donortrail/directory")
    @AUTH.require("viewer")
    def dt_dir():
        if DT is None:
            return unavailable("donortrail")
        return jsonify(DT.directory())

    # --------------------------------------------------------------- langintel
    @app.post("/api/langintel/detect")
    @AUTH.require("viewer")
    def li_detect():
        if LI is None:
            return unavailable("langintel")
        d = request.get_json(silent=True) or {}
        return jsonify(LI.detect_script(d.get("text")))

    @app.post("/api/langintel/translate")
    @AUTH.require("analyst")
    def li_translate():
        if LI is None:
            return unavailable("langintel")
        d = request.get_json(silent=True) or {}
        return jsonify(LI.translate(d.get("text"), d.get("source", "auto"),
                                    d.get("target", "en")))

    @app.post("/api/langintel/transliterate")
    @AUTH.require("viewer")
    def li_translit():
        if LI is None:
            return unavailable("langintel")
        d = request.get_json(silent=True) or {}
        return jsonify(LI.transliterate(d.get("text")))

    @app.post("/api/langintel/normalize")
    @AUTH.require("viewer")
    def li_normalize():
        if LI is None:
            return unavailable("langintel")
        d = request.get_json(silent=True) or {}
        return jsonify(LI.normalize(d.get("text")))

    @app.post("/api/langintel/expand")
    @AUTH.require("viewer")
    def li_expand():
        if LI is None:
            return unavailable("langintel")
        d = request.get_json(silent=True) or {}
        return jsonify(LI.expand_terms(d.get("name"), d.get("max", 20)))

    # --------------------------------------------------------------- malintel
    @app.post("/api/malintel/file")
    @AUTH.require("analyst")
    def mi_file():
        if MI is None:
            return unavailable("malintel")
        d = request.get_json(silent=True) or {}
        return jsonify(MI.file_hashes(d.get("path")))

    @app.post("/api/malintel/hash")
    @AUTH.require("viewer")
    def mi_hash():
        if MI is None:
            return unavailable("malintel")
        d = request.get_json(silent=True) or {}
        return jsonify(MI.hash_lookup(d.get("sha256")))

    @app.post("/api/malintel/ioc")
    @AUTH.require("viewer")
    def mi_ioc():
        if MI is None:
            return unavailable("malintel")
        d = request.get_json(silent=True) or {}
        return jsonify(MI.ioc(d.get("indicator"), d.get("otx_key")))

    @app.post("/api/malintel/yara")
    @AUTH.require("analyst")
    def mi_yara():
        if MI is None:
            return unavailable("malintel")
        d = request.get_json(silent=True) or {}
        return jsonify(MI.yara_scan(d.get("path"), d.get("rules")))

    @app.post("/api/malintel/attach")
    @AUTH.require("analyst")
    def mi_attach():
        if MI is None:
            return unavailable("malintel")
        d = request.get_json(silent=True) or {}
        return jsonify(MI.attach(d.get("case_id"), d.get("path"),
                                 user_fn()["username"]))

    # --------------------------------------------------------------- phishkit
    @app.post("/api/phishkit/check")
    @AUTH.require("viewer")
    def pk_check():
        if PK is None:
            return unavailable("phishkit")
        d = request.get_json(silent=True) or {}
        return jsonify(PK.check(d.get("url"), d.get("registrar_lookup", True)))

    @app.post("/api/phishkit/campaign")
    @AUTH.require("viewer")
    def pk_campaign():
        if PK is None:
            return unavailable("phishkit")
        d = request.get_json(silent=True) or {}
        return jsonify(PK.campaign(d.get("q"), d.get("limit", 40)))

    @app.post("/api/phishkit/takedown")
    @AUTH.require("analyst")
    def pk_takedown():
        if PK is None:
            return unavailable("phishkit")
        d = request.get_json(silent=True) or {}
        return jsonify(PK.takedown_open(d.get("url"), d.get("brand"),
                                        user_fn()["username"]))

    @app.put("/api/phishkit/takedown/<int:takedown_id>")
    @AUTH.require("analyst")
    def pk_takedown_update(takedown_id):
        if PK is None:
            return unavailable("phishkit")
        d = request.get_json(silent=True) or {}
        out = PK.takedown_update(takedown_id, d.get("status", ""),
                                 user_fn()["username"])
        if out.get("status") == "error":
            return jsonify(out), 400
        return jsonify(out)

    @app.get("/api/phishkit/takedowns")
    @AUTH.require("viewer")
    def pk_takedowns():
        if PK is None:
            return unavailable("phishkit")
        return jsonify(PK.takedowns(request.args.get("status"),
                                    request.args.get("limit", 50, type=int)))

    # ------------------------------------------------------------- supplychain
    @app.post("/api/supplychain/check")
    @AUTH.require("analyst")
    def sc_check():
        if SC is None:
            return unavailable("supplychain")
        d = request.get_json(silent=True) or {}
        return jsonify(SC.check(d.get("brand"), d.get("registries"),
                                d.get("variants", 40)))

    @app.post("/api/supplychain/watch")
    @AUTH.require("analyst")
    def sc_watch():
        if SC is None:
            return unavailable("supplychain")
        d = request.get_json(silent=True) or {}
        return jsonify(SC.watch(d.get("brand"), d.get("case_id"),
                                user_fn()["username"]))

    @app.post("/api/supplychain/unwatch")
    @AUTH.require("analyst")
    def sc_unwatch():
        if SC is None:
            return unavailable("supplychain")
        d = request.get_json(silent=True) or {}
        return jsonify(SC.unwatch(d.get("brand")))

    @app.get("/api/supplychain/watch")
    @AUTH.require("viewer")
    def sc_list():
        if SC is None:
            return unavailable("supplychain")
        return jsonify(SC.list_watch())

    @app.post("/api/supplychain/check_all")
    @AUTH.require("analyst")
    def sc_check_all():
        if SC is None:
            return unavailable("supplychain")
        return jsonify(SC.check_all())

    # ------------------------------------------------------------- opsecaudit
    @app.post("/api/opsecaudit/run")
    @AUTH.require("analyst")
    def oa_run():
        if OA is None:
            return unavailable("opsecaudit")
        d = request.get_json(silent=True) or {}
        out = OA.run(d.get("target"), d.get("authorization"),
                     d.get("case_id"), user_fn()["username"])
        if out.get("http"):
            return jsonify(out), out["http"]
        return jsonify(out)

    @app.post("/api/opsecaudit/quick")
    @AUTH.require("analyst")
    def oa_quick():
        if OA is None:
            return unavailable("opsecaudit")
        d = request.get_json(silent=True) or {}
        out = OA.quick(d.get("target"), d.get("authorization"))
        if out.get("http"):
            return jsonify(out), out["http"]
        return jsonify(out)
