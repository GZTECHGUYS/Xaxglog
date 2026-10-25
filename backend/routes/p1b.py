"""Route group P1b: exposure, imgverify, synthetic, brandguard, docintel,
filings, feedstream, browserrender, identitytimeline."""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    EX = _mod("modules.exposure.exposure", "exposure", CAPS)
    IV = _mod("modules.imgverify.imgverify", "imgverify", CAPS)
    SY = _mod("modules.synthetic.synthetic", "synthetic", CAPS)
    BG = _mod("modules.brandguard.brandguard", "brandguard", CAPS)
    DI = _mod("modules.docintel.docintel", "docintel", CAPS)
    FL = _mod("modules.filings.filings", "filings", CAPS)
    FS = _mod("modules.feedstream.feedstream", "feedstream", CAPS)
    BR = _mod("modules.browserrender.browserrender", "browserrender", CAPS)
    IT = _mod("modules.identitytimeline.identitytimeline", "identitytimeline", CAPS)

    # -------------------------------------------------------------- exposure
    @app.post("/api/exposure/assess")
    @AUTH.require("analyst")
    def ex_assess():
        if EX is None:
            return unavailable("exposure")
        d = request.get_json(silent=True) or {}
        return jsonify(EX.assess(d.get("target")))

    @app.post("/api/exposure/watch")
    @AUTH.require("analyst")
    def ex_watch():
        if EX is None:
            return unavailable("exposure")
        d = request.get_json(silent=True) or {}
        return jsonify(EX.watch(d.get("target"), d.get("case_id"),
                                user_fn()["username"]))

    @app.post("/api/exposure/unwatch")
    @AUTH.require("analyst")
    def ex_unwatch():
        if EX is None:
            return unavailable("exposure")
        d = request.get_json(silent=True) or {}
        return jsonify(EX.unwatch(d.get("target")))

    @app.get("/api/exposure/watch")
    @AUTH.require("viewer")
    def ex_list():
        if EX is None:
            return unavailable("exposure")
        return jsonify(EX.list_watch(request.args.get("case_id", type=int)))

    @app.post("/api/exposure/check_all")
    @AUTH.require("analyst")
    def ex_check_all():
        if EX is None:
            return unavailable("exposure")
        return jsonify(EX.check_all())

    # ------------------------------------------------------------- imgverify
    @app.post("/api/imgverify/hashes")
    @AUTH.require("analyst")
    def iv_hashes():
        if IV is None:
            return unavailable("imgverify")
        d = request.get_json(silent=True) or {}
        return jsonify(IV.hashes(d.get("path")))

    @app.post("/api/imgverify/attach")
    @AUTH.require("analyst")
    def iv_attach():
        if IV is None:
            return unavailable("imgverify")
        d = request.get_json(silent=True) or {}
        return jsonify(IV.attach(d.get("case_id"), d.get("path"),
                                 user_fn()["username"]))

    @app.post("/api/imgverify/similar")
    @AUTH.require("viewer")
    def iv_similar():
        if IV is None:
            return unavailable("imgverify")
        d = request.get_json(silent=True) or {}
        return jsonify(IV.similar(d.get("case_id"), d.get("path"),
                                  d.get("threshold", 10), d.get("limit", 20)))

    @app.get("/api/imgverify/reverse_links")
    @AUTH.require("viewer")
    def iv_reverse():
        if IV is None:
            return unavailable("imgverify")
        return jsonify(IV.reverse_links(request.args.get("url")))

    # -------------------------------------------------------------- synthetic
    @app.post("/api/synthetic/assess")
    @AUTH.require("analyst")
    def sy_assess():
        if SY is None:
            return unavailable("synthetic")
        d = request.get_json(silent=True) or {}
        return jsonify(SY.assess(d.get("path"), d.get("case_id"),
                                 user_fn()["username"]))

    # ------------------------------------------------------------- brandguard
    @app.post("/api/brandguard/generate")
    @AUTH.require("analyst")
    def bg_generate():
        if BG is None:
            return unavailable("brandguard")
        d = request.get_json(silent=True) or {}
        return jsonify(BG.generate(d.get("brand"),
                                   max_out=d.get("max", 200)))

    @app.post("/api/brandguard/check")
    @AUTH.require("viewer")
    def bg_check():
        if BG is None:
            return unavailable("brandguard")
        d = request.get_json(silent=True) or {}
        return jsonify(BG.check(d.get("candidate"), d.get("probe", True)))

    @app.post("/api/brandguard/sweep")
    @AUTH.require("analyst")
    def bg_sweep():
        if BG is None:
            return unavailable("brandguard")
        d = request.get_json(silent=True) or {}
        return jsonify(BG.sweep(d.get("brand"), max_check=d.get("max", 120),
                                case_id=d.get("case_id"),
                                queried_by=user_fn()["username"]))

    @app.post("/api/brandguard/fast_sweep")
    @AUTH.require("analyst")
    def bg_fast():
        if BG is None:
            return unavailable("brandguard")
        d = request.get_json(silent=True) or {}
        return jsonify(BG.fast_sweep(d.get("brand"),
                                     workers=d.get("workers", 24)))

    # --------------------------------------------------------------- docintel
    @app.post("/api/docintel/analyze")
    @AUTH.require("analyst")
    def di_analyze():
        if DI is None:
            return unavailable("docintel")
        d = request.get_json(silent=True) or {}
        out = DI.analyze(d.get("path"), d.get("case_id"),
                         user_fn()["username"])
        if out.get("status") == "ok" and d.get("summary"):
            out["summary"] = DI.summarize(out["report"])
        return jsonify(out)

    # ---------------------------------------------------------------- filings
    @app.post("/api/filings/company")
    @AUTH.require("viewer")
    def fl_company():
        if FL is None:
            return unavailable("filings")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.company(d.get("q")))

    @app.post("/api/filings/filings")
    @AUTH.require("viewer")
    def fl_filings():
        if FL is None:
            return unavailable("filings")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.filings(d.get("cik"), d.get("forms"),
                                  d.get("limit", 25)))

    @app.post("/api/filings/fulltext")
    @AUTH.require("viewer")
    def fl_fulltext():
        if FL is None:
            return unavailable("filings")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.fulltext(d.get("q"), d.get("forms"),
                                   d.get("date_range"), d.get("limit", 25)))

    @app.post("/api/filings/insider")
    @AUTH.require("viewer")
    def fl_insider():
        if FL is None:
            return unavailable("filings")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.insider(d.get("q"), d.get("limit", 20)))

    # ------------------------------------------------------------- feedstream
    @app.post("/api/feedstream/run")
    @AUTH.require("analyst")
    def fs_run():
        if FS is None:
            return unavailable("feedstream")
        d = request.get_json(silent=True) or {}
        return jsonify(FS.run_once(d.get("feeds")))

    @app.get("/api/feedstream/status")
    @AUTH.require("viewer")
    def fs_status():
        if FS is None:
            return unavailable("feedstream")
        return jsonify(FS.status())

    # ----------------------------------------------------------- browserrender
    @app.get("/api/browserrender/caps")
    @AUTH.require("viewer")
    def br_caps():
        if BR is None:
            return unavailable("browserrender")
        return jsonify(BR.caps())

    @app.post("/api/browserrender/render")
    @AUTH.require("analyst")
    def br_render():
        if BR is None:
            return unavailable("browserrender")
        d = request.get_json(silent=True) or {}
        return jsonify(BR.render(d.get("url"), d.get("wait_ms", 1500),
                                 d.get("screenshot_path")))

    @app.post("/api/browserrender/text")
    @AUTH.require("analyst")
    def br_text():
        if BR is None:
            return unavailable("browserrender")
        d = request.get_json(silent=True) or {}
        return jsonify(BR.text(d.get("url"), d.get("wait_ms", 1500)))

    @app.post("/api/browserrender/shutdown")
    @AUTH.require("admin")
    def br_shutdown():
        if BR is None:
            return unavailable("browserrender")
        return jsonify(BR.shutdown())

    # -------------------------------------------------------- identitytimeline
    @app.post("/api/identitytimeline/timeline")
    @AUTH.require("viewer")
    def it_timeline():
        if IT is None:
            return unavailable("identitytimeline")
        d = request.get_json(silent=True) or {}
        return jsonify(IT.timeline(d.get("url"), d.get("limit", 5000)))

    @app.post("/api/identitytimeline/age")
    @AUTH.require("viewer")
    def it_age():
        if IT is None:
            return unavailable("identitytimeline")
        d = request.get_json(silent=True) or {}
        return jsonify(IT.account_age_hint(d.get("url")))

    @app.post("/api/identitytimeline/multi")
    @AUTH.require("analyst")
    def it_multi():
        if IT is None:
            return unavailable("identitytimeline")
        d = request.get_json(silent=True) or {}
        return jsonify(IT.multi(d.get("handles"), d.get("base_urls") or []))
