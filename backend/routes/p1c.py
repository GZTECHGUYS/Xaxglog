"""Route group P1c: flight, maritime, satellite (transport & imagery)."""
from flask import request, jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    FL = _mod("modules.flight.flight", "flight", CAPS)
    MR = _mod("modules.maritime.maritime", "maritime", CAPS)
    ST = _mod("modules.satellite.satellite", "satellite", CAPS)

    # ----------------------------------------------------------------- flight
    @app.post("/api/flight/aircraft")
    @AUTH.require("viewer")
    def fl_aircraft():
        if FL is None:
            return unavailable("flight")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.aircraft(d.get("icao24")))

    @app.post("/api/flight/area")
    @AUTH.require("viewer")
    def fl_area():
        if FL is None:
            return unavailable("flight")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.area(d.get("lamin"), d.get("lomin"),
                               d.get("lamax"), d.get("lomax"),
                               d.get("limit", 100)))

    @app.post("/api/flight/airport")
    @AUTH.require("viewer")
    def fl_airport():
        if FL is None:
            return unavailable("flight")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.airport(d.get("icao"), d.get("kind", "departure"),
                                  d.get("begin"), d.get("end")))

    @app.post("/api/flight/attach")
    @AUTH.require("analyst")
    def fl_attach():
        if FL is None:
            return unavailable("flight")
        d = request.get_json(silent=True) or {}
        return jsonify(FL.attach(d.get("case_id"), d.get("icao24"),
                                 user_fn()["username"]))

    # --------------------------------------------------------------- maritime
    @app.post("/api/maritime/mmsi")
    @AUTH.require("viewer")
    def mr_mmsi():
        if MR is None:
            return unavailable("maritime")
        d = request.get_json(silent=True) or {}
        return jsonify(MR.decode_mmsi(d.get("mmsi")))

    @app.post("/api/maritime/search")
    @AUTH.require("viewer")
    def mr_search():
        if MR is None:
            return unavailable("maritime")
        d = request.get_json(silent=True) or {}
        return jsonify(MR.vessel_search(d.get("q")))

    @app.post("/api/maritime/news")
    @AUTH.require("viewer")
    def mr_news():
        if MR is None:
            return unavailable("maritime")
        d = request.get_json(silent=True) or {}
        return jsonify(MR.maritime_news(d.get("query"),
                                        d.get("timespan", "3month"),
                                        d.get("maxrecords", 25)))

    # -------------------------------------------------------------- satellite
    @app.post("/api/satellite/preview")
    @AUTH.require("viewer")
    def st_preview():
        if ST is None:
            return unavailable("satellite")
        d = request.get_json(silent=True) or {}
        return jsonify(ST.preview(d.get("lat"), d.get("lon"),
                                  d.get("layer", "modis_truecolor"),
                                  d.get("date"), d.get("zoom", 9)))

    @app.post("/api/satellite/scenes")
    @AUTH.require("viewer")
    def st_scenes():
        if ST is None:
            return unavailable("satellite")
        d = request.get_json(silent=True) or {}
        return jsonify(ST.scene_search(bbox=d.get("bbox"), point=d.get("point"),
                                       datetime_range=d.get("datetime_range"),
                                       collection=d.get("collection", "sentinel-2-l2a"),
                                       max_cloud=d.get("max_cloud", 20),
                                       limit=d.get("limit", 20)))

    @app.get("/api/satellite/layers")
    @AUTH.require("viewer")
    def st_layers():
        if ST is None:
            return unavailable("satellite")
        return jsonify(ST.layers())
