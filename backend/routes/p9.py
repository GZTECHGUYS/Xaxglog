"""Route group P9: Phase 1-12 platform services.

Kept separate so a failure in the upgrade layer flips one CAPS flag instead of
taking down the base dashboard.  The package owns its own SQLite tables and
reuses the shared audit/evidence store.
"""
from flask import jsonify


def register(app, CAPS, user_fn, AUTH, _mod, unavailable):
    PLATFORM = _mod("modules.platform.routes", "platform_ops", CAPS)
    if PLATFORM is None:
        @app.get("/api/platform/phases")
        def platform_unavailable():
            return jsonify({"status": "error",
                            "error": "platform_ops module unavailable"}), 503
        return
    PLATFORM.register(app, CAPS, user_fn, AUTH, unavailable)
