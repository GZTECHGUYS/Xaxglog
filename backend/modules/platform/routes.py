"""JSON API for the Phase 1-12 platform layer.

Registered by ``routes/p9.py`` so a failure here cannot break the base app.
"""
from __future__ import annotations

import os

from flask import jsonify, request, send_file

from . import collab, core, ecosystem, ops, store


def _bool(value, default=False):
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


def _user(user_fn):
    try:
        return user_fn() or {"username": "system", "role": "viewer"}
    except Exception:
        return {"username": "system", "role": "viewer"}


def register(app, CAPS, user_fn, AUTH, unavailable):
    # ------------------------------------------------------------ phases/overview
    @app.get("/api/platform/phases")
    @AUTH.require("viewer")
    def platform_phases():
        return jsonify(core.phase_catalog())

    @app.get("/api/platform/overview")
    @AUTH.require("viewer")
    def platform_overview():
        return jsonify({
            "status": "ok",
            "phases": core.phase_catalog(),
            "analytics": core.analytics(),
            "runtime": ops.runtime_info(),
            "offline": ops.offline_status(),
        })

    @app.get("/api/platform/analytics")
    @AUTH.require("viewer")
    def platform_analytics():
        return jsonify(core.analytics())

    # ---------------------------------------------------------------- graph/core
    @app.get("/api/platform/graph")
    @AUTH.require("viewer")
    def platform_graph():
        return jsonify({"status": "ok", **store.graph(
            request.args.get("case_id", 0, type=int),
            _int(request.args.get("limit"), 1000, 1, 5000))})

    @app.get("/api/platform/graph/bundle")
    @AUTH.require("viewer")
    def platform_graph_bundle():
        return jsonify(core.graph_bundle(request.args.get("case_id", 0, type=int)))

    @app.post("/api/platform/graph/entities")
    @AUTH.require("analyst")
    def platform_entity_add():
        d = request.get_json(silent=True) or {}
        try:
            out = store.upsert_entity(
                d.get("case_id", 0), d.get("type") or d.get("entity_type") or "unknown",
                d.get("value") or d.get("target") or "", label=d.get("label", ""),
                source=d.get("source", ""), confidence=d.get("confidence"),
                meta=d.get("meta") or {},
            )
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify({"status": "ok", "entity": out})

    @app.post("/api/platform/graph/edges")
    @AUTH.require("analyst")
    def platform_edge_add():
        d = request.get_json(silent=True) or {}
        try:
            out = store.add_edge(
                d.get("case_id", 0), d.get("src_id"), d.get("dst_id"),
                d.get("relation") or d.get("type") or "related",
                weight=d.get("weight", 1.0), source=d.get("source", ""),
                meta=d.get("meta") or {},
            )
        except (TypeError, ValueError) as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify({"status": "ok", "edge": out})

    @app.get("/api/platform/graph/resolve")
    @AUTH.require("viewer")
    def platform_resolve():
        q = request.args.get("q") or request.args.get("query") or ""
        return jsonify({"status": "ok", "query": q, "matches": store.resolve_entity(
            q, request.args.get("case_id", 0, type=int),
            _int(request.args.get("limit"), 20, 1, 200))})

    @app.post("/api/platform/graph/artifact")
    @AUTH.require("analyst")
    def platform_artifact_add():
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        try:
            out = store.add_artifact(
                d.get("case_id", 0), d.get("entity_id"),
                d.get("type") or d.get("artifact_type") or "recon",
                d.get("source") or "manual", d.get("content", ""),
                d.get("queried_by") or u["username"], url=d.get("url", ""),
                access_mode=d.get("access_mode", "public"),
                status=d.get("status", "verified"), meta=d.get("meta") or {},
            )
        except Exception as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify({"status": "ok", "artifact": out})

    @app.post("/api/platform/graph/ingest")
    @AUTH.require("analyst")
    def platform_graph_ingest():
        """Ingest normalized public-source rows into the case graph.

        Input rows are ``{type,value,label?,relation?,source?,url?,status?}``.
        The subject is the graph anchor; every row becomes an entity + edge +
        provenance record.  This is an operator-controlled import, not an
        automatic identity claim.
        """
        d = request.get_json(silent=True) or {}
        case_id = d.get("case_id", 0)
        subject = d.get("subject") or d.get("query") or ""
        subject_type = d.get("subject_type") or "person"
        rows = d.get("rows") or []
        if not subject:
            return jsonify({"status": "error", "error": "subject required"}), 400
        if not isinstance(rows, list) or len(rows) > 500:
            return jsonify({"status": "error", "error": "rows must be a list (max 500)"}), 400
        root = store.upsert_entity(case_id, subject_type, subject,
                                   label=d.get("label", subject),
                                   source="platform.ingest")
        created = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("value"):
                continue
            node = store.upsert_entity(
                case_id, row.get("type") or "unknown", row["value"],
                label=row.get("label", ""), source=row.get("source", ""),
                confidence=row.get("confidence"), meta=row.get("meta") or {},
            )
            edge = store.add_edge(
                case_id, root["id"], node["id"], row.get("relation") or "related",
                weight=row.get("confidence") or 1.0, source=row.get("source", ""),
            )
            prov = store.add_provenance(
                case_id, source=row.get("source") or "platform.ingest",
                url=row.get("url", ""), access_mode=row.get("access_mode", "public"),
                status=row.get("status", "fragile"), entity_id=node["id"],
                meta={"subject": subject, "row": row},
            )
            created.append({"entity": node, "edge": edge, "provenance": prov})
        store.add_timeline(case_id, None, "ingest", f"Ingested {len(created)} rows for {subject}",
                           source="platform.ingest", entity_id=root["id"],
                           content={"subject": subject, "count": len(created)})
        return jsonify({"status": "ok", "subject": root, "created": len(created),
                        "rows": created, "graph": store.graph(case_id)})

    @app.get("/api/platform/timeline")
    @AUTH.require("viewer")
    def platform_timeline():
        return jsonify({"status": "ok", "events": store.timeline(
            request.args.get("case_id", 0, type=int),
            _int(request.args.get("limit"), 500, 1, 5000))})

    @app.post("/api/platform/timeline")
    @AUTH.require("analyst")
    def platform_timeline_add():
        d = request.get_json(silent=True) or {}
        try:
            out = store.add_timeline(
                d.get("case_id", 0), d.get("ts"), d.get("kind") or "observation",
                d.get("title") or "event", detail=d.get("detail", ""),
                source=d.get("source", ""), entity_id=d.get("entity_id"),
                content=d.get("content"),
            )
        except Exception as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify({"status": "ok", "event": out})

    @app.get("/api/platform/provenance")
    @AUTH.require("viewer")
    def platform_provenance():
        return jsonify({"status": "ok", "records": store.provenance(
            request.args.get("case_id", 0, type=int),
            _int(request.args.get("limit"), 500, 1, 5000))})

    @app.post("/api/platform/provenance")
    @AUTH.require("analyst")
    def platform_provenance_add():
        d = request.get_json(silent=True) or {}
        try:
            out = store.add_provenance(
                d.get("case_id", 0), source=d.get("source") or "manual",
                url=d.get("url", ""), access_mode=d.get("access_mode", "public"),
                status=d.get("status", "verified"), sha256=d.get("sha256", ""),
                artifact_id=d.get("artifact_id"), entity_id=d.get("entity_id"),
                meta=d.get("meta") or {},
            )
        except Exception as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify({"status": "ok", "provenance": out})

    # -------------------------------------------------------------------- social
    @app.get("/api/platform/social/coverage")
    @AUTH.require("viewer")
    def platform_social_coverage():
        return jsonify(core.social_coverage())

    @app.post("/api/platform/social/recon")
    @AUTH.require("analyst")
    def platform_social_recon():
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        out = core.social_recon(
            d.get("name") or d.get("query") or "",
            probe=_bool(d.get("probe"), False),
            variants=_bool(d.get("variants"), True),
            case_id=d.get("case_id", 0), user=u["username"],
        )
        return jsonify(out), (200 if out.get("status") == "ok" else 400)

    @app.get("/api/platform/sources/health")
    @AUTH.require("viewer")
    def platform_source_health():
        return jsonify(core.source_health())

    @app.post("/api/platform/sources/health/check")
    @AUTH.require("analyst")
    def platform_source_health_check():
        d = request.get_json(silent=True) or {}
        ids = d.get("ids") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        try:
            from modules.module_registry import engine
            out = engine.verify(
                ids=ids,
                query=d.get("query") or "John Smith",
                checks=_int(d.get("checks"), 2, 1, 3),
                timeout=_int(d.get("timeout"), 8, 2, 30),
                max_workers=_int(d.get("max_workers"), 4, 1, 12),
                persist=_bool(d.get("persist"), False),
                limit=_int(d.get("limit"), 20, 1, 80),
            )
        except Exception as exc:
            return jsonify({"status": "error", "error": str(exc)[:300]}), 500
        return jsonify({"status": "ok", "verification": out,
                        "after": core.source_health()})

    # ------------------------------------------------------------------- runtime
    @app.get("/api/platform/runtime")
    @AUTH.require("viewer")
    def platform_runtime():
        return jsonify(ops.runtime_info())

    @app.post("/api/platform/runtime/self-test")
    @AUTH.require("viewer")
    def platform_self_test():
        return jsonify(ops.self_test())

    # --------------------------------------------------------------------- packs
    @app.get("/api/platform/packs")
    @AUTH.require("viewer")
    def platform_packs():
        return jsonify(ops.pack_list())

    @app.post("/api/platform/packs/validate")
    @AUTH.require("analyst")
    def platform_pack_validate():
        return jsonify(ops.validate_pack((request.get_json(silent=True) or {}).get("manifest") or {}))

    @app.post("/api/platform/packs/install")
    @AUTH.require("admin")
    def platform_pack_install():
        d = request.get_json(silent=True) or {}
        out = ops.install_pack(d.get("manifest") or {}, d.get("signature", ""))
        return jsonify(out), (200 if out.get("status") == "installed" else 400)

    @app.post("/api/platform/packs/<name>/<version>/toggle")
    @AUTH.require("admin")
    def platform_pack_toggle(name, version):
        d = request.get_json(silent=True) or {}
        return jsonify({"status": "ok", "pack": ops.set_pack_enabled(
            name, version, _bool(d.get("enabled"), True))})

    @app.post("/api/platform/packs/rollback")
    @AUTH.require("admin")
    def platform_pack_rollback():
        d = request.get_json(silent=True) or {}
        out = ops.rollback_pack(d.get("name") or "", d.get("version") or None)
        return jsonify(out), (200 if out.get("status") == "ok" else 400)

    # ------------------------------------------------------------------- offline
    @app.get("/api/platform/offline")
    @AUTH.require("viewer")
    def platform_offline():
        return jsonify(ops.offline_status())

    @app.post("/api/platform/offline")
    @AUTH.require("admin")
    def platform_offline_set():
        d = request.get_json(silent=True) or {}
        return jsonify(ops.set_offline(_bool(d.get("offline"), True)))

    @app.post("/api/platform/cache/warm")
    @AUTH.require("analyst")
    def platform_cache_warm():
        return jsonify(ops.warm_cache())

    # ------------------------------------------------------------------ security
    @app.get("/api/platform/security/posture")
    @AUTH.require("viewer")
    def platform_security():
        return jsonify(ops.security_posture())

    @app.post("/api/platform/security/ssrf-check")
    @AUTH.require("analyst")
    def platform_ssrf():
        d = request.get_json(silent=True) or {}
        return jsonify(ops.ssrf_check(d.get("url") or ""))

    @app.get("/api/platform/audit")
    @AUTH.require("admin")
    def platform_audit():
        return jsonify(ops.audit_tail(_int(request.args.get("limit"), 200, 1, 2000)))

    # -------------------------------------------------------------- collaboration
    @app.get("/api/platform/workspaces")
    @AUTH.require("viewer")
    def platform_workspaces():
        u = _user(user_fn)
        return jsonify(collab.overview(u["username"], u["role"]))

    @app.post("/api/platform/workspaces")
    @AUTH.require("analyst")
    def platform_workspace_create():
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        try:
            out = collab.create_workspace(d.get("name") or "", d.get("description", ""), u["username"])
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify(out)

    @app.post("/api/platform/workspaces/<int:workspace_id>/members")
    @AUTH.require("analyst")
    def platform_workspace_member(workspace_id):
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        if not collab.can_manage(workspace_id, u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace owner/admin required"}), 403
        try:
            out = collab.add_member(workspace_id, d.get("username") or "", d.get("role", "analyst"))
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify(out)

    @app.get("/api/platform/workspaces/<int:workspace_id>/comments")
    @AUTH.require("viewer")
    def platform_comments(workspace_id):
        u = _user(user_fn)
        if not collab.can_access(workspace_id, u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        return jsonify(collab.list_comments(workspace_id))

    @app.post("/api/platform/workspaces/<int:workspace_id>/comments")
    @AUTH.require("analyst")
    def platform_comment_add(workspace_id):
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        if not collab.can_access(workspace_id, u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        try:
            out = collab.add_comment(workspace_id, u["username"], d.get("body") or "",
                                     case_id=d.get("case_id", 0),
                                     artifact_id=d.get("artifact_id"),
                                     entity_id=d.get("entity_id"))
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify(out)

    @app.post("/api/platform/comments/<int:comment_id>/resolve")
    @AUTH.require("analyst")
    def platform_comment_resolve(comment_id):
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        comment = store.comment_get(comment_id)
        if not comment:
            return jsonify({"status": "error", "error": "comment not found"}), 404
        if comment.get("workspace_id") and not collab.can_access(
                comment["workspace_id"], u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        return jsonify(collab.resolve_comment(comment_id, _bool(d.get("resolved"), True)))

    @app.get("/api/platform/assignments")
    @AUTH.require("viewer")
    def platform_assignments():
        u = _user(user_fn)
        workspace_id = request.args.get("workspace_id", type=int)
        if workspace_id is not None and not collab.can_access(
                workspace_id, u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        out = collab.list_assignments(
            workspace_id, request.args.get("case_id", type=int),
            request.args.get("status"))
        allowed = collab.allowed_ids(u["username"], u["role"])
        if allowed is not None:
            out["assignments"] = [a for a in out.get("assignments", [])
                                  if a.get("workspace_id") in allowed]
            out["count"] = len(out["assignments"])
        return jsonify(out)

    @app.post("/api/platform/assignments")
    @AUTH.require("analyst")
    def platform_assignment_add():
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        workspace_id = d.get("workspace_id")
        if workspace_id is not None and not collab.can_access(
                workspace_id, u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        try:
            out = collab.add_assignment(
                workspace_id, d.get("title") or "", u["username"],
                case_id=d.get("case_id", 0), detail=d.get("detail", ""),
                assignee=d.get("assignee", ""), due_at=d.get("due_at"))
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify(out)

    @app.post("/api/platform/assignments/<int:assignment_id>")
    @AUTH.require("analyst")
    def platform_assignment_update(assignment_id):
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        assignment = store.assignment_get(assignment_id)
        if not assignment:
            return jsonify({"status": "error", "error": "assignment not found"}), 404
        if assignment.get("workspace_id") and not collab.can_access(
                assignment["workspace_id"], u["username"], u["role"]):
            return jsonify({"status": "error", "error": "workspace access denied"}), 403
        try:
            out = collab.update_assignment(
                assignment_id, status=d.get("status"), assignee=d.get("assignee"),
                due_at=d.get("due_at"))
        except ValueError as exc:
            return jsonify({"status": "error", "error": str(exc)}), 400
        return jsonify(out)

    # --------------------------------------------------------------- performance
    @app.get("/api/platform/performance")
    @AUTH.require("viewer")
    def platform_performance():
        return jsonify(ops.performance())

    @app.post("/api/platform/performance/benchmark")
    @AUTH.require("analyst")
    def platform_benchmark():
        d = request.get_json(silent=True) or {}
        return jsonify(ops.benchmark(_int(d.get("iterations"), 20, 1, 500)))

    # ------------------------------------------------------------------- plugins
    @app.get("/api/platform/plugins")
    @AUTH.require("viewer")
    def platform_plugins():
        return jsonify(ecosystem.list_plugins())

    @app.post("/api/platform/plugins/validate")
    @AUTH.require("analyst")
    def platform_plugin_validate():
        return jsonify(ecosystem.validate_plugin((request.get_json(silent=True) or {}).get("manifest") or {}))

    @app.post("/api/platform/plugins/install")
    @AUTH.require("admin")
    def platform_plugin_install():
        d = request.get_json(silent=True) or {}
        out = ecosystem.install_plugin(d.get("manifest") or {}, _bool(d.get("enabled"), True))
        return jsonify(out), (200 if out.get("status") == "installed" else 400)

    @app.post("/api/platform/plugins/<name>/<version>/toggle")
    @AUTH.require("admin")
    def platform_plugin_toggle(name, version):
        d = request.get_json(silent=True) or {}
        return jsonify(ecosystem.toggle_plugin(name, version, _bool(d.get("enabled"), True)))

    # ----------------------------------------------------------------- compliance
    @app.get("/api/platform/compliance/policy")
    @AUTH.require("viewer")
    def platform_compliance_policy():
        return jsonify(ecosystem.policy())

    @app.get("/api/platform/compliance/retention")
    @AUTH.require("viewer")
    def platform_retention_preview():
        return jsonify(ecosystem.retention_preview(_int(request.args.get("days"), 365, 1, 36500)))

    @app.post("/api/platform/compliance/retention")
    @AUTH.require("admin")
    def platform_retention_run():
        d = request.get_json(silent=True) or {}
        u = _user(user_fn)
        return jsonify(ecosystem.retention_run(
            _int(d.get("days"), 365, 1, 36500),
            _bool(d.get("dry_run"), True), u["username"]))

    @app.get("/api/platform/compliance/export")
    @AUTH.require("analyst")
    def platform_export():
        return jsonify(ecosystem.case_export(request.args.get("case_id", 0, type=int)))

    @app.post("/api/platform/compliance/dsar")
    @AUTH.require("analyst")
    def platform_dsar():
        d = request.get_json(silent=True) or {}
        return jsonify(ecosystem.dsar_plan(d.get("subject") or d.get("query") or ""))

    # --------------------------------------------------------------- observability
    @app.get("/api/platform/health")
    def platform_health():
        return jsonify(ecosystem.health())

    @app.get("/api/platform/metrics")
    def platform_metrics():
        return ecosystem.metrics(), 200, {"Content-Type": "text/plain; version=0.0.4"}

    @app.get("/api/platform/support/diagnostics")
    @AUTH.require("admin")
    def platform_diagnostics():
        return jsonify(ecosystem.diagnostics())

    @app.get("/api/platform/support/bundle")
    @AUTH.require("admin")
    def platform_support_bundle():
        u = _user(user_fn)
        out = ecosystem.support_bundle(u["username"])
        return jsonify(out)

    @app.get("/api/platform/support/bundle/<name>")
    @AUTH.require("admin")
    def platform_support_download(name):
        safe = os.path.basename(name)
        path = os.path.join(ops.SUPPORT_DIR, safe)
        if not os.path.exists(path):
            return jsonify({"status": "error", "error": "bundle not found"}), 404
        return send_file(path, as_attachment=True, download_name=safe)
