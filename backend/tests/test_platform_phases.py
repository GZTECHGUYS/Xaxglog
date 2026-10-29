"""Tests for the Phase 1-12 platform layer and the three reported regressions."""
import os
import sys
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.deep_search import social
from modules.platform import collab, core, ecosystem, ops, store


class SocialCoverageRegressionTests(unittest.TestCase):
    def test_name_coverage_does_not_label_public_search_as_handle_only(self):
        cov = social.name_search_coverage()
        self.assertEqual(cov["total_platforms"], len(social.PLATFORMS))
        self.assertEqual(
            cov["direct_name_apis"] + cov["public_search_link_out_count"]
            + cov["handle_only_count"],
            cov["total_platforms"],
        )
        self.assertGreater(cov["public_search_link_out_count"], 50)
        self.assertLess(cov["handle_only_count"], 10)
        self.assertNotIn("GitHub", cov["handle_only"])
        self.assertIn("GitHub", cov["handle_matrix_name_searchable"])

    def test_name_search_links_are_explicit_and_not_evidence(self):
        rows = social.name_search_links("Jane Doe")
        self.assertEqual(len(rows), len(social.PLATFORMS))
        modes = {r["mode"] for r in rows}
        self.assertEqual(modes, {"direct_api", "search_link", "handle_only"})
        for row in rows:
            self.assertFalse(row["automatic_evidence"])
            if row["mode"] == "search_link":
                self.assertIn("Jane+Doe", row["url"])


class ForensicsOptionalDependencyTests(unittest.TestCase):
    def test_web_tools_imports_without_optional_packages(self):
        from modules.forensics import web_tools
        out = web_tools.get_ip_info("8.8.8.8")
        self.assertIsInstance(out, dict)
        if web_tools.ipinfo is None:
            self.assertIn("error", out)

    def test_file_tools_degrades_without_pillow(self):
        from modules.forensics import file_tools
        if file_tools.Image is not None:
            self.skipTest("Pillow is installed; optional-dependency fallback not exercised")
        out = file_tools.get_exif(None)
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)


class PlatformStoreTests(unittest.TestCase):
    case_id = 987654

    def setUp(self):
        store.ensure_schema()

    def test_graph_timeline_and_provenance_round_trip(self):
        person = store.upsert_entity(self.case_id, "person", "Jane Test",
                                     label="Jane", confidence=0.8)
        email = store.upsert_entity(self.case_id, "email", "jane@example.org")
        edge = store.add_edge(self.case_id, person["id"], email["id"], "owns")
        self.assertTrue(edge["id"])
        bundle = store.graph(self.case_id)
        self.assertGreaterEqual(bundle["counts"]["nodes"], 2)
        self.assertGreaterEqual(bundle["counts"]["edges"], 1)
        event = store.add_timeline(self.case_id, None, "observation", "Seen together")
        self.assertTrue(event["id"])
        prov = store.add_provenance(self.case_id, source="unit-test",
                                    status="fragile", sha256="a" * 64)
        self.assertEqual(prov["sha256"], "a" * 64)
        self.assertGreaterEqual(len(store.timeline(self.case_id)), 1)
        self.assertGreaterEqual(len(store.provenance(self.case_id)), 1)
        matches = store.resolve_entity("Jane Tst", self.case_id)
        self.assertTrue(matches)

    def test_workspace_comment_and_assignment(self):
        ws = store.workspace_create("Test Workspace " + uuid.uuid4().hex[:6],
                                    "unit test", "admin")
        self.assertTrue(ws["id"])
        comment = collab.add_comment(ws["id"], "admin", "review this", case_id=self.case_id)
        self.assertTrue(comment["comment"]["id"])
        assignment = collab.add_assignment(ws["id"], "review", "admin", case_id=self.case_id)
        self.assertTrue(assignment["assignment"]["id"])
        listed = collab.list_comments(ws["id"])
        self.assertEqual(listed["count"], 1)
        resolved = collab.resolve_comment(comment["comment"]["id"])
        self.assertTrue(resolved["comment"]["resolved"])


class PackAndPluginTests(unittest.TestCase):
    def test_pack_signature_and_rollback(self):
        suffix = uuid.uuid4().hex[:8]
        name = "test-pack-" + suffix
        secret = "unit-test-secret"
        manifests = []
        for version in ("1.0.0", "1.1.0"):
            manifests.append({
                "name": name, "version": version, "min_app": "1.0.0",
                "modules": [{"id": "m_" + version.replace(".", "_"),
                             "label": "Test " + version,
                             "probe_type": "link_out",
                             "url": "https://example.org/{query}"}],
            })
        try:
            for manifest in manifests:
                sig = ops.pack_signature(manifest, secret)
                out = ops.install_pack(manifest, sig, secret=secret)
                self.assertEqual(out["status"], "installed", out)
                self.assertTrue(out["signed"])
            bad = ops.install_pack(manifests[0], "bad", secret=secret)
            self.assertEqual(bad["status"], "rejected")
            rollback = ops.rollback_pack(name, "1.0.0")
            self.assertEqual(rollback["status"], "ok")
            self.assertEqual(rollback["active"], "1.0.0")
            from modules.module_registry import registry
            self.assertIsNotNone(registry.get("m_1_0_0"))
            self.assertIsNone(registry.get("m_1_1_0"))
        finally:
            for manifest in manifests:
                path = ops._pack_path(manifest["name"], manifest["version"])
                if os.path.exists(path):
                    os.remove(path)
            try:
                import db as DB
                DB.get_db().execute("DELETE FROM module_packs WHERE name=?", (name,))
                DB.get_db().commit()
            except Exception:
                pass
            try:
                from modules.module_registry import registry
                registry.reload()
            except Exception:
                pass

    def test_plugin_is_declarative_only(self):
        good = ecosystem.validate_plugin({
            "name": "unit-plugin", "version": "1.0.0", "kind": "link_out",
            "probe_type": "link_out", "url": "https://example.org/{query}",
        })
        self.assertTrue(good["valid"])
        bad = ecosystem.validate_plugin({
            "name": "bad-plugin", "version": "1.0.0", "kind": "source",
            "entrypoint": "evil.py",
        })
        self.assertFalse(bad["valid"])


class OpsAndObservabilityTests(unittest.TestCase):
    def test_runtime_self_test_and_metrics(self):
        runtime = ops.runtime_info()
        self.assertEqual(runtime["app"], "Xaxglog")
        self.assertIn("linux-deb", runtime["build_targets"])
        self.assertIn("checks", ops.self_test())
        self.assertIn("xaxglog_up", ecosystem.metrics())
        health = ecosystem.health()
        self.assertIn(health["status"], ("ok", "degraded"))

    def test_ssrf_guard_blocks_loopback(self):
        out = ops.ssrf_check("http://127.0.0.1:5000/")
        self.assertFalse(out["allowed"])

    def test_retention_preview_is_dry_run(self):
        out = ecosystem.retention_preview(1)
        self.assertTrue(out["dry_run"])
        self.assertIn("counts", out)


class PlatformRouteTests(unittest.TestCase):
    def test_routes_are_registered_and_require_auth(self):
        import app as app_module
        client = app_module.app.test_client()
        self.assertEqual(client.get("/api/platform/phases").status_code, 401)
        login = client.post("/api/auth/login", json={
            "username": "admin", "password": os.getenv("XAXGLOG_ADMIN_PASSWORD", "xaxglog-admin"),
        })
        if login.status_code != 200:
            self.skipTest("admin login unavailable in this environment")
        token = login.get_json()["token"]
        headers = {"Authorization": "Bearer " + token}
        r = client.get("/api/platform/phases", headers=headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["count"], 12)
        r = client.get("/api/platform/social/coverage", headers=headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("coverage", r.get_json())


if __name__ == "__main__":
    unittest.main()
