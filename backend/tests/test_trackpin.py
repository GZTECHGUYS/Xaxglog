"""Unit tests for the lawful TrackPin workflow (consent + authority packet)."""
import sqlite3
import unittest
from unittest import mock

import db
from modules.trackpin import trackpin as TP


class TrackPinTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(db.SCHEMA)
        self.patch = mock.patch.object(db, "get_db", return_value=self.conn)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.conn.close)

    def test_consent_link_is_one_time_and_returns_a_point(self):
        created = TP.create_operation(
            "Witness check-in", "+14155552671", mode="consent_checkin",
            legal_basis="subject consent", user="analyst1")
        self.assertEqual(created["status"], "ok")
        token = created["consent_token"]
        self.assertTrue(token)
        info = TP.consent_info(token)
        self.assertTrue(info["valid"])
        shared = TP.submit_consent(token, 37.77, -122.42, 30, consent=True)
        self.assertEqual(shared["status"], "ok")
        self.assertEqual(shared["point"]["source"], "consent_link")
        second = TP.submit_consent(token, 37.78, -122.43, 30, consent=True)
        self.assertIn("error", second)

        op_id = created["operation"]["id"]
        got = TP.get_operation(op_id, "analyst1", "analyst")
        self.assertEqual(got["operation"]["point_count"], 1)
        self.assertTrue(got["operation"]["points"][0]["consent"])

    def test_consent_requires_explicit_flag(self):
        created = TP.create_operation("Check-in", "+14155552671", user="analyst1")
        token = created["consent_token"]
        out = TP.submit_consent(token, 1.0, 2.0, consent=False)
        self.assertIn("error", out)
        self.assertTrue(TP.consent_info(token)["valid"])

    def test_manual_point_and_geojson(self):
        created = TP.create_operation("Field note", "jane@example.com",
                                      mode="manual_ingest", user="analyst1")
        op_id = created["operation"]["id"]
        added = TP.add_point(op_id, 51.5, -0.12, 15, source="manual",
                             note="witness report", user="analyst1")
        self.assertEqual(added["status"], "ok")
        gj = TP.geojson(op_id, "analyst1", "analyst")
        self.assertEqual(gj["type"], "FeatureCollection")
        self.assertEqual(len(gj["features"]), 1)

    def test_authority_packet_requires_basis_and_is_not_carrier_access(self):
        created = TP.create_operation(
            "Carrier request", "+14155552671", mode="authority_request",
            legal_basis="warrant W-123", user="analyst1")
        op_id = created["operation"]["id"]
        out = TP.request_authority(op_id, "Carrier Liaison", "W-123",
                                   "warrant W-123", "analyst1")
        self.assertEqual(out["status"], "ok")
        self.assertIn("LAWFUL LOCATION", out["packet"])
        self.assertIn("does not access carrier systems", out["packet"])
        missing = TP.request_authority(op_id, "", "", "", "analyst1")
        self.assertIn("error", missing)

    def test_other_user_cannot_open_operation(self):
        created = TP.create_operation("Private", "jane@example.com", user="analyst1")
        op_id = created["operation"]["id"]
        out = TP.get_operation(op_id, "someone_else", "viewer")
        self.assertIn("error", out)

    def test_case_scope_requires_membership(self):
        now = db.utcnow()
        self.conn.execute(
            "INSERT INTO cases (id,case_number,name,description,legal_basis,status,"
            "created_by,created_at) VALUES (1,'C-1','Test case','','','open',?,?)",
            ("owner", now))
        denied = TP.create_operation("Scoped", "jane@example.com", case_id=1,
                                     user="analyst1", role="analyst")
        self.assertIn("error", denied)
        self.conn.execute(
            "INSERT INTO case_members (case_id,username,permission) VALUES (1,?,?)",
            ("analyst1", "edit"))
        allowed = TP.create_operation("Scoped", "jane@example.com", case_id=1,
                                      user="analyst1", role="analyst")
        self.assertEqual(allowed["status"], "ok")


if __name__ == "__main__":
    unittest.main()
