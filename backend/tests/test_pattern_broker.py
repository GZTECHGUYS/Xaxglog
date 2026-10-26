"""Tests for the Pattern Tracker and public broker-exposure modules.

Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import sqlite3
import unittest
from types import SimpleNamespace
from unittest import mock

import db
from modules.broker import broker as BRK
from modules.pattern import emailgraph as EG
from modules.pattern import pattern as PAT
from modules.trackers import trackers as TRK


class _MemoryDb(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(db.SCHEMA)
        self.patch = mock.patch.object(db, "get_db", return_value=self.conn)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.conn.close)
        PAT._ready = False


class PatternTests(_MemoryDb):
    def test_links_and_interactions_rank_contacts(self):
        added = PAT.add_link("person", "Jane Doe", "org", "Acme Ltd",
                             "member_of", "unit-test", 0.9)
        self.assertNotIn("error", added)
        self.assertEqual(PAT.list_links("Jane Doe")["count"], 1)

        events = [
            {"actor": "Jane Doe", "target": "bob", "platform": "github",
             "kind": "reply", "ts": f"2026-10-0{i}T12:00:00Z",
             "url": f"https://example.com/post/{i}"}
            for i in range(1, 6)
        ]
        result = PAT.ingest_events(events)
        self.assertEqual(result["inserted"], 5)
        self.assertEqual(result["skipped"], 0)

        contacts = PAT.frequent_contacts("Jane Doe")
        self.assertEqual(contacts["contacts"][0]["value"], "bob")
        self.assertTrue(contacts["contacts"][0]["qualified"])

        pnl = PAT.pnl("Jane Doe")
        self.assertEqual(pnl["interactions"], 5)
        self.assertEqual(pnl["peak_hour_utc"], 12)
        self.assertIn("github", pnl["platforms"])

    def test_url_and_ip_ledgers(self):
        urls = PAT.record_urls(
            "Jane Doe",
            ["https://example.com/a", "https://example.com/b", "not-a-url"],
            source="unit-test")
        self.assertEqual(urls["inserted"], 2)
        self.assertEqual(PAT.url_diet("Jane Doe")["total"], 2)

        ips = PAT.add_ips("Jane Doe", ["8.8.8.8", "not-an-ip"],
                          source="manual")
        self.assertEqual(ips["inserted"], 1)
        ledger = PAT.ip_ledger("Jane Doe")
        self.assertEqual(ledger["count"], 1)
        self.assertEqual(ledger["ips"][0]["ip"], "8.8.8.8")

    def test_email_thread_graph(self):
        raw1 = (
            "Message-ID: <a@example.com>\n"
            "From: Alice <alice@example.com>\n"
            "To: Bob <bob@example.com>\n"
            "Subject: Hello\n"
            "Date: Mon, 20 Oct 2026 10:00:00 +0000\n\nbody\n"
        )
        raw2 = (
            "Message-ID: <b@example.com>\n"
            "In-Reply-To: <a@example.com>\n"
            "From: Bob <bob@example.com>\n"
            "To: Alice <alice@example.com>\n"
            "Subject: Re: Hello\n"
            "Date: Mon, 20 Oct 2026 11:00:00 +0000\n\nbody\n"
        )
        out = EG.analyze([raw1, raw2], ingest=False)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["messages"], 2)
        self.assertEqual(out["thread_count"], 1)
        self.assertEqual(len(out["participants"]), 2)

    def test_pattern_tracker_kinds_are_registered(self):
        kinds = {row["kind"] for row in TRK.registry()}
        self.assertTrue({"new_contact", "contact_drop", "cadence_change"} <= kinds)


class BrokerTests(_MemoryDb):
    def test_catalog_and_validation(self):
        self.assertGreaterEqual(len(BRK.catalog()), 5)
        out = BRK.sweep("", delay=0)
        self.assertEqual(out["status"], "error")
        self.assertIn("name or address", out["error"])

    def test_sweep_hit_blocked_and_clean_statuses(self):
        responses = [
            (SimpleNamespace(status_code=200,
                             text="<h1>Results for Jane Doe</h1><p>2 results</p>"),
             None, ""),
            (SimpleNamespace(status_code=403, text=""), None, ""),
            (SimpleNamespace(status_code=200, text="<html>nothing here</html>"),
             None, ""),
        ]
        with mock.patch.object(BRK, "_fetch", side_effect=responses):
            out = BRK.sweep("Jane Doe",
                            brokers=["whitepages", "spokeo", "radaris"],
                            delay=0)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["hits"], 1)
        self.assertEqual(out["blocked"], 1)
        self.assertEqual(out["clean"], 1)
        self.assertEqual(out["exposure_score"], 50.0)


if __name__ == "__main__":
    unittest.main()
