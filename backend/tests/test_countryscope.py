"""Tests for country-scoped search.

Network calls are mocked. Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

import db
from modules.countryscope import countryscope as CS


class _NoAudit(unittest.TestCase):
    def setUp(self):
        self.audit = mock.patch.object(db, "audit")
        self.audit.start()
        self.addCleanup(self.audit.stop)


class CountryScopeTests(_NoAudit):
    def test_catalog_and_profile(self):
        rows = CS.countries()
        self.assertGreaterEqual(len(rows), 60)
        self.assertEqual(CS.profile("UK")["iso2"], "GB")
        us = CS.profile("US")
        self.assertEqual(us["status"], "ok")
        source_ids = {s["id"] for s in us["sources"]}
        self.assertIn("company_registry", source_ids)
        self.assertIn("procurement", source_ids)
        self.assertIn("courts", source_ids)
        self.assertIn("charity", source_ids)

    def test_site_scope_combines_cctld_and_server_country(self):
        asn = {"country": "Germany", "country_code": "DE", "org": "Example Host",
               "hosting": True}
        with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), \
                mock.patch("modules.infra.infra.asn_lookup", return_value=asn), \
                mock.patch("modules.infra.infra.ptr_lookup", return_value="host.example"):
            out = CS.search("https://example.de/path", "DE", include_live=False)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["kind"], "site")
        self.assertEqual(out["scope"]["match"], "high")
        self.assertTrue(out["scope"]["ccTLD_match"])
        self.assertTrue(out["scope"]["ip_country_match"])
        self.assertEqual(out["scope"]["ip_country_code"], "DE")
        ids = {s["id"] for s in out["sources"]}
        self.assertTrue({"rdap", "crt", "urlscan", "wayback"} <= ids)

    def test_site_scope_marks_cctld_match_as_medium(self):
        asn = {"country": "United States", "country_code": "US", "org": "US Host"}
        with mock.patch("socket.gethostbyname", return_value="5.6.7.8"), \
                mock.patch("modules.infra.infra.asn_lookup", return_value=asn), \
                mock.patch("modules.infra.infra.ptr_lookup", return_value=""):
            out = CS.search("example.de", "DE", include_live=False)
        self.assertEqual(out["scope"]["match"], "medium")
        self.assertTrue(out["scope"]["ccTLD_match"])
        self.assertFalse(out["scope"]["ip_country_match"])

    def test_name_scope_uses_gleif_and_us_live_sources(self):
        gleif = {
            "status": "ok", "count": 2, "results": [
                {"name": "Acme US", "lei": "LEI-US", "legal_country": "US",
                 "hq_country": "US", "jurisdiction": "US-DE"},
                {"name": "Acme DE", "lei": "LEI-DE", "legal_country": "DE",
                 "hq_country": "DE", "jurisdiction": "DE"},
            ],
        }
        proc = {"status": "ok", "count": 1, "results": [
            {"awardee": "Acme US", "source": "usaspending",
             "url": "https://www.usaspending.gov/award/X"},
        ]}
        nonp = {"status": "ok", "count": 1, "results": [
            {"name": "Acme Foundation", "url": "https://projects.propublica.org/nonprofits/x"},
        ]}
        lob = {"status": "ok", "count": 0, "results": []}
        with mock.patch.object(CS, "_gleif", return_value=gleif), \
                mock.patch.object(CS, "_procurement", return_value=proc), \
                mock.patch.object(CS, "_nonprofit", return_value=nonp), \
                mock.patch.object(CS, "_lobbying", return_value=lob):
            out = CS.search("Acme", "US")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["scope"]["match"], "high")
        self.assertEqual(out["scope"]["gleif_country_matches"], 1)
        types = {s["type"] for s in out["scope"]["signals"]}
        self.assertTrue({"gleif_jurisdiction", "procurement_award",
                         "nonprofit_match"} <= types)
        self.assertEqual(set(out["scope"]["live"]),
                         {"gleif", "procurement", "nonprofit", "lobbying"})
        self.assertEqual(out["summary"]["match"], "high")

    def test_name_requires_a_country(self):
        out = CS.search("Jane Doe", "auto")
        self.assertEqual(out["status"], "needs_country")
        self.assertIn("countries", out)

    def test_phone_scope_compares_number_plan_country(self):
        fake = {
            "status": "ok", "parsed": {"iso_region": "DE"},
            "signals": [{"type": "phone_region", "value": "Berlin"}],
        }
        with mock.patch("modules.deep_search.location.phone_signals",
                        return_value=fake):
            out = CS.search("+49 30 123456", "DE", include_live=False)
        self.assertEqual(out["kind"], "phone")
        self.assertEqual(out["scope"]["match"], "high")
        self.assertTrue(out["scope"]["country_match"])

    def test_auto_detects_cctld(self):
        asn = {"country": "France", "country_code": "FR", "org": "FR Host"}
        with mock.patch("socket.gethostbyname", return_value="9.9.9.9"), \
                mock.patch("modules.infra.infra.asn_lookup", return_value=asn), \
                mock.patch("modules.infra.infra.ptr_lookup", return_value=""):
            out = CS.search("example.fr", "auto", include_live=False)
        self.assertEqual(out["country"]["iso2"], "FR")
        self.assertTrue(out["country_inferred"])


if __name__ == "__main__":
    unittest.main()
