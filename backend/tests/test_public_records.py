"""Tests for public-records modules: procurement, lobbying, nonprofit.

All network calls are mocked. Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from types import SimpleNamespace
from unittest import mock

import db
from modules.lobbying import lobbying as LB
from modules.nonprofit import nonprofit as NP
from modules.procurement import procurement as PR


def _resp(data=None, code=200):
    return SimpleNamespace(status_code=code, json=lambda: data or {})


class _NoAudit(unittest.TestCase):
    def setUp(self):
        self.audit = mock.patch.object(db, "audit")
        self.audit.start()
        self.addCleanup(self.audit.stop)


class ProcurementTests(_NoAudit):
    def test_merges_us_and_eu_results(self):
        def fake_post(url, payload, timeout=25):
            if "usaspending" in url:
                return _resp({
                    "results": [{
                        "Award ID": "AA-1", "Recipient Name": "Acme Corp",
                        "Award Amount": 12345.0, "Awarding Agency": "DoD",
                        "Awarding Sub Agency": "Army", "Start Date": "2026-01-01",
                        "End Date": "2026-12-31", "Description": "Widgets",
                        "generated_internal_id": "CONT_AWD_1",
                    }],
                    "page_metadata": {"total": 1},
                })
            return _resp({
                "notices": [{
                    "publication-number": "123-2026",
                    "notice-title": {"eng": "Widget tender"},
                    "buyer-name": {"eng": "EU Buyer"},
                    "winner-name": {"eng": "Acme Corp"},
                    "publication-date": "2026-02-01",
                    "estimated-value-lot": "50000",
                    "links": {"html": "https://ted.europa.eu/en/notice/-/detail/123-2026"},
                }],
                "totalNoticeCount": 1,
            })

        with mock.patch.object(PR, "_post_json", side_effect=fake_post):
            out = PR.search("Acme", country="all", limit=5)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["sources"]["usaspending"]["status"], "ok")
        self.assertEqual(out["sources"]["ted"]["status"], "ok")
        self.assertEqual({r["source"] for r in out["results"]},
                         {"usaspending", "ted"})
        us = next(r for r in out["results"] if r["source"] == "usaspending")
        self.assertEqual(us["awardee"], "Acme Corp")
        self.assertIn("usaspending.gov/award/CONT_AWD_1", us["url"])

    def test_case_artifact_is_stored(self):
        with mock.patch.object(PR, "_post_json",
                               return_value=_resp({"results": []})), \
                mock.patch.object(db, "store_artifact") as store:
            out = PR.search("Acme", country="us", case_id=7, user="analyst")
        self.assertEqual(out["status"], "ok")
        store.assert_called_once()
        args = store.call_args[0]
        self.assertEqual(args[0], 7)
        self.assertEqual(args[2], "procurement")
        self.assertEqual(args[5], "analyst")

    def test_validation_and_blocked_source(self):
        self.assertEqual(PR.search("")["status"], "error")
        self.assertEqual(PR.search("Acme", country="mars")["status"], "error")

        def fake_post(url, payload, timeout=25):
            if "usaspending" in url:
                return _resp({"results": []})
            return _resp(code=403)

        with mock.patch.object(PR, "_post_json", side_effect=fake_post):
            out = PR.search("Acme", country="all")
        self.assertEqual(out["sources"]["ted"]["status"], "blocked")
        self.assertEqual(out["status"], "ok")


class LobbyingTests(_NoAudit):
    def test_client_and_registrant_results_are_deduped(self):
        filing = {
            "id": 1,
            "client": {"name": "Acme Corp"},
            "registrant": {"name": "Lobby LLP"},
            "lobbyists": [{"lobbyist": {"first_name": "Jane", "last_name": "Doe"}}],
            "lobbying_activities": [{
                "general_issue_code_display": "Taxation",
                "description": "Tax credits",
            }],
            "income": "120000",
            "filing_year": 2026,
            "filing_period": "first_quarter",
            "dt_posted": "2026-04-20",
            "url": "/filings/public/filing/1",
        }

        def fake_get(url, params=None, timeout=25):
            if (params or {}).get("client_name"):
                return _resp({"count": 1, "results": [filing]})
            return _resp({"count": 1, "results": [filing]})

        with mock.patch.object(LB, "_get", side_effect=fake_get):
            out = LB.search("Acme", year=2026, limit=10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["count"], 1)
        row = out["results"][0]
        self.assertEqual(row["client"], "Acme Corp")
        self.assertEqual(row["registrant"], "Lobby LLP")
        self.assertEqual(row["lobbyists"], ["Jane Doe"])
        self.assertIn("Taxation", row["issues"][0])
        self.assertTrue(row["url"].startswith("https://lda.senate.gov/"))

    def test_empty_query_is_rejected(self):
        self.assertEqual(LB.search("")["status"], "error")


class NonprofitTests(_NoAudit):
    def test_search_and_ein_lookup(self):
        org = {
            "ein": 123456789, "name": "Acme Foundation", "city": "New York",
            "state": "NY", "ntee_code": "T20", "subseccd": 3,
            "ruling_date": "2001-01-01", "score": 1.0,
        }

        def fake_get(url, params=None, timeout=25):
            if "search.json" in url:
                return _resp({"total_results": 1, "organizations": [org]})
            return _resp({
                "organization": org,
                "filings_with_data": [{
                    "tax_prd_yr": 2024, "formtype": 990,
                    "totrevenue": 500000, "totfuncexpns": 400000,
                    "totassetsend": 900000,
                    "pdf_url": "https://example.com/990.pdf",
                }],
                "filings_without_data": [{}, {}],
            })

        with mock.patch.object(NP, "_get", side_effect=fake_get):
            found = NP.search("Acme", state="NY")
            detail = NP.organization("12-3456789")
        self.assertEqual(found["status"], "ok")
        self.assertEqual(found["count"], 1)
        self.assertEqual(found["results"][0]["ein"], "123456789")
        self.assertEqual(detail["status"], "ok")
        self.assertEqual(detail["ein"], "123456789")
        self.assertEqual(detail["filings"][0]["revenue"], 500000)
        self.assertEqual(detail["filings_without_data"], 2)

    def test_invalid_ein_is_rejected_without_request(self):
        with mock.patch.object(NP, "_get") as get:
            out = NP.organization("123")
        self.assertEqual(out["status"], "error")
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
