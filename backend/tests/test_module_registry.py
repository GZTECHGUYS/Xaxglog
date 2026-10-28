"""Tests for the declarative module registry and compatibility helpers.

No test performs a network call: generic probes are exercised with a fake
``fetch`` and adapter/engine calls are mocked.  Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from modules.module_registry import engine as E
from modules.module_registry import probes as P
from modules.module_registry import registry as R
from modules.module_registry import store as ST
from modules.operator_compat import operator_compat as OC


class RegistryTests(unittest.TestCase):
    def test_registry_has_generic_types_and_honest_counts(self):
        s = R.summary()
        self.assertGreaterEqual(s["total"], 400)
        for ptype in ("json_api_probe", "http_profile_probe", "html_search_probe",
                      "oembed_probe", "adapter_probe", "link_out"):
            self.assertIn(ptype, s["by_probe"], ptype)
        self.assertEqual(s["automatic"], s["verified"] + s["fragile"])
        self.assertEqual(s["live_verified"], s["automatic"])
        self.assertGreater(s["automatic"], 50)
        self.assertGreater(s["link_out"], 50)
        self.assertGreater(s["blocked"], 0)
        self.assertEqual(s["total"], sum(s["by_status"].values()))

    def test_every_module_has_explicit_status_and_probe(self):
        for m in R.modules():
            self.assertIn(m["status"], R.STATUSES, m["id"])
            self.assertIn(m["probe_type"], P.PROBE_TYPES, m["id"])
            self.assertTrue(m["label"], m["id"])
            self.assertTrue(m["category"], m["id"])
            if m["automatic"]:
                self.assertIn(m["status"], R.AUTOMATIC_STATUSES)
                self.assertNotEqual(m["probe_type"], "link_out")

    def test_no_google_or_bing_result_page_is_automatic(self):
        for m in R.modules():
            if m["automatic"] and m["probe_type"] == "html_search_probe":
                host = (m["probe"].get("url") or "").lower()
                self.assertNotIn("google.", host)
                self.assertNotIn("bing.", host)

    def test_select_and_get(self):
        verified = R.select(statuses=["verified"], limit=5)
        self.assertTrue(verified)
        self.assertTrue(all(x["status"] == "verified" for x in verified))
        first = verified[0]
        self.assertIsNotNone(R.get(first["id"]))
        self.assertTrue(R.select(categories=["social"]))
        self.assertTrue(R.select(probe_types=["link_out"], limit=2))

    def test_link_out_prefers_human_page(self):
        m = R.get("crossref")
        link = P.build_link(m, "Jane Doe")
        self.assertIn("search.crossref.org", link)
        self.assertNotIn("api.crossref.org", link)


class StoreTests(unittest.TestCase):
    def test_verification_overlay_is_atomic_and_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "status.json")
            data = ST.set_status({}, "example", "fragile", query="Jane",
                                 checks=2, fragile=True, detail="ok")
            self.assertTrue(ST.save_status(data, path))
            loaded = ST.load_status(path)
            self.assertEqual(loaded["example"]["status"], "fragile")
            self.assertEqual(loaded["example"]["checks"], 2)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class ProbeTests(unittest.TestCase):
    def test_json_api_probe(self):
        body = json.dumps({"items": [
            {"login": "jane", "html_url": "https://example.org/jane", "id": 7},
            {"login": "john", "html_url": "https://example.org/john", "id": 8},
        ]})
        with mock.patch.object(P, "fetch", return_value={
                "status": "ok", "http": 200, "url": "https://api.example/search",
                "text": body, "headers": {}}):
            out = P.json_api_probe({
                "url": "https://api.example/search?q={q}", "items_path": "items",
                "fields": {"name": "login", "url": "html_url", "id": "id"},
                "source": "example", "label": "Example", "category": "code",
                "module_id": "example",
            }, "jane")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["results"][0]["title"], "jane")

    def test_profile_probe_parses_og_and_marks_not_found(self):
        html = ('<html><head><title>Jane Doe</title>'
                '<meta property="og:title" content="Jane Doe">'
                '<meta property="og:description" content="Public profile">'
                '<link rel="canonical" href="https://example.org/jane"></head></html>')
        with mock.patch.object(P, "fetch", return_value={
                "status": "ok", "http": 200, "url": "https://example.org/jane",
                "text": html, "headers": {}}):
            out = P.http_profile_probe({"url": "https://example.org/{u}",
                                        "source": "example", "module_id": "example"},
                                       "jane")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["title"], "Jane Doe")
        self.assertTrue(out["results"][0]["fragile"])

        with mock.patch.object(P, "fetch", return_value={
                "status": "ok", "http": 200, "url": "https://example.org/none",
                "text": "<html><title>User not found</title></html>", "headers": {}}):
            out = P.http_profile_probe({"url": "https://example.org/{u}"}, "none")
        self.assertEqual(out["status"], "not_found")

    def test_search_probe_extracts_links_and_refuses_google(self):
        html = ('<a href="https://news.example/a">Story A</a>'
                '<a href="/login">Login</a>'
                '<a href="https://news.example/b">Story B</a>')
        with mock.patch.object(P, "fetch", return_value={
                "status": "ok", "http": 200, "url": "https://search.example/?q=x",
                "text": html, "headers": {}}):
            out = P.html_search_probe({"url": "https://search.example/?q={q}",
                                       "limit": 10}, "x")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(len(out["results"]), 2)
        self.assertTrue(all(r["fragile"] for r in out["results"]))

        out = P.html_search_probe({"url": "https://www.google.com/search?q={q}"}, "x")
        self.assertEqual(out["status"], "blocked")
        out = P.html_search_probe({"url": "https://www.google.co.uk/search?q={q}"}, "x")
        self.assertEqual(out["status"], "blocked")
        out = P.html_search_probe({"url": "https://www.bing.com/search?q={q}"}, "x")
        self.assertEqual(out["status"], "blocked")

    def test_oembed_probe(self):
        body = json.dumps({"title": "A video", "author_name": "Jane",
                           "thumbnail_url": "https://img.example/x.jpg",
                           "provider_name": "Example"})
        with mock.patch.object(P, "fetch", return_value={
                "status": "ok", "http": 200, "url": "https://example/oembed",
                "text": body, "headers": {}}):
            out = P.oembed_probe({"url": "https://example/oembed?url={q}"},
                                 "https://example/v/1")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["title"], "A video")


class EngineTests(unittest.TestCase):
    def _module(self, mid, status="verified", ptype="json_api_probe"):
        return {
            "id": mid, "source_id": mid, "label": mid, "category": "code",
            "types": ["name"], "access": "api", "status": status,
            "verified": status in ("verified", "fragile"),
            "fragile": status == "fragile",
            "automatic": status in ("verified", "fragile"),
            "probe_type": ptype, "probe": {"type": ptype},
            "search_url": "https://example.org/?q={q}", "profile_url": "",
            "homepage": "https://example.org/", "adapter": "",
            "requires_key": False, "key_env": "", "region": "global",
            "last_checked": "", "last_error": "",
        }

    def test_search_dedupes_and_ranks_cross_source(self):
        a = self._module("a")
        b = self._module("b")
        mods = [a, b]

        def fake_run(module, query, timeout=8):
            return {"status": "ok", "results": [{
                "source": module["id"], "source_label": module["label"],
                "title": "Jane Doe", "url": "https://example.org/jane?utm_source=x",
                "snippet": "public", "fragile": False,
            }]}

        with mock.patch.object(R, "modules", return_value=mods), \
             mock.patch.object(R, "select", return_value=mods), \
             mock.patch.object(E.probes, "run_probe", side_effect=fake_run):
            out = E.search("Jane Doe", module_ids=["a", "b"], include_link_out=False,
                           limit=10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["count"], 1)
        self.assertEqual(len(out["results"][0]["sources"]), 2)
        self.assertGreater(out["results"][0]["rank_score"], 1.0)

    def test_one_success_one_block_is_unstable(self):
        self.assertEqual(E._combine_status(["ok", "blocked"], False), "unstable")
        self.assertEqual(E._combine_status(["ok", "ok"], True), "fragile")
        self.assertEqual(E._combine_status(["blocked", "blocked"], False), "blocked")

    def test_search_empty_is_explicit(self):
        a = self._module("a")
        with mock.patch.object(R, "modules", return_value=[a]), \
             mock.patch.object(R, "select", return_value=[a]), \
             mock.patch.object(E.probes, "run_probe",
                               return_value={"status": "blocked", "error": "captcha",
                                             "results": []}):
            out = E.search("Jane Doe", module_ids=["a"], include_link_out=False)
        self.assertEqual(out["status"], "empty")
        self.assertIn("blocked", out["diagnostics"]["reason"].lower())

    def test_verify_marks_scrape_fragile(self):
        m = self._module("scrape", status="candidate", ptype="http_profile_probe")
        with mock.patch.object(R, "get", return_value=m), \
             mock.patch.object(E.probes, "run_probe",
                               return_value={"status": "ok", "results": [{"title": "Jane"}]}):
            out = E.verify(ids=["scrape"], checks=2, persist=False)
        self.assertEqual(out["checked"], 1)
        self.assertEqual(out["fragile"], 1)
        self.assertEqual(out["results"]["scrape"]["status"], "fragile")
        R.reload()


class CompatibilityTests(unittest.TestCase):
    def test_key_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(OC, "KEY_PATH", os.path.join(td, "keys.json")), \
                 mock.patch.object(OC, "FERNET_PATH", os.path.join(td, "fernet.key")):
                OC.save_key("hibp", "a" * 32)
                self.assertIn("hibp", OC.list_services())
                self.assertEqual(OC.get_key("hibp"), "a" * 32)
                OC.delete_key("hibp")
                self.assertNotIn("hibp", OC.list_services())

    def test_validate_key_is_format_only(self):
        self.assertTrue(OC.validate_key("hibp", "a" * 32)["valid"])
        self.assertFalse(OC.validate_key("hibp", "short")["valid"])
        self.assertFalse(OC.validate_key("unknown", "x")["valid"])

    def test_rules_are_deterministic(self):
        out = OC.template_rules({"indicator_value": "8.8.8.8",
                                 "indicator_type": "ip", "threat_score": 80})
        self.assertIn("8.8.8.8", out["snort"])
        self.assertIn("rule Xaxglog_8_8_8_8", out["yara"])
        self.assertIn("iptables", out["firewall"])

    def test_deep_lookup_maps_live_and_local_shape(self):
        fake = {
            "input": "8.8.8.8", "detected_type": "ip",
            "results": {"ip": {"geo": {"country": "US", "isp": "Google"},
                               "abuseipdb": {"confidence_score": 0}}},
        }
        with mock.patch("modules.deep_search.connectors.deep_search",
                        return_value=fake), \
             mock.patch.object(OC, "_local_matches", return_value=[]):
            out = OC.deep_lookup("8.8.8.8")
        self.assertEqual(out["detected_type"], "ip")
        self.assertEqual(out["indicator_type"], "ip")
        self.assertEqual(out["query"], "8.8.8.8")
        self.assertIn("ipapi", out["live"])
        self.assertIn("abuseipdb", out["live"])
        self.assertEqual(out["count"], 0)

    def test_deep_lookup_normalises_domain_cards(self):
        fake = {
            "input": "example.com", "detected_type": "domain",
            "results": {"domain": {
                "dns": {"A": ["1.2.3.4"], "MX": ["10 mail.example.com"],
                        "NS": ["ns1.example.com"]},
                "subdomains": {"count": 2, "sample": ["www.example.com", "api.example.com"]},
                "rdap": {"registrar": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                         "events": [{"eventAction": "registration", "eventDate": "2000-01-01"}],
                         "nameservers": ["ns1.example.com"]},
            }},
        }
        with mock.patch("modules.deep_search.connectors.deep_search",
                        return_value=fake), \
             mock.patch.object(OC, "_local_matches", return_value=[]):
            out = OC.deep_lookup("example.com")
        self.assertEqual(out["live"]["whois"]["registrar"], "Example Registrar")
        self.assertEqual(out["live"]["whois"]["creation_date"], "2000-01-01")
        self.assertEqual(out["live"]["crtsh"]["subdomain_count"], 2)
        self.assertEqual(out["live"]["securitytrails"]["a_records"], ["1.2.3.4"])


if __name__ == "__main__":
    unittest.main()
