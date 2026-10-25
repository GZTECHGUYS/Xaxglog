"""Unit tests for the people/social deep-search connectors.

Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

from modules.deep_search import connectors as connectors
from modules.deep_search import social


class DetectTypeTests(unittest.TestCase):
    def test_full_name_is_person(self):
        self.assertEqual(connectors.detect_type("Jane Doe"), "person")
        self.assertEqual(connectors.detect_type("Jean-Luc Picard"), "person")

    def test_company_suffix_is_company(self):
        self.assertEqual(connectors.detect_type("Acme Ltd"), "company")
        self.assertEqual(connectors.detect_type("Example Holdings GmbH"), "company")

    def test_handle_email_domain_ip_phone_unchanged(self):
        self.assertEqual(connectors.detect_type("jane_doe"), "username")
        self.assertEqual(connectors.detect_type("jane@example.com"), "email")
        self.assertEqual(connectors.detect_type("example.com"), "domain")
        self.assertEqual(connectors.detect_type("8.8.8.8"), "ip")
        self.assertEqual(connectors.detect_type("+1 202-555-0143"), "phone")


class PlatformTests(unittest.TestCase):
    def test_catalog_counts_match_platform_list(self):
        cat = social.sources_catalog()
        self.assertEqual(cat["profile_platforms"], len(social.PLATFORMS))
        self.assertEqual(sum(cat["by_category"].values()), len(social.PLATFORMS))
        self.assertIn("wikidata", cat["people_registries"])
        self.assertIn("bluesky", cat["people_registries"])

    def test_platform_for_url(self):
        self.assertEqual(social.platform_for_url("https://x.com/jane"), "X/Twitter")
        self.assertEqual(social.platform_for_url("https://www.linkedin.com/in/jane"), "LinkedIn")
        self.assertEqual(social.platform_for_url("https://example.org/jane"), "")

    def test_invalid_handle_rejected(self):
        out = social.check_username("not a handle")
        self.assertIn("error", out)
        self.assertEqual(out["hits"], [])


class ScraperTests(unittest.TestCase):
    def test_private_and_non_http_urls_blocked(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
                    "file:///etc/passwd"):
            out = social.scrape_profile(url)
            self.assertEqual(out["status"], "error")

    def test_public_url_validation_uses_global_ips(self):
        with mock.patch("socket.getaddrinfo",
                        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            ok, why = social._validate_public_url("https://example.com/profile")
        self.assertTrue(ok, why)

        with mock.patch("socket.getaddrinfo",
                        return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]):
            ok, why = social._validate_public_url("https://internal.example/profile")
        self.assertFalse(ok)
        self.assertIn("private", why)

    def test_parse_open_graph_jsonld_and_social_links(self):
        page = """
        <html><head>
        <title>Jane Doe</title>
        <meta property="og:title" content="Jane Doe">
        <meta property="og:description" content="OSINT analyst">
        <link rel="canonical" href="/jane">
        <script type="application/ld+json">
          {"@type":"Person","name":"Jane Doe","sameAs":["https://x.com/jane"]}
        </script>
        </head><body>
        <a href="https://x.com/jane">X profile</a>
        <a href="/about">About</a>
        </body></html>
        """
        out = social._parse_profile_html(page, "https://example.com/jane")
        self.assertEqual(out["title"], "Jane Doe")
        self.assertEqual(out["og"]["og:description"], "OSINT analyst")
        self.assertEqual(out["canonical"], "https://example.com/jane")
        self.assertEqual(out["jsonld"][0]["name"], "Jane Doe")
        self.assertEqual(out["social_links"][0]["platform"], "X/Twitter")


class RegistryTests(unittest.TestCase):
    def test_registry_rejects_invalid_name(self):
        out = social.name_registry_search("a")
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["sources"], {})

    def test_registry_merges_and_sorts_source_results(self):
        def fake_wikidata(_name):
            return [{"name": "Jane Doe", "match": 0.5, "url": "https://wd/1"},
                    {"name": "Jane Doe", "match": 1.0, "url": "https://wd/2"}]

        fake = dict(social.PEOPLE_SOURCES)
        fake["wikidata"] = fake_wikidata
        for key in list(fake):
            if key != "wikidata":
                fake[key] = lambda _name: []
        with mock.patch.dict(social.PEOPLE_SOURCES, fake, clear=True):
            out = social.name_registry_search("Jane Doe")
        self.assertEqual(out["counts"]["wikidata"], 2)
        self.assertEqual(out["sources"]["wikidata"][0]["match"], 1.0)
        self.assertEqual(out["status"], "ok")

    def test_profile_probe_requires_handle_evidence(self):
        with mock.patch.object(social, "_probe",
                               return_value=(200, "https://example.com/jane", "<title>App shell</title>", "")):
            rec = social._probe_one("GitHub", "https://example.com/{u}", "jane")
        self.assertIsNone(rec["exists"])
        self.assertEqual(rec["status"], "unverified")

    def test_profile_probe_marks_redirect_to_login_as_missing(self):
        with mock.patch.object(social, "_probe",
                               return_value=(200, "https://example.com/login?next=jane", "<title>Login</title>", "")):
            rec = social._probe_one("GitHub", "https://example.com/{u}", "jane")
        self.assertFalse(rec["exists"])


class NamePlatformTests(unittest.TestCase):
    def test_normalizes_display_name_hits_and_dedupes(self):
        people = {"sources": {
            "github": [{"login": "jane", "url": "https://github.com/jane", "match": 1.0}],
            "bluesky": [{"handle": "jane.bsky.social", "name": "Jane Doe",
                         "url": "https://bsky.app/profile/jane.bsky.social", "match": 1.0}],
            "wikipedia": [{"title": "Jane Doe", "url": "https://en.wikipedia.org/wiki/Jane_Doe"}],
        }}
        out = social.normalize_people_platforms(people)
        self.assertEqual(out["checked"], len(social.NAME_PLATFORM_META))
        self.assertIn("GitHub", out["platforms"])
        self.assertIn("Bluesky", out["platforms"])
        self.assertNotIn("Wikipedia", out["platforms"])
        self.assertEqual(len(out["hits"]), 2)

    def test_new_people_indexes_registered(self):
        for key in ("crossref", "arxiv", "lemmy", "stackexchange", "codeberg"):
            self.assertIn(key, social.PEOPLE_SOURCES)

    def test_name_and_handle_variants(self):
        variants = social.name_variants("Jane A. Doe")
        self.assertIn("Jane Doe", variants)
        self.assertIn("Doe Jane", variants)
        self.assertIn("J Doe", variants)
        handles = social.handle_candidates("Jane Doe")
        self.assertIn("janedoe", handles)
        self.assertIn("jane.doe", handles)
        self.assertIn("jane_doe", handles)
        self.assertIn("jdoe", handles)

    def test_name_search_coverage_reports_boundary(self):
        cov = social.name_search_coverage()
        self.assertEqual(cov["total_platforms"], len(social.PLATFORMS))
        self.assertTrue(cov["checked_platforms"])
        self.assertIn("GitHub", cov["checked_platforms"])
        self.assertGreater(len(cov["not_name_searchable"]), 0)


class LocationSignalTests(unittest.TestCase):
    def test_phone_signals_are_labeled_coarse(self):
        try:
            import phonenumbers  # noqa: F401
        except ImportError:
            self.skipTest("phonenumbers not installed")
        from modules.deep_search import location
        out = location.phone_signals("+14155552671")
        self.assertEqual(out["precision"], "coarse")
        self.assertTrue(out["signals"])
        self.assertTrue(any(s["type"] == "phone_region" for s in out["signals"]))
        self.assertIn("not GPS", out["disclaimer"])

    def test_profile_signals_extract_jsonld_address(self):
        from modules.deep_search import location
        scraped = {
            "status": "ok", "url": "https://example.com/jane", "name": "Jane Doe",
            "jsonld": [{"@type": "Person", "name": "Jane Doe",
                        "address": {"addressLocality": "Berlin",
                                    "addressCountry": "DE"}}],
            "og": {},
        }
        signals = location.profile_signals(scraped)
        self.assertTrue(any(s["type"] == "profile_address" and "Berlin" in s["value"]
                            for s in signals))

    def test_location_search_empty_query_is_graceful(self):
        out = connectors.location_search("", include_profiles=False)
        self.assertEqual(out["status"], "error")
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
