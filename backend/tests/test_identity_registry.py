"""Tests for the Phase-1/2 identity orchestrator and unified source registry.

All network calls are mocked. Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

from modules.identity import adapters as AD
from modules.identity import identity as ID
from modules.source_registry import source_registry as SR


class SourceRegistryTests(unittest.TestCase):
    def test_catalog_is_large_and_structured(self):
        cat = SR.catalog(include_sources=False)
        self.assertGreaterEqual(cat["total"], 200)
        self.assertGreaterEqual(cat["verified"], 20)
        self.assertIn("people", cat["by_category"])
        self.assertIn("records", cat["by_category"])
        self.assertIn("social", cat["by_category"])
        self.assertIn("api", cat["by_access"])
        self.assertIn("link_out", cat["by_access"])
        self.assertIn("optional_key", cat["by_access"])
        self.assertGreater(cat["queryable"], 50)

    def test_every_source_has_explicit_access_and_status(self):
        for src in SR.sources():
            self.assertIn(src["access"], SR.ACCESS_MODES, src["id"])
            self.assertTrue(src["id"])
            self.assertTrue(src["label"])
            self.assertTrue(src["category"])
            self.assertIn("status", src)
            self.assertIn("types", src)

    def test_extra_public_record_code_and_infra_sources(self):
        # These were added as real keyless/public sources, not placeholders.
        for sid in (
            "dbpedia", "brreg", "recherche_entreprises", "vies",
            "data_gov_uk", "data_gov_au", "data_gov_ie", "data_europa",
            "federal_register", "rubygems", "packagist", "nuget", "maven",
            "ripe_stat", "shodan_internetdb",
        ):
            src = SR.get(sid)
            self.assertIsNotNone(src, sid)
            self.assertEqual(src["status"], "verified", sid)
            self.assertTrue(src["adapter"], sid)

    def test_select_and_get(self):
        people = SR.select(categories=["people"], queryable=True)
        self.assertTrue(people)
        self.assertTrue(all(s["category"] == "people" for s in people))
        self.assertIsNotNone(SR.get("github_users"))
        self.assertIsNone(SR.get("does_not_exist"))

    def test_search_links_are_public_linkouts(self):
        links = SR.search_links("Jane Doe", types=["person", "name"], limit=250)
        self.assertTrue(links)
        for link in links:
            self.assertIn("http", link["url"])
            self.assertNotIn("{q}", link["url"])
            self.assertIn(link["access"], SR.ACCESS_MODES)
        self.assertTrue(any("github.com/search" in x["url"] or "linkedin.com/search" in x["url"]
                            for x in links))

    def test_plan_for_person_has_variants_and_adapters(self):
        plan = SR.plan("person", depth="standard")
        self.assertGreater(plan["count"], 20)
        self.assertTrue(any(s["category"] == "people" for s in plan["sources"]))


class NameNormalizationTests(unittest.TestCase):
    def test_comma_form_and_suffix(self):
        out = ID.normalize_name("Doe, Jane A. Jr.")
        self.assertEqual(out["base"], "Jane A. Doe")
        self.assertEqual(out["suffixes"], ["Jr."])
        self.assertEqual(out["comma_form"], "Doe, Jane A. Jr.")
        self.assertTrue(out["valid"])

    def test_variants_are_always_on_and_prioritized(self):
        variants = ID.name_variants("Jane A. Doe")
        self.assertEqual(variants[0], "Jane A. Doe")
        self.assertIn("Doe Jane", variants)
        self.assertIn("Doe, Jane", variants)
        self.assertIn("J Doe", variants)
        self.assertIn("JaneDoe", variants)
        self.assertEqual(len(variants), len(set(v.lower() for v in variants)))

    def test_handle_variants(self):
        handles = ID.handle_variants("Jane Doe")
        self.assertIn("janedoe", handles)
        self.assertIn("jane.doe", handles)
        self.assertIn("jdoe", handles)

    def test_invalid_names_rejected(self):
        self.assertFalse(ID.is_person_name("Jane 123"))
        self.assertFalse(ID.is_person_name("a"))
        self.assertFalse(ID.is_person_name("x" * 200))
        self.assertTrue(ID.is_person_name("Jean-Luc Picard"))
        self.assertTrue(ID.is_person_name("Doe, Jane"))

    def test_detect_kind_handles_comma_name(self):
        self.assertEqual(ID.detect_kind("Doe, Jane"), "person")
        self.assertEqual(ID.detect_kind("jane_doe"), "username")
        self.assertEqual(ID.detect_kind("jane@example.com"), "email")


class IdentitySearchTests(unittest.TestCase):
    def _person(self):
        return {
            "input": "Jane Doe",
            "query_type": "name",
            "people": {
                "sources": {
                    "wikidata": [{"name": "Jane Doe", "url": "https://wd/1", "match": 1.0}],
                    "github": [{"name": "Jane Doe", "url": "https://github.com/jane", "match": 0.8}],
                },
                "counts": {"wikidata": 1, "github": 1},
                "errors": {},
            },
            "name_platforms": {"hits": [{"platform": "GitHub", "name": "Jane Doe",
                                         "url": "https://github.com/jane", "match": 0.8}]},
            "social": {"status": "empty", "results": []},
        }

    def test_search_merges_dedupes_and_reports_coverage(self):
        extra = {
            "sources": {
                "gitlab_users": [{"source": "gitlab_users", "label": "GitLab users",
                                  "name": "Jane Doe", "url": "https://gitlab.com/jane",
                                  "match": 0.9}],
                "pubmed": [{"source": "pubmed", "label": "PubMed", "name": "Jane Doe",
                            "url": "https://pubmed.ncbi.nlm.nih.gov/1/", "match": 0.7}],
            },
            "counts": {"gitlab_users": 1, "pubmed": 1},
            "errors": {"europepmc": "blocked"},
            "total": 2,
            "status": "partial",
        }
        variant = {
            "sources": {"github": [{"name": "Jane Doe", "url": "https://github.com/jane",
                                     "match": 0.75, "matched_variant": "Doe Jane"}]},
            "counts": {"github": 1},
            "errors": {},
            "total": 1,
            "variants_tried": ["Doe Jane"],
        }
        records = {
            "sources": {"procurement": {"status": "ok", "count": 1},
                        "propublica": {"status": "ok", "count": 1}},
            "results": [
                {"source": "usaspending", "category": "records", "name": "Jane Doe",
                 "url": "https://www.usaspending.gov/award/1", "match": 0.45,
                 "detail": "DoD"},
                {"source": "propublica", "category": "records", "name": "Jane Doe Foundation",
                 "url": "https://projects.propublica.org/nonprofits/organizations/1",
                 "match": 0.45, "detail": "NY"},
            ],
            "errors": {}, "total": 2, "status": "ok",
        }
        web = {"engines": {"ddg": "ok", "mojeek": "blocked"}, "results": [
            {"title": "Jane Doe profile", "url": "https://example.org/jane",
             "snippet": "public profile", "engines": ["ddg"]}],
            "total": 1, "status": "ok"}

        with mock.patch.object(ID.DEEP, "person_search", return_value=self._person()), \
                mock.patch.object(ID.AD, "run_adapters", return_value=extra), \
                mock.patch.object(ID, "_variant_people_search", return_value=variant), \
                mock.patch.object(ID, "_records_search", return_value=records), \
                mock.patch.object(ID, "_web_search", return_value=web), \
                mock.patch.object(ID.SR, "search_links", return_value=[]):
            out = ID.search("Doe, Jane", depth="standard", include_web=True)

        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["normalized"]["base"], "Jane Doe")
        self.assertGreaterEqual(out["total"], 4)
        # GitHub URL appears in exact + variant + name_platforms; must dedupe.
        github = [r for r in out["results"] if "github.com/jane" in (r.get("url") or "")]
        self.assertEqual(len(github), 1)
        self.assertIn("coverage", out)
        self.assertGreater(out["coverage"]["planned"], 0)
        self.assertIn("by_source", out["coverage"])
        self.assertTrue(any(v["status"] == "blocked" for v in out["coverage"]["by_source"].values()))
        self.assertTrue(out["variants"])

    def test_empty_search_is_explicit(self):
        empty = {"sources": {}, "counts": {}, "errors": {}, "total": 0, "status": "empty"}
        person = {"people": {"sources": {}, "counts": {}, "errors": {}},
                  "name_platforms": {"hits": []}, "social": {"status": "empty"}}
        with mock.patch.object(ID.DEEP, "person_search", return_value=person), \
                mock.patch.object(ID.AD, "run_adapters", return_value=empty), \
                mock.patch.object(ID, "_variant_people_search", return_value=empty), \
                mock.patch.object(ID, "_records_search", return_value=empty), \
                mock.patch.object(ID, "_web_search", return_value={"engines": {}, "results": []}), \
                mock.patch.object(ID.SR, "search_links", return_value=[]):
            out = ID.search("Jane Doe", depth="quick", include_web=False,
                            include_records=False)
        self.assertEqual(out["status"], "empty")
        self.assertIn("coverage", out)
        self.assertIn("No automatic hit", out["note"])

    def test_non_person_routes_to_deep_search(self):
        with mock.patch.object(ID.DEEP, "deep_search", return_value={"input": "x", "results": {}}):
            out = ID.search("example.com", kind="domain")
        self.assertEqual(out["input"], "x")
        self.assertIn("identity_plan", out)


class AdapterRunnerTests(unittest.TestCase):
    def test_run_adapters_separates_empty_and_error(self):
        def good(_q):
            return [{"name": "Jane", "url": "https://example.org/jane", "match": 1.0}]

        def empty(_q):
            return []

        def blocked(_q):
            raise RuntimeError("blocked")

        out = AD.run_adapters("Jane", {"good": good, "empty": empty, "blocked": blocked},
                              max_workers=3)
        self.assertEqual(out["counts"]["good"], 1)
        self.assertEqual(out["counts"]["empty"], 0)
        self.assertIn("blocked", out["errors"])
        self.assertEqual(out["status"], "partial")

    def test_verify_sources_marks_no_adapter(self):
        out = ID.verify_sources(["does_not_exist"], query="Jane Doe")
        self.assertEqual(out["results"]["does_not_exist"]["status"], "no_adapter")
        self.assertEqual(out["no_adapter"], 1)


if __name__ == "__main__":
    unittest.main()
