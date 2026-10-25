"""Tests for public reverse-image lookup.

Network calls are mocked. Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

from modules.imgreverse import imgreverse as IR


class CatalogTests(unittest.TestCase):
    def test_catalog_and_excluded_face_search(self):
        cat = IR.catalog()
        self.assertGreaterEqual(cat["engines"], 14)
        ids = {e["id"] for e in cat["engines_list"]}
        for wanted in ("google_lens", "bing_visual", "yandex", "tineye",
                       "saucenao", "iqdb", "ascii2d", "baidu", "sogou",
                       "karma_decay", "trace_moe"):
            self.assertIn(wanted, ids)
        self.assertNotIn("pimeyes", ids)
        self.assertNotIn("facecheck_id", ids)
        excluded = {e["id"] for e in cat["excluded"]}
        self.assertIn("pimeyes", excluded)
        self.assertIn("facecheck_id", excluded)

    def test_links_are_encoded(self):
        out = IR.links("https://example.com/a b.jpg")
        self.assertIn("google_lens", out)
        self.assertIn("tineye", out)
        self.assertIn("trace_moe", out)
        self.assertIn("a%20b.jpg", out["google_lens"])


class SearchTests(unittest.TestCase):
    def test_keyless_api_hit_is_normalized(self):
        with mock.patch.object(IR, "_validate_image_url", return_value=(True, "")), \
                mock.patch.object(IR, "_trace_moe", return_value={
                    "engine": "trace_moe", "status": "ok", "hits": [
                        {"title": "Example Anime", "similarity": 0.98}]}), \
                mock.patch.object(IR, "_saucenao", return_value={
                    "engine": "saucenao_api", "status": "unavailable", "hits": []}), \
                mock.patch.object(IR, "_tineye", return_value={
                    "engine": "tineye_api", "status": "unavailable", "hits": []}), \
                mock.patch.object(IR, "_google_vision", return_value={
                    "engine": "google_vision", "status": "unavailable", "hits": []}):
            out = IR.search("https://example.com/a.jpg")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["summary"]["total_hits"], 1)
        self.assertEqual(out["hits"][0]["title"], "Example Anime")
        self.assertGreaterEqual(out["summary"]["links"], 10)
    def test_trace_moe_normalizes_hit(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = {"result": [{
            "anilist": {"title": {"romaji": "Example Anime"}},
            "similarity": 0.97, "episode": 2, "from": 12.5, "to": 14.0,
            "filename": "example.mkv", "video": "https://example.com/clip.mp4",
            "image": "https://example.com/frame.jpg", "isAdult": False,
        }]}
        with mock.patch.object(IR.requests, "get", return_value=response):
            out = IR._trace_moe("https://example.com/a.jpg")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["hits"][0]["title"], "Example Anime")
        self.assertEqual(out["hits"][0]["episode"], 2)

    def test_trace_moe_blocked_is_reported(self):
        response = mock.Mock(status_code=429)
        with mock.patch.object(IR.requests, "get", return_value=response):
            out = IR._trace_moe("https://example.com/a.jpg")
        self.assertEqual(out["status"], "blocked")

    def test_optional_keyed_api_without_key_is_unavailable(self):
        out = IR._saucenao("https://example.com/a.jpg", "")
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["hits"], [])


    def test_links_only_mode_is_ok(self):
        with mock.patch.object(IR, "_validate_image_url", return_value=(True, "")):
            out = IR.search("https://example.com/a.jpg", include_api=False)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["hits"], [])
        self.assertGreaterEqual(len(out["links"]), 10)

    def test_private_image_url_is_rejected(self):
        with mock.patch.object(IR, "_validate_image_url",
                               return_value=(False, "private/reserved address blocked")):
            out = IR.search("http://127.0.0.1/a.jpg")
        self.assertEqual(out["status"], "error")
        self.assertIn("private", out["error"])

    def test_local_path_hashes_without_upload(self):
        with mock.patch.object(IR.IV, "hashes", return_value={
                "status": "ok", "sha256": "a" * 64, "dhash": "0" * 16}):
            out = IR.search(image_path="/tmp/example.jpg")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["hashes"]["sha256"], "a" * 64)
        self.assertEqual(out["links"], {})
        self.assertIn("local image hashed", out["note"])

    def test_case_attachment_is_hashed(self):
        with mock.patch.object(IR, "_validate_image_url", return_value=(True, "")), \
                mock.patch.object(IR, "links", return_value={"google_lens": "x"}), \
                mock.patch.object(IR.db, "audit"), \
                mock.patch.object(IR.db, "store_artifact",
                                  return_value={"id": 9, "hash": "def"}) as store:
            out = IR.search("https://example.com/a.jpg", include_api=False,
                            case_id=42, user="tester")
        store.assert_called_once()
        self.assertEqual(out["artifact"]["id"], 9)

    def test_empty_input_is_graceful(self):
        out = IR.search()
        self.assertEqual(out["status"], "error")
        self.assertIn("required", out["error"])


if __name__ == "__main__":
    unittest.main()
