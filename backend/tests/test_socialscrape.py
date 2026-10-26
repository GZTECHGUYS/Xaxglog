"""Tests for broad public social-media discovery/scraping.

Network calls are mocked. Run from ``backend/``::

    python -m unittest discover -s tests -v
"""
import unittest
from unittest import mock

from modules.socialscrape import socialscrape as SS


class CatalogTests(unittest.TestCase):
    def test_catalog_is_large_and_international(self):
        cat = SS.catalog()
        self.assertGreaterEqual(cat["platforms"], 150)
        self.assertGreaterEqual(cat["searchable_platforms"], 140)
        self.assertIn("CN", cat["regions"])
        self.assertIn("RU", cat["regions"])
        self.assertIn("JP", cat["regions"])
        self.assertIn("KR", cat["regions"])
        self.assertIn("IN", cat["regions"])
        self.assertIn("LATAM", cat["regions"])
        self.assertIn("MENA", cat["regions"])
        self.assertTrue(cat["limits"]["no_login"])
        self.assertEqual(SS._domain_from_template("https://x.com/{u}"), "x.com")
        self.assertEqual(SS._domain_from_template("https://{u}.tistory.com"), "tistory.com")
        global_count = sum(1 for p in SS.PLATFORMS if p["region"] == "global")
        self.assertEqual(len(SS._select_platforms(None, "global", "all")), global_count)

    def test_platform_detection_for_international_hosts(self):
        self.assertEqual(SS.platform_for_url("https://www.pixiv.net/users/1"), "Pixiv")
        self.assertEqual(SS.platform_for_url("https://vk.com/jane"), "VK")
        self.assertEqual(SS.platform_for_url("https://www.xiaohongshu.com/user/profile/1"),
                         "Xiaohongshu")
        self.assertEqual(SS.platform_for_url("https://x.com/jane"), "X/Twitter")

    def test_query_type_detection(self):
        self.assertEqual(SS.detect_query_type("Jane Doe"), "name")
        self.assertEqual(SS.detect_query_type("jane_doe"), "handle")
        self.assertEqual(SS.detect_query_type("#osint"), "hashtag")
        self.assertEqual(SS.detect_query_type("https://x.com/jane/status/1"), "url")

    def test_search_links_cover_selected_platforms(self):
        links = SS.search_links("Jane Doe", platforms=["X/Twitter", "Weibo", "Pixiv"])
        by_name = {x["platform"]: x for x in links}
        self.assertIn("X/Twitter", by_name)
        self.assertIn("Weibo", by_name)
        self.assertIn("Pixiv", by_name)
        self.assertIn("Jane+Doe", by_name["X/Twitter"]["url"])
        self.assertEqual(by_name["Pixiv"]["region"], "JP")


class ParserTests(unittest.TestCase):
    def test_parse_public_post_metadata_media_and_tags(self):
        page = """
        <html><head>
          <title>Jane Doe on X</title>
          <meta property="og:title" content="Jane Doe post">
          <meta property="og:description" content="Hello #osint @jane_doe">
          <meta property="og:site_name" content="X">
          <meta property="article:published_time" content="2026-10-20T12:00:00Z">
          <meta name="author" content="Jane Doe">
          <meta property="og:image" content="/img/a.jpg">
          <meta property="og:type" content="article">
          <script type="application/ld+json">
            {"@type":"Article","headline":"Jane Doe post",
             "image":["https://example.com/img/c.jpg"]}
          </script>
        </head><body>
          <img data-src="/img/b.jpg">
          <a href="https://x.com/jane">X profile</a>
          <p>More #osint text</p>
        </body></html>
        """
        out = SS._parse_public_page(page, "https://example.com/post/1")
        self.assertEqual(out["title"], "Jane Doe post")
        self.assertEqual(out["author"], "Jane Doe")
        self.assertEqual(out["post_type"], "post")
        self.assertTrue(out["published"].startswith("2026-10-20T12:00:00"))
        self.assertIn("https://example.com/img/a.jpg", out["images"])
        self.assertIn("https://example.com/img/b.jpg", out["images"])
        self.assertIn("osint", out["hashtags"])
        self.assertIn("jane_doe", out["mentions"])
        self.assertTrue(any(x["platform"] == "X/Twitter" for x in out["social_links"]))

    def test_private_urls_are_blocked(self):
        out = SS.scrape_public_page("http://127.0.0.1/")
        self.assertEqual(out["status"], "error")
        self.assertIn("private", out["error"].lower())

    def test_scrape_public_page_merges_oembed(self):
        page = '<html><head><meta property="og:title" content="Post"></head></html>'
        with mock.patch.object(SS, "_fetch_public", return_value={
                "status": "ok", "page": page, "final_url": "https://x.com/jane/status/1",
                "bytes": len(page)}), \
                mock.patch.object(SS, "oembed", return_value={
                    "status": "ok", "title": "oEmbed title", "author_name": "Jane",
                    "thumbnail_url": "https://example.com/t.jpg"}):
            out = SS.scrape_public_page("https://x.com/jane/status/1")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["oembed"]["title"], "oEmbed title")
        self.assertIn("https://example.com/t.jpg", out["images"])

    def test_fetch_public_marks_login_wall_as_blocked(self):
        response = mock.Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.encoding = "utf-8"
        response.url = "https://example.com/jane"
        response.iter_content.return_value = [b"<html>Please complete the captcha to continue</html>"]
        with mock.patch.object(SS, "_validate_public_url", return_value=(True, "")), \
                mock.patch.object(SS.requests, "get", return_value=response):
            out = SS._fetch_public("https://example.com/jane")
        self.assertEqual(out["status"], "blocked")
        self.assertIn("captcha", out["error"].lower())


class AdapterTests(unittest.TestCase):
    def test_oembed_normalizes_public_metadata(self):
        response = mock.Mock()
        response.status_code = 200
        response.json.return_value = {
            "provider_name": "TikTok", "title": "Example clip",
            "author_name": "Jane", "thumbnail_url": "https://example.com/t.jpg",
            "html": "<blockquote>clip</blockquote>", "type": "video",
        }
        with mock.patch.object(SS.requests, "get", return_value=response):
            out = SS.oembed("https://www.tiktok.com/@jane/video/1")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["title"], "Example clip")
        self.assertEqual(out["author_name"], "Jane")

    def test_oembed_blocked_is_reported(self):
        response = mock.Mock(status_code=403)
        with mock.patch.object(SS.requests, "get", return_value=response):
            out = SS.oembed("https://www.tiktok.com/@jane/video/1")
        self.assertEqual(out["status"], "blocked")

    def test_reddit_adapter_normalizes_results(self):
        fake = {"status": "ok", "data": {"data": {"children": [{"data": {
            "title": "Jane thread", "permalink": "/r/osint/comments/1/jane/",
            "selftext": "public post", "author": "jane", "created_utc": 1700000000,
        }}]}}}
        with mock.patch.object(SS, "_json_get", return_value=fake):
            out = SS.reddit_search("Jane")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["platform"], "Reddit")
        self.assertTrue(out["results"][0]["url"].startswith("https://www.reddit.com/r/"))

    def test_bluesky_adapter_normalizes_results(self):
        fake = {"status": "ok", "data": {"posts": [{
            "uri": "at://did:plc:x/app.bsky.feed.post/rkey1",
            "author": {"handle": "jane.bsky.social"},
            "record": {"text": "Hello #osint"},
            "indexedAt": "2026-10-20T12:00:00Z",
        }]}}
        with mock.patch.object(SS, "_json_get", return_value=fake):
            out = SS.bluesky_search("Jane")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["platform"], "Bluesky")
        self.assertEqual(out["results"][0]["author"], "jane.bsky.social")

    def test_lemmy_adapter_normalizes_results(self):
        fake = {"status": "ok", "data": {"posts": [{
            "post": {"id": 7, "name": "Jane thread", "body": "public",
                     "published": "2026-10-20T12:00:00Z"},
            "creator": {"name": "jane"},
        }]}}
        with mock.patch.object(SS, "_json_get", return_value=fake):
            out = SS.lemmy_search("Jane")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["platform"], "Lemmy")
        self.assertEqual(out["results"][0]["author"], "jane")

    def test_blocked_adapter_does_not_raise(self):
        with mock.patch.object(SS, "_json_get",
                               return_value={"status": "blocked", "http": 429}):
            out = SS.reddit_search("Jane")
        self.assertEqual(out["status"], "blocked")
        self.assertEqual(out["results"], [])


class SearchTests(unittest.TestCase):
    def test_search_normalizes_engine_results_and_links(self):
        fake_eng = {
            "ddg": {"status": "ok", "results": [
                {"title": "Jane on X", "url": "https://x.com/jane/status/1",
                 "snippet": "#osint @jane"},
                {"title": "Jane on Pixiv", "url": "https://www.pixiv.net/users/1",
                 "snippet": "artist"},
            ]},
            "weibo": {"status": "blocked", "results": []},
        }
        with mock.patch.object(SS, "_run_engines", return_value=fake_eng):
            out = SS.search("Jane Doe", platforms=["X/Twitter", "Pixiv", "Weibo"],
                            limit=10)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["summary"]["results"], 2)
        self.assertEqual({r["platform"] for r in out["results"]},
                         {"X/Twitter", "Pixiv"})
        self.assertIn("osint", out["hashtags"])
        self.assertGreaterEqual(len(out["search_links"]), 2)

    def test_handle_probe_adds_profiles(self):
        fake_eng = {"ddg": {"status": "ok", "results": []}}
        fake_prof = {"checked": 10, "hits": [{"platform": "GitHub",
                                              "url": "https://github.com/jane"}],
                     "coverage": {}}
        with mock.patch.object(SS, "_run_engines", return_value=fake_eng), \
                mock.patch.object(SS.SOCIAL, "check_username", return_value=fake_prof):
            out = SS.search("jane_doe", probe=True)
        self.assertEqual(len(out["profiles"]), 1)
        self.assertEqual(out["profile_checked"], 10)

    def test_url_query_uses_public_page_scraper(self):
        fake_page = {"status": "ok", "url": "https://x.com/jane/status/1",
                     "final_url": "https://x.com/jane/status/1",
                     "title": "Post", "description": "hello", "platform": "X/Twitter",
                     "author": "Jane", "published": "2026-10-20T12:00:00Z",
                     "hashtags": ["osint"], "mentions": ["jane"],
                     "images": ["https://example.com/a.jpg"], "post_type": "post"}
        with mock.patch.object(SS, "scrape_public_page", return_value=fake_page):
            out = SS.search("https://x.com/jane/status/1")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["results"][0]["platform"], "X/Twitter")
        self.assertEqual(out["hashtags"], ["osint"])

    def test_case_attachment_is_hashed(self):
        fake_eng = {"ddg": {"status": "ok", "results": [
            {"title": "Hit", "url": "https://x.com/jane", "snippet": ""}]}}
        with mock.patch.object(SS, "_run_engines", return_value=fake_eng), \
                mock.patch.object(SS.db, "audit"), \
                mock.patch.object(SS.db, "store_artifact",
                                  return_value={"id": 7, "hash": "abc"}) as store:
            out = SS.search("Jane Doe", case_id=42, user="tester")
        store.assert_called_once()
        self.assertEqual(out["artifact"]["id"], 7)

    def test_empty_query_is_graceful(self):
        out = SS.search("")
        self.assertEqual(out["status"], "error")
        self.assertIn("empty", out["error"])


if __name__ == "__main__":
    unittest.main()
