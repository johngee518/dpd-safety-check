#!/usr/bin/env python3
"""Sitemap-count rule: intended noindex shrinks pass; a broken or empty sitemap fails."""
import unittest

from check import evaluate_sitemap, is_noindex


class IsNoindexTests(unittest.TestCase):
    def test_meta_name_then_content(self):
        self.assertTrue(is_noindex({}, '<meta name="robots" content="noindex,follow">'))

    def test_meta_content_then_name(self):
        self.assertTrue(is_noindex({}, "<meta content='noindex' name='robots'>"))

    def test_meta_none_directive(self):
        self.assertTrue(is_noindex({}, '<meta name="robots" content="none">'))

    def test_x_robots_tag(self):
        self.assertTrue(is_noindex({"x-robots-tag": "noindex, nofollow"}, "<html></html>"))

    def test_index_follow_is_not_noindex(self):
        self.assertFalse(is_noindex({}, '<meta name="robots" content="index,follow">'))
        self.assertFalse(is_noindex({}, "<html><title>ok</title></html>"))
        self.assertFalse(is_noindex({"x-robots-tag": "all"}, ""))


class SitemapRuleTests(unittest.TestCase):
    def test_intentional_noindex_shrink_passes(self):
        current = [f"/hub/{i}/" for i in range(60)]
        dropped = [f"/states/{i}/" for i in range(40)]
        previous = current + dropped
        info = {path: {"status": 200, "noindex": True} for path in dropped}
        ok, detail = evaluate_sitemap(current, previous, info)
        self.assertTrue(ok, detail)
        self.assertIn("60 pages listed", detail)
        self.assertIn("40 dropped and noindexed", detail)

    def test_empty_sitemap_fails(self):
        ok, detail = evaluate_sitemap([], ["/rates/", "/homes/"], {})
        self.assertFalse(ok)
        self.assertIn("no English URLs", detail)

    def test_unreadable_sitemap_treated_as_empty_fails(self):
        ok, detail = evaluate_sitemap(None, ["/rates/"], {})
        self.assertFalse(ok)
        self.assertIn("no English URLs", detail)

    def test_broken_sitemap_drop_without_noindex_fails(self):
        current = ["/"]
        previous = ["/", "/rates/", "/homes/", "/blog/"]
        info = {
            "/rates/": {"status": 200, "noindex": False},
            "/homes/": {"status": 404, "noindex": False},
            "/blog/": {"status": 0, "error": "timeout"},
        }
        ok, detail = evaluate_sitemap(current, previous, info)
        self.assertFalse(ok, detail)
        self.assertIn("3 unexplained", detail)
        self.assertIn("/rates/ (200 without noindex)", detail)
        self.assertIn("/homes/ (HTTP 404)", detail)
        self.assertIn("/blog/ (HTTP timeout)", detail)

    def test_stable_or_growing_sitemap_passes(self):
        ok, detail = evaluate_sitemap(["/", "/rates/", "/new/"], ["/", "/rates/"], {})
        self.assertTrue(ok, detail)
        self.assertEqual(detail, "3 pages listed")

    def test_first_run_without_previous_passes_if_nonempty(self):
        ok, detail = evaluate_sitemap(["/", "/rates/"], None, {})
        self.assertTrue(ok, detail)
        self.assertEqual(detail, "2 pages listed")

    def test_mixed_drop_fails_if_any_unexplained(self):
        current = ["/a/"]
        previous = ["/a/", "/noindex/", "/oops/"]
        info = {
            "/noindex/": {"status": 200, "noindex": True},
            "/oops/": {"status": 200, "noindex": False},
        }
        ok, detail = evaluate_sitemap(current, previous, info)
        self.assertFalse(ok, detail)
        self.assertIn("1 unexplained", detail)
        self.assertIn("/oops/", detail)
        self.assertNotIn("/noindex/", detail)


if __name__ == "__main__":
    unittest.main()
