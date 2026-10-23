import unittest

from hunter.detection import fingerprint
from hunter.engine import wildcard_page_match
from hunter.gui import same_site_views
from hunter.network import Response


class SiteIdentityTests(unittest.TestCase):
    def asset(self, url, body, truncated=False):
        response = Response(url, 200, {"content-type": "text/html; charset=utf-8"},
                            body, 1, truncated=truncated)
        return {"url": url, **fingerprint(response, ["example.test"])}

    def test_truncated_identical_pages_can_group(self):
        body = "<title>Example</title>" + "public information " * 500
        apex = self.asset("https://example.test/", body, truncated=True)
        www = self.asset("https://www.example.test/", body, truncated=True)
        self.assertIsNone(apex["content_sha256"])
        self.assertTrue(same_site_views(apex, www))

    def test_minor_dynamic_text_can_group_but_distinct_sites_do_not(self):
        shared = "".join(f"<p>Public page section number {number} contains useful information.</p>"
                         for number in range(100))
        apex = self.asset("https://example.test/", f"<title>Example</title>{shared}<p>Today: Monday</p>")
        www = self.asset("https://www.example.test/", f"<title>Example</title>{shared}<p>Today: Tuesday</p>")
        different = self.asset("https://www.example.test/",
                               "<title>Unrelated store</title>" + "<p>Completely different products</p>" * 100)
        self.assertTrue(same_site_views(apex, www))
        self.assertFalse(same_site_views(apex, different))

    def test_short_identical_protocol_responses_can_group(self):
        http = self.asset("http://example.test/", "<p>OK</p>")
        https = self.asset("https://example.test/", "<p>OK</p>")
        self.assertTrue(same_site_views(http, https))
        www = self.asset("https://www.example.test/", "<p>OK</p>")
        self.assertTrue(same_site_views(https, www))

    def test_login_shell_with_dynamic_markup_and_same_public_text_can_group(self):
        shared = "<title>Account login</title>" + "<p>Sign in to your account now</p>" * 4
        http = self.asset("http://example.test/", shared + "<script>" + "a" * 2200 + "</script>")
        https = self.asset("https://example.test/", shared + "<script>" + "b" * 2200 + "</script>")
        self.assertTrue(same_site_views(http, https))

    def test_shared_layout_with_different_titles_is_not_one_site(self):
        shared = "<p>" + " ".join(f"menu{number}" for number in range(120)) + "</p>"
        http = self.asset("http://example.test/",
                          "<title>Internal admin portal</title>" + shared + "<p>Administration</p>")
        https = self.asset("https://example.test/",
                           "<title>Public customer portal</title>" + shared + "<p>Shopping</p>")
        self.assertFalse(same_site_views(http, https))

    def test_distinct_canonical_paths_do_not_merge_shared_layouts(self):
        shared = "<p>" + " ".join(f"menu{number}" for number in range(120)) + "</p>"
        http = self.asset("http://example.test/",
                          '<title>Internal admin portal</title><link rel="canonical" '
                          'href="https://example.test/admin">' + shared + "<p>Administration</p>")
        https = self.asset("https://example.test/",
                           '<title>Public customer portal</title><link rel="canonical" '
                           'href="https://example.test/shop">' + shared + "<p>Shopping</p>")
        self.assertEqual(http["site_identity"]["canonical"], "https://example.test/admin")
        self.assertEqual(https["site_identity"]["canonical"], "https://example.test/shop")
        self.assertFalse(same_site_views(http, https))

    def test_matching_full_canonical_can_corroborate_dynamic_variants(self):
        shared = "<p>" + " ".join(f"menu{number}" for number in range(120)) + "</p>"
        canonical = '<link rel="canonical" href="https://example.test/home">'
        http = self.asset("http://example.test/", "<title>Old title</title>" + canonical + shared)
        https = self.asset("https://example.test/", "<title>New title</title>" + canonical + shared)
        self.assertTrue(same_site_views(http, https))

    def test_restricted_and_healthy_protocol_views_stay_separate(self):
        http = self.asset("http://example.test/", "<title>Admin login</title>")
        http["http_status"] = 401
        https = self.asset("https://example.test/", "<title>Public storefront</title>")
        self.assertFalse(same_site_views(http, https))

    def test_wildcard_empty_page_is_suppressed_but_real_content_survives(self):
        baseline = self.asset("https://random.example.test/", "")
        empty_candidate = self.asset("https://accounts.example.test/", "")
        real_candidate = self.asset("https://admin.example.test/",
                                    "<title>Administration</title><p>Real login page</p>")
        php_response = Response("https://php.example.test/", 200,
                                {"content-type": "text/html", "x-powered-by": "PHP/8.5.12"}, "", 1)
        php_candidate = {"url": php_response.url, **fingerprint(php_response, ["example.test"])}
        different_server = {**empty_candidate, "server": "nginx"}
        self.assertTrue(wildcard_page_match(empty_candidate, baseline))
        self.assertFalse(wildcard_page_match(real_candidate, baseline))
        self.assertFalse(wildcard_page_match(php_candidate, baseline))
        self.assertFalse(wildcard_page_match(different_server, baseline))


if __name__ == "__main__":
    unittest.main()
