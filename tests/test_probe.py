"""Unit tests for the probe builders and response classifiers."""

import unittest

import sso_bypass_prober as p


class TestUrlBuilder(unittest.TestCase):
    def test_joins_base_and_path(self):
        self.assertEqual(
            p.build_url("https://app.example.com/", "/api/admin"),
            "https://app.example.com/api/admin",
        )

    def test_appends_query_params(self):
        url = p.build_url("https://app.example.com", "/dashboard", {"role": "admin"})
        self.assertEqual(url, "https://app.example.com/dashboard?role=admin")


class TestProbeLists(unittest.TestCase):
    def test_protected_paths_cover_common_api_surface(self):
        self.assertGreaterEqual(len(p.PROTECTED_PATHS), 15)
        for must_have in ("/api/users", "/api/admin", "/api/v1/me", "/dashboard"):
            self.assertIn(must_have, p.PROTECTED_PATHS)

    def test_query_bypass_params_include_classics(self):
        params = dict(p.QUERY_BYPASS_PARAMS)
        self.assertEqual(params["sso"], "false")
        self.assertEqual(params["auth"], "0")
        self.assertEqual(params["logged_in"], "true")
        self.assertEqual(params["role"], "admin")

    def test_header_bypasses_include_classics(self):
        headers = dict(p.HEADER_BYPASSES)
        for name in ("X-Forwarded-User", "X-Remote-User", "X-Authenticated-User"):
            self.assertIn(name, headers)

    def test_every_check_has_severity(self):
        for check in ("direct-access", "query-param-bypass",
                      "header-injection", "method-override"):
            self.assertIn(check, p.SEVERITY)


class TestResponseClassifier(unittest.TestCase):
    def test_login_page_is_not_protected_content(self):
        login = '<form><input type="password"><button>Sign in</button></form> welcome'
        self.assertTrue(p.looks_like_login_page(login))
        self.assertFalse(p.is_protected_content(200, login))

    def test_dashboard_html_is_protected_content(self):
        from fixture import DASHBOARD_HTML
        self.assertFalse(p.looks_like_login_page(DASHBOARD_HTML))
        self.assertTrue(p.is_protected_content(200, DASHBOARD_HTML))

    def test_non_200_is_not_protected_content(self):
        self.assertFalse(p.is_protected_content(401, '{"error":"unauthorized"} long enough body here'))
        self.assertFalse(p.is_protected_content(404, "not found page content here yes"))

    def test_tiny_body_is_not_protected_content(self):
        self.assertFalse(p.is_protected_content(200, "ok"))


if __name__ == "__main__":
    unittest.main()
