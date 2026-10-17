"""Integration tests: probe the local fixtures and assert real behavior."""

import unittest

import sso_bypass_prober as p
from fixture import HardenedHandler, VulnerableHandler, start_fixture


class FixtureCase(unittest.TestCase):
    handler = None

    @classmethod
    def setUpClass(cls):
        cls.server = start_fixture(cls.handler)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()


class TestVulnerableFixture(FixtureCase):
    handler = VulnerableHandler

    def test_bypasses_are_found(self):
        findings = p.run_probes(self.base)
        self.assertTrue(findings, "expected findings on the vulnerable fixture")
        checks = {f["check"] for f in findings}
        self.assertIn("query-param-bypass", checks)
        self.assertIn("header-injection", checks)
        self.assertIn("direct-access", checks)
        self.assertIn("method-override", checks)

    def test_query_param_bypass_on_dashboard(self):
        findings = p.run_probes(self.base)
        urls = [f["url"] for f in findings if f["check"] == "query-param-bypass"]
        self.assertTrue(any("role=admin" in u and "/dashboard" in u for u in urls))

    def test_param_pollution_on_api_admin(self):
        findings = p.run_probes(self.base)
        urls = [f["url"] for f in findings if f["check"] == "query-param-bypass"]
        self.assertTrue(any("admin=true" in u and "/api/admin" in u for u in urls))

    def test_findings_carry_severity(self):
        for f in p.run_probes(self.base):
            self.assertIn(f["severity"], ("HIGH", "MEDIUM"))


class TestHardenedFixture(FixtureCase):
    handler = HardenedHandler

    def test_no_bypasses_found(self):
        findings = p.run_probes(self.base)
        self.assertEqual(findings, [],
                         "hardened fixture must produce zero findings, got: %r" % findings)


if __name__ == "__main__":
    unittest.main()
