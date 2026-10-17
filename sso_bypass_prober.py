#!/usr/bin/env python3
"""sso-bypass-prober — probe YOUR OWN login flow for classic SSO/auth bypasses.

Checks, all without any session cookie:
  1. direct access to common protected API paths
  2. query-param bypasses (?sso=false, ?auth=0, ?logged_in=true, ?role=admin, ...)
  3. header-injection bypasses (X-Forwarded-User, X-Remote-User, ...)
  4. HTTP method override (X-HTTP-Method-Override)

Stdlib only: urllib, http.server, argparse, unittest.
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------
# Probe definitions
# --------------------------------------------------------------------------

PROTECTED_PATHS = [
    "/api/users",
    "/api/admin",
    "/api/v1/users",
    "/api/v1/me",
    "/api/v1/admin",
    "/api/v2/users",
    "/api/internal",
    "/api/config",
    "/api/secrets",
    "/api/debug",
    "/admin",
    "/dashboard",
    "/settings",
    "/account",
    "/profile",
]

QUERY_BYPASS_PARAMS = [
    ("sso", "false"),
    ("auth", "0"),
    ("logged_in", "true"),
    ("loggedin", "1"),
    ("role", "admin"),
    ("admin", "true"),
    ("authenticated", "true"),
    ("bypass", "1"),
]

HEADER_BYPASSES = [
    ("X-Forwarded-User", "admin"),
    ("X-Remote-User", "admin"),
    ("X-Authenticated-User", "admin"),
    ("X-User", "admin"),
]

# Paths where param/header bypasses are worth trying (login-adjacent surface).
BYPASS_TARGETS = ["/dashboard", "/api/admin"]
METHOD_OVERRIDE_TARGETS = ["/api/admin", "/dashboard"]

LOGIN_MARKERS = (
    "password",
    "sign in",
    "signin",
    "log in",
    "login",
    "authentication",
    "/login",
)

SEVERITY = {
    "direct-access": "HIGH",
    "query-param-bypass": "HIGH",
    "header-injection": "HIGH",
    "method-override": "MEDIUM",
}


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def build_url(base, path, params=None):
    """Join a base URL and path, optionally appending a query string."""
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def fetch(url, headers=None, method="GET", data=None, timeout=10):
    """Unauthenticated request. Returns (status, body, final_url)."""
    req = urllib.request.Request(
        url, data=data, headers=headers or {}, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), resp.url
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), url
    except Exception as exc:  # connection refused, DNS, timeout...
        return None, "request failed: %s" % exc, url


def looks_like_login_page(body):
    lowered = body.lower()
    return any(marker in lowered for marker in LOGIN_MARKERS)


def is_protected_content(status, body):
    """True when an unauthenticated response looks like real protected content."""
    return (
        status == 200
        and len(body.strip()) >= 20
        and not looks_like_login_page(body)
    )


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def run_probes(base_url, timeout=10):
    """Run every check against base_url. Returns a list of finding dicts."""
    findings = []

    def add(check, url, detail):
        findings.append(
            {
                "check": check,
                "severity": SEVERITY[check],
                "url": url,
                "detail": detail,
            }
        )

    # 1. Direct access to protected paths, no cookie at all.
    for path in PROTECTED_PATHS:
        url = build_url(base_url, path)
        status, body, _ = fetch(url, timeout=timeout)
        if is_protected_content(status, body):
            add(
                "direct-access",
                url,
                "protected path returned HTTP %s with no session cookie" % status,
            )

    # 2. Query-param bypasses (only where the plain page is denied).
    for path in BYPASS_TARGETS:
        plain_url = build_url(base_url, path)
        status, body, _ = fetch(plain_url, timeout=timeout)
        if is_protected_content(status, body):
            continue  # already open; nothing to bypass
        for key, val in QUERY_BYPASS_PARAMS:
            url = build_url(base_url, path, {key: val})
            status, body, _ = fetch(url, timeout=timeout)
            if is_protected_content(status, body):
                add(
                    "query-param-bypass",
                    url,
                    "?%s=%s returned protected content (HTTP %s) with no session"
                    % (key, val, status),
                )

    # 3. Header-injection bypasses.
    for path in BYPASS_TARGETS:
        plain_url = build_url(base_url, path)
        status, body, _ = fetch(plain_url, timeout=timeout)
        if is_protected_content(status, body):
            continue
        for header, val in HEADER_BYPASSES:
            url = build_url(base_url, path)
            status, body, _ = fetch(url, headers={header: val}, timeout=timeout)
            if is_protected_content(status, body):
                add(
                    "header-injection",
                    url,
                    "%s: %s returned protected content (HTTP %s) with no session"
                    % (header, val, status),
                )

    # 4. HTTP method override.
    for path in METHOD_OVERRIDE_TARGETS:
        url = build_url(base_url, path)
        status, body, _ = fetch(
            url,
            method="POST",
            data=b"",
            headers={
                "X-HTTP-Method-Override": "GET",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=timeout,
        )
        if is_protected_content(status, body):
            add(
                "method-override",
                url,
                "X-HTTP-Method-Override: GET over POST returned protected "
                "content (HTTP %s) with no session" % status,
            )

    return findings


def print_findings(label, findings):
    print("== Probing %s ==" % label)
    if not findings:
        print("   no findings — every bypass vector was rejected")
    for f in findings:
        print("  [%s] %-18s %s" % (f["severity"], f["check"], f["url"]))
        print("         %s" % f["detail"])
    print("   => %d finding(s)\n" % len(findings))


def run_demo():
    """Start vulnerable + hardened local fixtures, probe both, show the difference."""
    from fixture import HardenedHandler, VulnerableHandler, start_fixture

    print("sso-bypass-prober --demo")
    print("Spinning up two LOCAL fixture apps (no network, no setup)...\n")

    vuln = start_fixture(VulnerableHandler)
    hard = start_fixture(HardenedHandler)
    vuln_url = "http://127.0.0.1:%d" % vuln.server_address[1]
    hard_url = "http://127.0.0.1:%d" % hard.server_address[1]

    try:
        vuln_findings = run_probes(vuln_url)
        print_findings("%s  (VULNERABLE fixture)" % vuln_url, vuln_findings)
        hard_findings = run_probes(hard_url)
        print_findings("%s  (HARDENED fixture)" % hard_url, hard_findings)
    finally:
        vuln.shutdown()
        hard.shutdown()

    print(
        "DEMO RESULT: vulnerable app exposed %d bypass finding(s); "
        "hardened app exposed %d." % (len(vuln_findings), len(hard_findings))
    )
    return 0 if vuln_findings and not hard_findings else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe YOUR OWN login flow for classic SSO/auth bypasses."
    )
    parser.add_argument("--target", help="base URL to probe, e.g. https://staging.myapp.com")
    parser.add_argument("--demo", action="store_true",
                        help="run the 30-second local demo against vulnerable + hardened fixtures")
    parser.add_argument("--timeout", type=int, default=10, help="per-request timeout in seconds")
    args = parser.parse_args(argv)

    if args.demo:
        return run_demo()
    if not args.target:
        parser.error("give --target <base-url> or --demo")
    findings = run_probes(args.target, timeout=args.timeout)
    print_findings(args.target, findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
