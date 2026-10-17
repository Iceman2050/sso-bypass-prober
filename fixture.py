"""Local vulnerable + hardened fixture apps for sso-bypass-prober.

--demo mode and the integration tests spin these up on localhost with zero setup.
Both fixtures expose the same surface; the vulnerable one is full of classic
SSO/auth bypasses, the hardened one ignores all of them.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DASHBOARD_HTML = (
    "<html><body><h1>Member Dashboard</h1>"
    "<p>Welcome back, admin. Secret metrics: 42.</p></body></html>"
)
LOGIN_HTML = (
    "<html><body><h1>Sign in</h1>"
    '<form action="/login"><input name="user">'
    '<input type="password" name="pw"><button>Log in</button></form>'
    "</body></html>"
)
ADMIN_JSON = '{"role":"admin","users":["alice","bob"],"flag":"SSO_ADMIN_PANEL"}'
USERS_JSON = '[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]'

# Classic query-param bypasses the vulnerable fixture falls for.
DASHBOARD_BYPASS_PARAMS = {
    "role": "admin",
    "logged_in": "true",
    "sso": "false",
    "auth": "0",
}
ADMIN_BYPASS_PARAMS = {"admin": "true"}

# Trusted-header names the vulnerable fixture naively accepts.
TRUSTED_HEADERS = (
    "x-forwarded-user",
    "x-remote-user",
    "x-authenticated-user",
    "x-user",
)


class _Base(BaseHTTPRequestHandler):
    server_version = "Fixture/1.0"

    def _cookie_ok(self):
        return "session=valid" in self.headers.get("Cookie", "")

    def _params(self):
        return parse_qs(urlparse(self.path).query)

    def _trusted_header_present(self):
        return any(self.headers.get(h) for h in TRUSTED_HEADERS)

    def _send(self, code, body, ctype="text/html"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep demo/test output clean
        pass


class VulnerableHandler(_Base):
    """Full of classic bypasses: param pollution, trusted headers, method override."""

    def _dashboard(self, params):
        if self._cookie_ok():
            return self._send(200, DASHBOARD_HTML)
        for key, val in DASHBOARD_BYPASS_PARAMS.items():
            if params.get(key, [None])[0] == val:
                return self._send(200, DASHBOARD_HTML)  # query-param bypass
        if self._trusted_header_present():
            return self._send(200, DASHBOARD_HTML)  # header-injection bypass
        return self._send(200, LOGIN_HTML)

    def _api_admin(self, params):
        if self._cookie_ok():
            return self._send(200, ADMIN_JSON, "application/json")
        for key, val in ADMIN_BYPASS_PARAMS.items():
            if params.get(key, [None])[0] == val:
                return self._send(200, ADMIN_JSON, "application/json")  # param pollution
        if self._trusted_header_present():
            return self._send(200, ADMIN_JSON, "application/json")  # header injection
        return self._send(401, '{"error":"unauthorized"}', "application/json")

    def do_GET(self):
        path = urlparse(self.path).path
        params = self._params()
        if path == "/dashboard":
            return self._dashboard(params)
        if path == "/api/admin":
            return self._api_admin(params)
        if path == "/api/users":
            return self._send(200, USERS_JSON, "application/json")  # no auth at all
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        if self.headers.get("X-HTTP-Method-Override"):
            # Naively trusts the override header and skips auth entirely.
            return self._send(200, ADMIN_JSON, "application/json")
        return self._send(403, '{"error":"forbidden"}', "application/json")


class HardenedHandler(_Base):
    """Ignores every bypass vector: cookie session or nothing."""

    def do_GET(self):
        path = urlparse(self.path).path
        authed = self._cookie_ok()
        if path == "/dashboard":
            return self._send(200, DASHBOARD_HTML if authed else LOGIN_HTML)
        if path == "/api/admin":
            if authed:
                return self._send(200, ADMIN_JSON, "application/json")
            return self._send(401, '{"error":"unauthorized"}', "application/json")
        if path == "/api/users":
            if authed:
                return self._send(200, USERS_JSON, "application/json")
            return self._send(401, '{"error":"unauthorized"}', "application/json")
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        # Method-override header is ignored; POST endpoints need a real session.
        if self._cookie_ok():
            return self._send(200, '{"ok":true}', "application/json")
        return self._send(403, '{"error":"forbidden"}', "application/json")


def start_fixture(handler_cls, port=0):
    """Start a fixture app on 127.0.0.1 (ephemeral port by default). Returns the server."""
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
