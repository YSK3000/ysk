import http.client
import io
import json
import os
import re
import socket
import threading
import unittest

import _support  # noqa: F401

from kekkai import config, netutil, server
from kekkai.mcp import Server as MCPServer
from kekkai.mcp import TOOLS, ToolError


class DashboardSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from kekkai import demo
        cfg = config.load()
        cls.monitor = demo.build(cfg)
        cls.token = "t" * 43
        cls.app = server.App(cls.monitor, cfg, cls.token, demo=True)
        cls.httpd = server.Server(("127.0.0.1", 0), cls.app)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.monitor.store.close()
        netutil.DEMO_PUBLIC_NETS = ()

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or "127.0.0.1:%d" % self.port}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def auth(self, extra=None):
        h = {"Authorization": "Bearer " + self.token}
        h.update(extra or {})
        return h

    def test_auth_and_host(self):
        r, _ = self.req("GET", "/api/summary")
        self.assertEqual(r.status, 401)
        r, body = self.req("GET", "/api/summary", headers=self.auth())
        self.assertEqual(r.status, 200)
        self.assertTrue(json.loads(body)["demo"])
        r, _ = self.req("GET", "/api/summary", headers=self.auth(), host="attacker.example:%d" % self.port)
        self.assertEqual(r.status, 403, "DNS rebinding: foreign Host header must be refused")
        r, _ = self.req("GET", "/api/summary", headers={"Cookie": "kekkai_session=wrong"})
        self.assertEqual(r.status, 401)

    def test_token_exchange_and_headers(self):
        r, _ = self.req("GET", "/?token=" + self.token)
        self.assertEqual(r.status, 302)
        ck = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", ck)
        self.assertIn("SameSite=Strict", ck)
        r, body = self.req("GET", "/")
        self.assertIn("ロック", body.decode())
        r, body = self.req("GET", "/", headers={"Cookie": "kekkai_session=" + self.token})
        self.assertIn('src="/static/js/app.js"', body.decode())
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")

    def test_csrf_and_scope(self):
        r, _ = self.req("POST", "/api/discover", body="{}", headers=self.auth({"Origin": "https://evil.example",
                                                                               "Content-Type": "application/json"}))
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/api/discover", body="{}", headers=self.auth({"Sec-Fetch-Site": "cross-site",
                                                                               "Content-Type": "application/json"}))
        self.assertEqual(r.status, 403)
        r, body = self.req("POST", "/api/scan", body=json.dumps({"ip": "8.8.8.8"}),
                           headers=self.auth({"Content-Type": "application/json"}))
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/api/scan", body="x" * 70000, headers=self.auth({"Content-Type": "application/json"}))
        self.assertEqual(r.status, 413)

    def test_static_traversal(self):
        for p in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/%2e%2e/config.py", "/static//etc/passwd"):
            r, _ = self.req("GET", p)
            self.assertEqual(r.status, 404, p)
        r, _ = self.req("GET", "/static/js/app.js")
        self.assertEqual(r.status, 200)

    def test_no_http_desync_on_rejected_post(self):
        """Regression: an unread body of a rejected POST must not be parsed as the next request."""
        smuggled = "GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port
        first = ("POST /api/discover HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: https://evil.example\r\n"
                 "Authorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (
                     self.port, self.token, len(smuggled), smuggled))
        second = "GET /static/favicon.svg HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % self.port
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall((first + second).encode())
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        statuses = re.findall(rb"HTTP/1\.1 (\d{3})", buf)
        self.assertEqual(statuses, [b"403", b"200"], buf[:300])

    def test_api_endpoints(self):
        for path in ("/api/connections", "/api/devices", "/api/alerts?status=all", "/api/posture", "/api/exposure",
                     "/api/intel", "/api/destinations?hours=24", "/api/timeline", "/api/report", "/api/ai/status",
                     "/api/lookup?ip=203.0.113.66", "/api/networks"):
            r, body = self.req("GET", path, headers=self.auth())
            self.assertEqual(r.status, 200, path)
            json.loads(body)
        r, body = self.req("GET", "/api/lookup?ip=203.0.113.66", headers=self.auth())
        self.assertEqual(json.loads(body)["threats"][0]["feed"], "feodo")
        r, _ = self.req("GET", "/api/lookup?ip=nonsense", headers=self.auth())
        self.assertEqual(r.status, 400)
        alerts = json.loads(self.req("GET", "/api/alerts?status=all", headers=self.auth())[1])["alerts"]
        aid = alerts[0]["id"]
        r, body = self.req("POST", "/api/alerts/%d/status" % aid, body=json.dumps({"status": "ack"}),
                           headers=self.auth({"Content-Type": "application/json"}))
        self.assertEqual((r.status, json.loads(body)["status"]), (200, "ack"))
        r, body = self.req("POST", "/api/ai/analyze", body=json.dumps({"alert_id": aid}),
                           headers=self.auth({"Content-Type": "application/json"}))
        self.assertEqual(r.status, 200)
        self.assertIn("ok", json.loads(body))


class FakeTools:
    def call(self, name, args):
        if name == "kekkai_lookup_ip" and args.get("ip") == "bad":
            raise ToolError("invalid IP address")
        return {"tool": name, "args": args}


class MCPTest(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        self.srv = MCPServer(tools=FakeTools(), out=self.out)

    def test_legacy_handshake(self):
        r = self.srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-03-26", "capabilities": {}}})
        self.assertEqual(r["result"]["protocolVersion"], "2025-03-26")
        r = self.srv.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})
        self.assertEqual(r["result"]["protocolVersion"], "2025-11-25")
        self.assertIsNone(self.srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = self.srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(len(tools), len(TOOLS))
        for t in tools:
            self.assertTrue(t["name"].startswith("kekkai_"))
            self.assertEqual(t["inputSchema"]["type"], "object")

    def test_modern_and_errors(self):
        meta = {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}
        r = self.srv.handle({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": meta})
        self.assertEqual(r["result"]["supportedVersions"], ["2026-07-28"])
        r = self.srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": dict(meta, name="kekkai_status", arguments={})})
        self.assertEqual(r["result"]["resultType"], "complete")
        self.assertFalse(r["result"]["isError"])
        r = self.srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                             "params": {"name": "kekkai_lookup_ip", "arguments": {"ip": "bad"}}})
        self.assertTrue(r["result"]["isError"])
        r = self.srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rm_rf", "arguments": {}}})
        self.assertEqual(r["error"]["code"], -32602)
        r = self.srv.handle({"jsonrpc": "2.0", "id": 5, "method": "does/not/exist"})
        self.assertEqual(r["error"]["code"], -32601)
        self.assertEqual(self.srv.handle({"id": 6, "method": "ping"})["error"]["code"], -32600)
        self.assertEqual(self.srv.handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})["result"], {})


class WebAssetTest(unittest.TestCase):
    """The dashboard must never build HTML from data (device names come from the network)."""

    def test_no_html_injection_sinks(self):
        root = os.path.join(os.path.dirname(__file__), "..", "src", "kekkai", "web", "js")
        for fn in os.listdir(root):
            with open(os.path.join(root, fn), encoding="utf-8") as f:
                src = re.sub(r"^\s*//.*$", "", f.read(), flags=re.M)
            for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
                self.assertNotIn(sink, src, "%s uses %s" % (fn, sink))
            self.assertNotRegex(src, r"(?<!add\()\b\w+\.append\(", "%s: use add() (null-safe) instead of Element.append" % fn)

    def test_html_has_no_inline_script(self):
        root = os.path.join(os.path.dirname(__file__), "..", "src", "kekkai", "web")
        for fn in ("index.html", "locked.html"):
            with open(os.path.join(root, fn), encoding="utf-8") as f:
                html = f.read()
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)", fn)
            self.assertNotIn("style=", html, fn)


if __name__ == "__main__":
    unittest.main()
