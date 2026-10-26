"""AI privacy boundaries; no real model or cloud credentials are needed."""
import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

import _support  # noqa: F401
from kekkai import ai, config, server


class AIPrivacyTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        self.alert = {"rule": "lan.new_device", "detail": "fictional test device"}

    def test_auto_never_falls_back_to_cloud(self):
        with patch.object(ai, "ollama_models", return_value=[]), \
                patch.object(ai, "openai_models", return_value=[]), \
                patch.object(ai, "anthropic_ready", return_value=(True, "ready")) as ready, \
                patch.object(ai, "_anthropic") as cloud:
            self.assertEqual(ai.choose(self.cfg), (None, None))
            self.assertFalse(ai.analyze_alert(self.cfg, self.alert)["ok"])
            ready.assert_not_called()
            cloud.assert_not_called()

    def test_explicit_cloud_still_redacts(self):
        self.cfg.set("ai.provider", "anthropic")
        self.alert["detail"] = "aa:bb:cc:dd:ee:ff home 203.0.113.9"
        monitor = SimpleNamespace(state={"exposure": {"public_ip": "203.0.113.9"}}, demo=False)
        with patch.object(ai, "anthropic_ready", return_value=(True, "ready")), \
                patch.object(ai, "_anthropic", return_value={"ok": True}) as cloud:
            self.assertTrue(ai.analyze_alert(self.cfg, self.alert, monitor)["ok"])
            prompt = cloud.call_args.args[2]
            self.assertNotIn("aa:bb:cc:dd:ee:ff", prompt)
            self.assertNotIn("203.0.113.9", prompt)
            self.assertIn("aa:bb:cc:xx:xx:xx", prompt)

    def test_manual_model_cannot_bypass_local_url_check(self):
        for provider, key in (("ollama", "ollama_url"), ("openai", "openai_base_url")):
            with self.subTest(provider=provider):
                self.cfg.set("ai.provider", provider)
                self.cfg.set("ai." + key, "https://outside.example/v1")
                self.cfg.set("ai." + provider + "_model", "test-model")
                with patch.object(ai, "_local") as local:
                    self.assertFalse(ai.analyze_alert(self.cfg, self.alert)["ok"])
                    local.assert_not_called()

    def test_transport_refuses_nonlocal_before_open(self):
        with patch("urllib.request.build_opener") as build:
            with self.assertRaises(ValueError):
                ai._local("POST", "https://outside.example/chat", {"secret": "dummy"})
            build.assert_not_called()

    def test_local_url_validation(self):
        for url in ("http://127.0.0.1:11434", "http://localhost:1234/v1", "https://[::1]:1234/v1"):
            self.assertTrue(ai._is_local_url(url), url)
        for url in (None, 1, "", "file:///etc/passwd", "http://localhost.evil/", "http://localhost@evil/",
                    "http://user@localhost/", "http://127.0.0.1:99999/", "http://localhost:0/",
                    "http://localhost/\n", "http://localhost/v1?token=x", "http://localhost/#fragment"):
            with self.subTest(url=url):
                self.assertFalse(ai._is_local_url(url))

    def test_localhost_is_pinned_to_loopback(self):
        with patch("urllib.request.build_opener") as build:
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b"{}"
            self.assertEqual(ai._local("GET", "http://localhost:1234/v1/models"), {})
            self.assertEqual(build.return_value.open.call_args.args[0].full_url,
                             "http://127.0.0.1:1234/v1/models")

    def test_disabled_does_not_probe_models(self):
        self.cfg.set("ai.provider", "off")
        with patch.object(ai, "_local") as local, patch.object(ai, "anthropic_ready") as cloud:
            self.assertIsNone(ai.status(self.cfg)["active"])
            self.assertFalse(ai.analyze_alert(self.cfg, self.alert)["ok"])
            local.assert_not_called()
            cloud.assert_not_called()




    def test_status_does_not_select_available_cloud_automatically(self):
        with patch.object(ai, "ollama_models", return_value=[]), \
                patch.object(ai, "openai_models", return_value=[]), \
                patch.object(ai, "anthropic_ready", return_value=(True, "ready")):
            result = ai.status(self.cfg)
            self.assertIsNone(result["active"])
            self.assertTrue(next(p for p in result["providers"] if p["id"] == "anthropic")["available"])

    def test_unknown_provider_is_reported(self):
        self.cfg.set("ai.provider", "typo")
        with self.assertRaises(RuntimeError):
            ai.choose(self.cfg)

    def test_malformed_model_lists_are_unavailable(self):
        for discover, key in ((ai.ollama_models, "models"), (ai.openai_models, "data")):
            for payload in (None, [], {key: None}, {key: "invalid"}, {key: [None, 42, {}]}):
                with self.subTest(discover=discover.__name__, payload=payload):
                    with patch.object(ai, "_local", return_value=payload):
                        self.assertEqual(discover(self.cfg), [])

    def test_local_provider_order_and_fixed_models(self):
        with patch.object(ai, "ollama_models", return_value=["ollama-test"]), \
                patch.object(ai, "openai_models", return_value=["lm-test"]):
            self.assertEqual(ai.choose(self.cfg), ("ollama", "ollama-test"))
            self.assertEqual(ai.choose(self.cfg, om=[]), ("openai", "lm-test"))
        for provider, reply in (("ollama", {"message": {"content": "analysis"}}),
                                ("openai", {"choices": [{"message": {"content": "analysis"}}]})):
            self.cfg.set("ai.provider", provider)
            self.cfg.set("ai." + provider + "_model", "fixed-model")
            with patch.object(ai, "_local", return_value=reply):
                self.assertTrue(ai.analyze_alert(self.cfg, self.alert)["ok"])

    def test_malformed_analysis_returns_error_instead_of_crashing(self):
        for provider in ("ollama", "openai"):
            self.cfg.set("ai.provider", provider)
            self.cfg.set("ai." + provider + "_model", "fixed-model")
            for payload in (None, [], {"message": 1}, {"choices": [None]}):
                with self.subTest(provider=provider, payload=payload), patch.object(ai, "_local", return_value=payload):
                    self.assertFalse(ai.analyze_alert(self.cfg, self.alert)["ok"])


class LocalHTTPTest(unittest.TestCase):
    def test_success_and_all_redirects(self):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path.startswith("/redirect/"):
                    self.send_response(int(self.path.rsplit("/", 1)[1]))
                    self.send_header("Location", "/target")
                    self.end_headers()
                else:
                    body = json.dumps({"models": [{"name": "local-model"}]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        try:
            self.assertEqual(ai._local("GET", base + "/models")["models"][0]["name"], "local-model")
            for code in (301, 302, 303, 307, 308):
                with self.subTest(code=code):
                    with self.assertRaises((ValueError, OSError)):
                        ai._local("GET", base + "/redirect/%d" % code)
            self.assertNotIn("/target", hits, "a redirect must never be followed, even locally")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
