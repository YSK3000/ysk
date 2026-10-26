"""Tor access: SOCKS5 must hand the .onion name to Tor (no local DNS), and only text from .onion is read."""
import socket
import struct
import threading
import unittest

import _support  # noqa: F401

from kekkai.intel import tor

ONION = "a" * 52 + "abcd.onion"


class FakeTor:
    """A minimal SOCKS5 server standing in for tor, recording what the client asked for."""

    def __init__(self, reply=0, body=b"<html><title>Leak board</title><script>x()</script><p>ACME Corp files</p></html>",
                 ctype="text/html; charset=utf-8"):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.addr = self.srv.getsockname()
        self.requests = []
        self.reply, self.body, self.ctype = reply, body, ctype
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c:
                hello = c.recv(3)
                c.sendall(b"\x05\x00")
                if len(hello) < 3:
                    continue
                head = c.recv(4)
                if len(head) < 4:
                    continue
                ver, cmd, _, atyp = head
                name = c.recv(c.recv(1)[0]) if atyp == 3 else c.recv(4)
                port = struct.unpack("!H", c.recv(2))[0]
                self.requests.append((cmd, atyp, name.decode(errors="replace"), port))
                c.sendall(bytes([5, self.reply, 0, 1]) + b"\0\0\0\0\0\0")
                if self.reply:
                    continue
                c.recv(65536)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (
                    self.ctype.encode(), len(self.body), self.body))

    def close(self):
        self.srv.close()


class TorTest(unittest.TestCase):
    def test_onion_name_is_resolved_by_tor_not_locally(self):
        t = FakeTor()
        self.addCleanup(t.close)
        page = tor.fetch_onion("http://%s/board" % ONION, proxy=t.addr, timeout=10)
        self.assertEqual(t.requests, [(1, 3, ONION, 80)])  # CONNECT with ATYP 3 = domain name
        self.assertEqual(page["title"], "Leak board")
        self.assertIn("ACME Corp files", page["text"])
        self.assertNotIn("x()", page["text"])  # scripts are dropped

    def test_tor_errors_are_explained(self):
        t = FakeTor(reply=0xF0)
        self.addCleanup(t.close)
        with self.assertRaisesRegex(tor.TorError, "onionサービスの情報が見つかりません"):
            tor.fetch_onion("http://%s/" % ONION, proxy=t.addr, timeout=10)

    def test_binaries_are_not_downloaded(self):
        t = FakeTor(body=b"PK\x03\x04" + b"\0" * 100, ctype="application/zip")
        self.addCleanup(t.close)
        page = tor.fetch_onion("http://%s/dump.zip" % ONION, proxy=t.addr, timeout=10)
        self.assertEqual((page["text"], page["skipped"]), ("", "テキスト以外は取得しません"))

    def test_only_onion_hosts(self):
        for bad in ("http://example.com/", "file:///etc/passwd", "http://abc.onion/", "http://127.0.0.1/"):
            with self.assertRaises(tor.TorError):
                tor.fetch_onion(bad, proxy=("127.0.0.1", 1))
        self.assertTrue(tor.is_onion(ONION))
        self.assertFalse(tor.is_onion("facebookcorewwwi.onion"))  # v2: retired by Tor


class OwnTorTest(unittest.TestCase):
    def test_own_tor_is_recorded_not_alarmed(self):
        from kekkai.detect import engine
        tor_exit = [{"kind": "tor-exit", "severity": "low", "label": "Tor exit", "feed": "tor_exit"}]
        base = {"raddr": "185.220.101.1", "rport": 9001, "direction": "out", "threats": tor_exit, "geo": {}}
        mine = dict(base, process="tor", path="/opt/homebrew/Cellar/tor/0.4.9.14/bin/tor")
        other = dict(base, process="tor", path="/Users/Shared/.x/tor")  # a fake "tor" elsewhere stays an alert
        inbound = dict(mine, direction="in", lport=22)
        sev = [engine.connection_findings([c], set())[0].severity for c in (mine, other, inbound)]
        self.assertEqual(sev, ["info", "low", "medium"])


if __name__ == "__main__":
    unittest.main()
