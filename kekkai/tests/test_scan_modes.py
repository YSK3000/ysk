"""nmap integration: XML parsing with versions, auto scan-mode selection, and auto-scan of new LAN devices."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401  テスト用の環境変数を設定する副作用のため読み込む
from kekkai import config
from kekkai.discovery import nmap
from kekkai.monitor import Monitor
from kekkai.platforms.base import Platform
from kekkai.store import Store

NMAP_XML = (
    '<?xml version="1.0"?>\n<nmaprun>\n<host>\n<ports>\n'
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"/></port>\n'
    '<port protocol="tcp" portid="80"><state state="closed"/></port>\n'
    '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>\n'
    '</ports>\n</host>\n</nmaprun>'
)


class StubPlatform(Platform):
    name = "test"


class ParseXmlTest(unittest.TestCase):
    def test_extracts_open_ports_with_version_banner(self):
        got = {p["port"]: p for p in nmap.parse_xml(NMAP_XML)}
        self.assertIn(22, got)
        self.assertNotIn(80, got)  # closed ports are dropped
        self.assertEqual(got[22]["service"], "ssh")
        self.assertIn("OpenSSH", got[22]["banner"])
        self.assertIn("9.6", got[22]["banner"])
        self.assertEqual(got[23]["risk"], "high")  # risk label kept from SERVICES (telnet)

    def test_rejects_xml_entities(self):  # XXE guard
        with self.assertRaises(ValueError):
            nmap.parse_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')


def _monitor(tmp):
    cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
    store = Store(str(Path(tmp) / "t.db"))
    return Monitor(cfg, store, StubPlatform()), cfg, store


class ScanModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m, self.cfg, store = _monitor(self.tmp.name)
        self.addCleanup(store.close)

    def test_auto_uses_nmap_when_available(self):
        self.m._deep_available = lambda: True
        self.assertEqual(self.m.resolve_scan_mode("auto"), "deep")

    def test_auto_falls_back_without_nmap(self):
        self.m._deep_available = lambda: False
        self.assertEqual(self.m.resolve_scan_mode("auto"), "quick")

    def test_auto_respects_use_nmap_off(self):
        self.m._deep_available = lambda: True
        self.cfg.set("scan.use_nmap", False)
        self.assertEqual(self.m.resolve_scan_mode("auto"), "quick")

    def test_explicit_modes_pass_through(self):
        self.m._deep_available = lambda: True
        self.assertEqual(self.m.resolve_scan_mode("quick"), "quick")
        self.assertEqual(self.m.resolve_scan_mode("deep"), "deep")


class AutoScanDevicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m, _, store = _monitor(self.tmp.name)
        self.addCleanup(store.close)

    def test_scans_local_ips_only_and_survives_a_failing_host(self):
        scanned = []

        def fake_deep(ip):
            scanned.append(ip)
            if ip == "192.168.1.5":
                raise RuntimeError("host down")
            return {"ip": ip, "open": [], "worst": None, "ts": 0}

        self.m._deep_scan = fake_deep
        with mock.patch.object(self.m, "raise_findings") as rf:
            self.m._autoscan_devices("net1", ["192.168.1.5", "192.168.1.6", "8.8.8.8"])
        # the public IP is skipped (LAN-only); both private IPs are tried despite the first failing
        self.assertEqual(scanned, ["192.168.1.5", "192.168.1.6"])
        self.assertEqual(rf.call_count, 1)  # only the successful scan produced findings


if __name__ == "__main__":
    unittest.main()
