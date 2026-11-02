"""脆弱性診断: nmap CPE -> NVD CVE lookup (rate limit, cache), KEV fallback, and the combined assessment."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _support import HERE

from kekkai import config, vulnscan
from kekkai.discovery import nmap
from kekkai.intel import nvd, vulns
from kekkai.monitor import Monitor
from kekkai.platforms.base import Platform
from kekkai.store import Store


def sample():
    with open(os.path.join(HERE, "fixtures", "vulns", "nvd_api2_sample.json"), "rb") as f:
        return f.read()


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


class CpeTest(unittest.TestCase):
    def test_cpe22_to_23(self):
        self.assertEqual(nvd.cpe23("cpe:/a:openbsd:openssh:7.4"), "cpe:2.3:a:openbsd:openssh:7.4")
        self.assertEqual(nvd.cpe23("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"), "cpe:2.3:a:openbsd:openssh:9.6")

    def test_refuses_versionless_or_odd_cpe(self):  # would match every CVE of the product
        self.assertIsNone(nvd.cpe23("cpe:/a:apache:http_server"))
        self.assertIsNone(nvd.cpe23("cpe:/a:apache:http_server:*"))
        self.assertIsNone(nvd.cpe23("cpe:/a:evil:x&y:1.0"))
        self.assertIsNone(nvd.cpe23("not-a-cpe"))
        self.assertEqual(nvd.vendor_product("cpe:/a:apache:http_server"), ("apache", "http_server"))


class ParseTest(unittest.TestCase):
    def test_parses_scores_kev_and_drops_rejected(self):
        cves, total = nvd.parse(sample())
        ids = [c["id"] for c in cves]
        self.assertNotIn("CVE-2099-1004", ids)                 # rejected
        self.assertEqual(ids[0], "CVE-2099-1002")              # KEV first
        by = {c["id"]: c for c in cves}
        self.assertTrue(by["CVE-2099-1002"]["kev"])
        self.assertEqual((by["CVE-2099-1001"]["score"], by["CVE-2099-1001"]["severity"]), (9.8, "critical"))
        self.assertEqual(by["CVE-2099-1003"]["severity"], "medium")  # v2 keeps severity outside cvssData
        self.assertTrue(by["CVE-2099-1001"]["summary"].startswith("Test entry"))  # English description chosen
        self.assertEqual(total, 4)


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = Clock()
        self.calls = []

    def client(self, status=200, body=None):
        def fetch(url, **kw):
            self.calls.append((url, kw.get("headers")))
            return status, {}, body if body is not None else sample()
        return nvd.NVD(Path(self.tmp.name), fetch=fetch, clock=self.clock.now, sleep=self.clock.sleep)

    def test_query_uses_virtual_match_and_caches(self):
        c = self.client()
        r1 = c.cves_for("cpe:/a:openbsd:openssh:7.4")
        self.assertIn("virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A7.4", self.calls[0][0])
        self.assertEqual(len(r1["cves"]), 3)
        r2 = c.cves_for("cpe:/a:openbsd:openssh:7.4")
        self.assertTrue(r2["cached"])
        self.assertEqual(len(self.calls), 1)

    def test_rate_gap_between_requests(self):
        c = self.client()
        c.cves_for("cpe:/a:openbsd:openssh:7.4")
        c.cves_for("cpe:/a:openbsd:openssh:8.0")
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(self.clock.slept and self.clock.slept[0] >= 6.0)  # 5 per 30 s without a key

    def test_rate_limited_stops_and_is_not_cached(self):
        c = self.client(status=403, body=b"")
        r = c.cves_for("cpe:/a:openbsd:openssh:7.4")
        self.assertTrue(c.rate_limited and r["error"])
        self.assertTrue(c.cves_for("cpe:/a:openbsd:openssh:8.0")["error"])
        self.assertEqual(len(self.calls), 1)  # no hammering after the limit
        self.assertEqual(list(Path(self.tmp.name).glob("*.json")), [])

    def test_failure_is_never_cached_as_no_cves(self):
        c = self.client(status=500, body=b"")
        self.assertTrue(c.cves_for("cpe:/a:openbsd:openssh:7.4")["error"])
        self.assertEqual(list(Path(self.tmp.name).glob("*.json")), [])

    def test_versionless_is_skipped_without_request(self):
        c = self.client()
        self.assertTrue(c.cves_for("cpe:/a:apache:http_server")["skipped"])
        self.assertEqual(self.calls, [])

    def test_api_key_header(self):
        def fetch(url, **kw):
            self.calls.append(kw.get("headers"))
            return 200, {}, sample()
        nvd.NVD(Path(self.tmp.name), fetch=fetch, api_key="k", clock=self.clock.now,
                sleep=self.clock.sleep).cves_for("cpe:/a:openbsd:openssh:7.4")
        self.assertEqual(self.calls[0], {"apiKey": "k"})


class NmapCpeTest(unittest.TestCase):
    def test_parse_xml_keeps_cpe_product_version(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0">'
               '<cpe>cpe:/a:openbsd:openssh:7.4</cpe></service></port></ports></host></nmaprun>')
        p = nmap.parse_xml(xml)[0]
        self.assertEqual((p["product"], p["version"], p["cpe"]), ("OpenSSH", "7.4", ["cpe:/a:openbsd:openssh:7.4"]))


class StubPlatform(Platform):
    name = "test"

    def os_version(self):
        return None


class FakeNVD:
    queried = 1
    cache_hits = 0
    rate_limited = False

    def __init__(self, error=None):
        self.error = error

    def cves_for(self, cpe):
        if self.error:
            return {"cpe": cpe, "cves": [], "total": 0, "error": self.error}
        cves, total = nvd.parse(sample())
        return {"cpe": cpe, "query": nvd.cpe23(cpe), "cves": cves, "total": total, "error": None}


KEV_ROWS = {"title": "test", "catalogVersion": "test", "count": 12, "vulnerabilities": [
    {"cveID": "CVE-2099-2001", "vendorProject": "OpenBSD", "product": "OpenSSH",
     "vulnerabilityName": "Test entry OpenSSH", "dateAdded": "2099-01-01", "dueDate": "2099-01-21",
     "knownRansomwareCampaignUse": "Unknown"}] + [
    {"cveID": "CVE-2099-30%02d" % i, "vendorProject": "Example%d" % i, "product": "Widget",
     "vulnerabilityName": "Test entry", "dateAdded": "2099-01-01"} for i in range(11)]}


class AssessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.addCleanup(self.store.close)
        with mock.patch.object(vulns, "KEV_MIN", 5):
            vulns.update(force=True, fetch=lambda url, **_: (200, {}, json.dumps(KEV_ROWS).encode())
                         if "kev" in url else (200, {}, b'{"OSVersions": []}'))
        self.m = Monitor(cfg, self.store, StubPlatform())
        self.m.vulns = vulns.VulnDB()
        self.m.state["network"] = {"id": "net1"}
        self.store.upsert_device("net1", "aa:bb:cc:00:00:01", "192.168.1.20", vendor="Acme", kind="nas")
        self.store.set_device_ports("net1", "aa:bb:cc:00:00:01", [
            {"port": 22, "service": "ssh", "risk": "low", "product": "OpenSSH", "version": "7.4",
             "cpe": ["cpe:/a:openbsd:openssh:7.4"]},
            {"port": 23, "service": "telnet", "risk": "high", "note": "Telnetは平文。無効化を。"}])
        self.m._deep_available = lambda: False

    def test_service_cves_ranked_and_config_flagged(self):
        res = vulnscan.assess(self.m, nvd=FakeNVD())
        svc = [i for i in res["items"] if i["category"] == "service"]
        cfg = [i for i in res["items"] if i["category"] == "config"]
        self.assertEqual(len(svc), 1)
        self.assertEqual(svc[0]["severity"], "critical")       # KEV-listed and CVSS 9.8 present
        self.assertEqual(svc[0]["exploited"], ["CVE-2099-1002"])
        self.assertEqual(svc[0]["cve_count"], 4)
        self.assertEqual(cfg[0]["port"], 23)
        self.assertEqual(res["items"][0]["category"], "service")  # most severe first
        self.assertEqual(res["summary"]["worst"], "critical")
        f = vulnscan.findings(res)
        self.assertEqual([x.rule for x in f], ["vuln.service"])

    def test_offline_falls_back_to_product_level_kev(self):
        res = vulnscan.assess(self.m, nvd=None)
        svc = [i for i in res["items"] if i["category"] == "service"]
        self.assertEqual(svc[0]["confidence"], "低")
        self.assertIn("CVE-2099-2001", svc[0]["exploited"])
        self.assertIn("版は未照合", svc[0]["title"])

    def test_nvd_error_also_falls_back(self):
        res = vulnscan.assess(self.m, nvd=FakeNVD(error="NVDの回数制限"))
        svc = [i for i in res["items"] if i["category"] == "service"]
        self.assertEqual(svc[0]["note"], "NVDの回数制限")

    def test_exposed_risky_service_is_critical(self):
        self.m.state["exposure"] = {"shared_ipv4": False, "internetdb": {"found": True, "ports": [23], "vulns": []}}
        res = vulnscan.assess(self.m, nvd=FakeNVD())
        cfg = [i for i in res["items"] if i["category"] == "config"][0]
        self.assertEqual(cfg["severity"], "critical")

    def test_run_vulnscan_stores_and_refuses_concurrent(self):
        self.m.nvd_client = lambda use_nvd=None: FakeNVD()
        res = self.m.run_vulnscan(scan_devices=False)
        self.assertEqual(self.m.state["vulnscan"]["ts"], res["ts"])
        self.assertEqual(self.store.kv_get("vulnscan_last")["summary"]["worst"], "critical")
        self.assertEqual(self.m.summary()["vulnscan"]["summary"]["worst"], "critical")
        self.m.state["vulnscan_running"] = True
        with self.assertRaises(RuntimeError):
            self.m.run_vulnscan(scan_devices=False)

    def test_weekly_cycle_skips_when_recent(self):
        self.m.nvd_client = lambda use_nvd=None: FakeNVD()
        self.m.run_vulnscan(scan_devices=False)
        self.assertTrue(self.m.vulnscan_cycle()["skipped"])

    def test_blind_spots_are_never_reported_as_clean(self):
        self.store.set_device_ports("net1", "aa:bb:cc:00:00:01", [])   # nothing to find
        res = vulnscan.assess(self.m, nvd=None)                       # offline, no nmap, no exposure check
        self.assertEqual(res["summary"]["total"], 0)
        self.assertFalse(res["summary"]["complete"])
        self.assertEqual(res["summary"]["label"], "検出なし（診断は不完全）")
        joined = " ".join(res["gaps"])
        self.assertIn("nmap", joined)
        self.assertIn("NVD", joined)
        self.assertIn("公開IP", joined)

    def test_coverage_cards_reflect_real_runs(self):
        from kekkai.coverage import describe
        cards = {c["id"]: c for c in describe(self.m)["cards"]}
        self.assertEqual(cards["vulnscan"]["state"], "inactive")       # never claims a scan that did not run
        self.assertEqual(cards["exposure"]["state"], "inactive")
        self.assertEqual(cards["leaks"]["state"], "inactive")
        self.m.nvd_client = lambda use_nvd=None: FakeNVD()
        self.m.run_vulnscan(scan_devices=False)
        cards = {c["id"]: c for c in describe(self.m)["cards"]}
        self.assertEqual(cards["vulnscan"]["state"], "partial")        # no nmap / exposure here -> partial
        self.assertIn("緊急 1", cards["vulnscan"]["detail"])

    def test_report_includes_assessment(self):
        from kekkai import report
        self.m.nvd_client = lambda use_nvd=None: FakeNVD()
        self.m.run_vulnscan(scan_devices=False)
        md = report.markdown(self.m)
        self.assertIn("## 脆弱性診断", md)
        self.assertIn("CVE-2099-1002", md)
        self.assertIn("未診断:", md)

    def test_kev_for_product_exact_match_only(self):
        db = self.m.vulns
        self.assertEqual([k["cveID"] for k in db.kev_for_product("openbsd", "openssh")], ["CVE-2099-2001"])
        self.assertEqual(db.kev_for_product("openbsd", "open"), [])
        self.assertEqual(db.kev_for_product("apple", "macos"), [])  # vendors skipped for product matching


if __name__ == "__main__":
    unittest.main()
