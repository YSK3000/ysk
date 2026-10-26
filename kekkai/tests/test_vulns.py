"""Matching against public vulnerability data, using excerpts of the real CISA KEV catalog and SOFA feed."""
import json
import os
import time
import unittest
from unittest import mock

from _support import HERE

from kekkai import config, paths
from kekkai.detect import engine as rules
from kekkai.intel import vulns
from kekkai.util import FetchError


def raw(name):
    with open(os.path.join(HERE, "fixtures", "vulns", name), "rb") as f:
        return f.read()


class VulnDataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def fetch(url, **_):
            if "cisa.gov" in url or "sofafeed" in url:
                raise FetchError("blocked")  # primary sites unreachable -> GitHub mirrors are used
            return 200, {}, raw("kev_excerpt.json" if "kev" in url else "sofa_excerpt.json")
        with mock.patch.object(vulns, "KEV_MIN", 10):
            cls.rep = vulns.update(force=True, fetch=fetch)
        cls.db = vulns.VulnDB()

    def test_update_falls_back_to_mirrors(self):
        self.assertEqual(self.rep, {"kev.json": "ok", "sofa_macos.json": "ok"})
        self.assertEqual(vulns.update(fetch=lambda *a, **k: self.fail("fresh files must not be refetched")),
                         {"kev.json": "fresh", "sofa_macos.json": "fresh"})

    def test_broken_download_keeps_old_data(self):
        rep = vulns.update(force=True, fetch=lambda url, **_: (200, {}, b'{"vulnerabilities": []}'))
        self.assertTrue(rep["kev.json"].startswith("error"))
        self.assertGreater(self.db.status()["kev_entries"], 10)

    def test_macos_version_gap(self):  # the real numbers for the macOS seen on the CI runner
        st = self.db.macos("26.6.2", now=time.mktime((2026, 10, 26, 0, 0, 0, 0, 0, -1)))
        self.assertEqual((st["line"], st["latest"], st["cves"]), ("Tahoe 26", "26.7.1", 174))
        self.assertEqual(st["exploited"], ["CVE-2026-65400", "CVE-2026-86950"])
        self.assertEqual(set(st["kev"]), set(st["exploited"]))
        f = rules.macos_vuln_findings(st)
        self.assertEqual((f[0].rule, f[0].severity), ("host.macos_vulns", "high"))
        self.assertIn("support.apple.com", f[0].detail)
        self.assertEqual(self.db.macos("26.7.1")["cves"], 0)
        self.assertEqual(rules.macos_vuln_findings(self.db.macos("26.7.1")), [])

    def test_unsupported_macos(self):
        st = self.db.macos("12.7.6", now=time.mktime((2026, 10, 26, 0, 0, 0, 0, 0, -1)))
        f = rules.macos_vuln_findings(st)
        self.assertEqual((f[0].rule, f[0].severity), ("host.macos_unsupported", "high"))
        self.assertTrue(self.db.macos("11.7.10")["unknown_line"])
        self.assertIsNone(self.db.macos(None))

    def test_device_model_and_vendor(self):
        hit = self.db.device_hits("D-Link International", ["DIR-859"])
        self.assertEqual({k["cveID"] for k in hit["model"]}, {"CVE-2024-0769", "CVE-2019-17621"})
        other = self.db.device_hits("D-Link International", ["DIR-820L"])  # DIR-820 and DIR-820L are different models
        self.assertEqual([k["cveID"] for k in other["model"]], ["CVE-2022-26258"])
        f = rules.device_vuln_findings({"ip": "192.168.1.1", "mac": "aa", "vendor": "D-Link", "model": "DIR-859"}, hit)
        self.assertEqual((f[0].rule, f[0].severity), ("lan.kev_model", "high"))
        vendor_only = self.db.device_hits("QNAP Systems, Inc.", ["TS-231P"])
        self.assertTrue(vendor_only["vendor"] and not vendor_only["model"])
        self.assertEqual(rules.device_vuln_findings({"mac": "bb", "vendor": "QNAP"}, vendor_only)[0].severity, "low")

    def test_no_false_vendor_matches(self):
        self.assertEqual(self.db.device_hits("NEC Platforms, Ltd.", ["Aterm WX5400HP"])["vendor"], [])  # not ConnectWise
        self.assertEqual(self.db.device_hits("Apple, Inc.", ["AppleTV14,1"])["vendor"], [])  # Mac is checked by version

    def test_public_ip_cves(self):
        hits = self.db.kev_for(["cve-2024-3273", "CVE-1999-0001"])
        self.assertEqual([k["cveID"] for k in hits], ["CVE-2024-3273"])
        self.assertEqual(rules.exposure_kev_findings("203.0.113.10", hits)[0].severity, "high")


class MonitorIntegrationTest(unittest.TestCase):
    def test_posture_reports_unpatched_macos(self):
        import _fakenet
        from kekkai.monitor import Monitor
        with open(str(paths.sub("vulns", "sofa_macos.json")), "w") as f:
            json.dump(vulns._compact_sofa(json.loads(raw("sofa_excerpt.json"))), f)
        plat = _fakenet.FakePlatform()
        plat.os_version = lambda: "26.6.2"
        m = Monitor(config.load(), store=_fakenet.Store(":memory:"), platform=plat)
        m._audit = _fakenet.audit
        audit = m.posture_cycle()
        row = next(c for c in audit["checks"] if c["id"] == "macos_vulns")
        self.assertEqual(row["status"], "fail")
        alerts = [a for a in m.store.alerts(None, limit=20) if a["rule"] == "host.macos_vulns"]
        self.assertEqual(alerts[0]["severity"], "high")
        m.store.close()


if __name__ == "__main__":
    unittest.main()
