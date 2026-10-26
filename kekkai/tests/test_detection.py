import os
import tempfile
import unittest

import _support  # noqa: F401

from kekkai import netutil
from kekkai.detect import engine as rules
from kekkai.store import Store

GW, GW_MAC, ATT = "192.168.10.1", "a4:2b:b0:10:00:01", "7c:df:a1:3e:00:37"


def conn(**kw):
    base = {"proto": "tcp", "laddr": "192.168.10.23", "lport": 50000, "raddr": "8.8.8.8", "rport": 443, "state": "ESTABLISHED",
            "pid": 100, "process": "app", "path": "/Applications/App.app/Contents/MacOS/App", "direction": "out", "geo": {},
            "threats": []}
    base.update(kw)
    return base


class RuleTest(unittest.TestCase):
    def test_arp_spoof(self):
        neigh = [{"ip": GW, "mac": ATT}, {"ip": "192.168.10.37", "mac": ATT}]
        f = rules.arp_findings(neigh, GW, GW_MAC, ATT)
        self.assertEqual((f[0].rule, f[0].severity), ("lan.arp_spoof", "critical"))
        f = rules.arp_findings([{"ip": GW, "mac": ATT}], GW, GW_MAC, ATT)
        self.assertEqual(f[0].severity, "high")
        self.assertEqual(rules.arp_findings([{"ip": GW, "mac": GW_MAC}], GW, GW_MAC, GW_MAC), [])
        f = rules.arp_findings([{"ip": "192.168.10.5", "mac": "aa:aa:aa:00:00:01"},
                                {"ip": "192.168.10.6", "mac": "aa:aa:aa:00:00:01"}], GW, None, GW_MAC)
        self.assertEqual((f[0].rule, f[0].severity), ("lan.duplicate_mac", "low"))

    def test_connection_rules(self):
        c2 = conn(raddr="8.8.4.4", rport=4444, path="/Users/Shared/.x/agent",
                  threats=[{"feed": "feodo", "label": "Feodo", "severity": "critical", "kind": "botnet-c2"}],
                  signature={"checked": True, "signed": False})
        found = {(f.rule, f.severity) for f in rules.connection_findings([c2], {4444})}
        self.assertIn(("conn.threat_feed", "critical"), found)
        self.assertIn(("conn.suspicious_port", "medium"), found)
        self.assertIn(("conn.suspicious_binary", "high"), found)
        self.assertIn(("conn.unsigned_binary", "medium"), found)
        tor_in = conn(direction="in", threats=[{"feed": "tor_exit", "label": "Tor", "severity": "low", "kind": "tor-exit"}])
        self.assertEqual(rules.connection_findings([tor_in], set())[0].severity, "medium")
        lan = conn(raddr="192.168.10.44", rport=4444)
        self.assertEqual(rules.connection_findings([lan], {4444}), [], "LAN traffic is not judged by internet rules")
        self.assertEqual(rules.connection_findings([conn()], {4444}), [])

    def test_paths(self):
        for p in ("/tmp/x", "/private/tmp/x", "/Users/Shared/a", "/Users/me/Downloads/run",
                  "/private/var/folders/ab/cd1234/T/x", "/Users/me/.hidden/bin"):
            self.assertTrue(rules.suspicious_path(p), p)
        for p in ("/Applications/Safari.app/Contents/MacOS/Safari", "/usr/bin/ssh", "/opt/homebrew/bin/node", None):
            self.assertFalse(rules.suspicious_path(p), p)

    def test_listener_dns_proxy(self):
        ls = [{"proto": "tcp", "port": 22, "exposed": True, "process": "sshd"},
              {"proto": "tcp", "port": 631, "exposed": False}]
        f = rules.listener_findings(ls, set(), False)
        self.assertEqual((f[0].rule, f[0].severity), ("host.new_listener", "high"))
        self.assertEqual(rules.listener_findings(ls, {"tcp:22"}, False), [])
        self.assertEqual(rules.listener_findings(ls, {"tcp:22"}, True)[0].rule, "host.exposed_on_untrusted")
        self.assertEqual(rules.dns_findings(["192.168.1.1"], ["192.168.1.1"]), [])
        self.assertEqual(rules.dns_findings(["1.1.1.1"], ["192.168.1.1"])[0].severity, "low")
        self.assertEqual(rules.dns_findings(["45.77.1.2"], ["192.168.1.1"])[0].severity, "high")
        self.assertEqual(rules.dns_findings(["45.77.1.2"], []), [], "no baseline yet")
        self.assertEqual(rules.proxy_findings({"pac": "http://x/p.pac"}, {})[0].severity, "high")
        self.assertEqual(rules.proxy_findings({}, {"pac": "x"}), [])

    def test_persistence(self):
        base = {"/L/a.plist": 100.0}
        items = [{"plist": "/L/a.plist", "label": "a", "mtime": 100.0, "program": "/Applications/A.app/a", "exists": True},
                 {"plist": "/L/b.plist", "label": "b", "mtime": 200.0, "program": "/Users/Shared/.b/b", "exists": True},
                 {"plist": "/L/c.plist", "label": "c", "mtime": 200.0, "program": "/gone/c", "exists": False},
                 {"plist": "/L/k.plist", "label": "com.kekkai.monitor", "mtime": 200.0, "program": "/usr/bin/python3"}]
        f = {x.subject: x.severity for x in rules.persistence_findings(items, base)}
        self.assertNotIn("/L/a.plist", f)
        self.assertEqual(f["/L/b.plist"], "high")
        self.assertEqual(f["/L/c.plist"], "low")
        self.assertNotIn("/L/k.plist", f, "our own LaunchAgent is never reported")

    def test_wifi(self):
        self.assertEqual(rules.wifi_findings({"ssid": "x", "security": "OPEN"})[0].severity, "medium")
        self.assertEqual(rules.wifi_findings({"ssid": "x", "security": "WEP"})[0].severity, "high")
        twin = rules.wifi_findings({"ssid": "home", "security": "WPA2", "nearby": [{"ssid": "home", "security": "OPEN"}]})
        self.assertEqual(twin[0].rule, "wifi.evil_twin")
        self.assertEqual(rules.wifi_findings({"ssid": "home", "security": "WPA3"}), [])

    def test_threat_level(self):
        self.assertEqual(rules.threat_level({"critical": 1}), (5, "CRITICAL"))
        self.assertEqual(rules.threat_level({}), (1, "SECURE"))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.st = Store(os.path.join(tempfile.mkdtemp(), "t.db"))

    def tearDown(self):
        self.st.close()

    def test_alert_dedup(self):
        a, new = self.st.raise_alert("n", "r", "low", "t", "d", subject="s")
        self.assertTrue(new)
        b, new2 = self.st.raise_alert("n", "r", "high", "t", "d2", subject="s")
        self.assertFalse(new2)
        self.assertEqual((b["id"], b["count"], b["severity"]), (a["id"], 2, "high"))
        self.st.set_alert_status(a["id"], "resolved")
        _, new3 = self.st.raise_alert("n", "r", "high", "t", "d", subject="s")
        self.assertFalse(new3, "re-fire within an hour stays resolved")
        self.assertEqual(self.st.alert_counts()["high"], 0)
        with self.assertRaises(ValueError):
            self.st.set_alert_status(a["id"], "bogus")

    def test_devices(self):
        d, new = self.st.upsert_device("n", "aa:bb:cc:00:00:01", "192.168.1.5", vendor="X", services=["_a._tcp"])
        self.assertTrue(new)
        d, new = self.st.upsert_device("n", "aa:bb:cc:00:00:01", "192.168.1.6", services=["_b._tcp"])
        self.assertFalse(new)
        self.assertEqual(d["ip"], "192.168.1.6")
        self.assertEqual(d["ips"], ["192.168.1.5", "192.168.1.6"])
        self.assertEqual(d["services"], ["_a._tcp", "_b._tcp"])
        self.assertEqual(d["vendor"], "X")
        self.st.update_device("n", "aa:bb:cc:00:00:01", label="TV", trusted=True)
        self.assertEqual(self.st.device("n", "aa:bb:cc:00:00:01")["trusted"], 1)
        self.assertTrue(self.st.integrity_ok())

    def test_kv(self):
        self.assertIsNone(self.st.kv_get("x"))
        self.st.kv_set("x", {"a": [1, 2]})
        self.assertEqual(self.st.kv_get("x"), {"a": [1, 2]})


class NoUnfoundedSecureTest(unittest.TestCase):
    def test_checking_until_first_cycle(self):  # "SECURE" must not be shown before anything was checked
        import _fakenet
        from kekkai import config
        from kekkai.monitor import Monitor
        m = Monitor(config.load(), store=_fakenet.Store(":memory:"), platform=_fakenet.FakePlatform())
        self.assertEqual(m.summary()["threat"]["label"], "CHECKING")
        m.store.close()


class IntrusionScenarioTest(unittest.TestCase):
    """End-to-end: a scripted intrusion on a fake LAN must be detected, without false positives."""

    def tearDown(self):
        netutil.EXTRA_PUBLIC_NETS = ()

    def test_intrusion_is_detected(self):
        import _fakenet
        from kekkai import config
        m = _fakenet.build(config.load())
        alerts = m.store.alerts(None, limit=200)
        by_rule = {}
        for a in alerts:
            by_rule.setdefault(a["rule"], []).append(a)
        self.assertEqual(by_rule["conn.threat_feed"][0]["severity"], "critical")
        self.assertIn("lan.new_device", by_rule)
        self.assertIn("lan.risky_service", by_rule)
        self.assertIn("exposure.upnp_new", by_rule)
        persist = [a["subject"] for a in by_rule.get("host.persistence_new", [])]
        self.assertEqual(len(persist), 1, "only the malicious LaunchAgent may be reported: %s" % persist)
        self.assertIn("sysmond", persist[0])
        for _ in range(8):
            m.fast_cycle()
        arp = [a for a in m.store.alerts(None, limit=200) if a["rule"] == "lan.arp_spoof"]
        self.assertTrue(arp and arp[0]["severity"] == "critical")
        self.assertEqual(m.threat_summary()["level"], 5)
        from kekkai import report
        self.assertIn("ARPスプーフィング", report.markdown(m))
        m.store.close()


if __name__ == "__main__":
    unittest.main()
