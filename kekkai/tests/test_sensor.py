"""Packet sensor: real tcpdump output, the capture loop, network changes and clean shutdown."""
import collections
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import _pcap
from _support import fixture

from kekkai import paths, sensor
from kekkai.platforms.base import LanContext
from kekkai.util import find_cmd

EXPECTED = collections.Counter({("port_scan", _pcap.ATK_IP): 1, ("port_scan", _pcap.ATK2_IP): 1,
                                ("arp_sweep", _pcap.ATK_IP): 1, ("arp_spoof", _pcap.ATK_MAC): 1,
                                ("dns_threat", "login." + _pcap.BAD_DOMAIN): 1, ("dns_threat", "cdn." + _pcap.BAD_DOMAIN): 1,
                                ("dns_threat", "api." + _pcap.BAD_DOMAIN): 1, ("dns_threat", "v6." + _pcap.BAD_DOMAIN): 1})


def detector() -> sensor.Detector:
    return sensor.Detector(_pcap.OWN_IP, _pcap.OWN_MAC, _pcap.GW_IP, _pcap.GW_MAC, {_pcap.BAD_DOMAIN})


def summarize(events):
    key = {"port_scan": "src", "arp_sweep": "src", "arp_spoof": "mac", "dns_threat": "domain"}
    return collections.Counter((e["kind"], e[key[e["kind"]]]) for e in events)


def feed_all(lines):
    d = detector()
    return [e for e in (d.feed(x) for x in lines) if e]


class TcpdumpOutputTest(unittest.TestCase):
    """The Detector must understand what tcpdump really prints, not what we think it prints."""

    def test_frozen_real_output(self):  # captured from tcpdump 4.99.4 reading tests/_pcap.py's attack
        self.assertEqual(summarize(feed_all(fixture("linux", "tcpdump_attack.txt").splitlines())), EXPECTED)

    def test_live_tcpdump_binary(self):  # the tcpdump on this machine (Apple's on macOS) with the sensor's own filter
        if not find_cmd("tcpdump"):
            if os.environ.get("KEKKAI_REQUIRE_TCPDUMP"):
                self.fail("tcpdump is required in CI")
            self.skipTest("tcpdump not installed")
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "attack.pcap")
            _pcap.write_pcap(pcap, _pcap.attack_frames())
            r = subprocess.run(sensor.tcpdump_cmd(None, _pcap.OWN_IP, read_file=pcap), capture_output=True, text=True,
                               timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        if os.environ.get("KEKKAI_SHOW_TCPDUMP"):
            sys.stderr.write("\n".join(lines[:3] + [x for x in lines if "[SEW]" in x][:1] + lines[-5:]) + "\n")
        self.assertEqual(summarize(feed_all(lines)), EXPECTED, "\n".join(lines[-8:]))


class NetworkChangeTest(unittest.TestCase):
    HOME = ["a0:b1:c2:00:00:%02x" % i for i in range(1, 6)]

    def ctx(self, ip=_pcap.OWN_IP, gw_mac=_pcap.GW_MAC, gw=_pcap.GW_IP, iface="en0", macs=None, gw_dup=False):
        return {"iface": iface, "ip": ip, "mac": _pcap.OWN_MAC, "gw": gw, "gw_mac": gw_mac,
                "macs": sorted((macs if macs is not None else self.HOME) + ([gw_mac] if gw_mac else [])), "gw_dup": gw_dup}

    def state(self, **kw):
        cap = mock.Mock()
        return {"ctx": self.ctx(**kw), "restart": False, "cap": cap, "det": detector()}, cap

    def test_poisoned_arp_table_does_not_replace_router_mac(self):
        st, cap = self.state()
        sensor.on_context(st, self.ctx(gw_mac=_pcap.ATK_MAC))  # same neighbours, router MAC "changed"
        self.assertFalse(st["restart"])
        cap.stop.assert_not_called()
        self.assertEqual((st["ctx"]["gw_mac"], st["det"].gateway_mac), (_pcap.GW_MAC, _pcap.GW_MAC))
        self.assertEqual(sensor.refresh(st["ctx"], self.ctx(gw_mac=_pcap.ATK_MAC))["gw_mac"], _pcap.GW_MAC)

    def test_spoof_seen_as_duplicate_mac_even_without_other_neighbours(self):
        st, cap = self.state(macs=[])
        sensor.on_context(st, self.ctx(gw_mac=_pcap.ATK_MAC, macs=[], gw_dup=True))
        self.assertFalse(st["restart"])
        self.assertEqual(st["det"].gateway_mac, _pcap.GW_MAC)

    def test_cafe_with_same_ip_plan_is_a_new_network(self):  # 192.168.10.23 via 192.168.10.1 at both places
        st, cap = self.state()
        cafe = self.ctx(gw_mac="00:11:22:33:44:55", macs=["0e:00:00:00:00:%02x" % i for i in range(1, 4)])
        sensor.on_context(st, cafe)
        self.assertTrue(st["restart"])
        cap.stop.assert_called_once()
        self.assertEqual(st["ctx"]["gw_mac"], "00:11:22:33:44:55")
        self.assertEqual(sensor.refresh(self.ctx(), cafe)["gw_mac"], "00:11:22:33:44:55")

    def test_new_address_is_a_new_network(self):
        st, cap = self.state()
        sensor.on_context(st, self.ctx(ip="192.168.10.140", gw_mac="00:11:22:33:44:55"))
        self.assertTrue(st["restart"])
        cap.stop.assert_called_once()

    def test_offline_keeps_current_capture(self):
        st, cap = self.state()
        sensor.on_context(st, {"iface": None, "ip": None, "mac": None, "gw": None, "gw_mac": None, "macs": []})
        self.assertFalse(st["restart"])
        cap.stop.assert_not_called()

    def test_router_mac_learned_when_unknown_at_start(self):
        st, _ = self.state(gw_mac=None)
        st["det"].gateway_mac = None
        sensor.on_context(st, self.ctx())
        self.assertEqual(st["det"].gateway_mac, _pcap.GW_MAC)

    def test_context_from_platform(self):
        from kekkai.platforms.base import Neighbor
        plat = mock.Mock()
        plat.lan_context.return_value = LanContext(interface="en0", ip=_pcap.OWN_IP, mac=_pcap.OWN_MAC,
                                                   gateway=_pcap.GW_IP, gateway_mac=_pcap.ATK_MAC)
        plat.neighbors.return_value = [Neighbor(_pcap.GW_IP, _pcap.ATK_MAC, "en0"), Neighbor(_pcap.ATK_IP, _pcap.ATK_MAC, "en0"),
                                       Neighbor("192.168.10.9", None, "en0"), Neighbor("10.9.9.9", "02:00:00:00:09:09", "en5")]
        c = sensor.sensor_context(plat)
        self.assertEqual((c["iface"], c["gw_mac"], c["macs"], c["gw_dup"]), ("en0", _pcap.ATK_MAC, [_pcap.ATK_MAC], True))
        en7 = mock.Mock(ipv4=[("10.0.5.2", 24)], mac="02:00:00:00:05:02")
        en7.name = "en7"
        plat.interfaces.return_value = [en7]
        plat.neighbors.return_value = []
        c = sensor.sensor_context(plat, "en7")
        self.assertEqual((c["iface"], c["ip"], c["gw"], c["gw_dup"]), ("en7", "10.0.5.2", None, False))


class FakeTcpdump:
    """A stand-in tcpdump script so run() can be tested end to end without root."""

    def __init__(self, d, stdout_file=None, fail=None):
        self.pidfile = os.path.join(d, "pid")
        self.path = os.path.join(d, "tcpdump")
        body = ["import os, sys, time", "open(%r, 'w').write(str(os.getpid()))" % self.pidfile]
        if fail:
            body += ["sys.stderr.write(%r + '\\n')" % fail, "sys.exit(1)"]
        else:
            body += ["sys.stderr.write('tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\\n')",
                     "sys.stderr.write('listening on en0, link-type EN10MB (Ethernet), snapshot length 256 bytes\\n')",
                     "sys.stderr.flush()",
                     "sys.stdout.write(open(%r).read())" % stdout_file, "sys.stdout.flush()", "time.sleep(120)"]
        with open(self.path, "w") as f:
            f.write("#!%s\n%s\n" % (sys.executable, "\n".join(body)))
        os.chmod(self.path, 0o755)

    def pid(self):
        with open(self.pidfile) as f:
            return int(f.read())


class RunLoopTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_term = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, self.old_term)
        for name in ("events.jsonl", "heartbeat"):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(str(paths.sub("sensor", name)))
        plat = mock.Mock()
        plat.lan_context.return_value = LanContext(interface="en0", ip=_pcap.OWN_IP, mac=_pcap.OWN_MAC,
                                                   gateway=_pcap.GW_IP, gateway_mac=_pcap.GW_MAC)
        plat.neighbors.return_value = []
        for p in (mock.patch("os.geteuid", return_value=0), mock.patch("kekkai.platforms.get_platform", return_value=plat),
                  mock.patch.object(sensor, "load_domains", return_value={_pcap.BAD_DOMAIN}),
                  mock.patch.object(sensor, "HEARTBEAT_EVERY", 0.05)):
            p.start()
            self.addCleanup(p.stop)

    def use(self, fake):
        p = mock.patch.object(sensor, "find_cmd", return_value=fake.path)
        p.start()
        self.addCleanup(p.stop)

    def test_detects_writes_heartbeat_and_stops_cleanly_on_sigterm(self):
        stdout_file = os.path.join(self.tmp.name, "lines.txt")
        with open(stdout_file, "w") as f:
            f.write(fixture("linux", "tcpdump_attack.txt"))
        fake = FakeTcpdump(self.tmp.name, stdout_file)
        self.use(fake)
        spool, beat = str(paths.sub("sensor", "events.jsonl")), str(paths.sub("sensor", "heartbeat"))

        def unhandled(signum, frame):
            raise AssertionError("sensor did not install a SIGTERM handler")
        signal.signal(signal.SIGTERM, unhandled)

        def stopper():
            deadline = time.time() + 20
            while time.time() < deadline:
                n = 0
                if os.path.exists(spool):
                    with open(spool) as f:
                        n = sum(1 for _ in f)
                if n >= sum(EXPECTED.values()) and os.path.exists(beat):
                    break
                time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=stopper, daemon=True).start()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = sensor.run(None)
        self.assertEqual(rc, 0)
        with open(spool) as f:
            self.assertEqual(summarize(json.loads(x) for x in f), EXPECTED)
        self.assertTrue(os.path.exists(beat), "heartbeat must be written without waiting for traffic")
        self.assertIn("を監視中", out.getvalue())
        self.assertIn("[!] port_scan", out.getvalue())
        with self.assertRaises(ProcessLookupError):  # tcpdump must not be left running as root
            os.kill(fake.pid(), 0)

    def test_tcpdump_failure_is_reported_not_silent(self):
        self.use(FakeTcpdump(self.tmp.name, fail="tcpdump: en0: You don't have permission to capture on that device"))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = sensor.run(None)
        self.assertEqual(rc, 1)
        self.assertIn("permission to capture", err.getvalue())


if __name__ == "__main__":
    unittest.main()
