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

from kekkai import sensor
from kekkai.platforms.base import LanContext
from kekkai.util import find_cmd

EXPECTED = collections.Counter({("port_scan", _pcap.ATK_IP): 1, ("port_scan", _pcap.ATK2_IP): 1,
                                ("arp_sweep", _pcap.ATK_IP): 1, ("arp_spoof", _pcap.ATK_MAC): 1,
                                ("dns_threat", "login." + _pcap.BAD_DOMAIN): 1, ("dns_threat", "cdn." + _pcap.BAD_DOMAIN): 1,
                                ("dns_threat", "api." + _pcap.BAD_DOMAIN): 1, ("dns_threat", "v6." + _pcap.BAD_DOMAIN): 1})
EXPECTED.update({("conn_out", "93.184.215.%d" % (i + 1)): 1 for i in range(len(_pcap.SCAN_PORTS))})


def detector() -> sensor.Detector:
    return sensor.Detector(_pcap.OWN_IP, _pcap.OWN_MAC, _pcap.GW_IP, _pcap.GW_MAC, {_pcap.BAD_DOMAIN})


def summarize(events):
    key = {"port_scan": "src", "arp_sweep": "src", "arp_spoof": "mac", "dns_threat": "domain", "conn_out": "dst"}
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


class ShortConnectionTest(unittest.TestCase):
    """Connections too short for the 15 s poll are still checked against the threat lists."""

    def setUp(self):
        import _fakenet
        from kekkai import config
        from kekkai.monitor import Monitor
        self.m = Monitor(config.load(), store=_fakenet.Store(":memory:"), platform=_fakenet.FakePlatform())
        self.m.feeds = _fakenet.FakeFeeds(tempfile.mkdtemp())
        self.m.geo = _fakenet.FakeGeo()
        _fakenet.netutil.EXTRA_PUBLIC_NETS = (_fakenet.netutil.ipaddress.ip_network("203.0.113.0/24"),)
        self.addCleanup(setattr, _fakenet.netutil, "EXTRA_PUBLIC_NETS", ())
        self.addCleanup(self.m.store.close)
        self.spool = sensor.state_dir() / "events.jsonl"
        self.addCleanup(lambda: self.spool.exists() and self.spool.unlink())

    def ingest(self, *events):
        with open(str(self.spool), "a") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        self.m.sensor_cycle()
        return [a for a in self.m.store.alerts(None, limit=50) if a["rule"] == "sensor.threat_conn"]

    def test_short_connection_to_listed_ip_alerts(self):
        alerts = self.ingest({"kind": "conn_out", "dst": "203.0.113.66", "dport": 4444, "ts": 1.0},
                             {"kind": "conn_out", "dst": "17.253.144.10", "dport": 443, "ts": 1.0})
        self.assertEqual([(a["subject"], a["severity"]) for a in alerts], [("203.0.113.66", "critical")])

    def test_connection_seen_by_poll_is_left_to_the_poll(self):  # the poll alert names the app; no duplicate
        self.m.state["connections"] = [{"raddr": "203.0.113.66", "rport": 4444}]
        self.assertEqual(self.ingest({"kind": "conn_out", "dst": "203.0.113.66", "dport": 4444, "ts": 1.0}), [])


class StateDirTest(unittest.TestCase):
    def test_refuses_symlinked_state_dir(self):  # a planted symlink must not redirect root's writes
        with tempfile.TemporaryDirectory() as d:
            os.symlink(d, os.path.join(d, "link"))
            with mock.patch.dict(os.environ, {"KEKKAI_SENSOR_DIR": os.path.join(d, "link")}):
                with self.assertRaises(RuntimeError):
                    sensor.prepare_state_dir()

    def test_default_location_must_be_root_owned(self):
        env = {k: v for k, v in os.environ.items() if k != "KEKKAI_SENSOR_DIR"}
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sensor, "state_dir", return_value=sensor.Path(d)):
            if os.geteuid() != 0:  # a user-owned folder is exactly what must be refused
                with self.assertRaises(RuntimeError):
                    sensor.prepare_state_dir()

    def test_clean_state_dir_removes_every_sensor_file(self):
        from kekkai import service
        with tempfile.TemporaryDirectory() as parent:
            d = os.path.join(parent, "KEKKAI Sensor")
            os.makedirs(os.path.join(d, "code"))
            with open(os.path.join(d, "code", "DIGEST"), "w") as f:
                f.write("deadbeef\n")
            # Every file the sensor writes, including btm.json and the rotated spool,
            # must go so the directory can be removed on uninstall.
            for name in ("events.jsonl", "events.jsonl.1", "heartbeat",
                         "domains-tif-mini.txt", "btm.json"):
                with open(os.path.join(d, name), "w") as f:
                    f.write("x")
            service.clean_state_dir(sensor.Path(d))
            self.assertFalse(os.path.exists(d), "uninstall left the state directory behind")

    def test_clean_state_dir_keeps_unexpected_subdir(self):
        from kekkai import service
        with tempfile.TemporaryDirectory() as parent:
            d = os.path.join(parent, "KEKKAI Sensor")
            os.makedirs(os.path.join(d, "mystery"))  # not ours: don't recurse into it
            with open(os.path.join(d, "heartbeat"), "w") as f:
                f.write("x")
            service.clean_state_dir(sensor.Path(d))
            self.assertTrue(os.path.isdir(os.path.join(d, "mystery")))
            self.assertFalse(os.path.exists(os.path.join(d, "heartbeat")))

    def test_clean_state_dir_preserves_unrelated_files_and_symlinks(self):
        from kekkai import service
        with tempfile.TemporaryDirectory() as parent:
            d = sensor.Path(parent) / "state"
            d.mkdir()
            note = d / "my-notes.txt"
            note.write_text("keep")
            target = sensor.Path(parent) / "outside.txt"
            target.write_text("keep outside")
            (d / "heartbeat").symlink_to(target)
            service.clean_state_dir(d)
            self.assertEqual(note.read_text(), "keep")
            self.assertEqual(target.read_text(), "keep outside")
            self.assertTrue((d / "heartbeat").is_symlink())

    def test_clean_state_dir_does_not_follow_directory_symlink(self):
        from kekkai import service
        with tempfile.TemporaryDirectory() as parent:
            target = sensor.Path(parent) / "outside"
            target.mkdir()
            (target / "btm.json").write_text("keep")
            link = sensor.Path(parent) / "sensor-link"
            link.symlink_to(target, target_is_directory=True)
            service.clean_state_dir(link)
            self.assertEqual((target / "btm.json").read_text(), "keep")


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
                os.unlink(str(sensor.state_dir() / name))
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
        spool, beat = str(sensor.state_dir() / "events.jsonl"), str(sensor.state_dir() / "heartbeat")

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


class ServiceTest(unittest.TestCase):
    def test_btm_write_failure_does_not_kill_heartbeat(self):
        plat = mock.Mock()
        plat.background_items.return_value = [{"identifier": "test.item"}]
        stop = mock.Mock()
        stop.wait.side_effect = [False, False, True]
        cap = mock.Mock()
        cap.alive.return_value = True
        with mock.patch.object(sensor, "atomic_write", side_effect=OSError("disk unavailable")), \
                mock.patch.object(sensor, "_beat") as beat:
            sensor._keeper(stop, "unused", {"cap": cap}, plat, None)
        self.assertEqual(beat.call_count, 2)

    def test_empty_btm_snapshot_replaces_old_items(self):
        plat = mock.Mock()
        plat.background_items.return_value = []
        with mock.patch.object(sensor, "atomic_write") as write:
            sensor.dump_btm(plat)
        self.assertEqual(json.loads(write.call_args.args[1])["items"], [])

    def test_daemon_runs_root_owned_copy_in_isolated_mode(self):
        from kekkai import service
        with tempfile.TemporaryDirectory() as d:
            code = sensor.Path(d) / "code"
            service._copy_code(code)
            self.assertEqual((code / "DIGEST").read_text().strip(), service.code_digest())
            self.assertFalse(list(code.rglob("*.html")), "only Python code is copied")
            pl = service.sensor_plist(sys.executable, code)
            self.assertEqual(pl["ProgramArguments"][1:3], ["-I", "-B"])
            self.assertNotIn("EnvironmentVariables", pl)
            self.assertTrue(pl["KeepAlive"])
            # the exact boot line launchd runs, asked for --help instead of starting a capture
            boot = pl["ProgramArguments"][-1].replace("main(['sensor'])", "main(['sensor', '--help'])")
            env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
            r = subprocess.run([sys.executable, "-I", "-B", "-c", boot + "\n"], capture_output=True, text=True,
                               cwd="/", env=env, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("--interface", r.stdout)
            r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.path.insert(0, %r); import kekkai.sensor, "
                                "kekkai.platforms.macos, kekkai.platforms.linux, kekkai.cli; print(kekkai.sensor.__file__)" % str(code)],
                               capture_output=True, text=True, cwd="/", env=env, timeout=60)
            self.assertTrue(r.stdout.strip().startswith(str(code)), r.stdout + r.stderr)

    def test_status_reports_running_and_outdated(self):
        from kekkai import service
        d = sensor.state_dir()
        (d / "code").mkdir(parents=True, exist_ok=True)
        (d / "code" / "DIGEST").write_text("0000000000000000\n")
        (d / "heartbeat").write_text(str(time.time()))
        self.addCleanup(lambda: [p.unlink() for p in (d / "heartbeat", d / "code" / "DIGEST") if p.exists()])
        with mock.patch("os.path.exists", side_effect=lambda p: p == service.SENSOR_PLIST or os.path.lexists(p)):
            st = service.status()
        self.assertTrue(st["installed"] and st["running"] and st["outdated"])


if __name__ == "__main__":
    unittest.main()
