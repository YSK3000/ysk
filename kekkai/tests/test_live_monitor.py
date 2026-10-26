"""Real monitoring lifecycle, failure reporting, and Mac command failure regressions."""
import contextlib
import copy
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import _support
from kekkai import cli, config, server
from kekkai.live_runtime import single_monitor
from kekkai.monitor import Monitor
from kekkai.platforms.base import Connection, LanContext, Platform
from kekkai.platforms.macos import MacOSPlatform
from kekkai.store import Store


class FakePlatform(Platform):
    name = "test"
    broken = False

    def lan_context(self):
        return LanContext(interface="en0", ip="192.168.1.3", prefixlen=24, gateway="192.168.1.1")

    def connections(self):
        if self.broken:
            raise RuntimeError("permission denied")
        return [Connection(proto="tcp", laddr="192.168.1.3", lport=45678,
                           raddr="1.1.1.1", rport=443, state="ESTABLISHED", pid=123, process="test")]


class LiveMonitorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        self.cfg.set("notify.macos", False)
        self.platform = FakePlatform()
        self.store = Store(str(Path(self.tmp.name) / "test.db"))
        self.addCleanup(self.store.close)
        self.m = Monitor(self.cfg, self.store, self.platform)

    def test_startup_never_claims_live_or_invents_home_location(self):
        self.assertEqual(self.m.summary()["monitoring"]["status"], "starting")
        self.assertIsNone(self.m.state["home"]["lat"])
        self.assertIsNone(self.m.state["home"]["lon"])

    def test_failed_collection_preserves_snapshot_and_recovers(self):
        self.m.fast_cycle()
        self.assertEqual(self.m.monitoring_status()["status"], "live")
        old = self.m.snapshot("connections")
        old_ts = self.m.state["ts"]
        old_cycle = self.m.state["cycle"]
        self.platform.broken = True
        with self.assertRaises(RuntimeError):
            self.m.fast_cycle()
        self.assertEqual(self.m.monitoring_status()["status"], "error")
        self.assertEqual(self.m.snapshot("connections"), old)
        self.assertEqual(self.m.state["ts"], old_ts)
        self.assertEqual(self.m.state["cycle"], old_cycle)
        self.platform.broken = False
        self.m.fast_cycle()
        self.assertEqual(self.m.monitoring_status()["status"], "live")
        self.assertFalse(self.m.monitoring_status()["errors"])

    def test_freshness_and_shutdown(self):
        self.m.fast_cycle()
        self.m.state["ts"] = time.time() - 60
        self.assertEqual(self.m.monitoring_status()["status"], "stale")
        self.m.stop()
        self.assertEqual(self.m.monitoring_status()["status"], "stopped")

    def test_loop_survives_error_and_collects_again(self):
        recovered = threading.Event()
        calls = []

        def collect():
            calls.append(1)
            self.platform.broken = len(calls) == 1
            self.m.fast_cycle()
            recovered.set()

        worker = threading.Thread(target=self.m._loop, args=("fast", collect, lambda: 0, 0), daemon=True)
        self.m._threads.append(worker)
        worker.start()
        try:
            self.assertTrue(recovered.wait(5))
            self.assertEqual(self.m.monitoring_status()["status"], "live")
            self.assertGreaterEqual(self.m.state["health"]["fast"]["errors"], 1)
        finally:
            self.m.stop()
        self.assertFalse(worker.is_alive())

    def test_start_is_idempotent(self):
        with patch.object(self.m, "_loop", side_effect=lambda *a: self.m._stop.wait(5)):
            self.m.start()
            try:
                first = list(self.m._threads)
                self.m.start()
                self.assertEqual(self.m._threads, first)
            finally:
                self.m.stop()
            self.assertTrue(all(not t.is_alive() for t in first))

    def test_old_demo_argument_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.build_parser().parse_args(["serve", "--demo"])
        args = cli.build_parser().parse_args(["serve"])
        self.assertFalse(hasattr(args, "demo"))


    def test_process_lock_released_and_duplicate_refused(self):
        with single_monitor() as first:
            self.assertTrue(first)
            with single_monitor() as second:
                self.assertFalse(second)
        with single_monitor() as again:
            self.assertTrue(again)

    def test_sensor_heartbeat_expires_without_sensor_poll(self):
        from kekkai.sensor import state_dir
        import os
        beat = state_dir() / "heartbeat"
        beat.parent.mkdir(parents=True, exist_ok=True)
        beat.write_text("test heartbeat")
        self.addCleanup(lambda: beat.unlink(missing_ok=True))
        self.assertTrue(self.m.summary()["sensor"]["active"])
        old = time.time() - 60
        os.utime(beat, (old, old))
        self.assertFalse(self.m.summary()["sensor"]["active"])

    def test_failure_does_not_relearn_baselines(self):
        self.m.fast_cycle()
        keys = ["last_network", "baseline:listeners", "baseline:proxies"]
        before = {key: self.store.kv_get(key) for key in keys}
        with patch.object(self.platform, "proxies", side_effect=OSError("denied")):
            with self.assertRaises(RuntimeError):
                self.m.fast_cycle()
        self.assertEqual(before, {key: self.store.kv_get(key) for key in keys})
        self.assertEqual(self.m.state["cycle"], 1)

    def test_coverage_does_not_treat_installation_as_protection(self):
        from kekkai.coverage import describe
        with patch("kekkai.coverage.find_cmd", return_value=None), patch("pathlib.Path.exists", return_value=False):
            cards = {c["id"]: c for c in describe(self.m)["cards"]}
        self.assertEqual(cards["connections"]["state"], "starting")
        self.assertEqual(cards["sensor"]["state"], "inactive")
        self.assertEqual(cards["nmap"]["state"], "unavailable")
        self.assertEqual(cards["blocking"]["state"], "external")
        self.m.state["sensor"] = {"active": True, "last_beat": time.time() - 60}
        self.assertEqual(next(c for c in describe(self.m)["cards"] if c["id"] == "sensor")["state"], "inactive")

    def test_mcp_coverage_remains_available_on_collection_error(self):
        from kekkai.mcp import KekkaiTools
        tools = KekkaiTools()
        tools._m = self.m
        self.platform.broken = True
        result = tools.call("kekkai_coverage", {})
        self.assertEqual(result["cards"][0]["state"], "error")


class MacCollectorTest(unittest.TestCase):
    def test_command_failures_are_not_empty_success(self):
        for method in ("connections", "interfaces", "neighbors", "lan_context", "processes", "dns_servers", "proxies"):
            with self.subTest(method=method):
                with patch("kekkai.platforms.macos.run", return_value=(1, "", "permission denied")):
                    with self.assertRaisesRegex(RuntimeError, "取得失敗"):
                        getattr(MacOSPlatform(), method)()

    def test_macos_connections_from_command_fixtures(self):
        def run(cmd, **kwargs):
            if cmd[0] == "netstat":
                name = "netstat_tcp_macos26.txt" if cmd[-1] == "tcp" else "netstat_udp.txt"
                return 0, _support.fixture("macos", name), ""
            if cmd[0] == "ps":
                return 0, _support.fixture("macos", "ps.txt"), ""
            if cmd[0] == "lsof":
                return 0, _support.fixture("macos", "lsof.txt"), ""
            raise AssertionError(cmd)
        with patch("kekkai.platforms.macos.run", side_effect=run):
            rows = MacOSPlatform().connections()
        self.assertGreater(len(rows), 0)
        self.assertTrue(any(c.pid for c in rows))

    def test_codesign_does_not_block_polling_and_is_bounded(self):
        p = MacOSPlatform()
        release = threading.Event()
        started = threading.Event()
        def sign(path):
            started.set()
            release.wait(3)
            return {"checked": True, "signed": True}
        with tempfile.TemporaryDirectory() as tmp, patch.object(p, "code_signature", side_effect=sign):
            paths = [str(Path(tmp) / str(i)) for i in range(3)]
            for name in paths:
                Path(name).write_text("test")
            try:
                for name in paths:
                    self.assertTrue(p.code_signature_cached(name)["pending"])
                self.assertTrue(started.wait(1))
                self.assertEqual(len(p._sig_jobs), 2)
            finally:
                release.set()


if __name__ == "__main__":
    unittest.main()
