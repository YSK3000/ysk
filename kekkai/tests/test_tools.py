"""nmap installer: official checksum parsing, signature judgement, choice changes, admin step, abort paths."""
import copy
import hashlib
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401
from kekkai import config, tools
from kekkai.monitor import Monitor
from kekkai.platforms.base import LanContext, Platform
from kekkai.store import Store

# Exact layout of nmap.org's dist/sigs/<file>.digest.txt, recorded on the real macOS runner (2026-11-02).
DIGEST = """../webroot/nmap/dist/nmap-7.993.dmg:    MD5 = 10 21 CD 2F DC F4 88 04  2B 41 21
                                              B7 D9 6D BF EF
../webroot/nmap/dist/nmap-7.993.dmg:   SHA1 = E263 282C D0EF 9880 EACB  478E
                                              147F 41CD 4E36 E11B
../webroot/nmap/dist/nmap-7.993.dmg: SHA224 = DA23DDAF C2306E1C C53EE903
                                              8C15B399 55FC68CF 157B6803
                                              B458E4C5
../webroot/nmap/dist/nmap-7.993.dmg: SHA256 = 960390C3 150A913C 78AAD84A
                                              E2B6B7A7 96AA2A63 E0D25A5B
                                              3128B6BF 4420C24A
../webroot/nmap/dist/nmap-7.993.dmg: SHA384 = 87CC5D8F 61B61416 A1D58532
                                              0365773B 5869FF48 55F74EDF
"""


class StubPlatform(Platform):
    name = "test"

    def lan_context(self):
        return LanContext(interface="en0", ip="192.168.1.3", prefixlen=24, gateway="192.168.1.1")


class ParseTest(unittest.TestCase):
    def test_latest_dmg_from_download_page(self):
        page = ('<a href="https://nmap.org/dist/nmap-7.993.dmg">nmap-7.993.dmg</a> '
                '<!-- Latest development release universal installer: nmap-7.25BETA2.dmg --> nmap-7.95.dmg')
        self.assertEqual(tools.latest_dmg(page), "nmap-7.993.dmg")
        self.assertIsNone(tools.latest_dmg("no installer here"))

    def test_sha256_from_official_digest_file(self):
        self.assertEqual(tools.digest_sha256(DIGEST, "nmap-7.993.dmg"),
                         "960390c3150a913c78aad84ae2b6b7a796aa2a63e0d25a5b3128b6bf4420c24a")
        self.assertIsNone(tools.digest_sha256(DIGEST.replace("SHA256", "SHAXXX"), "nmap-7.993.dmg"))
        self.assertEqual(tools.digest_sha256("%s  nmap-8.0.dmg\n" % ("ab" * 32), "nmap-8.0.dmg"), "ab" * 32)

    def test_signature_judgement(self):
        ok, why = tools.check_pkg_signature('Package "nmap-7.993.mpkg":\n   Status: no signature\n')
        self.assertTrue(ok)                       # measured: nmap.org ships the installer unsigned
        self.assertIn("SHA-256", why)
        ok, why = tools.check_pkg_signature(
            "   Status: signed by a developer certificate issued by Apple for distribution\n"
            "   1. Developer ID Installer: Example Org (ABCDE12345)\n")
        self.assertTrue(ok)
        self.assertIn("ABCDE12345", why)
        ok, _ = tools.check_pkg_signature("   Status: signed by untrusted certificate\n")
        self.assertFalse(ok)                      # a present-but-bad signature is never accepted

    def test_only_nmap_is_selected(self):
        shown = plistlib.dumps([
            {"choiceAttribute": "visible", "attributeSetting": 1, "choiceIdentifier": "org.insecure.nmap"},
            {"choiceAttribute": "selected", "attributeSetting": 1, "choiceIdentifier": "org.insecure.nmap"},
            {"choiceAttribute": "selected", "attributeSetting": 1, "choiceIdentifier": "org.insecure.nmap.zenmap"},
            {"choiceAttribute": "selected", "attributeSetting": 1, "choiceIdentifier": "org.insecure.nmap.ncat"},
            {"choiceAttribute": "selected", "attributeSetting": 1, "choiceIdentifier": "org.insecure.nmap.nping"},
        ]).decode()
        changes = plistlib.loads(tools.choice_changes(shown))
        self.assertEqual(sorted(c["choiceIdentifier"] for c in changes),
                         ["org.insecure.nmap.ncat", "org.insecure.nmap.nping", "org.insecure.nmap.zenmap"])
        self.assertTrue(all(c["attributeSetting"] == 0 and c["choiceAttribute"] == "selected" for c in changes))
        self.assertIsNone(tools.choice_changes("not a plist"))


class AdminStepTest(unittest.TestCase):
    def test_paths_are_arguments_not_script(self):
        cmd = tools.osascript_cmd([["/usr/sbin/installer", "-pkg", "/x/n'map.pkg", "-target", "/"]])
        script = " ".join(cmd[:cmd.index("end run") + 1])
        self.assertNotIn("n'map", script)                       # the path never enters the AppleScript source
        self.assertIn("with administrator privileges", script)
        self.assertEqual(cmd[-5:], ["/usr/sbin/installer", "-pkg", "/x/n'map.pkg", "-target", "/"])
        self.assertNotIn("administrator", " ".join(tools.osascript_cmd([["/bin/echo", "a"]], admin=False)))

    def test_unsafe_paths_refused(self):
        rc, why = tools._admin_install("/tmp/a b;rm -rf ~/x.pkg")
        self.assertEqual(rc, 2)
        self.assertIn("unsafe", why)

    def test_rosetta_and_choices_in_one_privileged_run(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(tools.subprocess, "run", fake_run), mock.patch.dict("os.environ", {"KEKKAI_PRIV": ""}):
            tools._admin_install("/t/nmap.mpkg", "/t/choices.plist", rosetta=True)
        args = seen["cmd"][seen["cmd"].index("end run") + 1:]
        self.assertEqual(args[:3], ["/usr/sbin/softwareupdate", "--install-rosetta", "--agree-to-license"])
        self.assertIn("-applyChoiceChangesXML", args)


class InstallFlowTest(unittest.TestCase):
    def test_tampered_download_is_not_installed(self):
        page = b'<a href="/dist/nmap-7.993.dmg">nmap-7.993.dmg</a>'

        def fetch(url, **kw):
            if url.endswith("download.html"):
                return 200, {}, page
            if url.endswith(".digest.txt"):
                return 200, {}, DIGEST.encode()
            return 200, {}, b"not the official image"
        with mock.patch.object(tools, "IS_MACOS", True), mock.patch.object(tools, "find_cmd", return_value=None), \
                mock.patch.object(tools, "brew_path", return_value=None), \
                mock.patch.object(tools, "_admin_install", side_effect=AssertionError("must not install")):
            res = tools.install_nmap(fetch=fetch)
        self.assertFalse(res["ok"])
        self.assertIn("チェックサム不一致", res["error"])

    def test_missing_official_checksum_aborts(self):
        def fetch(url, **kw):
            return (200, {}, b"nmap-7.993.dmg") if url.endswith("download.html") else (404, {}, b"")
        with mock.patch.object(tools, "IS_MACOS", True), mock.patch.object(tools, "find_cmd", return_value=None), \
                mock.patch.object(tools, "brew_path", return_value=None):
            res = tools.install_nmap(fetch=fetch)
        self.assertFalse(res["ok"])
        self.assertIn("チェックサム", res["error"])

    def test_not_macos(self):
        with mock.patch.object(tools, "IS_MACOS", False):
            self.assertFalse(tools.install_nmap()["ok"])

    def test_already_installed_is_a_no_op(self):
        with mock.patch.object(tools, "IS_MACOS", True), mock.patch.object(tools, "find_cmd", return_value="/x/nmap"), \
                mock.patch.object(tools, "nmap_version", return_value="7.993"):
            res = tools.install_nmap(fetch=lambda *a, **k: self.fail("no download when present"))
        self.assertTrue(res["ok"] and res["already"])

    def test_sha256_helper(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"abc")
            f.flush()
            self.assertEqual(tools._sha256(f.name), hashlib.sha256(b"abc").hexdigest())


class BundleCommandTest(unittest.TestCase):
    def test_official_app_bundle_runs_the_real_binary(self):
        import os
        from kekkai.discovery import nmap as nmapmod
        with tempfile.TemporaryDirectory() as d:
            app = os.path.join(d, "nmap.app", "Contents")
            for rel in ("MacOS/nmap", "Resources/bin/nmap"):
                path = os.path.join(app, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write("#!/bin/sh\n")
                os.chmod(path, 0o755)
            os.makedirs(os.path.join(app, "Resources", "share", "nmap"))
            with mock.patch.object(nmapmod, "find_cmd", return_value=os.path.join(app, "MacOS", "nmap")):
                exe, env = nmapmod.command()
            self.assertEqual(exe, os.path.join(app, "Resources", "bin", "nmap"))
            self.assertEqual(env["DYLD_LIBRARY_PATH"], os.path.join(app, "Resources", "lib"))
            self.assertEqual(env["NMAPDIR"], os.path.join(app, "Resources", "share", "nmap"))
        with mock.patch.object(nmapmod, "find_cmd", return_value="/opt/homebrew/bin/nmap"):
            self.assertEqual(nmapmod.command(), ("/opt/homebrew/bin/nmap", None))   # Homebrew: unchanged


class TopPortsFallbackTest(unittest.TestCase):
    def test_explicit_port_list_when_top_ports_is_rejected(self):
        from kekkai.discovery import nmap as nmapmod
        calls = []
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="8080"><state state="open"/>'
               '<service name="http" product="SimpleHTTPServer" version="0.6"/></port></ports></host></nmaprun>')

        def fake_run(cmd, timeout=None, env=None):
            calls.append(cmd)
            if "--top-ports" in cmd:
                return 1, "", "--top-ports should be an integer between 1 and 65535\nQUITTING!\n"
            return 0, xml, ""
        with mock.patch.object(nmapmod, "run", fake_run), mock.patch.object(nmapmod, "find_cmd", return_value="/x/nmap"):
            res = nmapmod.scan("192.168.1.20")
        self.assertEqual(len(calls), 2)
        plist = calls[1][calls[1].index("-p") + 1].split(",")
        for must in ("22", "23", "445", "7547", "8080", "37215"):
            self.assertIn(must, plist)
        self.assertEqual(res["scanned"], len(plist))
        self.assertEqual(res["open"][0]["product"], "SimpleHTTPServer")

    def test_other_errors_are_not_retried(self):
        from kekkai.discovery import nmap as nmapmod
        calls = []
        with mock.patch.object(nmapmod, "run", lambda cmd, **k: calls.append(cmd) or (1, "", "Failed to resolve")), \
                mock.patch.object(nmapmod, "find_cmd", return_value="/x/nmap"):
            with self.assertRaises(RuntimeError):
                nmapmod.scan("192.168.1.20")
        self.assertEqual(len(calls), 1)


class MonitorInstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.addCleanup(self.store.close)
        self.m = Monitor(cfg, self.store, StubPlatform())

    def test_progress_result_and_coverage_card(self):
        from kekkai.coverage import describe
        events = []
        self.m.bus.publish = lambda kind, data: events.append((kind, data))

        def fake_install(progress=None, prefer=None):
            progress("ダウンロード中")
            card = {c["id"]: c for c in describe(self.m)["cards"]}["nmap"]
            if card["state"] not in ("installing", "available"):
                raise AssertionError(card)
            return {"ok": False, "error": "テスト用の失敗"}
        self.m._install_nmap = fake_install
        with mock.patch("kekkai.coverage.find_cmd", return_value=None):
            res = self.m.install_nmap()
            card = {c["id"]: c for c in describe(self.m)["cards"]}["nmap"]
        self.assertFalse(res["ok"])
        self.assertFalse(self.m.state["nmap_install"]["running"])
        self.assertEqual(card["state"], "unavailable")
        self.assertIn("前回の導入は失敗", card["detail"])     # a failed install is shown, not hidden
        self.assertTrue(any(k == "tools" and d.get("running") for k, d in events))
        self.assertTrue(any(k == "tools" and not d.get("running") and d["result"]["error"] for k, d in events))

    def test_second_install_while_running_is_refused(self):
        self.m.state["nmap_install"] = {"running": True}
        with self.assertRaises(RuntimeError):
            self.m.install_nmap()



class RefreshAgentTest(unittest.TestCase):
    """Replacing KEKKAI.app must not leave the old background monitor serving the old code."""

    def setUp(self):
        from kekkai import cli
        self.cli = cli
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.plist = str(Path(self.tmp.name) / "agent.plist")
        self.calls = []

    def write_agent(self, root):
        with open(self.plist, "wb") as f:
            plistlib.dump({"Label": "com.kekkai.monitor", "EnvironmentVariables": {"PYTHONPATH": root}}, f)

    def run_refresh(self, versions, code="same"):
        from kekkai import service
        mine = service.code_digest()
        seq = iter(versions)
        info = lambda *a, **k: {"version": next(seq, self.cli.__version__), "code": mine if code == "same" else code}  # noqa: E731
        with mock.patch.object(self.cli, "IS_MACOS", True), mock.patch.object(self.cli, "_agent_path", return_value=self.plist), \
                mock.patch.object(self.cli, "_running_info", side_effect=info), \
                mock.patch.object(self.cli, "run", side_effect=lambda cmd, **k: self.calls.append(cmd) or (0, "", "")), \
                mock.patch.object(self.cli, "cmd_install_agent", side_effect=lambda a: self.calls.append(["install-agent"]) or 0), \
                mock.patch("kekkai.server.session_alive", return_value=True):
            return self.cli.refresh_agent(wait=2)

    def test_old_version_is_restarted(self):
        self.write_agent(self.cli._code_root())
        self.assertEqual(self.run_refresh(["0.1.0"]), "restarted")
        self.assertTrue(any(c[:3] == ["launchctl", "kickstart", "-k"] for c in self.calls))

    def test_agent_from_another_copy_is_re_registered(self):
        self.write_agent("/Users/me/Downloads/KEKKAI.app/Contents/Resources/kekkai/src")
        self.assertEqual(self.run_refresh([self.cli.__version__]), "moved")
        self.assertIn(["install-agent"], self.calls)

    def test_same_version_but_different_code_is_restarted(self):
        """A rebuilt app keeps its version number: the old monitor must still be replaced."""
        self.write_agent(self.cli._code_root())
        self.assertEqual(self.run_refresh([self.cli.__version__], code="0123456789abcdef"), "restarted")

    def test_old_server_without_code_fingerprint_is_restarted(self):
        self.write_agent(self.cli._code_root())
        self.assertEqual(self.run_refresh([self.cli.__version__], code=None), "restarted")

    def test_current_version_is_left_alone(self):
        self.write_agent(self.cli._code_root())
        self.assertIsNone(self.run_refresh([self.cli.__version__]))
        self.assertEqual(self.calls, [])

    def test_no_agent_registered(self):
        with mock.patch.object(self.cli, "IS_MACOS", True), mock.patch.object(self.cli, "_agent_path", return_value="/nonexistent"):
            self.assertIsNone(self.cli.refresh_agent())



class SelfTestTest(unittest.TestCase):
    """nmap_selftest must say which step fails on this Mac, and never report 'working' without identifying a service."""

    def test_not_installed(self):
        with mock.patch("kekkai.discovery.nmap.command", return_value=(None, None)):
            res = tools.nmap_selftest("192.168.1.1")
        self.assertFalse(res["ok"])
        self.assertEqual(res["failed"]["id"], "found")
        self.assertIn("nmapを入れる", res["failed"]["fix"])

    def test_cannot_run_points_to_rosetta(self):
        with mock.patch("kekkai.discovery.nmap.command", return_value=("/x/nmap", None)), \
                mock.patch.object(tools.subprocess, "run", side_effect=OSError(86, "Bad CPU type in executable")), \
                mock.patch.object(tools, "apple_silicon", return_value=True), \
                mock.patch.object(tools, "rosetta_ready", return_value=False):
            res = tools.nmap_selftest("192.168.1.1")
        self.assertEqual(res["failed"]["id"], "runs")
        self.assertIn("Rosetta", res["failed"]["fix"])

    def _with_fake_nmap(self, xml_for_service, lan_reach, lan_xml='<state state="closed"/>'):
        runs = []

        def fake_util_run(cmd, timeout=None, env=None):
            runs.append(cmd)
            if "127.0.0.1" in cmd:
                port = cmd[cmd.index("-p") + 1]
                return 0, xml_for_service.replace("PORT", port), ""
            return 0, "<nmaprun><host><ports><port portid='53'>%s</port></ports></host></nmaprun>" % lan_xml, ""
        ver = mock.Mock(returncode=0, stdout="Nmap version 7.993 ( https://nmap.org )\n", stderr="")
        with mock.patch("kekkai.discovery.nmap.command", return_value=("/x/nmap", None)), \
                mock.patch.object(tools.subprocess, "run", return_value=ver), \
                mock.patch("kekkai.util.run", fake_util_run), \
                mock.patch.object(tools, "_lan_reach", return_value=lan_reach):
            return tools.nmap_selftest("192.168.1.1"), runs

    def test_all_steps_pass(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="PORT"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="9.6"/></port></ports></host></nmaprun>')
        res, runs = self._with_fake_nmap(xml, (True, "ok"))
        self.assertTrue(res["ok"], res)
        self.assertEqual([x["id"] for x in res["steps"]], ["found", "runs", "service", "lan"])

    def test_service_not_identified_is_a_failure(self):
        xml = '<nmaprun><host><ports><port protocol="tcp" portid="PORT"><state state="open"/></port></ports></host></nmaprun>'
        res, _ = self._with_fake_nmap(xml, (True, "ok"))
        self.assertFalse(res["ok"])
        self.assertEqual(res["failed"]["id"], "service")

    def test_lan_blocked_by_macos_explains_the_setting(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="PORT"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="9.6"/></port></ports></host></nmaprun>')
        res, _ = self._with_fake_nmap(xml, (False, "No route to host"))
        self.assertFalse(res["ok"])
        self.assertEqual(res["failed"]["id"], "lan")
        self.assertIn("ローカルネットワーク", res["failed"]["fix"])

    def test_nmap_filtered_while_python_reaches_router(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="PORT"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="9.6"/></port></ports></host></nmaprun>')
        res, _ = self._with_fake_nmap(xml, (True, "ok"), lan_xml='<state state="filtered"/>')
        self.assertEqual(res["failed"]["id"], "lan")

    @unittest.skipUnless(__import__("shutil").which("nmap"), "nmap not installed here")
    def test_real_nmap_identifies_the_test_service(self):
        res = tools.nmap_selftest(None)
        self.assertTrue(res["ok"], tools.selftest_lines(res))


class BannerListenerTest(unittest.TestCase):
    def test_survives_clients_that_reset_at_once(self):
        """nmap's connect scan resets immediately (EPIPE on macOS); the test service must keep answering."""
        import socket
        import struct
        srv, port, stop = tools._banner_listener()
        self.addCleanup(srv.close)
        self.addCleanup(stop.set)
        for _ in range(5):
            c = socket.create_connection(("127.0.0.1", port), timeout=2)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # close with RST
            c.close()
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.addCleanup(c.close)
        self.assertEqual(c.recv(64), tools._FAKE_BANNER)


class CoverageEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.addCleanup(self.store.close)
        self.m = Monitor(cfg, self.store, StubPlatform())

    def card(self):
        from kekkai.coverage import describe
        with mock.patch("kekkai.coverage.find_cmd", return_value="/x/nmap"):
            return {c["id"]: c for c in describe(self.m)["cards"]}["nmap"]

    def test_installed_is_not_claimed_working_until_proven(self):
        self.m.state["nmap_check"] = None
        self.assertEqual(self.card()["state"], "unverified")
        self.m.state["nmap_check"] = {"ok": True, "ts": __import__("time").time(), "steps": []}
        self.assertEqual(self.card()["state"], "active")
        self.m.state["nmap_check"] = {"ok": False, "ts": __import__("time").time(), "steps": [],
                                      "failed": {"label": "自宅LANへの接続", "detail": "No route to host", "fix": tools.LAN_FIX}}
        card = self.card()
        self.assertEqual(card["state"], "broken")
        self.assertIn("No route to host", card["detail"])
        self.assertEqual(card["fix"], tools.LAN_FIX)

    def test_dialog_failure_continues_in_terminal(self):
        present = {"v": False}
        self.m._deep_available = lambda: present["v"]
        self.m._install_nmap = lambda progress=None, prefer=None: {"ok": False, "method": "pkg", "admin_failed": True,
                                                                     "error": "No user interaction allowed"}

        def opener():
            present["v"] = True        # the user typed the password in Terminal
            return True, ""
        self.m._open_terminal_install = opener
        self.m.bus.publish = lambda *a, **k: None
        with mock.patch.object(self.m, "nmap_check", return_value={"ok": True, "steps": []}), \
                mock.patch.object(tools, "nmap_version", return_value="7.993"):
            res = self.m.install_nmap()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["method"], "pkg-terminal")

    def test_install_that_does_not_work_is_reported_as_failure(self):
        self.m._install_nmap = lambda progress=None, prefer=None: {"ok": True, "method": "brew"}
        self.m.bus.publish = lambda *a, **k: None
        broken = {"ok": False, "steps": [], "failed": {"label": "nmap の起動", "detail": "dyld: Library not loaded", "fix": "やり直し"}}
        with mock.patch.object(self.m, "nmap_check", return_value=broken):
            res = self.m.install_nmap()
        self.assertFalse(res["ok"])
        self.assertIn("動作確認で失敗", res["error"])


class TranslocationTest(unittest.TestCase):
    def test_temporary_copy_is_never_registered(self):
        from kekkai import cli
        moved = "/private/var/folders/ab/T/AppTranslocation/1234/d/KEKKAI.app/Contents/Resources/kekkai/src"
        with mock.patch.object(cli, "IS_MACOS", True), mock.patch.object(cli, "_code_root", return_value=moved), \
                mock.patch("os.path.exists", return_value=True):
            self.assertIsNone(cli.refresh_agent())
        with mock.patch.object(cli, "IS_MACOS", True), mock.patch("os.geteuid", return_value=501), \
                mock.patch("os.path.abspath", return_value=moved + "/kekkai/cli.py"):
            self.assertEqual(cli.cmd_install_agent(__import__("argparse").Namespace()), 2)


if __name__ == "__main__":
    unittest.main()
