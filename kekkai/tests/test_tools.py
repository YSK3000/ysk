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


if __name__ == "__main__":
    unittest.main()
