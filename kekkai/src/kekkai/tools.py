"""Install nmap (the optional deep scanner) for the user, from an official source, with their consent.

Two routes, chosen automatically:
- Homebrew present  -> `brew install nmap` as the user (no password; native build; `brew upgrade` keeps it current).
- no Homebrew       -> the official installer from nmap.org: download over verified HTTPS and compare with the
                       SHA-256 nmap.org publishes, then install it through the standard macOS administrator
                       dialog (the password goes to macOS, never to KEKKAI). Only the nmap component is selected
                       (not Zenmap/Ncat/Nping). Measured on a real macOS 26 runner (2026-11-02): the installer
                       (nmap-7.993) has no Apple signature, is x86-64 only and installs /Applications/nmap.app,
                       so Apple Silicon also needs Apple's Rosetta 2, which is installed in the same step.
KEKKAI never runs anything as root itself; the root step is Apple's /usr/sbin/installer (and softwareupdate
for Rosetta) on the checksum-verified package.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from kekkai.util import IS_MACOS, FetchError, find_cmd, http_get, log

NMAP_DOWNLOAD_PAGE = "https://nmap.org/download.html"
NMAP_DIST = "https://nmap.org/dist/"
BREW_PATHS = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
_DMG_RE = re.compile(r"\bnmap-(\d+)\.(\d+)(?:\.(\d+))?(?:-(\d+))?\.dmg\b")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/+-]+$")
MAX_DMG_BYTES = 200 * 1024 * 1024

Progress = Callable[[str], None]


def brew_path() -> Optional[str]:
    for p in BREW_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def nmap_version(path: Optional[str] = None) -> Optional[str]:
    from kekkai.discovery.nmap import command
    exe, env = command()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20,
                             env=dict(os.environ, **(env or {}))).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Nmap version (\S+)", out)
    return m.group(1) if m else None


def nmap_status() -> Dict[str, Any]:
    exe = find_cmd("nmap")
    brew = brew_path()
    method = None if exe else ("brew" if brew else "pkg")
    return {"installed": bool(exe), "path": exe, "version": nmap_version(exe) if exe else None,
            "method": method, "needs_password": method == "pkg",
            "needs_rosetta": method == "pkg" and not rosetta_ready(), "supported": IS_MACOS}


def latest_dmg(page: str) -> Optional[str]:
    """Pick the newest `nmap-X.YY.dmg` named on the official download page."""
    best: Optional[Tuple[Tuple[int, ...], str]] = None
    for m in _DMG_RE.finditer(page):
        key = tuple(int(x or 0) for x in m.groups())
        if best is None or key > best[0]:
            best = (key, m.group(0))
    return best[1] if best else None


def digest_sha256(text: str, filename: str) -> Optional[str]:
    """Find the SHA-256 for `filename` in nmap.org's .digest.txt (GnuPG --print-mds style or `hash  name`)."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "SHA256" not in line.upper():
            continue
        # "nmap-7.95.dmg: SHA256 = 0123 4567 ..." possibly wrapped onto the following indented lines
        chunk = line.split("=", 1)[1] if "=" in line else ""
        j = i + 1
        while j < len(lines) and lines[j][:1].isspace() and "=" not in lines[j]:
            chunk += lines[j]
            j += 1
        hexs = re.sub(r"[^0-9A-Fa-f]", "", chunk)
        if len(hexs) == 64 and (filename in line or filename in text[:200]):
            return hexs.lower()
    for line in lines:
        m = re.match(r"^\s*([0-9A-Fa-f]{64})\s+\*?(\S+)\s*$", line)
        if m and m.group(2).endswith(filename):
            return m.group(1).lower()
    return None


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_pkg_signature(text: str) -> Tuple[bool, str]:
    """Judge `pkgutil --check-signature` output.

    nmap.org ships its installer unsigned (measured), so "no signature" is accepted (integrity then rests on
    the published SHA-256). A signature that is present but not valid, or not Apple-issued, is rejected.
    """
    if "Status: no signature" in text:
        return True, "Apple署名なし（nmap公式の配布形態）・SHA-256一致"
    if "Status: signed by a developer certificate issued by Apple" in text:
        m = re.search(r"Developer ID Installer: ([^\n(]+)\(([A-Z0-9]{10})\)", text)
        return True, ("Developer ID: %s(%s)" % (m.group(1).strip(), m.group(2))) if m else "Apple発行の証明書で署名"
    return False, "インストーラーの署名が不正です（中止しました）"


def apple_silicon() -> bool:
    if not IS_MACOS:
        return False
    try:
        out = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.stdout.strip() == "1"


def rosetta_ready() -> bool:
    """True when x86-64 programs can run (always on Intel; on Apple Silicon only with Rosetta 2)."""
    if not apple_silicon():
        return True
    try:
        return subprocess.run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


_SKIP_CHOICES = re.compile(r"zenmap|ncat|nping|ndiff", re.I)


def choice_changes(xml_text: str) -> Optional[bytes]:
    """From `installer -showChoiceChangesXML`, deselect everything except nmap itself. None if not parseable."""
    import plistlib
    try:
        items = plistlib.loads(xml_text.encode() if isinstance(xml_text, str) else xml_text)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(items, list):
        return None
    out = []
    for it in items:
        if not isinstance(it, dict) or it.get("choiceAttribute") != "selected":
            continue
        ident = str(it.get("choiceIdentifier", ""))
        if _SKIP_CHOICES.search(ident):
            out.append({"choiceIdentifier": ident, "choiceAttribute": "selected", "attributeSetting": 0})
    return plistlib.dumps(out) if out else None


def osascript_cmd(steps: List[List[str]], admin: bool = True) -> List[str]:
    """One osascript call that runs `steps` (joined with &&), each word AppleScript-quoted from argv.

    With admin=True macOS shows its standard administrator dialog (one prompt for every step).
    """
    args: List[str] = []
    parts = []
    for step in steps:
        words = []
        for w in step:
            args.append(w)
            words.append("quoted form of (item %d of argv)" % len(args))
        parts.append(" & \" \" & ".join(words))
    line = "do shell script " + " & \" && \" & ".join(parts)
    if admin:
        line += (" with prompt \"KEKKAI: nmap（nmap.org 公式）を入れます。"
                 "Macのログインパスワードを入力してください。\" with administrator privileges")
    cmd = ["/usr/bin/osascript"]
    for x in ("on run argv", line, "end run"):
        cmd += ["-e", x]
    return cmd + args


def _admin_install(pkg: str, choices: Optional[str] = None, rosetta: bool = False) -> Tuple[int, str]:
    """Run Apple's installer as root through the standard macOS administrator dialog.

    KEKKAI_PRIV=sudo (CI only) uses non-interactive sudo instead, since nobody can type a password there.
    Paths are passed as arguments (quoted form), never spliced into the script, and must be plain paths.
    """
    for path in (pkg, choices):
        if path and not _SAFE_PATH.match(path):
            return 2, "unsafe path: %r" % path
    steps = []
    if rosetta:
        steps.append(["/usr/sbin/softwareupdate", "--install-rosetta", "--agree-to-license"])
    inst = ["/usr/sbin/installer", "-pkg", pkg, "-target", "/"]
    if choices:
        inst += ["-applyChoiceChangesXML", choices]
    steps.append(inst)
    if os.environ.get("KEKKAI_PRIV") == "sudo-tty":
        # Terminal route: sudo asks for the password in the Terminal window the user is looking at
        for step in steps:
            try:
                rc = subprocess.run(["/usr/bin/sudo"] + step, timeout=1800).returncode
            except (OSError, subprocess.SubprocessError) as e:
                return 1, str(e)
            if rc != 0:
                return rc, "sudo %s が失敗（rc=%s）" % (step[0], rc)
        return 0, ""
    if os.environ.get("KEKKAI_PRIV") == "sudo":
        log_out = []
        for step in steps:
            try:
                p = subprocess.run(["/usr/bin/sudo", "-n"] + step, capture_output=True, text=True, timeout=1800)
            except (OSError, subprocess.SubprocessError) as e:
                return 1, str(e)
            log_out.append((p.stdout + p.stderr).strip())
            if p.returncode != 0:
                return p.returncode, "\n".join(log_out)[-600:]
        return 0, "\n".join(log_out)[-600:]
    cmd = osascript_cmd(steps)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)
    return p.returncode, (p.stdout + p.stderr).strip()[-600:]


def _install_brew(brew: str, progress: Progress) -> Dict[str, Any]:
    progress("Homebrew で nmap を入れています（1〜5分）…")
    env = dict(os.environ)
    env.update({"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1",
                "NONINTERACTIVE": "1"})
    env["PATH"] = os.path.dirname(brew) + ":/usr/bin:/bin:/usr/sbin:/sbin"
    try:
        p = subprocess.run([brew, "install", "nmap"], capture_output=True, text=True, timeout=1800, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "method": "brew", "error": "brew を実行できません: %s" % e}
    if p.returncode != 0:
        return {"ok": False, "method": "brew", "error": "brew install nmap が失敗: %s" % (p.stderr or p.stdout).strip()[-400:]}
    return {"ok": True, "method": "brew", "source": "Homebrew (formulae.brew.sh/formula/nmap)"}


def _install_pkg(progress: Progress, fetch: Callable[..., Any]) -> Dict[str, Any]:
    progress("nmap.org から最新版を確認しています…")
    status, _, body = fetch(NMAP_DOWNLOAD_PAGE, timeout=60, max_bytes=4 * 1024 * 1024)
    if status != 200:
        raise FetchError("download page HTTP %s" % status)
    dmg = latest_dmg(body.decode("utf-8", "replace"))
    if not dmg:
        return {"ok": False, "method": "pkg", "error": "nmap.org のダウンロードページに macOS 版が見つかりません"}
    status, _, dig = fetch(NMAP_DIST + "sigs/" + dmg + ".digest.txt", timeout=60, max_bytes=256 * 1024)
    want = digest_sha256(dig.decode("utf-8", "replace"), dmg) if status == 200 else None
    if not want:
        return {"ok": False, "method": "pkg", "error": "公式のチェックサム（%s.digest.txt）を取得できません" % dmg}
    work = tempfile.mkdtemp(prefix="kekkai-nmap-")
    mnt = os.path.join(work, "mnt")
    try:
        progress("%s をダウンロードしています…" % dmg)
        status, _, data = fetch(NMAP_DIST + dmg, timeout=600, max_bytes=MAX_DMG_BYTES)
        if status != 200:
            raise FetchError("%s HTTP %s" % (dmg, status))
        path = os.path.join(work, dmg)
        with open(path, "wb") as f:
            f.write(data)
        got = _sha256(path)
        if got != want:
            return {"ok": False, "method": "pkg", "error": "チェックサム不一致（改ざんの可能性）。中止しました"}
        progress("チェックサム一致。署名を確認しています…")
        os.mkdir(mnt)
        p = subprocess.run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mnt, path],
                           capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            return {"ok": False, "method": "pkg", "error": "ディスクイメージを開けません: %s" % p.stderr.strip()[-300:]}
        pkgs = sorted(n for n in os.listdir(mnt) if n.endswith((".pkg", ".mpkg")))
        if not pkgs:
            return {"ok": False, "method": "pkg", "error": "ディスクイメージにインストーラーがありません"}
        pkg = os.path.join(mnt, pkgs[0])
        sig = subprocess.run(["/usr/sbin/pkgutil", "--check-signature", pkg], capture_output=True, text=True, timeout=60)
        ok, who = check_pkg_signature(sig.stdout + sig.stderr)
        if not ok:
            return {"ok": False, "method": "pkg", "error": who}
        choices = None
        shown = subprocess.run(["/usr/sbin/installer", "-showChoiceChangesXML", "-pkg", pkg],
                               capture_output=True, text=True, timeout=60)
        xml = choice_changes(shown.stdout) if shown.returncode == 0 else None
        if os.environ.get("KEKKAI_DEBUG_CHOICES"):
            progress("choices rc=%s: %s" % (shown.returncode, (shown.stdout or shown.stderr)[:3000]))
        if xml:
            choices = os.path.join(work, "choices.plist")
            with open(choices, "wb") as f:
                f.write(xml)
        need_rosetta = not rosetta_ready()
        progress("確認済み（%s）。macOSのパスワード入力画面が出たら入力してください%s…" % (
            who, "（Apple Silicon 用に Apple の Rosetta 2 も入ります）" if need_rosetta else ""))
        rc, out = _admin_install(pkg, choices, rosetta=need_rosetta)
        if rc != 0:
            cancelled = "-128" in out or "User canceled" in out or "キャンセル" in out
            return {"ok": False, "method": "pkg", "cancelled": cancelled, "admin_failed": not cancelled,
                    "error": "インストールを取り消しました" if cancelled else
                    "インストーラーが失敗: %s（ターミナルで KEKKAI.app/Contents/Resources/kekkai/kekkai install-nmap "
                    "を実行しても導入できます）" % out}
        return {"ok": True, "method": "pkg", "source": NMAP_DIST + dmg, "sha256": got, "signer": who,
                "rosetta_installed": need_rosetta, "only_nmap": bool(choices)}
    finally:
        if os.path.ismount(mnt):
            subprocess.run(["/usr/bin/hdiutil", "detach", "-force", mnt], capture_output=True, timeout=120)
        shutil.rmtree(work, ignore_errors=True)


def install_nmap(progress: Optional[Progress] = None, fetch: Callable[..., Any] = http_get,
                 prefer: Optional[str] = None) -> Dict[str, Any]:
    """Install nmap. Returns {"ok", "method", "path", "version", "error"?, "source"?}. Never raises."""
    say: Progress = progress or (lambda s: None)
    t0 = time.time()
    if not IS_MACOS:
        return {"ok": False, "error": "macOS 専用です（Linux はディストリビューションのパッケージで導入）"}
    if find_cmd("nmap") and prefer is None:
        return {"ok": True, "method": "present", "path": find_cmd("nmap"), "version": nmap_version(), "already": True}
    brew = brew_path()
    try:
        if (prefer or ("brew" if brew else "pkg")) == "brew" and brew:
            res = _install_brew(brew, say)
        else:
            res = _install_pkg(say, fetch)
    except FetchError as e:
        res = {"ok": False, "method": "pkg", "error": "nmap.org に接続できません: %s" % e}
    except (OSError, subprocess.SubprocessError) as e:
        log.exception("nmap install failed")
        res = {"ok": False, "error": "導入中にエラー: %s" % e}
    exe = find_cmd("nmap")
    if res.get("ok") and not exe:
        res = dict(res, ok=False, error="導入は終わりましたが nmap が見つかりません")
    res.update({"path": exe, "version": nmap_version(exe) if exe else None, "duration": round(time.time() - t0, 1)})
    return res


def open_terminal_install() -> Tuple[bool, str]:
    """Continue the install in a Terminal window (password typed there), when the macOS dialog could not be used.

    The script is written by KEKKAI into its own data folder (not downloaded, so Gatekeeper does not stop it)
    and only runs this copy's `kekkai install-nmap`.
    """
    import shlex
    from kekkai import paths
    launcher = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "kekkai")
    if not os.access(launcher, os.X_OK):
        return False, "KEKKAI の起動スクリプトが見つかりません: %s" % launcher
    script = paths.sub("install-nmap.command")
    body = ("#!/bin/sh\n"
            "echo 'KEKKAI: nmap（nmap.org 公式）を入れます。'\n"
            "echo 'Macのログインパスワードを入力して return を押してください（入力中の文字は表示されません）。'\n"
            "%s install-nmap --yes --terminal --method pkg\n"
            "echo; echo '--- 終わりました。このウインドウは閉じて構いません（KEKKAI の画面に結果が出ます）---'\n"
            % shlex.quote(launcher))
    with open(str(script), "w", encoding="utf-8") as f:
        f.write(body)
    os.chmod(str(script), 0o700)
    try:
        p = subprocess.run(["/usr/bin/open", "-a", "Terminal", str(script)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return p.returncode == 0, (p.stderr or "").strip()


# ------------------------------------------------------------------ self-test on this Mac
_FAKE_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


def _banner_listener() -> Tuple[Any, int, Any]:
    """A loopback TCP service that greets like OpenSSH 9.6, so nmap -sV has something real to identify."""
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.5)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            # nmap's port scan connects and resets at once; on macOS writing to that socket raises EPIPE.
            # Every connection error must be swallowed so the service stays up for the version probe.
            try:
                c.sendall(_FAKE_BANNER)
                c.settimeout(2)
                c.recv(1024)
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass
    threading.Thread(target=serve, daemon=True, name="kekkai-nmap-selftest").start()
    return srv, srv.getsockname()[1], stop


def _lan_reach(gateway: str) -> Tuple[Optional[bool], str]:
    """Can this process open TCP connections to the router? (False = refused by macOS, None = no answer)."""
    import errno
    import socket
    last = None
    for port in (53, 80, 443):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1.5)
        try:
            rc = sk.connect_ex((gateway, port))
        except OSError as e:
            rc = e.errno or -1
        finally:
            sk.close()
        if rc in (0, errno.ECONNREFUSED):
            return True, "ルーター(%s)の%d番に到達" % (gateway, port)
        last = rc
    if last in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES):
        return False, os.strerror(last)
    return None, "ルーターの53/80/443番は応答なし"


LAN_FIX = ("システム設定 →「プライバシーとセキュリティ」→「ローカルネットワーク」で、一覧にある KEKKAI または Python を"
           "オンにし、KEKKAI.app を開き直してください")


def nmap_selftest(gateway: Optional[str] = None) -> Dict[str, Any]:
    """Prove on this Mac, step by step, that nmap runs and identifies services; say which step fails and why."""
    from kekkai.discovery.nmap import command, parse_xml
    from kekkai.util import run
    t0 = time.time()
    steps: List[Dict[str, Any]] = []

    def add(sid: str, label: str, ok: Optional[bool], detail: str, fix: Optional[str] = None) -> None:
        steps.append({"id": sid, "label": label, "ok": ok, "detail": detail, "fix": fix})

    def done() -> Dict[str, Any]:
        failed = [x for x in steps if x["ok"] is False]
        identified = any(x["id"] == "service" and x["ok"] for x in steps)
        return {"ok": not failed and identified, "steps": steps, "ts": time.time(),
                "duration": round(time.time() - t0, 1), "failed": failed[0] if failed else None}

    exe, env = command()
    if not exe:
        add("found", "nmap の場所", False, "nmap が見つかりません", "「nmapを入れる」で導入してください")
        return done()
    add("found", "nmap の場所", True, exe)
    p_env = dict(os.environ, **(env or {}))
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60, env=p_env)
        out, err, rc = p.stdout, p.stderr, p.returncode
    except OSError as e:
        out, err, rc = "", str(e), 126
    except subprocess.SubprocessError as e:
        out, err, rc = "", str(e), 124
    m = re.search(r"Nmap version (\S+)", out)
    if rc != 0 or not m:
        why = (err or out).strip()[-300:] or "rc=%s" % rc
        fix = None
        if "Bad CPU type" in why or "[Errno 86]" in why or (apple_silicon() and not rosetta_ready()):
            fix = "Apple の Rosetta 2 が必要です。もう一度「nmapを入れる」を押すと一緒に入ります"
        elif "Library not loaded" in why or "dyld" in why:
            fix = "nmap の付属ライブラリが読めません。nmap.app を削除して「nmapを入れる」をやり直してください"
        add("runs", "nmap の起動", False, why, fix or "「nmapを入れる」をやり直してください")
        return done()
    add("runs", "nmap の起動", True, "Nmap %s" % m.group(1))

    srv, port, stop = _banner_listener()
    try:
        rc, xml, err = run([exe, "-sV", "--version-light", "-Pn", "-p", str(port), "-oX", "-", "--", "127.0.0.1"],
                           timeout=120, env=env)
    finally:
        stop.set()
        srv.close()
    found = []
    if rc == 0:
        try:
            found = [x for x in parse_xml(xml) if x.get("port") == port]
        except Exception:  # noqa: BLE001 - malformed output is a failure, reported below
            found = []
    if found and (found[0].get("product") or "").lower().startswith("openssh"):
        add("service", "サービスと版の特定", True, "テスト用のサービスを %s %s と特定" % (
            found[0].get("product"), found[0].get("version") or ""))
    else:
        add("service", "サービスと版の特定", False,
            (err.strip()[-300:] if rc != 0 else "ポートは見えたが製品名を特定できず: %r" % (found[:1],)),
            "nmap のデータファイルが壊れている可能性。nmap.app を削除して「nmapを入れる」をやり直してください")
        return done()

    if not gateway:
        add("lan", "自宅LANへの接続", None, "ルーターが分からないため未確認")
        return done()
    reach, why = _lan_reach(gateway)
    if reach is False:
        add("lan", "自宅LANへの接続", False, "macOS がLANへの接続を止めています（%s）" % why, LAN_FIX)
        return done()
    rc, xml, err = run([exe, "-Pn", "-sT", "-p", "53,80,443", "-oX", "-", "--", gateway], timeout=60, env=env)
    states = re.findall(r'<state state="(\w+)"', xml or "")
    if rc != 0:
        add("lan", "自宅LANへの接続", False, "nmap がルーターを調べられません: %s" % err.strip()[-200:], LAN_FIX)
    elif states and all(st == "filtered" for st in states) and reach:
        add("lan", "自宅LANへの接続", False, "KEKKAI はルーターに届くのに nmap からは届きません（ポートが全て filtered）",
            LAN_FIX)
    else:
        add("lan", "自宅LANへの接続", True if reach else None,
            "nmap でルーター(%s)を確認: %s" % (gateway, ", ".join(sorted(set(states))) or "応答なし"))
    return done()


def selftest_lines(res: Dict[str, Any]) -> List[str]:
    mark = {True: "✓", False: "✗", None: "・"}
    lines = ["%s %s: %s" % (mark[x["ok"]], x["label"], x["detail"]) for x in res.get("steps", [])]
    if res.get("failed") and res["failed"].get("fix"):
        lines.append("→ 直し方: " + res["failed"]["fix"])
    return lines


def describe_result(res: Dict[str, Any]) -> List[str]:
    if res.get("ok"):
        return ["nmap %s を使えるようになりました（%s）" % (res.get("version") or "", res.get("path"))]
    return ["nmap を入れられませんでした: %s" % res.get("error", "不明なエラー")]
