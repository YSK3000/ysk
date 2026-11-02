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
    exe = path or find_cmd("nmap")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20).stdout
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
            return {"ok": False, "method": "pkg", "cancelled": cancelled,
                    "error": "インストールを取り消しました" if cancelled else "インストーラーが失敗: %s" % out}
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


def describe_result(res: Dict[str, Any]) -> List[str]:
    if res.get("ok"):
        return ["nmap %s を使えるようになりました（%s）" % (res.get("version") or "", res.get("path"))]
    return ["nmap を入れられませんでした: %s" % res.get("error", "不明なエラー")]
