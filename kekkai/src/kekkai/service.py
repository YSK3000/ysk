"""Always-on packet sensor on macOS: `sudo ./kekkai install-sensor` registers a LaunchDaemon.

The daemon runs as root, so it never executes the user's checkout (malware running as the user could edit it
and get root). install copies the Python package into the root-owned state directory and the daemon runs
that copy in isolated mode (-I: no PYTHONPATH, no user site-packages). Re-run install after updating KEKKAI.
"""
from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict

from kekkai.sensor import prepare_state_dir, state_dir
from kekkai.util import IS_MACOS, run


def bootstrap(domain: str, plist: str, label: str) -> tuple:
    """(Re)load a launchd job. Right after bootout launchctl may still answer "5: Input/output error"."""
    run(["launchctl", "bootout", "%s/%s" % (domain, label)], timeout=20)
    rc, err = 1, ""
    for _ in range(5):
        rc, _, err = run(["launchctl", "bootstrap", domain, plist], timeout=20)
        if rc == 0:
            break
        time.sleep(1)
    return rc, err

SENSOR_LABEL = "com.kekkai.sensor"
SENSOR_PLIST = "/Library/LaunchDaemons/%s.plist" % SENSOR_LABEL
SENSOR_LOG = "/Library/Logs/kekkai-sensor.log"
PKG = Path(__file__).resolve().parent


def code_digest(pkg: Path = PKG) -> str:
    h = hashlib.sha256()
    for p in sorted(pkg.rglob("*.py")):
        if "__pycache__" not in p.parts:
            h.update(str(p.relative_to(pkg)).encode() + b"\0" + p.read_bytes())
    return h.hexdigest()[:16]


def daemon_python() -> str:
    return "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def sensor_plist(python: str, code: Path) -> Dict[str, Any]:
    boot = "import sys; sys.path.insert(0, %r); from kekkai.cli import main; sys.exit(main(['sensor']))" % str(code)
    return {"Label": SENSOR_LABEL, "ProgramArguments": [python, "-I", "-B", "-c", boot], "WorkingDirectory": "/",
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 30,
            "StandardOutPath": SENSOR_LOG, "StandardErrorPath": SENSOR_LOG}


def status() -> Dict[str, Any]:
    d = state_dir()
    beat = d / "heartbeat"
    try:
        age = time.time() - beat.stat().st_mtime
    except OSError:
        age = None
    try:
        installed_digest = (d / "code" / "DIGEST").read_text().strip()
    except OSError:
        installed_digest = None
    installed = os.path.exists(SENSOR_PLIST)
    return {"installed": installed, "running": age is not None and age < 30, "beat_age": age,
            "outdated": bool(installed and installed_digest and installed_digest != code_digest())}


def _copy_code(dest: Path) -> None:
    tmp = dest.with_name(dest.name + ".new")
    shutil.rmtree(str(tmp), ignore_errors=True)
    for src in sorted(PKG.rglob("*.py")):
        if "__pycache__" in src.parts:
            continue
        out = tmp / "kekkai" / src.relative_to(PKG)
        out.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(str(src), str(out))
        os.chmod(str(out), 0o644)
    (tmp / "DIGEST").write_text(code_digest() + "\n")
    shutil.rmtree(str(dest), ignore_errors=True)
    os.rename(str(tmp), str(dest))


def install_sensor() -> int:
    if not IS_MACOS:
        print("macOS専用です（Linuxでは sudo ./kekkai sensor を使ってください）")
        return 2
    if os.geteuid() != 0:
        print("管理者権限が必要です:  sudo ./kekkai install-sensor")
        return 2
    try:
        d = prepare_state_dir()
    except (OSError, RuntimeError) as e:
        print("保存先を準備できません: %s" % e)
        return 1
    _copy_code(d / "code")
    tmp = SENSOR_PLIST + ".new"
    with open(tmp, "wb") as f:
        plistlib.dump(sensor_plist(daemon_python(), d / "code"), f)
    os.chmod(tmp, 0o644)
    os.rename(tmp, SENSOR_PLIST)
    t0 = time.time()
    rc, err = bootstrap("system", SENSOR_PLIST, SENSOR_LABEL)
    if rc != 0:
        print("  launchctl bootstrap に失敗: %s" % (err.strip() or rc))
        return 1
    beat = d / "heartbeat"
    while time.time() - t0 < 30:
        if beat.exists() and beat.stat().st_mtime >= t0 - 1:
            print("  パケットセンサーを常時監視に登録しました（起動時に自動で開始・停止しても自動で再開）")
            print("  ログ: %s   解除: sudo ./kekkai uninstall-sensor" % SENSOR_LOG)
            return 0
        time.sleep(0.5)
    print("  センサーが30秒以内に動き出しませんでした。ログを確認してください: %s" % SENSOR_LOG)
    try:
        with open(SENSOR_LOG, "r", encoding="utf-8", errors="replace") as f:
            print("".join(f.readlines()[-10:]))
    except OSError:
        pass
    return 1


def uninstall_sensor() -> int:
    if not IS_MACOS:
        print("macOS専用です")
        return 2
    if os.geteuid() != 0:
        print("管理者権限が必要です:  sudo ./kekkai uninstall-sensor")
        return 2
    run(["launchctl", "bootout", "system/" + SENSOR_LABEL], timeout=20)
    for p in (SENSOR_PLIST, SENSOR_PLIST + ".new"):
        if os.path.exists(p):
            os.unlink(p)
    clean_state_dir(state_dir())
    print("  パケットセンサーの常時監視を解除しました")
    return 0


def clean_state_dir(d: Path) -> None:
    """Remove only what the sensor itself created, then the directory if it is empty."""
    if d.is_symlink():
        return
    if (d / "code" / "DIGEST").exists():
        shutil.rmtree(str(d / "code"), ignore_errors=True)
    # Include the BTM snapshot and rotated spool, but preserve unrelated files
    # (and symlinks) even if the user put them beside the sensor's state.
    owned_files = {"events.jsonl", "events.jsonl.1", "heartbeat", "domains-tif-mini.txt", "btm.json"}
    try:
        with os.scandir(str(d)) as it:
            for entry in it:
                if entry.name in owned_files and entry.is_file(follow_symlinks=False):
                    try:
                        os.unlink(entry.path)
                    except OSError:
                        pass
    except OSError:
        pass
    try:
        d.rmdir()
    except OSError:
        pass
