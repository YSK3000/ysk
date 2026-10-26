"""macOS hardening checks. Parsers are pure functions; see tests/fixtures/macos."""
from __future__ import annotations

import os
import plistlib
import re
from typing import Any, Dict, List, Optional

from kekkai.audit import check
from kekkai.util import run

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def parse_firewall_state(text: str) -> Optional[bool]:
    t = text.lower()
    if "state = 1" in t or "state = 2" in t or "firewall is enabled" in t:
        return True
    if "state = 0" in t or "firewall is disabled" in t:
        return False
    return None


def parse_on_off(text: str) -> Optional[bool]:
    t = text.lower()
    if re.search(r"\b(is on|enabled|is enabled)\b", t) and "disabled" not in t:
        return True
    if re.search(r"\b(is off|disabled|is disabled)\b", t):
        return False
    return None


def parse_fdesetup(text: str) -> str:
    t = text.strip()
    if "FileVault is On" in t:
        return "on"
    if "FileVault is Off" in t:
        return "off"
    if "progress" in t.lower():
        return "progress"
    return "unknown"


def parse_csrutil(text: str) -> str:
    t = text.lower()
    if "custom configuration" in t or "unknown" in t:
        return "custom"
    if "status: enabled" in t:
        return "enabled"
    if "status: disabled" in t:
        return "disabled"
    return "unknown"


def parse_softwareupdate(rc: int, out: str, err: str) -> Dict[str, Any]:
    text = out + "\n" + err
    if "No new software available" in text:
        return {"state": "current", "updates": []}
    labels = re.findall(r"^\s*\*\s*Label:\s*(.+)$", text, re.M)
    if not labels:
        labels = [m.strip() for m in re.findall(r"^\s*\*\s+(.+)$", text, re.M)]
    if labels:
        return {"state": "pending", "updates": labels[:10]}
    return {"state": "unknown", "updates": [], "error": text.strip()[-200:]}


def _plist(path: str) -> Dict[str, Any]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - unreadable or missing
        return {}


def macos_checks(snapshot: Dict[str, Any], slow: bool = False) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    rc, o, e = run([SOCKETFILTERFW, "--getglobalstate"], timeout=10)
    fw = parse_firewall_state(o + e) if rc != 127 else None
    out.append(check("firewall", "ファイアウォール", {True: "pass", False: "fail", None: "unknown"}[fw],
                     {True: "オン", False: "オフ", None: "確認できませんでした"}[fw],
                     "システム設定 > ネットワーク > ファイアウォール をオンに。" if fw is not True else "", "network", 10))
    if fw:
        rc, o, e = run([SOCKETFILTERFW, "--getstealthmode"], timeout=10)
        st = parse_on_off(o + e)
        out.append(check("stealth", "ステルスモード", "pass" if st else "warn" if st is False else "unknown",
                         "オン（pingやポート探索に応答しない）" if st else "オフ",
                         "ファイアウォール > オプション > ステルスモードを有効にする をオンに。" if not st else "", "network", 4))

    rc, o, e = run(["fdesetup", "status"], timeout=10)
    fv = parse_fdesetup(o + e)
    out.append(check("filevault", "FileVault（ディスク暗号化）",
                     {"on": "pass", "off": "fail", "progress": "info"}.get(fv, "unknown"),
                     {"on": "オン", "off": "オフ（盗難・紛失時にデータを読まれます）", "progress": "暗号化処理中"}.get(fv, "不明"),
                     "システム設定 > プライバシーとセキュリティ > FileVault をオンに。" if fv == "off" else "", "system", 10))

    rc, o, e = run(["csrutil", "status"], timeout=10)
    sip = parse_csrutil(o + e)
    out.append(check("sip", "SIP（システム整合性保護）",
                     {"enabled": "pass", "disabled": "fail", "custom": "warn"}.get(sip, "unknown"),
                     {"enabled": "有効", "disabled": "無効（root化マルウェアに無防備）", "custom": "一部無効"}.get(sip, "不明"),
                     "リカバリーモードで csrutil enable を実行。" if sip in ("disabled", "custom") else "", "system", 10))

    rc, o, e = run(["spctl", "--status"], timeout=10)
    gk = "enabled" if "assessments enabled" in o + e else "disabled" if "assessments disabled" in o + e else "unknown"
    out.append(check("gatekeeper", "Gatekeeper（未確認アプリの実行防止）",
                     {"enabled": "pass", "disabled": "fail"}.get(gk, "unknown"),
                     {"enabled": "有効", "disabled": "無効"}.get(gk, "不明"),
                     "ターミナルで sudo spctl --master-enable を実行。" if gk == "disabled" else "", "system", 8))

    su = _plist("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    off = [k for k, label in (("CriticalUpdateInstall", "セキュリティ対応"), ("ConfigDataInstall", "システムデータ(XProtect等)"),
                             ("AutomaticCheckEnabled", "アップデートの確認"))
           if su.get(k) is False]
    out.append(check("autoupdate", "自動アップデート設定", "fail" if off else "pass",
                     ("オフになっている項目: " + "、".join(off)) if off else "セキュリティ更新の自動インストールは有効（既定値）",
                     "システム設定 > 一般 > ソフトウェアアップデート > 自動アップデート の(i)ですべてオンに。" if off else "",
                     "update", 9))

    rc, o, _ = run(["sw_vers"], timeout=5)
    ver = dict(re.findall(r"^(\w+):\s*(.+)$", o, re.M))
    if slow:
        rc, o2, e2 = run(["softwareupdate", "--list"], timeout=120)
        su_state = parse_softwareupdate(rc, o2, e2)
        if su_state["state"] == "pending":
            out.append(check("pending_updates", "未適用のアップデート", "warn",
                             "%s %s / 利用可能: %s" % (ver.get("ProductName", "macOS"), ver.get("ProductVersion", ""),
                                                     "、".join(su_state["updates"])),
                             "システム設定 > 一般 > ソフトウェアアップデート から今すぐ適用（最重要の対策です）。", "update", 10))
        elif su_state["state"] == "current":
            out.append(check("pending_updates", "未適用のアップデート", "pass",
                             "%s %s は最新です" % (ver.get("ProductName", "macOS"), ver.get("ProductVersion", "")), "", "update", 10))
        else:
            out.append(check("pending_updates", "未適用のアップデート", "unknown", "確認できませんでした", "", "update", 10))
    else:
        out.append(check("os_version", "macOSバージョン", "info",
                         "%s %s (%s)" % (ver.get("ProductName", "macOS"), ver.get("ProductVersion", "?"), ver.get("BuildVersion", "?")),
                         "「診断を実行（詳細）」で未適用アップデートを確認できます。", "update", 1))

    lw = _plist("/Library/Preferences/com.apple.loginwindow.plist")
    if lw.get("autoLoginUser"):
        out.append(check("autologin", "自動ログイン", "fail", "ユーザー %s で自動ログインが有効" % lw.get("autoLoginUser"),
                         "システム設定 > ユーザとグループ > 自動ログイン をオフに。", "system", 7))
    else:
        out.append(check("autologin", "自動ログイン", "pass", "無効", "", "system", 7))
    if lw.get("GuestEnabled"):
        out.append(check("guest", "ゲストユーザー", "warn", "ゲストユーザーが有効", "システム設定 > ユーザとグループ でゲストをオフに。",
                         "system", 3))

    nat = _plist("/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
    if (nat.get("NAT") or {}).get("Enabled") == 1:
        out.append(check("internet_sharing", "インターネット共有", "warn", "このMacが他の機器にネット接続を共有しています",
                         "不要なら システム設定 > 一般 > 共有 > インターネット共有 をオフに。", "sharing", 5))

    rc, o, e = run(["profiles", "status", "-type", "enrollment"], timeout=10)
    if rc == 0:
        mdm = re.search(r"MDM enrollment:\s*(\w+)", o + e)
        if mdm and mdm.group(1).lower().startswith("yes"):
            out.append(check("mdm", "MDM（遠隔管理）登録", "warn", "このMacはMDMに登録されています",
                             "会社支給でないなら要注意。システム設定 > プライバシーとセキュリティ > プロファイル を確認。", "system", 6))
        elif mdm:
            out.append(check("mdm", "MDM（遠隔管理）登録", "pass", "登録なし", "", "system", 3))

    rc, o, e = run(["tmutil", "destinationinfo"], timeout=15)
    if rc != 127:
        txt = o + e
        if "No destinations configured" in txt:
            out.append(check("backup", "バックアップ（Time Machine）", "warn", "バックアップ先が設定されていません",
                             "ランサムウェア対策として外付けディスク等へのTime Machineを設定（ネットから切り離して保管が理想）。",
                             "system", 6))
        elif "Name" in txt or "Kind" in txt:
            out.append(check("backup", "バックアップ（Time Machine）", "pass", "バックアップ先が設定されています", "", "system", 6))

    rc, o, e = run(["sysadminctl", "-screenLock", "status"], timeout=10)
    t = (o + e).lower()
    if "screenlock is off" in t:
        out.append(check("screenlock", "画面ロック", "fail", "スリープ/スクリーンセーバー後にパスワードを要求しません",
                         "システム設定 > ロック画面 で「パスワードを要求」を「すぐに」に。", "system", 5))
    elif "delay is" in t:
        m = re.search(r"delay is ([^\n.]+)", t)
        out.append(check("screenlock", "画面ロック", "pass", "有効（%s）" % (m.group(1).strip() if m else ""), "", "system", 5))

    gl = _plist(os.path.expanduser("~/Library/Preferences/.GlobalPreferences.plist"))
    if gl.get("LDMGlobalEnabled"):
        out.append(check("lockdown", "ロックダウンモード", "pass", "有効（高度な標的型攻撃への最大防御）", "", "system", 1))
    return out
