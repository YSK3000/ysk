"""Minimal Linux posture checks (KEKKAI targets macOS; Linux is for testing and servers)."""
from __future__ import annotations

import os
from typing import Any, Dict, List

from kekkai.audit import check
from kekkai.util import find_cmd, run


def linux_checks(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if find_cmd("ufw"):
        rc, o, _ = run(["ufw", "status"], timeout=10)
        active = "Status: active" in o
        out.append(check("firewall", "ファイアウォール(ufw)", "pass" if active else "warn" if rc == 0 else "unknown",
                         "有効" if active else "無効または権限不足", "sudo ufw enable" if not active else "", "network", 10))
    else:
        out.append(check("firewall", "ファイアウォール", "unknown", "ufw が見つかりません（nftables/iptables は root で確認）",
                         "", "network", 10))
    auto = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades") or os.path.exists("/etc/dnf/automatic.conf")
    out.append(check("autoupdate", "自動アップデート", "pass" if auto else "warn",
                     "自動更新の設定あり" if auto else "自動更新の設定が見つかりません",
                     "unattended-upgrades / dnf-automatic を設定。" if not auto else "", "update", 8))
    rc, o, _ = run(["uname", "-sr"], timeout=5)
    out.append(check("kernel", "カーネル", "info", o.strip() or "?", "", "update", 1))
    return out
