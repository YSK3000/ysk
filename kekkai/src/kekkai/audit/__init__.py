"""Security posture audit (Lynis-style hardening checks)."""
from __future__ import annotations

import ipaddress
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from kekkai.netutil import parse_ip

WEIGHTS = {"fail": 0.0, "warn": 0.5, "pass": 1.0}

KNOWN_RESOLVERS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare(マルウェア遮断)", "1.0.0.2": "Cloudflare(マルウェア遮断)",
    "1.1.1.3": "Cloudflare(家族向け)", "1.0.0.3": "Cloudflare(家族向け)", "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google", "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.11": "Quad9",
    "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
}


def classify_resolver(ns: str) -> Dict[str, Any]:
    ip = parse_ip(ns)
    if ip is None:
        return {"server": ns, "kind": "invalid"}
    if ns in KNOWN_RESOLVERS:
        return {"server": ns, "kind": "public-known", "name": KNOWN_RESOLVERS[ns]}
    if ip.is_loopback:
        return {"server": ns, "kind": "local", "name": "このMac内(VPN/フィルタアプリ等)"}
    if ip.is_private or ip.is_link_local:
        return {"server": ns, "kind": "lan", "name": "LAN内(通常はルーター)"}
    if isinstance(ip, ipaddress.IPv4Address) and (str(ip).startswith("45.90.28.") or str(ip).startswith("45.90.30.")):
        return {"server": ns, "kind": "public-known", "name": "NextDNS"}
    return {"server": ns, "kind": "public-other", "name": "プロバイダ等の外部DNS"}


def check(cid: str, title: str, status: str, detail: str, fix: str = "", category: str = "system",
          weight: int = 5) -> Dict[str, Any]:
    return {"id": cid, "title": title, "status": status, "detail": detail, "fix": fix,
            "category": category, "weight": weight}


def common_checks(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Checks that work from collected state on any OS."""
    out: List[Dict[str, Any]] = []
    dns = snapshot.get("dns") or []
    if dns:
        cls = [classify_resolver(s) for s in dns]
        unknown = [c for c in cls if c["kind"] in ("public-other", "invalid")]
        out.append(check("dns", "DNSサーバー", "info" if unknown else "pass",
                         " / ".join("%s（%s）" % (c["server"], c.get("name", "")) for c in cls),
                         "見覚えのない外部DNSが設定されていたらDNSハイジャックの可能性。ネットワーク設定のDNSを確認。"
                         if unknown else "", "network", 6))
    proxies = snapshot.get("proxies") or {}
    if proxies:
        out.append(check("proxy", "プロキシ設定", "warn", "有効: " + ", ".join("%s=%s" % kv for kv in proxies.items()),
                         "心当たりがなければ システム設定 > ネットワーク > (接続) > 詳細 > プロキシ をすべてオフに。"
                         "アドウェアやマルウェアが通信を盗み見るために設定することがあります。", "network", 8))
    else:
        out.append(check("proxy", "プロキシ設定", "pass", "プロキシは設定されていません", "", "network", 4))
    wifi = snapshot.get("wifi")
    if wifi and wifi.get("security"):
        sec = wifi["security"]
        status = {"OPEN": "fail", "WEP": "fail", "WPA": "warn", "OWE": "warn"}.get(sec.split("-")[0].split("/")[0], "pass")
        out.append(check("wifi", "Wi-Fiの暗号化", status, "接続中: %s（%s）" % (wifi.get("ssid") or "SSID非公開", sec),
                         "" if status == "pass" else "ルーターの設定をWPA2/WPA3にする。公衆Wi-FiではVPNを使う。", "network", 10))
    listeners = snapshot.get("listeners") or []
    exposed = [item for item in listeners if item.get("exposed")]
    sens = [item for item in exposed if item.get("sensitive")]
    if sens:
        out.append(check("listeners", "外部から接続できるサービス", "warn",
                         "、".join("%s/%d(%s)" % (item["proto"], item["port"], item.get("process") or "?") for item in sens[:10]),
                         "使っていない共有機能（リモートログイン/画面共有/ファイル共有）はシステム設定 > 一般 > 共有 でオフに。",
                         "sharing", 8))
    else:
        out.append(check("listeners", "外部から接続できるサービス", "pass",
                         "要注意のサービスは待ち受けていません（全%d件）" % len(exposed), "", "sharing", 6))
    persist = snapshot.get("persistence") or []
    flagged = [p for p in persist if p.get("flag")]
    if persist:
        out.append(check("persistence", "自動起動項目（LaunchAgents/Daemons）", "warn" if flagged else "pass",
                         ("要確認 %d件: " % len(flagged) + "、".join(p.get("label") or p["plist"] for p in flagged[:6]))
                         if flagged else "%d件（すべて署名済み/通常の場所）" % len(persist),
                         "見覚えのない項目は配置元のアプリを確認し、不要ならアンインストール。", "persistence", 8))
    return out


def score(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = 0.0
    got = 0.0
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0, "unknown": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
        if c["status"] in WEIGHTS:
            total += c["weight"]
            got += c["weight"] * WEIGHTS[c["status"]]
    return {"score": int(round(100 * got / total)) if total else None, "counts": counts}


def run_audit(snapshot: Dict[str, Any], slow: bool = False,
              progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    t0 = time.time()
    if sys.platform == "darwin":
        from kekkai.audit.macos import macos_checks
        checks = macos_checks(snapshot, slow=slow)
    elif sys.platform.startswith("linux"):
        from kekkai.audit.linux import linux_checks
        checks = linux_checks(snapshot)
    else:
        checks = []
    checks += common_checks(snapshot)
    order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}
    checks.sort(key=lambda c: (order.get(c["status"], 9), -c["weight"]))
    result = {"ts": time.time(), "duration": round(time.time() - t0, 1), "checks": checks}
    result.update(score(checks))
    return result
