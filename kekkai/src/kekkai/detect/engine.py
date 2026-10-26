"""Detection engine: compares each snapshot with per-network baselines and raises alerts.

Rules are deliberately conservative and explain likely benign causes, because a monitor
that cries wolf gets switched off.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from kekkai.audit import classify_resolver
from kekkai.netutil import is_public

SENSITIVE_PORTS = {21: "FTP", 22: "SSH(リモートログイン)", 23: "Telnet", 445: "SMB(ファイル共有)", 548: "AFP",
                   3283: "Apple Remote Desktop", 3389: "RDP", 5900: "画面共有(VNC)", 5555: "ADB", 2375: "Docker API",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 1080: "SOCKSプロキシ", 3306: "MySQL",
                   5432: "PostgreSQL", 8080: "HTTPプロキシ/管理画面"}

SUSPICIOUS_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/dev/shm/",
                   "/Volumes/")
_TEMP_RE = re.compile(r"^/private/var/folders/[^/]+/[^/]+/T/|/Downloads/|/\.[^/]+/")

# Rules that stay quiet while a network's baseline is being learned.
LEARNING_SILENT = {"lan.new_device", "host.new_listener", "host.persistence_new", "host.dns_changed",
                   "host.proxy_enabled", "exposure.upnp_new"}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    advice: str = ""
    subject: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


TOR_PATHS = ("/opt/homebrew/bin/tor", "/opt/homebrew/Cellar/tor/", "/usr/local/bin/tor", "/usr/local/Cellar/tor/",
             "/Applications/Tor Browser.app/")


def own_tor(c: Dict[str, Any]) -> bool:
    path = c.get("path") or ""
    return (c.get("process") or "") in ("tor", "firefox", "Tor Browser") and path.startswith(TOR_PATHS)


def suspicious_path(path: Optional[str]) -> bool:
    if not path:
        return False
    return path.startswith(SUSPICIOUS_DIRS) or bool(_TEMP_RE.search(path))


def is_exposed_addr(laddr: str) -> bool:
    return laddr in ("*", "0.0.0.0", "::") or not (laddr.startswith("127.") or laddr == "::1")


# ------------------------------------------------------------------ connection rules

def connection_findings(conns: List[Dict[str, Any]], suspicious_ports: Set[int],
                        signature: Any = None) -> List[Finding]:
    """conns are enriched dicts produced by monitor.enrich_connections()."""
    out: List[Finding] = []
    for c in conns:
        raddr = c.get("raddr")
        if not raddr or not is_public(raddr):
            continue
        who = "%s (PID %s)" % (c.get("process") or "不明なプロセス", c.get("pid") or "?")
        where = _where(c.get("geo") or {})
        threats = c.get("threats") or []
        inbound = c.get("direction") == "in"
        for t in threats:
            if t["kind"] == "tor-exit":
                sev = "medium" if inbound else "low"
                if not inbound and own_tor(c):
                    sev = "info"  # the user's own tor / Tor Browser; kept as a record, since its path is user-writable
                out.append(Finding(
                    "conn.tor", sev, "Tor出口ノードとの通信" + ("（外部からの接続）" if inbound else ""),
                    "%s が %s:%s（%s）と通信しています。" % (who, raddr, c.get("rport"), where),
                    "Torを使っていないのに外部から接続されている場合は、公開しているサービス（ポート %s）を見直してください。" % c.get("lport")
                    if inbound else "Tor Browser等を使っていなければ、どのアプリの通信か確認してください。",
                    subject="%s:%s" % (raddr, c.get("process")), data=_cdata(c)))
                continue
            out.append(Finding(
                "conn.threat_feed", t["severity"],
                "脅威リスト掲載IPとの通信: %s" % raddr,
                "%s が %s:%s（%s）と%s中。掲載リスト: %s" % (who, raddr, c.get("rport"), where,
                                                    "通信（外部から接続）" if inbound else "通信", t["label"]),
                "1) そのアプリに心当たりがあるか確認 2) なければネットワークから切断し、アプリを終了・削除 "
                "3) ブラウザ/アカウントのパスワード変更と2段階認証 4) AI解説で詳細確認。誤検知(共有IP/CDN)もあり得ます。",
                subject="%s:%s" % (raddr, c.get("process")), data=_cdata(c)))
            break
        rport = c.get("rport") or 0
        if not inbound and rport in suspicious_ports and c.get("proto") == "tcp":
            out.append(Finding(
                "conn.suspicious_port", "medium", "要注意ポートへの外部通信: %s/%s" % (rport, c.get("proto")),
                "%s が %s:%s（%s）へ接続。マルウェアの遠隔操作やボットネットで使われやすいポートです。" % (who, raddr, rport, where),
                "使用中のアプリ（チャット/ゲーム/リモートデスクトップ等）による正当な通信か確認してください。",
                subject="%s:%s:%s" % (raddr, rport, c.get("process")), data=_cdata(c)))
        path = c.get("path")
        if path and suspicious_path(path):
            out.append(Finding(
                "conn.suspicious_binary", "high", "一時フォルダ等から起動したプロセスが外部通信",
                "%s（%s）が %s:%s（%s）と通信。マルウェアが好む場所から実行されています。" % (who, path, raddr, rport, where),
                "心当たりがなければプロセスを終了し、ファイルの出どころを確認・削除。KnockKnock/BlockBlock等でも確認を。",
                subject=path, data=_cdata(c)))
        sig = c.get("signature")
        if sig and sig.get("checked") and not sig.get("signed"):
            out.append(Finding(
                "conn.unsigned_binary", "medium", "未署名のプログラムが外部通信: %s" % (c.get("process") or "?"),
                "%s（%s）はコード署名がありません。宛先: %s:%s（%s）" % (who, path, raddr, rport, where),
                "自分で入れた開発ツール等なら問題ありません。心当たりがなければ終了して調査してください。",
                subject=path or "", data=_cdata(c)))
    return out


def _where(g: Dict[str, Any]) -> str:
    parts = [g.get("country_ja") or g.get("country_name") or g.get("country"), g.get("city"), g.get("org")]
    return " / ".join(p for p in parts if p) or "所在地不明"


def _cdata(c: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("proto", "laddr", "lport", "raddr", "rport", "state", "pid", "process", "path", "direction", "geo", "threats")
    return {k: c.get(k) for k in keys}


# ------------------------------------------------------------------ LAN rules

def arp_findings(neighbors: List[Dict[str, Any]], gateway_ip: Optional[str], prev_gateway_mac: Optional[str],
                 gateway_mac: Optional[str]) -> List[Finding]:
    out: List[Finding] = []
    by_mac: Dict[str, List[str]] = {}
    for n in neighbors:
        if n.get("mac"):
            by_mac.setdefault(n["mac"], []).append(n["ip"])
    if gateway_ip and gateway_mac:
        sharers = [ip for ip in by_mac.get(gateway_mac, []) if ip != gateway_ip]
        changed = bool(prev_gateway_mac and prev_gateway_mac != gateway_mac)
        if sharers or changed:
            sev = "critical" if (sharers and changed) else "high"
            detail = []
            if changed:
                detail.append("ルーター(%s)のMACアドレスが %s → %s に変わりました。" % (gateway_ip, prev_gateway_mac, gateway_mac))
            if sharers:
                detail.append("ルーターと同じMAC(%s)を %s も名乗っています。" % (gateway_mac, "、".join(sharers)))
            out.append(Finding(
                "lan.arp_spoof", sev, "ARPスプーフィング（中間者攻撃）の疑い",
                " ".join(detail) + " 誰かがルーターになりすまして通信を盗み見ている可能性があります。",
                "1) すぐにWi-Fiを切断（重要な操作は中止）2) ルーターを再起動 3) 再接続後も続く場合はWi-Fiパスワード変更"
                "（WPA2/WPA3）と接続機器の確認。ルーター交換・中継機の追加直後なら誤検知の可能性があります。",
                subject=gateway_ip, data={"gateway": gateway_ip, "mac": gateway_mac, "previous": prev_gateway_mac,
                                          "sharing_ips": sharers}))
    for mac, ips in by_mac.items():
        if len(ips) > 1 and mac != gateway_mac:
            out.append(Finding(
                "lan.duplicate_mac", "low", "同じMACアドレスが複数のIPを使用",
                "%s が %s を使っています。" % (mac, "、".join(sorted(ips))),
                "Wi-Fi中継機（MAC変換）やIPの再割当てでよく起きます。中継機がない環境で続く場合は要調査。",
                subject=mac, data={"mac": mac, "ips": ips}))
    return out


def new_device_finding(dev: Dict[str, Any]) -> Finding:
    from kekkai.discovery.lan import KIND_LABELS
    rnd = dev.get("randomized")
    sev = "low" if rnd else "medium"
    if dev.get("kind") in ("camera", "iot", "unknown") and not rnd:
        sev = "medium"
    name = dev.get("hostname") or dev.get("vendor") or ("ランダム化MAC（スマホ等）" if rnd else "名称不明")
    return Finding(
        "lan.new_device", sev, "新しい機器がネットワークに参加: %s" % name,
        "IP %s / MAC %s / メーカー: %s / 種別: %s%s" % (
            dev.get("ip"), dev.get("mac"), dev.get("vendor") or "不明", KIND_LABELS.get(dev.get("kind") or "unknown", "?"),
            "（MACランダム化: iPhone/Androidのプライベートアドレスの可能性）" if rnd else ""),
        "家族の機器なら LANマップ で「信頼する」に。心当たりがない場合はルーターの管理画面で接続を拒否し、Wi-Fiパスワードを変更してください。",
        subject=dev.get("mac") or "", data={"device": dev})


def risky_service_findings(dev: Dict[str, Any], scan: Dict[str, Any]) -> List[Finding]:
    out = []
    bad = [p for p in scan.get("open", []) if p.get("risk") in ("high", "critical")]
    for p in bad:
        out.append(Finding(
            "lan.risky_service", p["risk"],
            "危険なサービスが開いています: %s %s/%s" % (dev.get("hostname") or dev.get("ip"), p["port"], p.get("service")),
            "%s（%s, %s）: %s" % (dev.get("ip"), dev.get("vendor") or "メーカー不明", p.get("banner") or "バナーなし", p.get("note")),
            "機器の設定で該当機能を無効化し、ファームウェアを更新。初期パスワードのままなら必ず変更してください。",
            subject="%s:%s" % (dev.get("mac") or dev.get("ip"), p["port"]), data={"device": dev, "port": p}))
    return out


# ------------------------------------------------------------------ host rules

def listener_key(item: Dict[str, Any]) -> str:
    return "%s:%s" % (item["proto"], item["port"])


def listener_findings(listeners: List[Dict[str, Any]], baseline: Set[str], untrusted_network: bool) -> List[Finding]:
    out = []
    for item in listeners:
        if item["proto"] != "tcp" or not item.get("exposed"):
            continue
        key = listener_key(item)
        port = item["port"]
        sens = SENSITIVE_PORTS.get(port)
        if key not in baseline:
            sev = "high" if sens else ("low" if port >= 49152 else "medium")
            out.append(Finding(
                "host.new_listener", sev, "新しい待ち受けポート: %s/%d" % (item["proto"], port),
                "%s（%s）がLAN/外部から接続可能な状態でポート %d を開きました。%s" % (
                    item.get("process") or "不明なプロセス", item.get("path") or "パス不明", port, ("種類: " + sens) if sens else ""),
                "自分で有効にした機能（共有・開発サーバー等）か確認。不要ならアプリ/共有設定をオフに。",
                subject=key, data=item))
        elif sens and untrusted_network:
            out.append(Finding(
                "host.exposed_on_untrusted", "medium", "外出先ネットワークで %s が公開中" % sens,
                "このネットワークは未登録（自宅以外）です。同じWi-Fiの他人から %s に接続を試みられる可能性があります。" % sens,
                "外出先では システム設定 > 一般 > 共有 の該当機能をオフにするか、ファイアウォールで遮断してください。",
                subject=key, data=item))
    return out


def dns_findings(current: List[str], baseline: List[str]) -> List[Finding]:
    new = [s for s in current if s not in baseline]
    if not new or not baseline:
        return []
    cls = [classify_resolver(s) for s in new]
    unknown = [c for c in cls if c["kind"] in ("public-other", "invalid")]
    sev = "high" if unknown else "low"
    return [Finding(
        "host.dns_changed", sev, "DNSサーバーの設定が変わりました",
        "以前: %s → 現在: %s（%s）" % (", ".join(baseline), ", ".join(current),
                                   " / ".join("%s=%s" % (c["server"], c.get("name")) for c in cls)),
        "自分で変更していない場合、DNSハイジャック（偽サイトへの誘導）の可能性があります。ネットワーク設定のDNSを確認し、"
        "ルーターの管理画面のDNS設定と管理者パスワードも確認してください。VPN接続の開始でも変わることがあります。",
        subject=",".join(sorted(current)), data={"before": baseline, "after": current, "classified": cls})]


def proxy_findings(current: Dict[str, Any], baseline: Dict[str, Any]) -> List[Finding]:
    if not current or current == baseline:
        return []
    return [Finding(
        "host.proxy_enabled", "high", "プロキシ設定が有効になりました",
        "現在の設定: %s" % ", ".join("%s=%s" % kv for kv in current.items()),
        "アドウェア/マルウェアが通信を盗み見る典型的な手口です。会社のVPN/セキュリティソフトの設定でなければ、"
        "システム設定 > ネットワーク > 詳細 > プロキシ をオフにし、不審な構成プロファイルがないか確認してください。",
        subject=",".join(sorted(current)), data={"proxies": current, "before": baseline})]


def persistence_flag(item: Dict[str, Any]) -> Optional[str]:
    prog = item.get("program")
    sig = item.get("signature") or {}
    if prog and suspicious_path(prog):
        return "suspicious-path"
    if prog and prog.startswith("/") and item.get("exists") is False:
        return "missing-binary"
    if sig.get("checked") and not sig.get("signed"):
        return "unsigned"
    return None


def persistence_findings(items: List[Dict[str, Any]], baseline: Dict[str, float]) -> List[Finding]:
    out = []
    for it in items:
        path = it["plist"]
        if it.get("label") == "com.kekkai.monitor":
            continue  # our own auto-start agent (kekkai install-agent)
        prev = baseline.get(path)
        if prev is not None and (it.get("mtime") or 0) <= prev + 1:
            continue
        flag = persistence_flag(it)
        sig = it.get("signature") or {}
        if flag == "suspicious-path":
            sev = "high"
        elif flag == "unsigned":
            sev = "medium"
        elif flag == "missing-binary" or sig.get("apple") or sig.get("team"):
            sev = "low"
        else:
            sev = "medium"
        out.append(Finding(
            "host.persistence_new", sev, ("自動起動項目が追加されました" if prev is None else "自動起動項目が変更されました") +
            ": %s" % (it.get("label") or os.path.basename(path)),
            "%s → 実行ファイル: %s（署名: %s）" % (path, it.get("program") or "不明", sig.get("summary") or "未確認"),
            "最近インストールしたアプリによるものか確認。心当たりがなければファイルの内容と配置元を確認し、不要なら削除してください。",
            subject=path, data=it))
    return out


def btm_key(it: Dict[str, Any]) -> str:
    return "%s|%s|%s" % (it.get("uid"), it.get("identifier") or it.get("name") or "", it.get("executable") or "")


def claims_apple(it: Dict[str, Any]) -> bool:
    ident = (it.get("identifier") or "").lower()
    return ident.startswith("com.apple.") and it.get("apple") is False


def btm_findings(items: List[Dict[str, Any]], baseline: List[str]) -> List[Finding]:
    """New login/background items (sfltool dumpbtm). Masquerading as Apple, hidden/unsigned paths score highest."""
    known = set(baseline)
    out = []
    for it in items:
        key = btm_key(it)
        if key in known or (it.get("identifier") or "") == "16.com.kekkai.sensor":
            continue
        exe = it.get("executable")
        name = it.get("name") or it.get("identifier") or "名称不明"
        if claims_apple(it):
            sev, why = "high", "Apple純正を装っていますが、Appleの署名がありません"
        elif exe and suspicious_path(exe):
            sev, why = "high", "隠しフォルダ/一時領域から実行されます"
        elif exe and it.get("signed") is False:
            sev, why = "medium", "署名がありません"
        elif it.get("missing"):
            sev, why = "low", "実行ファイルが見つかりません"
        elif it.get("apple") or it.get("team"):
            sev, why = "low", "署名あり（通常のアプリの可能性が高い）"
        else:
            sev, why = "medium", "提供元を確認できません"
        out.append(Finding(
            "host.login_item_new", sev, "ログイン/常駐項目が追加: %s" % name,
            "%s（%s / 提供元: %s）が自動起動に登録されています。%s。実行ファイル: %s（出典: macOS Background Task Management、"
            "MITRE ATT&CK T1547.015）" % (name, it.get("type") or "種別不明", it.get("developer") or it.get("team") or "不明",
                                       why, exe or it.get("url") or "不明"),
            "最近入れたアプリによるものか確認。心当たりがなければ システム設定 > 一般 > ログイン項目とスキップ で無効化・削除し、"
            "実行ファイルの配置元を確認してください。",
            subject=key, data=it))
    return out


def wifi_findings(wifi: Optional[Dict[str, Any]]) -> List[Finding]:
    if not wifi:
        return []
    out = []
    sec = (wifi.get("security") or "").upper()
    if sec.startswith(("OPEN", "WEP")):
        out.append(Finding(
            "wifi.insecure", "high" if sec.startswith("WEP") else "medium", "暗号化が弱い/ないWi-Fiに接続中（%s）" % sec,
            "SSID: %s。同じWi-Fiにいる人に通信を盗み見られる可能性があります。" % (wifi.get("ssid") or "非公開"),
            "自宅ならルーターをWPA2/WPA3に設定。外出先ではVPNを使うか、スマホのテザリングを利用してください。",
            subject=wifi.get("ssid") or "?", data=wifi))
    elif sec == "WPA":
        out.append(Finding("wifi.insecure", "medium", "古い暗号化方式(WPA/TKIP)のWi-Fi",
                           "WPA(TKIP)は既に破られています。", "ルーターの設定をWPA2-AES以上に変更してください。",
                           subject=wifi.get("ssid") or "?", data=wifi))
    ssid = wifi.get("ssid")
    if ssid and not str(ssid).startswith("<"):
        twins = [n for n in wifi.get("nearby") or [] if n.get("ssid") == ssid and (n.get("security") or "").startswith("OPEN")]
        if twins and not sec.startswith("OPEN"):
            out.append(Finding(
                "wifi.evil_twin", "medium", "同名の暗号化なしWi-Fiが近くにあります（なりすましの疑い）",
                "接続中の「%s」と同じ名前で暗号化なしのアクセスポイントが見えています。" % ssid,
                "自動接続先にならないよう注意し、Wi-Fi設定で接続先の暗号化表示を確認してください。",
                subject=ssid, data={"twins": twins}))
    return out


def sensor_finding(ev: Dict[str, Any]) -> Optional[Finding]:
    kind = ev.get("kind")
    if kind == "port_scan":
        return Finding("sensor.port_scan", "high", "このMacへのポートスキャンを検知: %s" % ev.get("src"),
                       "%s 秒間に %s 個のポートへ接続試行がありました（例: %s）。" % (
                           ev.get("window"), ev.get("ports"), ", ".join(str(p) for p in (ev.get("sample") or [])[:10])),
                       "LAN内の機器なら、その機器が乗っ取られている可能性があります。不明な機器ならWi-Fiパスワードを変更してください。",
                       subject=str(ev.get("src")), data=ev)
    if kind == "arp_sweep":
        return Finding("sensor.arp_sweep", "high", "LAN内の偵察（ARPスキャン）を検知: %s" % ev.get("mac"),
                       "%s（%s）が %s 秒間に %s 台のIPを探索しました。" % (ev.get("mac"), ev.get("src"), ev.get("window"),
                                                                ev.get("targets")),
                       "ネットワーク管理ツール以外なら、侵入者や感染機器による偵察の可能性があります。機器を特定してください。",
                       subject=str(ev.get("mac")), data=ev)
    if kind == "arp_spoof":
        return Finding("sensor.arp_spoof", "critical", "ARP応答の偽装を検知（ルーターなりすまし）",
                       "ルーター %s を %s が名乗るARP応答を観測しました（本来: %s）。" % (ev.get("ip"), ev.get("mac"), ev.get("expected")),
                       "直ちにWi-Fiを切断し、ルーター再起動とWi-Fiパスワード変更を。", subject=str(ev.get("ip")), data=ev)
    if kind == "dns_threat":
        return Finding("sensor.dns_threat", "high", "危険なドメインへの名前解決: %s" % ev.get("domain"),
                       "%s が %s を問い合わせました（リスト: %s）。" % (ev.get("src"), ev.get("domain"), ev.get("list")),
                       "どの機器/アプリの通信か確認してください。フィッシングやマルウェア配布サイトの可能性があります。",
                       subject=str(ev.get("domain")), data=ev)
    return None


def sensor_conn_finding(ev: Dict[str, Any], threats: List[Dict[str, Any]], geo: Dict[str, Any]) -> Optional[Finding]:
    """An outbound connection seen by the packet sensor (incl. ones too short for the 15 s poll) to a listed IP."""
    if not threats:
        return None
    t = threats[0]  # FeedSet.match returns the most severe listing first
    where = " / ".join(x for x in (geo.get("country_ja") or geo.get("country"), geo.get("org")) if x) or "場所不明"
    return Finding("sensor.threat_conn", t["severity"], "脅威リスト掲載IPへの接続（パケットで検知）: %s" % ev.get("dst"),
                   "このMacが %s:%s（%s）へ接続を開始しました。掲載リスト: %s。通信一覧に出ないほど短い接続だったため、"
                   "どのアプリかは特定できていません。" % (ev.get("dst"), ev.get("dport"), where, t["label"]),
                   "同じ接続が繰り返すか「通信」画面とアラートを確認してください。心当たりがなければ、最近入れたアプリや"
                   "自動起動項目を確認し、LuLu等で接続先をブロックしてください。誤検知（共有IP/CDN）もあり得ます。",
                   subject=str(ev.get("dst")), data=ev)


UPDATE_ADVICE = "システム設定 > 一般 > ソフトウェアアップデート から今すぐ更新してください（自動アップデートもオンに）。"


def macos_vuln_findings(st: Optional[Dict[str, Any]], stale_days: int = 400) -> List[Finding]:
    """Unpatched, publicly known macOS vulnerabilities for this exact version (SOFA + CISA KEV)."""
    if not st or st.get("unknown_line"):
        return []
    days = st.get("days_since_security_release")
    if days is not None and days > stale_days and st.get("newer_major"):
        return [Finding("host.macos_unsupported", "high", "このmacOS（%s）はセキュリティ更新が止まっている可能性" % st["line"],
                        "%s %s には %d 日間セキュリティ更新が出ていません。Appleは新しい脆弱性を古いmacOSでは直さないことがあります。"
                        "（出典: Apple のセキュリティアップデート情報 https://support.apple.com/ja-jp/100100 、SOFA）" % (
                            st["line"], st["version"], days),
                        "対応する新しいmacOSへアップグレードしてください（Macが対応していなければ、買い替えも検討）。",
                        subject="macos-%s" % st["line"], data=st)]
    if not st.get("cves"):
        return []
    exploited = st.get("exploited") or []
    detail = "macOS %s → 最新 %s。未修正の既知の脆弱性 %d 件（%s で修正済み）。" % (
        st["version"], st.get("latest"), st["cves"], "、".join(st.get("missing_releases") or []))
    if exploited:
        detail += "うち %d 件は実際の攻撃で悪用が確認されています: %s。" % (len(exploited), ", ".join(exploited[:8]))
    detail += "（出典: Apple のセキュリティアップデート情報 https://support.apple.com/ja-jp/100100 、CISA KEV、SOFA）"
    return [Finding("host.macos_vulns", "high" if exploited else "medium",
                    "macOSに未修正の脆弱性: %d 件%s" % (st["cves"], "（うち悪用確認 %d 件）" % len(exploited) if exploited else ""),
                    detail, UPDATE_ADVICE, subject="macos-%s" % st["version"], data=st)]


def kev_label(k: Dict[str, Any]) -> str:
    return "%s（%s）" % (k["cveID"], k.get("vulnerabilityName") or k.get("product") or "")


def device_vuln_findings(dev: Dict[str, Any], hits: Dict[str, List[Dict[str, Any]]]) -> List[Finding]:
    name = dev.get("hostname") or dev.get("model") or dev.get("vendor") or dev.get("ip")
    if hits.get("model"):
        ks = hits["model"]
        return [Finding("lan.kev_model", "high", "機器の型番に、悪用が確認された脆弱性: %s" % name,
                        "%s（%s / %s）の型番が、CISA KEV（実際の攻撃で悪用された脆弱性の一覧）の対象製品と一致しました: %s" % (
                            name, dev.get("vendor") or "?", dev.get("ip"), "、".join(kev_label(k) for k in ks[:5])),
                        "1) メーカーサイトで最新ファームウェアを確認して更新 2) 更新が終了した機種なら買い替え "
                        "3) それまでは外部公開（ポート開放・UPnP）をやめる。型番の表記違いによる誤一致もあり得ます。",
                        subject="%s|kev-model" % dev.get("mac"), data={"cves": [k["cveID"] for k in ks], "ip": dev.get("ip")})]
    if hits.get("vendor"):
        ks = hits["vendor"]
        return [Finding("lan.kev_vendor", "low", "メーカー製品に悪用確認済みの脆弱性あり（型番は要確認）: %s" % name,
                        "%s 製品には CISA KEV 掲載の脆弱性が %d 件あります（例: %s）。この機器の型番が該当するかは確認できていません。" % (
                            dev.get("vendor"), len(ks), "、".join(kev_label(k) for k in ks[:3])),
                        "機器の型番とファームウェアのバージョンを確認し、メーカーの最新版に更新してください。",
                        subject="%s|kev-vendor" % dev.get("mac"), data={"cves": [k["cveID"] for k in ks][:50], "ip": dev.get("ip")})]
    return []


def exposure_kev_findings(public_ip: Optional[str], kev_hits: List[Dict[str, Any]]) -> List[Finding]:
    if not kev_hits:
        return []
    return [Finding("exposure.kev", "high", "インターネットから見える自宅の機器に、悪用確認済みの脆弱性",
                    "公開IP %s について Shodan が関連付けたCVEのうち、%d 件が CISA KEV（実際の攻撃で悪用）に掲載: %s。"
                    "Shodanはバナー等からの推定なので、機器の特定と確認が必要です。" % (
                        public_ip, len(kev_hits), "、".join(kev_label(k) for k in kev_hits[:5])),
                    "1) ルーターや公開している機器のファームウェアを更新 2) 不要なポート開放・UPnPをやめる 3) 「外部公開」画面で確認。",
                    subject="%s|kev" % public_ip, data={"cves": [k["cveID"] for k in kev_hits]})]


def threat_level(counts: Dict[str, int]) -> Tuple[int, str]:
    if counts.get("critical"):
        return 5, "CRITICAL"
    if counts.get("high"):
        return 4, "HIGH"
    if counts.get("medium"):
        return 3, "ELEVATED"
    if counts.get("low"):
        return 2, "GUARDED"
    return 1, "SECURE"


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        k = (f.rule, f.subject)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
