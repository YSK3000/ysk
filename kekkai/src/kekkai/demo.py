"""Demo mode: a fictional home network + scripted attack, run through the REAL detection engine.

`./kekkai serve --demo` lets you try the dashboard (or record a screencast) without touching
your network. Every identifier here is fictional; malicious endpoints use documentation
address ranges (RFC 5737), which demo mode temporarily treats as "internet".
"""
from __future__ import annotations

import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from kekkai import netutil
from kekkai.audit import common_checks, score
from kekkai.platforms.base import Connection, LanContext, Neighbor, Platform
from kekkai.store import Store

GW_MAC = "a4:2b:b0:10:00:01"
CAM_MAC = "7c:df:a1:3e:00:37"
ATTACKER_MAC = "7c:df:a1:3e:00:37"   # the compromised camera later impersonates the router

DEVICES = [
    # ip, mac, vendor, hostname, kind, services, model, stage
    ("192.168.10.1", GW_MAC, "NEC Platforms", "aterm", "router", ["_http._tcp"], "Aterm WX5400HP", 0),
    ("192.168.10.24", "9a:4e:2c:11:aa:01", None, "iPhone", "phone", ["_companion-link._tcp"], None, 0),
    ("192.168.10.25", "be:12:76:04:3c:9d", None, "iPad", "phone", ["_companion-link._tcp"], None, 0),
    ("192.168.10.30", "58:d3:49:10:00:30", "Apple", "Living-Room", "media", ["_airplay._tcp", "_raop._tcp"], "AppleTV14,1", 0),
    ("192.168.10.31", "d4:a3:3d:10:00:31", "Apple", "HomePod-mini", "speaker", ["_airplay._tcp", "_raop._tcp"], "AudioAccessory5,1", 0),
    ("192.168.10.40", "64:eb:8c:10:00:40", "Seiko Epson", "EPSON-EW-M754T", "printer", ["_ipp._tcp", "_printer._tcp", "_uscan._tcp"], "EW-M754T", 0),
    ("192.168.10.41", "98:41:5c:10:00:41", "Nintendo", "Switch", "game", [], None, 0),
    ("192.168.10.42", "04:5d:4b:10:00:42", "Sony", "BRAVIA-XR", "tv", ["_googlecast._tcp"], "BRAVIA XR", 0),
    ("192.168.10.43", "44:00:49:10:00:43", "Amazon Technologies", "echo-dot", "speaker", [], None, 0),
    ("192.168.10.44", "10:6f:3f:10:00:44", "BUFFALO", "LS220D", "nas", ["_smb._tcp", "_afpovertcp._tcp"], "LS220D", 0),
    ("192.168.10.50", "c8:c9:a3:10:00:50", "Espressif", "SwitchBot-Hub", "iot", ["_hap._tcp"], None, 0),
    ("192.168.10.55", "00:d8:61:10:00:55", "Micro-Star", "DESKTOP-K2", "computer", ["_smb._tcp"], None, 0),
    ("192.168.10.37", CAM_MAC, "Espressif", "IPC-360", "camera", ["_http._tcp"], "IPC-360 Pro", 1),
]
THIS = ("192.168.10.23", "3c:22:fb:7a:10:23")

CITY = {
    "tokyo": ("JP", "日本", "Tokyo", 35.69, 139.69), "osaka": ("JP", "日本", "Osaka", 34.69, 135.50),
    "sf": ("US", "アメリカ合衆国", "San Francisco", 37.77, -122.42), "cupertino": ("US", "アメリカ合衆国", "Cupertino", 37.32, -122.03),
    "ashburn": ("US", "アメリカ合衆国", "Ashburn", 39.04, -77.49), "seattle": ("US", "アメリカ合衆国", "Seattle", 47.61, -122.33),
    "dublin": ("IE", "アイルランド", "Dublin", 53.35, -6.26), "frankfurt": ("DE", "ドイツ", "Frankfurt am Main", 50.11, 8.68),
    "amsterdam": ("NL", "オランダ", "Amsterdam", 52.37, 4.90), "london": ("GB", "イギリス", "London", 51.51, -0.13),
    "singapore": ("SG", "シンガポール", "Singapore", 1.35, 103.82), "sydney": ("AU", "オーストラリア", "Sydney", -33.87, 151.21),
    "seoul": ("KR", "大韓民国", "Seoul", 37.57, 126.98), "saopaulo": ("BR", "ブラジル", "São Paulo", -23.55, -46.63),
    "stockholm": ("SE", "スウェーデン", "Stockholm", 59.33, 18.07), "toronto": ("CA", "カナダ", "Toronto", 43.65, -79.38),
}

# process, path, remote ip, port, proto, city, asn, org
FLOWS = [
    ("Safari", "/Applications/Safari.app/Contents/MacOS/Safari", "17.253.144.10", 443, "tcp", "cupertino", 714, "Apple Inc."),
    ("Safari", "/Applications/Safari.app/Contents/MacOS/Safari", "23.211.8.70", 443, "tcp", "tokyo", 20940, "Akamai International B.V."),
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "142.250.196.110", 443, "udp", "tokyo", 15169, "Google LLC"),
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "104.16.132.229", 443, "tcp", "sydney", 13335, "Cloudflare, Inc."),
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "151.101.1.140", 443, "tcp", "osaka", 54113, "Fastly, Inc."),
    ("identityservicesd", "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd",
     "17.57.146.20", 5223, "tcp", "cupertino", 714, "Apple Inc."),
    ("LINE", "/Applications/LINE.app/Contents/MacOS/LINE", "147.92.150.193", 443, "tcp", "tokyo", 38631, "LINE Corporation"),
    ("Slack", "/Applications/Slack.app/Contents/MacOS/Slack", "54.230.107.11", 443, "tcp", "tokyo", 16509, "Amazon.com, Inc."),
    ("Spotify", "/Applications/Spotify.app/Contents/MacOS/Spotify", "35.186.224.25", 443, "tcp", "stockholm", 15169, "Google LLC"),
    ("zoom.us", "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "170.114.52.2", 443, "tcp", "seattle", 30103, "Zoom Communications, Inc."),
    ("Claude", "/Applications/Claude.app/Contents/MacOS/Claude", "160.79.104.10", 443, "tcp", "sf", 399358, "Anthropic, PBC"),
    ("git-remote-https", "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-https", "140.82.112.4", 443, "tcp",
     "ashburn", 36459, "GitHub, Inc."),
    ("Microsoft Teams", "/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams", "52.112.95.20", 443, "tcp", "dublin", 8075, "Microsoft Corporation"),
    ("Dropbox", "/Applications/Dropbox.app/Contents/MacOS/Dropbox", "162.125.80.18", 443, "tcp", "frankfurt", 19679, "Dropbox, Inc."),
    ("Discord", "/Applications/Discord.app/Contents/MacOS/Discord", "162.159.135.232", 443, "tcp", "london", 13335, "Cloudflare, Inc."),
    ("Steam Helper", "/Users/demo/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steamwebhelper",
     "23.62.226.90", 443, "tcp", "singapore", 20940, "Akamai International B.V."),
    ("KakaoTalk", "/Applications/KakaoTalk.app/Contents/MacOS/KakaoTalk", "211.249.220.24", 443, "tcp", "seoul", 10049, "Kakao Corp"),
    ("Notion", "/Applications/Notion.app/Contents/MacOS/Notion", "208.103.161.1", 443, "tcp", "toronto", 13335, "Cloudflare, Inc."),
    ("ssh", "/usr/bin/ssh", "52.69.186.44", 22, "tcp", "tokyo", 16509, "Amazon.com, Inc."),
    ("python3.12", "/opt/homebrew/Cellar/python@3.12/3.12.7/Frameworks/Python.framework/Versions/3.12/bin/python3.12",
     "151.101.0.223", 443, "tcp", "tokyo", 54113, "Fastly, Inc."),
    ("Netflix", "/Applications/Netflix.app/Contents/MacOS/Netflix", "45.57.91.1", 443, "tcp", "saopaulo", 2906, "Netflix Streaming Services Inc."),
]
C2 = ("sysmond", "/Users/Shared/.sysmond/sysmond", "203.0.113.66", 4444, "tcp")
C2_GEO = {"country": "NL", "country_name": "Netherlands", "country_ja": "オランダ", "city": "Amsterdam（架空）", "lat": 52.37,
          "lon": 4.90, "asn": 64512, "org": "DEMO Bulletproof Hosting（架空）"}

BOOT = time.time()

SIGS = {
    "/Users/Shared/.sysmond/sysmond": {"checked": True, "signed": False, "adhoc": False, "apple": False, "team": None,
                                       "authority": [], "summary": "unsigned"},
}


class DemoGeo:
    available = {"city": True, "asn": True, "city_build": time.time() - 86400 * 9, "asn_build": time.time() - 86400 * 9}
    _table: Dict[str, Dict[str, Any]] = {}

    def __init__(self) -> None:
        for _, _, ip, _, _, city, asn, org in FLOWS:
            c = CITY[city]
            self._table[ip] = {"country": c[0], "country_name": c[0], "country_ja": c[1], "city": c[2], "lat": c[3], "lon": c[4],
                               "asn": asn, "org": org}
        self._table[C2[2]] = dict(C2_GEO)
        self._table["203.0.113.10"] = {"country": "JP", "country_ja": "日本", "city": "Tokyo", "lat": 35.6812, "lon": 139.7671,
                                       "asn": 64496, "org": "DEMO ISP（架空）"}

    def lookup(self, ip: str) -> Dict[str, Any]:
        out = {"ip": ip}
        out.update(self._table.get(ip, {}))
        if ip not in self._table and not netutil.is_public(ip):
            out["scope"] = "local"
        return out


class DemoFeeds:
    def __init__(self, tmp: str):
        self.meta_path = os.path.join(tmp, "feeds-meta.json")
        with open(self.meta_path, "w") as f:
            f.write("{}")

    def match(self, ip: str) -> List[Dict[str, Any]]:
        if ip == C2[2]:
            return [{"feed": "feodo", "label": "abuse.ch Feodo Tracker（ボットネットC2サーバー）", "severity": "critical",
                     "kind": "botnet-c2"}]
        return []

    def status(self) -> List[Dict[str, Any]]:
        from kekkai.intel.feeds import FEEDS
        counts = {"feodo": 312, "et_compromised": 1489, "spamhaus_drop": 1407, "firehol_level1": 4632, "cins_army": 15000,
                  "tor_exit": 1243}
        return [{"id": k, "label": v["label"], "severity": v["severity"], "kind": v["kind"], "home": v["home"],
                 "entries": counts.get(k, 0), "updated_at": time.time() - 3600 * 3, "status": "ok", "error": None}
                for k, v in FEEDS.items()]

    def update(self, *a: Any, **k: Any) -> Dict[str, str]:
        return {"demo": "skipped"}

    @property
    def total_entries(self) -> int:
        return 24083


class DemoOUI:
    size = 54289

    def vendor(self, mac: str) -> Optional[str]:
        for d in DEVICES:
            if d[1] == mac:
                return d[2]
        return "Apple" if mac == THIS[1] else None


class DemoPlatform(Platform):
    name = "macos"

    def __init__(self) -> None:
        self.cycle = 0

    @property
    def stage(self) -> int:
        return self.cycle

    def lan_context(self) -> LanContext:
        gw_mac = ATTACKER_MAC if self.stage >= 9 else GW_MAC
        return LanContext(interface="en0", kind="wifi", ip=THIS[0], prefixlen=24, mac=THIS[1], gateway="192.168.10.1",
                          gateway_mac=gw_mac, default_via="en0")

    def neighbors(self) -> List[Neighbor]:
        out = []
        for ip, mac, *_rest, stage in DEVICES:
            if stage > 0 and self.stage < 3:
                continue
            if ip == "192.168.10.1" and self.stage >= 9:
                mac = ATTACKER_MAC
            out.append(Neighbor(ip=ip, mac=mac, interface="en0"))
        return out

    def connections(self) -> List[Connection]:
        self.cycle += 1
        out = []
        for i, (proc, path, ip, port, proto, *_x) in enumerate(FLOWS):
            if (i + self.cycle) % 9 == 0:
                continue  # a little churn so the map breathes
            out.append(Connection(proto=proto, laddr=THIS[0], lport=50000 + i, raddr=ip, rport=port,
                                  state="ESTABLISHED" if proto == "tcp" else "", pid=400 + i * 7, process=proc, path=path))
        if self.stage >= 4:
            out.append(Connection(proto="tcp", laddr=THIS[0], lport=51337, raddr=C2[2], rport=C2[3], state="ESTABLISHED",
                                  pid=6666, process=C2[0], path=C2[1]))
        out += [Connection(proto="tcp", laddr="*", lport=7000, raddr="*", rport=0, state="LISTEN", pid=520, process="ControlCenter",
                           path="/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"),
                Connection(proto="tcp", laddr="127.0.0.1", lport=47665, raddr="*", rport=0, state="LISTEN", pid=900,
                           process="Python", path="/usr/bin/python3"),
                Connection(proto="tcp", laddr=THIS[0], lport=51010, raddr="192.168.10.44", rport=445, state="ESTABLISHED",
                           pid=330, process="NetAuthSysAgent", path="/System/Library/CoreServices/NetAuthAgent.app"),
                Connection(proto="tcp", laddr="127.0.0.1", lport=54001, raddr="127.0.0.1", rport=11434, state="ESTABLISHED",
                           pid=910, process="Python", path="/usr/bin/python3")]
        return out

    def dns_servers(self) -> List[str]:
        return ["192.168.10.1"]

    def proxies(self) -> Dict[str, Any]:
        return {}

    def wifi(self) -> Optional[Dict[str, Any]]:
        return {"interface": "en0", "ssid": "KEKKAI-HOME-5G", "security": "WPA3/WPA2", "channel": "149 (5GHz, 80MHz)",
                "phy": "802.11ax", "signal": "-52 dBm / -93 dBm",
                "nearby": [{"ssid": "aterm-5f3c21-a", "security": "WPA2"}, {"ssid": "Free_Wi-Fi_Station", "security": "OPEN"}]}

    def persistence_items(self) -> List[Dict[str, Any]]:
        base = BOOT - 86400 * 40
        items = [
            {"label": "com.google.keystone.agent", "program": "/Users/demo/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
             "plist": "/Users/demo/Library/LaunchAgents/com.google.keystone.agent.plist", "scope": "user", "mtime": base, "exists": True,
             "signature": {"checked": True, "signed": True, "team": "EQHXZ8M8AV", "summary": "Developer ID Application: Google LLC (EQHXZ8M8AV)"}},
            {"label": "com.microsoft.update.agent", "program": "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant.app/Contents/MacOS/Microsoft Update Assistant",
             "plist": "/Library/LaunchAgents/com.microsoft.update.agent.plist", "scope": "agent", "mtime": base, "exists": True,
             "signature": {"checked": True, "signed": True, "team": "UBF8T346G9", "summary": "Developer ID Application: Microsoft Corporation (UBF8T346G9)"}},
            {"label": "com.docker.vmnetd", "program": "/Library/PrivilegedHelperTools/com.docker.vmnetd",
             "plist": "/Library/LaunchDaemons/com.docker.vmnetd.plist", "scope": "daemon", "mtime": base, "exists": True,
             "signature": {"checked": True, "signed": True, "team": "9BNSXJN65R", "summary": "Developer ID Application: Docker Inc (9BNSXJN65R)"}},
        ]
        if self.stage >= 4:
            items.append({"label": "com.apple.sysmond", "program": C2[1], "plist": "/Users/demo/Library/LaunchAgents/com.apple.sysmond.plist",
                          "scope": "user", "mtime": BOOT + 30, "run_at_load": True, "keep_alive": True, "exists": True,
                          "signature": dict(SIGS[C2[1]])})
        return items

    def code_signature(self, path: str) -> Dict[str, Any]:
        if path in SIGS:
            return dict(SIGS[path])
        return {"checked": True, "signed": True, "apple": path.startswith("/System/"), "team": "DEMO", "summary": "Developer ID"}

    def notify(self, title: str, message: str) -> bool:
        return True


def demo_discover(platform: DemoPlatform, ctx: LanContext, oui: Any, active: bool = True) -> Dict[str, Any]:
    devices = []
    for ip, mac, vendor, host, kind, services, model, stage in DEVICES:
        if stage > 0 and platform.stage < 3:
            continue
        devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": host, "services": services, "kind": kind,
                        "model": model, "randomized": netutil.mac_is_randomized(mac), "upnp": None})
    devices.append({"ip": THIS[0], "mac": THIS[1], "vendor": "Apple", "hostname": "MacBook-Pro", "services": [], "kind": "this",
                    "model": "Mac16,7", "randomized": False, "upnp": None})
    igd = {"router": "192.168.10.1", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "external_ip": "203.0.113.10",
           "mappings": [{"external_port": "51413", "protocol": "TCP", "internal_client": "192.168.10.41", "internal_port": "51413",
                         "description": "Nintendo Switch", "enabled": True, "lease": "0", "remote_host": "*"}]}
    if platform.stage >= 3:
        igd["mappings"].append({"external_port": "8080", "protocol": "TCP", "internal_client": "192.168.10.37", "internal_port": "80",
                                "description": "IPCam P2P", "enabled": True, "lease": "0", "remote_host": "*"})
    return {"devices": devices, "igd": igd, "neighbors": [n.to_dict() for n in platform.neighbors()],
            "stats": {"swept": 253, "neighbors": len(devices) - 1, "mdns": 7, "upnp": 3, "duration": 6.1}}


def demo_scan(ip: str, **_: Any) -> Dict[str, Any]:
    from kekkai.discovery.portscan import SERVICES
    table = {"192.168.10.37": [(23, "IPC-360 login:"), (80, "Boa/0.94.13"), (554, "")],
             "192.168.10.1": [(53, ""), (80, "Aterm"), (443, "")], "192.168.10.44": [(139, ""), (445, ""), (80, "lighttpd")],
             "192.168.10.40": [(80, "EPSON_Linux UPnP/1.0"), (443, ""), (631, ""), (9100, "")]}
    ports = []
    for p, banner in table.get(ip, [(62078, "")]):
        svc = SERVICES.get(p, ("unknown", "info", ""))
        e = {"port": p, "service": svc[0], "risk": svc[1], "note": svc[2]}
        if banner:
            e["banner"] = banner
        ports.append(e)
    order = ["info", "low", "medium", "high", "critical"]
    return {"ip": ip, "scanned": 78, "open": ports, "worst": max((x["risk"] for x in ports), key=order.index),
            "duration": 2.4, "method": "tcp-connect", "ts": time.time()}


def demo_audit(snapshot: Dict[str, Any], slow: bool = False) -> Dict[str, Any]:
    from kekkai.audit import check
    checks = [
        check("firewall", "ファイアウォール", "pass", "オン", "", "network", 10),
        check("stealth", "ステルスモード", "warn", "オフ", "ファイアウォール > オプション > ステルスモードを有効にする をオンに。", "network", 4),
        check("filevault", "FileVault（ディスク暗号化）", "pass", "オン", "", "system", 10),
        check("sip", "SIP（システム整合性保護）", "pass", "有効", "", "system", 10),
        check("gatekeeper", "Gatekeeper（未確認アプリの実行防止）", "pass", "有効", "", "system", 8),
        check("autoupdate", "自動アップデート設定", "pass", "セキュリティ更新の自動インストールは有効（既定値）", "", "update", 9),
        check("pending_updates", "未適用のアップデート", "warn", "macOS 26.5 / 利用可能: macOS 26.5.1 (セキュリティ修正)",
              "システム設定 > 一般 > ソフトウェアアップデート から今すぐ適用（最重要の対策です）。", "update", 10),
        check("autologin", "自動ログイン", "pass", "無効", "", "system", 7),
        check("backup", "バックアップ（Time Machine）", "warn", "バックアップ先が設定されていません",
              "ランサムウェア対策として外付けディスク等へのTime Machineを設定（ネットから切り離して保管が理想）。", "system", 6),
        check("screenlock", "画面ロック", "pass", "有効（immediate）", "", "system", 5),
    ]
    checks += common_checks(snapshot)
    order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}
    checks.sort(key=lambda c: (order.get(c["status"], 9), -c["weight"]))
    res = {"ts": time.time(), "duration": 1.2, "checks": checks}
    res.update(score(checks))
    return res


def build(cfg: Any) -> Any:
    """Monitor wired to the fictional network, with a few cycles pre-run so the UI is populated."""
    from kekkai.monitor import Monitor
    netutil.DEMO_PUBLIC_NETS = (netutil.ipaddress.ip_network("203.0.113.0/24"),)
    tmp = tempfile.mkdtemp(prefix="kekkai-demo-")
    store = Store(os.path.join(tmp, "demo.db"))
    plat = DemoPlatform()
    cfg.set("monitor.interval_sec", 5)
    cfg.set("monitor.lan_discovery_interval_sec", 25)
    cfg.set("monitor.posture_interval_sec", 30)
    cfg.set("monitor.exposure_interval_sec", 120)
    cfg.set("notify.macos", False)
    m = Monitor(cfg, store=store, platform=plat)
    m.demo = True
    m.geo, m.feeds, m.oui = DemoGeo(), DemoFeeds(tmp), DemoOUI()
    m._discover = demo_discover
    m._scan = demo_scan
    m._deep_scan = demo_scan
    m._deep_available = lambda: True
    m._audit = demo_audit
    m._public_ip = lambda: "203.0.113.10"
    m._internetdb = lambda ip: {"ip": ip, "found": True, "ports": [8080, 51413], "vulns": [], "hostnames": [],
                                "tags": [], "cpes": ["cpe:/a:boa:boa"]}
    m.intel_cycle = lambda force=False: {"demo": True}
    m.state["home"] = {"lat": 35.6812, "lon": 139.7671, "label": "HOME", "source": "demo"}
    # Baseline (stage 1-2), then the incident unfolds (stage 3-4).
    m.fast_cycle()
    m.lan_cycle()
    m.posture_cycle()
    m.fast_cycle()
    m.fast_cycle()
    m.lan_cycle()
    m.fast_cycle()
    m.posture_cycle()
    m.exposure_cycle()
    for ip in ("192.168.10.37", "192.168.10.1", "192.168.10.40", "192.168.10.44"):
        job = {"id": "demo-" + ip, "ip": ip, "mode": "quick", "status": "running", "started": time.time()}
        m._run_scan(job)
    trusted = ("192.168.10.1", "192.168.10.30", "192.168.10.31", "192.168.10.40", "192.168.10.42", "192.168.10.44", "192.168.10.55")
    net_id = m.state["network"]["id"]
    for d in m.store.devices(net_id):
        if d["ip"] in trusted or d["kind"] == "this":
            m.store.update_device(net_id, d["mac"], trusted=True)
    m.store.update_device(net_id, "9a:4e:2c:11:aa:01", label="iPhone（家族）", trusted=True)
    return m
