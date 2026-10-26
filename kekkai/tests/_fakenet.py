"""Test-only fake LAN: a scripted intrusion run through the real Monitor and detection engine.

Stages advance with each fast cycle: a camera joins (3), it opens a UPnP port and the Mac starts talking to a
C2 server from an unsigned LaunchAgent (4), then the camera impersonates the router (9). Internet hosts use
documentation ranges (RFC 5737), which tests treat as public via netutil.EXTRA_PUBLIC_NETS.
"""
import os
import tempfile
import time

from kekkai import netutil
from kekkai.audit import check, common_checks, score
from kekkai.platforms.base import Connection, LanContext, Neighbor, Platform
from kekkai.store import Store

GW_IP, GW_MAC = "192.168.10.1", "a4:2b:b0:10:00:01"
CAM_IP, CAM_MAC = "192.168.10.37", "7c:df:a1:3e:00:37"
THIS = ("192.168.10.23", "3c:22:fb:7a:10:23")
C2 = ("sysmond", "/Users/Shared/.sysmond/sysmond", "203.0.113.66", 4444)
PUBLIC_IP = "203.0.113.10"
DEVICES = [  # ip, mac, vendor, hostname, kind, joins at stage
    (GW_IP, GW_MAC, "NEC Platforms", "aterm", "router", 0),
    ("192.168.10.24", "9a:4e:2c:11:aa:01", None, "iPhone", "phone", 0),
    ("192.168.10.40", "64:eb:8c:10:00:40", "Seiko Epson", "EPSON-EW-M754T", "printer", 0),
    ("192.168.10.44", "10:6f:3f:10:00:44", "BUFFALO", "LS220D", "nas", 0),
    (CAM_IP, CAM_MAC, "Espressif", "IPC-360", "camera", 3),
]
FLOWS = [  # process, path, remote ip, port
    ("Safari", "/Applications/Safari.app/Contents/MacOS/Safari", "17.253.144.10", 443),
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "142.250.196.110", 443),
    ("ssh", "/usr/bin/ssh", "52.69.186.44", 22),
]
GEO = {
    "17.253.144.10": ("US", "Cupertino", 37.32, -122.03, 714, "Apple Inc."),
    "142.250.196.110": ("JP", "Tokyo", 35.69, 139.69, 15169, "Google LLC"),
    "52.69.186.44": ("JP", "Tokyo", 35.69, 139.69, 16509, "Amazon.com, Inc."),
    C2[2]: ("NL", "Amsterdam", 52.37, 4.90, 64512, "Example Hosting"),
    PUBLIC_IP: ("JP", "Tokyo", 35.68, 139.77, 64496, "Example ISP"),
}
START = time.time()


class FakeGeo:
    available = {"city": True, "asn": True, "city_build": START - 86400 * 9, "asn_build": START - 86400 * 9}

    def lookup(self, ip):
        out = {"ip": ip}
        if ip in GEO:
            cc, city, lat, lon, asn, org = GEO[ip]
            out.update({"country": cc, "country_name": cc, "country_ja": cc, "city": city, "lat": lat, "lon": lon,
                        "asn": asn, "org": org})
        elif not netutil.is_public(ip):
            out["scope"] = "local"
        return out


class FakeFeeds:
    def __init__(self, tmp):
        self.meta_path = os.path.join(tmp, "feeds-meta.json")
        with open(self.meta_path, "w") as f:
            f.write("{}")

    def match(self, ip):
        if ip == C2[2]:
            return [{"feed": "feodo", "label": "abuse.ch Feodo Tracker（ボットネットC2サーバー）", "severity": "critical",
                     "kind": "botnet-c2"}]
        return []

    def status(self):
        from kekkai.intel.feeds import FEEDS
        return [{"id": k, "label": v["label"], "severity": v["severity"], "kind": v["kind"], "home": v["home"],
                 "entries": 100, "updated_at": START - 3600, "status": "ok", "error": None} for k, v in FEEDS.items()]

    def update(self, *a, **k):
        return {}

    @property
    def total_entries(self):
        return 100 * 6


class FakeOUI:
    size = 54289

    def vendor(self, mac):
        return next((d[2] for d in DEVICES if d[1] == mac), "Apple" if mac == THIS[1] else None)


class FakePlatform(Platform):
    name = "macos"

    def __init__(self):
        self.stage = 0

    def lan_context(self):
        return LanContext(interface="en0", kind="wifi", ip=THIS[0], prefixlen=24, mac=THIS[1], gateway=GW_IP,
                          gateway_mac=CAM_MAC if self.stage >= 9 else GW_MAC, default_via="en0")

    def neighbors(self):
        out = []
        for ip, mac, _v, _h, _k, joins in DEVICES:
            if self.stage >= joins:
                out.append(Neighbor(ip=ip, mac=CAM_MAC if ip == GW_IP and self.stage >= 9 else mac, interface="en0"))
        return out

    def connections(self):
        self.stage += 1
        out = [Connection(proto="tcp", laddr=THIS[0], lport=50000 + i, raddr=ip, rport=port, state="ESTABLISHED",
                          pid=400 + i, process=proc, path=path) for i, (proc, path, ip, port) in enumerate(FLOWS)]
        if self.stage >= 4:
            out.append(Connection(proto="tcp", laddr=THIS[0], lport=51337, raddr=C2[2], rport=C2[3], state="ESTABLISHED",
                                  pid=6666, process=C2[0], path=C2[1]))
        out.append(Connection(proto="tcp", laddr="*", lport=7000, raddr="*", rport=0, state="LISTEN", pid=520,
                              process="ControlCenter", path="/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"))
        return out

    def dns_servers(self):
        return [GW_IP]

    def proxies(self):
        return {}

    def wifi(self):
        return {"interface": "en0", "ssid": "HOME-5G", "security": "WPA3/WPA2", "channel": "149 (5GHz, 80MHz)",
                "phy": "802.11ax", "signal": "-52 dBm / -93 dBm", "nearby": []}

    def persistence_items(self):
        items = [{"label": "com.google.keystone.agent", "scope": "user", "mtime": START - 86400 * 40, "exists": True,
                  "program": "/Users/u/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                  "plist": "/Users/u/Library/LaunchAgents/com.google.keystone.agent.plist",
                  "signature": {"checked": True, "signed": True, "team": "EQHXZ8M8AV", "summary": "Developer ID Application: Google LLC"}}]
        if self.stage >= 4:
            items.append({"label": "com.apple.sysmond", "program": C2[1], "plist": "/Users/u/Library/LaunchAgents/com.apple.sysmond.plist",
                          "scope": "user", "mtime": START + 30, "run_at_load": True, "keep_alive": True, "exists": True,
                          "signature": self.code_signature(C2[1])})
        return items

    def code_signature(self, path):
        if path == C2[1]:
            return {"checked": True, "signed": False, "adhoc": False, "apple": False, "team": None, "authority": [],
                    "summary": "unsigned"}
        return {"checked": True, "signed": True, "apple": path.startswith("/System/"), "team": "TEAM", "summary": "Developer ID"}

    def notify(self, title, message):
        return True


def discover(platform, ctx, oui, active=True):
    devices = [{"ip": ip, "mac": mac, "vendor": vendor, "hostname": host, "services": [], "kind": kind, "model": None,
                "randomized": netutil.mac_is_randomized(mac), "upnp": None}
               for ip, mac, vendor, host, kind, joins in DEVICES if platform.stage >= joins]
    devices.append({"ip": THIS[0], "mac": THIS[1], "vendor": "Apple", "hostname": "MacBook-Pro", "services": [], "kind": "this",
                    "model": None, "randomized": False, "upnp": None})
    igd = {"router": GW_IP, "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "external_ip": PUBLIC_IP, "mappings": []}
    if platform.stage >= 3:
        igd["mappings"].append({"external_port": "8080", "protocol": "TCP", "internal_client": CAM_IP, "internal_port": "80",
                                "description": "IPCam P2P", "enabled": True, "lease": "0", "remote_host": "*"})
    return {"devices": devices, "igd": igd, "neighbors": [n.to_dict() for n in platform.neighbors()],
            "stats": {"swept": 253, "neighbors": len(devices) - 1, "mdns": 0, "upnp": 1, "duration": 1.0}}


def scan(ip, **_):
    from kekkai.discovery.portscan import SERVICES
    table = {CAM_IP: [(23, "IPC-360 login:"), (80, "Boa/0.94.13")], GW_IP: [(53, ""), (80, "Aterm")]}
    ports = []
    for p, banner in table.get(ip, [(62078, "")]):
        svc = SERVICES.get(p, ("unknown", "info", ""))
        ports.append(dict({"port": p, "service": svc[0], "risk": svc[1], "note": svc[2]}, **({"banner": banner} if banner else {})))
    order = ["info", "low", "medium", "high", "critical"]
    return {"ip": ip, "scanned": 78, "open": ports, "worst": max((x["risk"] for x in ports), key=order.index),
            "duration": 0.1, "method": "tcp-connect", "ts": time.time()}


def audit(snapshot, slow=False):
    checks = [check("firewall", "ファイアウォール", "pass", "オン", "", "network", 10),
              check("filevault", "FileVault（ディスク暗号化）", "pass", "オン", "", "system", 10),
              check("backup", "バックアップ（Time Machine）", "warn", "バックアップ先が設定されていません", "外付けディスク等に設定", "system", 6)]
    checks += common_checks(snapshot)
    res = {"ts": time.time(), "duration": 0.1, "checks": checks}
    res.update(score(checks))
    return res


def build(cfg):
    """A Monitor on the fake LAN with no real network, notification, download or AI access."""
    from kekkai.monitor import Monitor
    netutil.EXTRA_PUBLIC_NETS = (netutil.ipaddress.ip_network("203.0.113.0/24"),)
    tmp = tempfile.mkdtemp(prefix="kekkai-fakenet-")
    for key, value in (("notify.macos", False), ("ai.provider", "off")):
        cfg.set(key, value)
    m = Monitor(cfg, store=Store(os.path.join(tmp, "test.db")), platform=FakePlatform())
    m.geo, m.feeds, m.oui = FakeGeo(), FakeFeeds(tmp), FakeOUI()
    m._discover, m._scan, m._deep_scan, m._audit = discover, scan, scan, audit
    m._deep_available = lambda: False
    m._public_ip = lambda: PUBLIC_IP
    m._internetdb = lambda ip: {"ip": ip, "found": True, "ports": [8080], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
    m.intel_cycle = lambda force=False: {}
    # baseline (stages 1-2), then the intrusion unfolds (stages 3-4)
    for step in ("fast", "lan", "posture", "fast", "fast", "lan", "fast", "posture", "exposure"):
        getattr(m, step + "_cycle")()
    for ip in (CAM_IP, GW_IP):
        m._run_scan({"id": "scan-" + ip, "ip": ip, "mode": "quick", "status": "running", "started": time.time()})
    return m
