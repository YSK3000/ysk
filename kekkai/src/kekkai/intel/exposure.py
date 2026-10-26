"""How the internet sees your home: public IP + Shodan InternetDB (free, no key, weekly data)."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, Optional

from kekkai.netutil import is_public, parse_ip
from kekkai.util import FetchError, http_get

PUBLIC_IP_SOURCES = ("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://checkip.amazonaws.com")

RISKY_PORTS = {
    21: "FTP（平文）", 22: "SSH", 23: "Telnet（平文・極めて危険）", 25: "SMTP", 53: "DNS（オープンリゾルバの恐れ）",
    80: "HTTP（管理画面の恐れ）", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 161: "SNMP", 445: "SMB（ランサムウェアの主要侵入口）",
    554: "RTSP（カメラ映像）", 1433: "MSSQL", 1723: "PPTP VPN（脆弱）", 1883: "MQTT（IoT）", 1900: "UPnP",
    2375: "Docker API（乗っ取り直結）", 3306: "MySQL", 3389: "RDP（ランサムウェアの主要侵入口）", 5000: "UPnP/NAS",
    5432: "PostgreSQL", 5555: "Android ADB", 5900: "VNC（画面共有）", 6379: "Redis", 7547: "TR-069（ルーター管理）",
    8080: "HTTP代替（管理画面の恐れ）", 8443: "HTTPS代替（VPN/管理画面）", 8291: "MikroTik Winbox", 9200: "Elasticsearch",
    10443: "SSL-VPN", 11211: "Memcached", 27017: "MongoDB", 32400: "Plex", 37215: "Huawei HG532（ボットネット標的）",
    52869: "Realtek UPnP（ボットネット標的）",
}


def public_ip(fetch: Callable[..., Any] = http_get) -> Optional[str]:
    for url in PUBLIC_IP_SOURCES:
        try:
            status, _, body = fetch(url, timeout=8, max_bytes=4096)
        except FetchError:
            continue
        if status == 200:
            ip = body.decode("ascii", "replace").strip()
            if is_public(ip):
                return str(parse_ip(ip))
    return None


def internetdb(ip: str, fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
    status, _, body = fetch("https://internetdb.shodan.io/" + ip, timeout=12, max_bytes=1024 * 1024)
    if status == 404:
        return {"ip": ip, "found": False, "ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
    if status != 200:
        raise FetchError("InternetDB HTTP %s" % status)
    data = json.loads(body.decode("utf-8", "replace"))
    data["found"] = True
    for k in ("ports", "vulns", "hostnames", "tags", "cpes"):
        if not isinstance(data.get(k), list):
            data[k] = []
    return data


def assess(public: Optional[str], idb: Optional[Dict[str, Any]], upnp: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine public IP, InternetDB and router UPnP data into findings."""
    findings = []
    wan_ip = (upnp or {}).get("external_ip")
    shared = False
    if wan_ip and public and wan_ip != public:
        shared = True
        note = ("ルーターのWAN側IP(%s)と実際の公開IP(%s)が異なります。CGNAT・DS-Lite(transix等)・二重ルーターの可能性があり、"
                "IPv4では外部から直接到達しにくい構成です。下のInternetDB結果は共有IPのもので、あなたの機器とは限りません。") % (wan_ip, public)
        findings.append({"severity": "info", "title": "共有IPv4の可能性", "detail": note})
    if idb and idb.get("found"):
        ports = sorted(int(p) for p in idb.get("ports", []) if str(p).isdigit())
        vulns = idb.get("vulns", [])
        if vulns:
            findings.append({"severity": "low" if shared else "high", "title": "公開IPに既知の脆弱性(CVE)が記録されています",
                             "detail": "Shodanが %d 件のCVEを関連付けています: %s" % (len(vulns), ", ".join(vulns[:12]))})
        for p in ports:
            label = RISKY_PORTS.get(p)
            sev = "medium" if label else "low"
            if p in (23, 445, 3389, 2375, 5900, 5555, 7547, 37215, 52869):
                sev = "high"
            if shared:
                sev = "info"
            findings.append({"severity": sev, "title": "インターネットからポート %d が見えています" % p,
                             "detail": (label or "サービス") + "。ルーターのポート開放/UPnP設定を確認してください。", "port": p})
    for m in (upnp or {}).get("mappings", []):
        findings.append({"severity": "medium", "title": "UPnPでポート %s/%s が開放されています" % (m.get("external_port"), m.get("protocol")),
                         "detail": "転送先 %s:%s（%s）。心当たりがなければルーターで削除し、UPnPを無効化してください。" % (
                             m.get("internal_client"), m.get("internal_port"), m.get("description") or "説明なし")})
    return {"checked_at": time.time(), "public_ip": public, "wan_ip": wan_ip, "shared_ipv4": shared,
            "internetdb": idb, "upnp": upnp, "findings": findings}
