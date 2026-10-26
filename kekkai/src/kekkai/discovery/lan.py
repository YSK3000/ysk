"""LAN discovery orchestration (netdiscover/arp-scan style) + device classification."""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Dict, List, Optional

from kekkai.discovery import mdns, ssdp
from kekkai.discovery.mdns import SERVICE_HINTS
from kekkai.netutil import ip_sort_key, is_local_target, mac_is_randomized
from kekkai.platforms.base import LanContext, Neighbor
from kekkai.util import log

MAX_SWEEP_HOSTS = 1024

KIND_LABELS = {
    "router": "ルーター", "this": "このMac", "computer": "PC", "phone": "スマホ/タブレット", "apple": "Apple機器",
    "media": "AirPlay/メディア", "tv": "テレビ/ストリーミング", "speaker": "スマートスピーカー", "printer": "プリンター",
    "nas": "NAS/ファイル共有", "camera": "カメラ", "iot": "IoT/スマート家電", "game": "ゲーム機",
    "network": "ネットワーク機器", "unknown": "不明",
}

_VENDOR_HINTS = [
    (("nintendo", "sony interactive", "microsoft xbox", "valve"), "game"),
    (("espressif", "tuya", "shelly", "switchbot", "sonoff", "itead", "broadlink", "nature", "lifx", "signify",
      "philips lighting", "xiaomi", "aqara", "irobot", "dyson", "panasonic appliances"), "iot"),
    (("hikvision", "dahua", "wyze", "arlo", "reolink", "ezviz", "ring", "atom tech", "i-pro", "axis comm"), "camera"),
    (("brother", "canon", "seiko epson", "epson", "hewlett", "hp inc", "kyocera", "ricoh", "xerox", "lexmark", "fuji xerox",
      "fujifilm business"), "printer"),
    (("synology", "qnap", "western digital", "seagate", "asustor", "terramaster"), "nas"),
    (("sonos", "bose", "amazon technologies", "amazon.com"), "speaker"),
    (("roku", "lg electronics", "vizio", "tcl", "hisense", "sharp", "toshiba visual", "funai"), "tv"),
    (("nec platforms", "yamaha", "buffalo", "i-o data", "elecom", "tp-link", "asustek", "netgear", "sagemcom", "sercomm",
      "sumitomo electric", "zte", "huawei", "ubiquiti", "mikrotik", "cisco", "aruba", "linksys", "d-link", "fortinet",
      "juniper", "allied telesis", "eero", "nokia"), "network"),
    (("raspberry pi", "intel", "dell", "lenovo", "micro-star", "hon hai", "gigabyte", "asrock", "realtek", "liteon",
      "azurewave", "framework"), "computer"),
    (("google",), "tv"),
    (("apple",), "apple"),
    (("samsung", "oppo", "vivo", "oneplus", "motorola", "fcnt", "kyocera communication", "sharp mobile", "zte mobile"),
     "phone"),
]

_NAME_HINTS = [
    (("iphone", "ipad", "android", "galaxy", "pixel", "xperia", "aquos-sense", "redmi"), "phone"),
    (("macbook", "imac", "mac-mini", "macmini", "mac-studio", "desktop-", "laptop-", "-pc", "thinkpad"), "computer"),
    (("printer", "epson", "canon", "brother", "ew-m", "px-m", "mfc-", "dcp-"), "printer"),
    (("bravia", "aquos", "viera", "regza", "-tv", "tv-", "firetv", "fire-tv", "chromecast", "appletv", "apple-tv"), "tv"),
    (("switch", "nintendo", "playstation", "ps5", "ps4", "xbox"), "game"),
    (("echo", "alexa", "homepod", "nest", "google-home", "sonos"), "speaker"),
    (("cam", "camera", "ipcam", "tapo-c"), "camera"),
    (("nas", "diskstation", "linkstation", "landisk", "terastation"), "nas"),
]


def classify(ip: str, mac: Optional[str], vendor: Optional[str], hostname: Optional[str], services: List[str],
             upnp_type: Optional[str], ctx: LanContext) -> str:
    if ctx.gateway and ip == ctx.gateway:
        return "router"
    if ctx.ip and ip == ctx.ip:
        return "this"
    if upnp_type and "InternetGatewayDevice" in upnp_type:
        return "router"
    name = (hostname or "").lower()
    for keys, kind in _NAME_HINTS:
        if any(k in name for k in keys):
            return kind
    for s in services:
        hint = SERVICE_HINTS.get(s)
        if hint and hint[0] and hint[0] not in ("apple",):
            return hint[0]
    if upnp_type:
        if "MediaRenderer" in upnp_type or "MediaServer" in upnp_type:
            return "tv"
        if "Printer" in upnp_type:
            return "printer"
    v = (vendor or "").lower()
    for keys, kind in _VENDOR_HINTS:
        if any(k in v for k in keys):
            return kind
    if any(s == "_companion-link._tcp" for s in services):
        return "apple"
    if mac and mac_is_randomized(mac):
        return "phone"
    return "unknown"


def sweep_targets(ctx: LanContext) -> List[str]:
    if not ctx.ip or ctx.prefixlen is None:
        return []
    net = ipaddress.ip_network("%s/%d" % (ctx.ip, ctx.prefixlen), strict=False)
    if net.num_addresses > MAX_SWEEP_HOSTS + 2:
        net = ipaddress.ip_network("%s/24" % ctx.ip, strict=False)
    return [str(h) for h in net.hosts() if str(h) != ctx.ip and is_local_target(str(h))]


def udp_sweep(targets: List[str], port: int = 9, pace: float = 0.002) -> int:
    """Send one tiny UDP datagram per host so the kernel ARP-resolves it (no root needed)."""
    sent = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return 0
    s.setblocking(False)
    try:
        for t in targets:
            if not is_local_target(t):
                continue
            try:
                s.sendto(b"KEKKAI-ARP", (t, port))
                sent += 1
            except OSError:
                pass
            if pace:
                time.sleep(pace)
    finally:
        s.close()
    return sent


def reverse_dns(ips: List[str], timeout: float = 2.5) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not ips:
        return out

    def one(ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return None

    pool = ThreadPoolExecutor(max_workers=16)
    futs = {pool.submit(one, ip): ip for ip in ips}
    done, _ = wait(futs, timeout=timeout)
    for f in done:
        name = f.result()
        if name and name != futs[f]:
            out[futs[f]] = name.rstrip(".")
    pool.shutdown(wait=False)
    return out


def discover(platform: Any, ctx: LanContext, oui: Any, active: bool = True,
             upnp_audit: bool = True) -> Dict[str, Any]:
    """One discovery pass. Returns {"devices": [...], "igd": {...}|None, "stats": {...}}."""
    t0 = time.time()
    swept = 0
    if active:
        swept = udp_sweep(sweep_targets(ctx))
        time.sleep(1.8)
    net = ctx.network
    neigh: List[Neighbor] = [n for n in platform.neighbors()
                             if n.mac and (net is None or _in(n.ip, net))
                             and (ctx.interface is None or n.interface in (None, ctx.interface))]
    ips = sorted({n.ip for n in neigh}, key=ip_sort_key)
    m = mdns.discover(iface_ip=ctx.ip, timeout=3.0, reverse_ips=ips)
    upnp = ssdp.discover(iface_ip=ctx.ip, timeout=2.5)
    rdns = reverse_dns(ips)

    upnp_by_ip: Dict[str, Dict[str, Any]] = {}
    igd: Optional[Dict[str, Any]] = None
    for u in upnp:
        ip = u["ip"]
        if not u.get("location") or (ip in upnp_by_ip and upnp_by_ip[ip].get("friendlyName")):
            continue
        try:
            desc = ssdp.describe(u["location"], ip)
        except Exception as e:  # noqa: BLE001 - untrusted device responses
            log.debug("upnp describe %s failed: %s", ip, e)
            continue
        desc["server"] = u.get("server")
        upnp_by_ip[ip] = desc
        if upnp_audit and igd is None and "InternetGatewayDevice" in (desc.get("deviceType") or ""):
            try:
                igd = ssdp.igd_audit(desc, ip)
            except Exception as e:  # noqa: BLE001
                log.debug("igd audit failed: %s", e)

    devices = []
    seen_macs = set()
    for n in neigh:
        if n.mac in seen_macs:
            # Same MAC on several IPs: keep the first, rules.py reports the duplicate.
            continue
        seen_macs.add(n.mac)
        md = m.get(n.ip, {})
        up = upnp_by_ip.get(n.ip, {})
        vendor = oui.vendor(n.mac) if oui else None
        names = md.get("names") or []
        hostname = _best_name(names) or rdns.get(n.ip) or up.get("friendlyName")
        services = md.get("services") or []
        kind = classify(n.ip, n.mac, vendor, hostname, services, up.get("deviceType"), ctx)
        devices.append({
            "ip": n.ip, "mac": n.mac, "vendor": vendor, "hostname": hostname, "services": services,
            "kind": kind, "model": md.get("model") or up.get("modelName"), "randomized": mac_is_randomized(n.mac or "00"),
            "upnp": {k: up.get(k) for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType", "server")} if up else None,
        })
    if ctx.ip and ctx.mac:
        devices.append({"ip": ctx.ip, "mac": ctx.mac, "vendor": oui.vendor(ctx.mac) if oui else None,
                        "hostname": socket.gethostname(), "services": [], "kind": "this", "model": None,
                        "randomized": mac_is_randomized(ctx.mac), "upnp": None})
    return {"devices": devices, "igd": igd, "neighbors": [n.to_dict() for n in neigh],
            "stats": {"swept": swept, "neighbors": len(neigh), "mdns": len(m), "upnp": len(upnp),
                      "duration": round(time.time() - t0, 1)}}


def _in(ip: str, net: Any) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _best_name(names: List[str]) -> Optional[str]:
    for n in names:
        if n.endswith(".local"):
            return n[:-6]
    return names[0] if names else None
