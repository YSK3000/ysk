"""Bonjour / mDNS discovery (RFC 6762 legacy-unicast queries: no need to bind port 5353)."""
from __future__ import annotations

import random
import select
import socket
import time
from typing import Any, Dict, List, Optional, Set

from kekkai.discovery.dnswire import T_A, T_PTR, T_SRV, T_TXT, build_query, parse_message
from kekkai.netutil import is_local_target

MDNS_ADDR = ("224.0.0.251", 5353)
SERVICES_META = "_services._dns-sd._udp.local"

# service type -> (device kind, Japanese label)
SERVICE_HINTS = {
    "_airplay._tcp": ("media", "AirPlay"),
    "_raop._tcp": ("media", "AirPlayスピーカー"),
    "_companion-link._tcp": ("apple", "Apple機器"),
    "_googlecast._tcp": ("tv", "Chromecast/Google TV"),
    "_ipp._tcp": ("printer", "プリンター(IPP)"),
    "_ipps._tcp": ("printer", "プリンター(IPPS)"),
    "_printer._tcp": ("printer", "プリンター(LPR)"),
    "_pdl-datastream._tcp": ("printer", "プリンター(RAW 9100)"),
    "_uscan._tcp": ("printer", "スキャナー"),
    "_hap._tcp": ("iot", "HomeKitアクセサリ"),
    "_hap._udp": ("iot", "HomeKitアクセサリ(Thread)"),
    "_homekit._tcp": ("iot", "HomeKit"),
    "_matter._tcp": ("iot", "Matter機器"),
    "_matterc._udp": ("iot", "Matter(未設定)"),
    "_smb._tcp": ("nas", "ファイル共有(SMB)"),
    "_afpovertcp._tcp": ("nas", "ファイル共有(AFP)"),
    "_adisk._tcp": ("nas", "Time Machine"),
    "_ssh._tcp": ("computer", "SSH"),
    "_sftp-ssh._tcp": ("computer", "SFTP"),
    "_rfb._tcp": ("computer", "画面共有(VNC)"),
    "_sonos._tcp": ("speaker", "Sonos"),
    "_spotify-connect._tcp": ("speaker", "Spotify Connect"),
    "_amzn-wplay._tcp": ("tv", "Fire TV"),
    "_nvstream._tcp": ("computer", "NVIDIA GameStream"),
    "_http._tcp": ("", "Web管理画面"),
    "_rdlink._tcp": ("apple", "Apple機器"),
    "_meshcop._udp": ("iot", "Threadボーダールーター"),
    "_trel._udp": ("iot", "Thread"),
    "_workstation._tcp": ("computer", "PC"),
    "_device-info._tcp": ("", "機器情報"),
}


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _sock(iface_ip: Optional[str]) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    if iface_ip:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        except OSError:
            pass
    s.bind(("0.0.0.0", 0))
    s.setblocking(False)
    return s


def discover(iface_ip: Optional[str] = None, timeout: float = 3.0,
             reverse_ips: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Return {ip: {"names": [...], "services": [...], "txt": {...}, "model": str|None}}."""
    found: Dict[str, Dict[str, Any]] = {}
    asked: Set[str] = set()
    qid = random.randint(1, 0xFFFF)
    try:
        sock = _sock(iface_ip)
    except OSError:
        return found

    def send(questions: List[Any]) -> None:
        for i in range(0, len(questions), 12):
            try:
                sock.sendto(build_query(qid, questions[i:i + 12]), MDNS_ADDR)
            except (OSError, ValueError):
                pass

    send([(SERVICES_META, T_PTR)])
    if reverse_ips:
        send([(reverse_name(ip), T_PTR) for ip in reverse_ips if ":" not in ip])
    deadline = time.time() + timeout
    try:
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            r, _, _ = select.select([sock], [], [], min(left, 0.25))
            if not r:
                continue
            try:
                data, (src, _port) = sock.recvfrom(9000)
            except OSError:
                continue
            if not is_local_target(src):
                continue
            try:
                msg = parse_message(data)
            except ValueError:
                continue
            if not msg["response"]:
                continue
            entry = found.setdefault(src, {"names": [], "services": [], "txt": {}, "model": None})
            follow = []
            for rec in msg["records"]:
                name, rtype, val = rec["name"], rec["type"], rec.get("value")
                if val is None:
                    continue
                lname = name.lower()
                if rtype == T_PTR and lname == SERVICES_META.lower():
                    stype = _service_type(val)
                    if stype and stype not in asked and len(asked) < 64:
                        asked.add(stype)
                        follow.append((stype + ".local", T_PTR))
                    if stype:
                        _add(entry["services"], stype)
                elif rtype == T_PTR and lname.endswith(".in-addr.arpa"):
                    _add(entry["names"], str(val).rstrip("."))
                elif rtype == T_PTR:
                    stype = _service_type(name)
                    if stype:
                        _add(entry["services"], stype)
                    inst = str(val).split("._", 1)[0]
                    if inst and len(entry["names"]) < 6:
                        _add(entry["names"], inst)
                elif rtype == T_SRV and isinstance(val, dict):
                    tgt = str(val.get("target", "")).rstrip(".")
                    if tgt:
                        _add(entry["names"], tgt)
                elif rtype == T_TXT and isinstance(val, list):
                    for item in val[:24]:
                        if "=" in item:
                            k, v = item.split("=", 1)
                            if k.lower() in ("model", "md", "ty", "fn", "rpmd", "am"):
                                entry["txt"][k.lower()] = v[:80]
                    if "model" in entry["txt"] and not entry["model"]:
                        entry["model"] = entry["txt"]["model"]
                    elif "md" in entry["txt"] and not entry["model"]:
                        entry["model"] = entry["txt"]["md"]
                elif rtype == T_A and val != src and is_local_target(val):
                    # Responders announce their own address; ignore records for other hosts.
                    pass
            if follow:
                send(follow)
    finally:
        sock.close()
    return found


def _service_type(name: Any) -> Optional[str]:
    """'_airplay._tcp.local' or 'Living Room._airplay._tcp.local' -> '_airplay._tcp'."""
    parts = str(name).rstrip(".").split(".")
    for i in range(len(parts) - 1):
        if parts[i].startswith("_") and parts[i + 1] in ("_tcp", "_udp"):
            return parts[i] + "." + parts[i + 1]
    return None


def _add(lst: List[str], v: str) -> None:
    if v and v not in lst and len(lst) < 40:
        lst.append(v)
