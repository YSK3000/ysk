"""OS-neutral data model for what the collectors observe."""
from __future__ import annotations

import dataclasses
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from kekkai.netutil import is_public, network_of, parse_ip

TCP_STATES = {
    "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "SYN_RECV", "ESTABLISHED", "CLOSE_WAIT",
    "FIN_WAIT_1", "FIN_WAIT_2", "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "LAST_ACK", "TIME_WAIT",
}


class Model:
    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Interface(Model):
    name: str
    mac: Optional[str] = None
    ipv4: List[Tuple[str, int]] = field(default_factory=list)   # (address, prefixlen)
    ipv6: List[Tuple[str, int]] = field(default_factory=list)
    up: bool = False
    active: bool = False
    kind: str = "other"          # wifi | ethernet | loopback | vpn | bridge | p2p | other
    hw_port: Optional[str] = None  # macOS "Wi-Fi", "Thunderbolt Ethernet", ...


@dataclass
class Neighbor(Model):
    ip: str
    mac: Optional[str]
    interface: Optional[str] = None
    permanent: bool = False
    state: str = ""


@dataclass
class Connection(Model):
    proto: str                   # tcp | udp
    laddr: str
    lport: int
    raddr: str
    rport: int
    state: str = ""
    pid: Optional[int] = None
    process: Optional[str] = None
    path: Optional[str] = None
    uid: Optional[int] = None

    @property
    def is_listen(self) -> bool:
        if self.proto == "tcp":
            return self.state == "LISTEN"
        return self.rport == 0 and self.raddr in ("*", "0.0.0.0", "::", "")

    @property
    def is_remote_public(self) -> bool:
        return is_public(self.raddr)

    def key(self) -> Tuple[Any, ...]:
        return (self.proto, self.laddr, self.lport, self.raddr, self.rport)


@dataclass
class LanContext(Model):
    """The physical network this machine sits on (not the VPN tunnel)."""
    interface: Optional[str] = None
    kind: str = ""
    ip: Optional[str] = None
    prefixlen: Optional[int] = None
    mac: Optional[str] = None
    gateway: Optional[str] = None
    gateway_mac: Optional[str] = None
    default_via: Optional[str] = None    # interface carrying the default route (VPN detection)

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if self.ip and self.prefixlen is not None:
            return network_of(self.ip, self.prefixlen)
        return None

    @property
    def vpn_active(self) -> bool:
        return bool(self.default_via and self.interface and self.default_via != self.interface)


@dataclass
class ProcInfo(Model):
    pid: int
    ppid: Optional[int] = None
    uid: Optional[int] = None
    name: str = ""
    path: Optional[str] = None


class Platform:
    """Interface implemented by platforms/macos.py and platforms/linux.py."""

    name = "generic"

    def interfaces(self) -> List[Interface]:
        return []

    def lan_context(self) -> LanContext:
        return LanContext()

    def neighbors(self) -> List[Neighbor]:
        return []

    def connections(self) -> List[Connection]:
        return []

    def processes(self) -> Dict[int, ProcInfo]:
        return {}

    def dns_servers(self) -> List[str]:
        return []

    def proxies(self) -> Dict[str, Any]:
        return {}

    def wifi(self) -> Optional[Dict[str, Any]]:
        return None

    def persistence_items(self) -> List[Dict[str, Any]]:
        return []

    def code_signature(self, path: str) -> Dict[str, Any]:
        return {"checked": False}

    def notify(self, title: str, message: str) -> bool:
        return False

    def open_url(self, url: str) -> bool:
        import webbrowser
        try:
            return webbrowser.open(url)
        except Exception:
            return False

    def capabilities(self) -> Dict[str, Any]:
        return {"root": hasattr(os, "geteuid") and os.geteuid() == 0}


def pick_lan(interfaces: List[Interface], gateway_for: Dict[str, str],
             default_via: Optional[str]) -> LanContext:
    """Choose the physical LAN interface: active, private IPv4, wifi/ethernet preferred."""
    best: Optional[Tuple[int, Interface, str, int]] = None
    for iface in interfaces:
        if not iface.up or iface.kind in ("loopback", "vpn", "p2p"):
            continue
        for addr, plen in iface.ipv4:
            ip = parse_ip(addr)
            if ip is None or not ip.is_private or ip.is_loopback or ip.is_link_local:
                continue
            score = 0
            if iface.name in gateway_for:
                score += 10
            if iface.active:
                score += 4
            if iface.kind in ("wifi", "ethernet"):
                score += 3
            if iface.name == default_via:
                score += 2
            if best is None or score > best[0]:
                best = (score, iface, addr, plen)
    if best is None:
        return LanContext(default_via=default_via)
    _, iface, addr, plen = best
    return LanContext(interface=iface.name, kind=iface.kind, ip=addr, prefixlen=plen,
                      mac=iface.mac, gateway=gateway_for.get(iface.name), default_via=default_via)
