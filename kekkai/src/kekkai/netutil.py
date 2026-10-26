"""IP / MAC helpers shared by collectors, detection and the scanner guard."""
from __future__ import annotations

import ipaddress
import re
from typing import Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Targets KEKKAI is allowed to actively probe: your own LAN / this machine only.
LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
))

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]{12}$")

# Demo mode only: documentation ranges (RFC 5737) that should behave like internet hosts.
DEMO_PUBLIC_NETS: tuple = ()


def parse_ip(value: object) -> Optional[IPAddress]:
    """Parse an address string, tolerating zone ids, brackets and IPv4-mapped IPv6."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("*", "-"):
        return None
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def norm_ip(value: object) -> Optional[str]:
    ip = parse_ip(value)
    return str(ip) if ip is not None else None


def is_local_target(value: object) -> bool:
    """True when the address is on a private/link-local/loopback range (allowed scan target)."""
    ip = parse_ip(value)
    if ip is None or ip.is_multicast or ip.is_unspecified:
        return False
    return any(ip in net for net in LOCAL_NETS if net.version == ip.version)


def is_public(value: object) -> bool:
    ip = parse_ip(value)
    if ip is not None and DEMO_PUBLIC_NETS and any(ip in n for n in DEMO_PUBLIC_NETS if n.version == ip.version):
        return True
    return bool(ip is not None and ip.is_global and not ip.is_multicast)


def normalize_mac(value: object) -> Optional[str]:
    """Return aa:bb:cc:dd:ee:ff or None.

    Accepts macOS short octets ("0:1a:2b:3:4:5"), dashes, Cisco dots and bare hex.
    """
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s or "incomplete" in s:
        return None
    if "." in s and ":" not in s and "-" not in s:
        s = s.replace(".", "")
    if _HEX_ONLY.match(s):
        parts = [s[i:i + 2] for i in range(0, 12, 2)]
    else:
        parts = re.split(r"[:\-]", s)
        if len(parts) != 6:
            return None
    out = []
    for p in parts:
        if not p or len(p) > 2 or not all(c in "0123456789abcdef" for c in p):
            return None
        out.append(p.zfill(2))
    mac = ":".join(out)
    if mac == "00:00:00:00:00:00":
        return None
    return mac


def mac_first_octet(mac: str) -> int:
    return int(mac[:2], 16)


def mac_is_multicast(mac: str) -> bool:
    return bool(mac_first_octet(mac) & 0x01)


def mac_is_randomized(mac: str) -> bool:
    """Locally administered bit: phones' "private Wi-Fi address", VMs, some IoT."""
    return bool(mac_first_octet(mac) & 0x02)


def mac_oui(mac: str) -> str:
    return mac.replace(":", "")[:6].upper()


def ip_sort_key(value: str) -> tuple:
    ip = parse_ip(value)
    if ip is None:
        return (9, value)
    return (ip.version, int(ip))


def network_of(addr: str, prefixlen: int) -> Optional[ipaddress.IPv4Network]:
    try:
        return ipaddress.ip_network("%s/%d" % (addr, prefixlen), strict=False)
    except ValueError:
        return None
