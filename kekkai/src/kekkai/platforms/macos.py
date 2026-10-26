"""macOS collectors.

Every parser is a pure function over command output so it can be tested against
fixtures (tests/fixtures/macos) and against real runners in CI. Nothing here needs root;
root only adds process names for other users' sockets via lsof.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import plistlib
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

from kekkai.netutil import mac_is_multicast, normalize_mac, parse_ip
from kekkai.platforms.base import (TCP_STATES, Connection, Interface, LanContext, Neighbor, Platform,
                                   ProcInfo, pick_lan)
from kekkai.util import find_cmd, run

# ---------------------------------------------------------------- ifconfig / hardware ports

_IF_HDR = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+): flags=[0-9a-fA-F]+<(?P<flags>[^>]*)>")
_INET = re.compile(r"^\s+inet (?P<addr>\d+\.\d+\.\d+\.\d+)(?: --> \S+)? netmask (?P<mask>\S+)")
_INET6 = re.compile(r"^\s+inet6 (?P<addr>[0-9a-fA-F:]+)(?:%\S+)? prefixlen (?P<plen>\d+)")
_ETHER = re.compile(r"^\s+ether (?P<mac>[0-9a-fA-F:]+)")
_STATUS = re.compile(r"^\s+status: (?P<status>\w+)")


def mask_to_prefix(mask: str) -> int:
    try:
        if mask.lower().startswith("0x"):
            return bin(int(mask, 16)).count("1")
        return ipaddress.ip_network("0.0.0.0/" + mask).prefixlen
    except ValueError:
        return 32


def iface_kind(name: str, hw_port: Optional[str]) -> str:
    if name.startswith("lo"):
        return "loopback"
    if hw_port:
        h = hw_port.lower()
        if "wi-fi" in h or "airport" in h or "wlan" in h:
            return "wifi"
        if "bridge" in h:
            return "bridge"
        if any(k in h for k in ("ethernet", "lan", "thunderbolt", "usb")):
            return "ethernet"
    if re.match(r"^(utun|ipsec|ppp|tun|tap|wg|gpd)\d*$", name):
        return "vpn"
    if name.startswith("bridge"):
        return "bridge"
    if re.match(r"^(awdl|llw|anpi|ap|gif|stf)\d*$", name):
        return "p2p"
    if name.startswith("en"):
        return "ethernet"
    return "other"


def parse_hardware_ports(text: str) -> Dict[str, str]:
    """`networksetup -listallhardwareports` -> {device: hardware port name}."""
    out: Dict[str, str] = {}
    port: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            out[line.split(":", 1)[1].strip()] = port
            port = None
    return out


def parse_ifconfig(text: str, hw_ports: Optional[Dict[str, str]] = None) -> List[Interface]:
    hw_ports = hw_ports or {}
    result: List[Interface] = []
    cur: Optional[Interface] = None
    for line in text.splitlines():
        m = _IF_HDR.match(line)
        if m:
            name = m.group("name")
            flags = set(m.group("flags").split(","))
            cur = Interface(name=name, up="UP" in flags and "RUNNING" in flags,
                            hw_port=hw_ports.get(name), kind=iface_kind(name, hw_ports.get(name)))
            # Interfaces without a status line (lo0, utun) count as active when up.
            cur.active = cur.up
            result.append(cur)
            continue
        if cur is None:
            continue
        m = _INET.match(line)
        if m:
            cur.ipv4.append((m.group("addr"), mask_to_prefix(m.group("mask"))))
            continue
        m = _INET6.match(line)
        if m:
            cur.ipv6.append((m.group("addr"), int(m.group("plen"))))
            continue
        m = _ETHER.match(line)
        if m:
            cur.mac = normalize_mac(m.group("mac"))
            continue
        m = _STATUS.match(line)
        if m:
            cur.active = m.group("status") == "active"
    return result


# ---------------------------------------------------------------- routes / ARP

def parse_netstat_routes(text: str) -> Tuple[Dict[str, str], Optional[str]]:
    """`netstat -rn -f inet` -> ({iface: gateway_ip}, interface of the primary default route)."""
    gateway_for: Dict[str, str] = {}
    default_via: Optional[str] = None
    in_inet = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Internet:"):
            in_inet = True
            continue
        if s.startswith("Internet6:"):
            in_inet = False
            continue
        if not in_inet or not s.startswith("default"):
            continue
        toks = s.split()
        if len(toks) < 4:
            continue
        gw, flags, netif = toks[1], toks[2], toks[3]
        scoped = "I" in flags
        if not scoped and default_via is None:
            default_via = netif
        if parse_ip(gw) is not None and netif not in gateway_for:
            gateway_for[netif] = gw
    return gateway_for, default_via


_ARP = re.compile(r"^\S+ \((?P<ip>[0-9a-fA-F:.]+)\) at (?P<mac>\S+)(?: on (?P<iface>\S+))?(?P<rest>.*)$")


def parse_arp(text: str) -> List[Neighbor]:
    """`arp -an`. macOS prints octets without leading zeros; normalize_mac fixes that."""
    out: List[Neighbor] = []
    for line in text.splitlines():
        m = _ARP.match(line.strip())
        if not m:
            continue
        ip = parse_ip(m.group("ip"))
        if ip is None or ip.is_multicast:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac is not None and (mac == "ff:ff:ff:ff:ff:ff" or mac_is_multicast(mac)):
            continue
        rest = m.group("rest") or ""
        out.append(Neighbor(ip=str(ip), mac=mac, interface=m.group("iface"),
                            permanent="permanent" in rest,
                            state="incomplete" if mac is None else "reachable"))
    return out


# ---------------------------------------------------------------- sockets

def split_hostport(token: str) -> Tuple[str, int]:
    """netstat style "addr.port" (IPv4 and IPv6) -> (addr, port)."""
    if token in ("*.*", "*"):
        return "*", 0
    host, _, port = token.rpartition(".")
    if not host:
        return token, 0
    if port == "*":
        return host, 0
    try:
        return host, int(port)
    except ValueError:
        return token, 0


def _clean_addr(addr: str) -> str:
    if addr == "*":
        return "*"
    ip = parse_ip(addr)
    return str(ip) if ip is not None else addr


def parse_netstat_sockets(text: str) -> List[Connection]:
    """`netstat -anv -p tcp|udp` (header driven, tolerant of column changes between releases)."""
    out: List[Connection] = []
    pid_col: Optional[int] = None
    for line in text.splitlines():
        if line.startswith("Proto"):
            hdr = line.replace("Local Address", "Local_Address").replace("Foreign Address", "Foreign_Address").split()
            pid_col = None
            for i, name in enumerate(hdr):
                if name == "pid" or name.startswith("process"):
                    pid_col = i
                    break
            continue
        if not (line.startswith("tcp") or line.startswith("udp")):
            continue
        toks = line.split()
        if len(toks) < 5:
            continue
        proto = "tcp" if toks[0].startswith("tcp") else "udp"
        if proto == "udp" and (len(toks) < 6 or toks[5] not in TCP_STATES):
            toks.insert(5, "")          # UDP has an empty (state) column
        state = toks[5] if proto == "tcp" and len(toks) > 5 else ""
        laddr, lport = split_hostport(toks[3])
        raddr, rport = split_hostport(toks[4])
        pid: Optional[int] = None
        pname: Optional[str] = None
        if pid_col is not None and pid_col < len(toks):
            v = toks[pid_col]
            if v.isdigit():
                pid = int(v)
            elif ":" in v and v.rsplit(":", 1)[1].isdigit():
                pname, pid_s = v.rsplit(":", 1)
                pid = int(pid_s)
        out.append(Connection(proto=proto, laddr=_clean_addr(laddr), lport=lport,
                              raddr=_clean_addr(raddr), rport=rport, state=state,
                              pid=pid if pid else None, process=pname))
    return out


def _split_lsof_side(side: str) -> Tuple[str, int]:
    side = side.strip()
    if side.startswith("["):
        host, _, rest = side[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = side.rpartition(":")
    try:
        p = int(port)
    except ValueError:
        p = 0
    return _clean_addr(host or "*"), p


def parse_lsof(text: str) -> List[Connection]:
    """`lsof -nP -iTCP -iUDP -FpcuPnT` field output."""
    out: List[Connection] = []
    pid: Optional[int] = None
    cmd: Optional[str] = None
    uid: Optional[int] = None
    cur: Dict[str, str] = {}

    def flush() -> None:
        if pid is None or "name" not in cur or "proto" not in cur:
            return
        name = cur["name"]
        if "->" in name:
            a, b = name.split("->", 1)
        else:
            a, b = name, "*:*"
        laddr, lport = _split_lsof_side(a)
        raddr, rport = _split_lsof_side(b)
        out.append(Connection(proto=cur["proto"], laddr=laddr, lport=lport, raddr=raddr, rport=rport,
                              state=cur.get("state", ""), pid=pid, process=cmd, uid=uid))

    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            flush()
            cur = {}
            try:
                pid = int(val)
            except ValueError:
                pid = None
            cmd, uid = None, None
        elif tag == "c":
            cmd = val
        elif tag == "u":
            try:
                uid = int(val)
            except ValueError:
                uid = None
        elif tag == "f":
            flush()
            cur = {}
        elif tag == "P":
            cur["proto"] = val.lower()
        elif tag == "n":
            cur["name"] = val
        elif tag == "T" and val.startswith("ST="):
            cur["state"] = val[3:]
    flush()
    return out


def parse_ps(text: str) -> Dict[int, ProcInfo]:
    """`ps -axo pid=,ppid=,uid=,comm=` (comm is the full executable path on macOS)."""
    out: Dict[int, ProcInfo] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        comm = parts[3].strip()
        path = comm if comm.startswith("/") else None
        out[pid] = ProcInfo(pid=pid, ppid=int(parts[1]) if parts[1].isdigit() else None,
                            uid=int(parts[2]) if parts[2].lstrip("-").isdigit() else None,
                            name=os.path.basename(comm) or comm, path=path)
    return out


# ---------------------------------------------------------------- DNS / proxy / Wi-Fi

def parse_scutil_dns(text: str) -> List[str]:
    """Default (non domain-specific) resolvers from `scutil --dns`."""
    blocks: List[Tuple[bool, List[str]]] = []
    scoped: List[str] = []
    in_scoped = False
    has_domain = False
    servers: List[str] = []
    started = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("DNS configuration (for scoped queries)"):
            if started:
                blocks.append((has_domain, servers))
            started, in_scoped = False, True
            continue
        if s.startswith("resolver #"):
            if started and not in_scoped:
                blocks.append((has_domain, servers))
            started, has_domain, servers = True, False, []
            continue
        if s.startswith("domain") and ":" in s:
            has_domain = True
        if s.startswith("nameserver[") and ":" in s:
            ns = s.split(":", 1)[1].strip()
            if in_scoped:
                scoped.append(ns)
            else:
                servers.append(ns)
    if started and not in_scoped:
        blocks.append((has_domain, servers))
    result: List[str] = []
    for has_dom, srv in blocks:
        if not has_dom:
            result.extend(srv)
    if not result:
        result = scoped
    seen: List[str] = []
    for ns in result:
        if ns not in seen:
            seen.append(ns)
    return seen


def parse_scutil_proxy(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    depth = 0
    for line in text.splitlines():
        s = line.strip()
        if s.endswith("{"):
            depth += 1
            if depth == 1:
                continue
        if s == "}":
            depth -= 1
            continue
        if depth == 1 and " : " in s:
            k, v = s.split(" : ", 1)
            v = v.strip()
            out[k.strip()] = int(v) if v.isdigit() else v
    return out


def proxy_summary(p: Dict[str, Any]) -> Dict[str, Any]:
    active = {}
    for kind, en, host, port in (("http", "HTTPEnable", "HTTPProxy", "HTTPPort"),
                                 ("https", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
                                 ("socks", "SOCKSEnable", "SOCKSProxy", "SOCKSPort")):
        if p.get(en) == 1:
            active[kind] = "%s:%s" % (p.get(host, "?"), p.get(port, "?"))
    if p.get("ProxyAutoConfigEnable") == 1:
        active["pac"] = p.get("ProxyAutoConfigURLString", "?")
    if p.get("ProxyAutoDiscoveryEnable") == 1:
        active["wpad"] = "auto-discovery"
    return active


def security_label(mode: Optional[str]) -> str:
    if not mode:
        return "UNKNOWN"
    m = mode.lower()
    if "none" in m or m.endswith("_open"):
        return "OPEN"
    if "owe" in m:
        return "OWE"
    if "wep" in m:
        return "WEP"
    ent = "-Enterprise" if "enterprise" in m else ""
    if "wpa3" in m:
        return ("WPA3/WPA2" if "transition" in m else "WPA3") + ent
    if "wpa2" in m:
        return "WPA2" + ent
    if "wpa" in m:
        return "WPA" + ent
    return mode


def parse_system_profiler_wifi(text: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    items = data.get("SPAirPortDataType") or []
    for item in items:
        for iface in item.get("spairport_airport_interfaces") or []:
            cur = iface.get("spairport_current_network_information")
            if not isinstance(cur, dict):
                continue
            nearby = []
            for n in iface.get("spairport_airport_other_local_wireless_networks") or []:
                if isinstance(n, dict):
                    nearby.append({"ssid": n.get("_name"), "security": security_label(n.get("spairport_security_mode")),
                                   "channel": n.get("spairport_network_channel"),
                                   "signal": n.get("spairport_signal_noise")})
            return {
                "interface": iface.get("_name"),
                "ssid": cur.get("_name"),
                "security": security_label(cur.get("spairport_security_mode")),
                "security_raw": cur.get("spairport_security_mode"),
                "channel": cur.get("spairport_network_channel"),
                "phy": cur.get("spairport_network_phymode"),
                "signal": cur.get("spairport_signal_noise"),
                "nearby": nearby,
            }
    return None


# ---------------------------------------------------------------- code signing / persistence

def parse_codesign(rc: int, stderr: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"checked": True, "signed": False, "adhoc": False, "apple": False,
                            "team": None, "authority": [], "identifier": None}
    if "not signed at all" in stderr:
        return info
    if rc != 0 and "Authority=" not in stderr and "Signature=adhoc" not in stderr:
        info["checked"] = False
        info["error"] = stderr.strip().splitlines()[-1] if stderr.strip() else "codesign failed"
        return info
    for line in stderr.splitlines():
        if line.startswith("Authority="):
            info["authority"].append(line.split("=", 1)[1])
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1]
            info["team"] = None if v == "not set" else v
        elif line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1]
        elif line.strip() == "Signature=adhoc":
            info["adhoc"] = True
    info["signed"] = bool(info["authority"]) or info["adhoc"]
    auth = info["authority"]
    info["apple"] = any(a in ("Software Signing", "Apple Mac OS Application Signing") for a in auth)
    info["summary"] = ("Apple" if info["apple"] else
                       auth[0] if auth else "ad-hoc" if info["adhoc"] else "unsigned")
    return info


PERSISTENCE_DIRS = ("~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons")


def read_launch_plist(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError, Exception):
        return None
    if not isinstance(data, dict):
        return None
    program = data.get("Program")
    args = data.get("ProgramArguments")
    if not program and isinstance(args, list) and args:
        program = args[0]
    return {
        "label": data.get("Label"),
        "program": program if isinstance(program, str) else None,
        "args": [str(a) for a in args][:8] if isinstance(args, list) else [],
        "run_at_load": bool(data.get("RunAtLoad")),
        "keep_alive": bool(data.get("KeepAlive")),
    }


# ---------------------------------------------------------------- platform

class MacOSPlatform(Platform):
    name = "macos"

    def __init__(self) -> None:
        self._hw_ports: Optional[Dict[str, str]] = None
        self._sig_cache: Dict[Tuple[str, float, int], Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._netstat_flags: Optional[List[str]] = None

    def hardware_ports(self) -> Dict[str, str]:
        if self._hw_ports is None:
            rc, out, _ = run(["networksetup", "-listallhardwareports"], timeout=10)
            self._hw_ports = parse_hardware_ports(out) if rc == 0 else {}
        return self._hw_ports

    def interfaces(self) -> List[Interface]:
        rc, out, _ = run(["ifconfig", "-a"], timeout=10)
        return parse_ifconfig(out, self.hardware_ports()) if rc == 0 else []

    def lan_context(self) -> LanContext:
        rc, out, _ = run(["netstat", "-rn", "-f", "inet"], timeout=10)
        gateway_for, default_via = parse_netstat_routes(out) if rc == 0 else ({}, None)
        ctx = pick_lan(self.interfaces(), gateway_for, default_via)
        if ctx.gateway:
            for n in self.neighbors():
                if n.ip == ctx.gateway and n.mac:
                    ctx.gateway_mac = n.mac
                    break
        return ctx

    def neighbors(self) -> List[Neighbor]:
        rc, out, _ = run(["arp", "-an"], timeout=15)
        return parse_arp(out) if rc == 0 else []

    def _netstat(self, proto: str) -> str:
        if self._netstat_flags is None:
            rc, _, err = run(["netstat", "-anvW", "-p", "tcp"], timeout=15)
            self._netstat_flags = ["-anvW"] if rc == 0 else ["-anv"]
        rc, out, _ = run(["netstat"] + self._netstat_flags + ["-p", proto], timeout=15)
        return out if rc == 0 else ""

    def connections(self) -> List[Connection]:
        conns = parse_netstat_sockets(self._netstat("tcp")) + parse_netstat_sockets(self._netstat("udp"))
        if conns and not any(c.pid for c in conns):
            self._fill_pids_from_lsof(conns)
        procs = self.processes()
        for c in conns:
            if c.pid and c.pid in procs:
                p = procs[c.pid]
                c.process = c.process or p.name
                c.path = p.path
                c.uid = p.uid
        return conns

    def _fill_pids_from_lsof(self, conns: List[Connection]) -> None:
        rc, out, _ = run(["lsof", "+c", "0", "-nP", "-iTCP", "-iUDP", "-FpcuPnT"], timeout=20)
        if rc not in (0, 1):
            return
        index = {(c.proto, c.lport, c.rport, c.raddr): c for c in parse_lsof(out)}
        for c in conns:
            hit = index.get((c.proto, c.lport, c.rport, c.raddr))
            if hit:
                c.pid, c.process, c.uid = hit.pid, hit.process, hit.uid

    def processes(self) -> Dict[int, ProcInfo]:
        rc, out, _ = run(["ps", "-axo", "pid=,ppid=,uid=,comm="], timeout=15)
        return parse_ps(out) if rc == 0 else {}

    def dns_servers(self) -> List[str]:
        rc, out, _ = run(["scutil", "--dns"], timeout=10)
        return parse_scutil_dns(out) if rc == 0 else []

    def proxies(self) -> Dict[str, Any]:
        rc, out, _ = run(["scutil", "--proxy"], timeout=10)
        return proxy_summary(parse_scutil_proxy(out)) if rc == 0 else {}

    def wifi(self) -> Optional[Dict[str, Any]]:
        rc, out, _ = run(["system_profiler", "SPAirPortDataType", "-json"], timeout=40)
        return parse_system_profiler_wifi(out) if rc == 0 else None

    def code_signature(self, path: str) -> Dict[str, Any]:
        try:
            st = os.stat(path)
        except OSError:
            return {"checked": False, "error": "missing"}
        key = (path, st.st_mtime, st.st_size)
        with self._lock:
            if key in self._sig_cache:
                return self._sig_cache[key]
        rc, _, err = run(["codesign", "-dv", "--verbose=2", path], timeout=10)
        info = parse_codesign(rc, err) if rc != 127 else {"checked": False, "error": "codesign missing"}
        with self._lock:
            self._sig_cache[key] = info
        return info

    def persistence_items(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for d in PERSISTENCE_DIRS:
            base = os.path.expanduser(d)
            for path in sorted(glob.glob(os.path.join(base, "*.plist"))):
                info = read_launch_plist(path) or {"label": None, "program": None, "args": []}
                info["plist"] = path
                info["scope"] = "user" if d.startswith("~") else ("daemon" if "Daemons" in d else "agent")
                try:
                    info["mtime"] = os.stat(path).st_mtime
                except OSError:
                    info["mtime"] = None
                prog = info.get("program")
                if prog and os.path.isabs(prog):
                    info["exists"] = os.path.exists(prog)
                    if info["exists"]:
                        info["signature"] = self.code_signature(prog)
                items.append(info)
        return items

    def notify(self, title: str, message: str) -> bool:
        # Arguments go through argv, so alert text can never be interpreted as AppleScript.
        rc, _, _ = run(["osascript", "-e", "on run argv", "-e",
                        "display notification (item 2 of argv) with title (item 1 of argv) sound name \"Basso\"",
                        "-e", "end run", title, message[:240]], timeout=10)
        return rc == 0

    def open_url(self, url: str) -> bool:
        rc, _, _ = run(["open", url], timeout=10)
        return rc == 0

    def capabilities(self) -> Dict[str, Any]:
        caps = super().capabilities()
        for tool in ("arp", "netstat", "lsof", "ps", "ifconfig", "scutil", "system_profiler", "codesign",
                     "socketfilterfw", "fdesetup", "csrutil", "spctl", "tcpdump", "nmap", "softwareupdate"):
            caps[tool] = find_cmd(tool) is not None
        return caps
