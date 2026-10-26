"""Linux collectors (procfs/sysfs, no external commands required)."""
from __future__ import annotations

import fcntl
import glob
import os
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

from kekkai.netutil import mac_is_multicast, normalize_mac, parse_ip
from kekkai.platforms.base import Connection, Interface, LanContext, Neighbor, Platform, ProcInfo, pick_lan
from kekkai.util import find_cmd, run

TCP_STATE_HEX = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT_1", "05": "FIN_WAIT_2",
    "06": "TIME_WAIT", "07": "CLOSED", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B


def _hex_ip(h: str) -> str:
    if len(h) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("=I", int(h, 16)))
    words = [struct.pack("=I", int(h[i:i + 8], 16)) for i in range(0, 32, 8)]
    ip = parse_ip(socket.inet_ntop(socket.AF_INET6, b"".join(words)))
    return str(ip)


def parse_proc_net(text: str, proto: str) -> List[Tuple[Connection, str]]:
    """/proc/net/{tcp,tcp6,udp,udp6} -> [(Connection, inode)]."""
    out: List[Tuple[Connection, str]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            lhex, lport = parts[1].split(":")
            rhex, rport = parts[2].split(":")
            laddr, raddr = _hex_ip(lhex), _hex_ip(rhex)
            lp, rp = int(lport, 16), int(rport, 16)
        except (ValueError, OSError):
            continue
        st = parts[3].upper()
        state = TCP_STATE_HEX.get(st, st) if proto == "tcp" else ("ESTABLISHED" if st == "01" else "")
        if raddr in ("0.0.0.0", "::"):
            raddr = "*"
        if laddr in ("0.0.0.0", "::"):
            laddr = "*"
        uid = int(parts[7]) if parts[7].isdigit() else None
        out.append((Connection(proto=proto, laddr=laddr, lport=lp, raddr=raddr, rport=rp, state=state, uid=uid),
                    parts[9]))
    return out


def parse_proc_arp(text: str) -> List[Neighbor]:
    out: List[Neighbor] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip = parse_ip(parts[0])
        if ip is None or ip.is_multicast:
            continue
        flags = int(parts[2], 16) if parts[2].startswith("0x") else 0
        mac = normalize_mac(parts[3]) if flags & 0x2 else None
        if mac and (mac == "ff:ff:ff:ff:ff:ff" or mac_is_multicast(mac)):
            continue
        out.append(Neighbor(ip=str(ip), mac=mac, interface=parts[5], permanent=bool(flags & 0x4),
                            state="reachable" if mac else "incomplete"))
    return out


def parse_proc_route(text: str) -> Tuple[Dict[str, str], Optional[str]]:
    gateway_for: Dict[str, str] = {}
    default_via: Optional[str] = None
    best_metric: Optional[int] = None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gw, mask = parts[0], parts[1], parts[2], parts[7]
        if dest != "00000000" or mask != "00000000":
            continue
        gw_ip = _hex_ip(gw)
        metric = int(parts[6]) if parts[6].isdigit() else 0
        if gw_ip != "0.0.0.0":
            gateway_for.setdefault(iface, gw_ip)
        if best_metric is None or metric < best_metric:
            best_metric, default_via = metric, iface
    return gateway_for, default_via


def parse_resolv_conf(text: str) -> List[str]:
    out: List[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in out:
            out.append(parts[1])
    return out


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _kind(name: str) -> str:
    if name == "lo":
        return "loopback"
    if os.path.exists("/sys/class/net/%s/wireless" % name) or name.startswith("wl"):
        return "wifi"
    if name.startswith(("tun", "tap", "wg", "ppp", "tailscale", "utun")):
        return "vpn"
    if name.startswith(("docker", "br-", "virbr", "cni", "bridge")):
        return "bridge"
    if name.startswith(("veth",)):
        return "p2p"
    if name.startswith(("eth", "en")):
        return "ethernet"
    return "other"


class LinuxPlatform(Platform):
    name = "linux"

    def interfaces(self) -> List[Interface]:
        names = sorted(n for _, n in socket.if_nameindex())
        v6: Dict[str, List[Tuple[str, int]]] = {}
        for line in _read("/proc/net/if_inet6").splitlines():
            p = line.split()
            if len(p) >= 6:
                v6.setdefault(p[5], []).append((_hex_ip_v6_plain(p[0]), int(p[2], 16)))
        out: List[Interface] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for name in names:
                iface = Interface(name=name, kind=_kind(name))
                packed = struct.pack("256s", name.encode()[:15])
                try:
                    flags = struct.unpack("H", fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, packed)[16:18])[0]
                    iface.up = bool(flags & 0x1) and bool(flags & 0x40)
                except OSError:
                    pass
                try:
                    addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, packed)[20:24])
                    mask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, packed)[20:24])
                    iface.ipv4.append((addr, bin(struct.unpack("!I", socket.inet_aton(mask))[0]).count("1")))
                except OSError:
                    pass
                iface.ipv6 = v6.get(name, [])
                iface.mac = normalize_mac(_read("/sys/class/net/%s/address" % name).strip())
                iface.active = iface.up and _read("/sys/class/net/%s/operstate" % name).strip() in ("up", "unknown")
                out.append(iface)
        finally:
            sock.close()
        return out

    def lan_context(self) -> LanContext:
        gateway_for, default_via = parse_proc_route(_read("/proc/net/route"))
        ctx = pick_lan(self.interfaces(), gateway_for, default_via)
        if ctx.gateway:
            for n in self.neighbors():
                if n.ip == ctx.gateway and n.mac:
                    ctx.gateway_mac = n.mac
        return ctx

    def neighbors(self) -> List[Neighbor]:
        return parse_proc_arp(_read("/proc/net/arp"))

    def connections(self) -> List[Connection]:
        pairs: List[Tuple[Connection, str]] = []
        for fname, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
            pairs += parse_proc_net(_read("/proc/net/" + fname), proto)
        inode_pid = self._socket_inodes()
        procs = self.processes()
        out: List[Connection] = []
        for c, inode in pairs:
            pid = inode_pid.get(inode)
            if pid:
                c.pid = pid
                p = procs.get(pid)
                if p:
                    c.process, c.path = p.name, p.path
            out.append(c)
        return out

    def _socket_inodes(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for fd_dir in glob.glob("/proc/[0-9]*/fd"):
            pid = int(fd_dir.split("/")[2])
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    result[target[8:-1]] = pid
        return result

    def processes(self) -> Dict[int, ProcInfo]:
        out: Dict[int, ProcInfo] = {}
        for d in glob.glob("/proc/[0-9]*"):
            pid = int(d.rsplit("/", 1)[1])
            stat = _read(d + "/stat")
            if not stat:
                continue
            name = stat[stat.find("(") + 1:stat.rfind(")")]
            rest = stat[stat.rfind(")") + 2:].split()
            ppid = int(rest[1]) if len(rest) > 1 and rest[1].isdigit() else None
            try:
                path: Optional[str] = os.readlink(d + "/exe")
            except OSError:
                path = None
            uid = None
            for line in _read(d + "/status").splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
            out[pid] = ProcInfo(pid=pid, ppid=ppid, uid=uid, name=name, path=path)
        return out

    def dns_servers(self) -> List[str]:
        servers = parse_resolv_conf(_read("/etc/resolv.conf"))
        if servers and all(s.startswith("127.0.0.5") for s in servers):
            upstream = parse_resolv_conf(_read("/run/systemd/resolve/resolv.conf"))
            if upstream:
                return upstream
        return servers

    def proxies(self) -> Dict[str, Any]:
        out = {}
        for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            if os.environ.get(k):
                out[k.lower().replace("_proxy", "")] = os.environ[k]
        return out

    def persistence_items(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for pattern, scope in (("~/.config/autostart/*.desktop", "user"),
                               ("~/.config/systemd/user/*.service", "user"),
                               ("/etc/systemd/system/*.service", "daemon")):
            for path in sorted(glob.glob(os.path.expanduser(pattern))):
                if os.path.islink(path):
                    continue
                program = None
                for line in _read(path).splitlines():
                    if line.startswith(("Exec=", "ExecStart=")):
                        program = line.split("=", 1)[1].strip().split(" ")[0].lstrip("-@")
                        break
                try:
                    mtime: Optional[float] = os.stat(path).st_mtime
                except OSError:
                    mtime = None
                items.append({"plist": path, "label": os.path.basename(path), "program": program,
                              "args": [], "scope": scope, "mtime": mtime,
                              "exists": os.path.exists(program) if program and program.startswith("/") else None})
        return items

    def notify(self, title: str, message: str) -> bool:
        if not find_cmd("notify-send"):
            return False
        rc, _, _ = run(["notify-send", title, message[:240]], timeout=5)
        return rc == 0

    def capabilities(self) -> Dict[str, Any]:
        caps = super().capabilities()
        for tool in ("tcpdump", "nmap", "notify-send"):
            caps[tool] = find_cmd(tool) is not None
        return caps


def _hex_ip_v6_plain(h: str) -> str:
    """/proc/net/if_inet6 stores addresses in network order (unlike /proc/net/tcp6)."""
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes.fromhex(h))
    except (ValueError, OSError):
        return h
