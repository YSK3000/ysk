"""Builds a classic pcap of a small LAN attack so the sensor can be tested against real tcpdump output."""
from __future__ import annotations

import socket
import struct
from typing import List, Tuple

OWN_IP, OWN_MAC = "192.168.10.23", "3c:22:fb:7a:10:23"
GW_IP, GW_MAC = "192.168.10.1", "a4:2b:b0:10:00:01"
ATK_IP, ATK_MAC = "192.168.10.50", "7c:df:a1:3e:00:37"
ATK2_IP, ATK2_MAC = "192.168.10.51", "02:5e:c0:00:00:51"
OWN_IP6, GW_IP6 = "2409:10:a0:1::23", "2409:10:a0:1::1"
BAD_DOMAIN = "evil-phish.example"
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 199, 443, 445, 554, 587, 993, 995,
              1025, 1723, 3306, 3389, 5900, 8080, 8443]
SWEEP_HOSTS = list(range(2, 50))


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _eth(dst: str, src: str, etype: int, payload: bytes) -> bytes:
    frame = _mac(dst) + _mac(src) + struct.pack("!H", etype) + payload
    return frame + b"\0" * max(0, 60 - len(frame))


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:] + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, sport: int, dst: str, dport: int, flags: int, smac: str, dmac: str, seq: int = 1000) -> bytes:
    opts = b"\x02\x04\x05\xb4"  # MSS 1460, like nmap -sS probes
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0 if flags == 0x02 else seq + 1, (6 << 4), flags, 1024, 0, 0) + opts
    ck = _csum(_pseudo(src, dst, 6, len(hdr)) + hdr)
    hdr = hdr[:16] + struct.pack("!H", ck) + hdr[18:]
    return _eth(dmac, smac, 0x0800, _ipv4(src, dst, 6, hdr, seq & 0xFFFF))


def dns_query(src: str, sport: int, dst: str, name: str, smac: str, dmac: str, qid: int, qtype: int = 1,
              flags: int = 0x0100) -> bytes:
    q = b"".join(struct.pack("!B", len(p)) + p.encode() for p in name.split(".")) + b"\0"
    opt = b"\0" + struct.pack("!HHIH", 41, 4096, 0, 0)  # EDNS0 -> "[1au]"
    msg = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 1) + q + struct.pack("!HH", qtype, 1) + opt
    udp = struct.pack("!HHHH", sport, 53, 8 + len(msg), 0) + msg
    v6 = ":" in src
    pseudo = (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) +
              struct.pack("!I3xB", len(udp), 17)) if v6 else _pseudo(src, dst, 17, len(udp))
    ck = _csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", ck) + udp[8:]
    if v6:
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64, socket.inet_pton(socket.AF_INET6, src),
                          socket.inet_pton(socket.AF_INET6, dst))
        return _eth(dmac, smac, 0x86DD, ip6 + udp)
    return _eth(dmac, smac, 0x0800, _ipv4(src, dst, 17, udp, qid))


def arp(op: int, sha: str, spa: str, tha: str, tpa: str, dmac: str) -> bytes:
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, _mac(sha), socket.inet_aton(spa),
                       _mac(tha), socket.inet_aton(tpa))
    return _eth(dmac, sha, 0x0806, body)


def attack_frames(t0: float = 1761400000.0) -> List[Tuple[float, bytes]]:
    """Benign noise first (must not alert), then a scan, a sweep, a router-impersonating ARP reply and a bad lookup."""
    fr: List[Tuple[float, bytes]] = []
    t = t0
    def add(b: bytes, dt: float = 0.01) -> None:
        nonlocal t
        t += dt
        fr.append((t, b))
    add(arp(2, GW_MAC, GW_IP, OWN_MAC, OWN_IP, OWN_MAC))                        # the real router
    add(dns_query(OWN_IP, 53001, GW_IP, "www.apple.com", OWN_MAC, GW_MAC, 4001))
    for i, p in enumerate(SCAN_PORTS):                                         # outbound SYNs: not a scan of us
        add(tcp(OWN_IP, 50000 + i, "93.184.215.%d" % (i + 1), p, 0x02, OWN_MAC, GW_MAC))
    for i, p in enumerate(SCAN_PORTS):                                         # someone else being scanned
        add(tcp(ATK_IP, 40000 + i, "192.168.10.77", p, 0x02, ATK_MAC, "02:00:00:00:00:77"))
    for i, p in enumerate(SCAN_PORTS):                                         # SYN-ACKs to us: replies, not probes
        add(tcp("192.168.10.77", p, OWN_IP, 41000 + i, 0x12, "02:00:00:00:00:77", OWN_MAC))
    for i, p in enumerate(SCAN_PORTS):                                         # nmap -sS against this Mac
        add(tcp(ATK_IP, 45000 + i, OWN_IP, p, 0x02, ATK_MAC, OWN_MAC), 0.002)
    for i, p in enumerate(SCAN_PORTS):                                         # connect() scan with ECN SYNs [SEW]
        add(tcp(ATK2_IP, 46000 + i, OWN_IP, p, 0xC2, ATK2_MAC, OWN_MAC), 0.002)
    for h in SWEEP_HOSTS:                                                      # netdiscover / arp-scan
        add(arp(1, ATK_MAC, ATK_IP, "00:00:00:00:00:00", "192.168.10.%d" % h, "ff:ff:ff:ff:ff:ff"), 0.005)
    add(arp(2, ATK_MAC, GW_IP, OWN_MAC, OWN_IP, OWN_MAC))                      # "I am the router" (MITM)
    add(dns_query(OWN_IP, 53002, GW_IP, "login." + BAD_DOMAIN, OWN_MAC, GW_MAC, 4002))
    add(dns_query(OWN_IP, 53003, GW_IP, "login." + BAD_DOMAIN, OWN_MAC, GW_MAC, 4003, qtype=28))  # same name: 1 alert
    add(dns_query(OWN_IP, 53004, GW_IP, "cdn." + BAD_DOMAIN, OWN_MAC, GW_MAC, 4004, flags=0x0110))   # CD bit -> "+%"
    add(dns_query(OWN_IP, 53005, GW_IP, "api." + BAD_DOMAIN, OWN_MAC, GW_MAC, 4005, qtype=65))      # HTTPS RR
    add(dns_query(OWN_IP6, 53006, GW_IP6, "v6." + BAD_DOMAIN, OWN_MAC, "33:33:00:00:00:01", 4006))  # IPv6 DNS (IPoE)
    return fr


def write_pcap(path: str, frames: List[Tuple[float, bytes]]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, b in frames:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(b), len(b)) + b)
