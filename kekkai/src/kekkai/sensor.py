"""Optional packet sensor — `sudo kekkai sensor` (Snort/Wireshark-lite on top of tcpdump).

Reads only packet headers and DNS question names (snaplen 256) and detects:
  * port scans against this Mac      * ARP sweeps (LAN reconnaissance, e.g. netdiscover/arp-scan)
  * ARP replies impersonating the router (MITM)      * DNS lookups of known malicious domains
Events are appended to <data>/sensor/events.jsonl, which the dashboard ingests.
"""
from __future__ import annotations

import collections
import json
import os
import re
import subprocess
import sys
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from kekkai import paths
from kekkai.netutil import normalize_mac
from kekkai.util import FetchError, atomic_write, find_cmd, http_get, log

DOMAIN_FEED_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"

ARP_REQ = re.compile(r"^(?P<ts>\d+\.\d+) (?P<smac>[0-9a-f:]{11,17}) > [0-9a-f:]{11,17}, ethertype ARP .*?"
                     r"Request who-has (?P<target>[\d.]+)(?: \([0-9a-f:]+\))? tell (?P<sender>[\d.]+)")
ARP_REP = re.compile(r"^(?P<ts>\d+\.\d+) (?P<smac>[0-9a-f:]{11,17}) > [0-9a-f:]{11,17}, ethertype ARP .*?"
                     r"Reply (?P<ip>[\d.]+) is-at (?P<mac>[0-9a-f:]{11,17})")
TCP_SYN = re.compile(r"^(?P<ts>\d+\.\d+) .*?ethertype IPv[46] .*?: (?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+) > "
                     r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+): Flags \[S\]")
DNS_Q = re.compile(r"^(?P<ts>\d+\.\d+) .*?: (?P<src>[0-9a-fA-F:.]+)\.\d+ > [0-9a-fA-F:.]+\.53: \d+\+?(?: \[[^\]]*\])* "
                   r"(?P<qtype>[A-Z]+)\? (?P<name>[^ ]+?)\.? \(")


class Detector:
    def __init__(self, own_ip: Optional[str], own_mac: Optional[str], gateway_ip: Optional[str],
                 gateway_mac: Optional[str], domains: Optional[Set[str]] = None,
                 scan_ports: int = 20, scan_window: float = 60, sweep_targets: int = 40, sweep_window: float = 30):
        self.own_ip, self.own_mac = own_ip, own_mac
        self.gateway_ip, self.gateway_mac = gateway_ip, gateway_mac
        self.domains = domains or set()
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.sweep_targets, self.sweep_window = sweep_targets, sweep_window
        self._syn: Dict[str, Deque[Tuple[float, int]]] = collections.defaultdict(collections.deque)
        self._arp: Dict[str, Deque[Tuple[float, str]]] = collections.defaultdict(collections.deque)
        self._cool: Dict[Tuple[str, str], float] = {}

    def _cooldown(self, kind: str, key: str, ts: float, seconds: float = 600) -> bool:
        k = (kind, key)
        if ts - self._cool.get(k, -1e18) < seconds:
            return False
        self._cool[k] = ts
        return True

    def feed(self, line: str) -> Optional[Dict[str, Any]]:
        m = TCP_SYN.match(line)
        if m:
            if self.own_ip and m.group("dst") != self.own_ip:
                return None
            ts, src, dport = float(m.group("ts")), m.group("src"), int(m.group("dport"))
            dq = self._syn[src]
            dq.append((ts, dport))
            while dq and ts - dq[0][0] > self.scan_window:
                dq.popleft()
            ports = {p for _, p in dq}
            if len(ports) >= self.scan_ports and self._cooldown("scan", src, ts):
                return {"kind": "port_scan", "src": src, "ports": len(ports), "window": int(self.scan_window),
                        "sample": sorted(ports)[:20], "ts": ts}
            return None
        m = ARP_REP.match(line)
        if m:
            ts, ip, mac = float(m.group("ts")), m.group("ip"), normalize_mac(m.group("mac"))
            if self.gateway_ip and self.gateway_mac and ip == self.gateway_ip and mac and mac != self.gateway_mac:
                if self._cooldown("spoof", mac, ts, 300):
                    return {"kind": "arp_spoof", "ip": ip, "mac": mac, "expected": self.gateway_mac, "ts": ts}
            return None
        m = ARP_REQ.match(line)
        if m:
            ts, smac, target = float(m.group("ts")), normalize_mac(m.group("smac")), m.group("target")
            if not smac or smac in (self.own_mac, self.gateway_mac):
                return None
            dq2 = self._arp[smac]
            dq2.append((ts, target))
            while dq2 and ts - dq2[0][0] > self.sweep_window:
                dq2.popleft()
            targets = {t for _, t in dq2}
            if len(targets) >= self.sweep_targets and self._cooldown("sweep", smac, ts):
                return {"kind": "arp_sweep", "mac": smac, "src": m.group("sender"), "targets": len(targets),
                        "window": int(self.sweep_window), "ts": ts}
            return None
        m = DNS_Q.match(line)
        if m and self.domains:
            name = m.group("name").lower().rstrip(".")
            hit = domain_match(name, self.domains)
            if hit and self._cooldown("dns", name, float(m.group("ts")), 3600):
                return {"kind": "dns_threat", "src": m.group("src"), "domain": name, "matched": hit,
                        "list": "HaGeZi TIF mini", "ts": float(m.group("ts"))}
        return None


def domain_match(name: str, domains: Set[str]) -> Optional[str]:
    parts = name.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in domains:
            return cand
    return None


def load_domains(force: bool = False) -> Set[str]:
    path = str(paths.sub("feeds", "domains-tif-mini.txt"))
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400
    if force or not fresh:
        try:
            status, _, body = http_get(DOMAIN_FEED_URL, timeout=60, max_bytes=32 * 1024 * 1024)
            if status == 200 and body.count(b"\n") > 1000:
                atomic_write(path, body, 0o644)
                paths.chown_to_invoker(paths.sub("feeds", "domains-tif-mini.txt"))
        except FetchError as e:
            log.warning("domain feed download failed: %s", e)
    out: Set[str] = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    out.add(line)
    return out


def tcpdump_cmd(iface: str, own_ip: Optional[str]) -> List[str]:
    syn = "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn%s)" % (" and dst host %s" % own_ip if own_ip else "")
    return [find_cmd("tcpdump") or "tcpdump", "-l", "-n", "-e", "-tt", "-s", "256", "-i", iface,
            "arp or %s or (udp dst port 53)" % syn]


def run(iface: Optional[str] = None, use_domains: bool = True) -> int:
    from kekkai.platforms import get_platform
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        print("パケットセンサーは管理者権限が必要です:  sudo ./kekkai sensor", file=sys.stderr)
        return 2
    if not find_cmd("tcpdump"):
        print("tcpdump が見つかりません", file=sys.stderr)
        return 2
    plat = get_platform()
    ctx = plat.lan_context()
    iface = iface or ctx.interface
    if not iface:
        print("監視するネットワークインターフェースが見つかりません（-i en0 で指定）", file=sys.stderr)
        return 2
    domains = load_domains() if use_domains else set()
    det = Detector(ctx.ip, ctx.mac, ctx.gateway, ctx.gateway_mac, domains)
    spool = paths.sub("sensor", "events.jsonl")
    beat = paths.sub("sensor", "heartbeat")
    print("KEKKAI sensor: %s (%s) を監視中 / 危険ドメイン %d 件 / Ctrl+C で停止" % (iface, ctx.ip, len(domains)))
    proc = subprocess.Popen(tcpdump_cmd(iface, ctx.ip), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, errors="replace", bufsize=1)
    last_beat = 0.0
    last_ctx = time.time()
    try:
        assert proc.stdout is not None
        with open(str(spool), "a", encoding="utf-8") as out:
            paths.chown_to_invoker(spool)
            for line in proc.stdout:
                now = time.time()
                if now - last_beat > 5:
                    with open(str(beat), "w") as b:
                        b.write(str(now))
                    paths.chown_to_invoker(beat)
                    last_beat = now
                if now - last_ctx > 60:
                    c2 = plat.lan_context()
                    if c2.gateway_mac and c2.gateway == det.gateway_ip and det.gateway_mac is None:
                        det.gateway_mac = c2.gateway_mac
                    last_ctx = now
                ev = det.feed(line.rstrip("\n"))
                if ev:
                    out.write(json.dumps(ev, ensure_ascii=False) + "\n")
                    out.flush()
                    print("[!] %s %s" % (ev["kind"], {k: v for k, v in ev.items() if k not in ("kind", "ts")}))
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
    return 0
