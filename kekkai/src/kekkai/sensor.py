"""Optional packet sensor — `sudo kekkai sensor` (Snort/Wireshark-lite on top of tcpdump).

Reads only packet headers and DNS question names (snaplen 256) and detects:
  * port scans against this Mac      * ARP sweeps (LAN reconnaissance, e.g. netdiscover/arp-scan)
  * ARP replies impersonating the router (MITM)      * DNS lookups of known malicious domains
Events are appended to <state>/events.jsonl, which the dashboard ingests. <state> is a root-owned directory
(see state_dir): root never writes into folders the normal user controls, where a planted symlink could make
it create or chown arbitrary files.
"""
from __future__ import annotations

import collections
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from kekkai.netutil import is_public, neighbor_overlap, normalize_mac
from kekkai.util import FetchError, atomic_write, find_cmd, http_get, log

DOMAIN_FEED_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"
SPOOL_LIMIT = 20 * 1024 * 1024  # events.jsonl is rotated to events.jsonl.1 beyond this
HEARTBEAT_EVERY = 5.0   # seconds; the dashboard treats a heartbeat older than 30 s as "sensor stopped"
CONTEXT_EVERY = 30.0    # how often the sensor checks whether the Mac moved to another network
BTM_EVERY = 300.0       # how often the (root) sensor snapshots login/background items for the dashboard

ARP_REQ = re.compile(r"^(?P<ts>\d+\.\d+) (?P<smac>[0-9a-f:]{11,17}) > [0-9a-f:]{11,17}, ethertype ARP .*?"
                     r"Request who-has (?P<target>[\d.]+)(?: \([0-9a-f:]+\))? tell (?P<sender>[\d.]+)")
ARP_REP = re.compile(r"^(?P<ts>\d+\.\d+) (?P<smac>[0-9a-f:]{11,17}) > [0-9a-f:]{11,17}, ethertype ARP .*?"
                     r"Reply (?P<ip>[\d.]+) is-at (?P<mac>[0-9a-f:]{11,17})")
# Any SYN without ACK: "[S]" from nmap -sS, "[SEW]" from ECN-enabled connect() scans, "[FS]" etc.
TCP_SYN = re.compile(r"^(?P<ts>\d+\.\d+) .*?ethertype IPv[46] .*?: (?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+) > "
                     r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+): Flags \[[A-Za-z]*S[A-Za-z]*\]")
# "4001+ [1au] A? name. (42)"; "+%" when the CD bit is set; unknown types print as "Type65"; optional class.
DNS_Q = re.compile(r"^(?P<ts>\d+\.\d+) .*?: (?P<src>[0-9a-fA-F:.]+)\.\d+ > [0-9a-fA-F:.]+\.53: \d+[+%]*(?: \[[^\]]*\])* "
                   r"(?P<qtype>[A-Za-z0-9]+)(?: [^ ?]+)?\? (?P<name>[^ ]+?)\.? \(")


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
        if len(self._cool) > 50000:  # outbound connections add many keys: keep memory bounded
            self._cool = {kk: v for kk, v in self._cool.items() if ts - v < 3600}
        self._cool[k] = ts
        return True

    def feed(self, line: str) -> Optional[Dict[str, Any]]:
        m = TCP_SYN.match(line)
        if m:
            if self.own_ip and m.group("src") == self.own_ip:
                # every connection this Mac opens, even ones too short-lived for the 15 s connection poll
                dst, dport = m.group("dst"), int(m.group("dport"))
                ts = float(m.group("ts"))
                if is_public(dst) and self._cooldown("out", "%s:%d" % (dst, dport), ts):
                    return {"kind": "conn_out", "dst": dst, "dport": dport, "ts": ts}
                return None
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


def state_dir() -> Path:
    env = os.environ.get("KEKKAI_SENSOR_DIR")
    if env:
        return Path(env)
    return Path("/Library/Application Support/KEKKAI Sensor" if sys.platform == "darwin" else "/var/lib/kekkai-sensor")


def prepare_state_dir() -> Path:
    """Create the state directory and refuse one an unprivileged user could have tampered with."""
    d = state_dir()
    os.makedirs(str(d), mode=0o755, exist_ok=True)
    st = os.lstat(str(d))
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError("%s がディレクトリではありません（シンボリックリンク等）" % d)
    if not os.environ.get("KEKKAI_SENSOR_DIR") and (st.st_uid != 0 or st.st_mode & 0o022):
        raise RuntimeError("%s は root 所有で、他のユーザーが書き込めない必要があります" % d)
    return d


def load_domains(force: bool = False, download: bool = True) -> Set[str]:
    path = str(state_dir() / "domains-tif-mini.txt")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400
    if download and (force or not fresh):
        try:
            status, _, body = http_get(DOMAIN_FEED_URL, timeout=60, max_bytes=32 * 1024 * 1024)
            if status == 200 and body.count(b"\n") > 1000:
                atomic_write(path, body, 0o644)
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


def tcpdump_cmd(iface: Optional[str], own_ip: Optional[str], read_file: Optional[str] = None) -> List[str]:
    syn = "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn%s)" % (
        " and (dst host %s or src host %s)" % (own_ip, own_ip) if own_ip else "")
    src = ["-r", read_file] if read_file else ["-i", iface or "any"]
    return [find_cmd("tcpdump") or "tcpdump", "-l", "-n", "-e", "-tt", "-s", "256"] + src + [
        "arp or %s or (udp dst port 53)" % syn]


class Capture:
    """One tcpdump process. stderr is drained by a thread so a failing capture is reported instead of silent."""

    def __init__(self, cmd: List[str]):
        self.started = time.time()
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     errors="replace", bufsize=1)
        self.errors: Deque[str] = collections.deque(maxlen=6)
        self.listening = threading.Event()
        self._drainer = threading.Thread(target=self._drain, daemon=True)
        self._drainer.start()

    def _drain(self) -> None:
        assert self.proc.stderr is not None
        try:
            for line in self.proc.stderr:
                line = line.strip()
                if line.startswith("listening on"):
                    self.listening.set()
                elif line and "verbose output suppressed" not in line:
                    self.errors.append(line)
        except (ValueError, OSError):  # pipe closed by finish()
            pass

    def alive(self) -> bool:
        return self.proc.poll() is None

    def finish(self) -> int:
        rc = self.proc.wait()
        self._drainer.join(2)  # make sure the error text is collected before it is reported
        for pipe in (self.proc.stdout, self.proc.stderr):
            if pipe is not None:
                pipe.close()
        return rc

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def sensor_context(plat: Any, want: Optional[str] = None) -> Dict[str, Any]:
    ctx = plat.lan_context()
    if not want or want == ctx.interface:
        c: Dict[str, Any] = {"iface": ctx.interface, "ip": ctx.ip, "mac": ctx.mac, "gw": ctx.gateway,
                             "gw_mac": ctx.gateway_mac}
    else:  # -i for a non-default interface: use its own address, no router to guard
        itf = next((i for i in plat.interfaces() if i.name == want), None)
        c = {"iface": want, "ip": itf.ipv4[0][0] if itf and itf.ipv4 else None, "mac": itf.mac if itf else None,
             "gw": None, "gw_mac": None}
    neigh = [n for n in plat.neighbors() if n.mac and n.interface in (None, c["iface"])]
    c["macs"] = sorted({n.mac for n in neigh if n.mac != c["mac"]})
    # one MAC answering for the router *and* another IP is the classic sign of ARP spoofing
    c["gw_dup"] = bool(c["gw_mac"]) and any(n.mac == c["gw_mac"] and n.ip != c["gw"] for n in neigh)
    return c


def same_network(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Still the same LAN? A changed router MAC alone (ARP spoofing) does not make it a new network;
    a changed router MAC with mostly unknown neighbours does (home -> cafe with the same IP plan)."""
    if (a["iface"], a["ip"], a["gw"]) != (b["iface"], b["ip"], b["gw"]):
        return False
    if not a["gw_mac"] or not b["gw_mac"] or a["gw_mac"] == b["gw_mac"]:
        return True
    routers = (a["gw_mac"], b["gw_mac"])
    others_a = [m for m in a.get("macs") or [] if m not in routers]
    others_b = [m for m in b.get("macs") or [] if m not in routers]
    return bool(b.get("gw_dup")) or neighbor_overlap(others_a, others_b) >= 0.5


def refresh(cur: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Same network: keep the router MAC learned first — the ARP table may already be poisoned by the attacker."""
    if not new["iface"]:
        return cur
    if same_network(cur, new) and cur["gw_mac"]:
        return dict(new, gw_mac=cur["gw_mac"])
    return new


def _say(msg: str) -> None:
    print(msg, flush=True)  # stdout is block-buffered under launchd/CI/pipes: flush so status and alerts show up


def _beat(path: Any) -> None:
    try:
        with open(str(path), "w") as b:
            b.write(str(time.time()))
    except OSError:
        pass


def on_context(state: Dict[str, Any], new: Dict[str, Any]) -> None:
    cur = state["ctx"]
    if not new["iface"]:
        return  # offline for a moment: keep the current capture
    if not same_network(cur, new):
        # e.g. home -> cafe: the new router legitimately has another MAC, so watch it with a fresh context
        state["ctx"], state["restart"] = new, True
        if state.get("cap") is not None:
            state["cap"].stop()
    elif cur["gw_mac"] is None and new["gw_mac"]:
        cur["gw_mac"] = new["gw_mac"]
        if state.get("det") is not None:
            state["det"].gateway_mac = new["gw_mac"]
    elif cur["gw_mac"] == new["gw_mac"]:
        cur["macs"] = new["macs"]  # follow the LAN's devices over time, but never while the router MAC is disputed


def dump_btm(plat: Any) -> None:
    """Snapshot login/background items (needs root; sfltool returns nothing otherwise) for the dashboard."""
    try:
        items = plat.background_items()
    except Exception as e:  # noqa: BLE001
        log.debug("btm dump failed: %s", e)
        return
    if items:
        atomic_write(str(state_dir() / "btm.json"),
                     json.dumps({"ts": time.time(), "items": items}, ensure_ascii=False).encode(), 0o644)


def _keeper(stop: threading.Event, beat: Any, state: Dict[str, Any], plat: Any, want: Optional[str]) -> None:
    """Heartbeat while tcpdump is alive (even on a quiet network) and recapture when the Mac changes network."""
    last_ctx = time.time()
    last_btm = 0.0
    while not stop.wait(HEARTBEAT_EVERY):
        cap = state.get("cap")
        if cap is not None and cap.alive():
            _beat(beat)
        if time.time() - last_btm >= BTM_EVERY:
            last_btm = time.time()
            dump_btm(plat)
        if time.time() - last_ctx < CONTEXT_EVERY:
            continue
        last_ctx = time.time()
        try:
            on_context(state, sensor_context(plat, want))
        except Exception as e:  # noqa: BLE001
            log.debug("sensor context refresh failed: %s", e)


def _domain_refresher(stop: threading.Event, live: Dict[str, Any]) -> None:
    """Fetch the malicious-domain list in the background (capture must not wait for it) and daily after that."""
    while True:
        new = load_domains()
        if new and new != live["domains"]:
            live["domains"] = new
            if live.get("det") is not None:
                live["det"].domains = new
            _say("危険ドメインリストを読み込みました: %d 件" % len(new))
        if stop.wait(86400):
            return


def _interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


def run(iface: Optional[str] = None, use_domains: bool = True) -> int:
    from kekkai.platforms import get_platform
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        print("パケットセンサーは管理者権限が必要です:  sudo ./kekkai sensor", file=sys.stderr)
        return 2
    if not find_cmd("tcpdump"):
        print("tcpdump が見つかりません", file=sys.stderr)
        return 2
    plat = get_platform()
    ctx = sensor_context(plat, iface)
    if not ctx["iface"]:
        print("監視するネットワークインターフェースが見つかりません（-i en0 で指定）", file=sys.stderr)
        return 2
    os.umask(0o022)  # files stay readable (not writable) for the dashboard running as the normal user
    try:
        state = prepare_state_dir()
    except (OSError, RuntimeError) as e:
        print("センサーの保存先を準備できません: %s" % e, file=sys.stderr)
        return 2
    domains = load_domains(download=False) if use_domains else set()
    spool = state / "events.jsonl"
    beat = state / "heartbeat"
    signal.signal(signal.SIGTERM, _interrupt)  # kill / launchd stop -> same clean shutdown as Ctrl+C
    live: Dict[str, Any] = {"ctx": ctx, "restart": False, "cap": None, "det": None, "domains": domains}
    stop = threading.Event()
    threading.Thread(target=_keeper, args=(stop, beat, live, plat, iface), daemon=True).start()
    if use_domains:
        threading.Thread(target=_domain_refresher, args=(stop, live), daemon=True).start()
    ever_ok, backoff = False, 5.0
    out = None
    try:
        out = open(str(spool), "a", encoding="utf-8")
        while True:
            c = live["ctx"]
            det = Detector(c["ip"], c["mac"], c["gw"], c["gw_mac"], live["domains"])
            live["det"] = det
            cap = Capture(tcpdump_cmd(c["iface"], c["ip"]))
            live["cap"] = cap
            _say("KEKKAI sensor: %s (%s) を監視中 / 危険ドメイン %d 件 / Ctrl+C で停止" % (
                c["iface"], c["ip"] or "IP不明", len(live["domains"])))
            assert cap.proc.stdout is not None
            for line in cap.proc.stdout:
                ev = det.feed(line.rstrip("\n"))
                if ev:
                    out.write(json.dumps(ev, ensure_ascii=False) + "\n")
                    out.flush()
                    if ev["kind"] != "conn_out":  # connection records are data, not alerts
                        _say("[!] %s %s" % (ev["kind"], {k: v for k, v in ev.items() if k not in ("kind", "ts")}))
                    if out.tell() > SPOOL_LIMIT:
                        out.close()
                        os.replace(str(spool), str(spool) + ".1")
                        out = open(str(spool), "a", encoding="utf-8")
            rc = cap.finish()
            if cap.listening.is_set() or time.time() - cap.started > 5:
                ever_ok, backoff = True, (5.0 if time.time() - cap.started > 60 else backoff)
            if live["restart"]:
                live["restart"] = False
                _say("ネットワークの変更を検知しました。新しい設定で監視を再開します")
                continue
            why = " / ".join(cap.errors) or "終了コード %s" % rc
            if not ever_ok:
                print("tcpdump を開始できませんでした: %s" % why, file=sys.stderr, flush=True)
                return 1
            print("tcpdump が停止しました（%s）。%d 秒後に再開します" % (why, backoff), file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
            live["ctx"] = refresh(live["ctx"], sensor_context(plat, iface))
    except KeyboardInterrupt:
        return 0
    finally:
        stop.set()
        if out is not None:
            out.close()
        if live["cap"] is not None:
            live["cap"].stop()
            live["cap"].finish()
