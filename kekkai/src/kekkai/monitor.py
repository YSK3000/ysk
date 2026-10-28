"""The monitor: runs collectors on schedules, enriches, detects, stores, publishes live state."""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from kekkai import __version__, paths
from kekkai.audit import run_audit
from kekkai.detect import engine as rules
from kekkai.detect.engine import Finding
from kekkai.discovery import lan as lanmod
from kekkai.discovery import nmap as nmapmod
from kekkai.discovery.portscan import ScopeError, scan_host
from kekkai.intel import updater
from kekkai.intel.exposure import assess, internetdb, public_ip
from kekkai.intel.feeds import SEV_RANK, FeedSet
from kekkai.intel.geo import Geo
from kekkai.intel.oui import OUI
from kekkai.intel.vulns import VulnDB
from kekkai.netutil import is_local_target, is_public, neighbor_overlap
from kekkai.notify import Notifier
from kekkai.platforms import get_platform
from kekkai.platforms.base import Connection, LanContext
from kekkai.store import Store
from kekkai.util import FetchError, log

DEFAULT_HOME = {"lat": None, "lon": None, "label": "HOME", "source": "unknown"}


class EventBus:
    def __init__(self) -> None:
        self._subs: List["queue.Queue[Tuple[str, Any]]"] = []
        self._lock = threading.Lock()

    def subscribe(self) -> "queue.Queue[Tuple[str, Any]]":
        q: "queue.Queue[Tuple[str, Any]]" = queue.Queue(maxsize=200)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Tuple[str, Any]]") -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, kind: str, data: Any) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait((kind, data))
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait((kind, data))
                except (queue.Empty, queue.Full):
                    pass


# Shown until the first check has finished: never claim "SECURE" before anything was looked at.
CHECKING: Dict[str, Any] = {"level": 0, "label": "CHECKING", "counts": {}}


class Monitor:
    def __init__(self, cfg: Any, store: Optional[Store] = None, platform: Any = None):
        self.cfg = cfg
        self.platform = platform or get_platform()
        self.store = store or Store(str(paths.sub("kekkai.db")))
        self.geo = Geo()
        self.feeds = FeedSet()
        self.oui = OUI()
        self.vulns = VulnDB()
        self.notifier = Notifier(cfg, self.platform)
        self.bus = EventBus()
        self.lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._lifecycle_lock = threading.Lock()
        self._intel_cache: Dict[str, Tuple[float, Dict[str, Any], List[Dict[str, Any]]]] = {}
        self._intel_epoch = 0.0
        self._prev_net: Optional[Dict[str, Any]] = self.store.kv_get("last_network")
        self._sensor_offset = 0
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.started = time.time()
        # Injection points (tests swap these out).
        self._discover = lanmod.discover
        self._public_ip = public_ip
        self._internetdb = internetdb
        self._scan = scan_host
        self._deep_scan = nmapmod.scan
        self._deep_available = nmapmod.available
        self._audit = run_audit
        self.state: Dict[str, Any] = {
            "version": __version__, "platform": self.platform.name, "started": self.started,
            "network": None, "home": dict(DEFAULT_HOME), "connections": [], "listeners": [], "neighbors": [],
            "dns": [], "proxies": {}, "wifi": None, "persistence": [], "posture": None, "exposure": None,
            "upnp": None, "lan": {"running": False, "last": None, "stats": None},
            "health": {}, "sensor": {"active": False}, "leaks": None, "cycle": 0,
        }
        self._load_home()

    # ------------------------------------------------------------ helpers
    def _health(self, name: str, ok: bool, duration: float, error: Optional[str] = None) -> None:
        with self.lock:
            h = self.state["health"].setdefault(name, {"runs": 0, "errors": 0})
            h["runs"] += 1
            h["duration"] = round(duration, 2)
            if ok:
                h["last_ok"] = time.time()
                h.pop("last_error", None)
            else:
                h["errors"] += 1
                h["last_error"] = (error or "?")[:400]
                h["error_ts"] = time.time()

    def _safe(self, name: str, fn: Callable[[], Any], default: Any) -> Any:
        try:
            result = fn()
            with self.lock:
                self.state["health"].setdefault("collectors", {}).pop(name, None)
            return result
        except Exception as e:  # noqa: BLE001 - a broken collector must never kill the monitor
            log.exception("collector %s failed", name)
            with self.lock:
                self.state["health"].setdefault("collectors", {})[name] = "%s: %s" % (type(e).__name__, e)
            return default

    def _load_home(self) -> None:
        lat, lon = self.cfg.get("home.lat"), self.cfg.get("home.lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            self.state["home"] = {"lat": lat, "lon": lon, "label": self.cfg.get("home.label", "HOME"), "source": "config"}
        else:
            saved = self.store.kv_get("home_geo")
            if isinstance(saved, dict) and saved.get("lat") is not None:
                self.state["home"] = saved

    def intel(self, ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        epoch = os.path.getmtime(self.feeds.meta_path) if os.path.exists(self.feeds.meta_path) else 0.0
        if epoch != self._intel_epoch:
            self._intel_cache.clear()
            self._intel_epoch = epoch
        hit = self._intel_cache.get(ip)
        if hit and time.time() - hit[0] < 3600:
            return hit[1], hit[2]
        g = self.geo.lookup(ip)
        t = self.feeds.match(ip)
        if len(self._intel_cache) > 20000:
            self._intel_cache.clear()
        self._intel_cache[ip] = (time.time(), g, t)
        return g, t

    # ------------------------------------------------------------ network identity
    def resolve_network(self, ctx: LanContext, neighbor_macs: List[str]) -> Dict[str, Any]:
        """Stable id for "this LAN" that survives a spoofed gateway MAC (so spoofing is detectable)."""
        subnet = str(ctx.network) if ctx.network else None
        prev = self._prev_net
        net_id = None
        if prev and subnet and prev.get("subnet") == subnet and prev.get("gateway") == ctx.gateway:
            if prev.get("gateway_mac") == ctx.gateway_mac or neighbor_overlap(prev.get("macs", []), neighbor_macs) >= 0.5:
                net_id = prev["id"]
        if net_id is None:
            if ctx.gateway_mac:
                net_id = "gw-" + ctx.gateway_mac.replace(":", "")
            elif subnet:
                net_id = "net-" + subnet.replace("/", "_")
            else:
                net_id = "offline"
        first_ever = not [n for n in self.store.networks() if n["id"] != "offline"]
        row = self.store.touch_network(net_id, ctx.gateway, subnet, None)
        if first_ever and net_id != "offline":
            self.store.update_network(net_id, label="自宅", trusted=True)
            row = self.store.network(net_id) or row
        cur = {"id": net_id, "subnet": subnet, "gateway": ctx.gateway, "gateway_mac": ctx.gateway_mac,
               "macs": sorted(set(neighbor_macs))[:256]}
        if prev is None or prev.get("id") != net_id:
            if prev is not None:
                self.store.log_event("network", "ネットワークが切り替わりました: %s → %s" % (prev.get("id"), net_id))
        if prev != cur:
            self._prev_net = cur
            self.store.kv_set("last_network", cur)
        return row

    # ------------------------------------------------------------ enrichment
    def build_listeners(self, conns: List[Connection]) -> List[Dict[str, Any]]:
        merged: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for c in conns:
            if not c.is_listen or c.lport == 0:
                continue
            key = (c.proto, c.lport)
            ent = merged.setdefault(key, {"proto": c.proto, "port": c.lport, "addrs": [], "process": c.process,
                                          "pid": c.pid, "path": c.path, "exposed": False})
            if c.laddr not in ent["addrs"]:
                ent["addrs"].append(c.laddr)
            ent["exposed"] = ent["exposed"] or rules.is_exposed_addr(c.laddr)
            ent["process"] = ent["process"] or c.process
            ent["path"] = ent["path"] or c.path
        out = sorted(merged.values(), key=lambda item: (item["proto"], item["port"]))
        for item in out:
            item["sensitive"] = item["port"] in rules.SENSITIVE_PORTS and item["proto"] == "tcp"
            item["service"] = rules.SENSITIVE_PORTS.get(item["port"])
        return out

    def enrich_connections(self, conns: List[Connection], listeners: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        listen = {(item["proto"], item["port"]) for item in listeners}
        susp = set(int(p) for p in self.cfg.get("rules.suspicious_remote_ports", []) or [])
        out = []
        for c in conns:
            if c.is_listen or c.raddr in ("*", "") or c.rport == 0:
                continue
            d = c.to_dict()
            d["direction"] = "in" if (c.proto, c.lport) in listen and c.state in ("ESTABLISHED", "") else "out"
            risk = 0
            flags = []
            if is_public(c.raddr):
                g, threats = self.intel(c.raddr)
                d["geo"] = g
                d["threats"] = threats
                d["scope"] = "internet"
                for t in threats:
                    r = 1 if t["kind"] == "tor-exit" else SEV_RANK.get(t["severity"], 0)
                    risk = max(risk, r)
                    flags.append(t["feed"])
                if c.path:
                    lookup = getattr(self.platform, "code_signature_cached", self.platform.code_signature)
                    sig = lookup(c.path)
                    d["signature"] = sig
                    if sig.get("checked"):
                        if not sig.get("signed"):
                            risk = max(risk, 2)
                            flags.append("unsigned")
                if rules.suspicious_path(c.path):
                    risk = max(risk, 3)
                    flags.append("suspicious-path")
                if d["direction"] == "out" and c.rport in susp and c.proto == "tcp":
                    risk = max(risk, 2)
                    flags.append("port-%d" % c.rport)
            else:
                d["scope"] = "lan" if is_local_target(c.raddr) else "other"
                if c.raddr.startswith("127.") or c.raddr == "::1":
                    d["scope"] = "local"
            d["risk"] = ["ok", "low", "medium", "high", "critical"][risk]
            d["flags"] = flags
            out.append(d)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
        out.sort(key=lambda d: (order[d["risk"]], d["scope"] != "internet", d.get("process") or ""))
        return out

    # ------------------------------------------------------------ alert plumbing
    def raise_findings(self, findings: List[Finding], net_id: Optional[str], learning: bool = False) -> List[Dict[str, Any]]:
        muted = set(self.cfg.get("rules.muted", []) or [])
        new_alerts = []
        for f in rules.dedupe(findings):
            if f.rule in muted or (learning and f.rule in rules.LEARNING_SILENT):
                continue
            alert, is_new = self.store.raise_alert(net_id, f.rule, f.severity, f.title, f.detail, f.advice,
                                                   f.subject, f.data)
            if is_new:
                new_alerts.append(alert)
                self.bus.publish("alert", alert)
                self.notifier.alert(alert)
        return new_alerts

    def threat_summary(self) -> Dict[str, Any]:
        counts = self.store.alert_counts()
        level, label = rules.threat_level(counts)
        return {"level": level, "label": label, "counts": counts}

    # ------------------------------------------------------------ cycles
    def fast_cycle(self) -> Dict[str, Any]:
        t0 = time.time()
        p = self.platform
        ctx = self._safe("lan_context", p.lan_context, LanContext())
        neighbors = self._safe("neighbors", p.neighbors, [])
        conns = self._safe("connections", p.connections, [])
        dns = self._safe("dns", p.dns_servers, [])
        proxies = self._safe("proxies", p.proxies, {})
        with self.lock:
            failures = {k: v for k, v in self.state["health"].get("collectors", {}).items()
                        if k in ("lan_context", "neighbors", "connections", "dns", "proxies")}
        if failures:
            # Keep the last successful snapshot and baselines; an empty result from
            # a failed command is not evidence that a connection or setting disappeared.
            raise RuntimeError("収集失敗: " + "; ".join("%s: %s" % item for item in failures.items()))
        neigh_dicts = [n.to_dict() for n in neighbors if n.mac]
        net = self.resolve_network(ctx, [n["mac"] for n in neigh_dicts])
        net_id = net["id"]
        cycles = self.store.bump_cycles(net_id)
        learning = cycles <= int(self.cfg.get("monitor.learning_cycles", 2))
        listeners = self.build_listeners(conns)
        enriched = self.enrich_connections(conns, listeners)
        susp = set(int(x) for x in self.cfg.get("rules.suspicious_remote_ports", []) or [])

        findings: List[Finding] = rules.connection_findings(enriched, susp)
        gw_key = "baseline:%s:gateway_mac" % net_id
        prev_gw = self.store.kv_get(gw_key)
        arp = rules.arp_findings(neigh_dicts, ctx.gateway, prev_gw, ctx.gateway_mac)
        findings += arp
        if ctx.gateway_mac and (prev_gw is None or not any(f.rule == "lan.arp_spoof" for f in arp)):
            self.store.kv_set(gw_key, ctx.gateway_mac)

        lkey = "baseline:listeners"
        lbase = self.store.kv_get(lkey)
        current_keys = [rules.listener_key(item) for item in listeners if item["proto"] == "tcp" and item["exposed"]]
        if lbase is None:
            self.store.kv_set(lkey, current_keys)
        else:
            findings += rules.listener_findings(listeners, set(lbase), not net.get("trusted"))
            merged = sorted(set(lbase) | set(current_keys))[-500:]
            if merged != sorted(lbase):
                self.store.kv_set(lkey, merged)

        dkey = "baseline:%s:dns" % net_id
        dbase = self.store.kv_get(dkey)
        if dns:
            if dbase is None:
                self.store.kv_set(dkey, dns)
            else:
                findings += rules.dns_findings(dns, dbase)
                union = list(dict.fromkeys(list(dbase) + dns))[-16:]
                if union != dbase:
                    self.store.kv_set(dkey, union)
        pkey = "baseline:proxies"
        pbase = self.store.kv_get(pkey)
        if pbase is None:
            self.store.kv_set(pkey, proxies)
        else:
            findings += rules.proxy_findings(proxies, pbase)
            if proxies != pbase:
                self.store.kv_set(pkey, proxies)

        self.raise_findings(findings, net_id, learning)
        dest = [{"ip": c["raddr"], "port": c["rport"], "proto": c["proto"], "process": c.get("process"),
                 "country": (c.get("geo") or {}).get("country"), "city": (c.get("geo") or {}).get("city"),
                 "asn": (c.get("geo") or {}).get("asn"), "org": (c.get("geo") or {}).get("org"),
                 "lat": (c.get("geo") or {}).get("lat"), "lon": (c.get("geo") or {}).get("lon"), "risk": c["risk"]}
                for c in enriched if c.get("scope") == "internet"]
        if dest:
            self._safe("record_destinations", lambda: self.store.record_destinations(dest), None)
        public = [c for c in enriched if c.get("scope") == "internet"]
        network = dict(net, interface=ctx.interface, kind=ctx.kind, ip=ctx.ip, prefixlen=ctx.prefixlen,
                       gateway=ctx.gateway, gateway_mac=ctx.gateway_mac, vpn_active=ctx.vpn_active,
                       default_via=ctx.default_via, learning=learning)
        with self.lock:
            self.state.update({
                "ts": time.time(), "network": network, "connections": enriched[:600], "listeners": listeners,
                "neighbors": neigh_dicts, "dns": dns, "proxies": proxies, "cycle": self.state["cycle"] + 1,
                "stats": {"connections": len(enriched), "internet": len(public),
                          "countries": len({(c.get("geo") or {}).get("country") for c in public} - {None}),
                          "processes": len({c.get("process") for c in public}),
                          "risky": len([c for c in enriched if c["risk"] not in ("ok",)]),
                          "devices": len(self.store.devices(net_id)), "listeners": len([item for item in listeners if item["exposed"]])},
                "threat": self.threat_summary(),
            })
        self._health("fast", True, time.time() - t0)
        self.bus.publish("state", self.summary())
        return network

    def lan_cycle(self, active: Optional[bool] = None) -> Dict[str, Any]:
        t0 = time.time()
        with self.lock:
            if self.state["lan"].get("running"):
                return {"busy": True}
            self.state["lan"]["running"] = True
        self.bus.publish("lan", {"running": True})
        try:
            ctx = self.platform.lan_context()
            act = self.cfg.get("monitor.active_sweep", True) if active is None else active
            res = self._discover(self.platform, ctx, self.oui, active=act)
            net = self.resolve_network(ctx, [d["mac"] for d in res["devices"] if d.get("mac") and d["kind"] != "this"])
            net_id = net["id"]
            bkey = "lan_baseline:%s" % net_id
            baselined = bool(self.store.kv_get(bkey))
            findings: List[Finding] = []
            new_ips: List[str] = []
            for d in res["devices"]:
                fields = {k: d.get(k) for k in ("vendor", "hostname", "kind", "model", "services", "upnp")}
                fields["randomized"] = d.get("randomized")
                row, is_new = self.store.upsert_device(net_id, d["mac"], d["ip"], **fields)
                if is_new and d["kind"] != "this" and d.get("ip"):
                    new_ips.append(d["ip"])
                if is_new and baselined and net.get("trusted") and d["kind"] != "this":
                    findings.append(rules.new_device_finding(d))
                if d["kind"] != "this":
                    up = d.get("upnp") or {}
                    hits = self.vulns.device_hits(up.get("manufacturer") or d.get("vendor"),
                                                  [d.get("model"), up.get("modelName"), up.get("modelNumber")])
                    findings += rules.device_vuln_findings(d, hits)
            if not baselined:
                self.store.kv_set(bkey, True)
                self.store.log_event("lan", "ベースライン学習: %d台の機器を登録" % len(res["devices"]))
            igd = res.get("igd")
            if igd is not None:
                ukey = "baseline:%s:upnp" % net_id
                keys = ["%s/%s->%s:%s" % (m.get("external_port"), m.get("protocol"), m.get("internal_client"),
                                          m.get("internal_port")) for m in igd.get("mappings", [])]
                ubase = self.store.kv_get(ukey)
                if ubase is not None:
                    for m, k in zip(igd.get("mappings", []), keys):
                        if k not in ubase:
                            findings.append(Finding(
                                "exposure.upnp_new", "high", "ルーターに新しいポート開放(UPnP)が追加されました",
                                "外部ポート %s/%s → %s:%s（%s）" % (m.get("external_port"), m.get("protocol"),
                                                                 m.get("internal_client"), m.get("internal_port"),
                                                                 m.get("description") or "説明なし"),
                                "機器が自動でインターネットに穴を開けました。ゲーム機等で心当たりがなければ、転送先の機器を調べ、"
                                "ルーターのUPnPを無効化してください（IoTマルウェアの常套手段です）。",
                                subject=k, data=m))
                elif keys:
                    findings.append(Finding(
                        "exposure.upnp_mappings", "low", "ルーターにUPnPのポート開放が %d 件あります" % len(keys),
                        "、".join(keys[:8]), "外部公開ページで内容を確認し、不要なものはルーターで削除してください。",
                        subject=net_id, data={"mappings": igd.get("mappings", [])}))
                self.store.kv_set(ukey, sorted(set(keys) | set(ubase or [])))
            self.raise_findings(findings, net_id)
            if new_ips and self.cfg.get("scan.deep_new_devices", False) and self._deep_available():
                threading.Thread(target=self._autoscan_devices, args=(net_id, new_ips), daemon=True,
                                 name="kekkai-autoscan").start()
            with self.lock:
                self.state["lan"] = {"running": False, "last": time.time(), "stats": res["stats"]}
                if igd is not None:
                    self.state["upnp"] = igd
            self._health("lan", True, time.time() - t0)
            self.bus.publish("lan", {"running": False, "stats": res["stats"]})
            return res["stats"]
        except Exception as e:
            with self.lock:
                self.state["lan"]["running"] = False
            self._health("lan", False, time.time() - t0, repr(e))
            raise

    def _collect_btm(self) -> List[Dict[str, Any]]:
        """Login/background items. sfltool needs root, so prefer the root sensor's recent snapshot;
        fall back to a direct read (works only if the dashboard itself runs as root)."""
        from kekkai.sensor import state_dir
        snap = state_dir() / "btm.json"
        try:
            if snap.exists() and time.time() - snap.stat().st_mtime < 86400:
                with open(str(snap), "r", encoding="utf-8") as f:
                    return json.load(f).get("items") or []
        except (OSError, ValueError):
            pass
        return self._safe("background_items", self.platform.background_items, [])

    def posture_cycle(self, slow: bool = False) -> Dict[str, Any]:
        t0 = time.time()
        wifi = self._safe("wifi", self.platform.wifi, None)
        persistence = self._safe("persistence", self.platform.persistence_items, [])
        for item in persistence:
            item["flag"] = rules.persistence_flag(item)
        net_id = (self.state.get("network") or {}).get("id")
        pkey = "baseline:persistence"
        pbase = self.store.kv_get(pkey)
        findings: List[Finding] = []
        cur = {p["plist"]: p.get("mtime") or 0 for p in persistence}
        if pbase is None:
            self.store.kv_set(pkey, cur)
        else:
            findings += rules.persistence_findings(persistence, pbase)
            if cur != pbase:
                self.store.kv_set(pkey, cur)
        findings += rules.wifi_findings(wifi)
        btm = self._collect_btm()
        bkey2 = "baseline:btm"
        bbase = self.store.kv_get(bkey2)
        cur_btm = [rules.btm_key(x) for x in btm]
        if bbase is None:
            self.store.kv_set(bkey2, cur_btm)
        else:
            findings += rules.btm_findings(btm, bbase)
            if set(cur_btm) != set(bbase):
                self.store.kv_set(bkey2, sorted(set(bbase) | set(cur_btm)))
        with self.lock:
            snap = {"dns": self.state.get("dns"), "proxies": self.state.get("proxies"), "wifi": wifi,
                    "listeners": self.state.get("listeners"), "persistence": persistence, "background_items": btm}
        audit = self._audit(snap, slow=slow)
        mac = self.vulns.macos(self._safe("os_version", self.platform.os_version, None))
        vf = rules.macos_vuln_findings(mac)
        findings += vf
        if mac and not mac.get("unknown_line"):
            audit = self._with_vuln_check(audit, mac, vf)
        if wifi and wifi.get("ssid") and net_id:
            self.store.touch_network(net_id, (self.state.get("network") or {}).get("gateway"),
                                     (self.state.get("network") or {}).get("subnet"), str(wifi.get("ssid")))
        self.raise_findings(findings, net_id)
        with self.lock:
            self.state.update({"wifi": wifi, "persistence": persistence, "posture": audit})
        self._health("posture", True, time.time() - t0)
        self.bus.publish("posture", {"score": audit.get("score")})
        return audit

    @staticmethod
    def _with_vuln_check(audit: Dict[str, Any], mac: Dict[str, Any], vf: List[Finding]) -> Dict[str, Any]:
        """Show the version-based vulnerability result in the posture audit too, and re-score."""
        from kekkai.audit import check, score
        if vf:
            status = "fail" if vf[0].severity == "high" else "warn"
            detail, fix = vf[0].title, vf[0].advice
        else:
            status, detail, fix = "pass", "macOS %s に既知の未修正脆弱性はありません（%s の最新）" % (mac["version"], mac["line"]), ""
        checks = [c for c in audit.get("checks") or [] if c.get("id") != "macos_vulns"]
        checks.append(check("macos_vulns", "既知の脆弱性（macOS）", status, detail, fix, "update", 10))
        out = dict(audit, checks=checks)
        out.update(score(checks))
        return out

    def exposure_cycle(self) -> Dict[str, Any]:
        t0 = time.time()
        if not self.cfg.get("privacy.external_lookups", True):
            res = {"disabled": True, "checked_at": time.time(), "findings": []}
            with self.lock:
                self.state["exposure"] = res
            return res
        pub = self._public_ip()
        idb, err = None, None
        if pub:
            try:
                idb = self._internetdb(pub)
            except (FetchError, ValueError) as e:
                err = str(e)
        res = assess(pub, idb, self.state.get("upnp"))
        if err:
            res["error"] = err
        if pub and self.state["home"].get("source") != "config":
            g = self.geo.lookup(pub)
            if g.get("lat") is not None:
                home = {"lat": g["lat"], "lon": g["lon"], "label": "HOME", "city": g.get("city"), "source": "geoip"}
                self.store.kv_set("home_geo", home)
                with self.lock:
                    self.state["home"] = home
        findings = []
        if not res.get("shared_ipv4"):
            for f in res["findings"]:
                if f["severity"] in ("high", "medium") and not f["title"].startswith("UPnP"):
                    findings.append(Finding("exposure.internetdb", f["severity"], f["title"], f["detail"],
                                            "ルーターのポート開放・UPnP・公開サーバー設定を見直してください。Shodanのデータは週1回更新です。",
                                            subject="%s:%s" % (pub, f.get("port", f["title"])), data=f))
        if not res.get("shared_ipv4"):
            findings += rules.exposure_kev_findings(pub, self.vulns.kev_for(((res.get("internetdb") or {}).get("vulns")) or []))
        # Alert only on what is NEWLY visible from the internet since the last check (ports/CVEs
        # that just appeared), so steady exposure is not re-alerted every cycle but a fresh hole
        # (e.g. UPnP just opened a port, or a new CVE got associated) is caught fast.
        idbd = res.get("internetdb") or {}
        if pub and idbd.get("found") and not res.get("shared_ipv4"):
            cur_ports = sorted({int(p) for p in idbd.get("ports", []) if str(p).isdigit()})
            cur_vulns = sorted({str(v) for v in idbd.get("vulns", [])})
            bkey = "exposure_baseline:%s" % pub
            base = self.store.kv_get(bkey)
            if base is not None:
                new_ports = [p for p in cur_ports if p not in set(base.get("ports", []))]
                new_vulns = [v for v in cur_vulns if v not in set(base.get("vulns", []))]
                if new_ports or new_vulns:
                    parts = []
                    if new_ports:
                        parts.append("ポート: " + "、".join(str(p) for p in new_ports))
                    if new_vulns:
                        parts.append("CVE: " + "、".join(new_vulns[:12]))
                    findings.append(Finding(
                        "exposure.new_exposure", "high",
                        "インターネットから新たに見える項目が増えました",
                        " / ".join(parts),
                        "前回の確認時には外部から見えなかったものです。ルーターのポート開放・UPnP・公開サーバー設定を"
                        "至急確認してください（心当たりが無ければ第三者による開放の疑い）。",
                        subject="%s:new" % pub, data={"new_ports": new_ports, "new_vulns": new_vulns}))
            self.store.kv_set(bkey, {"ports": cur_ports, "vulns": cur_vulns})
        net_id = (self.state.get("network") or {}).get("id")
        self.raise_findings(findings, net_id)
        with self.lock:
            self.state["exposure"] = res
        self._health("exposure", True, time.time() - t0)
        return res

    def intel_cycle(self, force: bool = False) -> Dict[str, Any]:
        t0 = time.time()
        report: Dict[str, Any] = {}
        report["feeds"] = self.feeds.update(self.cfg.get("intel.feeds"), self.cfg.get("intel.update_interval_hours", 12),
                                            force=force)
        report["geo_city"] = updater.update_geo("city", force=force)
        report["geo_asn"] = updater.update_geo("asn", force=force)
        report["oui"] = updater.update_oui(force=force)
        from kekkai.intel import vulns as vulnmod
        report["vulns"] = vulnmod.update(force=force)
        self._intel_cache.clear()
        self.store.log_event("intel", "脅威情報を更新しました", report)
        self._health("intel", True, time.time() - t0)
        return report

    def leak_watch_targets(self) -> List[str]:
        return [str(x) for x in (self.cfg.get("watch.names", []) or []) + (self.cfg.get("watch.domains", []) or []) if str(x).strip()]

    def leak_cycle(self, force: bool = False) -> Dict[str, Any]:
        t0 = time.time()
        targets = self.leak_watch_targets()
        if not targets or not self.cfg.get("privacy.external_lookups", True):
            with self.lock:
                self.state["leaks"] = {"enabled": False, "targets": targets}
            return {"skipped": "not configured"}
        from kekkai.intel import leaks
        res = leaks.check(targets)
        self.raise_findings(rules.leak_findings(res), (self.state.get("network") or {}).get("id"))
        with self.lock:
            self.state["leaks"] = {"enabled": True, "targets": targets, "match_count": res["match_count"],
                                   "checked_at": res["ts"], "error": (res["sources"][0] or {}).get("error")}
        self._health("leak", True, time.time() - t0)
        return res

    def sensor_cycle(self) -> None:
        from kekkai.sensor import state_dir
        spool = str(state_dir() / "events.jsonl")
        with self.lock:
            self.state["sensor"] = self.sensor_status()
        if not os.path.exists(spool):
            return
        size = os.path.getsize(spool)
        if size < self._sensor_offset:
            self._sensor_offset = 0
        if size == self._sensor_offset:
            return
        with open(spool, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self._sensor_offset)
            chunk = f.read(4 * 1024 * 1024)
            self._sensor_offset = f.tell()
        findings = []
        polled = {c.get("raddr") for c in self.snapshot("connections") or []}
        for line in chunk.splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("kind") == "conn_out":
                if ev.get("dst") in polled:
                    continue  # the connection poll sees it too, and knows which app it is
                g, threats = self.intel(str(ev.get("dst")))
                fnd = rules.sensor_conn_finding(ev, threats, g)
            else:
                fnd = rules.sensor_finding(ev)
            if fnd:
                findings.append(fnd)
        self.raise_findings(findings, (self.state.get("network") or {}).get("id"))

    # ------------------------------------------------------------ scans
    def resolve_scan_mode(self, mode: str) -> str:
        """'auto' -> 'deep' when nmap is usable (config scan.use_nmap and installed), else 'quick'."""
        if mode != "auto":
            return mode
        if self.cfg.get("scan.use_nmap", True) and self._deep_available():
            return "deep"
        return "quick"

    def start_scan(self, ip: str, mode: str = "quick") -> Dict[str, Any]:
        if not is_local_target(ip):
            raise ScopeError("LAN内(プライベートIP)のみスキャンできます")
        mode = self.resolve_scan_mode(mode)
        if mode == "deep" and not self._deep_available():
            raise RuntimeError("詳細スキャンには nmap が必要です（brew install nmap）")
        running = [j for j in self.jobs.values() if j["status"] == "running"]
        if len(running) >= 3:
            raise RuntimeError("同時に実行できるスキャンは3件までです")
        job = {"id": uuid.uuid4().hex[:12], "ip": ip, "mode": mode, "status": "running", "started": time.time()}
        self.jobs[job["id"]] = job
        threading.Thread(target=self._run_scan, args=(job,), daemon=True, name="scan-" + ip).start()
        return job

    def _run_scan(self, job: Dict[str, Any]) -> None:
        try:
            if job["mode"] == "deep":
                res = self._deep_scan(job["ip"])
            else:
                res = self._scan(job["ip"], timeout=float(self.cfg.get("scan.timeout_sec", 0.8)),
                                concurrency=int(self.cfg.get("scan.concurrency", 256)))
            net_id = (self.state.get("network") or {}).get("id")
            self.store.save_scan(net_id, job["ip"], job["mode"], res)
            dev = self.store.device_by_ip(net_id, job["ip"]) if net_id else None
            if dev:
                self.store.set_device_ports(net_id, dev["mac"], res["open"])
            self.raise_findings(rules.risky_service_findings(dev or {"ip": job["ip"]}, res), net_id)
            job.update(status="done", result=res, finished=time.time())
        except Exception as e:  # noqa: BLE001
            job.update(status="error", error=str(e), finished=time.time())
        self.bus.publish("scan", dict(job))
        old = [k for k, j in self.jobs.items() if j["status"] != "running" and time.time() - j.get("finished", 0) > 3600]
        for k in old:
            self.jobs.pop(k, None)

    def _autoscan_devices(self, net_id: Optional[str], ips: List[str]) -> None:
        """Deep-scan (nmap -sV) newly found LAN devices once, sequentially, to learn their services.
        LAN-only (is_local_target), best-effort: one slow host must not stop the rest or the monitor."""
        for ip in ips:
            if self._stop.is_set():
                return
            if not is_local_target(ip):
                continue
            try:
                res = self._deep_scan(ip)
            except Exception as e:  # noqa: BLE001  one unreachable/odd host must not abort the sweep
                self.store.log_event("lan", "自動詳細スキャン失敗 %s: %s" % (ip, e))
                continue
            dev = self.store.device_by_ip(net_id, ip) if net_id else None
            if dev:
                self.store.set_device_ports(net_id, dev["mac"], res["open"])
            self.raise_findings(rules.risky_service_findings(dev or {"ip": ip}, res), net_id)

    # ------------------------------------------------------------ views
    def sensor_status(self) -> Dict[str, Any]:
        from kekkai.sensor import state_dir
        try:
            last = (state_dir() / "heartbeat").stat().st_mtime
        except OSError:
            last = None
        return {"active": last is not None and 0 <= time.time() - last < 30, "last_beat": last}

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            s = self.state
            return {"ts": s.get("ts"), "version": s["version"], "platform": s["platform"], "network": s.get("network"),
                    "home": s.get("home"), "stats": s.get("stats"), "threat": s.get("threat") or CHECKING, "lan": s.get("lan"),
                    "sensor": self.sensor_status(), "cycle": s.get("cycle"), "monitoring": self.monitoring_status(),
                    "posture_score": (s.get("posture") or {}).get("score"), "health": s.get("health"),
                    "exposure_checked_at": (s.get("exposure") or {}).get("checked_at"),
                    "geo": self.geo.available, "feeds_entries": self.feeds.total_entries}

    def monitoring_status(self) -> Dict[str, Any]:
        with self.lock:
            health = self.state["health"]
            last = self.state.get("ts")
            errors = dict(health.get("collectors", {}))
            if health.get("fast", {}).get("last_error"):
                errors["fast"] = health["fast"]["last_error"]
            age = max(0, time.time() - last) if last is not None else None
            limit = max(30, float(self.cfg.get("monitor.interval_sec", 15)) * 3)
            if self._stop.is_set():
                status, label = "stopped", "監視停止"
            elif errors:
                status, label = "error", "収集エラー"
            elif last is None:
                status, label = "starting", "初回収集中"
            elif age > limit:
                status, label = "stale", "更新停止"
            elif not (self.state.get("network") or {}).get("interface"):
                status, label = "offline", "ネットワーク未接続"
            else:
                status, label = "live", "実監視中"
            return {"status": status, "label": label, "last_success": last,
                    "age_sec": round(age, 1) if age is not None else None,
                    "stale_after_sec": limit, "errors": errors}

    def snapshot(self, key: str) -> Any:
        with self.lock:
            return json.loads(json.dumps(self.state.get(key), default=str))

    # ------------------------------------------------------------ lifecycle
    def _loop(self, name: str, fn: Callable[[], Any], interval: Callable[[], float], delay: float) -> None:
        if self._stop.wait(delay):
            return
        while not self._stop.is_set():
            t0 = time.time()
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                log.exception("%s loop failed", name)
                self._health(name, False, time.time() - t0, "%s: %s" % (type(e).__name__, e))
            if self._stop.wait(max(1.0, interval())):
                return

    def start(self) -> None:
        with self._lifecycle_lock:
            if any(t.is_alive() for t in self._threads):
                return
            self._stop.clear()
            self._start_threads()

    def _start_threads(self) -> None:
        self._threads = []
        c = self.cfg
        specs = [
            ("fast", self.fast_cycle, lambda: float(c.get("monitor.interval_sec", 15)), 0.0),
            ("lan", self.lan_cycle, lambda: float(c.get("monitor.lan_discovery_interval_sec", 300)), 4.0),
            ("posture", self.posture_cycle, lambda: float(c.get("monitor.posture_interval_sec", 1800)), 8.0),
            ("exposure", self.exposure_cycle, lambda: float(c.get("monitor.exposure_interval_sec", 21600)), 25.0),
            ("intel", self.intel_cycle, lambda: 3600.0, 2.0),
            ("leak", self.leak_cycle, lambda: float(c.get("monitor.leak_check_interval_sec", 86400)), 30.0),
            ("sensor", self.sensor_cycle, lambda: 3.0, 3.0),
            ("prune", self.store.prune, lambda: 86400.0, 60.0),
        ]
        for name, fn, interval, delay in specs:
            t = threading.Thread(target=self._loop, args=(name, fn, interval, delay), daemon=True, name="kekkai-" + name)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            deadline = time.monotonic() + 2
            for thread in self._threads:
                if thread is not threading.current_thread():
                    thread.join(timeout=max(0, deadline - time.monotonic()))

    def check_stalls(self) -> Dict[str, str]:
        """Self-diagnosis: loops that have not succeeded for 3x their interval."""
        intervals = {"fast": float(self.cfg.get("monitor.interval_sec", 15)),
                     "lan": float(self.cfg.get("monitor.lan_discovery_interval_sec", 300))}
        out = {}
        now = time.time()
        with self.lock:
            for name, iv in intervals.items():
                h = self.state["health"].get(name)
                if now - self.started < iv * 3 + 30:
                    continue
                if not h or now - h.get("last_ok", 0) > iv * 3 + 30:
                    out[name] = "stalled"
        return out
