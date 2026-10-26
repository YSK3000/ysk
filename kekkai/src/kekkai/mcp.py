"""MCP server over stdio (`kekkai mcp`) so Claude Code / Claude Desktop can use KEKKAI as tools.

Dual-era: answers the legacy initialize handshake (2024-11-05 … 2025-11-25) and the stateless
2026-07-28 revision (server/discover, per-request _meta). Stdout carries protocol messages only.
"""
from __future__ import annotations

import json
import sys
import threading
import traceback
from typing import Any, Callable, Dict, List, Optional

from kekkai import __version__
from kekkai.util import dumps, log

LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
MODERN_VERSIONS = ["2026-07-28"]
META_VERSION = "io.modelcontextprotocol/protocolVersion"

INSTRUCTIONS = (
    "KEKKAI is a home-network defense monitor running on the user's Mac. Use kekkai_status first, then drill into "
    "kekkai_alerts / kekkai_connections / kekkai_devices. Scanning tools only work on the user's own LAN (private IPs). "
    "Explain findings in plain Japanese, separate facts from guesses, and recommend concrete, reversible actions."
)

RO = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}

TOOLS: List[Dict[str, Any]] = [
    {"name": "kekkai_status", "title": "全体の状況",
     "description": "Threat level, current network, counts of devices/connections/alerts, defense score and data freshness. "
                    "Runs one fresh collection cycle.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": RO},
    {"name": "kekkai_alerts", "title": "アラート一覧",
     "description": "List alerts raised by the detection engine (ARP spoofing, threat-feed hits, new devices, new listeners, "
                    "persistence, DNS/proxy changes, exposure).",
     "inputSchema": {"type": "object", "properties": {
         "status": {"type": "string", "enum": ["active", "open", "ack", "resolved", "all"], "default": "active"},
         "min_severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
         "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30}}, "additionalProperties": False},
     "annotations": RO},
    {"name": "kekkai_set_alert_status", "title": "アラートの状態変更",
     "description": "Mark an alert as acknowledged, resolved, or reopen it. Only do this when the user asked.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"},
                                                      "status": {"type": "string", "enum": ["ack", "resolved", "open"]}},
                     "required": ["id", "status"], "additionalProperties": False},
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
    {"name": "kekkai_devices", "title": "LAN内の機器",
     "description": "Devices seen on the current LAN (IP, MAC, vendor, kind, trust, open ports from past scans).",
     "inputSchema": {"type": "object", "properties": {"refresh": {"type": "boolean", "default": False,
                                                                  "description": "Run LAN discovery first (~10s)"}},
                     "additionalProperties": False}, "annotations": RO},
    {"name": "kekkai_connections", "title": "通信中の接続",
     "description": "Live TCP/UDP connections of this Mac with process, direction, GeoIP/ASN and threat-feed matches.",
     "inputSchema": {"type": "object", "properties": {
         "scope": {"type": "string", "enum": ["internet", "risky", "lan", "all"], "default": "internet"},
         "limit": {"type": "integer", "minimum": 1, "maximum": 400, "default": 80}}, "additionalProperties": False},
     "annotations": RO},
    {"name": "kekkai_lookup_ip", "title": "IP照会",
     "description": "GeoIP/ASN and threat-feed membership for one IP. external=true also queries Shodan InternetDB and "
                    "GreyNoise (sends the IP to those services).",
     "inputSchema": {"type": "object", "properties": {"ip": {"type": "string"}, "external": {"type": "boolean", "default": False}},
                     "required": ["ip"], "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "kekkai_scan_device", "title": "LAN機器のポートスキャン",
     "description": "TCP port scan of ONE device on the user's own LAN (private IPs only; refused otherwise). deep=true uses nmap -sV.",
     "inputSchema": {"type": "object", "properties": {"ip": {"type": "string"}, "deep": {"type": "boolean", "default": False}},
                     "required": ["ip"], "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}},
    {"name": "kekkai_audit", "title": "セキュリティ診断",
     "description": "macOS hardening audit (firewall, FileVault, SIP, Gatekeeper, updates, sharing, Wi-Fi, persistence). "
                    "detailed=true also checks pending software updates (1-2 min).",
     "inputSchema": {"type": "object", "properties": {"detailed": {"type": "boolean", "default": False}},
                     "additionalProperties": False}, "annotations": RO},
    {"name": "kekkai_exposure", "title": "外部露出チェック",
     "description": "How the internet sees the home: public IP, Shodan InternetDB ports/CVEs, router UPnP port mappings.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "kekkai_report", "title": "レポート",
     "description": "Full Markdown security report (alerts, devices, traffic, audit, exposure).",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": RO},
    {"name": "kekkai_doctor", "title": "自己診断",
     "description": "Self-diagnosis of KEKKAI itself: collectors, parsers, data freshness, AI providers.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "annotations": RO},
]


class ToolError(Exception):
    pass


class KekkaiTools:
    def __init__(self) -> None:
        self._m: Any = None
        self._lock = threading.Lock()

    @property
    def m(self) -> Any:
        with self._lock:
            if self._m is None:
                from kekkai import config
                from kekkai.monitor import Monitor
                self._m = Monitor(config.load())
            return self._m

    def call(self, name: str, args: Dict[str, Any]) -> Any:
        fn: Optional[Callable[[Dict[str, Any]], Any]] = getattr(self, "t_" + name.replace("kekkai_", ""), None)
        if not name.startswith("kekkai_") or fn is None:
            raise ToolError("unknown tool: %s" % name)
        return fn(args)

    def t_status(self, a: Dict[str, Any]) -> Any:
        m = self.m
        m.fast_cycle()
        s = m.summary()
        s.pop("health", None)
        s["feeds"] = [{k: f[k] for k in ("id", "entries", "status")} for f in m.feeds.status()]
        return s

    def t_alerts(self, a: Dict[str, Any]) -> Any:
        status = a.get("status", "active")
        rows = self.m.store.alerts(None if status == "all" else status, limit=int(a.get("limit", 30)),
                                   min_severity=a.get("min_severity"))
        for r in rows:
            r.pop("dedup", None)
        return {"threat": self.m.threat_summary(), "alerts": rows}

    def t_set_alert_status(self, a: Dict[str, Any]) -> Any:
        if a.get("status") not in ("ack", "resolved", "open"):
            raise ToolError("status must be ack/resolved/open")
        r = self.m.store.set_alert_status(int(a["id"]), a["status"])
        if not r:
            raise ToolError("alert %s not found" % a.get("id"))
        return r

    def t_devices(self, a: Dict[str, Any]) -> Any:
        m = self.m
        if a.get("refresh"):
            m.lan_cycle()
        else:
            m.fast_cycle()
        net = m.state.get("network") or {}
        return {"network": net, "devices": m.store.devices(net.get("id")) if net.get("id") else []}

    def t_connections(self, a: Dict[str, Any]) -> Any:
        m = self.m
        m.fast_cycle()
        scope = a.get("scope", "internet")
        rows = m.snapshot("connections") or []
        if scope == "internet":
            rows = [c for c in rows if c.get("scope") == "internet"]
        elif scope == "risky":
            rows = [c for c in rows if c.get("risk") != "ok"]
        elif scope == "lan":
            rows = [c for c in rows if c.get("scope") == "lan"]
        keep = ("proto", "raddr", "rport", "lport", "state", "pid", "process", "path", "direction", "risk", "flags", "threats")
        out = []
        for c in rows[: int(a.get("limit", 80))]:
            d = {k: c.get(k) for k in keep}
            g = c.get("geo") or {}
            d["where"] = {k: g.get(k) for k in ("country", "city", "asn", "org")}
            out.append(d)
        return {"count": len(rows), "connections": out, "listeners": m.snapshot("listeners")}

    def t_lookup_ip(self, a: Dict[str, Any]) -> Any:
        from kekkai.netutil import parse_ip
        ip = parse_ip(a.get("ip"))
        if ip is None:
            raise ToolError("invalid IP address")
        g, threats = self.m.intel(str(ip))
        out: Dict[str, Any] = {"ip": str(ip), "geo": g, "threats": threats}
        if a.get("external"):
            from kekkai.intel.lookups import enrich
            out["external"] = enrich(str(ip), self.m.cfg)
        return out

    def t_scan_device(self, a: Dict[str, Any]) -> Any:
        from kekkai.discovery import nmap
        from kekkai.discovery.portscan import ScopeError, raise_fd_limit, scan_host
        raise_fd_limit()
        ip = str(a.get("ip", ""))
        try:
            res = nmap.scan(ip) if a.get("deep") else scan_host(ip)
        except ScopeError as e:
            raise ToolError(str(e))
        except RuntimeError as e:
            raise ToolError(str(e))
        m = self.m
        net_id = (m.state.get("network") or {}).get("id")
        m.store.save_scan(net_id, ip, "deep" if a.get("deep") else "quick", res)
        return res

    def t_audit(self, a: Dict[str, Any]) -> Any:
        m = self.m
        if not m.state.get("listeners"):
            m.fast_cycle()
        return m.posture_cycle(slow=bool(a.get("detailed")))

    def t_exposure(self, a: Dict[str, Any]) -> Any:
        return self.m.exposure_cycle()

    def t_report(self, a: Dict[str, Any]) -> Any:
        from kekkai import report
        m = self.m
        m.fast_cycle()
        return report.markdown(m)

    def t_doctor(self, a: Dict[str, Any]) -> Any:
        from kekkai import doctor
        return doctor.run_checks(self.m.cfg, monitor=self.m, quick=True)


class Server:
    def __init__(self, tools: Optional[KekkaiTools] = None, out: Any = None):
        self.tools = tools or KekkaiTools()
        self.out = out
        self._wlock = threading.Lock()

    def write(self, msg: Dict[str, Any]) -> None:
        line = json.dumps(msg, ensure_ascii=False, default=str, separators=(",", ":"))
        with self._wlock:
            self.out.write(line + "\n")
            self.out.flush()

    def handle(self, msg: Any) -> Optional[Any]:
        if isinstance(msg, list):
            replies = [r for r in (self.handle(m) for m in msg) if r is not None]
            return replies or None
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        if method is None:
            return None  # a response to something we never send
        is_note = "id" not in msg
        meta = params.get("_meta") if isinstance(params, dict) else None
        modern = isinstance(meta, dict) and meta.get(META_VERSION) in MODERN_VERSIONS
        try:
            result = self.dispatch(method, params if isinstance(params, dict) else {}, modern)
        except MethodNotFound:
            if is_note:
                return None
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found: %s" % method}}
        except InvalidParams as e:
            return None if is_note else {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(e)}}
        except Exception as e:  # noqa: BLE001
            log.error("mcp %s failed: %s", method, traceback.format_exc())
            return None if is_note else {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}}
        if is_note:
            return None
        if modern and isinstance(result, dict):
            result.setdefault("resultType", "complete")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def dispatch(self, method: str, params: Dict[str, Any], modern: bool) -> Any:
        info = {"name": "kekkai", "title": "結界 KEKKAI", "version": __version__}
        if method == "initialize":
            want = params.get("protocolVersion")
            version = want if want in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
            return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": info, "instructions": INSTRUCTIONS}
        if method == "server/discover":
            return {"resultType": "complete", "supportedVersions": MODERN_VERSIONS,
                    "capabilities": {"tools": {"listChanged": False}}, "instructions": INSTRUCTIONS,
                    "ttlMs": 3600000, "cacheScope": "public", "_meta": {"io.modelcontextprotocol/serverInfo": info}}
        if method in ("notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed"):
            return None
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(name, str):
                raise InvalidParams("missing tool name")
            if not isinstance(args, dict):
                raise InvalidParams("arguments must be an object")
            if name not in {t["name"] for t in TOOLS}:
                raise InvalidParams("unknown tool: %s" % name)
            try:
                value = self.tools.call(name, args)
            except ToolError as e:
                return {"content": [{"type": "text", "text": "エラー: %s" % e}], "isError": True}
            except Exception as e:  # noqa: BLE001
                log.error("tool %s failed: %s", name, traceback.format_exc())
                return {"content": [{"type": "text", "text": "内部エラー: %s: %s" % (type(e).__name__, e)}], "isError": True}
            text = value if isinstance(value, str) else dumps(value, indent=1)
            if len(text) > 60000:
                text = text[:60000] + "\n…(truncated)"
            return {"content": [{"type": "text", "text": text}], "isError": False}
        if method in ("resources/list", "prompts/list"):
            return {method.split("/")[0]: []}
        raise MethodNotFound(method)


class MethodNotFound(Exception):
    pass


class InvalidParams(Exception):
    pass


def serve() -> int:
    proto_out = sys.stdout
    # Anything else that prints must not corrupt the protocol stream.
    sys.stdout = sys.stderr
    srv = Server(out=proto_out)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            srv.write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        reply = srv.handle(msg)
        if reply is not None:
            if isinstance(reply, list):
                with srv._wlock:
                    proto_out.write(json.dumps(reply, ensure_ascii=False, default=str) + "\n")
                    proto_out.flush()
            else:
                srv.write(reply)
    return 0
