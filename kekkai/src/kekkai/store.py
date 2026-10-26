"""SQLite persistence (WAL, safe to share between the dashboard, MCP server and sensor)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = ["critical", "high", "medium", "low", "info"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks(
  id TEXT PRIMARY KEY, label TEXT, ssid TEXT, gateway_ip TEXT, subnet TEXT,
  first_seen REAL, last_seen REAL, trusted INTEGER DEFAULT 0, cycles INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(
  network TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT, ips TEXT, vendor TEXT, hostname TEXT, label TEXT,
  kind TEXT, model TEXT, trusted INTEGER DEFAULT 0, randomized INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL, services TEXT, ports TEXT, upnp TEXT, last_scan REAL, notes TEXT,
  PRIMARY KEY(network, mac));
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT, ts REAL, last_ts REAL, count INTEGER DEFAULT 1,
  severity TEXT, rule TEXT, title TEXT, detail TEXT, advice TEXT, subject TEXT, data TEXT,
  status TEXT DEFAULT 'open', dedup TEXT, ai TEXT);
CREATE INDEX IF NOT EXISTS alerts_dedup ON alerts(dedup, status);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, last_ts);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS destinations(
  ip TEXT, port INTEGER, proto TEXT, process TEXT, first_seen REAL, last_seen REAL, hits INTEGER,
  country TEXT, city TEXT, asn INTEGER, org TEXT, lat REAL, lon REAL, risk TEXT,
  PRIMARY KEY(ip, port, proto, process));
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, network TEXT, target TEXT, mode TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, message TEXT, data TEXT);
"""

_JSON_COLS = {"ips", "services", "ports", "upnp", "data", "result", "ai"}


def _row(r: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if r is None:
        return None
    d = dict(r)
    for k in _JSON_COLS:
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    return d


def _j(v: Any) -> Optional[str]:
    return None if v is None else json.dumps(v, ensure_ascii=False, default=str)


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=15, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA busy_timeout=8000")
            self.db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def _all(self, sql: str, args: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [_row(r) for r in self.db.execute(sql, tuple(args)).fetchall()]  # type: ignore[misc]

    def _one(self, sql: str, args: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        with self._lock:
            return _row(self.db.execute(sql, tuple(args)).fetchone())

    def _exec(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.db.execute(sql, tuple(args))

    # ------------------------------------------------------------ key/value
    def kv_get(self, key: str, default: Any = None) -> Any:
        r = self._one("SELECT value FROM kv WHERE key=?", (key,))
        if r is None:
            return default
        try:
            return json.loads(r["value"])
        except (TypeError, ValueError):
            return default

    def kv_set(self, key: str, value: Any) -> None:
        self._exec("INSERT INTO kv(key,value,ts) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts",
                   (key, json.dumps(value, ensure_ascii=False, default=str), time.time()))

    # ------------------------------------------------------------ networks
    def touch_network(self, net_id: str, gateway_ip: Optional[str], subnet: Optional[str],
                      ssid: Optional[str]) -> Dict[str, Any]:
        t = time.time()
        with self._lock:
            row = self._one("SELECT * FROM networks WHERE id=?", (net_id,))
            if row is None:
                self._exec("INSERT INTO networks(id,label,ssid,gateway_ip,subnet,first_seen,last_seen,trusted,cycles) "
                           "VALUES(?,?,?,?,?,?,?,0,0)", (net_id, None, ssid, gateway_ip, subnet, t, t))
            else:
                self._exec("UPDATE networks SET last_seen=?, gateway_ip=?, subnet=?, ssid=COALESCE(?, ssid) WHERE id=?",
                           (t, gateway_ip, subnet, ssid, net_id))
            return self._one("SELECT * FROM networks WHERE id=?", (net_id,)) or {}

    def bump_cycles(self, net_id: str) -> int:
        self._exec("UPDATE networks SET cycles=cycles+1 WHERE id=?", (net_id,))
        r = self._one("SELECT cycles FROM networks WHERE id=?", (net_id,))
        return int(r["cycles"]) if r else 0

    def network(self, net_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM networks WHERE id=?", (net_id,))

    def networks(self) -> List[Dict[str, Any]]:
        return self._all("SELECT * FROM networks ORDER BY last_seen DESC")

    def update_network(self, net_id: str, label: Optional[str] = None, trusted: Optional[bool] = None) -> None:
        if label is not None:
            self._exec("UPDATE networks SET label=? WHERE id=?", (label[:64], net_id))
        if trusted is not None:
            self._exec("UPDATE networks SET trusted=? WHERE id=?", (1 if trusted else 0, net_id))

    # ------------------------------------------------------------ devices
    def device(self, net_id: str, mac: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM devices WHERE network=? AND mac=?", (net_id, mac))

    def devices(self, net_id: Optional[str]) -> List[Dict[str, Any]]:
        if net_id is None:
            return self._all("SELECT * FROM devices ORDER BY last_seen DESC")
        return self._all("SELECT * FROM devices WHERE network=? ORDER BY last_seen DESC", (net_id,))

    def upsert_device(self, net_id: str, mac: str, ip: Optional[str], **fields: Any) -> Tuple[Dict[str, Any], bool]:
        """Insert or merge a device sighting. Returns (row, is_new)."""
        t = time.time()
        with self._lock:
            cur = self.device(net_id, mac)
            if cur is None:
                ips = [ip] if ip else []
                self._exec(
                    "INSERT INTO devices(network,mac,ip,ips,vendor,hostname,kind,model,randomized,first_seen,last_seen,services,upnp) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (net_id, mac, ip, _j(ips), fields.get("vendor"), fields.get("hostname"), fields.get("kind"),
                     fields.get("model"), 1 if fields.get("randomized") else 0, t, t,
                     _j(fields.get("services") or []), _j(fields.get("upnp"))))
                return self.device(net_id, mac) or {}, True
            ips = list(cur.get("ips") or [])
            if ip and ip not in ips:
                ips = (ips + [ip])[-8:]
            sets = {"last_seen": t, "ips": _j(ips)}
            if ip:
                sets["ip"] = ip
            for k in ("vendor", "hostname", "kind", "model"):
                if fields.get(k):
                    sets[k] = fields[k]
            if fields.get("services"):
                merged = sorted(set(cur.get("services") or []) | set(fields["services"]))
                sets["services"] = _j(merged[:40])
            if fields.get("upnp"):
                sets["upnp"] = _j(fields["upnp"])
            cols = ", ".join("%s=?" % k for k in sets)
            self._exec("UPDATE devices SET %s WHERE network=? AND mac=?" % cols, list(sets.values()) + [net_id, mac])
            return self.device(net_id, mac) or {}, False

    def set_device_ports(self, net_id: str, mac: str, ports: List[Dict[str, Any]]) -> None:
        self._exec("UPDATE devices SET ports=?, last_scan=? WHERE network=? AND mac=?",
                   (_j(ports), time.time(), net_id, mac))

    def update_device(self, net_id: str, mac: str, label: Optional[str] = None, trusted: Optional[bool] = None,
                      notes: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if label is not None:
            self._exec("UPDATE devices SET label=? WHERE network=? AND mac=?", (label[:64] or None, net_id, mac))
        if trusted is not None:
            self._exec("UPDATE devices SET trusted=? WHERE network=? AND mac=?", (1 if trusted else 0, net_id, mac))
        if notes is not None:
            self._exec("UPDATE devices SET notes=? WHERE network=? AND mac=?", (notes[:2000], net_id, mac))
        return self.device(net_id, mac)

    def device_by_ip(self, net_id: str, ip: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM devices WHERE network=? AND ip=? ORDER BY last_seen DESC LIMIT 1", (net_id, ip))

    # ------------------------------------------------------------ alerts
    def raise_alert(self, network: Optional[str], rule: str, severity: str, title: str, detail: str,
                    advice: str = "", subject: str = "", data: Optional[Dict[str, Any]] = None,
                    dedup: Optional[str] = None) -> Tuple[Dict[str, Any], bool]:
        """Create an alert, or bump the existing one with the same dedup key. Returns (alert, is_new)."""
        dedup = dedup or "%s|%s|%s" % (network or "-", rule, subject)
        t = time.time()
        with self._lock:
            cur = self._one("SELECT * FROM alerts WHERE dedup=? AND status IN ('open','ack') ORDER BY id DESC LIMIT 1",
                            (dedup,))
            if cur is None:
                # A resolved alert that re-fires within an hour stays resolved (avoids flapping).
                cur = self._one("SELECT * FROM alerts WHERE dedup=? AND status='resolved' AND last_ts>? ORDER BY id DESC LIMIT 1",
                                (dedup, t - 3600))
            if cur is not None:
                sev = severity if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(cur["severity"], 0) else cur["severity"]
                self._exec("UPDATE alerts SET last_ts=?, count=count+1, data=?, severity=?, detail=? WHERE id=?",
                           (t, _j(data), sev, detail, cur["id"]))
                return self.alert(cur["id"]) or cur, False
            c = self._exec("INSERT INTO alerts(network,ts,last_ts,count,severity,rule,title,detail,advice,subject,data,status,dedup) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (network, t, t, 1, severity, rule, title, detail, advice, subject, _j(data), "open", dedup))
            return self.alert(int(c.lastrowid)) or {}, True

    def alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM alerts WHERE id=?", (alert_id,))

    def alerts(self, status: Optional[str] = None, limit: int = 200, min_severity: Optional[str] = None) -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM alerts", []  # type: Tuple[str, List[Any]]
        where = []
        if status == "active":
            where.append("status IN ('open','ack')")
        elif status:
            where.append("status=?")
            args.append(status)
        if min_severity:
            allowed = [s for s, v in SEVERITY_ORDER.items() if v >= SEVERITY_ORDER.get(min_severity, 0)]
            where.append("severity IN (%s)" % ",".join("?" * len(allowed)))
            args.extend(allowed)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY last_ts DESC LIMIT ?"
        args.append(int(limit))
        return self._all(sql, args)

    def set_alert_status(self, alert_id: int, status: str) -> Optional[Dict[str, Any]]:
        if status not in ("open", "ack", "resolved"):
            raise ValueError("bad status")
        self._exec("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        return self.alert(alert_id)

    def set_alert_ai(self, alert_id: int, analysis: Dict[str, Any]) -> None:
        self._exec("UPDATE alerts SET ai=? WHERE id=?", (_j(analysis), alert_id))

    def ack_all(self) -> int:
        return self._exec("UPDATE alerts SET status='ack' WHERE status='open'").rowcount

    def alert_counts(self) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for r in self._all("SELECT severity, COUNT(*) AS n FROM alerts WHERE status='open' GROUP BY severity"):
            out[r["severity"]] = r["n"]
        return out

    # ------------------------------------------------------------ destinations
    def record_destinations(self, rows: List[Dict[str, Any]]) -> None:
        t = time.time()
        with self._lock:
            self.db.execute("BEGIN")
            try:
                for r in rows:
                    self.db.execute(
                        "INSERT INTO destinations(ip,port,proto,process,first_seen,last_seen,hits,country,city,asn,org,lat,lon,risk) "
                        "VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?,?) ON CONFLICT(ip,port,proto,process) DO UPDATE SET "
                        "last_seen=excluded.last_seen, hits=hits+1, risk=excluded.risk",
                        (r["ip"], r["port"], r["proto"], r.get("process") or "?", t, t, r.get("country"), r.get("city"),
                         r.get("asn"), r.get("org"), r.get("lat"), r.get("lon"), r.get("risk")))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def destinations(self, since: float, limit: int = 500) -> List[Dict[str, Any]]:
        return self._all("SELECT * FROM destinations WHERE last_seen>=? ORDER BY last_seen DESC LIMIT ?", (since, limit))

    def destination_seen(self, ip: str) -> bool:
        return self._one("SELECT 1 AS x FROM destinations WHERE ip=? LIMIT 1", (ip,)) is not None

    # ------------------------------------------------------------ scans & events
    def save_scan(self, network: Optional[str], target: str, mode: str, result: Dict[str, Any]) -> int:
        c = self._exec("INSERT INTO scans(ts,network,target,mode,result) VALUES(?,?,?,?,?)",
                       (time.time(), network, target, mode, _j(result)))
        return int(c.lastrowid)

    def scans(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        if target:
            return self._all("SELECT * FROM scans WHERE target=? ORDER BY id DESC LIMIT ?", (target, limit))
        return self._all("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    def log_event(self, kind: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        self._exec("INSERT INTO events(ts,kind,message,data) VALUES(?,?,?,?)", (time.time(), kind, message, _j(data)))

    def events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def prune(self, days: int = 30) -> None:
        cutoff = time.time() - days * 86400
        self._exec("DELETE FROM destinations WHERE last_seen<?", (cutoff,))
        self._exec("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 5000)")
        self._exec("DELETE FROM alerts WHERE status='resolved' AND last_ts<?", (time.time() - 90 * 86400,))
        self._exec("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT 500)")

    def integrity_ok(self) -> bool:
        r = self._one("PRAGMA quick_check")
        return bool(r) and list(r.values())[0] == "ok"
