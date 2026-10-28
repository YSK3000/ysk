"""Local dashboard server (127.0.0.1 only).

Hardening — a security tool must not become the hole:
  * random token, exchanged once for an HttpOnly SameSite=Strict cookie
  * Host header allow-list (defeats DNS rebinding), Origin/Sec-Fetch-Site checks on POST
  * strict CSP (no inline script), no CORS, JSON body size limit
"""
from __future__ import annotations

import hmac
import json
import mimetypes
import os
import queue
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from kekkai import __version__, paths
from kekkai.discovery.portscan import ScopeError
from kekkai.netutil import is_public, normalize_mac, parse_ip
from kekkai.util import atomic_write, dumps, log

COOKIE = "kekkai_session"
MAX_BODY = 64 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
         ".woff2": "font/woff2"}


def load_or_create_token() -> str:
    p = paths.sub("session.json")
    try:
        with open(str(p), "r", encoding="utf-8") as f:
            data = json.load(f)
        tok = data.get("token")
        if isinstance(tok, str) and len(tok) >= 32:
            return tok
    except (OSError, ValueError):
        pass
    tok = secrets.token_urlsafe(32)
    atomic_write(str(p), json.dumps({"token": tok, "created": time.time()}).encode(), 0o600)
    return tok


def write_session(port: int, token: str, host: str) -> None:
    atomic_write(str(paths.sub("session.json")),
                 json.dumps({"token": token, "port": port, "host": host, "pid": os.getpid(), "updated": time.time()}).encode(),
                 0o600)


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], app: "App"):
        self.app = app
        super().__init__(addr, Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind() resolves socket.getfqdn(host) only for a display name; that reverse lookup
        # can stall for tens of seconds on macOS, delaying the dashboard after login.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError)):
            return  # the browser went away (tab closed, SSE reconnect)
        log.exception("unhandled error serving %s", client_address)


class App:
    """Routes. Kept separate from the handler so tests can call it directly."""

    def __init__(self, monitor: Any, cfg: Any, token: str):
        self.m = monitor
        self.cfg = cfg
        self.token = token
        self.port = 0
        self.web = paths.web_dir()
        self._ai_lock = threading.Lock()

    # ------------------------------------------------------------ GET
    def get(self, path: str, q: Dict[str, str]) -> Any:
        m = self.m
        net_id = (m.state.get("network") or {}).get("id")
        if path == "/api/summary":
            s = m.summary()
            s["stalls"] = m.check_stalls()
            return s
        if path == "/api/connections":
            return {"connections": m.snapshot("connections"), "listeners": m.snapshot("listeners")}
        if path == "/api/devices":
            devs = m.store.devices(net_id) if net_id else []
            for d in devs:
                d["new"] = time.time() - (d.get("first_seen") or 0) < 86400
                d["online"] = time.time() - (d.get("last_seen") or 0) < 900
            return {"network": m.state.get("network"), "devices": devs, "lan": m.state.get("lan"),
                    "neighbors": m.snapshot("neighbors")}
        if path == "/api/networks":
            return {"networks": m.store.networks()}
        if path == "/api/alerts":
            status = q.get("status", "active")
            return {"alerts": m.store.alerts(None if status == "all" else status, limit=_int(q.get("limit"), 300)),
                    "threat": m.threat_summary()}
        if path.startswith("/api/alert/"):
            a = m.store.alert(_int(path.rsplit("/", 1)[1], -1))
            if not a:
                raise ApiError(404, "not found")
            return a
        if path == "/api/posture":
            return {"posture": m.snapshot("posture"), "wifi": m.snapshot("wifi"),
                    "persistence": m.snapshot("persistence"), "listeners": m.snapshot("listeners")}
        if path == "/api/exposure":
            return {"exposure": m.snapshot("exposure"), "upnp": m.snapshot("upnp")}
        if path == "/api/destinations":
            hours = max(1, min(24 * 30, _int(q.get("hours"), 24)))
            return {"destinations": m.store.destinations(time.time() - hours * 3600, limit=800)}
        if path == "/api/intel":
            return {"feeds": m.feeds.status(), "geo": m.geo.available, "oui": m.oui.size,
                    "sensor": m.state.get("sensor"), "health": m.state.get("health"),
                    "attribution": ["IP Geolocation by DB-IP (https://db-ip.com) — CC BY 4.0",
                                    "地図: Natural Earth (public domain) / world-atlas (ISC)",
                                    "MACベンダー: IEEE Registration Authority"]}
        if path == "/api/lookup":
            ip = q.get("ip", "")
            if parse_ip(ip) is None:
                raise ApiError(400, "IPアドレスを入力してください")
            ip = str(parse_ip(ip))
            g, threats = m.intel(ip)
            out: Dict[str, Any] = {"ip": ip, "geo": g, "threats": threats, "public": is_public(ip),
                                   "seen": m.store.destination_seen(ip)}
            if q.get("ext") == "1":
                from kekkai.intel.lookups import enrich
                out["external"] = enrich(ip, self.cfg)
            return out
        if path.startswith("/api/scan/"):
            job = m.jobs.get(path.rsplit("/", 1)[1])
            if not job:
                raise ApiError(404, "job not found")
            return job
        if path == "/api/scans":
            return {"scans": m.store.scans(q.get("ip") or None, limit=20)}
        if path == "/api/timeline":
            return {"events": m.store.events(_int(q.get("limit"), 100))}
        if path == "/api/ai/status":
            from kekkai import ai
            return ai.status(self.cfg)
        if path == "/api/doctor":
            from kekkai import doctor
            return {"checks": doctor.run_checks(self.cfg, monitor=m, quick=True)}
        if path == "/api/coverage":
            from kekkai.coverage import describe
            return describe(m)
        if path == "/api/report":
            from kekkai import report
            return {"markdown": report.markdown(m)}
        raise ApiError(404, "unknown endpoint")

    # ------------------------------------------------------------ POST
    def post(self, path: str, body: Dict[str, Any]) -> Any:
        m = self.m
        net_id = (m.state.get("network") or {}).get("id")
        if path.startswith("/api/alerts/") and path.endswith("/status"):
            aid = _int(path.split("/")[3], -1)
            status = str(body.get("status", ""))
            if status not in ("open", "ack", "resolved"):
                raise ApiError(400, "status must be open/ack/resolved")
            a = m.store.set_alert_status(aid, status)
            if not a:
                raise ApiError(404, "not found")
            m.bus.publish("alert_update", a)
            return a
        if path == "/api/alerts/ack_all":
            n = m.store.ack_all()
            m.bus.publish("alert_update", {"ack_all": n})
            return {"updated": n}
        if path.startswith("/api/devices/"):
            mac = normalize_mac(urllib.parse.unquote(path.rsplit("/", 1)[1]))
            if not mac or not net_id:
                raise ApiError(400, "bad device")
            label = body.get("label")
            trusted = body.get("trusted")
            notes = body.get("notes")
            d = m.store.update_device(net_id, mac, label=str(label) if label is not None else None,
                                      trusted=bool(trusted) if trusted is not None else None,
                                      notes=str(notes) if notes is not None else None)
            if not d:
                raise ApiError(404, "device not found")
            return d
        if path.startswith("/api/networks/"):
            nid = urllib.parse.unquote(path.rsplit("/", 1)[1])
            if not m.store.network(nid):
                raise ApiError(404, "network not found")
            m.store.update_network(nid, label=body.get("label"), trusted=body.get("trusted"))
            return m.store.network(nid)
        if path == "/api/scan":
            ip = str(body.get("ip", ""))
            mode = body.get("mode")
            try:
                # default to "auto": use nmap -sV when installed, else the built-in TCP scanner
                return m.start_scan(ip, mode if mode in ("deep", "quick", "auto") else "auto")
            except ScopeError as e:
                raise ApiError(403, str(e))
            except RuntimeError as e:
                raise ApiError(409, str(e))
        if path == "/api/discover":
            threading.Thread(target=_quiet(m.lan_cycle), daemon=True).start()
            return {"started": True}
        if path == "/api/posture/run":
            threading.Thread(target=_quiet(lambda: m.posture_cycle(slow=bool(body.get("slow")))), daemon=True).start()
            return {"started": True}
        if path == "/api/exposure/run":
            threading.Thread(target=_quiet(m.exposure_cycle), daemon=True).start()
            return {"started": True}
        if path == "/api/intel/update":
            threading.Thread(target=_quiet(lambda: m.intel_cycle(force=bool(body.get("force")))), daemon=True).start()
            return {"started": True}
        if path == "/api/ai/analyze":
            from kekkai import ai
            a = m.store.alert(_int(body.get("alert_id"), -1))
            if not a:
                raise ApiError(404, "alert not found")
            if not self._ai_lock.acquire(blocking=False):
                raise ApiError(409, "AI解析を実行中です")
            try:
                result = ai.analyze_alert(self.cfg, a, m)
            finally:
                self._ai_lock.release()
            if result.get("ok"):
                m.store.set_alert_ai(a["id"], result)
            return result
        raise ApiError(404, "unknown endpoint")

    # ------------------------------------------------------------ static
    def static(self, rel: str) -> Optional[Tuple[bytes, str]]:
        base = self.web.resolve()
        target = (base / rel).resolve()
        if base not in target.parents and target != base:
            return None
        if not target.is_file():
            return None
        ctype = TYPES.get(target.suffix, mimetypes.guess_type(str(target))[0] or "application/octet-stream")
        return target.read_bytes(), ctype


def _int(v: Any, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _quiet(fn: Callable[[], Any]) -> Callable[[], None]:
    def run() -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("background task failed")
    return run


class Handler(BaseHTTPRequestHandler):
    server_version = "KEKKAI/" + __version__
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("http %s - %s", self.address_string(), fmt % args)

    # ------------------------------------------------------------ checks
    def _allowed_hosts(self) -> set:
        port = self.server.server_address[1]
        return {"127.0.0.1:%d" % port, "localhost:%d" % port, "[::1]:%d" % port}

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self._allowed_hosts()

    def _cookie_token(self) -> Optional[str]:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = cookies.SimpleCookie(raw)
        except cookies.CookieError:
            return None
        morsel = c.get(COOKIE)
        return morsel.value if morsel else None

    def _authed(self) -> bool:
        tok = self.app.token
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), tok):
            return True
        ck = self._cookie_token()
        return bool(ck) and hmac.compare_digest(ck, tok)

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {"http://" + h for h in self._allowed_hosts()}:
            return False
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return False
        return True

    # ------------------------------------------------------------ responses
    def _send(self, status: int, body: bytes, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj: Any) -> None:
        self._send(status, dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, msg: str) -> None:
        self._json(status, {"error": msg})

    # ------------------------------------------------------------ verbs
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._error(403, "invalid Host header")
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        path = u.path
        if path in ("/", "/index.html"):
            tok = q.get("token")
            if tok and hmac.compare_digest(tok, self.app.token):
                return self._send(302, b"", "text/plain", {
                    "Location": "/", "Set-Cookie": "%s=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000" % (
                        COOKIE, self.app.token)})
            name = "index.html" if self._authed() else "locked.html"
            res = self.app.static(name)
            if res is None:
                return self._error(500, "web assets missing")
            return self._send(200, res[0], res[1])
        if path.startswith("/static/"):
            res = self.app.static(urllib.parse.unquote(path[len("/static/"):]))
            if res is None:
                return self._error(404, "not found")
            return self._send(200, res[0], res[1])
        if path == "/favicon.ico":
            res = self.app.static("favicon.svg")
            return self._send(200, res[0], "image/svg+xml") if res else self._error(404, "")
        if not path.startswith("/api/"):
            return self._error(404, "not found")
        if not self._authed():
            return self._error(401, "unauthorized")
        if path == "/api/events":
            return self._sse()
        try:
            return self._json(200, self.app.get(path, q))
        except ApiError as e:
            return self._error(e.status, e.message)
        except Exception as e:  # noqa: BLE001
            log.exception("GET %s failed", path)
            return self._error(500, "%s: %s" % (type(e).__name__, e))

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        # Consume the body before any early rejection: on a keep-alive connection an unread
        # body would otherwise be parsed as the next request (HTTP desync).
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return self._error(411, "chunked bodies are not supported")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return self._error(400, "bad Content-Length")
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return self._error(413, "body too large")
        raw = self.rfile.read(length) if length else b""
        if not self._host_ok():
            return self._error(403, "invalid Host header")
        if not self._authed():
            return self._error(401, "unauthorized")
        if not self._origin_ok():
            return self._error(403, "cross-site request blocked")
        if raw and "json" not in (self.headers.get("Content-Type") or ""):
            return self._error(415, "JSON required")
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._error(400, "invalid JSON")
        path = urllib.parse.urlsplit(self.path).path
        try:
            return self._json(200, self.app.post(path, body))
        except ApiError as e:
            return self._error(e.status, e.message)
        except Exception as e:  # noqa: BLE001
            log.exception("POST %s failed", path)
            return self._error(500, "%s: %s" % (type(e).__name__, e))

    def _sse(self) -> None:
        q = self.app.m.bus.subscribe()
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.write(("event: hello\ndata: %s\n\n" % dumps(self.app.m.summary())).encode())
            self.wfile.flush()
            while True:
                try:
                    kind, data = q.get(timeout=15)
                    payload = "event: %s\ndata: %s\n\n" % (kind, dumps(data))
                except queue.Empty:
                    payload = ": ping\n\n"
                self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            self.app.m.bus.unsubscribe(q)


def serve(monitor: Any, cfg: Any, host: str = "127.0.0.1", port: int = 47665,
          open_browser: bool = True, ready: Optional[Callable[[str], None]] = None) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("セキュリティのため、ダッシュボードは 127.0.0.1 でのみ公開します")
    token = load_or_create_token()
    app = App(monitor, cfg, token)
    httpd = None
    for p in [port] + list(range(port + 1, port + 20)):
        try:
            httpd = Server((host, p), app)
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit("ポート %d〜%d が使用中です" % (port, port + 19))
    app.port = httpd.server_address[1]
    write_session(app.port, token, host)
    url = "http://127.0.0.1:%d/?token=%s" % (app.port, token)
    if ready:
        ready(url)
    if open_browser:
        threading.Timer(1.0, lambda: monitor.platform.open_url(url)).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()


def session_alive(timeout: float = 1.0) -> bool:
    """Is a dashboard from session.json actually listening (not a stale file from a stopped one)?"""
    try:
        with open(str(paths.sub("session.json")), "r", encoding="utf-8") as f:
            port = int(json.load(f)["port"])
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except (OSError, ValueError, KeyError):
        return False


def session_url() -> Optional[str]:
    try:
        with open(str(paths.sub("session.json")), "r", encoding="utf-8") as f:
            s = json.load(f)
        return "http://127.0.0.1:%d/?token=%s" % (int(s["port"]), s["token"])
    except (OSError, ValueError, KeyError):
        return None


def web_root() -> Path:
    return paths.web_dir()
