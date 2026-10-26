"""Read .onion pages through the local Tor client (Tor Project's tor: `brew install tor`).

* SOCKS5 (RFC 1928) with the host name sent to Tor (ATYP 3): nothing is resolved locally, so no DNS leak.
* Only .onion hosts, text only (HTML is reduced to text; no scripts, images or downloads), size-capped.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import struct
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

ONION = re.compile(r"^(?:[a-z2-7]{56})\.onion$")  # v3 onion service (v2 was retired by Tor in 2021)
SOCKS_ERRORS = {1: "一般的な失敗", 2: "許可されていません", 3: "ネットワークに到達できません", 4: "ホストに到達できません",
                5: "接続を拒否されました", 6: "TTL切れ", 7: "未対応のコマンド", 8: "未対応のアドレス形式",
                0xF0: "onionサービスの情報が見つかりません", 0xF1: "onionサービスの情報が不正", 0xF2: "onionサービスへの導入に失敗",
                0xF3: "onionサービスとの合流に失敗", 0xF4: "認証が必要なonionサービス", 0xF5: "認証が不正",
                0xF6: "onionアドレスが不正", 0xF7: "導入がタイムアウト"}
DEFAULT_SOCKS = [("127.0.0.1", 9050), ("127.0.0.1", 9150)]  # tor daemon, Tor Browser
MAX_BYTES = 2 * 1024 * 1024


class TorError(Exception):
    pass


def is_onion(host: str) -> bool:
    return bool(ONION.match((host or "").lower().rstrip(".")))


def _recv(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise TorError("Tor との接続が切れました")
        buf += chunk
    return buf


def socks5_connect(proxy: Tuple[str, int], host: str, port: int, timeout: float = 60) -> socket.socket:
    s = socket.create_connection(proxy, timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")  # version 5, one method: no authentication
        if _recv(s, 2) != b"\x05\x00":
            raise TorError("SOCKS5 の認証方式が合いません（Tor ではない可能性）")
        name = host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + struct.pack("!B", len(name)) + name + struct.pack("!H", port))
        ver, rep, _rsv, atyp = _recv(s, 4)
        if ver != 5 or rep != 0:
            raise TorError("Tor が接続できませんでした: %s" % SOCKS_ERRORS.get(rep, "コード %d" % rep))
        if atyp == 1:      # bound address: IPv4
            _recv(s, 4)
        elif atyp == 4:    # IPv6
            _recv(s, 16)
        else:              # domain name: length byte + name
            _recv(s, _recv(s, 1)[0])
        _recv(s, 2)        # bound port
        return s
    except BaseException:
        s.close()
        raise


def find_socks(candidates: Optional[List[Tuple[str, int]]] = None) -> Optional[Tuple[str, int]]:
    for addr in candidates or DEFAULT_SOCKS:
        try:
            with socket.create_connection(addr, timeout=1.5) as s:
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) == b"\x05\x00":
                    return addr
        except OSError:
            continue
    return None


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style", "noscript", "svg"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript", "svg") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif not self._skip and data.strip():
            self.parts.append(data.strip())


def html_to_text(html: str) -> Tuple[str, str]:
    p = _Text()
    p.feed(html)
    return " ".join(p.title.split()), "\n".join(p.parts)


class _Conn(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, proxy: Tuple[str, int], timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._proxy = proxy

    def connect(self) -> None:
        self.sock = socks5_connect(self._proxy, self.host, self.port, self.timeout)


class _TLSConn(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, proxy: Tuple[str, int], timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._proxy = proxy

    def connect(self) -> None:
        raw = socks5_connect(self._proxy, self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)  # certificates are verified


def fetch_onion(url: str, proxy: Optional[Tuple[str, int]] = None, timeout: float = 90, redirects: int = 3) -> Dict[str, Any]:
    """GET an .onion page through Tor and return its text (never binaries)."""
    proxy = proxy or find_socks()
    if not proxy:
        raise TorError("Tor が起動していません（brew install tor → brew services start tor、または Tor Browser を起動）")
    for _ in range(redirects + 1):
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not is_onion(host):
            raise TorError("対象は .onion のアドレスだけです: %s" % url)
        conn = (_TLSConn if u.scheme == "https" else _Conn)(host, u.port or (443 if u.scheme == "https" else 80), proxy, timeout)
        try:
            conn.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""),
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
                                  "Accept": "text/html,text/plain;q=0.9", "Accept-Encoding": "identity", "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urllib.parse.urljoin(url, r.getheader("Location"))
                continue
            ctype = (r.getheader("Content-Type") or "").lower()
            if not (ctype.startswith("text/") or "html" in ctype or not ctype):
                return {"url": url, "status": r.status, "type": ctype, "title": "", "text": "", "skipped": "テキスト以外は取得しません"}
            body = r.read(MAX_BYTES + 1)
        finally:
            conn.close()
        m = re.search(r"charset=([\w-]+)", ctype)
        try:
            html = body[:MAX_BYTES].decode(m.group(1) if m else "utf-8", "replace")
        except LookupError:
            html = body[:MAX_BYTES].decode("utf-8", "replace")
        title, text = html_to_text(html) if "html" in ctype or not ctype else ("", html)
        return {"url": url, "status": r.status, "type": ctype, "title": title, "text": text, "truncated": len(body) > MAX_BYTES}
    raise TorError("リダイレクトが多すぎます")
