"""Small shared helpers: subprocess wrapper, command lookup, HTTP fetch, JSON."""
from __future__ import annotations

import gzip
import io
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Sequence, Tuple

from kekkai import USER_AGENT

log = logging.getLogger("kekkai")

IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Places where macOS keeps admin tools that a LaunchAgent PATH may not include.
_EXTRA_PATHS = (
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
    "/usr/libexec",
    "/usr/libexec/ApplicationFirewall",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)


def find_cmd(name: str) -> Optional[str]:
    """Locate an executable on PATH or in well-known admin locations."""
    if os.path.isabs(name):
        return name if os.access(name, os.X_OK) else None
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_PATHS:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def run(cmd: Sequence[str], timeout: float = 10.0, input_text: Optional[str] = None,
        env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run a command without a shell. Never raises.

    Returns (returncode, stdout, stderr). 127 = not found, 124 = timeout.
    """
    cmd = list(cmd)
    exe = find_cmd(cmd[0])
    if exe is None:
        return 127, "", "command not found: %s" % cmd[0]
    cmd[0] = exe
    run_env = dict(os.environ)
    # Stable, parseable output regardless of the user's locale.
    run_env["LC_ALL"] = "C"
    run_env["LANG"] = "C"
    if env:
        run_env.update(env)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, input=input_text, env=run_env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        out = e.stdout
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out or "", "timeout after %.0fs" % timeout
    except OSError as e:
        return 126, "", str(e)


def now() -> float:
    return time.time()


def iso(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def dumps(obj: Any, indent: Optional[int] = None) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=indent, default=_json_default,
                      separators=None if indent else (",", ":"))


def _json_default(o: Any) -> Any:
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)


class FetchError(Exception):
    pass


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Apple's CLT Python sometimes lacks a default CA path; fall back to the system bundle.
    if IS_MACOS and not ctx.get_ca_certs() and os.path.exists("/etc/ssl/cert.pem"):
        try:
            ctx.load_verify_locations("/etc/ssl/cert.pem")
        except (OSError, ssl.SSLError):
            pass
    return ctx


def http_get(url: str, timeout: float = 30.0, max_bytes: int = 256 * 1024 * 1024,
             headers: Optional[Dict[str, str]] = None, method: str = "GET",
             data: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
    """HTTP(S) request with size cap. Falls back to curl when the Python TLS stack fails.

    Returns (status, headers, body). Raises FetchError on network failure.
    """
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            body = _read_capped(resp, max_bytes)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536)
        except Exception:
            body = b""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except (ssl.SSLError, urllib.error.URLError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError) or isinstance(e, ssl.SSLError):
            curl = _curl_get(url, timeout, max_bytes, hdrs, method, data)
            if curl is not None:
                return curl
        raise FetchError("%s: %s" % (url, reason))
    except (OSError, ValueError) as e:
        raise FetchError("%s: %s" % (url, e))


def _read_capped(resp: Any, max_bytes: int) -> bytes:
    buf = io.BytesIO()
    while True:
        chunk = resp.read(1024 * 256)
        if not chunk:
            break
        buf.write(chunk)
        if buf.tell() > max_bytes:
            raise FetchError("response exceeds %d bytes" % max_bytes)
    return buf.getvalue()


def _curl_get(url: str, timeout: float, max_bytes: int, hdrs: Dict[str, str], method: str,
              data: Optional[bytes]) -> Optional[Tuple[int, Dict[str, str], bytes]]:
    """Fallback for old TLS stacks (e.g. LibreSSL in Apple's bundled Python)."""
    curl = find_cmd("curl")
    if not curl:
        return None
    cmd = [curl, "-sS", "-L", "--max-time", str(int(timeout)), "--max-filesize", str(max_bytes),
           "-X", method, "-w", "\n%{http_code}"]
    for k, v in hdrs.items():
        cmd += ["-H", "%s: %s" % (k, v)]
    if data is not None:
        cmd += ["--data-binary", "@-"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    body, _, code = p.stdout.rpartition(b"\n")
    try:
        return int(code), {}, body
    except ValueError:
        return None


def maybe_gunzip(data: bytes, max_bytes: int = 512 * 1024 * 1024) -> bytes:
    if data[:2] != b"\x1f\x8b":
        return data
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        while True:
            chunk = gz.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            if out.tell() > max_bytes:
                raise FetchError("decompressed data exceeds limit")
    return out.getvalue()


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    tmp = "%s.tmp-%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0
