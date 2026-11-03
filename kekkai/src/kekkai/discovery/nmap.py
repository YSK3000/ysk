"""Optional deep scan with nmap (installed by `kekkai install-nmap`) — same LAN-only guard as the built-in scanner."""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from kekkai.discovery.portscan import SERVICES, _check_scope
from kekkai.util import find_cmd, run


def local_app() -> str:
    """Where KEKKAI keeps the nmap it installs itself (inside the user's KEKKAI folder: no password needed)."""
    from kekkai import paths
    return str(paths.data_dir() / "tools" / "nmap.app")


def _bundle(app: str) -> Optional[Tuple[str, Dict[str, str]]]:
    res = app + "/Contents/Resources"
    real = res + "/bin/nmap"
    if os.path.isfile(real) and os.access(real, os.X_OK):
        env = {"DYLD_LIBRARY_PATH": res + "/lib"}
        if os.path.isdir(res + "/share/nmap"):
            env["NMAPDIR"] = res + "/share/nmap"
        return real, env
    return None


def command() -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    """The nmap executable to run, plus any environment it needs.

    Order: an nmap on PATH / Homebrew / nmap.org's /Applications install, then the copy KEKKAI installed into
    its own folder. nmap.org's app bundle puts a shell launcher at nmap.app/Contents/MacOS/nmap; the bundled
    binary is run directly with the library and data paths that launcher sets.
    """
    exe = find_cmd("nmap")
    if exe:
        m = re.match(r"^(.*/nmap\.app)/Contents/MacOS/nmap$", exe)
        if m:
            b = _bundle(m.group(1))
            if b:
                return b
        return exe, None
    b = _bundle(local_app())
    return b if b else (None, None)


def available() -> bool:
    return command()[0] is not None


def parse_xml(text: str) -> List[Dict[str, Any]]:
    if "<!ENTITY" in text:
        raise ValueError("unexpected entity in nmap output")
    root = ET.fromstring(text)
    out = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        num = int(port.get("portid", "0"))
        svc = port.find("service")
        info = SERVICES.get(num, ("unknown", "info", ""))
        entry: Dict[str, Any] = {"port": num, "proto": port.get("protocol"), "service": info[0],
                                 "risk": info[1], "note": info[2]}
        if svc is not None:
            entry["service"] = svc.get("name") or entry["service"]
            banner = " ".join(x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x)
            if banner:
                entry["banner"] = banner[:160]
            if svc.get("product"):
                entry["product"] = svc.get("product")[:80]
            if svc.get("version"):
                entry["version"] = svc.get("version")[:40]
            # Application/OS CPEs (e.g. cpe:/a:openbsd:openssh:7.4) identify the exact product for CVE lookup.
            cpes = [c.text.strip() for c in svc.findall("cpe") if c.text and c.text.strip().startswith("cpe:/")]
            if cpes:
                entry["cpe"] = cpes[:4]
        out.append(entry)
    return out


# Common TCP services on home networks and small servers, added to KEKKAI's own list (portscan.SERVICES)
# when the port list has to be given explicitly.
EXTRA_PORTS = (20, 26, 79, 106, 113, 119, 179, 199, 427, 444, 513, 514, 543, 544, 990, 1025, 1026, 1027, 1110,
               1900, 2000, 2001, 2121, 2869, 3128, 3478, 4000, 4443, 4567, 4899, 5009, 5051, 5190, 5431, 5631,
               5666, 6000, 6001, 6646, 7070, 7443, 8001, 8002, 8010, 8082, 8083, 8086, 8089, 8090, 8099, 8181,
               8200, 8333, 8400, 8500, 8800, 8899, 9001, 9080, 9090, 9091, 9443, 9999, 10001, 10243, 12345,
               49153, 49154, 49155, 50000, 50001)


def explicit_ports() -> List[int]:
    return sorted(set(SERVICES) | set(EXTRA_PORTS))


def scan(ip: str, top_ports: int = 200, timeout: float = 240) -> Dict[str, Any]:
    _check_scope(ip)
    if not available():
        raise RuntimeError("nmap が見つかりません（防御機能の稼働状況の「nmapを入れる」か ./kekkai install-nmap）")
    t0 = time.time()
    exe, env = command()
    base = [exe or "nmap", "-sV", "--version-light", "-T4", "-Pn"]
    rc, out, err = run(base + ["--top-ports", str(top_ports), "-oX", "-", "--", ip], timeout=timeout, env=env)
    scanned: Any = top_ports
    if rc != 0 and "top-ports" in err:
        # Measured on a real macOS 26 runner: nmap.org's 7.993 build rejects every --top-ports value
        # ("--top-ports should be an integer between 1 and 65535") while Homebrew's 7.992 accepts it.
        # Fall back to an explicit list: KEKKAI's own risk-ranked ports plus common home/server ports.
        ports = explicit_ports()
        rc, out, err = run(base + ["-p", ",".join(map(str, ports)), "-oX", "-", "--", ip], timeout=timeout, env=env)
        scanned = len(ports)
    if rc != 0:
        raise RuntimeError("nmap failed: %s" % (err.strip()[-300:] or rc))
    ports = parse_xml(out)
    order = ["info", "low", "medium", "high", "critical"]
    worst = max((p["risk"] for p in ports), key=order.index) if ports else None
    return {"ip": ip, "scanned": scanned, "open": ports, "worst": worst, "duration": round(time.time() - t0, 1),
            "method": "nmap -sV", "ts": time.time()}
