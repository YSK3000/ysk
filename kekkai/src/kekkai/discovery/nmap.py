"""Optional deep scan with nmap (installed by `kekkai install-nmap`) — same LAN-only guard as the built-in scanner."""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from kekkai.discovery.portscan import SERVICES, _check_scope
from kekkai.util import find_cmd, run


def available() -> bool:
    return find_cmd("nmap") is not None


def command() -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    """The nmap executable to run, plus any environment it needs.

    nmap.org's macOS installer puts a shell launcher at nmap.app/Contents/MacOS/nmap. On a real macOS 26
    runner, `-sV ... --top-ports 200 -oX - -- <ip>` through that launcher failed with "--top-ports should be
    an integer", so the bundled binary is run directly with the library and data paths the launcher sets.
    """
    exe = find_cmd("nmap")
    if not exe:
        return None, None
    m = re.match(r"^(.*/nmap\.app)/Contents/MacOS/nmap$", exe)
    if m:
        res = m.group(1) + "/Contents/Resources"
        real = res + "/bin/nmap"
        if os.path.isfile(real) and os.access(real, os.X_OK):
            env = {"DYLD_LIBRARY_PATH": res + "/lib"}
            if os.path.isdir(res + "/share/nmap"):
                env["NMAPDIR"] = res + "/share/nmap"
            return real, env
    return exe, None


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


def scan(ip: str, top_ports: int = 200, timeout: float = 240) -> Dict[str, Any]:
    _check_scope(ip)
    if not available():
        raise RuntimeError("nmap が見つかりません（防御機能の稼働状況の「nmapを入れる」か ./kekkai install-nmap）")
    t0 = time.time()
    exe, env = command()
    rc, out, err = run([exe or "nmap", "-sV", "--version-light", "-T4", "-Pn", "--top-ports", str(top_ports),
                        "-oX", "-", "--", ip], timeout=timeout, env=env)
    if rc != 0:
        raise RuntimeError("nmap failed: %s" % (err.strip()[-300:] or rc))
    ports = parse_xml(out)
    order = ["info", "low", "medium", "high", "critical"]
    worst = max((p["risk"] for p in ports), key=order.index) if ports else None
    return {"ip": ip, "scanned": top_ports, "open": ports, "worst": worst, "duration": round(time.time() - t0, 1),
            "method": "nmap -sV", "ts": time.time()}
