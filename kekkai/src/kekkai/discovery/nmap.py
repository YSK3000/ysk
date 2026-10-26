"""Optional deep scan with nmap (brew install nmap) — same LAN-only guard as the built-in scanner."""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from kekkai.discovery.portscan import SERVICES, _check_scope
from kekkai.util import find_cmd, run


def available() -> bool:
    return find_cmd("nmap") is not None


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
        out.append(entry)
    return out


def scan(ip: str, top_ports: int = 200, timeout: float = 240) -> Dict[str, Any]:
    _check_scope(ip)
    if not available():
        raise RuntimeError("nmap が見つかりません（brew install nmap）")
    t0 = time.time()
    rc, out, err = run(["nmap", "-sV", "--version-light", "-T4", "-Pn", "--top-ports", str(top_ports),
                        "-oX", "-", "--", ip], timeout=timeout)
    if rc != 0:
        raise RuntimeError("nmap failed: %s" % (err.strip()[-300:] or rc))
    ports = parse_xml(out)
    order = ["info", "low", "medium", "high", "critical"]
    worst = max((p["risk"] for p in ports), key=order.index) if ports else None
    return {"ip": ip, "scanned": top_ports, "open": ports, "worst": worst, "duration": round(time.time() - t0, 1),
            "method": "nmap -sV", "ts": time.time()}
