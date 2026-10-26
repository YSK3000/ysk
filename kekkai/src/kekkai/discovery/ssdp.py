"""SSDP/UPnP discovery and router (IGD) port-mapping audit — read only.

Description URLs are fetched only when they point at the responding LAN device itself.
"""
from __future__ import annotations

import http.client
import re
import select
import socket
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from kekkai.netutil import is_local_target

SSDP_ADDR = ("239.255.255.250", 1900)
MAX_XML = 256 * 1024
_IGD_STS = ("ssdp:all", "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:2")


def _msearch(st: str, mx: int = 2) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
            "MX: %d\r\nST: %s\r\nUSER-AGENT: KEKKAI/0.1 UPnP/1.1\r\n\r\n" % (mx, st)).encode()


def parse_response(data: bytes) -> Optional[Dict[str, str]]:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines or not (lines[0].startswith("HTTP/1.1 200") or lines[0].startswith("NOTIFY")):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()[:512]
    return headers


def discover(iface_ip: Optional[str] = None, timeout: float = 3.0) -> List[Dict[str, Any]]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if iface_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            except OSError:
                pass
        s.bind(("0.0.0.0", 0))
        s.setblocking(False)
    except OSError:
        return []
    for st in _IGD_STS:
        try:
            s.sendto(_msearch(st), SSDP_ADDR)
        except OSError:
            pass
    seen: Dict[tuple, Dict[str, Any]] = {}
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            r, _, _ = select.select([s], [], [], 0.25)
            if not r:
                continue
            try:
                data, (src, _) = s.recvfrom(4096)
            except OSError:
                continue
            if not is_local_target(src):
                continue
            h = parse_response(data)
            if not h:
                continue
            key = (src, h.get("location"))
            if key not in seen:
                seen[key] = {"ip": src, "location": h.get("location"), "server": h.get("server"),
                             "st": h.get("st"), "usn": h.get("usn")}
    finally:
        s.close()
    return list(seen.values())


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _http(method: str, url: str, responder_ip: str, body: Optional[bytes] = None,
          headers: Optional[Dict[str, str]] = None, timeout: float = 3.0) -> tuple:
    u = urllib.parse.urlparse(url)
    if u.scheme != "http" or u.hostname != responder_ip or not is_local_target(u.hostname):
        raise ValueError("refusing to fetch %s (not the responding LAN device)" % url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read(MAX_XML + 1)
        if len(data) > MAX_XML:
            raise ValueError("response too large")
        return resp.status, data
    finally:
        conn.close()


def safe_xml(data: bytes) -> ET.Element:
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise ValueError("DTD/entities are not allowed")
    return ET.fromstring(data)


def describe(location: str, responder_ip: str) -> Dict[str, Any]:
    status, data = _http("GET", location, responder_ip)
    if status != 200:
        raise ValueError("HTTP %s" % status)
    root = safe_xml(data)
    info: Dict[str, Any] = {"location": location, "services": []}
    base = None
    for el in root.iter():
        tag = _strip_ns(el.tag)
        text = (el.text or "").strip()
        if tag == "URLBase" and text:
            base = text
        if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType", "modelDescription") \
                and text and tag not in info:
            info[tag] = text[:120]
        if tag == "service":
            svc = {_strip_ns(c.tag): (c.text or "").strip() for c in el}
            if svc.get("serviceType"):
                info["services"].append({"type": svc.get("serviceType"), "control": svc.get("controlURL")})
    info["base"] = base or location
    return info


_SOAP = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
         's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{svc}">{args}'
         '</u:{action}></s:Body></s:Envelope>')


def _soap(control: str, svc: str, action: str, responder_ip: str, args: str = "") -> Optional[Dict[str, str]]:
    body = _SOAP.format(action=action, svc=svc, args=args).encode()
    status, data = _http("POST", control, responder_ip, body=body, headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (svc, action)})
    if status != 200:
        return None
    root = safe_xml(data)
    out = {}
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag.startswith("New"):
            out[tag[3:]] = (el.text or "").strip()[:200]
    return out


def igd_audit(desc: Dict[str, Any], responder_ip: str, max_entries: int = 128) -> Optional[Dict[str, Any]]:
    svc = None
    for s in desc.get("services", []):
        if re.search(r"WAN(IP|PPP)Connection", s.get("type") or "") and s.get("control"):
            svc = s
            break
    if not svc:
        return None
    control = urllib.parse.urljoin(desc.get("base") or desc["location"], svc["control"])
    result: Dict[str, Any] = {"router": responder_ip, "service": svc["type"], "mappings": [], "external_ip": None}
    try:
        ext = _soap(control, svc["type"], "GetExternalIPAddress", responder_ip)
        if ext:
            result["external_ip"] = ext.get("ExternalIPAddress") or None
    except (OSError, ValueError, ET.ParseError):
        pass
    for i in range(max_entries):
        try:
            m = _soap(control, svc["type"], "GetGenericPortMappingEntry", responder_ip,
                      "<NewPortMappingIndex>%d</NewPortMappingIndex>" % i)
        except (OSError, ValueError, ET.ParseError):
            break
        if not m:
            break
        result["mappings"].append({
            "external_port": m.get("ExternalPort"), "protocol": m.get("Protocol"),
            "internal_client": m.get("InternalClient"), "internal_port": m.get("InternalPort"),
            "description": m.get("PortMappingDescription"), "enabled": m.get("Enabled") in ("1", "true"),
            "lease": m.get("LeaseDuration"), "remote_host": m.get("RemoteHost") or "*"})
    return result
