"""Tiny, defensive DNS wire-format codec (for mDNS). Malformed packets raise ValueError."""
from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Tuple

T_A, T_PTR, T_TXT, T_AAAA, T_SRV, T_ANY = 1, 12, 16, 28, 33, 255


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ValueError("bad label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(qid: int, questions: List[Tuple[str, int]], unicast_response: bool = False) -> bytes:
    qclass = 0x8001 if unicast_response else 0x0001
    body = b"".join(encode_name(n) + struct.pack(">HH", t, qclass) for n, t in questions)
    return struct.pack(">HHHHHH", qid & 0xFFFF, 0, len(questions), 0, 0, 0) + body


def read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumps = 0
    end = -1
    pos = offset
    while True:
        if pos >= len(data):
            raise ValueError("name out of bounds")
        ln = data[pos]
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > 32 or ptr >= len(data):
                raise ValueError("pointer loop")
            pos = ptr
            continue
        if ln & 0xC0:
            raise ValueError("bad label type")
        pos += 1
        if ln == 0:
            break
        if pos + ln > len(data):
            raise ValueError("label out of bounds")
        labels.append(data[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
        if len(labels) > 128:
            raise ValueError("name too long")
    return ".".join(labels), (end if end >= 0 else pos)


def parse_message(data: bytes) -> Dict[str, Any]:
    if len(data) < 12:
        raise ValueError("short packet")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if qd > 64 or an + ns + ar > 512:
        raise ValueError("implausible counts")
    pos = 12
    questions = []
    for _ in range(qd):
        name, pos = read_name(data, pos)
        if pos + 4 > len(data):
            raise ValueError("truncated question")
        qt, qc = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        questions.append({"name": name, "type": qt})
    records = []
    for _ in range(an + ns + ar):
        name, pos = read_name(data, pos)
        if pos + 10 > len(data):
            raise ValueError("truncated record")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            raise ValueError("truncated rdata")
        rdata = data[pos:pos + rdlen]
        rec: Dict[str, Any] = {"name": name, "type": rtype, "ttl": ttl}
        try:
            if rtype == T_A and rdlen == 4:
                rec["value"] = str(ipaddress.IPv4Address(rdata))
            elif rtype == T_AAAA and rdlen == 16:
                rec["value"] = str(ipaddress.IPv6Address(rdata))
            elif rtype == T_PTR:
                rec["value"], _ = read_name(data, pos)
            elif rtype == T_SRV and rdlen >= 7:
                prio, weight, port = struct.unpack(">HHH", rdata[:6])
                target, _ = read_name(data, pos + 6)
                rec["value"] = {"priority": prio, "weight": weight, "port": port, "target": target}
            elif rtype == T_TXT:
                items, i = [], 0
                while i < rdlen:
                    ln = rdata[i]
                    items.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                rec["value"] = items
        except ValueError:
            rec["value"] = None
        records.append(rec)
        pos += rdlen
    return {"id": qid, "flags": flags, "response": bool(flags & 0x8000), "questions": questions, "records": records}
