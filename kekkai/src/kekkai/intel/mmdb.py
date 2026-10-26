"""Minimal MaxMind DB (MMDB v2) reader: pure Python, mmap-backed, read-only.

Spec: https://maxmind.github.io/MaxMind-DB/ — used for the DB-IP Lite city/ASN databases.
"""
from __future__ import annotations

import ipaddress
import mmap
import struct
import threading
from typing import Any, Dict, Optional, Tuple

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class InvalidDatabaseError(Exception):
    pass


class _Decoder:
    def __init__(self, buf: Any, pointer_base: int, limit: int):
        self.buf = buf
        self.base = pointer_base
        self.limit = limit

    def decode(self, offset: int, depth: int = 0) -> Tuple[Any, int]:
        if depth > 64:
            raise InvalidDatabaseError("data nesting too deep")
        if offset >= self.limit:
            raise InvalidDatabaseError("offset outside data section")
        buf = self.buf
        ctrl = buf[offset]
        offset += 1
        typ = ctrl >> 5
        if typ == 1:
            ptr, offset = self._pointer(ctrl, offset)
            value, _ = self.decode(self.base + ptr, depth + 1)
            return value, offset
        if typ == 0:
            typ = 7 + buf[offset]
            offset += 1
        size, offset = self._size(ctrl, offset)
        if typ == 2:
            return bytes(buf[offset:offset + size]).decode("utf-8", "replace"), offset + size
        if typ == 7:
            out: Dict[str, Any] = {}
            for _ in range(size):
                key, offset = self.decode(offset, depth + 1)
                val, offset = self.decode(offset, depth + 1)
                out[str(key)] = val
            return out, offset
        if typ == 11:
            arr = []
            for _ in range(size):
                val, offset = self.decode(offset, depth + 1)
                arr.append(val)
            return arr, offset
        if typ in (5, 6, 9, 10):
            return int.from_bytes(bytes(buf[offset:offset + size]), "big"), offset + size
        if typ == 8:
            v = int.from_bytes(bytes(buf[offset:offset + size]), "big")
            if size == 4 and v >= 1 << 31:
                v -= 1 << 32
            return v, offset + size
        if typ == 3:
            if size != 8:
                raise InvalidDatabaseError("bad double size")
            return struct.unpack_from(">d", buf, offset)[0], offset + 8
        if typ == 15:
            if size != 4:
                raise InvalidDatabaseError("bad float size")
            return struct.unpack_from(">f", buf, offset)[0], offset + 4
        if typ == 4:
            return bytes(buf[offset:offset + size]), offset + size
        if typ == 14:
            return size != 0, offset
        if typ in (12, 13):
            return None, offset
        raise InvalidDatabaseError("unknown data type %d" % typ)

    def _size(self, ctrl: int, offset: int) -> Tuple[int, int]:
        size = ctrl & 0x1F
        buf = self.buf
        if size < 29:
            return size, offset
        if size == 29:
            return 29 + buf[offset], offset + 1
        if size == 30:
            return 285 + ((buf[offset] << 8) | buf[offset + 1]), offset + 2
        return 65821 + ((buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]), offset + 3

    def _pointer(self, ctrl: int, offset: int) -> Tuple[int, int]:
        ss = (ctrl >> 3) & 0x3
        vvv = ctrl & 0x7
        buf = self.buf
        if ss == 0:
            return (vvv << 8) | buf[offset], offset + 1
        if ss == 1:
            return ((vvv << 16) | (buf[offset] << 8) | buf[offset + 1]) + 2048, offset + 2
        if ss == 2:
            return ((vvv << 24) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]) + 526336, offset + 3
        return struct.unpack_from(">I", buf, offset)[0], offset + 4


class Reader:
    def __init__(self, path: str):
        self.path = path
        self._file = open(path, "rb")
        try:
            self._buf = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as e:
            self._file.close()
            raise InvalidDatabaseError("cannot map %s: %s" % (path, e))
        size = len(self._buf)
        start = self._buf.rfind(METADATA_MARKER, max(0, size - 128 * 1024))
        if start == -1:
            self.close()
            raise InvalidDatabaseError("%s is not a MaxMind DB file" % path)
        meta_start = start + len(METADATA_MARKER)
        meta, _ = _Decoder(self._buf, meta_start, size).decode(meta_start)
        if not isinstance(meta, dict):
            raise InvalidDatabaseError("bad metadata")
        self.metadata: Dict[str, Any] = meta
        self.node_count = int(meta["node_count"])
        self.record_size = int(meta["record_size"])
        if self.record_size not in (24, 28, 32):
            raise InvalidDatabaseError("unsupported record size %d" % self.record_size)
        self.ip_version = int(meta.get("ip_version", 6))
        self.node_bytes = self.record_size * 2 // 8
        self.search_tree_size = self.node_count * self.node_bytes
        self.data_start = self.search_tree_size + 16
        if self.data_start > start:
            raise InvalidDatabaseError("search tree larger than file")
        self._decoder = _Decoder(self._buf, self.data_start, start)
        self._ipv4_start: Optional[int] = None
        self._cache: Dict[int, Any] = {}
        self._lock = threading.Lock()

    @property
    def database_type(self) -> str:
        return str(self.metadata.get("database_type", ""))

    @property
    def build_epoch(self) -> int:
        return int(self.metadata.get("build_epoch", 0))

    def close(self) -> None:
        try:
            self._buf.close()
        finally:
            self._file.close()

    def _read_node(self, node: int, bit: int) -> int:
        off = node * self.node_bytes
        b = self._buf
        rs = self.record_size
        if rs == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        return struct.unpack_from(">I", b, off + bit * 4)[0]

    def _ipv4_start_node(self) -> int:
        if self._ipv4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._read_node(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def lookup(self, address: str) -> Optional[Dict[str, Any]]:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        packed = ip.packed
        if ip.version == 6:
            if self.ip_version == 4:
                return None
            node = 0
        else:
            node = self._ipv4_start_node()
        bits = len(packed) * 8
        node_count = self.node_count
        for i in range(bits):
            if node >= node_count:
                break
            node = self._read_node(node, (packed[i >> 3] >> (7 - (i & 7))) & 1)
        if node == node_count:
            return None
        if node < node_count:
            return None
        offset = node - node_count - 16
        cached = self._cache.get(offset)
        if cached is not None:
            return cached
        value, _ = self._decoder.decode(self.data_start + offset)
        with self._lock:
            if len(self._cache) > 20000:
                self._cache.clear()
            self._cache[offset] = value
        return value if isinstance(value, dict) else {"value": value}
