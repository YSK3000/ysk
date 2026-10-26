"""MAC address vendor lookup (IEEE registry: MA-L 24bit, MA-M 28bit, MA-S 36bit)."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
from typing import Dict, Optional

from kekkai import paths
from kekkai.netutil import mac_is_randomized, normalize_mac

_SUFFIX = re.compile(
    r"(?:[,.]\s*|\s+)(co\.?,?\s*ltd\.?|corporation|corp\.?|inc\.?|incorporated|llc|ltd\.?|limited|gmbh|s\.?a\.?|"
    r"b\.?v\.?|ag|oy|ab|pte\.?|pty\.?|plc|technologies|technology)$",
    re.IGNORECASE)


def short_vendor(name: str) -> str:
    n = " ".join(name.split())
    for _ in range(3):
        m = _SUFFIX.search(n)
        if not m or m.start() == 0:
            break
        n = n[:m.start()].rstrip(" ,.")
    return n or name


def parse_ieee_csv(text: str) -> Dict[str, str]:
    """IEEE oui.csv / mam.csv / oui36.csv: Registry,Assignment,Organization Name,Organization Address."""
    out: Dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or row[0] == "Registry":
            continue
        prefix = row[1].strip().upper()
        if re.fullmatch(r"[0-9A-F]{6,9}", prefix):
            out[prefix] = row[2].strip()
    return out


def parse_oui_data_json(text: str) -> Dict[str, str]:
    """npm "oui-data" index.json: {"000393": "Apple, Inc.\\nAddress..."}."""
    data = json.loads(text)
    out: Dict[str, str] = {}
    for k, v in data.items():
        key = str(k).upper()
        if re.fullmatch(r"[0-9A-F]{6,9}", key) and isinstance(v, str):
            out[key] = v.split("\n", 1)[0].strip()
    return out


class OUI:
    def __init__(self, data_dir: Optional[str] = None):
        self.path = os.path.join(data_dir or str(paths.data_dir()), "oui.json")
        self._db: Optional[Dict[str, str]] = None
        self._mtime = 0.0
        self._lock = threading.Lock()

    def _load(self) -> Dict[str, str]:
        try:
            mt = os.stat(self.path).st_mtime
        except OSError:
            return {}
        if self._db is None or mt != self._mtime:
            with self._lock:
                try:
                    with open(self.path, "r", encoding="utf-8") as f:
                        self._db = json.load(f)
                    self._mtime = mt
                except (OSError, ValueError):
                    self._db = {}
        return self._db or {}

    @property
    def size(self) -> int:
        return len(self._load())

    def vendor(self, mac: str) -> Optional[str]:
        m = normalize_mac(mac)
        if not m:
            return None
        if mac_is_randomized(m):
            return None
        hexs = m.replace(":", "").upper()
        db = self._load()
        for n in (9, 7, 6):
            v = db.get(hexs[:n])
            if v:
                return short_vendor(v)
        return None
