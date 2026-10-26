"""GeoIP + ASN enrichment backed by DB-IP Lite MMDB files (CC BY 4.0, attribution in the UI)."""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

from kekkai import paths
from kekkai.intel.mmdb import InvalidDatabaseError, Reader
from kekkai.netutil import is_public


def _name(names: Any, lang: str = "en") -> Optional[str]:
    if isinstance(names, dict):
        return names.get(lang) or names.get("en")
    return None


class Geo:
    def __init__(self, data_dir: Optional[str] = None):
        base = data_dir or str(paths.data_dir())
        self.city_path = os.path.join(base, "geo", "city.mmdb")
        self.asn_path = os.path.join(base, "geo", "asn.mmdb")
        self._city: Optional[Reader] = None
        self._asn: Optional[Reader] = None
        self._mtimes = (0.0, 0.0)
        self._checked = 0.0
        self._opened = False
        self._lock = threading.Lock()

    def _ensure(self) -> None:
        """Open (or re-open after `kekkai update`) the databases; stat at most every 30s."""
        t = time.time()
        if self._opened and t - self._checked < 30:
            return
        self._checked = t
        mt = (_mtime(self.city_path), _mtime(self.asn_path))
        if self._opened and mt == self._mtimes:
            return
        with self._lock:
            # Old readers are left to the GC: another thread may still be using them.
            self._city = _open(self.city_path)
            self._asn = _open(self.asn_path)
            self._mtimes = mt
            self._opened = True

    @property
    def available(self) -> Dict[str, Any]:
        self._ensure()
        return {
            "city": bool(self._city),
            "asn": bool(self._asn),
            "city_build": self._city.build_epoch if self._city else None,
            "asn_build": self._asn.build_epoch if self._asn else None,
        }

    def lookup(self, ip: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ip": ip}
        if not is_public(ip):
            out["scope"] = "local"
            return out
        self._ensure()
        if self._city:
            try:
                rec = self._city.lookup(ip) or {}
            except (InvalidDatabaseError, IndexError, ValueError):
                rec = {}
            country = rec.get("country") or rec.get("registered_country") or {}
            loc = rec.get("location") or {}
            subs = rec.get("subdivisions") or []
            out.update({
                "country": country.get("iso_code"),
                "country_name": _name(country.get("names")),
                "country_ja": _name(country.get("names"), "ja"),
                "city": _name((rec.get("city") or {}).get("names")),
                "region": _name(subs[0].get("names")) if subs and isinstance(subs[0], dict) else None,
                "lat": loc.get("latitude"),
                "lon": loc.get("longitude"),
            })
        if self._asn:
            try:
                rec = self._asn.lookup(ip) or {}
            except (InvalidDatabaseError, IndexError, ValueError):
                rec = {}
            out["asn"] = rec.get("autonomous_system_number")
            out["org"] = rec.get("autonomous_system_organization")
        return out


def _mtime(path: str) -> float:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


def _open(path: str) -> Optional[Reader]:
    if not os.path.exists(path):
        return None
    try:
        return Reader(path)
    except (InvalidDatabaseError, OSError, KeyError, ValueError):
        return None
