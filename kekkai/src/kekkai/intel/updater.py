"""Downloads for GeoIP/ASN (DB-IP Lite) and the IEEE MAC vendor registry."""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from kekkai import paths
from kekkai.intel.mmdb import InvalidDatabaseError, Reader
from kekkai.intel.oui import parse_ieee_csv, parse_oui_data_json
from kekkai.util import FetchError, atomic_write, http_get, log, maybe_gunzip

DBIP_ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com) — CC BY 4.0"


def _months(n: int = 3) -> List[str]:
    y, m = time.gmtime().tm_year, time.gmtime().tm_mon
    out = []
    for _ in range(n):
        out.append("%04d-%02d" % (y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return out


def geo_sources(kind: str) -> List[str]:
    """Official DB-IP monthly files first, then the jsDelivr npm mirrors."""
    name = {"city": "dbip-city-lite", "asn": "dbip-asn-lite"}[kind]
    urls = ["https://download.db-ip.com/free/%s-%s.mmdb.gz" % (name, ym) for ym in _months(2)]
    if kind == "city":
        urls.append("https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz")
    else:
        urls.append("https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-asn-mmdb/dbip-asn.mmdb")
    return urls


def _validate_mmdb(path: str, kind: str) -> Dict[str, Any]:
    r = Reader(path)
    try:
        rec = r.lookup("8.8.8.8") or {}
        if kind == "city" and "country" not in rec and "location" not in rec:
            raise InvalidDatabaseError("city database returned no location for 8.8.8.8")
        if kind == "asn" and "autonomous_system_number" not in rec:
            raise InvalidDatabaseError("asn database returned no ASN for 8.8.8.8")
        return {"type": r.database_type, "build_epoch": r.build_epoch}
    finally:
        r.close()


def update_geo(kind: str, max_age_days: float = 25, force: bool = False,
               fetch: Callable[..., Any] = http_get, progress: Optional[Callable[[str], None]] = None) -> str:
    target = str(paths.sub("geo", "%s.mmdb" % kind))
    if not force and os.path.exists(target) and (time.time() - os.stat(target).st_mtime) < max_age_days * 86400:
        return "fresh"
    errors = []
    for url in geo_sources(kind):
        try:
            if progress:
                progress("downloading %s" % url)
            status, _, body = fetch(url, timeout=600, max_bytes=200 * 1024 * 1024)
            if status != 200:
                raise FetchError("HTTP %s" % status)
            data = maybe_gunzip(body)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target), suffix=".mmdb")
            os.close(fd)
            try:
                with open(tmp, "wb") as f:
                    f.write(data)
                info = _validate_mmdb(tmp, kind)
                os.replace(tmp, target)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            meta_path = str(paths.sub("geo", "meta.json"))
            meta: Dict[str, Any] = {}
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except (OSError, ValueError):
                    meta = {}
            meta[kind] = dict(info, url=url, updated_at=time.time(), size=len(data))
            atomic_write(meta_path, json.dumps(meta, indent=1).encode(), 0o644)
            return "ok (%s, %.1f MB)" % (info["type"], len(data) / 1e6)
        except (FetchError, OSError, InvalidDatabaseError, ValueError, KeyError) as e:
            errors.append("%s: %s" % (url, e))
            log.info("geo %s source failed: %s", kind, e)
    return "error: " + " | ".join(errors[-3:])


OUI_SOURCES = [
    ("https://standards-oui.ieee.org/oui/oui.csv", "ieee"),
    ("https://standards-oui.ieee.org/oui28/mam.csv", "ieee"),
    ("https://standards-oui.ieee.org/oui36/oui36.csv", "ieee"),
    ("https://cdn.jsdelivr.net/npm/oui-data/index.json", "json"),
]


def update_oui(max_age_days: float = 30, force: bool = False, fetch: Callable[..., Any] = http_get) -> str:
    target = str(paths.sub("oui.json"))
    if not force and os.path.exists(target) and (time.time() - os.stat(target).st_mtime) < max_age_days * 86400:
        return "fresh"
    merged: Dict[str, str] = {}
    errors = []
    have_ieee_main = False
    for url, fmt in OUI_SOURCES:
        if fmt == "json" and have_ieee_main:
            continue
        try:
            status, _, body = fetch(url, timeout=120, max_bytes=64 * 1024 * 1024)
            if status != 200:
                raise FetchError("HTTP %s" % status)
            text = body.decode("utf-8", "replace")
            part = parse_ieee_csv(text) if fmt == "ieee" else parse_oui_data_json(text)
            if not part:
                raise FetchError("no entries")
            if url.endswith("/oui.csv"):
                have_ieee_main = True
            merged.update(part)
        except (FetchError, ValueError) as e:
            errors.append("%s: %s" % (url, e))
    if len(merged) < 10000:
        return "error: " + " | ".join(errors[-3:]) if errors else "error: too few entries"
    atomic_write(target, json.dumps(merged, ensure_ascii=False, separators=(",", ":")).encode(), 0o644)
    return "ok (%d prefixes)" % len(merged)
