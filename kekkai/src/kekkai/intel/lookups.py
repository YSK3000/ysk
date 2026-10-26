"""On-demand reputation "connectors" for a single IP (only called when the user asks)."""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Callable, Dict, Optional

from kekkai.intel.exposure import internetdb
from kekkai.netutil import is_public
from kekkai.util import FetchError, http_get


def greynoise(ip: str, key: Optional[str] = None, fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if key:
        headers["key"] = key
    status, _, body = fetch("https://api.greynoise.io/v3/community/" + ip, timeout=12, max_bytes=256 * 1024,
                            headers=headers)
    if status in (200, 404):
        data = json.loads(body.decode("utf-8", "replace") or "{}")
        return {"found": status == 200 and bool(data.get("seen") or data.get("riot") or data.get("noise")),
                "noise": data.get("noise"), "riot": data.get("riot"), "classification": data.get("classification"),
                "name": data.get("name"), "last_seen": data.get("last_seen"), "link": data.get("link")}
    if status == 429:
        raise FetchError("GreyNoise rate limit reached (community API)")
    raise FetchError("GreyNoise HTTP %s" % status)


def abuseipdb(ip: str, key: str, fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    status, _, body = fetch("https://api.abuseipdb.com/api/v2/check?" + q, timeout=12, max_bytes=256 * 1024,
                            headers={"Key": key, "Accept": "application/json"})
    if status != 200:
        raise FetchError("AbuseIPDB HTTP %s" % status)
    d = json.loads(body.decode("utf-8", "replace")).get("data", {})
    return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"), "isp": d.get("isp"),
            "usage": d.get("usageType"), "domain": d.get("domain"), "last_reported": d.get("lastReportedAt")}


def enrich(ip: str, cfg: Any, fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
    """Query every configured connector; failures are reported per connector, never raised."""
    out: Dict[str, Any] = {"ip": ip}
    if not is_public(ip):
        out["note"] = "プライベートIPのため外部照会は行いません"
        return out
    if not cfg.get("privacy.external_lookups", True):
        out["note"] = "privacy.external_lookups=false のため外部照会は無効です"
        return out
    for name, fn in (("internetdb", lambda: internetdb(ip, fetch)),
                     ("greynoise", lambda: greynoise(ip, cfg.get("intel.greynoise_key"), fetch))):
        try:
            out[name] = fn()
        except (FetchError, ValueError) as e:
            out[name] = {"error": str(e)}
    key = cfg.get("intel.abuseipdb_key")
    if key:
        try:
            out["abuseipdb"] = abuseipdb(ip, key, fetch)
        except (FetchError, ValueError) as e:
            out["abuseipdb"] = {"error": str(e)}
    return out
