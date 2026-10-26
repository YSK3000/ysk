"""Public vulnerability knowledge, matched against what KEKKAI sees.

* CISA KEV — vulnerabilities confirmed exploited in the wild (CC0):
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog (mirror: github.com/cisagov/kev-data)
* SOFA — Apple's macOS security releases with their CVEs and actively exploited CVEs, compiled by the
  Mac Admins Open Source project from https://support.apple.com/en-us/100100 (github.com/macadmins/sofa)
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from kekkai import paths
from kekkai.util import FetchError, atomic_write, http_get

KEV_SOURCES = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
               "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"]
SOFA_SOURCES = ["https://sofafeed.macadmins.io/v1/macos_data_feed.json",
                "https://raw.githubusercontent.com/macadmins/sofa/main/v1/macos_data_feed.json"]
KEV_KEEP = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "knownRansomwareCampaignUse",
            "requiredAction")
KEV_MIN = 500  # the real catalog has well over a thousand entries; less means a broken download
STALE_DAYS = 400  # a macOS line without any security release for this long is very likely out of support
# Vendors whose KEV entries are about their OS / enterprise products, not home gadgets: matching their
# devices by vendor alone only produces noise (the Mac itself is checked by version through SOFA).
VENDOR_SKIP = {"apple", "microsoft", "google", "android", "samsung", "intel", "amd", "linux", "mozilla"}


def _path(name: str) -> str:
    return str(paths.sub("vulns", name))


def _compact_kev(data: Dict[str, Any]) -> Dict[str, Any]:
    vulns = data.get("vulnerabilities") or []
    if len(vulns) < KEV_MIN:
        raise ValueError("KEV has only %d entries" % len(vulns))
    return {"catalogVersion": data.get("catalogVersion"), "dateReleased": data.get("dateReleased"),
            "vulnerabilities": [{k: v.get(k) for k in KEV_KEEP} for v in vulns]}


def _compact_sofa(data: Dict[str, Any]) -> Dict[str, Any]:
    lines = []
    for o in data.get("OSVersions") or []:
        rels = [{"name": r.get("UpdateName"), "version": r.get("ProductVersion"), "date": r.get("ReleaseDate"),
                 "cves": sorted(r.get("CVEs") or {}), "exploited": sorted(r.get("ActivelyExploitedCVEs") or [])}
                for r in o.get("SecurityReleases") or [] if r.get("ProductName") == "macOS" and r.get("ProductVersion")]
        latest = o.get("Latest") or {}
        lines.append({"name": o.get("OSVersion"), "latest": latest.get("ProductVersion"), "latest_date": latest.get("ReleaseDate"),
                      "releases": rels})
    if not lines:
        raise ValueError("no OSVersions in SOFA feed")
    return {"lines": lines}


def update(max_age_hours: float = 24, force: bool = False, fetch: Callable[..., Any] = http_get) -> Dict[str, str]:
    out = {}
    for name, sources, compact in (("kev.json", KEV_SOURCES, _compact_kev), ("sofa_macos.json", SOFA_SOURCES, _compact_sofa)):
        target = _path(name)
        if not force and os.path.exists(target) and time.time() - os.path.getmtime(target) < max_age_hours * 3600:
            out[name] = "fresh"
            continue
        errors = []
        for url in sources:
            try:
                status, _, body = fetch(url, timeout=60, max_bytes=32 * 1024 * 1024)
                if status != 200:
                    raise FetchError("HTTP %s" % status)
                data = compact(json.loads(body.decode("utf-8")))
                atomic_write(target, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), 0o644)
                out[name] = "ok"
                break
            except (FetchError, ValueError, UnicodeDecodeError) as e:
                errors.append("%s: %s" % (url.split("/")[2], e))
        else:
            out[name] = "error: " + " | ".join(errors)
    return out


def _version(s: Optional[str]) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def _norm(s: str) -> List[str]:
    return [t for t in re.split(r"[^0-9a-z]+", (s or "").lower()) if t]


def _grams(tokens: List[str]) -> set:
    """Single tokens and joined pairs, so "D-Link" == "dlink" and "TP LINK" == "tplink" (never substrings:
    "NEC" must not match "ConnectWise")."""
    return set(tokens) | {a + b for a, b in zip(tokens, tokens[1:])}


class VulnDB:
    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[float, Any]] = {}

    def _load(self, name: str) -> Any:
        p = _path(name)
        try:
            mt = os.path.getmtime(p)
        except OSError:
            return None
        hit = self._cache.get(name)
        if hit and hit[0] == mt:
            return hit[1]
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        self._cache[name] = (mt, data)
        return data

    @property
    def kev(self) -> Dict[str, Dict[str, Any]]:
        data = self._load("kev.json") or {}
        mt = (self._cache.get("kev.json") or (None,))[0]
        hit = self._cache.get("kev_index")
        if hit and hit[0] == mt:
            return hit[1]
        idx = {v["cveID"]: v for v in data.get("vulnerabilities") or [] if v.get("cveID")}
        self._cache["kev_index"] = (mt, idx)
        return idx

    def status(self) -> Dict[str, Any]:
        kev = self._load("kev.json") or {}
        sofa = self._load("sofa_macos.json") or {}
        return {"kev_entries": len(kev.get("vulnerabilities") or []), "kev_version": kev.get("catalogVersion"),
                "sofa_lines": len(sofa.get("lines") or [])}

    def kev_for(self, cves: Iterable[str]) -> List[Dict[str, Any]]:
        kev = self.kev
        return [kev[c] for c in dict.fromkeys(c.upper() for c in cves) if c.upper() in kev]

    def macos(self, version: Optional[str], now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Which publicly known macOS vulnerabilities are still unpatched on this version."""
        sofa = self._load("sofa_macos.json")
        mine = _version(version)
        if not sofa or not mine:
            return None
        line = next((x for x in sofa["lines"] if _version(x.get("latest"))[:1] == mine[:1]), None)
        newest_major = max((_version(x.get("latest"))[:1] for x in sofa["lines"] if x.get("latest")), default=mine[:1])
        if line is None:
            return {"version": version, "line": None, "unknown_line": True, "newer_major": newest_major > mine[:1]}
        missing = [r for r in line["releases"] if _version(r["version"]) > mine]
        cves = sorted({c for r in missing for c in r["cves"]})
        exploited = sorted({c for r in missing for c in r["exploited"]})
        kev = self.kev_for(cves)
        last = max((r["date"] for r in line["releases"] if r.get("date")), default=line.get("latest_date") or "")
        stale = None
        try:
            stale = int(((now or time.time()) - time.mktime(time.strptime(last[:10], "%Y-%m-%d"))) // 86400)
        except ValueError:
            pass
        return {"version": version, "line": line["name"], "latest": line.get("latest"), "missing_releases": [r["name"] for r in missing],
                "cves": len(cves), "exploited": sorted(set(exploited) | {k["cveID"] for k in kev}),
                "kev": [k["cveID"] for k in kev], "days_since_security_release": stale,
                "newer_major": newest_major > mine[:1], "unknown_line": False}

    def device_hits(self, vendor: Optional[str], models: Iterable[Optional[str]]) -> Dict[str, Any]:
        """KEV entries for a LAN device's vendor, and those whose product/name mention its model."""
        vg = _grams(_norm(vendor or ""))
        if not vg or vg & VENDOR_SKIP:
            return {"vendor": [], "model": []}
        by_vendor = []
        for v in self.kev.values():
            kt = _norm(v.get("vendorProject") or "")
            if kt and ("".join(kt) in vg or (len(kt[0]) >= 3 and kt[0] in vg)):
                by_vendor.append(v)
        model_tokens = set()
        for m in models:
            for t in _norm(m or ""):
                if len(t) >= 3 and re.search(r"\d", t):
                    model_tokens.add(t)
            toks = _norm(m or "")
            model_tokens |= {a + b for a, b in zip(toks, toks[1:]) if re.search(r"\d", a + b) and len(a + b) >= 4}
        by_model = [v for v in by_vendor
                    if model_tokens & _grams(_norm((v.get("product") or "") + " " + (v.get("vulnerabilityName") or "")))]
        return {"vendor": by_vendor, "model": by_model}
