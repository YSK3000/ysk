"""Known vulnerabilities for a detected product version, from NIST's NVD (CVE API 2.0).

nmap -sV reports each service's CPE, e.g. ``cpe:/a:openbsd:openssh:7.4``. The NVD API matches a CPE
against every CVE's affected-version ranges server-side (``virtualMatchString``), so the answer is the
CVEs that apply to *that version* — not every CVE ever filed for the product.

* API: https://services.nvd.nist.gov/rest/json/cves/2.0  (docs: https://nvd.nist.gov/developers/vulnerabilities)
* Public rate limit: 5 requests per rolling 30 s; 50 with a free API key (sent as the ``apiKey`` header).
* Results are cached per CPE for a day. Only the product/version string is sent, never anything about the user.

Version-based matching cannot see vendor backports (e.g. a Linux distribution that patches OpenSSH without
changing its version), so a match is "likely affected — confirm the installed build", not proof.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from kekkai.util import FetchError, http_get

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_GAP = 6.5        # seconds between requests without a key (5 per 30 s, with margin)
RATE_GAP_KEY = 0.7    # with a key (50 per 30 s)
CACHE_TTL = 86400
PAGE = 200
_SAFE = re.compile(r"^[a-z0-9._\-+~]+$")
SEV_ORDER = ["none", "low", "medium", "high", "critical"]


def cpe23(cpe: Optional[str]) -> Optional[str]:
    """``cpe:/a:openbsd:openssh:7.4`` (CPE 2.2, as nmap prints it) -> ``cpe:2.3:a:openbsd:openssh:7.4``.

    None unless part, vendor, product and a concrete version are present and plain: a CPE without a
    version would match every CVE ever filed for the product (pure false positives).
    """
    s = (cpe or "").strip().lower()
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")[2:]
    elif s.startswith("cpe:/"):
        parts = s[5:].split(":")
    else:
        return None
    if len(parts) < 4:
        return None
    part, vendor, product, version = parts[:4]
    if part not in ("a", "o", "h") or version in ("", "*", "-"):
        return None
    if not all(_SAFE.match(x) for x in (vendor, product, version)):
        return None
    return "cpe:2.3:%s:%s:%s:%s" % (part, vendor, product, version)


def vendor_product(cpe: Optional[str]) -> Optional[Tuple[str, str]]:
    """(vendor, product) from a CPE even when the version is missing; used for the offline KEV fallback."""
    s = (cpe or "").strip().lower()
    parts = s.split(":")[2:] if s.startswith("cpe:2.3:") else (s[5:].split(":") if s.startswith("cpe:/") else [])
    if len(parts) < 3 or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def _score(cve: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """Best available CVSS: v4.0, then v3.1, v3.0, v2 (NVD's primary score preferred)."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        prim = next((x for x in arr if isinstance(x, dict) and x.get("type") == "Primary"), arr[0])
        data = (prim or {}).get("cvssData") or {}
        sev = data.get("baseSeverity") or (prim or {}).get("baseSeverity")  # v2 keeps it outside cvssData
        score = data.get("baseScore")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        return score, (str(sev).lower() if sev else severity_from_score(score)), data.get("version")
    return None, None, None


def severity_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "none"


def parse(body: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """NVD CVE API 2.0 response -> compact CVE records (rejected CVEs dropped), most severe first."""
    data = json.loads(body.decode("utf-8", "replace"))
    out = []
    for v in data.get("vulnerabilities") or []:
        c = (v or {}).get("cve") or {}
        cid = str(c.get("id") or "")
        if not cid.startswith("CVE-") or str(c.get("vulnStatus") or "").lower() == "rejected":
            continue
        score, sev, ver = _score(c)
        desc = next((d.get("value") for d in c.get("descriptions") or []
                     if isinstance(d, dict) and d.get("lang") == "en"), "") or ""
        out.append({"id": cid, "score": score, "severity": sev, "cvss": ver,
                    "kev": bool(c.get("cisaExploitAdd")), "kev_due": c.get("cisaActionDue"),
                    "published": str(c.get("published") or "")[:10], "summary": desc[:240]})
    out.sort(key=lambda r: (r["kev"], r["score"] or 0.0), reverse=True)
    try:
        total = int(data.get("totalResults") or len(out))
    except (TypeError, ValueError):
        total = len(out)
    return out, total


class NVD:
    """CPE -> CVEs with NVD's rate limit respected and a one-day on-disk cache."""

    def __init__(self, cache_dir: Path, fetch: Callable[..., Any] = http_get, api_key: Optional[str] = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.cache_dir = Path(cache_dir)
        self.fetch = fetch
        self.api_key = api_key or None
        self.clock = clock
        self.sleep = sleep
        self._last = 0.0
        self.queried = 0
        self.cache_hits = 0
        self.rate_limited = False

    def _path(self, c23: str) -> Path:
        return self.cache_dir / (hashlib.sha1(c23.encode()).hexdigest() + ".json")

    def _cache_get(self, c23: str) -> Optional[Dict[str, Any]]:
        p = self._path(c23)
        try:
            if self.clock() - p.stat().st_mtime < CACHE_TTL:
                with open(str(p), "r", encoding="utf-8") as f:
                    res = json.load(f)
                if isinstance(res, dict) and res.get("query") == c23:
                    return dict(res, cached=True)
        except (OSError, ValueError):
            pass
        return None

    def _cache_put(self, c23: str, res: Dict[str, Any]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._path(c23).with_suffix(".tmp")
            with open(str(tmp), "w", encoding="utf-8") as f:
                json.dump(res, f, ensure_ascii=False)
            tmp.replace(self._path(c23))
        except OSError:
            pass

    def cves_for(self, cpe: str) -> Dict[str, Any]:
        c23 = cpe23(cpe)
        base: Dict[str, Any] = {"cpe": cpe, "query": c23, "cves": [], "total": 0, "error": None,
                                "skipped": False, "cached": False}
        if not c23:
            return dict(base, skipped=True, error="版が特定できないため照合しません（誤検知防止）")
        cached = self._cache_get(c23)
        if cached is not None:
            self.cache_hits += 1
            return cached
        if self.rate_limited:
            return dict(base, error="NVDの回数制限中のため未照合")
        wait = (RATE_GAP_KEY if self.api_key else RATE_GAP) - (self.clock() - self._last)
        if self._last and wait > 0:
            self.sleep(wait)
        url = NVD_URL + "?" + urllib.parse.urlencode({"virtualMatchString": c23, "resultsPerPage": PAGE})
        try:
            status, _, body = self.fetch(url, timeout=40, max_bytes=48 * 1024 * 1024,
                                         headers={"apiKey": self.api_key} if self.api_key else None)
        except FetchError as e:
            self._last = self.clock()
            return dict(base, error="NVDに接続できません: %s" % e)
        self._last = self.clock()
        self.queried += 1
        if status in (403, 429, 503):  # NVD has answered 403 (and 503 under load) past the rate window
            self.rate_limited = True
            return dict(base, error="NVDの回数制限（HTTP %s）。時間をおいて再実行してください" % status)
        if status != 200:  # never cache a failed lookup as "no CVEs": that would read as safe
            return dict(base, error="NVD HTTP %s" % status)
        try:
            cves, total = parse(body)
        except ValueError as e:
            return dict(base, error="NVDの応答を解析できません: %s" % e)
        res = dict(base, cves=cves, total=total)
        self._cache_put(c23, res)
        return res
