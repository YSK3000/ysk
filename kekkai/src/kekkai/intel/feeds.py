"""Threat-intelligence IP feeds: download, normalize, match.

Only public addresses are ever matched (FireHOL level1 contains bogon/private ranges).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from kekkai import paths
from kekkai.intel.ipset import IPSet
from kekkai.netutil import is_public
from kekkai.util import FetchError, atomic_write, http_get, log

_IP_OR_CIDR = re.compile(r"^[0-9a-fA-F:.]+(?:/\d{1,3})?$")


def parse_plain(text: str) -> List[str]:
    """One IP/CIDR per line; '#' and ';' comments; tolerates trailing comments."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        tok = line.split()[0]
        if _valid(tok):
            out.append(tok)
    return out


def _valid(tok: str) -> bool:
    if not _IP_OR_CIDR.match(tok):
        return False
    try:
        ipaddress.ip_network(tok, strict=False)
        return True
    except ValueError:
        return False


def parse_spamhaus_json(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        cidr = obj.get("cidr")
        if isinstance(cidr, str) and _valid(cidr):
            out.append(cidr)
    return out


FEEDS: Dict[str, Dict[str, Any]] = {
    "feodo": {
        "label": "abuse.ch Feodo Tracker（ボットネットC2サーバー）",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "severity": "critical", "kind": "botnet-c2", "parser": parse_plain,
        "home": "https://feodotracker.abuse.ch/",
    },
    "et_compromised": {
        "label": "Emerging Threats 侵害済みホスト",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "severity": "high", "kind": "compromised", "parser": parse_plain,
        "home": "https://rules.emergingthreats.net/",
    },
    "spamhaus_drop": {
        "label": "Spamhaus DROP（乗っ取られた/犯罪用ネットワーク）",
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "severity": "high", "kind": "hijacked-netblock", "parser": parse_spamhaus_json,
        "home": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    },
    "firehol_level1": {
        "label": "FireHOL Level1（攻撃元・悪性IPの集約リスト）",
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "severity": "high", "kind": "attacker", "parser": parse_plain,
        "home": "https://iplists.firehol.org/",
    },
    "cins_army": {
        "label": "CINS Army（スキャン・攻撃を繰り返すIP）",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "severity": "medium", "kind": "scanner", "parser": parse_plain,
        "home": "https://cinsscore.com/",
    },
    "tor_exit": {
        "label": "Tor 出口ノード",
        "url": "https://check.torproject.org/torbulkexitlist",
        "severity": "low", "kind": "tor-exit", "parser": parse_plain,
        "home": "https://check.torproject.org/",
    },
}

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class FeedSet:
    def __init__(self, data_dir: Optional[str] = None):
        self.dir = os.path.join(data_dir or str(paths.data_dir()), "feeds")
        os.makedirs(self.dir, exist_ok=True)
        self.meta_path = os.path.join(self.dir, "meta.json")
        self._sets: Dict[str, IPSet] = {}
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------ status
    def meta(self) -> Dict[str, Any]:
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def status(self) -> List[Dict[str, Any]]:
        meta = self.meta()
        out = []
        for fid, f in FEEDS.items():
            m = meta.get(fid, {})
            out.append({"id": fid, "label": f["label"], "severity": f["severity"], "kind": f["kind"],
                        "home": f["home"], "entries": m.get("entries", 0), "updated_at": m.get("updated_at"),
                        "status": m.get("status", "never"), "error": m.get("error")})
        return out

    # ------------------------------------------------------------ update
    def update(self, enabled: Optional[Dict[str, bool]] = None, max_age_hours: float = 12,
               force: bool = False, fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
        meta = self.meta()
        report: Dict[str, Any] = {}
        for fid, f in FEEDS.items():
            if enabled is not None and not enabled.get(fid, True):
                report[fid] = "disabled"
                continue
            m = meta.get(fid, {})
            age_h = (time.time() - m.get("updated_at", 0)) / 3600.0
            if not force and m.get("status") == "ok" and age_h < max_age_hours:
                report[fid] = "fresh"
                continue
            try:
                status, _, body = fetch(f["url"], timeout=40, max_bytes=64 * 1024 * 1024)
                if status != 200:
                    raise FetchError("HTTP %s" % status)
                entries = f["parser"](body.decode("utf-8", "replace"))
                if not entries:
                    raise FetchError("no entries parsed (format change or auth required?)")
                atomic_write(os.path.join(self.dir, fid + ".txt"), ("\n".join(entries) + "\n").encode(), 0o644)
                meta[fid] = {"entries": len(entries), "updated_at": time.time(), "status": "ok"}
                report[fid] = "ok (%d)" % len(entries)
            except (FetchError, OSError, ValueError) as e:
                prev = meta.get(fid, {})
                meta[fid] = dict(prev, status="error", error=str(e)[:300], tried_at=time.time())
                if prev.get("status") == "ok":
                    meta[fid]["status"] = "stale"
                report[fid] = "error: %s" % e
                log.warning("feed %s update failed: %s", fid, e)
        atomic_write(self.meta_path, json.dumps(meta, indent=1).encode(), 0o644)
        self._loaded_at = 0.0
        return report

    # ------------------------------------------------------------ matching
    def _ensure_loaded(self) -> None:
        mt = _mtime(self.meta_path)
        if self._loaded_at and mt <= self._loaded_at:
            return
        with self._lock:
            sets: Dict[str, IPSet] = {}
            for fid in FEEDS:
                path = os.path.join(self.dir, fid + ".txt")
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as fh:
                            sets[fid] = IPSet(fh.read().splitlines())
                    except OSError:
                        continue
            self._sets = sets
            self._loaded_at = max(mt, 1.0)

    def match(self, ip: str) -> List[Dict[str, Any]]:
        if not is_public(ip):
            return []
        self._ensure_loaded()
        hits = []
        for fid, s in self._sets.items():
            if ip in s:
                f = FEEDS[fid]
                hits.append({"feed": fid, "label": f["label"], "severity": f["severity"], "kind": f["kind"]})
        hits.sort(key=lambda h: -SEV_RANK.get(h["severity"], 0))
        return hits

    @property
    def total_entries(self) -> int:
        self._ensure_loaded()
        return sum(len(s) for s in self._sets.values())


def _mtime(path: str) -> float:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0
