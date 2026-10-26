"""Check whether the user's own identifiers appear in public breach/leak sources.

* ransomware.live API v2 (no key, free, personal use; attribution required; data must not be re-served):
  https://www.ransomware.live/ — ransomware gangs' leak-site victim listings.
* Have I Been Pwned Pwned Passwords range API (k-anonymity, no key): only a password's SHA-1 prefix is sent.

KEKKAI only looks for identifiers the user registered (their own domains / company names). It records that a
match exists and where it was announced — it never downloads the leaked data itself.
"""
from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

from kekkai.util import FetchError, http_get

RL_BASE = "https://api.ransomware.live/v2"
ATTRIBUTION = "出典: Ransomware.live (https://www.ransomware.live)"
VICTIM_KEEP = ("victim", "domain", "group", "group_name", "country", "activity", "attackdate", "discovered",
               "published", "url", "post_title", "post_url", "claim_url")


def _norm(s: Optional[str]) -> str:
    return " ".join((s or "").lower().split())


def _domain(s: str) -> str:
    s = _norm(s)
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc or s
    host = s.split("/")[0].strip()
    return host[4:] if host.startswith("www.") else host


def search_ransomware_live(terms: List[str], fetch: Callable[..., Any] = http_get,
                           recent_days: int = 0) -> Dict[str, Any]:
    """Match the user's company names / domains against ransomware leak-site victim listings."""
    wants = [_norm(t) for t in terms if _norm(t)]
    doms = {_domain(t) for t in terms if "." in t}
    if not wants:
        return {"source": "ransomware.live", "matches": [], "checked": 0, "error": None}
    seen: Dict[str, Dict[str, Any]] = {}
    checked = 0
    error = None
    queries = {w.split()[0] for w in wants if len(w.split()[0]) >= 3}
    try:
        for q in sorted(queries)[:12]:
            status, _, body = fetch("%s/searchvictims/%s" % (RL_BASE, urllib.parse.quote(q)),
                                    timeout=30, max_bytes=16 * 1024 * 1024)
            if status != 200:
                continue
            rows = json.loads(body.decode("utf-8", "replace"))
            checked += len(rows) if isinstance(rows, list) else 0
            for r in rows if isinstance(rows, list) else []:
                vic, dom = _norm(r.get("victim") or r.get("post_title")), _domain(r.get("domain") or "")
                hit = (dom and dom in doms) or any(w == vic or (len(w) >= 5 and w in vic) for w in wants)
                if hit:
                    key = (r.get("url") or r.get("post_url") or "") + "|" + (r.get("victim") or r.get("post_title") or "")
                    seen[key] = {k: r.get(k) for k in VICTIM_KEEP if r.get(k) is not None}
    except (FetchError, ValueError) as e:
        error = str(e)
    return {"source": "ransomware.live", "attribution": ATTRIBUTION, "matches": list(seen.values()),
            "checked": checked, "error": error, "ts": time.time()}


def check(targets: List[str], fetch: Callable[..., Any] = http_get) -> Dict[str, Any]:
    rl = search_ransomware_live(targets, fetch=fetch)
    return {"ts": time.time(), "targets": targets, "sources": [rl],
            "match_count": sum(len(s["matches"]) for s in [rl])}
