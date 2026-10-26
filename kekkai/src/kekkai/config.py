"""User configuration (config.json in the data dir), merged over defaults."""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

from kekkai import paths
from kekkai.util import atomic_write, log

DEFAULTS: Dict[str, Any] = {
    "monitor": {
        "interval_sec": 15,            # connections / ARP / DNS / proxy
        "lan_discovery_interval_sec": 300,
        "active_sweep": True,          # ping the local /24 so the ARP table fills up
        "posture_interval_sec": 1800,
        "exposure_interval_sec": 21600,
        "leak_check_interval_sec": 86400,   # ransomware.live leak-site check (only if watch.names is set)
        "learning_cycles": 2,          # first cycles only build the baseline
    },
    "watch": {
        # Your own identifiers to look for in public breach/leak sources. Leave empty to disable.
        "names": [],                   # company / org names, e.g. ["ACME Corp"]
        "domains": [],                 # your domains, e.g. ["acme.co.jp"]
    },
    "home": {"lat": None, "lon": None, "label": "HOME"},
    "intel": {
        "update_interval_hours": 12,
        "feeds": {
            "firehol_level1": True,
            "feodo": True,
            "et_compromised": True,
            "cins_army": True,
            "spamhaus_drop": True,
            "tor_exit": True,
        },
        "abuseipdb_key": None,
        "greynoise_key": None,
    },
    "privacy": {
        # Public-IP discovery and Shodan InternetDB lookups leave your machine.
        "external_lookups": True,
    },
    "notify": {"macos": True, "min_severity": "high", "webhook_url": None, "ntfy_url": None},
    "ai": {
        "provider": "auto",            # auto | ollama | openai | anthropic | off
        "ollama_url": "http://127.0.0.1:11434",
        "ollama_model": None,
        "openai_base_url": "http://127.0.0.1:1234/v1",
        "openai_model": None,
        "anthropic_model": "claude-opus-5-5",
        "redact_for_cloud": True,
    },
    "server": {"host": "127.0.0.1", "port": 47665, "open_browser": True},
    "scan": {"timeout_sec": 0.8, "concurrency": 256},
    "rules": {
        "muted": [],
        "suspicious_remote_ports": [23, 2323, 1337, 31337, 4444, 5555, 6666, 6667, 6668, 6669,
                                    50050, 1080, 9001, 9030, 3389, 445, 139, 135],
        "watch_countries": [],
    },
}


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: Dict[str, Any], path: str):
        self.data = data
        self.path = path

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value

    def save(self) -> None:
        atomic_write(self.path, (json.dumps(self.data, ensure_ascii=False, indent=2) + "\n").encode())


def load() -> Config:
    path = str(paths.sub("config.json"))
    user: Dict[str, Any] = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
            if not isinstance(user, dict):
                raise ValueError("top level must be an object")
        except (OSError, ValueError) as e:
            log.warning("config.json is invalid (%s); using defaults", e)
            user = {}
    cfg = Config(_merge(DEFAULTS, user), path)
    if not os.path.exists(path):
        try:
            cfg.save()
        except OSError:
            pass
    return cfg
