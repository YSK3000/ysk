"""Alert notifications: macOS Notification Center, generic webhook (Slack-compatible), ntfy."""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List

from kekkai.store import SEVERITY_ORDER
from kekkai.util import FetchError, http_get, log

SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}


class Notifier:
    def __init__(self, cfg: Any, platform: Any):
        self.cfg = cfg
        self.platform = platform
        self._sent: List[float] = []
        self._per_rule: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _allowed(self, alert: Dict[str, Any]) -> bool:
        min_sev = self.cfg.get("notify.min_severity", "high")
        if SEVERITY_ORDER.get(alert.get("severity", "info"), 0) < SEVERITY_ORDER.get(min_sev, 3):
            return False
        t = time.time()
        with self._lock:
            self._sent = [s for s in self._sent if t - s < 3600]
            if len(self._sent) >= 12:
                return False
            if t - self._per_rule.get(alert.get("rule", ""), 0) < 30:
                return False
            self._sent.append(t)
            self._per_rule[alert.get("rule", "")] = t
        return True

    def alert(self, alert: Dict[str, Any]) -> None:
        if not self._allowed(alert):
            return
        title = "結界 KEKKAI ⚠ %s" % SEV_JA.get(alert.get("severity", ""), "")
        body = "%s\n%s" % (alert.get("title", ""), (alert.get("detail") or "")[:160])
        if self.cfg.get("notify.macos", True):
            try:
                self.platform.notify(title, body)
            except Exception as e:  # noqa: BLE001
                log.debug("local notification failed: %s", e)
        hooks = [(self.cfg.get("notify.webhook_url"), "webhook"), (self.cfg.get("notify.ntfy_url"), "ntfy")]
        for url, kind in hooks:
            if url:
                threading.Thread(target=self._post, args=(url, kind, title, body, alert), daemon=True).start()

    def _post(self, url: str, kind: str, title: str, body: str, alert: Dict[str, Any]) -> None:
        try:
            if kind == "ntfy":
                prio = {"critical": "5", "high": "4"}.get(alert.get("severity", ""), "3")
                http_get(url, method="POST", data=body.encode(), timeout=10,
                         headers={"Title": title.encode("ascii", "ignore").decode() or "KEKKAI", "Priority": prio,
                                  "Tags": "warning"})
            else:
                http_get(url, method="POST", timeout=10, headers={"Content-Type": "application/json"},
                         data=json.dumps({"text": "%s\n%s" % (title, body)}, ensure_ascii=False).encode())
        except FetchError as e:
            log.warning("%s notification failed: %s", kind, e)
