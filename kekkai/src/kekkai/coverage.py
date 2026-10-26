"""Evidence-based defense coverage; installation is never treated as active protection."""
import time
from pathlib import Path
from kekkai.util import find_cmd


def describe(monitor):
    now = time.time()
    state = monitor.monitoring_status()
    feeds = monitor.feeds.status()
    max_age = max(24, float(monitor.cfg.get("intel.update_interval_hours", 12)) * 2) * 3600
    ready = [f for f in feeds if f.get("status") == "ok" and f.get("entries", 0)
             and f.get("updated_at") and 0 <= now - f["updated_at"] <= max_age]
    sensor = monitor.sensor_status()
    beat = sensor.get("last_beat")
    capturing = bool(sensor.get("active") and beat and 0 <= now - beat < 30)
    nmap = bool(find_cmd("nmap"))
    lulu = any(p.exists() for p in (Path('/Applications/LuLu.app'), Path.home() / 'Applications/LuLu.app'))
    cards = [
        {"id": "connections", "label": "このMacの通信", "state": state["status"],
         "detail": state["label"], "action": "通信一覧と最終収集時刻を確認"},
        {"id": "feeds", "label": "危険IPとの照合", "state": ("active" if state["status"] == "live" else "ready") if ready else "unavailable",
         "detail": "%d/%d リストが更新済み。照合には通信収集が必要" % (len(ready), len(feeds)),
         "action": "脅威情報画面で更新状態を確認"},
        {"id": "sensor", "label": "パケット侵入検知", "state": "active" if capturing else "inactive",
         "detail": "センサーの生存信号あり" if capturing else "センサー未稼働。パケット検知は動いていません",
         "action": "必要な場合に権限付きのセンサーを起動"},
        {"id": "nmap", "label": "Nmap 詳細診断", "state": "available" if nmap else "unavailable",
         "detail": "利用可能。LAN機器の詳細スキャンで使用" if nmap else "未導入。標準のTCPスキャンは利用可能",
         "action": "自分が管理する機器のサービスを確認", "url": "https://nmap.org/download.html"},
        {"id": "blocking", "label": "通信の遮断", "state": "external",
         "detail": "KEKKAI自体には遮断機能なし。LuLuの稼働状態は未確認" if lulu else "KEKKAI自体には遮断機能なし。外部ファイアウォールで補完",
         "action": "LuLu等の専用ファイアウォールで通信許可を管理", "url": "https://objective-see.org/products/lulu.html"},
    ]
    return {"checked_at": now, "cards": cards,
            "limits": ["他の機器同士の通信を、このMacだけで全て監視することはできません。",
                       "開放ポートや不審な通信は調査の手掛かりで、侵害や脆弱性の確定ではありません。",
                       "アラートが無いことは安全の保証ではありません。"]}
