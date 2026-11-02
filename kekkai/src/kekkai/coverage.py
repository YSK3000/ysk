"""Evidence-based defense coverage; installation is never treated as active protection."""
import time
from pathlib import Path
from kekkai.util import find_cmd


def _ago(sec):
    if sec < 3600:
        return "%d分前" % max(1, sec // 60)
    if sec < 86400 * 2:
        return "%d時間前" % (sec // 3600)
    return "%d日前" % (sec // 86400)


def _vulnscan_card(monitor, now):
    last = monitor.state.get("vulnscan") or {}
    card = {"id": "vulnscan", "label": "脆弱性診断", "action": "脆弱性診断の画面で実行・結果を確認"}
    if monitor.state.get("vulnscan_running"):
        return dict(card, state="running", detail="診断を実行中です")
    if not last.get("ts"):
        return dict(card, state="inactive", detail="まだ診断していません。画面または ./kekkai vulnscan で実行できます")
    s = last.get("summary") or {}
    week = float(monitor.cfg.get("monitor.vulnscan_interval_sec", 604800))
    age = now - float(last["ts"])
    detail = "%sに診断：%s（緊急 %d・高 %d）" % (_ago(age), s.get("label", "-"), s.get("critical", 0), s.get("high", 0))
    if not s.get("complete", True):
        return dict(card, state="partial", detail=detail + "。診断できていない範囲あり")
    return dict(card, state="active" if age <= week * 2 else "stale", detail=detail if age <= week * 2 else detail + "。結果が古くなっています")


def _exposure_card(monitor, now):
    exp = monitor.state.get("exposure") or {}
    card = {"id": "exposure", "label": "外部からの見え方", "action": "外部公開の画面でポート・CVEを確認"}
    if exp.get("disabled"):
        return dict(card, state="disabled", detail="外部照会がオフのため確認していません")
    if not exp.get("checked_at"):
        return dict(card, state="inactive", detail="まだ確認していません（Shodan InternetDB）")
    age = now - float(exp["checked_at"])
    iv = float(monitor.cfg.get("monitor.exposure_interval_sec", 21600))
    if exp.get("shared_ipv4"):
        return dict(card, state="limited", detail="%sに確認。公開IPが共有(CGNAT等)のため外部から直接は届きにくい構成" % _ago(age))
    ports = len(((exp.get("internetdb") or {}).get("ports")) or [])
    return dict(card, state="active" if age <= iv * 3 else "stale",
                detail="%sに確認。外から見えるポート %d 件・新たな公開は即警告" % (_ago(age), ports))


def _leaks_card(monitor):
    lk = monitor.state.get("leaks") or {}
    card = {"id": "leaks", "label": "ダークウェブの流出監視", "action": "config の watch.names / watch.domains に自社名・ドメインを登録"}
    if not lk.get("enabled"):
        return dict(card, state="inactive", detail="監視対象が未設定（自分の組織名・ドメインを登録すると毎日照合）")
    return dict(card, state="active", detail="%d 件の語を毎日照合。一致 %d 件" % (len(lk.get("targets") or []), lk.get("match_count") or 0))


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
        _vulnscan_card(monitor, now),
        _exposure_card(monitor, now),
        _leaks_card(monitor),
        {"id": "blocking", "label": "通信の遮断", "state": "external",
         "detail": "KEKKAI自体には遮断機能なし。LuLuの稼働状態は未確認" if lulu else "KEKKAI自体には遮断機能なし。外部ファイアウォールで補完",
         "action": "LuLu等の専用ファイアウォールで通信許可を管理", "url": "https://objective-see.org/products/lulu.html"},
    ]
    return {"checked_at": now, "cards": cards,
            "limits": ["他の機器同士の通信を、このMacだけで全て監視することはできません。",
                       "開放ポートや不審な通信は調査の手掛かりで、侵害や脆弱性の確定ではありません。",
                       "アラートが無いことは安全の保証ではありません。"]}
