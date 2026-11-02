"""Command line interface: `./kekkai <command>` (or `python3 -m kekkai <command>`)."""
from __future__ import annotations

import argparse
import logging
import os
import plistlib
import sys
import time
from typing import Any, List, Optional

from kekkai import __version__, paths
from kekkai.util import IS_MACOS, dumps, run

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
SEV_COLOR = {"critical": "1;37;41", "high": "1;31", "medium": "1;33", "low": "1;34", "info": "2"}
SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}
AGENT_LABEL = "com.kekkai.monitor"


def c(text: str, code: str) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if COLOR else text


BANNER = r"""
   ⬡ ⬡ ⬡   結界  K E K K A I
  ⬡ ⬢ ⬡   HOME NETWORK DEFENSE GRID  v{v}
   ⬡ ⬡ ⬡
"""


def banner() -> None:
    print(c(BANNER.format(v=__version__).rstrip("\n"), "36"))


def width(s: str) -> int:
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def table(rows: List[List[Any]], headers: List[str]) -> None:
    data = [[str(x if x is not None else "-") for x in r] for r in rows]
    cols = [max([width(h)] + [width(r[i]) for r in data]) for i, h in enumerate(headers)]
    cols = [min(w, 42) for w in cols]

    def cell(s: str, w: int) -> str:
        while width(s) > w:
            s = s[:-2] + "…"
        return s + " " * (w - width(s))

    print("  ".join(c(cell(h, cols[i]), "1;36") for i, h in enumerate(headers)))
    print("  ".join("─" * w for w in cols))
    for r in data:
        print("  ".join(cell(x, cols[i]) for i, x in enumerate(r)))


def monitor() -> Any:
    from kekkai import config
    from kekkai.monitor import Monitor
    return Monitor(config.load())


# ---------------------------------------------------------------------- commands

def cmd_serve(a: argparse.Namespace) -> int:
    from kekkai.live_runtime import single_monitor
    with single_monitor() as acquired:
        if not acquired:
            print("監視はすでに起動しています。./kekkai open で画面を開いてください。")
            return 1
        return _serve_live(a)


def _serve_live(a: argparse.Namespace) -> int:
    from kekkai import config, server
    from kekkai.discovery.portscan import raise_fd_limit
    raise_fd_limit()
    banner()
    cfg = config.load()
    m = monitor()
    m.start()
    port = a.port or int(cfg.get("server.port", 47665))

    def ready(url: str) -> None:
        print("  ダッシュボード: " + c(url, "1;4;36"))
        print("  （このURLは合言葉付きです。他人に共有しないでください。停止: Ctrl+C）")
        print("  データ: %s" % paths.data_dir())

    try:
        server.serve(m, cfg, port=port, open_browser=not a.no_browser and cfg.get("server.open_browser", True),
                     ready=ready)
    except KeyboardInterrupt:
        print("\n  停止しました")
    finally:
        m.stop()
    return 0


def cmd_open(a: argparse.Namespace) -> int:
    from kekkai import server
    from kekkai.platforms import get_platform
    url = server.session_url() if server.session_alive() else None
    if not url:
        print("ダッシュボードが起動していません: ./kekkai setup（自動起動の登録）または ./kekkai serve")
        return 1
    print(url)
    get_platform().open_url(url)
    return 0


def cmd_setup(a: argparse.Namespace) -> int:
    banner()
    print("  初期セットアップ: GeoIP / MACベンダー / 脅威フィードを取得します（数分かかります）\n")
    from kekkai import config, doctor
    from kekkai.intel import updater
    from kekkai.intel.feeds import FeedSet
    cfg = config.load()
    if not a.no_download:
        print("  [1/4] GeoIP (都市) …", updater.update_geo("city", force=a.force, progress=lambda s: None))
        print("  [2/4] GeoIP (ASN)  …", updater.update_geo("asn", force=a.force))
        print("  [3/4] MACベンダー  …", updater.update_oui(force=a.force))
        from kekkai.intel import vulns
        print("  [+]   脆弱性DB     …", ", ".join("%s=%s" % kv for kv in vulns.update(force=a.force).items()))
        rep = FeedSet().update(cfg.get("intel.feeds"), force=True)
        print("  [4/4] 脅威フィード …", ", ".join("%s=%s" % kv for kv in rep.items()))
        from kekkai import tools
        if IS_MACOS and not tools.nmap_status()["installed"] and sys.stdin.isatty():
            print("\n  nmap（LAN機器のサービスと版を特定し、脆弱性診断の精度を上げる）が入っていません。")
            cmd_install_nmap(argparse.Namespace(method=None, yes=False, json=False))
    print("\n  自己診断:")
    worst = doctor.print_report(doctor.run_checks(cfg, quick=True), COLOR)
    if not IS_MACOS or a.no_agent:
        print("\n  起動:  ./kekkai serve   （ダッシュボードが開きます）")
        return 0 if worst < 2 else 1
    print("\n  自動起動を登録します（ログイン中は常に監視。解除: ./kekkai uninstall-agent）")
    if cmd_install_agent(a) != 0:
        return 1
    from kekkai import server, service
    for _ in range(120):
        if server.session_alive():
            break
        time.sleep(0.5)
    if cmd_open(a) != 0:
        print("  ダッシュボードの起動を確認できません。ログ: ~/Library/Logs/kekkai.log")
        return 1
    if not service.status()["installed"]:
        print("\n  仕上げ（推奨）: sudo ./kekkai install-sensor")
        print("    ポートスキャン・ARP偽装・危険ドメインへのアクセスを、Macの起動中ずっとリアルタイムで検知します")
    return 0 if worst < 2 else 1


def cmd_install_nmap(a: argparse.Namespace) -> int:
    from kekkai import tools
    st = tools.nmap_status()
    if not st["supported"]:
        print("macOS 専用です（Linux はディストリビューションのパッケージで nmap を入れてください）")
        return 2
    if st["installed"] and not a.method:
        print("  nmap は導入済みです: %s（%s）" % (st["version"], st["path"]))
        return 0
    method = a.method or st["method"]
    if method == "brew":
        print("  Homebrew で nmap を入れます（パスワード不要・1〜5分）。")
    else:
        print("  nmap.org 公式のインストーラーで nmap を入れます。")
        print("   ・公式サイトから取得し、公式が公開している SHA-256 と照合します（不一致なら中止）")
        print("   ・macOS のパスワード入力画面が出ます（パスワードは macOS に渡り、KEKKAI は見ません）")
        print("   ・入るのは nmap だけです（Zenmap などの付属アプリは入れません）")
        if st["needs_rosetta"]:
            print("   ・nmap 公式版は Intel 用のため、Apple の Rosetta 2 も入ります（Appleの使用許諾に同意したことになります）")
    if not a.yes:
        if not sys.stdin.isatty():
            print("  確認できないため中止しました（--yes で実行）")
            return 2
        if input("  続けますか？ [Y/n] ").strip().lower() not in ("", "y", "yes"):
            print("  中止しました")
            return 1
    res = tools.install_nmap(progress=lambda msg: print("  …", msg), prefer=method)
    for line in tools.describe_result(res):
        print("  " + line)
    if a.json:
        print(dumps(res, indent=2))
    return 0 if res.get("ok") else 1


def cmd_update(a: argparse.Namespace) -> int:
    m = monitor()
    rep = m.intel_cycle(force=a.force)
    for k, v in rep.items():
        if isinstance(v, dict):
            for fk, fv in v.items():
                print("  %-16s %s" % (fk, fv))
        else:
            print("  %-16s %s" % (k, v))
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    from kekkai import config, doctor
    banner()
    worst = doctor.print_report(doctor.run_checks(config.load(), quick=a.quick), COLOR)
    return 0 if worst < 2 else 1


def _kind_ja(kind: Optional[str]) -> str:
    from kekkai.discovery.lan import KIND_LABELS
    return KIND_LABELS.get(kind or "unknown", kind or "-")


def cmd_scan(a: argparse.Namespace) -> int:
    from kekkai.discovery.portscan import raise_fd_limit
    raise_fd_limit()
    m = monitor()
    m.fast_cycle()
    if not a.json:
        print("  LANを探索中…（10秒ほど）")
    stats = m.lan_cycle(active=not a.passive)
    net = m.state.get("network") or {}
    devs = m.store.devices(net.get("id")) if net.get("id") else []
    if a.json:
        print(dumps({"network": net, "stats": stats, "devices": devs}, indent=1))
        return 0
    print("  ネットワーク: %s  GW %s (%s)  %s" % (net.get("subnet"), net.get("gateway"), net.get("gateway_mac"), stats))
    table([[d["ip"], d.get("label") or d.get("hostname"), _kind_ja(d.get("kind")), d.get("vendor"), d["mac"],
            "✓" if d.get("trusted") else ("NEW" if time.time() - (d.get("first_seen") or 0) < 3600 else "")]
           for d in sorted(devs, key=lambda x: [int(p) if p.isdigit() else 0 for p in (x.get("ip") or "0").split(".")])],
          ["IP", "名前", "種別", "メーカー", "MAC", "信頼"])
    _print_new_alerts(m)
    return 0


def cmd_devices(a: argparse.Namespace) -> int:
    m = monitor()
    m.fast_cycle()
    net = m.state.get("network") or {}
    devs = m.store.devices(net.get("id")) if net.get("id") else []
    if a.json:
        print(dumps(devs, indent=1))
        return 0
    table([[d["ip"], d.get("label") or d.get("hostname"), _kind_ja(d.get("kind")), d.get("vendor"), d["mac"],
            ",".join(str(p["port"]) for p in (d.get("ports") or [])[:8])] for d in devs],
          ["IP", "名前", "種別", "メーカー", "MAC", "開放ポート"])
    return 0


def cmd_conns(a: argparse.Namespace) -> int:
    m = monitor()
    m.fast_cycle()
    rows = m.snapshot("connections") or []
    if not a.all:
        rows = [r for r in rows if r.get("scope") == "internet"]
    if a.risky:
        rows = [r for r in rows if r.get("risk") != "ok"]
    if a.json:
        print(dumps(rows, indent=1))
        return 0
    table([[r.get("risk"), r.get("process"), "受信" if r.get("direction") == "in" else "送信", "%s:%s" % (r["raddr"], r["rport"]),
            r["proto"], ((r.get("geo") or {}).get("country") or r.get("scope")), (r.get("geo") or {}).get("org"),
            ",".join(r.get("flags") or [])] for r in rows[:200]],
          ["リスク", "プロセス", "方向", "宛先", "proto", "国", "組織", "検知"])
    _print_new_alerts(m)
    return 0


def cmd_alerts(a: argparse.Namespace) -> int:
    m = monitor()
    rows = m.store.alerts(None if a.all else "active", limit=100)
    if a.json:
        print(dumps(rows, indent=1))
        return 0
    if not rows:
        print("  未対応のアラートはありません")
        return 0
    for r in rows:
        print("%s %s  %s" % (c(" %s " % SEV_JA.get(r["severity"], r["severity"]), SEV_COLOR.get(r["severity"], "0")),
                             c(r["title"], "1"), c("#%d %s ×%d" % (r["id"], time.strftime("%m/%d %H:%M", time.localtime(r["last_ts"])),
                                                                      r["count"]), "2")))
        print("     %s" % r["detail"])
        if r.get("advice"):
            print(c("     → %s" % r["advice"], "36"))
    return 0


def cmd_audit(a: argparse.Namespace) -> int:
    m = monitor()
    m.fast_cycle()
    res = m.posture_cycle(slow=a.detailed)
    if a.json:
        print(dumps(res, indent=1))
        return 0
    banner()
    print("  防御スコア: %s / 100\n" % c(str(res.get("score")), "1;36"))
    marks = {"pass": c("合格", "32"), "warn": c("要確認", "33"), "fail": c("要対策", "1;31"), "info": c("情報", "36"),
             "unknown": c("不明", "2")}
    for ch in res["checks"]:
        print("  %s  %s — %s" % (marks.get(ch["status"], ch["status"]), c(ch["title"], "1"), ch["detail"]))
        if ch.get("fix") and ch["status"] in ("fail", "warn", "info"):
            print(c("          → %s" % ch["fix"], "36"))
    return 0


def cmd_exposure(a: argparse.Namespace) -> int:
    m = monitor()
    m.fast_cycle()
    res = m.exposure_cycle()
    if a.json:
        print(dumps(res, indent=1))
        return 0
    print("  公開IP: %s  (共有IPv4: %s)" % (res.get("public_ip"), "はい" if res.get("shared_ipv4") else "いいえ/不明"))
    idb = res.get("internetdb") or {}
    print("  Shodan InternetDB: %s / ports=%s / vulns=%s" % ("記録あり" if idb.get("found") else "記録なし",
                                                         idb.get("ports") or "-", (idb.get("vulns") or [])[:8] or "-"))
    for f in res.get("findings", []):
        print("  [%s] %s — %s" % (SEV_JA.get(f["severity"], f["severity"]), f["title"], f["detail"]))
    return 0


def cmd_portscan(a: argparse.Namespace) -> int:
    from kekkai.discovery import nmap
    from kekkai.discovery.portscan import ScopeError, raise_fd_limit, scan_host
    raise_fd_limit()
    ports = [int(p) for p in a.ports.split(",")] if a.ports else None
    use_nmap = a.deep or (not a.tcp and not ports and nmap.available())
    try:
        res = nmap.scan(a.ip) if use_nmap else scan_host(a.ip, ports=ports)
    except (ScopeError, RuntimeError) as e:
        print("  " + c(str(e), "31"))
        return 2
    if a.json:
        print(dumps(res, indent=1))
        return 0
    print("  %s: %d ポートを %.1f秒で確認（%s）" % (res["ip"], res["scanned"], res["duration"], res["method"]))
    table([[p["port"], p.get("service"), SEV_JA.get(p.get("risk"), p.get("risk")), p.get("banner"), p.get("note")] for p in res["open"]],
          ["ポート", "サービス", "リスク", "バナー", "メモ"])
    return 0


def cmd_vulnscan(a: argparse.Namespace) -> int:
    from kekkai.discovery.portscan import raise_fd_limit
    raise_fd_limit()
    m = monitor()
    quiet = a.json

    def say(msg: str, frac: float) -> None:
        if not quiet:
            print("  [%3d%%] %s" % (int(frac * 100), msg))
    if not quiet:
        print("  脆弱性診断を開始します（対象: このMac・自宅LANの機器・自宅の公開IP。LAN外はスキャンしません）")
    if not a.offline:
        from kekkai.intel import vulns
        try:
            vulns.update()  # KEV + Apple security releases; no-op when already fresh
        except Exception as e:  # noqa: BLE001  stale data is reported as a gap below
            if not quiet:
                print("  脆弱性データの更新に失敗しました: %s" % e)
        m.vulns = vulns.VulnDB()
    m.fast_cycle()
    try:
        m.lan_cycle(active=True)
    except Exception as e:  # noqa: BLE001  a failed LAN sweep still leaves the Mac and stored data to assess
        if not quiet:
            print("  LAN探索に失敗しました: %s" % e)
    if not a.offline:
        try:
            m.exposure_cycle()
        except Exception as e:  # noqa: BLE001
            if not quiet:
                print("  外部露出の確認に失敗しました: %s" % e)
    if not a.no_scan and not m._deep_available() and not quiet:
        print("  ※ nmap が無いため機器のサービスの版を特定できません（./kekkai install-nmap で入れると精度が上がります）")
    try:
        res = m.run_vulnscan(scan_devices=not a.no_scan, use_nvd=False if a.offline else None, progress=say)
    except RuntimeError as e:
        print("  " + c(str(e), "31"))
        return 2
    s, cov = res["summary"], res["coverage"]
    bad = s["worst"] in ("high", "critical")
    if a.json:
        print(dumps(res, indent=1))
        return 3 if bad else 0
    print()
    print("  総合: %s  （緊急 %d / 高 %d / 中 %d / 低 %d、悪用確認あり %d 件）" % (
        c(s["label"], "1;31" if bad else "1;32"), s["critical"], s["high"], s["medium"], s["low"], s["exploited"]))
    print("  対象: 機器 %d 台（版を特定 %d 台）／NVD照合 %d 回（キャッシュ %d 件）%s" % (
        cov["devices"], cov["with_versions"], cov["nvd_queried"], cov["nvd_cache_hits"],
        "／NVDの回数制限で一部未照合" if cov["nvd_rate_limited"] else ""))
    if res["items"]:
        table([[SEV_JA.get(i["severity"], i["severity"]), i["asset"], i["title"],
                ("⚠ " + ", ".join(i["exploited"][:2])) if i.get("exploited") else "", i.get("confidence", "")]
               for i in res["items"]], ["重大度", "対象", "内容", "悪用確認", "確度"])
        print("\n  直し方（優先順）:")
        for i in res["items"][:8]:
            print("   - [%s] %s: %s" % (SEV_JA.get(i["severity"], i["severity"]), i["asset"], i.get("fix", "")))
    else:
        print("  検出はありませんでした。")
    if res.get("gaps"):
        print("\n  " + c("診断できていない範囲:", "1;33"))
        for line in res["gaps"]:
            print("   ・" + line)
    print("\n  注意:")
    for line in res["limits"]:
        print("   ・" + line)
    return 3 if bad else 0


def cmd_lookup(a: argparse.Namespace) -> int:
    from kekkai.netutil import parse_ip
    ip = parse_ip(a.ip)
    if ip is None:
        print("IPアドレスを指定してください")
        return 2
    m = monitor()
    g, threats = m.intel(str(ip))
    out = {"ip": str(ip), "geo": g, "threats": threats}
    if a.external:
        from kekkai.intel.lookups import enrich
        out["external"] = enrich(str(ip), m.cfg)
    print(dumps(out, indent=1))
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    from kekkai import report
    m = monitor()
    m.fast_cycle()
    md = report.markdown(m)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(md + "\n")
        print("  保存しました: %s" % a.out)
    else:
        print(md)
    return 0


def cmd_sensor(a: argparse.Namespace) -> int:
    from kekkai import sensor
    return sensor.run(a.interface, use_domains=not a.no_domains)


def cmd_mcp(a: argparse.Namespace) -> int:
    from kekkai import mcp
    return mcp.serve()


def _agent_path() -> str:
    return os.path.expanduser("~/Library/LaunchAgents/%s.plist" % AGENT_LABEL)


def cmd_install_agent(a: argparse.Namespace) -> int:
    if not IS_MACOS:
        print("macOS専用です")
        return 2
    if os.geteuid() == 0:
        print("sudo なしで実行してください（自動起動はログイン中のユーザーとして動かします）")
        return 2
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logs = os.path.expanduser("~/Library/Logs")
    os.makedirs(logs, exist_ok=True)
    plist = {
        "Label": AGENT_LABEL,
        "ProgramArguments": [sys.executable, "-m", "kekkai", "serve", "--no-browser"],
        "EnvironmentVariables": {"PYTHONPATH": root},
        "WorkingDirectory": root,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
        "StandardOutPath": os.path.join(logs, "kekkai.log"),
        "StandardErrorPath": os.path.join(logs, "kekkai.log"),
    }
    path = _agent_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        plistlib.dump(plist, f)
    from kekkai import service
    rc, err = service.bootstrap("gui/%d" % os.getuid(), path, AGENT_LABEL)
    if rc != 0:
        print("  launchctl bootstrap に失敗: %s" % (err.strip() or rc))
        return 1
    print("  ログイン時に自動起動するよう登録しました: %s\n  ダッシュボードを開く: ./kekkai open" % path)
    print("  注意: macOS 15以降、バックグラウンド起動ではLAN探索が「ローカルネットワーク」の許可で止まることがあります。\n"
          "        ./kekkai doctor で確認し、必要なら システム設定 > プライバシーとセキュリティ > ローカルネットワーク で許可してください。")
    return 0


def _print_victims(res: dict, header: str) -> int:
    if res.get("error"):
        print("  取得エラー: %s" % res["error"])
        return 1
    if res.get("rate_limited"):
        print("  ※ 情報源の制限（1分に1回）により取得できませんでした。時間をおいて再実行してください。")
        return 1
    vics = res.get("victims") or []
    print("  %s: %d 件%s" % (header, res.get("count", len(vics)),
                            "（上位 %d 件を表示）" % len(vics) if res.get("count", 0) > len(vics) else ""))
    for m in vics:
        print("   - %s | グループ: %s | %s | %s | %s" % (
            m.get("victim") or m.get("post_title"), m.get("group") or m.get("group_name"),
            m.get("country") or "", (m.get("attackdate") or m.get("discovered") or m.get("published") or "")[:10],
            m.get("url") or m.get("post_url") or ""))
    print("  " + res.get("attribution", ""))
    print("  ※ 流出データ本体は取得しません。公開情報（被害組織の一覧）のみを表示しています。")
    return 0


def cmd_leaks(a: argparse.Namespace) -> int:
    from kekkai import config
    from kekkai.intel import leaks
    if getattr(a, "search", None):
        res = leaks.search_victims(a.search)
        if a.json:
            print(dumps(res))
            return 0
        return _print_victims(res, "暴露サイトの被害組織を検索「%s」" % a.search)
    if getattr(a, "country", None):
        res = leaks.recent_victims(a.country)
        if a.json:
            print(dumps(res))
            return 0
        return _print_victims(res, "最近の被害組織（%s）" % (a.country.upper()))
    cfg = config.load()
    targets = a.target or [str(x) for x in (cfg.get("watch.names", []) or []) + (cfg.get("watch.domains", []) or [])]
    if not targets:
        print("  監視対象が未設定です。例: ./kekkai leaks --target \"自社名\" example.co.jp")
        print("  または config.json の watch.names / watch.domains に登録してください。")
        return 2
    print("  公開情報源（Ransomware.live）で照合中: %s" % "、".join(targets))
    res = leaks.check(targets)
    if a.json:
        print(dumps(res))
        return 0
    src = res["sources"][0]
    if src.get("error"):
        print("  取得エラー: %s" % src["error"])
    if src.get("rate_limited"):
        print("  ※ 情報源の制限（1分に1回）のため一部の語のみ確認しました（確認済み: %s）。時間をおいて再実行してください。"
              % "、".join(src.get("queried") or []) or "なし")
    if not res["match_count"]:
        print("  一致はありませんでした（照合 %d 件）。%s" % (src.get("checked", 0), src.get("attribution", "")))
        return 0
    print("  ⚠ %d 件の一致が見つかりました:" % res["match_count"])
    for m in src["matches"]:
        print("   - %s | グループ: %s | %s | %s" % (m.get("victim") or m.get("post_title"), m.get("group") or m.get("group_name"),
                                                 (m.get("attackdate") or m.get("discovered") or "")[:10],
                                                 m.get("url") or m.get("post_url") or ""))
    print("  " + src.get("attribution", ""))
    return 3


def cmd_onion(a: argparse.Namespace) -> int:
    from kekkai.intel import tor
    try:
        page = tor.fetch_onion(a.url)
    except (tor.TorError, OSError) as e:
        print("  取得できませんでした: %s" % e)
        return 1
    if a.json:
        print(dumps(page))
        return 0
    print("  %s  HTTP %s  %s" % (page["url"], page["status"], page.get("title") or ""))
    if page.get("skipped"):
        print("  " + page["skipped"])
    text = page.get("text") or ""
    if a.find:
        hits = [ln for ln in text.splitlines() if any(w.lower() in ln.lower() for w in a.find)]
        print("  「%s」を含む行: %d 件" % ("・".join(a.find), len(hits)))
        for ln in hits[:50]:
            print("   - " + ln[:200])
        return 3 if hits else 0
    print(text[:3000])
    return 0


def cmd_install_sensor(a: argparse.Namespace) -> int:
    from kekkai import service
    return service.install_sensor()


def cmd_uninstall_sensor(a: argparse.Namespace) -> int:
    from kekkai import service
    return service.uninstall_sensor()


def cmd_uninstall_agent(a: argparse.Namespace) -> int:
    if not IS_MACOS:
        print("macOS専用です")
        return 2
    run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), AGENT_LABEL)], timeout=10)
    path = _agent_path()
    if os.path.exists(path):
        os.unlink(path)
    print("  自動起動を解除しました")
    return 0


def _print_new_alerts(m: Any) -> None:
    rows = [r for r in m.store.alerts("open", limit=10) if time.time() - r["ts"] < 120]
    if rows:
        print()
        for r in rows:
            print("  %s %s" % (c(" %s " % SEV_JA.get(r["severity"], r["severity"]), SEV_COLOR.get(r["severity"], "0")), r["title"]))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kekkai", description="結界 KEKKAI — 自宅ネットワークの監視・防御コンソール")
    p.add_argument("-v", "--verbose", action="store_true", help="詳細ログ")
    p.add_argument("--version", action="version", version="KEKKAI %s" % __version__)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="監視を開始してダッシュボードを開く")
    s.add_argument("--port", type=int)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(fn=cmd_serve)
    sub.add_parser("open", help="起動中のダッシュボードを開く").set_defaults(fn=cmd_open)
    s = sub.add_parser("setup", help="初回セットアップ（データ取得＋自己診断＋自動起動の登録）")
    s.add_argument("--no-download", action="store_true")
    s.add_argument("--no-agent", action="store_true", help="自動起動を登録しない")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_setup)
    s = sub.add_parser("update", help="GeoIP・脅威フィードを更新")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_update)
    s = sub.add_parser("doctor", help="自己診断（ツールの不具合チェック）")
    s.add_argument("--quick", action="store_true")
    s.set_defaults(fn=cmd_doctor)
    s = sub.add_parser("scan", help="LAN内の機器を探索")
    s.add_argument("--passive", action="store_true", help="ARPテーブルとmDNSのみ（pingしない）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("devices", help="登録済みの機器一覧")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_devices)
    s = sub.add_parser("conns", help="通信中の接続（既定: インターネットのみ）")
    s.add_argument("--all", action="store_true")
    s.add_argument("--risky", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_conns)
    s = sub.add_parser("alerts", help="アラート一覧")
    s.add_argument("--all", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_alerts)
    s = sub.add_parser("audit", help="セキュリティ診断")
    s.add_argument("--detailed", action="store_true", help="未適用アップデートも確認")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)
    s = sub.add_parser("exposure", help="インターネットから見た自宅（公開IP・Shodan・UPnP）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_exposure)
    s = sub.add_parser("portscan", help="LAN内の機器のポートスキャン（プライベートIPのみ）")
    s.add_argument("ip")
    s.add_argument("--deep", action="store_true", help="nmap -sV を使う（nmapが無ければエラー）")
    s.add_argument("--tcp", action="store_true", help="nmapがあっても内蔵スキャナを使う")
    s.add_argument("--ports", help="例: 22,80,443（内蔵スキャナ）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_portscan)
    s = sub.add_parser("install-nmap", help="nmap（詳細診断）を公式の配布元から入れる（macOS）")
    s.add_argument("--method", choices=("brew", "pkg"), help="brew=Homebrew / pkg=nmap.org 公式インストーラー（既定: 自動）")
    s.add_argument("--yes", action="store_true", help="確認せずに実行")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_install_nmap)
    s = sub.add_parser("vulnscan", help="脆弱性診断（このMac・自宅LANの機器・公開IP）")
    s.add_argument("--no-scan", action="store_true", help="nmapで機器を新たにスキャンせず、保存済みの情報で診断")
    s.add_argument("--offline", action="store_true", help="外部(NVD・Shodan)に問い合わせない")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_vulnscan)
    s = sub.add_parser("lookup", help="IPアドレスの照会")
    s.add_argument("ip")
    s.add_argument("--external", action="store_true", help="Shodan InternetDB / GreyNoise にも照会")
    s.set_defaults(fn=cmd_lookup)
    s = sub.add_parser("report", help="Markdownレポート")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("sensor", help="パケットセンサー（要 sudo）")
    s.add_argument("-i", "--interface")
    s.add_argument("--no-domains", action="store_true", help="危険ドメインリストを使わない")
    s.set_defaults(fn=cmd_sensor)
    sub.add_parser("mcp", help="MCPサーバー（Claude Code / Claude Desktop 用）").set_defaults(fn=cmd_mcp)
    sub.add_parser("install-agent", help="ログイン時に自動起動（macOS）").set_defaults(fn=cmd_install_agent)
    sub.add_parser("uninstall-agent", help="自動起動を解除").set_defaults(fn=cmd_uninstall_agent)
    s = sub.add_parser("leaks", help="暴露サイト(ダークウェブ)の流出情報を確認・検索")
    s.add_argument("--target", nargs="+", help="確認する語（未指定なら config の watch.* を使用）")
    s.add_argument("--search", help="暴露サイトの被害組織をキーワード検索（例: --search \"会社名\"）")
    s.add_argument("--country", help="最近の被害組織を国別に一覧（ISOコード 例: --country JP）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_leaks)
    s = sub.add_parser("onion", help=".onion のページを Tor 経由で読む（文字情報のみ）")
    s.add_argument("url")
    s.add_argument("--find", nargs="+", help="この語を含む行だけ表示（メールアドレス・社名など）")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_onion)
    sub.add_parser("install-sensor", help="パケットセンサーを常時監視に登録（要 sudo）").set_defaults(fn=cmd_install_sensor)
    sub.add_parser("uninstall-sensor", help="パケットセンサーの常時監視を解除（要 sudo）").set_defaults(fn=cmd_uninstall_sensor)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)  # launchd log file / pipes: show output as it happens
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not getattr(a, "fn", None):
        banner()
        parser.print_help()
        return 0
    try:
        return int(a.fn(a) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
