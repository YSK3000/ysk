"""Self-diagnosis: finds KEKKAI's own malfunctions (missing tools, broken parsers, stale data)."""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from kekkai import __version__, paths
from kekkai.util import IS_MACOS, find_cmd, http_get


def _c(name: str, status: str, detail: str, fix: str = "") -> Dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def _timed(fn: Callable[[], Any]) -> tuple:
    t0 = time.time()
    try:
        return fn(), None, time.time() - t0
    except Exception as e:  # noqa: BLE001
        return None, "%s: %s" % (type(e).__name__, e), time.time() - t0


def run_checks(cfg: Any, monitor: Any = None, quick: bool = False) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    v = sys.version_info
    out.append(_c("Python", "ok" if v >= (3, 9) else "fail", "%s (%s)" % (platform.python_version(), sys.executable),
                  "" if v >= (3, 9) else "Python 3.9以上が必要です（xcode-select --install か Homebrew）"))
    if IS_MACOS:
        out.append(_c("OS", "ok", "macOS %s (%s)" % (platform.mac_ver()[0], platform.machine())))
    else:
        out.append(_c("OS", "info", "%s %s — KEKKAIはmacOS向けです（Linuxは開発・検証用）" % (platform.system(), platform.release())))
    out.append(_c("KEKKAI", "ok", "v%s / データ: %s" % (__version__, paths.data_dir())))

    d = paths.data_dir()
    probe = d / ".write-test"
    try:
        probe.write_text("ok")
        probe.unlink()
        out.append(_c("データフォルダ", "ok", "書き込み可能"))
    except OSError as e:
        out.append(_c("データフォルダ", "fail", str(e), "フォルダの権限を確認してください（sudo で作られた場合は chown）"))

    from kekkai.store import Store
    try:
        st = monitor.store if monitor else Store(str(paths.sub("kekkai.db")))
        out.append(_c("データベース", "ok" if st.integrity_ok() else "fail", "SQLite整合性チェック",
                      "" if st.integrity_ok() else "kekkai.db が破損しています。バックアップして削除すると再作成されます。"))
    except Exception as e:  # noqa: BLE001
        out.append(_c("データベース", "fail", str(e)))

    need = ["arp", "netstat", "ps", "ifconfig", "scutil", "networksetup", "system_profiler"] if IS_MACOS else []
    missing = [t for t in need if not find_cmd(t)]
    if need:
        out.append(_c("必須コマンド", "fail" if missing else "ok", "不足: " + ", ".join(missing) if missing else "すべて利用可能"))
    opt = {"nmap": "詳細スキャン (brew install nmap)", "tcpdump": "パケットセンサー", "codesign": "署名チェック",
           "lsof": "プロセス特定の補助"}
    have = [k for k in opt if find_cmd(k)]
    lack = [k for k in opt if not find_cmd(k)]
    out.append(_c("追加ツール", "ok" if not lack else "info", "あり: %s%s" % (", ".join(have) or "-", (" / なし: " + ", ".join(lack)) if lack else ""),
                  "; ".join(opt[k] for k in lack)))

    from kekkai.platforms import get_platform
    p = monitor.platform if monitor else get_platform()
    ctx, err, dt = _timed(p.lan_context)
    if err or ctx is None:
        out.append(_c("LAN情報の取得", "fail", err or "none"))
    elif not ctx.interface:
        out.append(_c("LAN情報の取得", "warn", "有効なLANインターフェースがありません（オフライン？）", "Wi-Fi/有線の接続を確認"))
    else:
        out.append(_c("LAN情報の取得", "ok" if ctx.gateway else "warn",
                      "%s %s/%s GW=%s (%s) %.2fs" % (ctx.interface, ctx.ip, ctx.prefixlen, ctx.gateway, ctx.gateway_mac or "MAC不明", dt),
                      "" if ctx.gateway else "ゲートウェイを特定できません"))
    if ctx is not None and ctx.gateway:
        out.append(_local_network_check(ctx.gateway))
    neigh, err, dt = _timed(p.neighbors)
    known = [n for n in (neigh or []) if n.mac]
    out.append(_c("ARPテーブル", "fail" if err else ("ok" if known else "warn"),
                  err or "%d 台（応答なし %d） (%.2fs)" % (len(known), len(neigh or []) - len(known), dt),
                  "" if known else "LAN探索（kekkai scan）後に再確認してください"))
    conns, err, dt = _timed(p.connections)
    if err:
        out.append(_c("通信の取得", "fail", err))
    else:
        conns = conns or []
        with_pid = [c for c in conns if c.pid]
        ratio = len(with_pid) / len(conns) if conns else 0
        st = "ok" if conns and ratio > 0.5 else "warn"
        out.append(_c("通信の取得", st, "%d 件 / プロセス特定 %d%% (%.2fs)" % (len(conns), int(ratio * 100), dt),
                      "" if st == "ok" else "プロセス名を取得できない通信が多いです。sudo で実行すると改善する場合があります。"))
    dns, err, _ = _timed(p.dns_servers)
    out.append(_c("DNS設定の取得", "fail" if err else ("ok" if dns else "warn"), err or (", ".join(dns) or "取得できず")))

    from kekkai.intel.geo import Geo
    from kekkai.intel.feeds import FeedSet
    from kekkai.intel.oui import OUI
    g = monitor.geo if monitor else Geo()
    av = g.available
    for key, label in (("city", "GeoIP(都市)"), ("asn", "GeoIP(ASN)")):
        if not av.get(key):
            out.append(_c(label, "warn", "未取得", "./kekkai update を実行"))
        else:
            age = (time.time() - (av.get(key + "_build") or 0)) / 86400
            out.append(_c(label, "ok" if age < 70 else "warn", "ビルド %.0f日前" % age, "" if age < 70 else "./kekkai update で更新"))
    o = monitor.oui if monitor else OUI()
    out.append(_c("MACベンダーDB", "ok" if o.size > 10000 else "warn", "%d 件" % o.size, "" if o.size else "./kekkai update を実行"))
    fs = monitor.feeds if monitor else FeedSet()
    stat = fs.status()
    bad = [f["id"] for f in stat if f["status"] not in ("ok",)]
    okn = len(stat) - len(bad)
    out.append(_c("脅威フィード", "ok" if not bad else ("warn" if okn else "fail"), "%d/%d 正常%s" % (
        okn, len(stat), (" / 要確認: " + ", ".join(bad)) if bad else ""), "./kekkai update --force で再取得" if bad else ""))

    from kekkai import ai
    s = ai.status(cfg)
    out.append(_c("AIアナリスト", "ok" if s["active"] else "info",
                  ("%s / %s" % (s["active"]["provider"], s["active"]["model"])) if s["active"] else "未設定",
                  "" if s["active"] else "Ollama等のローカルLLMを起動すると、アラートのAI解説が使えます"))

    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        out.append(_c("同時ファイル数上限", "ok" if soft >= 1024 else "info", "soft=%s（スキャン時に自動で引き上げます）" % soft))
    except (ImportError, ValueError, OSError):
        pass

    sess = _session_check()
    if sess:
        out.append(sess)
    if monitor is not None:
        stalls = monitor.check_stalls()
        errs = {k: v.get("last_error") for k, v in monitor.state.get("health", {}).items()
                if isinstance(v, dict) and v.get("last_error")}
        if stalls or errs:
            out.append(_c("監視ループ", "warn", "停止: %s / エラー: %s" % (", ".join(stalls) or "-", "; ".join(
                "%s=%s" % (k, (v or "")[:80]) for k, v in errs.items()) or "-"), "ログ（--verbose）を確認し、再起動してください"))
        else:
            out.append(_c("監視ループ", "ok", "すべて正常に動作中"))
    if not quick:
        for name, url in (("更新サーバー(GitHub)", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/README.md"),
                          ("更新サーバー(DB-IP)", "https://download.db-ip.com/free/")):
            try:
                status, _, _ = http_get(url, timeout=8, max_bytes=1024 * 1024, method="GET")
                out.append(_c(name, "ok" if status < 500 else "warn", "HTTP %s" % status))
            except Exception as e:  # noqa: BLE001
                out.append(_c(name, "warn", str(e)[:120], "ネットワーク/プロキシ設定を確認"))
    return out


def _local_network_check(gateway: str) -> Dict[str, Any]:
    """macOS 15+ "Local Network" privacy can silently block LAN traffic for background (launchd) processes."""
    import errno
    import socket
    last: Optional[int] = None
    for port in (53, 80, 443):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            rc = s.connect_ex((gateway, port))
        except OSError as e:
            rc = e.errno or -1
        finally:
            s.close()
        if rc in (0, errno.ECONNREFUSED):
            return _c("ローカルネットワーク", "ok", "ルーター(%s)に到達できます" % gateway)
        last = rc
    if last in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES):
        return _c("ローカルネットワーク", "warn", "ルーターへの接続が拒否されました（%s）" % os.strerror(last),
                  "macOS の「ローカルネットワーク」許可が必要な可能性: システム設定 > プライバシーとセキュリティ > "
                  "ローカルネットワーク で、使っているターミナル/Python をオンに。自動起動(install-agent)時に起きやすいです。")
    return _c("ローカルネットワーク", "info", "ルーターの53/80/443番は応答なし（ルーターの設定によっては正常）")


def _session_check() -> Optional[Dict[str, Any]]:
    path = str(paths.sub("session.json"))
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            s = json.load(f)
        if not s.get("port"):
            return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request("http://127.0.0.1:%d/api/summary" % int(s["port"]),
                                     headers={"Authorization": "Bearer " + s["token"]})
        with opener.open(req, timeout=3) as r:
            ok = r.status == 200
        return _c("ダッシュボード", "ok" if ok else "warn", "http://127.0.0.1:%s で稼働中" % s["port"])
    except Exception:  # noqa: BLE001
        return _c("ダッシュボード", "info", "停止中（./kekkai serve で起動）")


def print_report(checks: List[Dict[str, Any]], color: bool = True) -> int:
    marks = {"ok": ("✓", "32"), "warn": ("!", "33"), "fail": ("✗", "31"), "info": ("i", "36")}
    worst = 0
    for c in checks:
        m, col = marks.get(c["status"], ("?", "0"))
        mark = "\033[%sm%s\033[0m" % (col, m) if color else m
        print(" %s %-16s %s" % (mark, c["name"], c["detail"]))
        if c.get("fix") and c["status"] != "ok":
            print("   %s→ %s" % (" " * 16, c["fix"]))
        worst = max(worst, {"fail": 2, "warn": 1}.get(c["status"], 0))
    return worst
