"""Markdown security report (for sharing, or for handing to Claude/an AI assistant)."""
from __future__ import annotations

import time
from typing import Any, Dict, List

from kekkai.discovery.lan import KIND_LABELS
from kekkai.util import iso

SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}


def _md_escape(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def markdown(m: Any, max_alerts: int = 30) -> str:
    st = m.state
    net = st.get("network") or {}
    threat = m.threat_summary()
    lines: List[str] = []
    lines.append("# 結界 KEKKAI セキュリティレポート")
    lines.append("")
    lines.append("- 作成: %s / プラットフォーム: %s / KEKKAI v%s" % (iso(time.time()), st.get("platform"), st.get("version")))
    lines.append("- 脅威レベル: **%s (%d/5)** — 未対応: %s" % (threat["label"], threat["level"], ", ".join(
        "%s %d" % (SEV_JA[k], v) for k, v in threat["counts"].items() if v) or "なし"))
    lines.append("- ネットワーク: %s %s（GW %s / %s）%s" % (
        net.get("label") or "未登録", net.get("subnet") or "", net.get("gateway") or "?", net.get("gateway_mac") or "?",
        " VPN接続中" if net.get("vpn_active") else ""))
    posture = st.get("posture") or {}
    if posture.get("score") is not None:
        lines.append("- 防御スコア: **%s/100**" % posture["score"])
    lines.append("")
    alerts = m.store.alerts("active", limit=max_alerts)
    lines.append("## 未対応アラート（%d件）" % len(alerts))
    lines.append("")
    if not alerts:
        lines.append("なし")
    for a in alerts:
        lines.append("### [%s] %s" % (SEV_JA.get(a["severity"], a["severity"]), a["title"]))
        lines.append("- 初回 %s / 最終 %s / %d回 / ルール `%s`" % (iso(a["ts"]), iso(a["last_ts"]), a["count"], a["rule"]))
        lines.append("- 詳細: %s" % a["detail"])
        if a.get("advice"):
            lines.append("- 対応: %s" % a["advice"])
        lines.append("")
    devs = m.store.devices(net.get("id")) if net.get("id") else []
    lines.append("## LAN内の機器（%d台）" % len(devs))
    lines.append("")
    if devs:
        lines.append("| IP | 名前 | 種別 | メーカー | MAC | 信頼 | 開放ポート |")
        lines.append("|---|---|---|---|---|---|---|")
        for d in sorted(devs, key=lambda x: tuple(int(p) if p.isdigit() else 0 for p in (x.get("ip") or "0").split("."))):
            ports = ", ".join("%s(%s)" % (p["port"], p.get("service")) for p in (d.get("ports") or [])[:8])
            lines.append("| %s | %s | %s | %s | %s | %s | %s |" % tuple(_md_escape(x) for x in (
                d.get("ip"), d.get("label") or d.get("hostname") or "-", KIND_LABELS.get(d.get("kind") or "unknown", "-"),
                d.get("vendor") or "-", d.get("mac"), "✓" if d.get("trusted") else "", ports or "-")))
    lines.append("")
    conns = [c for c in (st.get("connections") or []) if c.get("scope") == "internet"]
    lines.append("## インターネット通信（%d件）" % len(conns))
    lines.append("")
    agg: Dict[str, Dict[str, Any]] = {}
    for c in conns:
        g = c.get("geo") or {}
        key = "%s|%s" % (c.get("process"), g.get("org"))
        e = agg.setdefault(key, {"process": c.get("process"), "org": g.get("org"), "countries": set(), "n": 0, "risk": c.get("risk")})
        e["n"] += 1
        if g.get("country"):
            e["countries"].add(g["country"])
        if c.get("risk") not in ("ok", None):
            e["risk"] = c["risk"]
    if agg:
        lines.append("| プロセス | 接続先組織 | 国 | 件数 | リスク |")
        lines.append("|---|---|---|---|---|")
        for e in sorted(agg.values(), key=lambda x: -x["n"])[:40]:
            lines.append("| %s | %s | %s | %d | %s |" % (_md_escape(e["process"]), _md_escape(e["org"] or "-"),
                                                    ",".join(sorted(e["countries"])) or "-", e["n"], e["risk"]))
    lines.append("")
    checks = [c for c in posture.get("checks", []) if c["status"] in ("fail", "warn")]
    if checks:
        lines.append("## 診断で要対応の項目")
        lines.append("")
        for c in checks:
            lines.append("- **%s**（%s）: %s%s" % (c["title"], {"fail": "要対策", "warn": "要確認"}[c["status"]], c["detail"],
                                                  " → " + c["fix"] if c.get("fix") else ""))
        lines.append("")
    exp = st.get("exposure") or {}
    if exp.get("findings"):
        lines.append("## 外部からの見え方")
        lines.append("")
        lines.append("- 公開IP: %s" % (exp.get("public_ip") or "不明"))
        for f in exp["findings"]:
            lines.append("- [%s] %s — %s" % (SEV_JA.get(f["severity"], f["severity"]), f["title"], f["detail"]))
        lines.append("")
    lines.append("---")
    lines.append("IP Geolocation by DB-IP (CC BY 4.0) / 脅威情報: abuse.ch, Spamhaus, FireHOL, Emerging Threats, CINS, Tor Project")
    return "\n".join(lines)
