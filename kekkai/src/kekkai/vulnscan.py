"""脆弱性診断: a vulnerability assessment of this Mac, the home LAN and the home's public IP.

Defensive and limited to what the user owns: the Mac itself, devices on the private LAN (nmap only
ever targets private addresses) and the public IP as Shodan has already indexed it. Five sources:

1. this Mac       macOS version vs Apple's security releases (SOFA) and CISA KEV
2. services       nmap -sV product + version (CPE) -> NIST NVD CVEs for that version, KEV-flagged
3. devices        vendor / model (UPnP, mDNS) vs CISA KEV
4. public IP      CVEs Shodan associates with the home's IP, KEV-flagged
5. configuration  services that are dangerous to leave open (Telnet, RDP, ADB, Docker API, ...)

Each result carries its evidence and a confidence. A result is a lead to check, not proof of compromise,
and no result is not a guarantee of safety.
"""
from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Callable, Dict, List, Optional

from kekkai.detect.engine import Finding
from kekkai.intel.nvd import NOTICE as NVD_NOTICE, NVD, cpe23, severity_from_score, vendor_product
from kekkai.netutil import is_local_target

SEV = ["info", "low", "medium", "high", "critical"]
SEV_JA = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}
LIMITS = [
    "版番号での照合のため、Linux等で修正を取り込み済み（バックポート）でも検出されることがあります。実際の版と更新状況を確認してください。",
    "電源が切れていた機器、nmapで版を特定できないサービスは診断できていません。",
    "公開IPのCVEはShodanの推定で、実際に脆弱であるとは限りません。",
    "検出が無いことは安全の保証ではありません。",
]


def _rank(sev: Optional[str]) -> int:
    return SEV.index(sev) if sev in SEV else 0


def _at_least(sev: Optional[str], floor: str) -> str:
    return floor if _rank(sev) < _rank(floor) else str(sev)


def _dev_name(d: Dict[str, Any]) -> str:
    name = d.get("label") or d.get("hostname") or d.get("model") or d.get("vendor") or "不明な機器"
    return "%s（%s）" % (name, d.get("ip")) if d.get("ip") else str(name)


def _kev_brief(k: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": k.get("cveID"), "score": None, "severity": None, "kev": True,
            "summary": (k.get("vulnerabilityName") or "")[:240], "kev_due": k.get("dueDate"),
            "ransomware": str(k.get("knownRansomwareCampaignUse") or "").lower() == "known"}


# ------------------------------------------------------------------ 1) this Mac

def mac_items(m: Any) -> List[Dict[str, Any]]:
    ver = m._safe("os_version", m.platform.os_version, None)
    info = m.vulns.macos(ver) if ver else None
    if not info:
        return []
    fix = "システム設定 > 一般 > ソフトウェアアップデート で最新の macOS %s に更新してください。" % (info.get("latest") or "")
    base = {"id": "vuln:mac:os", "category": "os", "asset": "このMac", "asset_ip": None,
            "product": "macOS", "version": ver, "evidence": "sw_vers: %s / Apple セキュリティリリース(SOFA)" % ver,
            "source": "Apple(SOFA)・CISA KEV", "confidence": "高", "cves": [], "cve_count": 0, "exploited": []}
    if info.get("unknown_line"):
        return [dict(base, severity="high" if info.get("newer_major") else "medium",
                     title="このmacOS（%s）はセキュリティ更新の対象系列に見当たりません（サポート終了の可能性）" % ver,
                     fix="新しいmacOSへのアップグレードを検討してください。対応機種でなければ買い替えも検討を。")]
    out = []
    if info.get("cves"):
        expl = info.get("exploited") or []
        sev = "critical" if expl else "high"
        out.append(dict(base, severity=sev, cve_count=info["cves"], exploited=expl,
                        cves=[{"id": c, "kev": True, "score": None, "severity": None, "summary": "実際の悪用が確認済み"}
                              for c in expl[:10]],
                        title="macOS %s に未修正の脆弱性 %d 件（うち悪用確認 %d 件）" % (ver, info["cves"], len(expl)),
                        fix=fix))
    stale = info.get("days_since_security_release")
    if stale is not None and stale > 365:
        out.append(dict(base, id="vuln:mac:stale", severity="high", cve_count=0,
                        title="この系列のmacOSに1年以上セキュリティ更新が出ていません（%d日）" % stale,
                        fix="サポートが続く新しいmacOSへのアップグレードを検討してください。"))
    return out


# ------------------------------------------------------------------ 2) services (nmap CPE -> NVD)

def service_items(m: Any, devices: List[Dict[str, Any]], nvd: Optional[NVD]) -> List[Dict[str, Any]]:
    out = []
    for d in devices:
        for p in d.get("ports") or []:
            cpes = [c for c in (p.get("cpe") or []) if isinstance(c, str)]
            if not cpes:
                continue
            cpe = next((c for c in cpes if cpe23(c)), cpes[0])
            vp = vendor_product(cpe)
            label = " ".join(x for x in (p.get("product"), p.get("version")) if x) or (vp[1] if vp else cpe)
            base = {"category": "service", "asset": _dev_name(d), "asset_ip": d.get("ip"),
                    "port": p.get("port"), "product": p.get("product") or (vp[1] if vp else None),
                    "version": p.get("version"), "cpe": cpe,
                    "id": "vuln:svc:%s:%s:%s" % (d.get("mac") or d.get("ip"), p.get("port"), cpe),
                    "evidence": "nmap -sV ポート %s/%s: %s" % (p.get("port"), p.get("service"), cpe)}
            res = nvd.cves_for(cpe) if (nvd is not None and cpe23(cpe)) else None
            if res is not None and not res.get("error"):
                cves = res.get("cves") or []
                if not cves:
                    continue
                expl = [c["id"] for c in cves if c.get("kev")]
                top = max((c.get("score") or 0.0) for c in cves)
                sev = max((c.get("severity") or severity_from_score(c.get("score")) or "low" for c in cves), key=_rank)
                if expl:
                    sev = "critical" if top >= 9.0 else _at_least(sev, "high")
                out.append(dict(base, severity=sev, score=top or None, cves=cves[:10], cve_count=res.get("total") or len(cves),
                                exploited=expl, source="NIST NVD・CISA KEV", confidence="中",
                                title="%s に既知の脆弱性 %d 件（うち悪用確認 %d 件）" % (
                                    label, res.get("total") or len(cves), len(expl)),
                                fix="%s を最新版に更新してください。機器内蔵なら機器のファームウェア更新、"
                                    "不要なら機能を停止。外部公開しているなら優先度最上位です。" % (p.get("product") or "このソフト")))
                continue
            # NVD unavailable (offline / rate limit) or no version: product-level KEV as a fallback lead
            hits = m.vulns.kev_for_product(*vp) if vp else []
            if hits:
                no_ver = not cpe23(cpe)
                out.append(dict(base, severity="medium" if no_ver else "high", cves=[_kev_brief(k) for k in hits[:10]],
                                cve_count=len(hits), exploited=[k.get("cveID") for k in hits], score=None,
                                source="CISA KEV（製品名で照合・版は未照合）", confidence="低",
                                title="%s には実際に悪用された脆弱性があります（版は未照合%s）" % (
                                    label, "：版不明" if no_ver else "：NVD未接続"),
                                fix="この製品の版を確認し、該当するなら最新版へ更新してください。",
                                note=(res or {}).get("error")))
    return out


# ------------------------------------------------------------------ 3) devices (vendor / model vs KEV)

def device_items(m: Any, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for d in devices:
        if d.get("kind") == "this":
            continue
        up = d.get("upnp") if isinstance(d.get("upnp"), dict) else {}
        hits = m.vulns.device_hits(up.get("manufacturer") or d.get("vendor"),
                                   [d.get("model"), up.get("modelName"), up.get("modelNumber")])
        model, vendor = hits.get("model") or [], hits.get("vendor") or []
        if model:
            out.append({"id": "vuln:dev:%s:model" % (d.get("mac") or d.get("ip")), "category": "device",
                        "asset": _dev_name(d), "asset_ip": d.get("ip"), "product": d.get("model") or up.get("modelName"),
                        "severity": "high", "cves": [_kev_brief(k) for k in model[:10]], "cve_count": len(model),
                        "exploited": [k.get("cveID") for k in model], "source": "CISA KEV（型番で照合）", "confidence": "中",
                        "evidence": "機器情報(UPnP/mDNS): %s %s" % (d.get("vendor") or up.get("manufacturer") or "",
                                                                 d.get("model") or up.get("modelName") or ""),
                        "title": "この機種に関連する、実際に悪用された脆弱性 %d 件" % len(model),
                        "fix": "メーカーのサポートページでファームウェアを最新にしてください。サポート終了機種なら買い替えを。"})
        elif vendor:
            out.append({"id": "vuln:dev:%s:vendor" % (d.get("mac") or d.get("ip")), "category": "device",
                        "asset": _dev_name(d), "asset_ip": d.get("ip"), "product": d.get("vendor"),
                        "severity": "low", "cves": [_kev_brief(k) for k in vendor[:5]], "cve_count": len(vendor),
                        "exploited": [], "source": "CISA KEV（メーカー名のみ）", "confidence": "低",
                        "evidence": "メーカー: %s（型番は未特定）" % (d.get("vendor") or up.get("manufacturer")),
                        "title": "このメーカーの製品に悪用確認済みの脆弱性があります（機種は未確認）",
                        "fix": "機種名を確認し、該当機種ならファームウェアを更新してください。"})
    return out


# ------------------------------------------------------------------ 4) public IP (Shodan) and 5) configuration

def exposure_items(m: Any) -> List[Dict[str, Any]]:
    exp = m.state.get("exposure") or {}
    idb = exp.get("internetdb") or {}
    if exp.get("shared_ipv4") or not idb.get("found"):
        return []
    vulns = [str(v) for v in idb.get("vulns") or []]
    if not vulns:
        return []
    kev = m.vulns.kev_for(vulns)
    kev_ids = {k.get("cveID") for k in kev}
    cves = [_kev_brief(k) for k in kev] + [{"id": v, "kev": False, "score": None, "severity": None, "summary": ""}
                                           for v in vulns if v not in kev_ids]
    return [{"id": "vuln:wan:%s" % exp.get("public_ip"), "category": "exposure", "asset": "自宅の公開IP",
             "asset_ip": exp.get("public_ip"), "severity": "critical" if kev else "medium", "cves": cves[:10],
             "cve_count": len(vulns), "exploited": sorted(kev_ids), "source": "Shodan InternetDB・CISA KEV",
             "confidence": "中", "evidence": "Shodan InternetDB（公開IP %s）" % exp.get("public_ip"),
             "title": "公開IPに %d 件のCVEが関連付けられています（うち悪用確認 %d 件）" % (len(vulns), len(kev)),
             "fix": "ルーターのファームウェアを更新し、不要なポート開放・UPnPを無効化してください。"}]


def config_items(devices: List[Dict[str, Any]], exposed: set) -> List[Dict[str, Any]]:
    out = []
    for d in devices:
        for p in d.get("ports") or []:
            risk = p.get("risk")
            if risk not in ("high", "critical"):
                continue
            wan = p.get("port") in exposed
            out.append({"id": "vuln:cfg:%s:%s" % (d.get("mac") or d.get("ip"), p.get("port")), "category": "config",
                        "asset": _dev_name(d), "asset_ip": d.get("ip"), "port": p.get("port"),
                        "severity": "critical" if wan else risk, "cves": [], "cve_count": 0, "exploited": [],
                        "source": "ポート診断", "confidence": "高",
                        "evidence": "開放ポート %s/%s%s" % (p.get("port"), p.get("service"), "（公開IPでも開放）" if wan else ""),
                        "title": "危険なサービスが開いています: %s/%s%s" % (p.get("port"), p.get("service"),
                                                                     "（インターネットからも到達可能）" if wan else ""),
                        "fix": p.get("note") or "不要なら機器の設定でこの機能を無効化してください。"})
    return out


# ------------------------------------------------------------------ assessment

def _scan_devices(m: Any, net_id: str, devices: List[Dict[str, Any]], say: Callable[[str, float], None],
                  concurrency: int) -> int:
    targets = [d for d in devices if d.get("ip") and is_local_target(d["ip"])]
    done = 0
    if not targets:
        return 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = {pool.submit(m._deep_scan, d["ip"]): d for d in targets}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            done += 1
            try:
                res = fut.result()
                m.store.set_device_ports(net_id, d["mac"], res["open"])
            except Exception as e:  # noqa: BLE001  one unreachable host must not stop the assessment
                m.store.log_event("vulnscan", "詳細スキャン失敗 %s: %s" % (d.get("ip"), e))
            say("機器のサービスを特定中 %d/%d（%s）" % (done, len(targets), d.get("ip")), 0.05 + 0.55 * done / len(targets))
    return len(targets)


def coverage_gaps(m: Any, vstat: Dict[str, Any], nvd: Optional[NVD], devices: List[Dict[str, Any]],
                  with_versions: int) -> List[str]:
    """Why this assessment could miss things: never let a blind spot read as 'no vulnerabilities'."""
    gaps = []
    if not vstat.get("kev_entries"):
        gaps.append("CISA KEV（実際に悪用された脆弱性の一覧）が未取得です。./kekkai update で取得してください。")
    if not vstat.get("sofa_lines"):
        gaps.append("Appleのセキュリティ更新情報が未取得のため、このMacを照合できていません。")
    elif m.platform.name == "macos" and not m._safe("os_version", m.platform.os_version, None):
        gaps.append("このMacのmacOSの版を取得できませんでした。")
    if not m._deep_available():
        gaps.append("nmap が無いため機器のサービスの版を特定できていません（brew install nmap）。")
    elif devices and not with_versions:
        gaps.append("版を特定できた機器がありません（機器のスキャン前か、版を返さない機器です）。")
    if nvd is None:
        gaps.append("NVD（米国NISTの脆弱性DB）に照合していません（オフライン設定）。製品名でのKEV照合のみです。")
    elif getattr(nvd, "rate_limited", False):
        gaps.append("NVDの回数制限で一部の製品を照合できていません。時間をおいて再実行してください。")
    exp = m.state.get("exposure") or {}
    if not exp.get("checked_at") or exp.get("disabled"):
        gaps.append("自宅の公開IPの露出（Shodan）を確認していません。")
    elif exp.get("shared_ipv4"):
        gaps.append("公開IPが共有（CGNAT等）のため、公開IPのCVEは対象外です。")
    return gaps


def assess(m: Any, nvd: Optional[NVD] = None, scan_devices: bool = False,
           progress: Optional[Callable[[str, float], None]] = None, concurrency: int = 4) -> Dict[str, Any]:
    t0 = time.time()
    say = progress or (lambda msg, frac: None)
    net_id = (m.state.get("network") or {}).get("id")
    devices = m.store.devices(net_id) if net_id else []
    scanned = 0
    if scan_devices and net_id and m._deep_available():
        say("nmap で機器のサービスと版を特定します（%d台）" % len(devices), 0.05)
        scanned = _scan_devices(m, net_id, devices, say, concurrency)
        devices = m.store.devices(net_id)
    say("このMacの更新状況を確認中", 0.62)
    items = mac_items(m)
    say("サービスの版を脆弱性データベース(NVD)と照合中", 0.68)
    items += service_items(m, devices, nvd)
    say("機器の型番・公開IP・設定を確認中", 0.9)
    items += device_items(m, devices)
    items += exposure_items(m)
    items += config_items(devices, m._exposed_ports())
    items.sort(key=lambda i: (_rank(i.get("severity")), bool(i.get("exploited")), i.get("score") or 0.0), reverse=True)
    counts = {s: sum(1 for i in items if i.get("severity") == s) for s in SEV}
    worst = next((s for s in reversed(SEV) if counts[s]), None)
    with_services = sum(1 for d in devices
                        if any(cpe23(c) for p in d.get("ports") or [] for c in (p.get("cpe") or []) if isinstance(c, str)))
    vstat = m.vulns.status()
    gaps = coverage_gaps(m, vstat, nvd, devices, with_services)
    if worst:
        label = SEV_JA[worst]
    else:
        label = "検出なし（診断は不完全）" if gaps else "検出なし"
    res = {"ts": time.time(), "duration": round(time.time() - t0, 1),
           "summary": dict(counts, exploited=sum(1 for i in items if i.get("exploited")), total=len(items),
                           worst=worst, label=label, complete=not gaps),
           "items": items, "gaps": gaps,
           "coverage": {"devices": len(devices), "scanned": scanned, "with_versions": with_services,
                        "nmap": bool(m._deep_available()), "nvd": nvd is not None,
                        "nvd_queried": getattr(nvd, "queried", 0), "nvd_cache_hits": getattr(nvd, "cache_hits", 0),
                        "nvd_rate_limited": bool(getattr(nvd, "rate_limited", False)),
                        "exposure_checked_at": (m.state.get("exposure") or {}).get("checked_at")},
           "sources": {"kev_version": vstat.get("kev_version"), "kev_entries": vstat.get("kev_entries"),
                       "sofa_lines": vstat.get("sofa_lines"),
                       "nvd": "NIST NVD CVE API 2.0" if nvd is not None else None,
                       "notice": NVD_NOTICE if nvd is not None else None},
           "limits": LIMITS}
    say("診断が完了しました", 1.0)
    return res


def findings(res: Dict[str, Any]) -> List[Finding]:
    """Alerts for version-matched service CVEs (other categories are alerted by their own monitoring loops)."""
    out = []
    for i in res.get("items") or []:
        if i.get("category") != "service" or _rank(i.get("severity")) < _rank("high"):
            continue
        ids = "、".join(c["id"] for c in (i.get("cves") or [])[:6] if c.get("id"))
        out.append(Finding("vuln.service", i["severity"], i["title"],
                           "%s / %s / %s%s" % (i["asset"], i.get("evidence"), ids,
                                               "（悪用確認: %s）" % "、".join(i["exploited"][:4]) if i.get("exploited") else ""),
                           i.get("fix", ""), subject=i["id"], data={"cves": i.get("cves"), "cpe": i.get("cpe")}))
    return out
