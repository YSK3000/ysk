"""TCP connect scanner for YOUR OWN LAN devices (private ranges only — enforced)."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from kekkai.netutil import is_local_target

# port -> (service, risk, Japanese note). risk: critical/high/medium/low/info
SERVICES: Dict[int, tuple] = {
    21: ("ftp", "medium", "FTPは通信が暗号化されません。不要なら停止を。"),
    22: ("ssh", "low", "SSH。パスワード認証ではなく鍵認証を推奨。"),
    23: ("telnet", "high", "Telnetは平文で乗っ取りの定番（Mirai系ボットネットの標的）。直ちに無効化を。"),
    25: ("smtp", "low", ""),
    53: ("dns", "info", ""),
    80: ("http", "info", "Web管理画面。初期パスワードのままになっていないか確認を。"),
    81: ("http-alt", "low", "IPカメラ等の管理画面に多いポート。"),
    88: ("kerberos", "info", ""),
    110: ("pop3", "low", ""),
    111: ("rpcbind", "medium", ""),
    135: ("msrpc", "medium", ""),
    139: ("netbios", "medium", "NetBIOS/SMB。家庭内でも不要なら停止を。"),
    143: ("imap", "low", ""),
    161: ("snmp", "medium", ""),
    389: ("ldap", "low", ""),
    443: ("https", "info", ""),
    445: ("smb", "medium", "SMBファイル共有。ランサムウェアの横展開に使われます。"),
    465: ("smtps", "info", ""),
    515: ("lpd", "info", "プリンター"),
    548: ("afp", "low", ""),
    554: ("rtsp", "medium", "RTSP映像配信（カメラ）。認証なしで映像が見えないか確認を。"),
    587: ("submission", "info", ""),
    631: ("ipp", "info", "プリンター(IPP)"),
    873: ("rsync", "medium", ""),
    993: ("imaps", "info", ""),
    995: ("pop3s", "info", ""),
    1080: ("socks", "medium", "SOCKSプロキシ。意図しないものなら踏み台化の恐れ。"),
    1433: ("mssql", "medium", ""),
    1521: ("oracle", "medium", ""),
    1723: ("pptp", "medium", "PPTP VPNは脆弱な方式です。"),
    1883: ("mqtt", "medium", "MQTT(IoT)。認証なし運用は乗っ取りの恐れ。"),
    2049: ("nfs", "medium", ""),
    2375: ("docker", "critical", "Docker APIが認証なしで公開されると即乗っ取り可能です。"),
    2376: ("docker-tls", "low", ""),
    3000: ("http-dev", "low", "開発用Webサーバー"),
    3283: ("ard", "medium", "Apple Remote Desktop"),
    3306: ("mysql", "medium", ""),
    3389: ("rdp", "high", "RDP。ランサムウェアの主要な侵入口です。"),
    4444: ("metasploit?", "high", "Metasploit等の待ち受けに使われる番号です。心当たりがなければ要調査。"),
    5000: ("upnp/airplay", "info", ""),
    5001: ("nas-https", "low", ""),
    5060: ("sip", "low", ""),
    5353: ("mdns", "info", ""),
    5357: ("wsd", "low", ""),
    5432: ("postgres", "medium", ""),
    5555: ("adb", "high", "Android ADB(デバッグ)が開いています。乗っ取り・マルウェア感染の恐れ。"),
    5800: ("vnc-http", "medium", ""),
    5900: ("vnc", "medium", "画面共有(VNC)。強いパスワード必須。"),
    5985: ("winrm", "medium", ""),
    6379: ("redis", "high", "Redisが認証なしだと乗っ取られます。"),
    6667: ("irc", "high", "IRCはボットネットの指令に使われることがあります。"),
    7000: ("airplay", "info", ""),
    7547: ("tr-069", "medium", "TR-069(プロバイダ管理)。過去に大規模攻撃の標的。"),
    8000: ("http-alt", "low", ""),
    8008: ("http-cast", "info", "Chromecast等"),
    8009: ("cast", "info", "Chromecast等"),
    8080: ("http-proxy", "low", "管理画面/プロキシ。"),
    8081: ("http-alt", "low", ""),
    8088: ("http-alt", "low", ""),
    8123: ("home-assistant", "low", ""),
    8291: ("winbox", "medium", "MikroTik管理(Winbox)。"),
    8443: ("https-alt", "low", ""),
    8554: ("rtsp-alt", "medium", "RTSP映像配信（カメラ）"),
    8883: ("mqtts", "low", ""),
    8888: ("http-alt", "low", ""),
    9000: ("http-alt", "low", ""),
    9100: ("jetdirect", "low", "プリンター(RAW印刷)"),
    9200: ("elasticsearch", "high", "Elasticsearchが認証なしだと情報が丸見えです。"),
    10000: ("webmin", "medium", ""),
    11211: ("memcached", "high", ""),
    27017: ("mongodb", "high", "MongoDBが認証なしだと情報が丸見えです。"),
    32400: ("plex", "low", ""),
    37215: ("huawei-hg", "high", "ボットネットに狙われるルーター管理ポート。"),
    49152: ("upnp", "low", "UPnP"),
    52869: ("realtek-upnp", "high", "ボットネットに狙われるUPnP実装。"),
    62078: ("iphone-sync", "info", "iPhone/iPadの同期サービス"),
}

TOP_PORTS = sorted(SERVICES)
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8123, 8888, 9000, 10000, 32400}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 554, 587, 1883, 3306, 5900, 6379, 6667} | HTTP_PORTS


class ScopeError(PermissionError):
    pass


def _check_scope(ip: str) -> None:
    if not is_local_target(ip):
        raise ScopeError("KEKKAIは自宅LAN内(プライベートIP)の機器しかスキャンしません: %s" % ip)


async def _probe(ip: str, port: int, timeout: float, sem: asyncio.Semaphore, banners: bool) -> Optional[Dict[str, Any]]:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (asyncio.TimeoutError, OSError, ValueError):
            return None
        res: Dict[str, Any] = {"port": port}
        try:
            if banners and port in BANNER_PORTS:
                if port in HTTP_PORTS:
                    writer.write(("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: KEKKAI\r\n\r\n" % ip).encode())
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(512), 1.2)
                text = data.decode("utf-8", "replace")
                if port in HTTP_PORTS:
                    for line in text.split("\r\n"):
                        if line.lower().startswith("server:"):
                            res["banner"] = line.split(":", 1)[1].strip()[:120]
                            break
                    if "banner" not in res and text.startswith("HTTP/"):
                        res["banner"] = text.split("\r\n", 1)[0][:60]
                else:
                    first = text.strip().splitlines()[0] if text.strip() else ""
                    if first:
                        res["banner"] = "".join(ch for ch in first if ch.isprintable())[:120]
        except (asyncio.TimeoutError, OSError, UnicodeError, IndexError):
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except (asyncio.TimeoutError, OSError, AttributeError):
                pass
        svc = SERVICES.get(port)
        if svc:
            res.update({"service": svc[0], "risk": svc[1], "note": svc[2]})
        else:
            res.update({"service": "unknown", "risk": "info", "note": ""})
        return res


async def _scan(ip: str, ports: List[int], timeout: float, concurrency: int, banners: bool) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(_probe(ip, p, timeout, sem, banners) for p in ports))
    return sorted((r for r in results if r), key=lambda r: r["port"])


def scan_host(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.8, concurrency: int = 200,
              banners: bool = True) -> Dict[str, Any]:
    _check_scope(ip)
    ports = sorted({int(p) for p in (ports or TOP_PORTS) if 0 < int(p) < 65536})
    concurrency = max(1, min(concurrency, _fd_budget()))
    t0 = time.time()
    loop = asyncio.new_event_loop()
    try:
        open_ports = loop.run_until_complete(_scan(ip, ports, timeout, concurrency, banners))
    finally:
        loop.close()
    worst = "info"
    order = ["info", "low", "medium", "high", "critical"]
    for r in open_ports:
        if order.index(r["risk"]) > order.index(worst):
            worst = r["risk"]
    return {"ip": ip, "scanned": len(ports), "open": open_ports, "worst": worst if open_ports else None,
            "duration": round(time.time() - t0, 2), "method": "tcp-connect", "ts": time.time()}


def _fd_budget() -> int:
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return max(16, int(soft) - 64)
    except (ImportError, ValueError, OSError):
        return 128


def raise_fd_limit(target: int = 4096) -> None:
    """macOS defaults to 256 open files per process; lift the soft limit for scanning."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = target if hard == resource.RLIM_INFINITY else min(target, hard)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except (ImportError, ValueError, OSError):
        pass
