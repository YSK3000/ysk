#!/usr/bin/env python3
"""Real-machine smoke test (GitHub Actions macOS runners, or your own Mac).

Runs every collector against the real OS, prints raw command output next to what the parsers made
of it, downloads the real GeoIP/OUI/threat data, and exercises the server and MCP endpoints.
Exit code != 0 when a check that must work on macOS fails.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("KEKKAI_HOME", tempfile.mkdtemp(prefix="kekkai-smoke-"))

from kekkai import config  # noqa: E402
from kekkai.util import IS_MACOS, run  # noqa: E402

FAILS = []


def section(title):
    print("\n" + "=" * 8 + " " + title + " " + "=" * 8, flush=True)


def raw(cmd, lines=25):
    rc, out, err = run(cmd, timeout=60)
    text = (out or err).rstrip("\n").splitlines()
    print("$ %s  (rc=%s, %d lines)" % (" ".join(cmd), rc, len(text)))
    for line in text[:lines]:
        print("  | " + line)
    return rc, out, err


def check(name, ok, detail=""):
    print("[%s] %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
    if not ok:
        FAILS.append(name)


def guarded(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        FAILS.append(fn.__name__)


def collectors():
    from kekkai.platforms import get_platform
    p = get_platform()
    section("raw macOS command output")
    for cmd in (["sw_vers"], ["networksetup", "-listallhardwareports"], ["ifconfig", "-a"], ["netstat", "-rn", "-f", "inet"],
                ["arp", "-an"], ["netstat", "-anvW", "-p", "tcp"], ["netstat", "-anv", "-p", "udp"], ["scutil", "--dns"],
                ["scutil", "--proxy"], ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"], ["fdesetup", "status"],
                ["csrutil", "status"], ["spctl", "--status"], ["sysadminctl", "-screenLock", "status"],
                ["tmutil", "destinationinfo"], ["profiles", "status", "-type", "enrollment"]):
        raw(cmd, 12 if cmd[0] in ("netstat", "ifconfig") else 30)
    raw(["lsof", "+c", "0", "-nP", "-iTCP", "-iUDP", "-FpcuPnT"], 16)
    raw(["ps", "-axo", "pid=,ppid=,uid=,comm="], 8)
    raw(["system_profiler", "SPAirPortDataType", "-json"], 30)
    raw(["codesign", "-dv", "--verbose=2", "/Applications/Safari.app/Contents/MacOS/Safari"], 12)

    section("parsed by KEKKAI")
    ifs = p.interfaces()
    for i in ifs:
        if i.ipv4 or i.active:
            print("  iface", i.name, i.kind, i.hw_port, i.mac, i.ipv4, "active" if i.active else "")
    check("interfaces", any(i.ipv4 and i.kind != "loopback" for i in ifs))
    ctx = p.lan_context()
    print("  lan_context", ctx)
    check("lan_context.interface", bool(ctx.interface))
    check("lan_context.gateway", bool(ctx.gateway))
    neigh = p.neighbors()
    print("  neighbors", [(n.ip, n.mac) for n in neigh][:10])
    conns = p.connections()
    with_pid = [c for c in conns if c.pid]
    print("  connections %d, with pid %d, with process %d" % (len(conns), len(with_pid), len([c for c in conns if c.process])))
    for c in conns[:12]:
        print("   ", c.proto, c.laddr, c.lport, "->", c.raddr, c.rport, c.state, c.pid, c.process)
    check("connections parsed", len(conns) > 0)
    check("netstat pid column", len(with_pid) >= max(1, len(conns) // 2), "(%d/%d)" % (len(with_pid), len(conns)))
    check("process names", any(c.process for c in conns))
    procs = p.processes()
    check("processes", len(procs) > 30, "(%d)" % len(procs))
    dns = p.dns_servers()
    print("  dns", dns, "proxies", p.proxies())
    check("dns servers", bool(dns))
    print("  wifi", json.dumps(p.wifi(), ensure_ascii=False)[:300])
    items = p.persistence_items()
    print("  persistence", len(items))
    for it in items[:6]:
        print("   ", it.get("label"), it.get("program"), (it.get("signature") or {}).get("summary"), it.get("exists"))
    sig = p.code_signature("/Applications/Safari.app/Contents/MacOS/Safari")
    print("  safari signature", sig)
    check("codesign apple", bool(sig.get("signed") and sig.get("apple")))
    check("capabilities", bool(p.capabilities().get("netstat")))


def audit():
    section("posture audit")
    from kekkai.monitor import Monitor
    m = Monitor(config.load())
    m.fast_cycle()
    res = m.posture_cycle(slow=False)
    for c in res["checks"]:
        print("  %-8s %-32s %s" % (c["status"], c["title"], c["detail"][:90]))
    check("audit checks", len(res["checks"]) >= 8, "(%d, score %s)" % (len(res["checks"]), res.get("score")))
    unknown = [c["id"] for c in res["checks"] if c["status"] == "unknown"]
    check("audit parsers understand macOS output", not unknown, str(unknown))
    m.store.close()


def intel():
    section("real data downloads")
    from kekkai.intel import updater
    from kekkai.intel.feeds import FeedSet
    from kekkai.intel.geo import Geo
    from kekkai.intel.oui import OUI
    city = updater.update_geo("city", force=True)
    asn = updater.update_geo("asn", force=True)
    oui = updater.update_oui(force=True)
    feeds = FeedSet().update(force=True)
    print("  city:", city, "\n  asn:", asn, "\n  oui:", oui)
    for k, v in feeds.items():
        print("  feed %-16s %s" % (k, v))
    check("geo city", city.startswith("ok"))
    check("geo asn", asn.startswith("ok"))
    check("oui", oui.startswith("ok"))
    okfeeds = [k for k, v in feeds.items() if v.startswith("ok")]
    check("feeds", len(okfeeds) >= 4, str(okfeeds))
    g = Geo()
    for ip in ("8.8.8.8", "1.1.1.1", "17.253.144.10", "133.242.0.1"):
        print("  geo", g.lookup(ip))
    check("geo lookup", g.lookup("8.8.8.8").get("org", "").startswith("Google"))
    print("  oui Apple?", OUI().vendor("3c:22:fb:00:00:01"))
    check("oui lookup", (OUI().vendor("3c:22:fb:00:00:01") or "").startswith("Apple"))


def exposure_and_lan():
    section("exposure + LAN discovery on this runner")
    from kekkai.monitor import Monitor
    m = Monitor(config.load())
    m.fast_cycle()
    t0 = time.time()
    print("  lan_cycle", m.lan_cycle(), "%.1fs" % (time.time() - t0))
    print("  devices", [(d["ip"], d["mac"], d["kind"], d.get("vendor")) for d in m.store.devices(m.state["network"]["id"])][:10])
    res = m.exposure_cycle()
    print("  exposure", json.dumps({k: res.get(k) for k in ("public_ip", "shared_ipv4", "error")}),
          (res.get("internetdb") or {}).get("ports"))
    check("public ip", bool(res.get("public_ip")))
    summ = m.summary()
    print("  summary stats", summ.get("stats"), summ.get("threat"))
    m.store.close()


def server_and_mcp():
    section("dashboard server + MCP")
    from kekkai import server
    from kekkai.monitor import Monitor
    cfg = config.load()
    m = Monitor(cfg)
    m.fast_cycle()
    app = server.App(m, cfg, "x" * 43)
    httpd = server.Server(("127.0.0.1", 0), app)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request("http://127.0.0.1:%d/api/summary" % port, headers={"Authorization": "Bearer " + "x" * 43})
    with opener.open(req, timeout=10) as r:
        body = json.loads(r.read())
    check("server summary", r.status == 200 and "threat" in body)
    httpd.shutdown()
    m.store.close()
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    p = subprocess.Popen([sys.executable, "-m", "kekkai", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "kekkai_status", "arguments": {}}}]
    out, _ = p.communicate("\n".join(json.dumps(x) for x in msgs) + "\n", timeout=120)
    lines = [json.loads(x) for x in out.splitlines() if x.strip()]
    check("mcp", len(lines) == 2 and not lines[1]["result"]["isError"])
    from kekkai import doctor
    section("doctor")
    doctor.print_report(doctor.run_checks(cfg, quick=False), color=False)
    from kekkai.discovery.portscan import raise_fd_limit, scan_host
    raise_fd_limit()
    res = scan_host("127.0.0.1")
    print("  localhost open ports", [(x["port"], x["service"]) for x in res["open"]], res["duration"], "s")


if __name__ == "__main__":
    print("python", sys.version.replace("\n", " "), "| KEKKAI_HOME", os.environ["KEKKAI_HOME"])
    if IS_MACOS:
        guarded(collectors)
        guarded(audit)
    guarded(intel)
    guarded(exposure_and_lan)
    guarded(server_and_mcp)
    print("\nFAILED: %s" % FAILS if FAILS else "\nALL SMOKE CHECKS PASSED")
    sys.exit(1 if FAILS else 0)
