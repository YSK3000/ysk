import unittest

from _support import fixture

from kekkai import netutil
from kekkai.audit import macos as audit_macos
from kekkai.platforms import linux as lx
from kekkai.platforms import macos as mac
from kekkai.platforms.base import pick_lan
from kekkai.sensor import Detector, domain_match


class NetutilTest(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(netutil.normalize_mac("a4:2b:b0:1:2:3"), "a4:2b:b0:01:02:03")
        self.assertEqual(netutil.normalize_mac("A4-2B-B0-01-02-03"), "a4:2b:b0:01:02:03")
        self.assertEqual(netutil.normalize_mac("a42b.b001.0203"), "a4:2b:b0:01:02:03")
        self.assertEqual(netutil.normalize_mac("A42BB0010203"), "a4:2b:b0:01:02:03")
        for bad in ("(incomplete)", "", None, "zz:zz:zz:zz:zz:zz", "1:2:3", "00:00:00:00:00:00", "123:1:1:1:1:1"):
            self.assertIsNone(netutil.normalize_mac(bad), bad)

    def test_mac_bits(self):
        self.assertTrue(netutil.mac_is_randomized("9a:4e:2c:11:aa:01"))
        self.assertFalse(netutil.mac_is_randomized("3c:22:fb:7a:10:23"))
        self.assertTrue(netutil.mac_is_multicast("01:00:5e:00:00:fb"))

    def test_scope(self):
        for ip in ("192.168.1.10", "10.0.0.5", "172.20.1.1", "169.254.3.4", "127.0.0.1", "fe80::1", "fd00::5"):
            self.assertTrue(netutil.is_local_target(ip), ip)
        for ip in ("8.8.8.8", "100.64.0.1", "224.0.0.251", "2001:4860:4860::8888", "0.0.0.0", "nonsense", None):
            self.assertFalse(netutil.is_local_target(ip), ip)
        self.assertTrue(netutil.is_public("8.8.8.8"))
        self.assertFalse(netutil.is_public("192.168.1.1"))
        self.assertFalse(netutil.is_public("203.0.113.5"))

    def test_parse_ip(self):
        self.assertEqual(str(netutil.parse_ip("::ffff:1.2.3.4")), "1.2.3.4")
        self.assertEqual(str(netutil.parse_ip("fe80::1%en0")), "fe80::1")
        self.assertEqual(str(netutil.parse_ip("[2001:db8::1]")), "2001:db8::1")
        self.assertIsNone(netutil.parse_ip("*"))


class MacOSParserTest(unittest.TestCase):
    def test_ifconfig(self):
        hw = mac.parse_hardware_ports(fixture("macos", "hardware_ports.txt"))
        self.assertEqual(hw["en0"], "Wi-Fi")
        ifs = {i.name: i for i in mac.parse_ifconfig(fixture("macos", "ifconfig.txt"), hw)}
        en0 = ifs["en0"]
        self.assertEqual(en0.kind, "wifi")
        self.assertEqual(en0.mac, "3c:22:fb:7a:10:23")
        self.assertEqual(en0.ipv4, [("192.168.10.23", 24)])
        self.assertTrue(en0.active and en0.up)
        self.assertEqual(ifs["utun4"].kind, "vpn")
        self.assertEqual(ifs["utun4"].ipv4, [("10.8.0.6", 32)])
        self.assertEqual(ifs["lo0"].kind, "loopback")
        self.assertFalse(ifs["bridge0"].up)
        self.assertEqual(ifs["awdl0"].kind, "p2p")

    def test_routes_with_vpn(self):
        gw, via = mac.parse_netstat_routes(fixture("macos", "netstat_routes_vpn.txt"))
        self.assertEqual(via, "utun4")
        self.assertEqual(gw, {"utun4": "10.8.0.5", "en0": "192.168.10.1"})
        hw = mac.parse_hardware_ports(fixture("macos", "hardware_ports.txt"))
        ctx = pick_lan(mac.parse_ifconfig(fixture("macos", "ifconfig.txt"), hw), gw, via)
        self.assertEqual((ctx.interface, ctx.gateway, ctx.prefixlen), ("en0", "192.168.10.1", 24))
        self.assertTrue(ctx.vpn_active)

    def test_arp(self):
        n = mac.parse_arp(fixture("macos", "arp.txt"))
        by_ip = {x.ip: x for x in n}
        self.assertEqual(by_ip["192.168.10.1"].mac, "a4:2b:b0:10:00:01")
        self.assertEqual(by_ip["192.168.10.24"].mac, "9a:4e:2c:11:aa:01")
        self.assertIsNone(by_ip["192.168.10.37"].mac)
        self.assertEqual(by_ip["192.168.10.40"].mac, "64:eb:8c:10:00:40")
        self.assertNotIn("192.168.10.255", by_ip)
        self.assertNotIn("224.0.0.251", by_ip)

    def test_netstat_tcp(self):
        conns = mac.parse_netstat_sockets(fixture("macos", "netstat_tcp.txt"))
        self.assertEqual(len(conns), 7)
        c0 = conns[0]
        self.assertEqual((c0.proto, c0.laddr, c0.lport, c0.raddr, c0.rport, c0.state, c0.pid),
                         ("tcp", "192.168.10.23", 52344, "17.57.146.20", 5223, "ESTABLISHED", 432))
        v6 = conns[1]
        self.assertEqual((v6.raddr, v6.rport, v6.pid), ("2404:6800:4004:81d::200e", 443, 414))
        listen = conns[2]
        self.assertTrue(listen.is_listen)
        self.assertEqual((listen.laddr, listen.lport, listen.pid), ("*", 7000, 520))
        self.assertEqual(conns[4].state, "SYN_SENT")
        self.assertIsNone(conns[6].pid)  # pid 0 -> unknown

    def test_netstat_udp(self):
        conns = mac.parse_netstat_sockets(fixture("macos", "netstat_udp.txt"))
        self.assertEqual(len(conns), 3)
        self.assertTrue(conns[0].is_listen)
        self.assertEqual(conns[0].pid, 331)
        quic = conns[1]
        self.assertEqual((quic.raddr, quic.rport, quic.pid, quic.state), ("142.250.196.110", 443, 414, ""))
        self.assertFalse(quic.is_listen)

    def test_netstat_process_column_variant(self):
        text = ("Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      process:pid\n"
                "tcp4       0      0  10.0.0.2.5000          1.1.1.1.443            ESTABLISHED  curl:4242\n")
        c = mac.parse_netstat_sockets(text)[0]
        self.assertEqual((c.pid, c.process), (4242, "curl"))

    def test_lsof(self):
        conns = mac.parse_lsof(fixture("macos", "lsof.txt"))
        self.assertEqual(len(conns), 4)
        self.assertEqual(conns[0].process, "Google Chrome Helper")
        self.assertEqual((conns[0].raddr, conns[0].rport, conns[0].state), ("17.57.146.20", 5223, "ESTABLISHED"))
        self.assertEqual((conns[1].proto, conns[1].lport), ("udp", 5353))
        self.assertEqual((conns[3].raddr, conns[3].rport, conns[3].pid), ("2404:6800:4004:81d::200e", 443, 520))

    def test_ps(self):
        procs = mac.parse_ps(fixture("macos", "ps.txt"))
        self.assertEqual(procs[414].name, "Google Chrome")
        self.assertEqual(procs[414].path, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        self.assertEqual(procs[331].uid, 65)
        self.assertIsNone(procs[950].path)

    def test_dns_and_proxy(self):
        self.assertEqual(mac.parse_scutil_dns(fixture("macos", "scutil_dns.txt")), ["192.168.10.1", "2404:1a8:7f01:a::3"])
        p = mac.proxy_summary(mac.parse_scutil_proxy(fixture("macos", "scutil_proxy_pac.txt")))
        self.assertEqual(p, {"pac": "http://198.51.100.7/proxy.pac"})
        self.assertEqual(mac.proxy_summary(mac.parse_scutil_proxy("<dictionary> {\n  HTTPEnable : 0\n}\n")), {})

    def test_wifi(self):
        w = mac.parse_system_profiler_wifi(fixture("macos", "system_profiler_wifi.json"))
        self.assertEqual(w["ssid"], "KEKKAI-HOME-5G")
        self.assertEqual(w["security"], "WPA3/WPA2")
        self.assertEqual(w["nearby"][0]["security"], "OPEN")
        self.assertIsNone(mac.parse_system_profiler_wifi("not json"))
        self.assertEqual(mac.security_label("spairport_security_mode_wep"), "WEP")
        self.assertEqual(mac.security_label("spairport_security_mode_wpa2_enterprise"), "WPA2-Enterprise")

    def test_codesign(self):
        a = mac.parse_codesign(0, fixture("macos", "codesign_apple.txt"))
        self.assertTrue(a["signed"] and a["apple"])
        self.assertIsNone(a["team"])
        d = mac.parse_codesign(0, fixture("macos", "codesign_devid.txt"))
        self.assertEqual(d["team"], "EQHXZ8M8AV")
        self.assertFalse(d["apple"])
        ad = mac.parse_codesign(0, fixture("macos", "codesign_adhoc.txt"))
        self.assertTrue(ad["adhoc"] and ad["signed"])
        u = mac.parse_codesign(1, "/tmp/x: code object is not signed at all\n")
        self.assertFalse(u["signed"])
        self.assertTrue(u["checked"])
        e = mac.parse_codesign(1, "/nope: No such file or directory\n")
        self.assertFalse(e["checked"])

    def test_audit_parsers(self):
        self.assertTrue(audit_macos.parse_firewall_state("Firewall is enabled. (State = 1)"))
        self.assertTrue(audit_macos.parse_firewall_state("Firewall is blocking all non-essential incoming connections. (State = 2)"))
        self.assertFalse(audit_macos.parse_firewall_state("Firewall is disabled. (State = 0)"))
        self.assertTrue(audit_macos.parse_on_off("Firewall stealth mode is on"))
        self.assertTrue(audit_macos.parse_on_off("Stealth mode enabled"))
        self.assertFalse(audit_macos.parse_on_off("Firewall stealth mode is off"))
        self.assertFalse(audit_macos.parse_on_off("Stealth mode disabled"))
        self.assertEqual(audit_macos.parse_fdesetup("FileVault is On."), "on")
        self.assertEqual(audit_macos.parse_fdesetup("FileVault is Off."), "off")
        self.assertEqual(audit_macos.parse_csrutil("System Integrity Protection status: enabled."), "enabled")
        self.assertEqual(audit_macos.parse_csrutil("System Integrity Protection status: unknown (Custom Configuration)."), "custom")
        su = audit_macos.parse_softwareupdate(0, "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: macOS Tahoe 26.5.1-25F80\n\tTitle: macOS Tahoe 26.5.1, Version: 26.5.1, Size: 1234KiB, Recommended: YES, Action: restart,\n", "")
        self.assertEqual(su["state"], "pending")
        self.assertIn("macOS Tahoe 26.5.1-25F80", su["updates"])
        self.assertEqual(audit_macos.parse_softwareupdate(0, "", "No new software available.\n")["state"], "current")


class LinuxParserTest(unittest.TestCase):
    TCP = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
           "   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22179 1\n"
           "   1: 0201A8C0:C350 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1\n")

    def test_proc_net(self):
        rows = lx.parse_proc_net(self.TCP, "tcp")
        listen, est = rows[0][0], rows[1][0]
        self.assertEqual((listen.laddr, listen.lport, listen.state), ("127.0.0.1", 631, "LISTEN"))
        self.assertEqual((est.laddr, est.raddr, est.rport, est.state, est.uid), ("192.168.1.2", "8.8.8.8", 443, "ESTABLISHED", 1000))
        self.assertEqual(rows[1][1], "33333")

    def test_arp_route_resolv(self):
        arp = ("IP address       HW type     Flags       HW address            Mask     Device\n"
               "192.168.1.1      0x1         0x2         a4:2b:b0:01:02:03     *        eth0\n"
               "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        n = lx.parse_proc_arp(arp)
        self.assertEqual(n[0].mac, "a4:2b:b0:01:02:03")
        self.assertIsNone(n[1].mac)
        route = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                 "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                 "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
        gw, via = lx.parse_proc_route(route)
        self.assertEqual((gw, via), ({"eth0": "192.168.1.1"}, "eth0"))
        self.assertEqual(lx.parse_resolv_conf("# x\nnameserver 1.1.1.1\nnameserver 1.1.1.1\nsearch lan\n"), ["1.1.1.1"])


class SensorTest(unittest.TestCase):
    def det(self):
        return Detector("192.168.10.23", "3c:22:fb:7a:10:23", "192.168.10.1", "a4:2b:b0:10:00:01",
                        domains={"evil-phish.example"}, scan_ports=10, sweep_targets=10)

    def test_port_scan(self):
        d = self.det()
        ev = None
        for i, port in enumerate(range(20, 40)):
            line = ("1700000000.%06d 11:22:33:44:55:66 > 3c:22:fb:7a:10:23, ethertype IPv4 (0x0800), length 78: "
                    "192.168.10.50.51234 > 192.168.10.23.%d: Flags [S], seq 1, win 65535, length 0" % (i, port))
            ev = d.feed(line) or ev
        self.assertEqual(ev["kind"], "port_scan")
        self.assertEqual(ev["src"], "192.168.10.50")
        self.assertIsNone(d.feed(line))  # cooldown

    def test_arp_spoof_and_sweep(self):
        d = self.det()
        ev = d.feed("1700000000.000001 7c:df:a1:3e:0:37 > 3c:22:fb:7a:10:23, ethertype ARP (0x0806), length 42: "
                    "Reply 192.168.10.1 is-at 7c:df:a1:3e:0:37, length 28")
        self.assertEqual((ev["kind"], ev["mac"]), ("arp_spoof", "7c:df:a1:3e:00:37"))
        ok = d.feed("1700000000.000002 a4:2b:b0:10:0:1 > 3c:22:fb:7a:10:23, ethertype ARP (0x0806), length 42: "
                    "Reply 192.168.10.1 is-at a4:2b:b0:10:0:1, length 28")
        self.assertIsNone(ok)
        ev = None
        for i in range(2, 20):
            ev = d.feed("1700000001.%06d 7c:df:a1:3e:0:37 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: "
                        "Request who-has 192.168.10.%d tell 192.168.10.37, length 28" % (i, i)) or ev
        self.assertEqual(ev["kind"], "arp_sweep")

    def test_dns(self):
        d = self.det()
        ev = d.feed("1700000000.000001 3c:22:fb:7a:10:23 > a4:2b:b0:10:0:1, ethertype IPv4 (0x0800), length 80: "
                    "192.168.10.23.53211 > 192.168.10.1.53: 41234+ [1au] A? login.evil-phish.example. (45)")
        self.assertEqual((ev["kind"], ev["matched"]), ("dns_threat", "evil-phish.example"))
        self.assertIsNone(domain_match("example", {"evil-phish.example"}))


if __name__ == "__main__":
    unittest.main()
