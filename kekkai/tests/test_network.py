import random
import socket
import struct
import threading
import unittest

import _support  # noqa: F401

from kekkai.discovery import dnswire, ssdp
from kekkai.discovery.mdns import _service_type, reverse_name
from kekkai.discovery.portscan import ScopeError, scan_host


class DNSWireTest(unittest.TestCase):
    def test_roundtrip(self):
        q = dnswire.build_query(0x1234, [("_services._dns-sd._udp.local", dnswire.T_PTR)])
        msg = dnswire.parse_message(q)
        self.assertEqual(msg["id"], 0x1234)
        self.assertEqual(msg["questions"][0]["name"], "_services._dns-sd._udp.local")

    def _response(self):
        hdr = struct.pack(">HHHHHH", 7, 0x8400, 0, 3, 0, 0)
        name = dnswire.encode_name("Living Room._airplay._tcp.local")
        ptr = dnswire.encode_name("_airplay._tcp.local") + struct.pack(">HHIH", 12, 1, 120, len(name)) + name
        target = dnswire.encode_name("living.local")
        srv = (b"\xc0\x0c"[:0] + dnswire.encode_name("Living Room._airplay._tcp.local") +
               struct.pack(">HHIH", 33, 1, 120, 6 + len(target)) + struct.pack(">HHH", 0, 0, 7000) + target)
        txt_items = b"\x0emodel=AppleTV6" + b"\x05flag"
        txt = dnswire.encode_name("Living Room._airplay._tcp.local") + struct.pack(">HHIH", 16, 1, 120, len(txt_items)) + txt_items
        return hdr + ptr + srv + txt

    def test_parse_records(self):
        msg = dnswire.parse_message(self._response())
        self.assertTrue(msg["response"])
        vals = {r["type"]: r["value"] for r in msg["records"]}
        self.assertEqual(vals[12], "Living Room._airplay._tcp.local")
        self.assertEqual(vals[33]["port"], 7000)
        self.assertEqual(vals[16], ["model=AppleTV6", "flag"])

    def test_pointer_loop_and_fuzz(self):
        loop = struct.pack(">HHHHHH", 1, 0x8400, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            dnswire.parse_message(loop)
        rnd = random.Random(1)
        good = self._response()
        for _ in range(3000):
            data = bytearray(good)
            for _ in range(rnd.randint(1, 8)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            try:
                dnswire.parse_message(bytes(data[: rnd.randint(0, len(data))]))
            except ValueError:
                pass

    def test_helpers(self):
        self.assertEqual(_service_type("Living Room._airplay._tcp.local"), "_airplay._tcp")
        self.assertEqual(_service_type("_ipp._tcp.local."), "_ipp._tcp")
        self.assertIsNone(_service_type("host.local"))
        self.assertEqual(reverse_name("192.168.1.20"), "20.1.168.192.in-addr.arpa")


class SSDPTest(unittest.TestCase):
    def test_parse_response(self):
        h = ssdp.parse_response(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n")
        self.assertEqual(h["location"], "http://192.168.1.1:5000/desc.xml")
        self.assertIsNone(ssdp.parse_response(b"garbage"))

    def test_xml_safety(self):
        with self.assertRaises(ValueError):
            ssdp.safe_xml(b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><r>&lol;</r>')
        with self.assertRaises(ValueError):
            ssdp._http("GET", "http://evil.example/desc.xml", "192.168.1.1")
        with self.assertRaises(ValueError):
            ssdp._http("GET", "http://192.168.1.99/desc.xml", "192.168.1.1")
        with self.assertRaises(ValueError):
            ssdp._http("GET", "file:///etc/passwd", "192.168.1.1")

    def test_igd_audit(self):
        desc_xml = (b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
                    b'<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Aterm</friendlyName>'
                    b'<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>'
                    b'<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>')
        mapping = (b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:R xmlns:u="x">'
                   b'<NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalClient>192.168.1.37</NewInternalClient>'
                   b'<NewInternalPort>80</NewInternalPort><NewEnabled>1</NewEnabled><NewPortMappingDescription>cam</NewPortMappingDescription>'
                   b'</u:R></s:Body></s:Envelope>')
        ext = (b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:R xmlns:u="x">'
               b'<NewExternalIPAddress>203.0.113.10</NewExternalIPAddress></u:R></s:Body></s:Envelope>')
        calls = []

        def fake_http(method, url, responder_ip, body=None, headers=None, timeout=3.0):
            calls.append((method, url))
            if method == "GET":
                return 200, desc_xml
            if b"GetExternalIPAddress" in body:
                return 200, ext
            if b"<NewPortMappingIndex>0<" in body:
                return 200, mapping
            return 500, b"<error/>"

        orig = ssdp._http
        ssdp._http = fake_http
        try:
            desc = ssdp.describe("http://192.168.1.1:5000/desc.xml", "192.168.1.1")
            self.assertEqual(desc["friendlyName"], "Aterm")
            res = ssdp.igd_audit(desc, "192.168.1.1")
        finally:
            ssdp._http = orig
        self.assertEqual(res["external_ip"], "203.0.113.10")
        self.assertEqual(res["mappings"][0]["internal_client"], "192.168.1.37")
        self.assertEqual(len(res["mappings"]), 1)
        self.assertTrue(all(u.startswith("http://192.168.1.1:5000/") for _, u in calls))


class PortScanTest(unittest.TestCase):
    def test_scope_guard(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700::1111", "example.com"):
            with self.assertRaises(ScopeError):
                scan_host(ip)

    def test_local_scan_with_banner(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def serve():
            for _ in range(2):
                try:
                    c, _ = srv.accept()
                    c.sendall(b"SSH-2.0-TestServer_1.0\r\n")
                    c.close()
                except OSError:
                    return

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        from kekkai.discovery import portscan
        portscan.BANNER_PORTS = set(portscan.BANNER_PORTS) | {port}
        res = scan_host("127.0.0.1", ports=[port, 1], timeout=1.0)
        srv.close()
        self.assertEqual([p["port"] for p in res["open"]], [port])
        self.assertEqual(res["open"][0]["banner"], "SSH-2.0-TestServer_1.0")


if __name__ == "__main__":
    unittest.main()
