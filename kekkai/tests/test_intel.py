import ipaddress
import json
import os
import struct
import tempfile
import unittest

import _support  # noqa: F401

from kekkai.intel import feeds as feedsmod
from kekkai.intel.exposure import assess
from kekkai.intel.ipset import IPSet
from kekkai.intel.mmdb import InvalidDatabaseError, Reader
from kekkai.intel.oui import OUI, parse_ieee_csv, parse_oui_data_json, short_vendor


# ---------------------------------------------------------------- minimal MMDB writer (test only)
def _ctrl(t, size):
    if size < 29:
        first, extra = size, b""
    elif size < 285:
        first, extra = 29, bytes([size - 29])
    elif size < 65821:
        first, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        first, extra = 31, (size - 65821).to_bytes(3, "big")
    if t <= 7:
        return bytes([(t << 5) | first]) + extra
    return bytes([first, t - 7]) + extra


def enc(v):
    if isinstance(v, bool):
        return _ctrl(14, 1 if v else 0)
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, float):
        return _ctrl(3, 8) + struct.pack(">d", v)
    if isinstance(v, int):
        b = v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b""
        return _ctrl(6 if v < 2 ** 32 else 9, len(b)) + b
    if isinstance(v, dict):
        out = _ctrl(7, len(v))
        for k, x in v.items():
            out += enc(k) + enc(x)
        return out
    if isinstance(v, list):
        return _ctrl(11, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(v)


def write_mmdb(path, networks, record_size):
    """networks: {"1.2.3.0/24": {...}} (IPv4, stored under ::/96 like MaxMind does)."""
    root = {}
    data = b""
    offsets = {}
    for cidr, rec in networks.items():
        net = ipaddress.ip_network(cidr)
        bits = "0" * 96 + format(int(net.network_address), "032b")[: net.prefixlen]
        node = root
        for b in bits[:-1]:
            node = node.setdefault(b, {})
        offsets[cidr] = len(data)
        node[bits[-1]] = ("data", len(data))
        data += enc(rec)
    order, queue = [], [root]
    while queue:
        n = queue.pop(0)
        order.append(n)
        for k in ("0", "1"):
            if isinstance(n.get(k), dict):
                queue.append(n[k])
    index = {id(n): i for i, n in enumerate(order)}
    count = len(order)

    def val(child):
        if child is None:
            return count
        if isinstance(child, tuple):
            return count + 16 + child[1]
        return index[id(child)]

    tree = b""
    for n in order:
        left, r = val(n.get("0")), val(n.get("1"))
        if record_size == 24:
            tree += left.to_bytes(3, "big") + r.to_bytes(3, "big")
        elif record_size == 28:
            tree += (left & 0xFFFFFF).to_bytes(3, "big") + bytes([((left >> 24) & 0xF) << 4 | ((r >> 24) & 0xF)]) + (r & 0xFFFFFF).to_bytes(3, "big")
        else:
            tree += left.to_bytes(4, "big") + r.to_bytes(4, "big")
    meta = {"binary_format_major_version": 2, "binary_format_minor_version": 0, "build_epoch": 1790000000,
            "database_type": "Test-City", "description": {"en": "test"}, "ip_version": 6, "languages": ["en"],
            "node_count": count, "record_size": record_size}
    with open(path, "wb") as f:
        f.write(tree + b"\x00" * 16 + data + b"\xab\xcd\xefMaxMind.com" + enc(meta))


class MMDBTest(unittest.TestCase):
    NETS = {
        "8.8.8.0/24": {"country": {"iso_code": "US", "names": {"en": "United States", "ja": "アメリカ合衆国"}},
                       "location": {"latitude": 37.751, "longitude": -97.822}, "flag": True, "big": 2 ** 40},
        "133.242.0.0/16": {"country": {"iso_code": "JP"}, "city": {"names": {"en": "Tokyo" * 10}}, "list": [1, 2, 3]},
    }

    def test_record_sizes(self):
        for rs in (24, 28, 32):
            with self.subTest(record_size=rs):
                fd, path = tempfile.mkstemp(suffix=".mmdb")
                os.close(fd)
                write_mmdb(path, self.NETS, rs)
                r = Reader(path)
                self.assertEqual(r.record_size, rs)
                us = r.lookup("8.8.8.8")
                self.assertEqual(us["country"]["iso_code"], "US")
                self.assertEqual(us["country"]["names"]["ja"], "アメリカ合衆国")
                self.assertAlmostEqual(us["location"]["latitude"], 37.751)
                self.assertTrue(us["flag"])
                self.assertEqual(us["big"], 2 ** 40)
                jp = r.lookup("133.242.10.1")
                self.assertEqual(jp["city"]["names"]["en"], "Tokyo" * 10)
                self.assertEqual(jp["list"], [1, 2, 3])
                self.assertIsNone(r.lookup("8.8.9.9"))
                self.assertIsNone(r.lookup("1.1.1.1"))
                self.assertIsNone(r.lookup("not an ip"))
                r.close()
                os.unlink(path)

    def test_rejects_garbage(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"\x00" * 4096)
        os.close(fd)
        with self.assertRaises(InvalidDatabaseError):
            Reader(path)
        os.unlink(path)

    @unittest.skipUnless(os.environ.get("KEKKAI_TEST_MMDB"), "set KEKKAI_TEST_MMDB to a real DB-IP city mmdb")
    def test_real_dbip(self):
        r = Reader(os.environ["KEKKAI_TEST_MMDB"])
        self.assertEqual(r.lookup("8.8.8.8")["country"]["iso_code"], "US")


class IPSetFeedTest(unittest.TestCase):
    def test_ipset(self):
        s = IPSet(["10.0.0.0/8", "1.2.3.4", "1.2.3.5", "2001:db8::/32", "garbage", ""])
        self.assertIn("10.200.1.1", s)
        self.assertIn("1.2.3.5", s)
        self.assertNotIn("1.2.3.6", s)
        self.assertIn("2001:db8::1", s)
        self.assertNotIn("not-ip", s)
        self.assertEqual(len(s), 4)

    def test_parsers(self):
        self.assertEqual(feedsmod.parse_plain("# c\n1.2.3.4 # x\n5.6.7.0/24\n; semi\nbad line\n"), ["1.2.3.4", "5.6.7.0/24"])
        sp = '{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}\n{"type":"metadata","timestamp":1}\n'
        self.assertEqual(feedsmod.parse_spamhaus_json(sp), ["1.10.16.0/20"])

    def test_feedset_update_and_match(self):
        tmp = tempfile.mkdtemp()
        bodies = {"feodo": b"# feodo\n198.18.0.1\n8.8.8.8\n", "firehol_level1": b"10.0.0.0/8\n9.9.9.0/24\n",
                  "spamhaus_drop": b'{"cidr":"5.5.5.0/24"}\n'}

        def fake(url, **kw):
            for fid, f in feedsmod.FEEDS.items():
                if f["url"] == url and fid in bodies:
                    return 200, {}, bodies[fid]
            return 403, {}, b""

        fs = feedsmod.FeedSet(tmp)
        rep = fs.update(force=True, fetch=fake)
        self.assertTrue(rep["feodo"].startswith("ok"))
        self.assertTrue(rep["tor_exit"].startswith("error"))
        hits = fs.match("8.8.8.8")
        self.assertEqual(hits[0]["feed"], "feodo")
        self.assertEqual(fs.match("10.1.2.3"), [], "private addresses must never match (FireHOL lists bogons)")
        self.assertEqual(fs.match("5.5.5.5")[0]["feed"], "spamhaus_drop")
        st = {s["id"]: s for s in fs.status()}
        self.assertEqual(st["feodo"]["status"], "ok")
        self.assertEqual(st["tor_exit"]["status"], "error")
        rep2 = fs.update(fetch=fake)
        self.assertEqual(rep2["feodo"], "fresh")


class OUITest(unittest.TestCase):
    def test_parse_and_lookup(self):
        csv_text = ('Registry,Assignment,Organization Name,Organization Address\n'
                    'MA-L,3C22FB,"Apple, Inc.",1 Infinite Loop\n'
                    'MA-L,0055DA,"IEEE Registration Authority",x\n'
                    'MA-M,0055DA0,"Shinko Technos co.,ltd.",y\n'
                    'MA-S,0055DA012,"Tiny Vendor GmbH",z\n')
        db = parse_ieee_csv(csv_text)
        self.assertEqual(db["3C22FB"], "Apple, Inc.")
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "oui.json"), "w") as f:
            json.dump(db, f)
        o = OUI(tmp)
        self.assertEqual(o.vendor("3c:22:fb:7a:10:23"), "Apple")
        self.assertEqual(o.vendor("00:55:da:01:23:45"), "Tiny Vendor")
        self.assertEqual(o.vendor("00:55:da:0f:23:45"), "Shinko Technos")
        self.assertIsNone(o.vendor("9a:4e:2c:11:aa:01"), "randomized MACs have no vendor")
        self.assertEqual(parse_oui_data_json('{"3c22fb": "Apple, Inc.\\nCupertino"}'), {"3C22FB": "Apple, Inc."})

    def test_short_vendor(self):
        self.assertEqual(short_vendor("Apple, Inc."), "Apple")
        self.assertEqual(short_vendor("Samsung Electronics Co.,Ltd"), "Samsung Electronics")
        self.assertEqual(short_vendor("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-LINK")
        self.assertEqual(short_vendor("BUFFALO.INC"), "BUFFALO")
        self.assertEqual(short_vendor("Garag"), "Garag")


class ExposureTest(unittest.TestCase):
    def test_assess(self):
        idb = {"found": True, "ports": [23, 443], "vulns": ["CVE-2023-0001"]}
        res = assess("203.0.113.10", idb, {"external_ip": "203.0.113.10", "mappings": []})
        sev = {f["title"]: f["severity"] for f in res["findings"]}
        self.assertEqual(sev["インターネットからポート 23 が見えています"], "high")
        self.assertEqual(sev["公開IPに既知の脆弱性(CVE)が記録されています"], "high")
        shared = assess("203.0.113.10", idb, {"external_ip": "192.0.0.2", "mappings": []})
        self.assertTrue(shared["shared_ipv4"])
        self.assertTrue(all(f["severity"] in ("info", "low") for f in shared["findings"]))


class WorldDataTest(unittest.TestCase):
    def test_world_json(self):
        path = os.path.join(os.path.dirname(__file__), "..", "src", "kekkai", "web", "data", "world.json")
        with open(path, encoding="utf-8") as f:
            world = json.load(f)
        codes = {c["a2"] for c in world}
        self.assertTrue({"JP", "US", "BR", "AU", "RU"} <= codes)
        self.assertNotIn("AQ", codes)
        for c in world:
            for ring in c["p"]:
                for a, b in zip(ring, ring[1:]):
                    self.assertLessEqual(abs(a[0] - b[0]), 180, c["a2"])


if __name__ == "__main__":
    unittest.main()
