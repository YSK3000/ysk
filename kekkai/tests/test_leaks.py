"""Leak monitoring: match only the user's own identifiers; never fetch the leaked data itself."""
import json
import unittest

import _support  # noqa: F401

from kekkai.detect import engine as rules
from kekkai.intel import leaks

# Shape taken from the real ransomware.live /v2/searchvictims response seen in CI.
ROWS = [
    {"victim": "ACME Corporation", "domain": "acme.co.jp", "group": "qilin", "country": "JP",
     "attackdate": "2026-10-20T00:00:00+00:00", "url": "https://www.ransomware.live/id/abc",
     "claim_url": "http://leak7xyz.onion/acme"},
    {"victim": "Totally Different Bank", "domain": "bank.example", "group": "lockbit",
     "attackdate": "2026-10-01T00:00:00+00:00", "url": "https://www.ransomware.live/id/def"},
]


def fake_fetch(calls):
    def f(url, **_):
        calls.append(url)
        return 200, {}, json.dumps(ROWS).encode()
    return f


class LeaksTest(unittest.TestCase):
    def test_matches_own_identifier_only(self):
        calls = []
        res = leaks.check(["ACME Corporation", "acme.co.jp"], fetch=fake_fetch(calls))
        self.assertTrue(all("/searchvictims/" in u for u in calls))  # only the search endpoint, no data download
        matches = res["sources"][0]["matches"]
        self.assertEqual([m["victim"] for m in matches], ["ACME Corporation"])
        self.assertNotIn("bank.example", json.dumps(res, ensure_ascii=False))

    def test_domain_match(self):
        res = leaks.check(["acme.co.jp"], fetch=fake_fetch([]))
        self.assertEqual([m["domain"] for m in res["sources"][0]["matches"]], ["acme.co.jp"])

    def test_no_false_substring(self):  # "AC" must not match "ACME"
        res = leaks.check(["AC"], fetch=fake_fetch([]))
        self.assertEqual(res["match_count"], 0)

    def test_finding_is_critical_with_attribution(self):
        res = leaks.check(["ACME Corporation"], fetch=fake_fetch([]))
        f = rules.leak_findings(res)
        self.assertEqual((f[0].rule, f[0].severity), ("leak.ransomware", "critical"))
        self.assertIn("Ransomware.live", f[0].detail)
        self.assertIn("ダウンロードしないで", f[0].advice)

    def test_empty_targets_noop(self):
        self.assertEqual(leaks.check([], fetch=fake_fetch([]))["match_count"], 0)

    def test_rate_limit_stops_and_is_reported(self):
        calls = []
        def rl(url, **_):
            calls.append(url)
            return (429, {}, b'{"message": "1 per 1 minute"}')
        res = leaks.search_ransomware_live(["ACME Corporation", "example.co.jp"], fetch=rl)
        self.assertTrue(res["rate_limited"])
        self.assertEqual(len(calls), 1)  # stops at the first 429 instead of hammering
        self.assertIsNone(res["error"])


if __name__ == "__main__":
    unittest.main()
