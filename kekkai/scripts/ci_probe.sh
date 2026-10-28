#!/bin/bash
# 実機（GitHub Actions の macOS）で、実装前に「本物の挙動」を測る。
#  1) Tor: 公式の tor を入れて起動し、Tor Project 公式の onion 一覧にある .onion を KEKKAI で読めるか（必須）
#  2) ransomware.live API v2 の実際の応答（記録のみ）
#  3) sfltool dumpbtm の実際の出力（ログイン項目の監視の準備、記録のみ）
#  4) nmap: 公式の nmap を入れて、KEKKAI の詳細スキャン(-sV)が実機で動くか（必須）
set -u
cd "$(dirname "$0")/.."
PY=/usr/bin/python3

echo "==== 1) Tor"
brew install tor > /dev/null 2>&1 || { echo "FAIL: brew install tor"; exit 1; }
tor --version | head -1
tor --SocksPort 9050 --DataDirectory "$(mktemp -d)" --Log "notice stdout" > /tmp/tor.log 2>&1 &
TOR=$!
for _ in $(seq 120); do grep -q "Bootstrapped 100%" /tmp/tor.log && break; sleep 1; done
grep "Bootstrapped 100%" /tmp/tor.log || { tail -20 /tmp/tor.log; echo "FAIL: tor did not bootstrap"; kill $TOR; exit 1; }
curl -sS -m 30 https://onion.torproject.org/ -o /tmp/onions.html
ONIONS=$(grep -oE '[a-z2-7]{56}\.onion' /tmp/onions.html | awk '!seen[$0]++' | head -8)
echo "official onion addresses found: $(echo "$ONIONS" | wc -l)"
OK=0
ONION_OUTPUT=$(mktemp)
for o in $ONIONS; do
  # Do not pipe the command into head: head can succeed even when KEKKAI failed.
  if PYTHONPATH=src "$PY" -m kekkai onion "http://$o/" --json > "$ONION_OUTPUT"; then
    if "$PY" - "$ONION_OUTPUT" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        page = json.load(f)
    ok = (isinstance(page, dict) and isinstance(page.get("status"), int)
          and 200 <= page["status"] < 300 and not page.get("skipped")
          and isinstance(page.get("text"), str) and bool(page["text"].strip()))
except (OSError, ValueError):
    ok = False
sys.exit(0 if ok else 1)
PY
    then OK=1; echo "PASS read http://$o/ through Tor (HTTP 2xx, nonempty text)"; break; fi
  fi
done
rm -f "$ONION_OUTPUT"
kill $TOR
[ $OK = 1 ] || { echo "FAIL: could not read any official .onion page"; exit 1; }

echo "==== 2) ransomware.live API v2"
for path in "" recentvictims groups "searchvictims/bank" "countryvictims/JP"; do
  code=$(curl -sS -m 30 -o /tmp/rl.out -w "%{http_code} %{content_type}" "https://api.ransomware.live/v2/$path")
  echo "--- /v2/$path -> $code ($(wc -c < /tmp/rl.out) bytes)"
  head -c 700 /tmp/rl.out; echo
done

echo "==== 3) sfltool dumpbtm"
sudo sfltool dumpbtm > /tmp/btm.txt 2>&1; echo "rc=$? lines=$(wc -l < /tmp/btm.txt)"
head -90 /tmp/btm.txt

echo "==== 4) nmap deep scan (service/version detection, LAN-only guard on 127.0.0.1)"
brew install nmap > /dev/null 2>&1 || { echo "FAIL: brew install nmap"; exit 1; }
nmap --version | head -1
NMAP_OUT=$(mktemp)
if PYTHONPATH=src "$PY" -m kekkai portscan 127.0.0.1 --deep --json > "$NMAP_OUT"; then
  "$PY" - "$NMAP_OUT" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        r = json.load(f)
    ok = (isinstance(r, dict) and r.get("method") == "nmap -sV" and isinstance(r.get("open"), list))
    print("nmap method=%r open=%d" % (r.get("method"), len(r.get("open", []))))
except (OSError, ValueError) as e:
    print("parse error: %s" % e); ok = False
sys.exit(0 if ok else 1)
PY
  rc=$?
else
  echo "kekkai portscan --deep exited nonzero"; rc=1
fi
rm -f "$NMAP_OUT"
[ $rc = 0 ] && echo "PASS nmap -sV deep scan ran and parsed via KEKKAI" || { echo "FAIL: nmap deep scan"; exit 1; }
