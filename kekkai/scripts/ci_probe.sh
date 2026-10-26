#!/bin/bash
# 実機（GitHub Actions の macOS）で、実装前に「本物の挙動」を測る。
#  1) Tor: 公式の tor を入れて起動し、Tor Project 公式の onion 一覧にある .onion を KEKKAI で読めるか（必須）
#  2) ransomware.live API v2 の実際の応答（記録のみ）
#  3) sfltool dumpbtm の実際の出力（ログイン項目の監視の準備、記録のみ）
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
for o in $ONIONS; do
  if PYTHONPATH=src $PY -m kekkai onion "http://$o/" | head -3; then OK=1; echo "PASS read http://$o/ through Tor"; break; fi
done
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
