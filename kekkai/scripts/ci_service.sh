#!/bin/bash
# 実機（GitHub Actions の macOS）で、普段使いの常駐構成をそのまま確認する。
#  1) ./kekkai install-agent      → ダッシュボード付きの監視が自動で起動し、解除で止まる
#  2) sudo ./kekkai install-sensor → root 所有のコピーで常駐し、実際のDNS問い合わせを検知し、解除で後片付けされる
set -u
cd "$(dirname "$0")/.."
PY=/usr/bin/python3
STATE="/Library/Application Support/KEKKAI Sensor"
fail() {
  echo "FAIL: $*"
  for f in /Library/Logs/kekkai-sensor.log "$HOME/Library/Logs/kekkai.log"; do [ -f "$f" ] && { echo "--- $f"; tail -20 "$f"; }; done
  exit 1
}
alive() { $PY -c "import sys; sys.path.insert(0, 'src'); from kekkai import server; sys.exit(0 if server.session_alive() else 1)"; }

# ---- 1) 自動起動（LaunchAgent）
./kekkai install-agent || fail "install-agent"
for _ in $(seq 60); do alive && break; sleep 0.5; done
$PY - <<'PY' || fail "auto-started dashboard did not answer"
import json, sys, urllib.request
sys.path.insert(0, "src")
from kekkai import paths
s = json.load(open(str(paths.sub("session.json"))))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
req = urllib.request.Request("http://127.0.0.1:%d/api/summary" % s["port"], headers={"Authorization": "Bearer " + s["token"]})
with opener.open(req, timeout=5) as r:
    body = json.load(r)
print("PASS auto-started dashboard answers: HTTP %d, threat=%s" % (r.status, body["threat"]["label"]))
PY
./kekkai uninstall-agent || fail "uninstall-agent"
for _ in $(seq 20); do alive || break; sleep 0.5; done
alive && fail "dashboard still running after uninstall-agent"
echo "PASS uninstall-agent stopped the dashboard"

# ---- 2) 常時パケット監視（LaunchDaemon）
sudo mkdir -p "$STATE"
echo "kekkai-selftest.example.com" | sudo tee "$STATE/domains-tif-mini.txt" > /dev/null  # fresh list: no download
sudo ./kekkai install-sensor || fail "install-sensor"
[ "$(stat -f %Su "$STATE/code/kekkai/sensor.py")" = root ] || fail "daemon code is not root-owned"
[ "$(stat -f %Lp "$STATE")" = 755 ] || fail "state dir must be 755"
grep -q "を監視中" /Library/Logs/kekkai-sensor.log || fail "startup line missing in the daemon log"
echo "PASS daemon runs a root-owned copy: $(head -1 /Library/Logs/kekkai-sensor.log)"
$PY - <<'PY'
import socket
import uuid
for _ in range(3):
    try:
        socket.getaddrinfo(uuid.uuid4().hex[:12] + ".kekkai-selftest.example.com", 443)
    except OSError:
        pass
PY
for _ in $(seq 40); do grep -q dns_threat "$STATE/events.jsonl" 2>/dev/null && break; sleep 0.5; done
grep -q '"kind": "dns_threat"' "$STATE/events.jsonl" || fail "daemon did not detect the live DNS lookup"
echo "PASS live detection by the daemon: $(grep -c dns_threat "$STATE/events.jsonl") events"
./kekkai doctor --quick | grep "パケットセンサー" | tee /dev/stderr | grep -q "監視中" || fail "doctor does not see the running sensor"
sudo ./kekkai uninstall-sensor || fail "uninstall-sensor"
sleep 1
if pgrep -x tcpdump > /dev/null; then pgrep -lx tcpdump; fail "tcpdump left running"; fi
[ -e /Library/LaunchDaemons/com.kekkai.sensor.plist ] && fail "daemon plist left behind"
[ -e "$STATE" ] && fail "state dir left behind"
echo "PASS uninstall-sensor removed the daemon, its files and tcpdump"
