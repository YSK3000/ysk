#!/bin/bash
# Real-machine check of the packet sensor (GitHub Actions macOS runner, passwordless sudo).
# Proves: tcpdump starts as root, the heartbeat is written on a quiet network, a real DNS lookup of a
# listed domain is detected from live en0 traffic, SIGTERM shuts down cleanly and leaves no tcpdump behind.
set -u
cd "$(dirname "$0")/.."
PY=${PY:-/usr/bin/python3}
DATA="$HOME/Library/Application Support/KEKKAI"
LOG=$(mktemp)
fail() { echo "FAIL: $*"; echo "--- sensor log"; cat "$LOG"; exit 1; }

mkdir -p "$DATA/feeds" "$DATA/sensor"
rm -f "$DATA/sensor/heartbeat" "$DATA/sensor/events.jsonl"
echo "kekkai-selftest.example.com" > "$DATA/feeds/domains-tif-mini.txt"  # fresh file: no download

sudo -E env PYTHONPATH=src "$PY" -m kekkai sensor > "$LOG" 2>&1 &
SENSOR=$!
for _ in $(seq 60); do [ -f "$DATA/sensor/heartbeat" ] && break; sleep 0.5; done
[ -f "$DATA/sensor/heartbeat" ] || fail "no heartbeat within 30s (tcpdump not capturing?)"
grep -q "を監視中" "$LOG" || fail "startup message missing (stdout not flushed?)"
echo "PASS heartbeat + startup message: $(head -1 "$LOG")"

IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
sudo tcpdump -l -n -e -tt -s 256 -i "${IFACE:-en0}" -c 3 'udp dst port 53' > "$LOG.raw" 2>/dev/null &
RAW=$!
sleep 1
"$PY" - <<'PY'
import socket
import uuid
for _ in range(3):
    try:
        socket.getaddrinfo(uuid.uuid4().hex[:12] + ".kekkai-selftest.example.com", 443)
    except OSError:
        pass
PY
for _ in $(seq 40); do grep -q dns_threat "$DATA/sensor/events.jsonl" 2>/dev/null && break; sleep 0.5; done
sudo kill "$RAW" 2>/dev/null
wait "$RAW" 2>/dev/null
echo "--- live tcpdump lines (Apple format reference)"
cat "$LOG.raw"
grep -q '"kind": "dns_threat"' "$DATA/sensor/events.jsonl" || fail "live DNS lookup of a listed domain was not detected"
echo "PASS live detection: $(grep dns_threat "$DATA/sensor/events.jsonl" | head -1)"

sudo kill -TERM "$SENSOR"
wait "$SENSOR"
RC=$?
[ "$RC" -eq 0 ] || fail "sensor exit code $RC after SIGTERM (expected a clean 0)"
sleep 1
if pgrep -x tcpdump > /dev/null; then pgrep -lx tcpdump; fail "tcpdump left running after shutdown"; fi
echo "PASS clean shutdown on SIGTERM, no tcpdump left"
echo "--- sensor log"
cat "$LOG"
