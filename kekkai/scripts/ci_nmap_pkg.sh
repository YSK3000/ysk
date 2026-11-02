#!/bin/bash
# 実機確認（必須）: Homebrew の無い Mac と同じ経路で、KEKKAI が nmap.org 公式インストーラーから nmap を入れ、
# 詳細スキャン(-sV)でサービスの版まで取れること。パスワード画面は人が要るため、CI だけ sudo -n に置き換える。
set -u
cd "$(dirname "$0")/.." || exit 1
PY=/usr/bin/python3
export PYTHONPATH=src
fail() { echo "FAIL: $*"; exit 1; }

echo "==== 0) before"
$PY -c "from kekkai import tools; import json; print(json.dumps(tools.nmap_status()))"
$PY -c "from kekkai import tools; print('apple_silicon=%s rosetta_ready=%s' % (tools.apple_silicon(), tools.rosetta_ready()))"

echo "==== 1) kekkai install-nmap --method pkg (nmap.org official installer)"
OUT=$(mktemp)
KEKKAI_PRIV=sudo KEKKAI_DEBUG_CHOICES=1 $PY -m kekkai install-nmap --method pkg --yes --json | tee "$OUT"
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] || fail "install-nmap --method pkg exited $rc"

echo "==== 2) installed where KEKKAI looks, and only nmap"
$PY - <<'PY' || exit 1
from kekkai import tools
from kekkai.util import find_cmd
p = find_cmd("nmap")
print("find_cmd(nmap) =", p, "version =", tools.nmap_version(p))
assert p == "/Applications/nmap.app/Contents/MacOS/nmap", p
PY
ls -d /Applications/nmap.app /Applications/Zenmap.app /Applications/ncat.app /Applications/nping.app 2>&1
[ -e /Applications/Zenmap.app ] && fail "Zenmap.app was installed (choice changes not applied)"
[ -e /Applications/ncat.app ] && fail "ncat.app was installed (choice changes not applied)"
file /Applications/nmap.app/Contents/MacOS/nmap /Applications/nmap.app/Contents/Resources/bin/nmap
echo "--- launcher script (record)"; cat /Applications/nmap.app/Contents/MacOS/nmap
ls /Applications/nmap.app/Contents/Resources /Applications/nmap.app/Contents/Resources/share 2>&1 | head -20
$PY -c "from kekkai.discovery.nmap import command; print('command() ->', command())"
echo "--- --top-ports on this build (record only)"
ls /Applications/nmap.app/Contents/Resources/share/nmap | head -12
B=/Applications/nmap.app/Contents/Resources
for n in 20 200; do
  DYLD_LIBRARY_PATH=$B/lib NMAPDIR=$B/share/nmap $B/bin/nmap -Pn --top-ports $n -oX - -- 127.0.0.1 2>&1 | grep -E 'top-ports|<finished|scaninfo' | head -3
done
DYLD_LIBRARY_PATH=$B/lib NMAPDIR=$B/share/nmap $B/bin/nmap -d -Pn --top-ports 20 -- 127.0.0.1 2>&1 | head -12

echo "==== 3) deep scan with the installed nmap finds a real service and its version"
$PY -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
HTTP=$!
sleep 2
SCAN=$(mktemp)
$PY -m kekkai portscan 127.0.0.1 --deep --json > "$SCAN"; src=$?
kill $HTTP 2>/dev/null
[ $src = 0 ] || { cat "$SCAN"; fail "portscan --deep exited $src"; }
$PY - "$SCAN" <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
web = [p for p in r.get("open", []) if p.get("port") == 8080]
print("method=%s open=%s" % (r.get("method"), [(p["port"], p.get("product"), p.get("version")) for p in r.get("open", [])]))
assert r.get("method") == "nmap -sV", r.get("method")
assert web and web[0].get("product"), "8080 found without product/version: %r" % web
print("PASS nmap.org nmap identified %s %s on 8080" % (web[0].get("product"), web[0].get("version")))
PY

echo "==== 4) the administrator dialog script: argument quoting at runtime, and syntax of the admin form"
$PY - <<'PY' || exit 1
import subprocess
from kekkai import tools
cmd = tools.osascript_cmd([["/bin/echo", "a b"], ["/bin/echo", "x'y \"z\" $HOME"]], admin=False)
p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
out = p.stdout.replace("\r", "\n").strip().splitlines()
print("rc=%s out=%r err=%r" % (p.returncode, out, p.stderr.strip()))
assert p.returncode == 0 and out == ["a b", "x'y \"z\" $HOME"], out
admin = tools.osascript_cmd([["/usr/sbin/installer", "-pkg", "/tmp/x.pkg", "-target", "/"]])
lines = [admin[i + 1] for i, a in enumerate(admin) if a == "-e"]
c = subprocess.run(["/usr/bin/osacompile", "-o", "/tmp/kekkai-admin.scpt"] + sum((["-e", x] for x in lines), []),
                   capture_output=True, text=True, timeout=30)
print("osacompile rc=%s %s" % (c.returncode, c.stderr.strip()))
assert c.returncode == 0
print("PASS osascript quoting and admin script syntax")
PY

echo "==== 5) record: macOS UI strings around Gatekeeper / Open Anyway / automation consent"
$PY - <<'PY'
import plistlib
FILES = {
    "/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/Resources/Quarantine.loctable": ("BUTTON",),
    "/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/Resources/QuarantineHeadlines.loctable": ("CASPIAN", "UNVERIFIED", "NOT_VERIFIED"),
    "/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/Resources/CodeEvaluation.loctable": ("",),
    "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/Localizable.loctable": ("BUTTON", "ALLOW", "DENY", "OK_"),
}
for path, keys in FILES.items():
    try:
        t = plistlib.load(open(path, "rb"))
    except Exception as e:
        print(path, "unreadable", e); continue
    en, ja = t.get("en") or {}, t.get("ja") or {}
    print("--", path)
    n = 0
    for k in sorted(en):
        if any(x in k for x in keys) and n < 40:
            n += 1
            print("  %s | en=%r | ja=%r" % (k, en[k], ja.get(k)))
ext = "/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/Contents/Resources/Localizable.loctable"
t = plistlib.load(open(ext, "rb"))
en, ja = t.get("en") or {}, t.get("ja") or {}
print("--", ext)
for k, v in sorted(en.items()):
    if isinstance(v, str) and (v in ("Security", "Open Anyway", "Open", "Done", "Cancel") or "was blocked" in v or "blocked to protect" in v):
        print("  %s | en=%r | ja=%r" % (k, v, ja.get(k)))
PY
echo "PASS nmap.org installer route"
