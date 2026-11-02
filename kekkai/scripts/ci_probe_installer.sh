#!/bin/bash
# 実機macOSで、実装前に確かめる（記録のみ・一時的な計測）:
#  A) nmap 公式 macOS インストーラー（nmap.org）: 最新版の名前、署名・公証、対応CPU、入る場所、動作
#  B) macOS が実際に表示する日本語の文言（Gatekeeper の警告、「このまま開く」、ターミナル制御の確認）
set -u
W=$(mktemp -d)

echo "=== A1. nmap.org download page ==="
curl -fsSL --max-time 60 https://nmap.org/download.html -o "$W/dl.html" && echo fetched || echo "FETCH FAILED"
grep -oE 'nmap-[0-9][0-9.]*(-[0-9]+)?\.dmg' "$W/dl.html" | sort -u
grep -iE 'mac ?os|apple silicon|universal|notar|gatekeeper|unidentified' "$W/dl.html" | sed 's/<[^>]*>//g' | grep -v '^\s*$' | head -30

DMG=$(grep -oE 'nmap-[0-9][0-9.]*(-[0-9]+)?\.dmg' "$W/dl.html" | sort -uV | tail -1)
echo "DMG=$DMG"
[ -n "$DMG" ] || exit 0

echo "=== A2. download + digests ==="
curl -fsSL --max-time 300 -o "$W/$DMG" "https://nmap.org/dist/$DMG"; ls -l "$W/$DMG"
shasum -a 256 "$W/$DMG"
curl -fsSL --max-time 60 "https://nmap.org/dist/sigs/$DMG.digest.txt" | head -40
curl -fsSI --max-time 60 "https://nmap.org/dist/sigs/$DMG.asc" | head -3

echo "=== A3. dmg signature ==="
codesign -dvv "$W/$DMG" 2>&1 | head -20
spctl -a -vv -t open --context context:primary-signature "$W/$DMG" 2>&1 | head

echo "=== A4. mount + pkg signature ==="
MNT="$W/mnt"; mkdir -p "$MNT"
hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "$W/$DMG" | tail -2
ls -la "$MNT"
for p in "$MNT"/*pkg; do
  echo "PKG=$p"
  pkgutil --check-signature "$p" 2>&1
  spctl -a -vv -t install "$p" 2>&1
  ls -la "$p" 2>/dev/null | head
done

echo "=== A5. install (runner has passwordless sudo) ==="
PKG=$(ls -d "$MNT"/*pkg 2>/dev/null | head -1)
before=$(pkgutil --pkgs | sort)
sudo /usr/sbin/installer -pkg "$PKG" -target / 2>&1 | tail -5
after=$(pkgutil --pkgs | sort)
echo "new receipts:"; printf '%s\n' "$after" | comm -13 <(printf '%s\n' "$before") - 2>/dev/null || \
  for id in $after; do printf '%s\n' "$before" | grep -qx "$id" || echo "$id"; done
for id in $(pkgutil --pkgs | grep -i nmap); do echo "-- $id"; pkgutil --pkg-info "$id"; pkgutil --files "$id" | head -15; done
for b in /usr/local/bin/nmap /opt/homebrew/bin/nmap; do
  [ -x "$b" ] || continue
  echo "-- $b"; "$b" --version | head -3; lipo -archs "$b"; file "$b"
  codesign -dvv "$b" 2>&1 | grep -E 'Authority|TeamIdentifier|Signature|flags' | head -6
  xattr -l "$b"
done
echo "-- run as normal user via KEKKAI's scanner path"
/usr/local/bin/nmap -sV --version-light -T4 -Pn --top-ports 20 -oX - 127.0.0.1 2>&1 | grep -E '<port |<service|<finished' | head -10
hdiutil detach "$MNT" >/dev/null 2>&1

echo "=== B. macOS UI strings (en -> ja) ==="
sw_vers
/usr/bin/python3 - <<'PY'
import os, plistlib, subprocess
TARGETS = ["Open Anyway", "Not Opened", "Move to Trash", "could not verify", "wants access to control",
           "Privacy & Security", "cannot be opened because", "Open Anyway?"]
ROOTS = ["/System/Library/CoreServices/CoreServicesUIAgent.app",
         "/System/Library/ExtensionKit/Extensions",
         "/System/Library/PrivateFrameworks/TCC.framework",
         "/System/Library/PrivateFrameworks/SystemPolicy.framework",
         "/System/Library/CoreServices/SystemUIServer.app",
         "/System/Library/PreferencePanes/Security.prefPane"]

def load(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        p = subprocess.run(["plutil", "-convert", "xml1", "-o", "-", path], capture_output=True)
        try:
            return plistlib.loads(p.stdout)
        except Exception:
            return None

def hit(v):
    return isinstance(v, str) and any(t.lower() in v.lower() for t in TARGETS)

shown = 0
for root in ROOTS:
    for d, _dirs, files in os.walk(root):
        for fn in files:
            path = os.path.join(d, fn)
            if fn.endswith(".loctable"):
                t = load(path)
                if not isinstance(t, dict):
                    continue
                en = t.get("en") or t.get("Base") or {}
                ja = t.get("ja") or {}
                for k, v in en.items():
                    if hit(v) and shown < 120:
                        shown += 1
                        print("%s\n  key=%s\n  en=%r\n  ja=%r" % (path, k, v, ja.get(k)))
            elif fn.endswith(".strings") and os.path.basename(d) in ("en.lproj", "English.lproj", "Base.lproj"):
                t = load(path)
                if not isinstance(t, dict):
                    continue
                jap = os.path.join(os.path.dirname(d), "ja.lproj", fn)
                ja = (load(jap) if os.path.exists(jap) else None) or {}
                for k, v in t.items():
                    if hit(v) and shown < 120:
                        shown += 1
                        print("%s\n  key=%s\n  en=%r\n  ja=%r" % (path, k, v, ja.get(k)))
print("hits shown:", shown)
PY
exit 0
