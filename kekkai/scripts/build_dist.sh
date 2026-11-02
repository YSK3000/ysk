#!/bin/sh
# 配布用 zip を作る: KEKKAI.app ＋ はじめにお読みください.txt ＋ パケット監視の ON/OFF 用 .command。
# 使い方:  kekkai/ の中で  sh scripts/build_dist.sh  →  dist/KEKKAI-mac.zip
# zip は Python 標準の zipfile で作り、実行権限（755）を保ったまま格納する（Mac の「アーカイブユーティリティ」で解凍可）。
set -eu
SRC=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$SRC/dist"}
STAGE="$OUT/KEKKAI-mac"
rm -rf "$STAGE" "$OUT/KEKKAI-mac.zip"
mkdir -p "$STAGE"
sh "$SRC/scripts/build_app.sh" "$STAGE" >/dev/null
VERSION=$(PYTHONPATH="$SRC/src" python3 -c "import kekkai; print(kekkai.__version__)")
sed "s/@VERSION@/$VERSION/" "$SRC/packaging/mac/dist/はじめにお読みください.txt" > "$STAGE/はじめにお読みください.txt"
for f in "$SRC"/packaging/mac/dist/*.command; do
  cp "$f" "$STAGE/"
  chmod 755 "$STAGE/$(basename "$f")"
done
python3 - "$OUT" <<'PY'
import os, stat, sys, zipfile
out = sys.argv[1]
os.chdir(out)
n = x = 0
with zipfile.ZipFile("KEKKAI-mac.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for d, dirs, files in os.walk("KEKKAI-mac"):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            if "__pycache__" in p or f.endswith(".pyc") or f == ".DS_Store":
                continue
            mode = stat.S_IMODE(os.stat(p).st_mode)
            zi = zipfile.ZipInfo.from_file(p, p)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            zi.external_attr = (mode | stat.S_IFREG) << 16
            with open(p, "rb") as fh:
                z.writestr(zi, fh.read())
            n += 1
            x += bool(mode & 0o111)
with zipfile.ZipFile("KEKKAI-mac.zip") as z:
    assert z.testzip() is None
print("built: %s/KEKKAI-mac.zip (%d files, %d executable)" % (out, n, x))
PY
