#!/bin/sh
# KEKKAI.app を作る。プロジェクト一式をアプリ内に同梱するので、
# できあがった KEKKAI.app を /Applications に置けば、ダブルクリックだけで監視が始まる。
# 使い方:  kekkai/ の中で  sh scripts/build_app.sh  （出力先は任意: sh scripts/build_app.sh dist）
set -eu
SRC=$(cd "$(dirname "$0")/.." && pwd)        # kekkai/ の絶対パス
OUT=${1:-"$SRC/dist"}
APP="$OUT/KEKKAI.app"
RES="$APP/Contents/Resources/kekkai"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RES"

cp "$SRC/packaging/mac/Info.plist" "$APP/Contents/Info.plist"
cp "$SRC/packaging/mac/launcher.sh" "$APP/Contents/MacOS/KEKKAI"
chmod 755 "$APP/Contents/MacOS/KEKKAI"

# 実行に必要なものだけ同梱（キャッシュ・テスト・.git は入れない）。
cp "$SRC/kekkai" "$RES/kekkai"; chmod 755 "$RES/kekkai"
cp "$SRC/KEKKAI.command" "$RES/KEKKAI.command"; chmod 755 "$RES/KEKKAI.command"
cp "$SRC/README.md" "$SRC/THIRD_PARTY_NOTICES.md" "$SRC/pyproject.toml" "$RES/"
# src/ を __pycache__ 抜きで丸ごと（Web画面・world.json などの資産を含む）。
# tar 経由なら GNU/BSD どちらの tar でも、空白を含むパスも安全にコピーできる。
( cd "$SRC" && tar cf - --exclude='__pycache__' --exclude='*.pyc' src ) | ( cd "$RES" && tar xf - )

echo "built: $APP"
