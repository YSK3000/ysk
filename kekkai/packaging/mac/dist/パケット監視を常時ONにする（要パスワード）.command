#!/bin/sh
HERE=$(cd "$(dirname "$0")" && pwd)
for A in "$HERE/KEKKAI.app" "/Applications/KEKKAI.app" "$HOME/Applications/KEKKAI.app" "$HOME/Downloads/KEKKAI.app"; do
  if [ -d "$A/Contents/Resources/kekkai" ]; then APP="$A/Contents/Resources/kekkai"; break; fi
done
[ -z "${APP:-}" ] && { echo "KEKKAI.app が見つかりません。アプリケーションに置いてください。"; exit 1; }
cd "$APP" || exit 1
echo "常時パケット監視を有効化します。パスワードを入力してください（表示されません）。"
sudo ./kekkai install-sensor
echo; echo "--- 完了。閉じて構いません ---"
