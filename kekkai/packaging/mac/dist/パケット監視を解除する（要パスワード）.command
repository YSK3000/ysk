#!/bin/sh
HERE=$(cd "$(dirname "$0")" && pwd)
for A in "$HERE/KEKKAI.app" "/Applications/KEKKAI.app" "$HOME/Applications/KEKKAI.app" "$HOME/Downloads/KEKKAI.app"; do
  if [ -d "$A/Contents/Resources/kekkai" ]; then APP="$A/Contents/Resources/kekkai"; break; fi
done
[ -z "${APP:-}" ] && { echo "KEKKAI.app が見つかりません。"; exit 1; }
cd "$APP" || exit 1
sudo ./kekkai uninstall-sensor
echo; echo "--- 解除しました。閉じて構いません ---"
