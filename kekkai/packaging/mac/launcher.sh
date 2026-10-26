#!/bin/sh
# KEKKAI.app の起動本体（Finderでダブルクリックされると実行される）。
# プロジェクト一式はこのアプリ内（Contents/Resources/kekkai）に同梱されている。
HERE=$(cd "$(dirname "$0")" && pwd)
APP=$(cd "$HERE/../Resources/kekkai" 2>/dev/null && pwd) || {
  osascript -e 'display alert "KEKKAI" message "アプリの中身が壊れています。再ダウンロードしてください。" as critical'
  exit 1
}
cd "$APP" || exit 1

# すでに監視＋ダッシュボードが動いていれば、ブラウザで開いて終わり。
if ./kekkai open >/dev/null 2>&1; then
  exit 0
fi

# 自動起動が登録済みなら、止まっているだけなので再開を試みる（再セットアップはしない）。
PLIST="$HOME/Library/LaunchAgents/com.kekkai.monitor.plist"
if [ -f "$PLIST" ]; then
  launchctl kickstart -k "gui/$(id -u)/com.kekkai.monitor" >/dev/null 2>&1
  i=0
  while [ "$i" -lt 12 ]; do
    ./kekkai open >/dev/null 2>&1 && exit 0
    sleep 1
    i=$((i + 1))
  done
fi

# 初回（または未登録）: 進行が見えるよう Terminal でセットアップを実行する。
# セットアップはデータ取得 → 自己診断 → ログイン時の自動起動を登録 → ダッシュボードを開く。
osascript <<OSA
tell application "Terminal"
  activate
  do script "cd " & quoted form of "$APP" & " && ./kekkai setup; echo; echo '--- 完了。このウインドウは閉じて構いません。再度開くときは KEKKAI.app をダブルクリック ---'"
end tell
OSA
