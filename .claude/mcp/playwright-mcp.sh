#!/usr/bin/env bash
# Playwright MCP の起動ラッパー。
# - Mac など: Playwright の既定のブラウザを使う（サンドボックス有効のまま）
# - Claude Code のクラウド環境: 事前に入っている Chromium を使い、root 実行時のみ --no-sandbox を付ける
set -euo pipefail
if [ -z "${PLAYWRIGHT_MCP_EXECUTABLE_PATH:-}" ] && [ -x /opt/pw-browsers/chromium ]; then
  export PLAYWRIGHT_MCP_EXECUTABLE_PATH=/opt/pw-browsers/chromium
  if [ "$(id -u)" = "0" ]; then
    exec npx -y @playwright/mcp@0.0.83 --headless --isolated --no-sandbox "$@"
  fi
fi
exec npx -y @playwright/mcp@0.0.83 --headless --isolated "$@"
