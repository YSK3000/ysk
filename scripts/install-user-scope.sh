#!/usr/bin/env bash
# このリポジトリのサブエージェントとスキルを、ユーザー全体（~/.claude）にコピーする。
# コピーすると、Mac の別のプロジェクト（このリポジトリ以外）でも同じ担当とスキルが使える。
#
# 使い方:
#   bash scripts/install-user-scope.sh              # 何が起きるかを表示するだけ（変更しない）
#   bash scripts/install-user-scope.sh --apply      # 実際にコピーする（同名のファイルがあれば飛ばす）
#   bash scripts/install-user-scope.sh --apply --force       # 同名のファイルはバックアップしてから上書き
#   bash scripts/install-user-scope.sh --apply --with-rules  # CLAUDE.md の「答え方」「変更のしかた」も ~/.claude/CLAUDE.md に追記
#
# macOS 標準の bash 3.2 で動くように書いている。
set -euo pipefail

APPLY=0; FORCE=0; RULES=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --force) FORCE=1 ;;
    --with-rules) RULES=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "不明なオプション: $arg" >&2; exit 2 ;;
  esac
done

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
BACKUP="$DEST/backups/ysk-install-$(date +%Y%m%d-%H%M%S)"

say() { printf '%s\n' "$*"; }

# copy_one <コピー元> <コピー先>
copy_one() {
  src="$1"; dst="$2"; rel="${dst#$DEST/}"
  if [ -e "$dst" ]; then
    if cmp -s "$src" "$dst"; then return 0; fi   # 同じ内容なら何もしない
    if [ "$FORCE" != 1 ]; then say "  - そのまま（同名で内容が違う。上書きは --force）: $rel"; return 0; fi
    if [ "$APPLY" = 1 ]; then mkdir -p "$(dirname "$BACKUP/$rel")"; cp -p "$dst" "$BACKUP/$rel"; fi
    say "  - 上書き（バックアップあり）: $rel"
  else
    say "  - 追加: $rel"
  fi
  if [ "$APPLY" = 1 ]; then mkdir -p "$(dirname "$dst")"; cp -p "$src" "$dst"; fi
}

[ "$APPLY" = 1 ] || say "（表示のみ。実際にコピーするには --apply を付けてください）"
say "■ コピー先: $DEST"

say "■ サブエージェント"
find "$SRC/.claude/agents" -type f -name '*.md' | sort | while IFS= read -r f; do
  copy_one "$f" "$DEST/agents/${f#$SRC/.claude/agents/}"
done

say "■ スキル"
find "$SRC/.claude/skills" -type f | sort | while IFS= read -r f; do
  copy_one "$f" "$DEST/skills/${f#$SRC/.claude/skills/}"
done
if [ "$APPLY" = 1 ]; then chmod +x "$DEST/skills/mac-update-script/template.sh" 2>/dev/null || true; fi

if [ "$RULES" = 1 ]; then
  say "■ ルール（~/.claude/CLAUDE.md）"
  target="$DEST/CLAUDE.md"
  if [ -f "$target" ] && grep -q 'ysk-rules:start' "$target"; then
    say "  - 追記済みのため、そのまま"
  else
    say "  - 「答え方」「変更のしかた」を追記"
    if [ "$APPLY" = 1 ]; then
      if [ -f "$target" ]; then mkdir -p "$BACKUP"; cp -p "$target" "$BACKUP/CLAUDE.md"; fi
      {
        printf '\n<!-- ysk-rules:start (scripts/install-user-scope.sh が追記) -->\n'
        awk '/^## 答え方/{p=1} /^## 誰に任せるか/{p=0} p' "$SRC/CLAUDE.md"
        printf '<!-- ysk-rules:end -->\n'
      } >> "$target"
    fi
  fi
fi

say "■ MCP サーバー（必要なら手動で追加。Node.js が必要）"
say "  claude mcp add --scope user context7 -- npx -y @upstash/context7-mcp@4.3.0"
say "  claude mcp add --scope user playwright -- npx -y @playwright/mcp@0.0.83 --headless --isolated"
if [ "$APPLY" = 1 ] && [ -d "$BACKUP" ]; then say "■ バックアップ: $BACKUP"; fi
say "■ 完了しました"
