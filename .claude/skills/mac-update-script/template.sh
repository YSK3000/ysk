#!/usr/bin/env bash
# __SCRIPT_NAME__
# 内容: __SUMMARY__
#
# 使い方（Mac のターミナル）:
#   echo "<このファイルのSHA-256>  $HOME/Downloads/__SCRIPT_NAME__" | shasum -a 256 -c && bash ~/Downloads/__SCRIPT_NAME__
# 試し実行（何も変更しない）:
#   DRY_RUN=1 bash ~/Downloads/__SCRIPT_NAME__
#
# macOS 標準の bash 3.2 と BSD 版コマンドで動くように書いている。
set -euo pipefail

APP_NAME="__APP_NAME__"
TARGET_DIR="${TARGET_DIR:-__TARGET_DIR__}"
DRY_RUN="${DRY_RUN:-0}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$HOME/.update-backups/$APP_NAME/$STAMP"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/$APP_NAME-update.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

say()  { printf '%s\n' "$*"; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

# put_file <相対パス> <期待するSHA-256>  （本文は標準入力から受け取る）
# 中身をハッシュで確かめてから置き換える。既存ファイルは先にバックアップする。
put_file() {
  rel="$1"; want="$2"; dest="$TARGET_DIR/$rel"; tmp="$WORK_DIR/$(printf '%s' "$rel" | tr '/' '_')"
  cat > "$tmp"
  got="$(sha256_of "$tmp")"
  [ "$got" = "$want" ] || fail "中身の確認に失敗しました: $rel（スクリプトが壊れている可能性があります）"
  if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$want" ]; then
    say "  - $rel は適用済みです（変更なし）"; return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then say "  - [試し実行] $rel を更新します"; return 0; fi
  mkdir -p "$(dirname "$dest")" "$(dirname "$BACKUP_DIR/files/$rel")"
  if [ -f "$dest" ]; then cp -p "$dest" "$BACKUP_DIR/files/$rel"; printf '%s\n' "$rel" >> "$BACKUP_DIR/changed.txt"
  else printf '%s\n' "$rel" >> "$BACKUP_DIR/created.txt"; fi
  mv "$tmp" "$dest"
  say "  - $rel を更新しました"
}

write_rollback() {
  cat > "$BACKUP_DIR/rollback.sh" <<ROLLBACK
#!/usr/bin/env bash
# $APP_NAME の $STAMP の更新を元に戻す
set -euo pipefail
B="$BACKUP_DIR"; T="$TARGET_DIR"
if [ -f "\$B/changed.txt" ]; then while IFS= read -r f; do cp -p "\$B/files/\$f" "\$T/\$f"; echo "  - 戻しました: \$f"; done < "\$B/changed.txt"; fi
if [ -f "\$B/created.txt" ]; then while IFS= read -r f; do rm -f "\$T/\$f"; echo "  - 追加分を取り除きました: \$f"; done < "\$B/created.txt"; fi
echo "■ 元に戻しました"
ROLLBACK
}

say "■ $APP_NAME の更新を始めます"
if [ "$DRY_RUN" = "1" ]; then say "（試し実行です。ファイルは変更しません）"; fi

# 1. 前提の確認
[ -d "$TARGET_DIR" ] || fail "フォルダが見つかりません: $TARGET_DIR（TARGET_DIR=... を付けて実行すると場所を指定できます）"
# __PRECHECKS__  例: [ -f "$TARGET_DIR/Sources/main.swift" ] || fail "main.swift が見つかりません"
[ "$DRY_RUN" = "1" ] || mkdir -p "$BACKUP_DIR"

# 2. ファイルの更新（put_file を必要な数だけ並べる）
say "■ ファイルを更新します"
# __PUT_FILES__
# put_file "Sources/main.swift" "<SHA-256>" <<'__EOF_1__'
# （ファイルの中身）
# __EOF_1__
# 画像などのバイナリや、末尾に改行のないファイルは base64 で埋め込む:
# base64 --decode <<'__B64_1__' | put_file "Resources/icon.png" "<SHA-256>"
# （base64 の文字列）
# __B64_1__

# 3. 元に戻す手順を用意する
if [ "$DRY_RUN" != "1" ]; then
  if [ -f "$BACKUP_DIR/changed.txt" ] || [ -f "$BACKUP_DIR/created.txt" ]; then write_rollback
  else rm -rf "$BACKUP_DIR"; fi   # 何も変えなかったときは空のバックアップを残さない
fi

# 4. ビルド・確認（必要な場合）
# __BUILD__  例: (cd "$TARGET_DIR" && swift build -c release) || fail "ビルドに失敗しました。元に戻すには: bash \"$BACKUP_DIR/rollback.sh\""

say "■ 完了しました"
if [ -f "$BACKUP_DIR/rollback.sh" ]; then say "元に戻すには: bash \"$BACKUP_DIR/rollback.sh\""; fi
