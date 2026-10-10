#!/usr/bin/env bash
# PreToolUse フック: git commit / git push の前に、秘密情報らしきものが含まれていないか調べる。
# このリポジトリは公開されているため、うっかり混入を防ぐ安全網として置いている（完全な保証ではない）。
#
# - 調べる範囲: commit なら「ステージ済み＋未ステージの追跡ファイルの差分」、push なら「まだどのリモートにもないコミット」
# - 見つかったら終了コード 2 でコマンドを止め、理由を標準エラーに出す（Claude に伝わる）
# - 誤検知でユーザーが明示的に許可した場合だけ、コマンドの先頭に SECRET_SCAN_ALLOW=1 を付けて再実行する
# - macOS 標準の bash 3.2 と BSD 版 grep で動くように書いている

input=$(cat)

# Bash ツールの command 文字列を取り出す（JSON を厳密に解析せず、必要な部分だけ見る）
cmd=$(printf '%s' "$input" | grep -Eo '"command"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"' | head -n 1)
case "$cmd" in
  *SECRET_SCAN_ALLOW=1*) exit 0 ;;
  *git*commit*) mode=commit ;;
  *git*push*) mode=push ;;
  *) exit 0 ;;
esac

cwd=$(printf '%s' "$input" | grep -Eo '"cwd"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"' | head -n 1 | sed -E 's/^"cwd"[[:space:]]*:[[:space:]]*"//; s/"$//')
if [ -n "$cwd" ] && [ -d "$cwd" ]; then cd "$cwd" || exit 0; fi
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

self_path='.claude/hooks/secret-scan.sh'
if [ "$mode" = commit ]; then
  diff_text=$( { git diff --cached -- . ":(exclude)$self_path"; git diff -- . ":(exclude)$self_path"; } 2>/dev/null )
  names=$( { git diff --cached --name-only; git diff --name-only; } 2>/dev/null | sort -u )
else
  diff_text=$(git log -p --branches --not --remotes -- . ":(exclude)$self_path" 2>/dev/null)
  names=$(git log --name-only --format= --branches --not --remotes 2>/dev/null | sort -u)
fi

findings=""
add() { findings="${findings}  - $1
"; }

# 1. 追加された行に含まれる、典型的な鍵・トークンの形
added=$(printf '%s\n' "$diff_text" | grep -E '^\+' | grep -Ev '^\+\+\+ ')
check() {  # check <名前> <正規表現>
  hit=$(printf '%s\n' "$added" | grep -Eo -- "$2" | head -n 1)
  if [ -n "$hit" ]; then add "$1（${hit:0:6}…）"; fi
}
check "秘密鍵"                 '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
check "AWS アクセスキー"        '(AKIA|ASIA)[0-9A-Z]{16}'
check "GitHub トークン"         '(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})'
check "Anthropic API キー"      'sk-ant-[A-Za-z0-9_-]{20,}'
check "OpenAI 形式の API キー"  '(^|[^A-Za-z0-9_-])sk-(proj-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{40,})'
check "Slack トークン"          'xox[abprs]-[A-Za-z0-9-]{10,}'
check "Google API キー"         'AIza[0-9A-Za-z_-]{35}'
check "Google OAuth トークン"   'ya29\.[0-9A-Za-z_-]{20,}'
check "Stripe 本番キー"         '(^|[^A-Za-z0-9])(sk|rk)_live_[0-9A-Za-z]{20,}'
check "GitLab トークン"         'glpat-[A-Za-z0-9_-]{20,}'

# 2. 秘密情報を入れがちなファイル名
printf '%s\n' "$names" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  base=${f##*/}
  case "$base" in
    .env.example|.env.sample|.env.template) ;;
    .env|.env.*|*.pem|*.p12|*.pfx|*.p8|*.key|*.keystore|*.jks|id_rsa*|id_ed25519*|id_ecdsa*|.credentials.json|credentials.json|service-account*.json|.netrc|.npmrc|.pypirc)
      printf '  - 秘密情報を含みやすいファイル: %s\n' "$f" ;;
  esac
done > "${TMPDIR:-/tmp}/secret-scan-names.$$"
findings="${findings}$(cat "${TMPDIR:-/tmp}/secret-scan-names.$$")"
rm -f "${TMPDIR:-/tmp}/secret-scan-names.$$"

if [ -n "$(printf '%s' "$findings" | tr -d '[:space:]')" ]; then
  {
    echo "git $mode を止めました。秘密情報らしきものが含まれています（このリポジトリは公開されています）:"
    printf '%s\n' "$findings"
    echo "対応: 該当箇所を取り除くか .gitignore に入れてから、やり直してください。"
    echo "誤検知の場合は、ユーザーに確認して明示的な許可を得たときだけ、コマンドの先頭に SECRET_SCAN_ALLOW=1 を付けて再実行してください。"
  } >&2
  exit 2
fi
exit 0
