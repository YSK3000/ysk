# ysk

Claude Code を正確・効率的に使うための設定置き場です。

- `.claude/agents/`：専門のサブエージェント 30 体（調査・検証・計画・開発・デバッグ・デザイン・運用）。一覧と重複の整理は [docs/AGENTS.md](docs/AGENTS.md)
- `.claude/skills/`：`/full-cycle`、`/change-check`、`/fact-check`、`/scenario`、`/handoff`、`/mac-update-script`、`/contrast-check`
- `.mcp.json`：Playwright（ブラウザ操作）と Context7（ライブラリの最新ドキュメント）
- `.claude/settings.json`：権限の設定と、`git commit` / `git push` 前の秘密情報チェック（`.claude/hooks/secret-scan.sh`）
- `CLAUDE.md`：答え方・変更のしかた・担当の使い分けのルール

他のプロジェクトでも使うには、Mac で次を実行します（最初は表示のみ。`--apply` で実際にコピー）。

```
bash scripts/install-user-scope.sh
bash scripts/install-user-scope.sh --apply --with-rules
```
