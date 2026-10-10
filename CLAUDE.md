# 作業のルール（このリポジトリで動く Claude とサブエージェント向け）

このリポジトリは **公開（public）** されている。秘密情報・個人情報・非公開プロジェクトのコード・共有リンクやファイルIDは置かない、コミットしない。`git commit` / `git push` の前には `.claude/hooks/secret-scan.sh` が自動で検査する（安全網であり保証ではない）。

## 答え方
- 事実・推測・意見を分ける。推測には確度（高・中・低）と根拠を付ける。分からないことは「未確認」と書き、数字や出典を作らない。
- 出典はURLと日付つき。一次情報（公式文書・原典・実測）を優先する。「最新」「今」は確認日を書く。
- 事実を多く含む回答や調査レポートは、渡す前に `fact-checker`（数字があれば `numbers-verifier` も）で検証する。`/anthropic-skills:deep-research` のレポートも同じ。
- 不確かな見通し（集客、日程、天候、市場、人の行動、実機でしか分からないこと）は、1点ではなく幅とシナリオで示す（`/scenario`）。

## 変更のしかた
- 報告は「頼まれたこと / それ以外に変わること / 確認したこと / 確認できていないこと」に分ける（`/change-check`）。
- 頼まれていない変更や、削除・上書き・公開・共有・送信など元に戻しにくい操作は、先に内容を伝えて了承を得る。
- 一方で、一般的な正解がある細部はおすすめの案で進め、質問を増やしすぎない。聞くのは答えで作業が変わることだけ。
- コマンドを実行する前に、何をするのかを日本語で短く説明する。実行内容の説明欄（description）も日本語で書く。
- 画面や見た目に関わる作業では、デザインの確認を必ず行う（実装前は `visual-designer`、実装後は `design-qa`・`accessibility-auditor`・`ui-ux-reviewer`、配色は `/contrast-check`）。

## 誰に任せるか（重複しないように役割を分けている）
| やりたいこと | 使うもの |
|---|---|
| コードの場所を探す | 組み込みの `Explore` エージェント |
| 実装方針の設計・案の比較 | 組み込みの `Plan` エージェント |
| 作業の段取り・所要時間の幅 | `task-planner` |
| 依頼の整理（頼まれたこと・完了条件） | `requirements-analyst`（正式な仕様書は `product-management:write-spec`） |
| 一般的なWeb調査 / 時事 / API仕様 / セキュリティ情報 | `web-researcher` / `news-researcher` / `docs-researcher` / `security-researcher` |
| 選択肢の比較・選定 | `tech-comparator` |
| 不確かなことの見通し | `uncertainty-analyst`（入口は `/scenario`） |
| 複数の調査メモの統合 | `research-synthesizer`（大規模な調査は `/anthropic-skills:deep-research`） |
| 事実の検証 / 数字の検算 / 反証 | `fact-checker` / `numbers-verifier` / `red-team-reviewer` |
| 依頼外の変更の洗い出し | `scope-guardian` |
| バグのレビュー | 組み込みの `/code-review` |
| コードの脆弱性 / 秘密情報・公開範囲・配布物 | 組み込みの `/security-review` / `security-auditor` |
| Macアプリ / 音声処理 / シェル / Web / 自動化 | `swift-macos-developer` / `audio-engineer` / `shell-script-engineer` / `web-developer` / `automation-engineer` |
| テストと手動確認リスト | `test-engineer` |
| 不具合・ビルド失敗 / クラッシュログ / 重さ・発熱 | `debugger` / `crash-analyzer` / `performance-profiler` |
| 見た目の作成 / デザインの決まり / 使いやすさ / アクセシビリティ / 仕上がり確認 | `visual-designer` / `design-system-architect` / `ui-ux-reviewer` / `accessibility-auditor` / `design-qa` |
| 配布・リリース / Macへの更新スクリプト | `release-manager` / `/mac-update-script` |
| README・引き継ぎメモ | `docs-writer`（入口は `/handoff`）。共同編集のドキュメントは `docs` スキル |
| 調査から開発・確認まで通しで | `/full-cycle` |

- 互いに依存しない作業は、サブエージェントを並列で起動する。
- 詳しい一覧は `docs/AGENTS.md`。

## MCP
- `playwright`：ブラウザで表示・操作・スクリーンショット（Webの確認、モックアップの画像化）。
- `context7`：ライブラリの最新ドキュメント。クラウド環境ではネットワーク設定で `context7.com` を許可しないと使えない。使えないときは公式サイトを WebFetch で読む。
