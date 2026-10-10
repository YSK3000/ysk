---
name: full-cycle
description: 調査 → 要件整理 → 設計 → 実装 → テスト・デバッグ → 検証 → 報告 までを、専門のサブエージェントに分担させて一気通貫で進める。大きめの開発や改修を、手戻りなく正確に進めたいときにユーザーが呼び出す。
argument-hint: "[やりたいこと]"
disable-model-invocation: true
---

# /full-cycle

やりたいこと: $ARGUMENTS

各段階の担当は `.claude/agents/` のサブエージェント。互いに依存しない作業は**並列で**起動する。ユーザーへの確認は、答えによって作業が変わる場面だけにする。自分で決められる細部は、おすすめの案で進めて報告に書く。

## 1. 理解する（並列）
- `requirements-analyst`：頼まれたこと / 暗黙に必要なこと / やらないこと / 完了の条件
- 組み込みの `Explore` エージェント：関係するコードの場所と影響範囲（既存コードがある場合）
- `docs-researcher` / `web-researcher`：使うAPI・ライブラリ・仕様の確認（必要な場合）

→ 「聞く必要があるもの」があれば、ここでまとめて1回だけ質問する。

## 2. 決める
- 組み込みの `Plan` エージェント：実装方針の案の比較と推奨、変更箇所
- `task-planner`：手順・確認方法・時間の幅・ユーザーに確認する区切り
- 重要な判断を含むなら `red-team-reviewer` で穴を確認

## 2.5 デザイン（画面や見た目に関わる場合は必須）
- `visual-designer`：実装前に2〜3案のモックアップを作り、スクリーンショットでユーザーに選んでもらう
- `design-system-architect`：既存の色・文字・部品の決まりに合わせる。新しい値はトークンとして整理する
- 配色は `/contrast-check` で計算して確かめる

## 3. 作る
内容に合う担当を使う：`swift-macos-developer`、`audio-engineer`、`shell-script-engineer`、`web-developer`、`automation-engineer`。
同時に `test-engineer` にテスト（と実機の手動確認リスト）を用意させる。

## 4. 直す（問題が出たら）
`debugger`（不具合・ビルドやCIの失敗）、`crash-analyzer`（クラッシュレポート・ログ）、`performance-profiler`（重さ・発熱）から合うものを使う。症状を隠すだけの修正はしない。

## 5. 確かめる（並列）
`/change-check` と同じ手順：`scope-guardian`（必須）、組み込みの `/code-review`、`security-auditor`、画面の変更があれば `design-qa`・`accessibility-auditor`・`ui-ux-reviewer`、必要に応じて `numbers-verifier`・`fact-checker`。🔴 の指摘は直して再確認する。

## 6. 渡す
- 配布物があれば `release-manager`（チェックサム、確認コマンド、戻し方）
- 報告：頼まれたこと / それ以外に変わること / 確認したこと / 確認できていないこと / ユーザーにやってもらうこと
- 作業が続く場合は `/handoff` の形で現状を残す
