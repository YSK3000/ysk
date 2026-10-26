// Derive UI state from real collection freshness, independently of the SSE socket.
export function monitorView(summary, reachable, now = Date.now()) {
  const m = summary?.monitoring;
  if (!reachable) return { live: false, label: "接続確認中", detail: "監視サーバーへの接続を確認しています" };
  if (!m) return { live: false, label: "初回収集中", detail: "収集結果が届くまで判定を保留します" };
  const age = m.last_success == null ? null : Math.max(0, now / 1000 - m.last_success);
  const errors = Object.values(m.errors || {}).join(" / ");
  if (m.status === "error") return { live: false, label: "収集エラー", detail: errors || "最新の通信を取得できていません" };
  if (m.status === "stopped") return { live: false, label: "監視停止", detail: "監視プロセスが停止しています" };
  if (age != null && age > (m.stale_after_sec || 45))
    return { live: false, label: "更新停止", detail: `最終収集から ${Math.floor(age)} 秒。表示は前回の記録です` };
  if (m.status !== "live") return { live: false, label: m.label || "確認中", detail: "有効なネットワークと通信情報を確認しています" };
  const parts = [`最終収集 ${Math.floor(age || 0)} 秒前`, `更新 ${summary.cycle || 0} 回`];
  if (!summary.feeds_entries) parts.push("脅威リスト未取得：リスト照合は利用できません");
  if (!summary.geo?.city) parts.push("位置情報DB未取得：IP・プロセスの監視は継続");
  return { live: true, label: "実監視中", detail: parts.join(" ｜ ") };
}
