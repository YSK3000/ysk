import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../src/kekkai/web/js/health.js', import.meta.url), 'utf8');
const { monitorView } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
assert.equal(monitorView(null, true).live, false);
const base = {monitoring: {status: 'live', label: '実監視中', last_success: 1000, stale_after_sec: 45}, cycle: 2, feeds_entries: 0, geo: {}};
assert.equal(monitorView(base, true, 1001000).live, true);
assert.match(monitorView(base, true, 1001000).detail, /脅威リスト未取得/);
assert.equal(monitorView(base, false, 1001000).live, false);
assert.equal(monitorView(base, true, 1100000).label, '更新停止');
assert.equal(monitorView({...base, monitoring: {...base.monitoring, status: 'error', errors: {connections: 'permission denied'}}}, true).label, '収集エラー');
assert.equal(monitorView({...base, monitoring: {...base.monitoring, status: 'stopped'}}, true).live, false);
console.log('UI monitoring states: 7 checks passed');
