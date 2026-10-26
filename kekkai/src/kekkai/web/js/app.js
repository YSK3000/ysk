// KEKKAI dashboard. Vanilla ES modules, no build step, CSP-safe (no inline script, no innerHTML for data).
import { h, s, add, clear, api, post, icon, emblem, flag, clock, datetime, ago, trunc, sevBadge, SEV_JA, RISK_ORDER, debounce } from "./util.js";
import { WorldMap, nodesFromConnections } from "./worldmap.js";
import { LanMap, deviceName, deviceStatus } from "./lanmap.js";

const KIND_JA = {
  router: "ルーター", this: "このMac", computer: "PC", phone: "スマホ/タブレット", apple: "Apple機器", media: "AirPlay/メディア",
  tv: "テレビ/ストリーミング", speaker: "スマートスピーカー", printer: "プリンター", nas: "NAS/共有", camera: "カメラ",
  iot: "IoT/スマート家電", game: "ゲーム機", network: "ネットワーク機器", unknown: "不明",
};
const LEVELS = { 0: ["CHECKING", "確認中"], 1: ["SECURE", "安全"], 2: ["GUARDED", "注意"], 3: ["ELEVATED", "警戒"], 4: ["HIGH", "高"], 5: ["CRITICAL", "危険"] };
const STATUS_JA = { pass: "合格", warn: "要確認", fail: "要対策", info: "情報", unknown: "不明" };
const CAT_JA = { system: "システム", network: "ネットワーク", sharing: "共有・公開", update: "アップデート", persistence: "自動起動" };

const VIEWS = [
  { id: "command", label: "概要", en: "COMMAND", icon: "command" },
  { id: "geo", label: "世界地図", en: "GEO MAP", icon: "geo" },
  { id: "lan", label: "LANマップ", en: "LAN MAP", icon: "lan" },
  { id: "traffic", label: "通信", en: "TRAFFIC", icon: "traffic" },
  { id: "alerts", label: "アラート", en: "ALERTS", icon: "alerts" },
  { id: "audit", label: "診断", en: "AUDIT", icon: "audit" },
  { id: "exposure", label: "外部露出", en: "EXPOSURE", icon: "exposure" },
  { id: "intel", label: "脅威情報", en: "INTEL", icon: "intel" },
];

const S = {
  summary: null, conns: [], listeners: [], devices: [], network: null, lan: null, alerts: [], threat: null,
  posture: null, wifi: null, persistence: [], exposure: null, upnp: null, intel: null, ai: null, doctor: null,
  history: [], view: null, selectedMac: null, alertFilter: "active", trafficFilter: "internet", trafficQuery: "",
  geoHistory: false, geoRiskOnly: false, sse: false, lastConnFetch: 0, lastDevFetch: 0, aiBusy: {}, jobs: {},
};

const UI = {};
let current = null;

// ------------------------------------------------------------------ shell
function shell() {
  const app = document.getElementById("app");
  clear(app);
  UI.live = h("span", { class: "live-dot" });
  UI.liveText = h("span", { class: "live-text" }, "CONNECTING");
  UI.net = h("div", { class: "net-chip" });
  UI.threat = h("div", { class: "threat-meter", title: "脅威レベル" });
  UI.clock = h("div", { class: "clock" }, clock());
  const top = h("header", { class: "topbar" },
    h("a", { class: "brand", href: "#command", "aria-label": "KEKKAI 概要へ" }, emblem(34),
      h("div", { class: "brand-text" }, h("div", { class: "brand-title" }, h("span", { class: "kanji" }, "結界"), " KEKKAI"),
        h("div", { class: "brand-sub" }, "HOME NETWORK DEFENSE GRID"))),
    h("div", { class: "top-mid" }, h("div", { class: "live" }, UI.live, UI.liveText), UI.net),
    h("div", { class: "top-right" }, UI.threat, UI.clock));
  UI.nav = h("nav", { class: "sidenav", "aria-label": "表示切替" },
    VIEWS.map((v, i) => h("a", { href: `#${v.id}`, class: "nav-item", dataset: { view: v.id }, title: `${v.label} (${i + 1})` },
      icon(v.icon), h("span", { class: "nav-ja" }, v.label), h("span", { class: "nav-en" }, v.en),
      v.id === "alerts" ? (UI.navBadge = h("span", { class: "nav-badge", hidden: true })) : null)));
  UI.main = h("main", { class: "main", id: "main", tabindex: -1 });
  UI.toasts = h("div", { class: "toasts", "aria-live": "polite" });
  UI.drawer = h("aside", { class: "drawer", "aria-hidden": "true" });
  UI.scrim = h("div", { class: "scrim", onclick: closeDrawer });
  UI.locked = h("div", { class: "locked-overlay", hidden: true },
    h("div", { class: "panel locked-box" }, icon("lock", "big"), h("h2", null, "セッションが無効です"),
      h("p", null, "ターミナルに表示されたURLを開くか、", h("code", null, "./kekkai open"), " を実行してください。")));
  add(app, top, h("div", { class: "body" }, UI.nav, UI.main), UI.toasts, UI.scrim, UI.drawer, UI.locked);
  setInterval(() => { UI.clock.textContent = clock(); }, 1000);
}

function renderTop() {
  const sm = S.summary;
  if (!sm) return;
  const n = sm.network || {};
  clear(UI.net);
  add(UI.net, 
    h("span", { class: "net-label" }, n.label || (n.trusted ? "自宅" : "未登録ネットワーク")),
    h("span", { class: "net-detail" }, [n.ssid, n.subnet || n.ip].filter(Boolean).join(" · ") || "ネットワーク未接続"),
    n.vpn_active ? h("span", { class: "chip chip-violet" }, "VPN") : null,
    n.learning ? h("span", { class: "chip chip-amber" }, "学習中") : null,
    n.id && !n.trusted ? h("span", { class: "chip chip-amber" }, "外出先") : null,
    sm.sensor && sm.sensor.active ? h("span", { class: "chip chip-mint" }, "SENSOR") : null);
  const t = sm.threat || { level: 0, label: "CHECKING", counts: {} };
  S.threat = t;
  clear(UI.threat);
  UI.threat.className = `threat-meter lvl-${t.level}`;
  add(UI.threat, h("span", { class: "tm-label" }, "THREAT"),
    h("span", { class: "tm-bars" }, [1, 2, 3, 4, 5].map((i) => h("i", { class: i <= t.level ? "on" : "" }))),
    h("span", { class: "tm-name" }, LEVELS[t.level][0]), h("span", { class: "tm-ja" }, LEVELS[t.level][1]));
  const open = Object.values(t.counts || {}).reduce((a, b) => a + b, 0);
  UI.navBadge.hidden = !open;
  UI.navBadge.textContent = open > 99 ? "99+" : String(open);
}

function setLive(on, text) {
  S.sse = on;
  UI.live.classList.toggle("on", on);
  UI.liveText.textContent = text || (on ? "LIVE" : "OFFLINE");
}

// ------------------------------------------------------------------ data
async function loadSummary() { S.summary = await api("/api/summary"); renderTop(); }
async function loadConns() {
  const r = await api("/api/connections");
  S.conns = r.connections || []; S.listeners = r.listeners || []; S.lastConnFetch = Date.now();
}
async function loadDevices() {
  const r = await api("/api/devices");
  S.devices = r.devices || []; S.network = r.network; S.lan = r.lan; S.lastDevFetch = Date.now();
}
async function loadAlerts() {
  const r = await api(`/api/alerts?status=${S.alertFilter}`);
  S.alerts = r.alerts || []; S.threat = r.threat;
  if (S.alertFilter !== "active") S.activeAlerts = (await api("/api/alerts?status=active")).alerts || [];
  else S.activeAlerts = S.alerts;
}
async function loadPosture() { const r = await api("/api/posture"); Object.assign(S, { posture: r.posture, wifi: r.wifi, persistence: r.persistence || [], listeners: r.listeners || S.listeners }); }
async function loadExposure() { const r = await api("/api/exposure"); S.exposure = r.exposure; S.upnp = r.upnp; }
async function loadIntel() { S.intel = await api("/api/intel"); S.ai = await api("/api/ai/status").catch(() => null); }
async function loadHistory() { S.history = (await api("/api/destinations?hours=24")).destinations || []; }

const LOADERS = { conns: loadConns, devices: loadDevices, alerts: loadAlerts, posture: loadPosture, exposure: loadExposure,
                  intel: loadIntel, history: loadHistory };

async function refresh(keys) {
  await Promise.all(keys.map((k) => LOADERS[k]().catch((e) => console.warn("load", k, e))));
}

// ------------------------------------------------------------------ building blocks
function panel(en, ja, opts = {}) {
  const actions = h("div", { class: "panel-actions" });
  const body = h("div", { class: ["panel-b", opts.bodyCls] });
  const el = h("section", { class: ["panel", opts.cls] },
    h("header", { class: "panel-h" }, h("span", { class: "ph-en" }, en), ja ? h("span", { class: "ph-ja" }, ja) : null, actions), body);
  return { el, body, actions };
}

function button(label, opts = {}) {
  return h("button", { class: ["btn", opts.cls], type: "button", onclick: opts.onclick, disabled: opts.disabled, title: opts.title },
    opts.icon ? icon(opts.icon) : null, label);
}

function chips(options, value, onpick) {
  return h("div", { class: "chips", role: "tablist" }, options.map(([v, label]) =>
    h("button", { class: ["chip-btn", v === value && "on"], type: "button", role: "tab", "aria-selected": v === value ? "true" : "false",
                  onclick: () => onpick(v) }, label)));
}

function empty(text, sub) {
  return h("div", { class: "empty" }, h("div", { class: "empty-t" }, text), sub ? h("div", { class: "empty-s" }, sub) : null);
}

function kv(rows) {
  return h("dl", { class: "kv" }, rows.filter((r) => r && r[1] !== undefined && r[1] !== null && r[1] !== "").map(([k, v]) =>
    [h("dt", null, k), h("dd", null, v)]));
}

function toast(alert) {
  const el = h("div", { class: ["toast", `sev-b-${alert.severity}`], role: "status",
                         onclick: () => { location.hash = "#alerts"; el.remove(); } },
    sevBadge(alert.severity), h("div", { class: "toast-t" }, alert.title), h("div", { class: "toast-s" }, trunc(alert.detail, 120)));
  UI.toasts.appendChild(el);
  setTimeout(() => el.classList.add("out"), 7500);
  setTimeout(() => el.remove(), 8200);
}

function openDrawer(title, content) {
  clear(UI.drawer);
  add(UI.drawer, h("header", { class: "drawer-h" }, h("h2", null, title),
    h("button", { class: "icon-btn", type: "button", "aria-label": "閉じる", onclick: closeDrawer }, icon("x"))), content);
  UI.drawer.classList.add("open");
  UI.drawer.setAttribute("aria-hidden", "false");
  UI.scrim.classList.add("on");
}

function closeDrawer() {
  UI.drawer.classList.remove("open");
  UI.drawer.setAttribute("aria-hidden", "true");
  UI.scrim.classList.remove("on");
  S.selectedMac = null;
  if (current && current.id === "lan") current.update();
}

function gauge(level, counts) {
  const R = 64, C = 80, start = 135, sweep = 270, gap = 4;
  const seg = (sweep - gap * 4) / 5;
  const arc = (a0, a1) => {
    const p = (a) => [C + R * Math.cos((a * Math.PI) / 180), C + R * Math.sin((a * Math.PI) / 180)];
    const [x0, y0] = p(a0), [x1, y1] = p(a1);
    return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${R} ${R} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
  };
  const svg = s("svg", { viewBox: "0 0 160 150", class: `gauge lvl-${level}`, role: "img", "aria-label": `脅威レベル ${level}` });
  for (let i = 0; i < 5; i++) {
    const a0 = start + i * (seg + gap);
    svg.appendChild(s("path", { d: arc(a0, a0 + seg), class: ["g-seg", `g-seg-${i + 1}`, i < level && "on"] }));
  }
  add(svg, s("text", { x: C, y: 76, class: "g-num", "text-anchor": "middle" }, String(level)),
    s("text", { x: C, y: 98, class: "g-name", "text-anchor": "middle" }, LEVELS[level][0]),
    s("text", { x: C, y: 116, class: "g-ja", "text-anchor": "middle" }, `脅威レベル: ${LEVELS[level][1]}`));
  const row = h("div", { class: "g-counts" }, ["critical", "high", "medium", "low"].map((k) =>
    h("div", { class: `gc gc-${k}` }, h("b", null, String((counts || {})[k] || 0)), h("span", null, SEV_JA[k]))));
  return h("div", { class: "gauge-wrap" }, svg, row);
}

function stat(label, value, sub, cls) {
  return h("div", { class: ["stat", cls] }, h("div", { class: "stat-l" }, label), h("div", { class: "stat-v" }, value), h("div", { class: "stat-s" }, sub));
}

function alertItem(a) {
  return h("li", { class: ["feed-item", `sev-b-${a.severity}`, a.status !== "open" && "dim"], onclick: () => { location.hash = "#alerts"; } },
    h("div", { class: "fi-top" }, sevBadge(a.severity), h("span", { class: "fi-time" }, ago(a.last_ts)),
      a.count > 1 ? h("span", { class: "fi-count" }, `×${a.count}`) : null),
    h("div", { class: "fi-title" }, a.title));
}

function aggregate(list, keyFn, labelFn) {
  const m = new Map();
  for (const x of list) {
    const k = keyFn(x);
    if (!k) continue;
    const cur = m.get(k) || { key: k, label: labelFn(x), count: 0, risk: "ok" };
    cur.count++;
    if ((RISK_ORDER[x.risk] ?? 4) < (RISK_ORDER[cur.risk] ?? 4)) cur.risk = x.risk;
    m.set(k, cur);
  }
  return [...m.values()].sort((a, b) => b.count - a.count);
}

function bars(items, max) {
  const top = Math.max(1, ...items.map((i) => i.count));
  return h("ul", { class: "bars" }, items.slice(0, max).map((i) =>
    h("li", { class: `risk-${i.risk}` }, h("span", { class: "bar-l" }, i.label), h("span", { class: "bar-n" }, String(i.count)),
      h("span", { class: "bar-track" }, h("span", { class: "bar-fill", style: { width: `${(100 * i.count) / top}%` } })))));
}

function internetConns() { return S.conns.filter((c) => c.scope === "internet"); }

// ------------------------------------------------------------------ views
const Views = {};

Views.command = {
  needs: ["conns", "alerts", "devices"],
  mount(el) {
    const grid = h("div", { class: "grid-command" });
    const mp = panel("LIVE CONNECTIONS", "通信先マップ", { cls: "map-panel" });
    this.mapCaption = h("span", { class: "muted small" });
    add(mp.actions, this.mapCaption, h("a", { class: "link-btn", href: "#geo" }, "拡大 →"));
    this.map = new WorldMap(mp.body, { onSelect: openNode, labels: 5 });
    const tp = panel("THREAT LEVEL", "脅威レベル", { cls: "threat-panel" });
    this.gaugeBox = tp.body;
    const sp = panel("TELEMETRY", "状況", { cls: "stats-panel" });
    this.stats = h("div", { class: "stats" });
    sp.body.appendChild(this.stats);
    const side = h("div", { class: "side-stack" }, tp.el, sp.el);
    const ap = panel("ALERT FEED", "最新アラート", { cls: "feed-panel" });
    ap.actions.appendChild(h("a", { class: "link-btn", href: "#alerts" }, "すべて →"));
    this.feed = ap.body;
    const dp = panel("DESTINATIONS", "接続先の国・組織", { cls: "dest-panel" });
    this.dest = dp.body;
    const lp = panel("LAN", "家庭内ネットワーク", { cls: "lan-panel" });
    lp.actions.appendChild(h("a", { class: "link-btn", href: "#lan" }, "LANマップ →"));
    this.lanBox = h("div", { class: "lan-mini" });
    this.lanLegend = h("div", { class: "lan-legend" });
    add(lp.body, this.lanBox, this.lanLegend);
    this.lan = new LanMap(this.lanBox, { compact: true, onSelect: (d) => { S.selectedMac = d.mac; location.hash = "#lan"; } });
    add(grid, mp.el, side, h("div", { class: "bottom-row" }, ap.el, dp.el, lp.el));
    el.appendChild(grid);
  },
  update() {
    const sm = S.summary || {};
    this.map.setHome(sm.home);
    const nodes = nodesFromConnections(S.conns);
    this.map.update(nodes);
    this.mapCaption.textContent = `${nodes.length} 拠点 · ${internetConns().length} 接続`;
    clear(this.gaugeBox).appendChild(gauge((S.threat || sm.threat || {}).level ?? 0, (S.threat || sm.threat || {}).counts));
    const st = sm.stats || {};
    const online = S.devices.filter((d) => d.online).length;
    const fresh = S.devices.filter((d) => d.new && !d.trusted && d.kind !== "this").length;
    const counts = (S.threat || {}).counts || {};
    const openN = Object.values(counts).reduce((a, b) => a + b, 0);
    const topC = aggregate(internetConns(), (c) => (c.geo || {}).country, (c) => (c.geo || {}).country_ja || (c.geo || {}).country)[0];
    add(clear(this.stats), 
      stat("LAN DEVICES", String(S.devices.length || st.devices || 0), `オンライン ${online} ・ 新規 ${fresh}`, fresh ? "warn" : ""),
      stat("LIVE LINKS", String(st.internet ?? 0), `${st.processes ?? 0} プロセスが通信中`),
      stat("COUNTRIES", String(st.countries ?? 0), topC ? `最多: ${flag(topC.key)} ${topC.label}` : "—"),
      stat("OPEN ALERTS", String(openN), `緊急 ${counts.critical || 0} ・ 高 ${counts.high || 0}`, counts.critical ? "danger" : counts.high ? "warn" : ""),
      stat("DEFENSE SCORE", sm.posture_score == null ? "—" : `${sm.posture_score}`, "セキュリティ診断スコア", sm.posture_score != null && sm.posture_score < 70 ? "warn" : ""),
      stat("LISTENING", String(st.listeners ?? 0), "外部から接続可能なポート", st.listeners ? "" : ""));
    clear(this.feed);
    const items = (S.activeAlerts || S.alerts).slice(0, 7);
    this.feed.appendChild(items.length ? h("ul", { class: "feed" }, items.map(alertItem)) : empty("未対応のアラートはありません", "異常を検知するとここに表示されます"));
    clear(this.dest);
    const ic = internetConns();
    const byCountry = aggregate(ic, (c) => (c.geo || {}).country, (c) => `${flag((c.geo || {}).country)} ${(c.geo || {}).country_ja || (c.geo || {}).country}`);
    const byOrg = aggregate(ic, (c) => (c.geo || {}).org, (c) => trunc((c.geo || {}).org, 26));
    add(this.dest, h("div", { class: "two-col" }, h("div", null, h("h4", null, "国・地域"), byCountry.length ? bars(byCountry, 6) : empty("通信なし")),
      h("div", null, h("h4", null, "組織 (AS)"), byOrg.length ? bars(byOrg, 6) : empty("—"))));
    this.lan.update(S.devices, S.network);
    clear(this.lanLegend);
    const kinds = aggregate(S.devices, (d) => d.kind, (d) => KIND_JA[d.kind] || d.kind);
    add(this.lanLegend, h("ul", { class: "kind-list" }, kinds.slice(0, 8).map((k) => h("li", null, icon(k.key), h("span", null, k.label), h("b", null, String(k.count))))));
  },
};

Views.geo = {
  needs: ["conns"],
  mount(el) {
    const wrap = h("div", { class: "grid-geo" });
    const mp = panel("GEO MAP", "接続先の世界地図", { cls: "map-panel tall" });
    this.controls = h("div", { class: "geo-controls" });
    mp.actions.appendChild(this.controls);
    this.map = new WorldMap(mp.body, { onSelect: openNode, labels: 10 });
    const lp = panel("ENDPOINTS", "接続先一覧", { cls: "list-panel" });
    this.list = lp.body;
    add(wrap, mp.el, lp.el);
    el.appendChild(wrap);
    this.legend = h("div", { class: "map-legend" },
      ["ok", "low", "medium", "high", "critical"].map((r) => h("span", { class: `lg risk-${r}` }, h("i"), SEV_JA[r])));
    mp.body.appendChild(this.legend);
  },
  async update() {
    add(clear(this.controls), 
      chips([["live", "ライブ"], ["24h", "過去24時間"]], S.geoHistory ? "24h" : "live", async (v) => {
        S.geoHistory = v === "24h"; if (S.geoHistory) await loadHistory(); this.update();
      }),
      h("label", { class: "toggle" }, h("input", { type: "checkbox", checked: S.geoRiskOnly, onchange: (e) => { S.geoRiskOnly = e.target.checked; this.update(); } }), "危険のみ"));
    this.map.setHome((S.summary || {}).home);
    let nodes = nodesFromConnections(S.conns);
    if (S.geoHistory) {
      const live = new Set(nodes.map((n) => n.key));
      for (const d of S.history) {
        if (live.has(d.ip) || d.lat == null) continue;
        live.add(d.ip);
        nodes.push({ key: d.ip, ip: d.ip, lat: d.lat, lon: d.lon, country: d.country, country_ja: d.country, city: d.city, org: d.org,
                     asn: d.asn, count: Math.min(5, d.hits || 1), processes: new Set([d.process]), ports: new Set([d.port]),
                     risk: d.risk || "ok", threats: [], hist: true });
      }
    }
    if (S.geoRiskOnly) nodes = nodes.filter((n) => n.risk !== "ok");
    this.map.update(nodes);
    clear(this.list);
    nodes.sort((a, b) => (RISK_ORDER[a.risk] - RISK_ORDER[b.risk]) || b.count - a.count);
    if (!nodes.length) { this.list.appendChild(empty("表示する接続先がありません", S.geoRiskOnly ? "危険な接続はありません" : "GeoIPデータの取得後に表示されます")); return; }
    this.list.appendChild(h("ul", { class: "ep-list" }, nodes.slice(0, 120).map((n) =>
      h("li", { class: `risk-${n.risk}`, tabindex: 0, onclick: () => openNode(n), onkeydown: (e) => { if (e.key === "Enter") openNode(n); } },
        h("span", { class: "ep-flag" }, flag(n.country)),
        h("span", { class: "ep-main" }, h("span", { class: "ep-org" }, trunc(n.org || n.ip, 30)),
          h("span", { class: "ep-sub" }, `${n.ip} · ${[n.city, n.country_ja].filter(Boolean).join(", ")}`)),
        h("span", { class: "ep-proc" }, trunc([...n.processes].join(", "), 18)),
        n.risk !== "ok" ? sevBadge(n.risk) : h("span", { class: "ep-count" }, `×${n.count}`)))));
  },
};

function openNode(n) {
  const out = h("div", { class: "lookup-out" });
  const body = h("div", { class: "drawer-b" },
    kv([["IPアドレス", n.ip], ["所在地", [n.city, n.country_ja].filter(Boolean).join(" / ") || "不明"],
        ["組織", n.org ? `AS${n.asn || "?"} ${n.org}` : "不明"], ["プロセス", [...(n.processes || [])].join(", ") || "?"],
        ["ポート", [...(n.ports || [])].join(", ")], ["接続数", String(n.count)],
        ["リスク", n.risk !== "ok" ? sevBadge(n.risk) : "検出なし"]]),
    n.threats && n.threats.length ? h("div", { class: "callout danger" }, h("b", null, "脅威リストに掲載: "), n.threats.map((t) => t.label).join(" / ")) : null,
    h("div", { class: "btn-row" }, button("外部情報で照会", { icon: "target", onclick: () => lookupInto(n.ip, out) })), out);
  openDrawer(`${flag(n.country)} ${n.ip}`, body);
}

async function lookupInto(ip, out) {
  clear(out).appendChild(h("div", { class: "muted" }, "照会中… (Shodan InternetDB / GreyNoise)"));
  try {
    const r = await api(`/api/lookup?ip=${encodeURIComponent(ip)}&ext=1`);
    clear(out);
    const ext = r.external || {};
    if (ext.note) out.appendChild(h("p", { class: "muted" }, ext.note));
    const idb = ext.internetdb;
    if (idb) {
      out.appendChild(h("h4", null, "Shodan InternetDB"));
      out.appendChild(idb.error ? h("p", { class: "muted" }, idb.error) : kv([
        ["公開ポート", (idb.ports || []).join(", ") || "記録なし"], ["脆弱性", (idb.vulns || []).slice(0, 10).join(", ") || "記録なし"],
        ["ホスト名", (idb.hostnames || []).slice(0, 4).join(", ")], ["タグ", (idb.tags || []).join(", ")]]));
    }
    const gn = ext.greynoise;
    if (gn) {
      out.appendChild(h("h4", null, "GreyNoise"));
      out.appendChild(gn.error ? h("p", { class: "muted" }, gn.error) : kv([
        ["分類", gn.classification || (gn.found ? "観測あり" : "観測なし")], ["名前", gn.name], ["スキャナー", gn.noise ? "はい" : "いいえ"],
        ["既知の正規サービス", gn.riot ? "はい(RIOT)" : "いいえ"], ["最終観測", gn.last_seen]]));
    }
    const ab = ext.abuseipdb;
    if (ab) {
      out.appendChild(h("h4", null, "AbuseIPDB"));
      out.appendChild(ab.error ? h("p", { class: "muted" }, ab.error) : kv([["悪用スコア", `${ab.score}%`], ["報告数", ab.reports], ["ISP", ab.isp], ["用途", ab.usage]]));
    }
  } catch (e) {
    clear(out).appendChild(h("p", { class: "danger" }, `照会に失敗: ${e.message}`));
  }
}

Views.lan = {
  needs: ["devices"],
  mount(el) {
    const wrap = h("div", { class: "grid-lan" });
    const mp = panel("LAN MAP", "家庭内ネットワークの機器", { cls: "lanmap-panel" });
    this.actions = mp.actions;
    this.mapBox = h("div", { class: "lan-big" });
    mp.body.appendChild(this.mapBox);
    this.map = new LanMap(this.mapBox, { onSelect: (d) => openDevice(d) });
    this.meta = h("div", { class: "lan-meta" });
    mp.body.appendChild(this.meta);
    const lp = panel("DEVICES", "機器一覧", { cls: "list-panel" });
    this.list = lp.body;
    add(wrap, mp.el, lp.el);
    el.appendChild(wrap);
  },
  update() {
    const lanState = S.lan || {};
    this.map.setScanning(lanState.running);
    add(clear(this.actions), 
      button(lanState.running ? "探索中…" : "今すぐ探索", { icon: "scan", disabled: lanState.running, onclick: async () => {
        await post("/api/discover"); S.lan = Object.assign({}, S.lan, { running: true }); this.update();
      } }));
    this.map.update(S.devices, S.network, S.selectedMac);
    const n = S.network || {};
    add(clear(this.meta), kv([
      ["ネットワーク", h("span", null, n.label || "未登録", " ", n.trusted ? h("span", { class: "chip chip-mint" }, "信頼済み") : h("span", { class: "chip chip-amber" }, "未登録"))],
      ["サブネット", n.subnet || "-"], ["ゲートウェイ", n.gateway ? `${n.gateway} (${n.gateway_mac || "MAC不明"})` : "-"],
      ["最終探索", lanState.last ? `${ago(lanState.last)} · ${((lanState.stats || {}).neighbors) ?? "?"}台応答` : "未実行"]]),
      n.id ? h("div", { class: "btn-row" }, button(n.trusted ? "信頼を解除" : "このネットワークを自宅として信頼", {
        icon: "check", onclick: async () => { await post(`/api/networks/${encodeURIComponent(n.id)}`, { trusted: !n.trusted, label: n.trusted ? null : "自宅" }); await refresh(["devices"]); await loadSummary(); this.update(); },
      })) : null);
    clear(this.list);
    if (!S.devices.length) { this.list.appendChild(empty("まだ機器が見つかっていません", "「今すぐ探索」でLAN内を探索します")); return; }
    const sorted = [...S.devices].sort((a, b) => ({ risky: 0, new: 1, known: 2, trusted: 3 }[deviceStatus(a)] - { risky: 0, new: 1, known: 2, trusted: 3 }[deviceStatus(b)]));
    this.list.appendChild(h("ul", { class: "dev-list" }, sorted.map((d) => {
      const st = deviceStatus(d);
      return h("li", { class: [`st-${st}`, d.mac === S.selectedMac && "selected", !d.online && "offline"], tabindex: 0,
                       onclick: () => openDevice(d), onkeydown: (e) => { if (e.key === "Enter") openDevice(d); } },
        icon(d.kind || "unknown", "dev-ico"),
        h("span", { class: "dev-main" }, h("span", { class: "dev-name" }, trunc(deviceName(d), 28)),
          h("span", { class: "dev-sub" }, `${d.ip || "-"} · ${KIND_JA[d.kind] || "不明"}${d.vendor ? " · " + trunc(d.vendor, 18) : ""}`)),
        h("span", { class: "dev-st" }, { risky: sevBadge("high"), new: h("span", { class: "chip chip-amber" }, "NEW"),
          trusted: h("span", { class: "chip chip-mint" }, "信頼"), known: h("span", { class: "chip" }, d.online ? "online" : "offline") }[st]));
    })));
    if (S.selectedMac) {
      const d = S.devices.find((x) => x.mac === S.selectedMac);
      if (d && UI.drawer.classList.contains("open") && UI.drawer.dataset.mac === d.mac) renderDeviceDrawer(d);
    }
  },
};

function openDevice(d) {
  S.selectedMac = d.mac;
  renderDeviceDrawer(d);
  if (current && current.id === "lan") current.update();
}

function renderDeviceDrawer(d) {
  const ports = d.ports || [];
  const scanOut = h("div", { class: "scan-out" });
  const label = h("input", { class: "input", type: "text", value: d.label || "", maxlength: 64, placeholder: "例: 父のiPhone", "aria-label": "機器の名前" });
  const body = h("div", { class: "drawer-b" },
    kv([["IPアドレス", d.ip], ["MACアドレス", d.mac ? `${d.mac}${d.randomized ? "（ランダム化）" : ""}` : "-"], ["メーカー", d.vendor || "不明"],
        ["種別", KIND_JA[d.kind] || d.kind], ["ホスト名", d.hostname], ["モデル", d.model],
        ["サービス", (d.services || []).slice(0, 8).join(", ")], ["初回検出", datetime(d.first_seen)], ["最終確認", ago(d.last_seen)],
        ["最終スキャン", d.last_scan ? ago(d.last_scan) : "未実施"]]),
    h("div", { class: "field" }, h("label", null, "名前"), h("div", { class: "row" }, label,
      button("保存", { onclick: async () => { await post(`/api/devices/${encodeURIComponent(d.mac)}`, { label: label.value }); await refresh(["devices"]); current && current.update(); } }))),
    h("div", { class: "btn-row" },
      d.kind === "this" ? null : button(d.trusted ? "信頼を解除" : "この機器を信頼する", { icon: "check", cls: d.trusted ? "" : "primary",
        onclick: async () => { await post(`/api/devices/${encodeURIComponent(d.mac)}`, { trusted: !d.trusted }); await refresh(["devices"]); const nd = S.devices.find((x) => x.mac === d.mac); if (nd) renderDeviceDrawer(nd); current && current.update(); } }),
      button("クイックスキャン", { icon: "scan", onclick: () => startScan(d, "quick", scanOut) }),
      button("詳細スキャン (nmap)", { icon: "target", onclick: () => startScan(d, "deep", scanOut) })),
    h("h4", null, "開いているポート"),
    ports.length ? portTable(ports) : h("p", { class: "muted" }, d.last_scan ? "開いているポートは見つかりませんでした" : "スキャンするとここに表示されます"),
    scanOut);
  openDrawer(deviceName(d), body);
  UI.drawer.dataset.mac = d.mac || "";
}

function portTable(ports) {
  return h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["ポート", "サービス", "リスク", "詳細"].map((t) => h("th", null, t)))),
    h("tbody", null, ports.map((p) => h("tr", { class: `risk-${p.risk}` }, h("td", { class: "mono" }, String(p.port)), h("td", null, p.service || "?"),
      h("td", null, p.risk === "info" ? h("span", { class: "muted" }, "—") : sevBadge(p.risk)),
      h("td", { class: "small" }, [p.banner, p.note].filter(Boolean).join(" — "))))));
}

async function startScan(d, mode, out) {
  clear(out).appendChild(h("div", { class: "scanning-bar" }, h("span"), `スキャン中… ${d.ip} (${mode === "deep" ? "nmap -sV" : "TCP connect"})`));
  try {
    const job = await post("/api/scan", { ip: d.ip, mode });
    S.jobs[job.id] = { device: d, out };
    pollJob(job.id);
  } catch (e) {
    clear(out).appendChild(h("p", { class: "danger" }, e.message));
  }
}

async function pollJob(id) {
  const ctx = S.jobs[id];
  if (!ctx) return;
  try {
    const job = await api(`/api/scan/${id}`);
    if (job.status === "running") { setTimeout(() => pollJob(id), 1500); return; }
    delete S.jobs[id];
    clear(ctx.out);
    if (job.status === "error") { ctx.out.appendChild(h("p", { class: "danger" }, job.error)); return; }
    const r = job.result;
    add(ctx.out, h("p", { class: "muted" }, `${r.scanned} ポートを ${r.duration}秒で確認（${r.method}）: 開いているポート ${r.open.length} 件`));
    await refresh(["devices"]);
    const nd = S.devices.find((x) => x.mac === ctx.device.mac);
    if (nd && S.selectedMac === nd.mac) renderDeviceDrawer(nd);
    if (current) current.update();
  } catch (e) {
    setTimeout(() => pollJob(id), 3000);
  }
}

Views.traffic = {
  needs: ["conns"],
  mount(el) {
    this.wrap = h("div", { class: "stack" });
    const p = panel("TRAFFIC", "通信中の接続", { cls: "table-panel" });
    this.actions = p.actions;
    this.body = p.body;
    const lp = panel("LISTENING", "待ち受けポート（このMac）", { cls: "table-panel" });
    this.lbody = lp.body;
    add(this.wrap, p.el, lp.el);
    el.appendChild(this.wrap);
    this.search = h("input", { class: "input search", type: "search", placeholder: "プロセス・IP・組織で検索", value: S.trafficQuery,
                               oninput: debounce((e) => { S.trafficQuery = e.target.value; this.update(); }, 200), "aria-label": "検索" });
  },
  update() {
    add(clear(this.actions), chips([["internet", "インターネット"], ["risky", "危険のみ"], ["lan", "LAN"], ["all", "すべて"]], S.trafficFilter,
      (v) => { S.trafficFilter = v; this.update(); }), this.search);
    let rows = S.conns;
    if (S.trafficFilter === "internet") rows = rows.filter((c) => c.scope === "internet");
    if (S.trafficFilter === "risky") rows = rows.filter((c) => c.risk !== "ok");
    if (S.trafficFilter === "lan") rows = rows.filter((c) => c.scope === "lan");
    const q = S.trafficQuery.trim().toLowerCase();
    if (q) rows = rows.filter((c) => [c.process, c.raddr, (c.geo || {}).org, (c.geo || {}).city, (c.geo || {}).country_ja].join(" ").toLowerCase().includes(q));
    clear(this.body);
    if (!rows.length) this.body.appendChild(empty("該当する接続はありません"));
    else this.body.appendChild(h("div", { class: "tbl-wrap" }, h("table", { class: "tbl conn-tbl" },
      h("thead", null, h("tr", null, ["", "プロセス", "方向", "宛先", "ポート", "所在地", "組織", "状態", "検知"].map((t) => h("th", null, t)))),
      h("tbody", null, rows.slice(0, 400).map((c) => {
        const g = c.geo || {};
        return h("tr", { class: `risk-${c.risk}`, tabindex: 0, onclick: () => c.scope === "internet" && openNode(connNode(c)) },
          h("td", null, h("i", { class: `dot risk-${c.risk}` })),
          h("td", { class: "proc", title: c.path || "" }, c.process || "?", c.pid ? h("span", { class: "muted small" }, ` ${c.pid}`) : null),
          h("td", null, c.direction === "in" ? h("span", { class: "chip chip-amber" }, "受信") : h("span", { class: "chip" }, "送信")),
          h("td", { class: "mono" }, c.raddr), h("td", { class: "mono" }, `${c.rport}/${c.proto}`),
          h("td", null, c.scope === "internet" ? `${flag(g.country)} ${[g.city, g.country_ja].filter(Boolean).join(", ")}` : c.scope === "lan" ? "LAN" : c.scope),
          h("td", { class: "small" }, trunc(g.org || "", 28)), h("td", { class: "small mono" }, c.state || "—"),
          h("td", null, (c.flags || []).map((f) => h("span", { class: "chip chip-red" }, f))));
      })))));
    clear(this.lbody);
    const ls = S.listeners.filter((l) => l.proto === "tcp" || l.exposed);
    this.lbody.appendChild(ls.length ? h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" },
      h("thead", null, h("tr", null, ["ポート", "プロセス", "待ち受けアドレス", "公開範囲", "種別"].map((t) => h("th", null, t)))),
      h("tbody", null, ls.map((l) => h("tr", { class: l.sensitive && l.exposed ? "risk-medium" : "" },
        h("td", { class: "mono" }, `${l.port}/${l.proto}`), h("td", { title: l.path || "" }, l.process || "?"),
        h("td", { class: "mono small" }, l.addrs.join(", ")),
        h("td", null, l.exposed ? h("span", { class: "chip chip-amber" }, "LAN/外部") : h("span", { class: "chip" }, "このMacのみ")),
        h("td", null, l.service || "")))))) : empty("待ち受けポートはありません"));
  },
};

function connNode(c) {
  const g = c.geo || {};
  return { key: c.raddr, ip: c.raddr, lat: g.lat, lon: g.lon, country: g.country, country_ja: g.country_ja, city: g.city, org: g.org,
           asn: g.asn, count: 1, processes: new Set([c.process]), ports: new Set([c.rport]), risk: c.risk, threats: c.threats || [] };
}

Views.alerts = {
  needs: ["alerts"],
  mount(el) {
    const p = panel("ALERTS", "アラート", { cls: "alerts-panel" });
    this.actions = p.actions;
    this.body = p.body;
    el.appendChild(p.el);
  },
  update() {
    add(clear(this.actions), 
      chips([["active", "未対応"], ["open", "新規"], ["ack", "確認済み"], ["resolved", "解決済み"], ["all", "すべて"]], S.alertFilter,
        async (v) => { S.alertFilter = v; await loadAlerts(); this.update(); }),
      button("すべて確認済みに", { icon: "check", onclick: async () => { await post("/api/alerts/ack_all"); await loadAlerts(); await loadSummary(); this.update(); } }));
    clear(this.body);
    if (!S.alerts.length) { this.body.appendChild(empty("アラートはありません", "結界は監視を続けています")); return; }
    this.body.appendChild(h("div", { class: "alert-list" }, S.alerts.map(alertCard)));
  },
};

function alertCard(a) {
  const aiBox = h("div", { class: "ai-box" });
  if (a.ai && a.ai.text) renderAi(aiBox, a.ai);
  const setStatus = async (st) => { await post(`/api/alerts/${a.id}/status`, { status: st }); await loadAlerts(); await loadSummary(); current && current.update(); };
  return h("article", { class: ["alert-card", `sev-b-${a.severity}`, a.status !== "open" && "dim"] },
    h("header", null, sevBadge(a.severity), h("h3", null, a.title),
      h("span", { class: "ac-meta" }, `${datetime(a.ts)}${a.count > 1 ? ` · ${a.count}回 · 最終 ${ago(a.last_ts)}` : ""}`),
      h("span", { class: ["chip", a.status === "open" ? "chip-red" : a.status === "ack" ? "chip-amber" : "chip-mint"] },
        { open: "新規", ack: "確認済み", resolved: "解決済み" }[a.status] || a.status)),
    h("p", { class: "ac-detail" }, a.detail),
    a.advice ? h("details", { class: "ac-advice", open: a.severity === "critical" || a.severity === "high" },
      h("summary", null, "推奨される対応"), h("p", null, a.advice)) : null,
    h("div", { class: "btn-row" },
      a.status === "open" ? button("確認済み", { icon: "check", onclick: () => setStatus("ack") }) : null,
      a.status !== "resolved" ? button("解決", { onclick: () => setStatus("resolved") }) : button("再オープン", { onclick: () => setStatus("open") }),
      button(S.aiBusy[a.id] ? "AI解析中…" : "AIに解説させる", { icon: "ai", cls: "ai-btn", disabled: !!S.aiBusy[a.id], onclick: () => runAi(a, aiBox) }),
      h("span", { class: "muted small mono" }, a.rule)),
    aiBox);
}

async function runAi(a, box) {
  S.aiBusy[a.id] = true;
  clear(box).appendChild(h("div", { class: "scanning-bar" }, h("span"), "AIアナリストが分析中…"));
  try {
    const r = await post("/api/ai/analyze", { alert_id: a.id });
    if (!r.ok) { clear(box).appendChild(h("div", { class: "callout" }, h("b", null, "AIが利用できません: "), r.error || "", r.hint ? h("p", { class: "small" }, r.hint) : null)); return; }
    renderAi(box, r);
  } catch (e) {
    clear(box).appendChild(h("p", { class: "danger" }, e.message));
  } finally { delete S.aiBusy[a.id]; }
}

function renderAi(box, r) {
  clear(box);
  const lines = String(r.text || "").split("\n");
  const out = h("div", { class: "ai-text" });
  let list = null;
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line.trim()) { list = null; continue; }
    const m = line.match(/^\s*(#{1,4})\s+(.*)$/);
    if (m) { list = null; out.appendChild(h("h5", null, m[2].replace(/\*\*/g, ""))); continue; }
    const b = line.match(/^\s*(?:[-*・]|\d+[.)])\s+(.*)$/);
    if (b) { if (!list) { list = h("ul"); out.appendChild(list); } list.appendChild(h("li", null, b[1].replace(/\*\*/g, ""))); continue; }
    list = null;
    out.appendChild(h("p", null, line.replace(/\*\*/g, "")));
  }
  add(box, h("div", { class: "ai-head" }, icon("ai"), `AI解説 (${r.provider || "?"}${r.model ? " · " + r.model : ""})`), out);
}

Views.audit = {
  needs: ["posture"],
  mount(el) {
    const wrap = h("div", { class: "grid-audit" });
    const sp = panel("DEFENSE SCORE", "防御スコア", { cls: "score-panel" });
    this.score = sp.body;
    this.actions = sp.actions;
    const cp = panel("HARDENING CHECKS", "セキュリティ診断", { cls: "checks-panel" });
    this.checks = cp.body;
    const pp = panel("PERSISTENCE", "自動起動項目 (LaunchAgents/Daemons)", { cls: "persist-panel" });
    this.persist = pp.body;
    add(wrap, h("div", { class: "audit-side" }, sp.el, pp.el), cp.el);
    el.appendChild(wrap);
  },
  update() {
    const p = S.posture;
    add(clear(this.actions), button("再診断", { icon: "refresh", onclick: async () => { await post("/api/posture/run", { slow: false }); setTimeout(() => refresh(["posture"]).then(() => this.update()), 2500); } }),
      button("詳細診断", { title: "未適用のアップデートも確認（1〜2分）", onclick: async () => { await post("/api/posture/run", { slow: true }); this.note.textContent = "詳細診断を実行中…（完了後に自動更新）"; setTimeout(() => refresh(["posture"]).then(() => this.update()), 60000); } }));
    clear(this.score);
    this.note = h("div", { class: "muted small" });
    if (!p) { add(this.score, empty("診断結果を準備中…"), this.note); clear(this.checks); return; }
    const sc = p.score ?? 0;
    const R = 54, C = 2 * Math.PI * R;
    const ring = s("svg", { viewBox: "0 0 140 140", class: "score-ring" },
      s("circle", { cx: 70, cy: 70, r: R, class: "sr-bg" }),
      s("circle", { cx: 70, cy: 70, r: R, class: ["sr-fg", sc >= 80 ? "good" : sc >= 60 ? "mid" : "bad"], "stroke-dasharray": `${(C * sc) / 100} ${C}`, transform: "rotate(-90 70 70)" }),
      s("text", { x: 70, y: 78, "text-anchor": "middle", class: "sr-num" }, String(sc)));
    const c = p.counts || {};
    add(this.score, h("div", { class: "score-wrap" }, ring,
      h("ul", { class: "score-counts" }, ["fail", "warn", "pass", "info"].map((k) => h("li", { class: `st-${k}` }, h("b", null, String(c[k] || 0)), STATUS_JA[k])))),
      h("div", { class: "muted small" }, `最終診断: ${ago(p.ts)}`), this.note);
    clear(this.checks);
    const groups = {};
    for (const ch of p.checks || []) (groups[ch.category] = groups[ch.category] || []).push(ch);
    for (const [cat, list] of Object.entries(groups)) {
      this.checks.appendChild(h("h4", { class: "cat-h" }, CAT_JA[cat] || cat));
      this.checks.appendChild(h("ul", { class: "check-list" }, list.map((ch) => h("li", { class: `st-${ch.status}` },
        h("span", { class: "ck-st" }, STATUS_JA[ch.status] || ch.status),
        h("div", { class: "ck-main" }, h("div", { class: "ck-title" }, ch.title), h("div", { class: "ck-detail" }, ch.detail),
          ch.fix ? h("div", { class: "ck-fix" }, "→ ", ch.fix) : null)))));
    }
    clear(this.persist);
    const items = S.persistence || [];
    if (!items.length) this.persist.appendChild(empty("項目なし"));
    else this.persist.appendChild(h("ul", { class: "persist-list" }, items.slice(0, 60).map((it) =>
      h("li", { class: it.flag ? "flagged" : "" }, h("div", { class: "pl-label" }, trunc(it.label || it.plist, 46), it.flag ? h("span", { class: "chip chip-red" }, it.flag) : null),
        h("div", { class: "pl-sub" }, trunc(it.program || "?", 60), " · ", (it.signature || {}).summary || "署名未確認")))));
  },
};

Views.exposure = {
  needs: ["exposure"],
  mount(el) {
    const wrap = h("div", { class: "grid-exposure" });
    const ip = panel("PUBLIC FACE", "インターネットから見た自宅", { cls: "pub-panel" });
    this.actions = ip.actions;
    this.pub = ip.body;
    const fp = panel("FINDINGS", "検出事項", { cls: "find-panel" });
    this.find = fp.body;
    const up = panel("UPNP", "ルーターのポート開放 (UPnP)", { cls: "upnp-panel" });
    this.upnp = up.body;
    add(wrap, ip.el, fp.el, up.el);
    el.appendChild(wrap);
  },
  update() {
    add(clear(this.actions), button("今すぐ確認", { icon: "refresh", onclick: async () => { await post("/api/exposure/run"); setTimeout(() => refresh(["exposure"]).then(() => this.update()), 6000); } }));
    const e = S.exposure;
    clear(this.pub);
    if (!e) { this.pub.appendChild(empty("確認中…", "公開IPとShodan InternetDBを照会します")); }
    else if (e.disabled) { this.pub.appendChild(empty("外部照会は無効です", "config.json の privacy.external_lookups で有効化できます")); }
    else {
      const idb = e.internetdb || {};
      add(this.pub, h("div", { class: "pub-ip mono" }, e.public_ip || "取得できませんでした"),
        kv([["ルーターWAN側IP", e.wan_ip || "不明（UPnP非対応）"], ["共有IPv4", e.shared_ipv4 ? "はい（CGNAT/DS-Lite等）" : "いいえ/不明"],
            ["Shodan記録", idb.found ? "あり" : "なし（スキャンで見つかっていません）"], ["公開ポート", (idb.ports || []).join(", ") || "—"],
            ["脆弱性(CVE)", (idb.vulns || []).slice(0, 8).join(", ") || "—"], ["最終確認", ago(e.checked_at)]]),
        e.error ? h("p", { class: "danger small" }, e.error) : null,
        h("p", { class: "muted small" }, "データ: Shodan InternetDB（無料・週1回更新）。公開IPの確認に外部サービスを使います。"));
    }
    clear(this.find);
    const f = (e && e.findings) || [];
    this.find.appendChild(f.length ? h("ul", { class: "find-list" }, f.map((x) => h("li", { class: `sev-b-${x.severity}` }, sevBadge(x.severity), h("div", null, h("b", null, x.title), h("p", null, x.detail)))))
      : empty("外部に見えている問題は見つかりません", "定期的に自動確認します"));
    clear(this.upnp);
    const u = S.upnp;
    if (!u) this.upnp.appendChild(empty("UPnP対応ルーターが見つかりません", "UPnPが無効なのは安全な状態です"));
    else {
      add(this.upnp, kv([["ルーター", u.router], ["サービス", u.service], ["WAN側IP", u.external_ip || "-"]]));
      this.upnp.appendChild((u.mappings || []).length ? h("table", { class: "tbl" },
        h("thead", null, h("tr", null, ["外部ポート", "転送先", "説明", "状態"].map((t) => h("th", null, t)))),
        h("tbody", null, u.mappings.map((m) => h("tr", null, h("td", { class: "mono" }, `${m.external_port}/${m.protocol}`),
          h("td", { class: "mono" }, `${m.internal_client}:${m.internal_port}`), h("td", null, m.description || "—"), h("td", null, m.enabled ? "有効" : "無効")))))
        : h("p", { class: "muted" }, "ポート開放はありません"));
    }
  },
};

Views.intel = {
  needs: ["intel"],
  mount(el) {
    const wrap = h("div", { class: "grid-intel" });
    const fp = panel("THREAT FEEDS", "脅威インテリジェンス", { cls: "feeds-panel" });
    this.factions = fp.actions; this.feeds = fp.body;
    const lp = panel("IP LOOKUP", "IP照会", { cls: "lookup-panel" });
    this.lookup = lp.body;
    const ap = panel("AI ANALYST", "AIアナリスト", { cls: "ai-panel" });
    this.ai = ap.body;
    const hp = panel("SELF DIAGNOSIS", "自己診断（ツールの不具合検出）", { cls: "health-panel" });
    this.hactions = hp.actions; this.health = hp.body;
    add(wrap, fp.el, lp.el, ap.el, hp.el);
    el.appendChild(wrap);
    const input = h("input", { class: "input", type: "text", placeholder: "例: 8.8.8.8", "aria-label": "IPアドレス" });
    const out = h("div", { class: "lookup-out" });
    const go = () => { if (input.value.trim()) lookupBasic(input.value.trim(), out); };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    add(this.lookup, h("div", { class: "row" }, input, button("照会", { icon: "target", cls: "primary", onclick: go })), out);
  },
  update() {
    const it = S.intel;
    add(clear(this.factions), button("今すぐ更新", { icon: "refresh", onclick: async () => { await post("/api/intel/update", { force: true }); this.note.textContent = "更新中…（数分かかることがあります）"; setTimeout(() => refresh(["intel"]).then(() => this.update()), 20000); } }));
    clear(this.feeds);
    this.note = h("div", { class: "muted small" });
    if (!it) { this.feeds.appendChild(empty("読み込み中…")); return; }
    const g = it.geo || {};
    add(this.feeds, h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["リスト", "件数", "更新", "状態"].map((t) => h("th", null, t)))),
      h("tbody", null, it.feeds.map((f) => h("tr", { class: f.status === "ok" ? "" : "risk-medium" },
        h("td", null, h("a", { href: f.home, target: "_blank", rel: "noopener noreferrer" }, f.label)), h("td", { class: "mono" }, String(f.entries || 0)),
        h("td", { class: "small" }, f.updated_at ? ago(f.updated_at) : "未取得"),
        h("td", { title: f.error || "" }, f.status === "ok" ? h("span", { class: "chip chip-mint" }, "OK") : h("span", { class: "chip chip-amber" }, f.status)))))),
      kv([["GeoIP(都市)", g.city ? `OK · ${datetime(g.city_build)}` : "未取得（kekkai setup）"], ["ASN", g.asn ? `OK · ${datetime(g.asn_build)}` : "未取得"],
          ["MACベンダーDB", it.oui ? `${it.oui.toLocaleString()} 件` : "未取得"]]),
      this.note, h("p", { class: "muted small" }, (it.attribution || []).join(" / ")));
    clear(this.ai);
    const ai = S.ai;
    if (ai) {
      add(this.ai, kv([["使用するAI", ai.active ? `${ai.active.provider}${ai.active.model ? " · " + ai.active.model : ""}` : "未設定"],
        ...(ai.providers || []).map((p) => [p.label, p.available ? h("span", { class: "chip chip-mint" }, p.detail || "利用可能") : h("span", { class: "chip" }, p.detail || "未検出")])]),
        h("p", { class: "muted small" }, ai.hint || ""));
    }
    add(clear(this.hactions), button("自己診断を実行", { icon: "check", onclick: async () => { S.doctor = (await api("/api/doctor")).checks; this.update(); } }));
    clear(this.health);
    const hl = it.health || {};
    this.health.appendChild(h("table", { class: "tbl" }, h("thead", null, h("tr", null, ["処理", "実行回数", "エラー", "所要時間", "最終成功"].map((t) => h("th", null, t)))),
      h("tbody", null, Object.entries(hl).filter(([k]) => k !== "collectors").map(([k, v]) => h("tr", { class: v.last_error ? "risk-medium" : "" },
        h("td", { class: "mono" }, k), h("td", { class: "mono" }, String(v.runs || 0)), h("td", { title: v.last_error || "" }, v.last_error ? trunc(v.last_error, 40) : "0"),
        h("td", { class: "mono" }, `${v.duration ?? "-"}s`), h("td", { class: "small" }, ago(v.last_ok)))))));
    if (hl.collectors) this.health.appendChild(h("div", { class: "callout" }, h("b", null, "収集エラー: "), Object.entries(hl.collectors).map(([k, v]) => `${k}: ${v}`).join(" / ")));
    const sensor = it.sensor || {};
    this.health.appendChild(h("p", { class: "small" }, sensor.active ? "パケットセンサー: 稼働中" : "パケットセンサー: 停止中（ポートスキャン/ARP偽装のリアルタイム検知には ", h("code", null, "sudo ./kekkai sensor"), " を別ターミナルで実行）"));
    if (S.doctor) this.health.appendChild(h("ul", { class: "doctor-list" }, S.doctor.map((d) => h("li", { class: `st-${d.status}` },
      h("span", { class: "ck-st" }, { ok: "OK", warn: "注意", fail: "NG", info: "情報" }[d.status] || d.status), h("b", null, d.name), " ", h("span", { class: "muted" }, d.detail),
      d.fix ? h("div", { class: "ck-fix" }, "→ ", d.fix) : null))));
  },
};

async function lookupBasic(ip, out) {
  clear(out).appendChild(h("div", { class: "muted" }, "照会中…"));
  try {
    const r = await api(`/api/lookup?ip=${encodeURIComponent(ip)}`);
    const g = r.geo || {};
    add(clear(out), kv([["IP", r.ip], ["種別", r.public ? "グローバルIP" : "プライベート/特殊用途"],
      ["所在地", [g.city, g.region, g.country_ja || g.country_name].filter(Boolean).join(", ") || "—"],
      ["組織", g.org ? `AS${g.asn} ${g.org}` : "—"], ["過去の通信", r.seen ? "あり" : "なし"],
      ["脅威リスト", r.threats.length ? h("span", { class: "danger" }, r.threats.map((t) => t.label).join(" / ")) : "掲載なし"]]),
      r.public ? h("div", { class: "btn-row" }, button("外部情報でも照会", { onclick: () => { const ext = h("div"); out.appendChild(ext); lookupInto(r.ip, ext); } })) : null);
  } catch (e) { clear(out).appendChild(h("p", { class: "danger" }, e.message)); }
}

// ------------------------------------------------------------------ routing
async function go() {
  const id = (location.hash || "#command").slice(1);
  const meta = VIEWS.find((v) => v.id === id) || VIEWS[0];
  for (const a of UI.nav.querySelectorAll(".nav-item")) a.classList.toggle("on", a.dataset.view === meta.id);
  closeDrawerSilently();
  clear(UI.main);
  const view = Object.create(Views[meta.id]);
  view.id = meta.id;
  current = view;
  const container = h("div", { class: `view view-${meta.id}` });
  UI.main.appendChild(container);
  view.mount(container);
  document.title = `${meta.label} — 結界 KEKKAI`;
  await refresh(view.needs);
  if (current === view) await view.update();
}

function closeDrawerSilently() {
  UI.drawer.classList.remove("open");
  UI.drawer.setAttribute("aria-hidden", "true");
  UI.scrim.classList.remove("on");
}

// ------------------------------------------------------------------ live updates
function connectSSE() {
  let es;
  try { es = new EventSource("/api/events"); } catch (_) { setLive(false); return; }
  es.addEventListener("open", () => setLive(true));
  es.addEventListener("error", () => setLive(false, "RECONNECTING"));
  const onSummary = (e) => {
    try { S.summary = Object.assign({}, S.summary || {}, JSON.parse(e.data)); } catch (_) { return; }
    renderTop();
    liveRefresh();
  };
  es.addEventListener("hello", onSummary);
  es.addEventListener("state", onSummary);
  es.addEventListener("alert", (e) => {
    try { toast(JSON.parse(e.data)); } catch (_) { /* ignore */ }
    loadAlerts().then(() => { if (current && current.needs.includes("alerts")) current.update(); });
    loadSummary();
  });
  es.addEventListener("alert_update", () => loadSummary());
  es.addEventListener("lan", (e) => {
    try { S.lan = Object.assign({}, S.lan || {}, JSON.parse(e.data)); } catch (_) { /* ignore */ }
    loadDevices().then(() => { if (current && (current.id === "lan" || current.id === "command")) current.update(); });
  });
  es.addEventListener("posture", () => { if (current && current.id === "audit") refresh(["posture"]).then(() => current.update()); loadSummary(); });
  es.addEventListener("scan", () => { if (current && current.id === "lan") refresh(["devices"]).then(() => current.update()); });
}

const liveRefresh = debounce(async () => {
  if (!current) return;
  const needs = current.needs.filter((k) => k === "conns" || (k === "devices" && Date.now() - S.lastDevFetch > 30000) || (k === "alerts"));
  if (!needs.length) return;
  await refresh(needs);
  if (current && !UI.drawer.classList.contains("open")) current.update();
  else if (current && current.id !== "lan") current.update();
}, 600);

function keyboard(e) {
  if (e.target && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
  if (e.key === "Escape") { closeDrawer(); return; }
  const n = Number(e.key);
  if (n >= 1 && n <= VIEWS.length && !e.metaKey && !e.ctrlKey && !e.altKey) location.hash = `#${VIEWS[n - 1].id}`;
}

async function main() {
  shell();
  document.addEventListener("kekkai:unauthorized", () => { UI.locked.hidden = false; });
  window.addEventListener("hashchange", go);
  document.addEventListener("keydown", keyboard);
  try { await loadSummary(); } catch (e) { setLive(false); }
  await go();
  connectSSE();
  setInterval(() => { if (!S.sse) { loadSummary().then(liveRefresh).catch(() => {}); } }, 10000);
}

main();
