// World map: Equal Earth projection, live connection arcs from HOME to each remote endpoint.
import { h, s, add, clear, flag, trunc, SEV_JA } from "./util.js";

const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
const RAD = Math.PI / 180;
const LAT_TOP = 84, LAT_BOTTOM = -58;

export function equalEarth(lon, lat) {
  const l = lon * RAD, t = Math.asin(M * Math.sin(lat * RAD));
  const t2 = t * t, t6 = t2 * t2 * t2;
  const x = (l * Math.cos(t)) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)));
  const y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2));
  return [x, y];
}

const W = 1000;
const XMAX = equalEarth(180, 0)[0];
const YTOP = equalEarth(0, LAT_TOP)[1];
const YBOT = equalEarth(0, LAT_BOTTOM)[1];
const SCALE = (W - 20) / (2 * XMAX);
const H = Math.ceil((YTOP - YBOT) * SCALE + 20);

export function proj(lon, lat) {
  const [x, y] = equalEarth(lon, Math.max(LAT_BOTTOM - 4, Math.min(LAT_TOP, lat)));
  return [W / 2 + x * SCALE, 10 + (YTOP - y) * SCALE];
}

let worldCache = null;
export async function loadWorld() {
  if (!worldCache) {
    const r = await fetch("/static/data/world.json", { credentials: "same-origin" });
    worldCache = await r.json();
  }
  return worldCache;
}

function ringPath(ring) {
  let d = "";
  for (let i = 0; i < ring.length; i++) {
    const [x, y] = proj(ring[i][0], ring[i][1]);
    d += (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
  }
  return d + "Z";
}

function graticule() {
  const parts = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    let d = "";
    for (let lat = LAT_BOTTOM; lat <= LAT_TOP; lat += 2) {
      const [x, y] = proj(lon, lat);
      d += (d ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }
    parts.push(d);
  }
  for (let lat = -40; lat <= 80; lat += 20) {
    let d = "";
    for (let lon = -180; lon <= 180; lon += 3) {
      const [x, y] = proj(lon, lat);
      d += (d ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }
    parts.push(d);
  }
  return parts.join(" ");
}

function outline() {
  let d = "";
  for (let lat = LAT_BOTTOM; lat <= LAT_TOP; lat += 2) { const [x, y] = proj(-180, lat); d += (d ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1); }
  for (let lat = LAT_TOP; lat >= LAT_BOTTOM; lat -= 2) { const [x, y] = proj(180, lat); d += "L" + x.toFixed(1) + " " + y.toFixed(1); }
  return d + "Z";
}

const RISK_RANK = { ok: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Group live connections by remote IP into map nodes.
export function nodesFromConnections(conns) {
  const byIp = new Map();
  for (const c of conns) {
    const g = c.geo || {};
    if (c.scope !== "internet" || g.lat == null || g.lon == null) continue;
    let n = byIp.get(c.raddr);
    if (!n) {
      n = { key: c.raddr, ip: c.raddr, lat: g.lat, lon: g.lon, country: g.country, country_ja: g.country_ja || g.country_name,
            city: g.city, org: g.org, asn: g.asn, count: 0, processes: new Set(), ports: new Set(), risk: "ok",
            threats: [], inbound: false };
      byIp.set(c.raddr, n);
    }
    n.count++;
    if (c.process) n.processes.add(c.process);
    if (c.rport) n.ports.add(c.rport);
    if (c.direction === "in") n.inbound = true;
    if ((RISK_RANK[c.risk] || 0) > (RISK_RANK[n.risk] || 0)) n.risk = c.risk;
    for (const t of c.threats || []) if (!n.threats.find((x) => x.feed === t.feed)) n.threats.push(t);
  }
  return [...byIp.values()];
}

export class WorldMap {
  constructor(container, opts = {}) {
    this.opts = opts;
    this.root = h("div", { class: "worldmap" });
    container.appendChild(this.root);
    this.view = [0, 0, W, H];
    this.svg = s("svg", { viewBox: this.view.join(" "), class: "wm-svg", preserveAspectRatio: "xMidYMid meet", role: "img",
                         "aria-label": "接続先の世界地図" });
    const defs = s("defs", null,
      s("clipPath", { id: "wm-clip" }, s("path", { d: outline() })),
      s("radialGradient", { id: "wm-glow" }, s("stop", { offset: "0%", "stop-color": "#00e5ff", "stop-opacity": ".55" }),
        s("stop", { offset: "100%", "stop-color": "#00e5ff", "stop-opacity": "0" })),
      s("radialGradient", { id: "wm-glow-red" }, s("stop", { offset: "0%", "stop-color": "#ff3860", "stop-opacity": ".6" }),
        s("stop", { offset: "100%", "stop-color": "#ff3860", "stop-opacity": "0" })));
    this.svg.appendChild(defs);
    this.gRoot = s("g", { class: "wm-root" });
    this.gBase = s("g", { "clip-path": "url(#wm-clip)" });
    this.gBase.appendChild(s("path", { d: outline(), class: "wm-sphere" }));
    this.gBase.appendChild(s("path", { d: graticule(), class: "wm-graticule" }));
    this.gCountries = s("g", { class: "wm-countries" });
    this.gBase.appendChild(this.gCountries);
    this.gArcs = s("g", { class: "wm-arcs" });
    this.gNodes = s("g", { class: "wm-nodes" });
    this.gLabels = s("g", { class: "wm-labels" });
    this.gHome = s("g", { class: "wm-home" });
    add(this.gRoot, this.gBase, this.gArcs, this.gNodes, this.gLabels, this.gHome);
    this.svg.appendChild(this.gRoot);
    this.root.appendChild(this.svg);
    this.tip = h("div", { class: "map-tip", hidden: true });
    this.root.appendChild(this.tip);
    if (opts.controls !== false) this.root.appendChild(this.controls());
    this.countryEls = new Map();
    this.nodeEls = new Map();
    this.home = null;
    this.bindZoom();
    loadWorld().then((w) => this.drawCountries(w)).catch(() => {});
  }

  controls() {
    const btn = (label, title, fn) => h("button", { class: "wm-btn", title, "aria-label": title, onclick: fn }, label);
    return h("div", { class: "wm-controls" },
      btn("+", "拡大", () => this.zoom(0.7)), btn("−", "縮小", () => this.zoom(1 / 0.7)), btn("⟲", "リセット", () => this.reset()));
  }

  drawCountries(world) {
    clear(this.gCountries);
    for (const c of world) {
      const d = c.p.map(ringPath).join("");
      const el = s("path", { d, class: "wm-country", dataset: { a2: c.a2 || "" } });
      el.appendChild(s("title", null, c.n));
      this.gCountries.appendChild(el);
      if (c.a2) this.countryEls.set(c.a2, el);
    }
    if (this.lastNodes) this.highlight(this.lastNodes);
  }

  setHome(home) {
    if (!home || home.lat == null) return;
    const key = `${home.lat},${home.lon}`;
    if (this.homeKey === key) return;
    this.homeKey = key;
    this.home = proj(home.lon, home.lat);
    clear(this.gHome);
    const [x, y] = this.home;
    add(this.gHome, 
      s("circle", { cx: x, cy: y, r: 22, fill: "url(#wm-glow)", class: "wm-home-glow" }),
      s("circle", { cx: x, cy: y, r: 5, class: "wm-home-pulse" }),
      s("circle", { cx: x, cy: y, r: 3.6, class: "wm-home-core" }),
      s("text", { x: x + 8, y: y - 8, class: "wm-home-label" }, home.label || "HOME"));
  }

  highlight(nodes) {
    for (const el of this.countryEls.values()) el.classList.remove("active", "active-risk");
    for (const n of nodes) {
      const el = this.countryEls.get(n.country);
      if (!el) continue;
      el.classList.add("active");
      if ((RISK_RANK[n.risk] || 0) >= 2) el.classList.add("active-risk");
    }
  }

  update(nodes) {
    this.lastNodes = nodes;
    this.highlight(nodes);
    const seen = new Set();
    const max = Math.max(1, ...nodes.map((n) => n.count));
    for (const n of nodes) {
      seen.add(n.key);
      const [x, y] = proj(n.lon, n.lat);
      let rec = this.nodeEls.get(n.key);
      const r = 2.2 + 3.2 * Math.sqrt(n.count / max);
      const riskCls = `risk-${n.risk}`;
      if (!rec) {
        const g = s("g", { class: "wm-node", tabindex: 0, role: "button", "aria-label": `${n.ip} ${n.org || ""}` });
        const halo = s("circle", { cx: x, cy: y, r: r * 3.2, class: "wm-node-halo" });
        const dot = s("circle", { cx: x, cy: y, r, class: "wm-node-dot" });
        add(g, halo, dot);
        g.addEventListener("mouseenter", (e) => this.showTip(rec.node, e));
        g.addEventListener("mousemove", (e) => this.moveTip(e));
        g.addEventListener("mouseleave", () => this.hideTip());
        g.addEventListener("focus", (e) => this.showTip(rec.node, e));
        g.addEventListener("blur", () => this.hideTip());
        g.addEventListener("click", () => this.opts.onSelect && this.opts.onSelect(rec.node));
        this.gNodes.appendChild(g);
        const arc = s("path", { class: "wm-arc", pathLength: 100 });
        const flow = s("path", { class: "wm-flow", pathLength: 100 });
        flow.style.animationDelay = `${(-Math.random() * 3).toFixed(2)}s`;
        add(this.gArcs, arc, flow);
        rec = { g, halo, dot, arc, flow, node: n };
        this.nodeEls.set(n.key, rec);
        g.classList.add("enter");
        requestAnimationFrame(() => g.classList.remove("enter"));
      }
      rec.node = n;
      rec.dot.setAttribute("r", r.toFixed(2));
      rec.halo.setAttribute("r", (r * 3.2).toFixed(2));
      rec.g.setAttribute("class", `wm-node ${riskCls}`);
      if (this.home) {
        const d = arcPath(this.home, [x, y]);
        rec.arc.setAttribute("d", d);
        rec.flow.setAttribute("d", d);
      }
      rec.arc.setAttribute("class", `wm-arc ${riskCls}`);
      rec.flow.setAttribute("class", `wm-flow ${riskCls}${n.inbound ? " inbound" : ""}`);
    }
    for (const [key, rec] of this.nodeEls) {
      if (seen.has(key)) continue;
      rec.g.remove(); rec.arc.remove(); rec.flow.remove();
      this.nodeEls.delete(key);
    }
    this.drawLabels(nodes);
  }

  drawLabels(nodes) {
    clear(this.gLabels);
    const byCity = new Map();
    for (const n of nodes) {
      const k = `${n.city || n.country}`;
      const cur = byCity.get(k) || { n, count: 0 };
      cur.count += n.count;
      byCity.set(k, cur);
    }
    const max = this.opts.labels ?? 6;
    const top = [...byCity.values()].sort((a, b) => b.count - a.count).slice(0, max * 3);
    // Greedy placement: right of the dot, else left; skip labels that would overlap (incl. HOME).
    const placed = this.home ? [[this.home[0] + 4, this.home[1] - 18, 44, 13]] : [];
    let shown = 0;
    for (const { n, count } of top) {
      if (shown >= max) break;
      const text = `${trunc(n.city || n.country_ja || "", 16)} · ${count}`;
      const [x, y] = proj(n.lon, n.lat);
      const w = [...text].reduce((acc, ch) => acc + (ch.charCodeAt(0) > 0x2e80 ? 8 : 4.6), 0);
      const box = [[x + 6, y - 6, w, 11], [x - 6 - w, y - 6, w, 11]].find((b) =>
        !placed.some((p) => b[0] < p[0] + p[2] && p[0] < b[0] + b[2] && b[1] < p[1] + p[3] && p[1] < b[1] + b[3]));
      if (!box) continue;
      placed.push(box);
      shown++;
      this.gLabels.appendChild(s("text", { x: box[0], y: y + 3, class: "wm-label" }, text));
    }
  }

  showTip(n, e) {
    if (!n) return;
    clear(this.tip);
    add(this.tip, 
      h("div", { class: "tip-title" }, `${flag(n.country)} ${n.ip}`),
      h("div", { class: "tip-row" }, [n.city, n.country_ja].filter(Boolean).join(" / ") || "所在地不明"),
      h("div", { class: "tip-row muted" }, n.org ? `AS${n.asn || "?"} ${n.org}` : "AS不明"),
      h("div", { class: "tip-row" }, `プロセス: ${[...n.processes].slice(0, 4).join(", ") || "?"}`),
      h("div", { class: "tip-row" }, `ポート: ${[...n.ports].slice(0, 6).join(", ")} ・ 接続 ${n.count}`),
      n.threats.length ? h("div", { class: "tip-row danger" }, "⚠ " + n.threats.map((t) => t.label).join(" / ")) : null,
      n.risk !== "ok" ? h("div", { class: `tip-risk risk-${n.risk}` }, `リスク: ${SEV_JA[n.risk] || n.risk}`) : null);
    this.tip.hidden = false;
    this.moveTip(e);
  }

  moveTip(e) {
    const box = this.root.getBoundingClientRect();
    let cx = e && e.clientX != null ? e.clientX : box.left + box.width / 2;
    let cy = e && e.clientY != null ? e.clientY : box.top + box.height / 2;
    if (e && e.type === "focus" && e.target.getBoundingClientRect) {
      const r = e.target.getBoundingClientRect(); cx = r.right; cy = r.top;
    }
    const tw = this.tip.offsetWidth || 220, th = this.tip.offsetHeight || 100;
    let x = cx - box.left + 14, y = cy - box.top + 14;
    if (x + tw > box.width - 6) x = cx - box.left - tw - 14;
    if (y + th > box.height - 6) y = cy - box.top - th - 14;
    this.tip.style.left = `${Math.max(6, x)}px`;
    this.tip.style.top = `${Math.max(6, y)}px`;
  }

  hideTip() { this.tip.hidden = true; }

  bindZoom() {
    let drag = null;
    this.svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const pt = this.toSvg(e.clientX, e.clientY);
      this.zoom(e.deltaY > 0 ? 1.12 : 1 / 1.12, pt);
    }, { passive: false });
    this.svg.addEventListener("pointerdown", (e) => {
      if (e.target.closest && e.target.closest(".wm-node")) return;
      drag = { x: e.clientX, y: e.clientY, view: [...this.view] };
      this.svg.setPointerCapture(e.pointerId);
      this.svg.classList.add("dragging");
    });
    this.svg.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const box = this.svg.getBoundingClientRect();
      const k = this.view[2] / box.width;
      this.view[0] = drag.view[0] - (e.clientX - drag.x) * k;
      this.view[1] = drag.view[1] - (e.clientY - drag.y) * k;
      this.applyView();
    });
    const end = () => { drag = null; this.svg.classList.remove("dragging"); };
    this.svg.addEventListener("pointerup", end);
    this.svg.addEventListener("pointercancel", end);
    this.svg.addEventListener("dblclick", () => this.reset());
  }

  toSvg(cx, cy) {
    const box = this.svg.getBoundingClientRect();
    const sx = this.view[2] / box.width, sy = this.view[3] / box.height;
    const k = Math.max(sx, sy);
    const ox = (box.width * k - this.view[2]) / 2, oy = (box.height * k - this.view[3]) / 2;
    return [this.view[0] + (cx - box.left) * k - ox, this.view[1] + (cy - box.top) * k - oy];
  }

  zoom(f, at) {
    const [x, y, w, hh] = this.view;
    const nw = Math.min(W, Math.max(W / 12, w * f));
    const k = nw / w;
    const [px, py] = at || [x + w / 2, y + hh / 2];
    this.view = [px - (px - x) * k, py - (py - y) * k, nw, hh * k];
    this.applyView();
  }

  reset() { this.view = [0, 0, W, H]; this.applyView(); }

  applyView() {
    const [x, y, w, hh] = this.view;
    const cx = Math.min(Math.max(x, -w * 0.25), W - w * 0.75);
    const cy = Math.min(Math.max(y, -hh * 0.25), H - hh * 0.75);
    this.view = [cx, cy, w, hh];
    this.svg.setAttribute("viewBox", this.view.map((v) => v.toFixed(1)).join(" "));
    this.svg.classList.toggle("zoomed", w < W * 0.98);
  }
}

function arcPath([x1, y1], [x2, y2]) {
  const dx = x2 - x1, dy = y2 - y1;
  const dist = Math.hypot(dx, dy);
  if (dist < 1.5) {
    return `M${x1.toFixed(1)} ${y1.toFixed(1)} C${(x1 - 8).toFixed(1)} ${(y1 - 14).toFixed(1)} ${(x1 + 8).toFixed(1)} ${(y1 - 14).toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`;
  }
  const lift = Math.min(160, 18 + dist * 0.28);
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
  // perpendicular, biased upward so arcs bow toward the north like flight paths
  let nx = -dy / dist, ny = dx / dist;
  if (ny > 0) { nx = -nx; ny = -ny; }
  const cx = mx + nx * lift, cy = my + ny * lift;
  return `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

export const MAP_SIZE = { W, H };
