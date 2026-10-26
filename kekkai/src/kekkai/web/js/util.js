// DOM helpers. Data is only ever inserted as text nodes / attributes (never parsed as HTML),
// so names coming from LAN devices (mDNS, UPnP) cannot inject markup.
const SVGNS = "http://www.w3.org/2000/svg";

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

function setAttrs(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.setAttribute("class", Array.isArray(v) ? v.filter(Boolean).join(" ") : v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "style") Object.assign(el.style, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, kids);
  return el;
}

export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  setAttrs(el, attrs);
  append(el, kids);
  return el;
}

// Null-safe append (native Element.append() would render null as the text "null").
export function add(el, ...kids) {
  append(el, kids);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function handle(r) {
  let body = null;
  try { body = await r.json(); } catch (_) { body = null; }
  if (!r.ok) {
    if (r.status === 401) document.dispatchEvent(new CustomEvent("kekkai:unauthorized"));
    throw new ApiError(r.status, (body && body.error) || r.statusText);
  }
  return body;
}

export async function api(path) {
  return handle(await fetch(path, { credentials: "same-origin", cache: "no-store" }));
}

export async function post(path, body) {
  return handle(await fetch(path, {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
  }));
}

export const SEV = ["critical", "high", "medium", "low", "info"];
export const SEV_JA = { critical: "緊急", high: "高", medium: "中", low: "低", info: "情報", ok: "正常" };
export const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, ok: 4, info: 4 };

export function flag(a2) {
  if (!a2 || a2.length !== 2) return "🌐";
  return String.fromCodePoint(...[...a2.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

export function pad(n) { return String(n).padStart(2, "0"); }

export function clock(ts) {
  const d = ts ? new Date(ts * 1000) : new Date();
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function datetime(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function ago(ts) {
  if (!ts) return "-";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}秒前`;
  if (s < 3600) return `${Math.floor(s / 60)}分前`;
  if (s < 86400) return `${Math.floor(s / 3600)}時間前`;
  return `${Math.floor(s / 86400)}日前`;
}

export function trunc(str, n) {
  str = String(str ?? "");
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

export function sevBadge(sev, extra) {
  return h("span", { class: ["sev", `sev-${sev}`, extra] }, SEV_JA[sev] || sev);
}

export function debounce(fn, ms) {
  let t = null;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// Minimal line icons (24x24, stroke). Static markup only.
const ICON_PATHS = {
  command: ["M3 12l9-8 9 8", "M5 10v10h14V10", "M10 20v-6h4v6"],
  geo: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M3 12h18", "M12 3c3 3.2 3 14.8 0 18", "M12 3c-3 3.2-3 14.8 0 18"],
  lan: ["M12 8a2 2 0 1 0 0-4a2 2 0 0 0 0 4z", "M5 20a2 2 0 1 0 0-4a2 2 0 0 0 0 4z", "M19 20a2 2 0 1 0 0-4a2 2 0 0 0 0 4z", "M12 8v4", "M12 12l-6 4", "M12 12l6 4"],
  traffic: ["M4 8h13l-3-3", "M20 16H7l3 3"],
  alerts: ["M12 4l9 16H3z", "M12 10v4", "M12 17v.5"],
  audit: ["M12 3l7 3v6c0 4.5-3 7.5-7 9c-4-1.5-7-4.5-7-9V6z", "M9 12l2 2 4-4"],
  exposure: ["M2 12s3.6-6 10-6s10 6 10 6s-3.6 6-10 6S2 12 2 12z", "M12 9.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 0 0 0-5z"],
  intel: ["M4 19V5", "M4 19h16", "M8 15l3-4 3 2 4-6"],
  router: ["M4 14h16v5H4z", "M8 14l-2-6", "M16 14l2-6", "M7.5 16.5h.01", "M11 16.5h.01"],
  computer: ["M5 6h14v9H5z", "M3 18h18"],
  this: ["M5 6h14v9H5z", "M3 18h18", "M12 9v3"],
  phone: ["M8 3h8v18H8z", "M11.5 18h1"],
  tv: ["M3 6h18v11H3z", "M8 21h8"],
  media: ["M4 5h16v14H4z", "M10 9l5 3-5 3z"],
  speaker: ["M8 3h8v18H8z", "M12 14a2.5 2.5 0 1 0 0 5a2.5 2.5 0 0 0 0-5z", "M12 7h.01"],
  printer: ["M7 9V4h10v5", "M5 9h14v7H5z", "M7 14h10v6H7z"],
  nas: ["M5 4h14v5H5z", "M5 10h14v5H5z", "M5 16h14v4H5z", "M8 6.5h.01", "M8 12.5h.01"],
  camera: ["M4 8h12v9H4z", "M16 11l4-2v7l-4-2", "M10 12.5a1.5 1.5 0 1 0 0 .01"],
  iot: ["M7 7h10v10H7z", "M10 10h4v4h-4z", "M9 4v3", "M15 4v3", "M9 17v3", "M15 17v3", "M4 9h3", "M4 15h3", "M17 9h3", "M17 15h3"],
  game: ["M6 9h12a3 3 0 0 1 3 3v2a3 3 0 0 1-5 2l-1-1H9l-1 1a3 3 0 0 1-5-2v-2a3 3 0 0 1 3-3z", "M8 11v3", "M6.5 12.5h3", "M16 12h.01"],
  apple: ["M8 3h8v18H8z", "M11.5 18h1", "M10 6h4"],
  network: ["M3 9h18v6H3z", "M7 12h.01", "M10 12h.01", "M13 12h.01"],
  unknown: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5V14", "M12 17h.01"],
  scan: ["M4 7V4h3", "M17 4h3v3", "M20 17v3h-3", "M7 20H4v-3", "M4 12h16"],
  bolt: ["M13 2L4 14h7l-1 8 9-12h-7z"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 4v7h-7"],
  check: ["M5 12l5 5 9-10"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  ai: ["M12 3l2 5 5 2-5 2-2 5-2-5-5-2 5-2z", "M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"],
  lock: ["M6 11h12v9H6z", "M8 11V8a4 4 0 0 1 8 0v3"],
  plus: ["M12 5v14", "M5 12h14"],
  minus: ["M5 12h14"],
  target: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8z", "M12 12h.01"],
};

export function icon(name, cls) {
  const paths = ICON_PATHS[name] || ICON_PATHS.unknown;
  return s("svg", { viewBox: "0 0 24 24", class: ["icon", cls], "aria-hidden": "true" },
    paths.map((d) => s("path", { d })));
}

export function iconSymbols() {
  // <symbol>s for the SVG maps (use href="#ico-kind")
  return s("defs", null, Object.entries(ICON_PATHS).map(([k, ps]) =>
    s("symbol", { id: `ico-${k}`, viewBox: "0 0 24 24" }, ps.map((d) => s("path", { d })))));
}

export function emblem(size = 34) {
  // Hexagonal ward ("結界") emblem.
  const hex = (r) => Array.from({ length: 6 }, (_, i) => {
    const a = Math.PI / 6 + i * Math.PI / 3;
    return `${(50 + r * Math.cos(a)).toFixed(2)},${(50 + r * Math.sin(a)).toFixed(2)}`;
  }).join(" ");
  return s("svg", { viewBox: "0 0 100 100", width: size, height: size, class: "emblem", "aria-hidden": "true" },
    s("polygon", { points: hex(46), class: "emblem-outer" }),
    s("polygon", { points: hex(34), class: "emblem-mid" }),
    s("polygon", { points: hex(20), class: "emblem-core" }),
    s("path", { d: "M50 4V96 M10 27L90 73 M90 27L10 73", class: "emblem-rays" }));
}
