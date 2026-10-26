// LAN topology map (Zenmap-style radial view): router in the centre, devices on rings.
import { s, h, add, clear, trunc, iconSymbols } from "./util.js";

const KIND_ORDER = ["this", "computer", "apple", "phone", "tv", "media", "speaker", "game", "printer", "nas", "camera",
  "iot", "network", "unknown"];

export function deviceName(d) {
  return d.label || d.hostname || d.model || d.vendor || (d.randomized ? "プライベートアドレス機器" : "不明な機器");
}

export function deviceStatus(d) {
  const ports = d.ports || [];
  if (ports.some((p) => p.risk === "critical" || p.risk === "high")) return "risky";
  if (d.new && !d.trusted) return "new";
  if (d.trusted) return "trusted";
  return "known";
}

export class LanMap {
  constructor(container, opts = {}) {
    this.opts = opts;
    this.size = opts.compact ? 420 : 760;
    const S = this.size;
    this.root = h("div", { class: ["lanmap", opts.compact && "compact"] });
    const padX = opts.compact ? 40 : 110;  // room for labels left/right of the outer ring
    this.svg = s("svg", { viewBox: `${-padX} 0 ${S + padX * 2} ${S}`, class: "lm-svg", role: "img", "aria-label": "LAN内の機器マップ" });
    this.svg.appendChild(iconSymbols());
    const c = S / 2;
    const rings = s("g", { class: "lm-rings" });
    for (const r of [0.16, 0.31, 0.45]) rings.appendChild(s("circle", { cx: c, cy: c, r: S * r }));
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * Math.PI * 2;
      rings.appendChild(s("line", { x1: c + Math.cos(a) * S * 0.08, y1: c + Math.sin(a) * S * 0.08,
                                    x2: c + Math.cos(a) * S * 0.47, y2: c + Math.sin(a) * S * 0.47, class: "lm-spoke" }));
    }
    this.radar = s("g", { class: "lm-radar" },
      s("path", { d: `M${c} ${c} L${c} ${c - S * 0.47} A${S * 0.47} ${S * 0.47} 0 0 1 ${c + S * 0.47 * Math.sin(0.6)} ${c - S * 0.47 * Math.cos(0.6)} Z`,
                  class: "lm-sweep" }));
    this.gLinks = s("g", { class: "lm-links" });
    this.gNodes = s("g", { class: "lm-nodes" });
    this.gCenter = s("g", { class: "lm-center" });
    add(this.svg, rings, this.radar, this.gLinks, this.gNodes, this.gCenter);
    this.root.appendChild(this.svg);
    container.appendChild(this.root);
  }

  setScanning(on) { this.root.classList.toggle("scanning", !!on); }

  update(devices, network, selectedMac) {
    const S = this.size, c = S / 2;
    clear(this.gLinks); clear(this.gNodes); clear(this.gCenter);
    const router = devices.find((d) => d.kind === "router") ||
      (network && network.gateway ? { ip: network.gateway, mac: network.gateway_mac, kind: "router", vendor: null } : null);
    const others = devices.filter((d) => d !== router && d.kind !== "router");
    others.sort((a, b) => (KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind)) || ipNum(a.ip) - ipNum(b.ip));
    const n = others.length;
    const twoRings = n > (this.opts.compact ? 14 : 18);
    others.forEach((d, i) => {
      const a = (i / Math.max(1, n)) * Math.PI * 2 - Math.PI / 2;
      const rr = S * (twoRings ? (i % 2 ? 0.43 : 0.3) : 0.36);
      const x = c + Math.cos(a) * rr, y = c + Math.sin(a) * rr;
      const st = deviceStatus(d);
      const online = d.online !== false;
      this.gLinks.appendChild(s("line", { x1: c, y1: c, x2: x, y2: y, class: ["lm-link", `st-${st}`, !online && "offline"] }));
      if (online && !this.opts.compact) {
        const dur = 2.6 + Math.random() * 2;
        this.gLinks.appendChild(s("circle", { r: 2, class: ["lm-packet", `st-${st}`] },
          s("animateMotion", { dur: `${dur.toFixed(2)}s`, repeatCount: "indefinite", begin: `${(-Math.random() * dur).toFixed(2)}s`,
                               path: `M${c} ${c} L${x.toFixed(1)} ${y.toFixed(1)}` })));
      }
      const g = s("g", { class: ["lm-node", `st-${st}`, `kind-${d.kind}`, !online && "offline", d.mac === selectedMac && "selected"],
                         transform: `translate(${x.toFixed(1)} ${y.toFixed(1)})`, tabindex: 0, role: "button",
                         "aria-label": `${deviceName(d)} ${d.ip}` });
      const R = this.opts.compact ? 11 : 17;
      add(g, s("circle", { r: R + 6, class: "lm-halo" }), s("circle", { r: R, class: "lm-dot" }),
        s("use", { href: `#ico-${d.kind || "unknown"}`, x: -R * 0.62, y: -R * 0.62, width: R * 1.24, height: R * 1.24, class: "lm-ico" }));
      if (!this.opts.compact || n <= 10) {
        const right = Math.cos(a) >= -0.15;
        const lx = right ? R + 8 : -R - 8;
        add(g, s("text", { x: lx, y: -2, class: "lm-label", "text-anchor": right ? "start" : "end" }, trunc(deviceName(d), 20)),
          s("text", { x: lx, y: 11, class: "lm-sub", "text-anchor": right ? "start" : "end" }, d.ip || ""));
      }
      if (st === "new") g.appendChild(s("text", { x: 0, y: -R - 9, class: "lm-badge", "text-anchor": "middle" }, "NEW"));
      if (st === "risky") g.appendChild(s("text", { x: 0, y: -R - 9, class: "lm-badge danger", "text-anchor": "middle" }, "RISK"));
      const pick = () => this.opts.onSelect && this.opts.onSelect(d);
      g.addEventListener("click", pick);
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
      this.gNodes.appendChild(g);
    });
    const hex = (r) => Array.from({ length: 6 }, (_, i) => {
      const a = Math.PI / 6 + i * Math.PI / 3;
      return `${(c + r * Math.cos(a)).toFixed(1)},${(c + r * Math.sin(a)).toFixed(1)}`;
    }).join(" ");
    const R0 = this.opts.compact ? 24 : 36;
    const cg = s("g", { class: ["lm-router", router && router.mac === selectedMac && "selected"], tabindex: 0, role: "button",
                        "aria-label": "ルーター" });
    add(cg, s("polygon", { points: hex(R0 + 10), class: "lm-router-halo" }), s("polygon", { points: hex(R0), class: "lm-router-hex" }),
      s("use", { href: "#ico-router", x: c - R0 * 0.55, y: c - R0 * 0.62, width: R0 * 1.1, height: R0 * 1.1, class: "lm-ico" }));
    if (!this.opts.compact) {
      add(cg, s("text", { x: c, y: c + R0 + 26, class: "lm-label center", "text-anchor": "middle" },
        router ? trunc(deviceName(router), 22) : "ゲートウェイ不明"),
        s("text", { x: c, y: c + R0 + 40, class: "lm-sub", "text-anchor": "middle" }, router ? router.ip : ""));
    }
    if (router) cg.addEventListener("click", () => this.opts.onSelect && this.opts.onSelect(router));
    this.gCenter.appendChild(cg);
  }
}

function ipNum(ip) {
  const p = String(ip || "").split(".").map(Number);
  return p.length === 4 ? ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3] : 0;
}
