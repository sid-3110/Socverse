/* ===========================================================================
   socverse_viz.js  —  network renderer logic (Module 3)
   Enterprise SVG device icons + role-aware resolver, icon-chip nodes with
   labels, status rings, hover asset cards, enriched edges, glowing protocol
   packets with trails, sequential attack-path light-up, and full reset.
   Consumes window.SOCVERSE (built by ui/viz/snapshot.py). Pure client-side;
   never calls back into Python. Field access is defensive.
   =========================================================================== */
(function () {
  "use strict";

  var S = window.SOCVERSE || { nodes: [], edges: [], devices: {}, timeline: [], packets: [], colors: {}, soc: {}, attack: {} };

  var GROUP_FILL = { security: "#f43f5e", network: "#3b82f6", server: "#22c55e",
    endpoint: "#a855f7", cloud: "#06b6d4", other: "#94a3b8" };
  var STATUS_RING = { healthy: "#22c55e", warning: "#f59e0b", critical: "#ef4444",
    offline: "#64748b", "under-attack": "#f97316", compromised: "#ec4899" };

  // ---- tiny DOM / string helpers -----------------------------------------
  function el(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }
  function esc(v) { if (v == null) return ""; return String(v).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function uniq(a) { return Array.from(new Set(a.filter(function (x) { return x != null && x !== ""; }))); }
  function dev(id) { return (S.devices && S.devices[id]) || { name: id }; }
  function host(id) { var d = dev(id); return d.name || d.hostname || id; }

  // ---- enterprise device icons (white line glyphs on the group chip) ------
  function _svg(inner) {
    return "data:image/svg+xml;utf8," + encodeURIComponent(
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' " +
      "stroke='#ffffff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'>" + inner + "</svg>");
  }
  var SV_ICONS = {
    ROUTER:      _svg("<circle cx='12' cy='12' r='3'/><path d='M12 9V3M12 21v-6M9 12H3M21 12h-6'/><path d='M7 7l2.5 2.5M17 7l-2.5 2.5M7 17l2.5-2.5M17 17l-2.5-2.5'/>"),
    SWITCH:      _svg("<rect x='3' y='8' width='18' height='8' rx='1'/><path d='M16 12h-5M14 10l2 2-2 2'/><path d='M8 12h5M10 14l-2-2 2-2'/>"),
    NGFW:        _svg("<rect x='3' y='4' width='18' height='16' rx='1'/><path d='M3 9.5h18M3 15h18M9 4v5.5M15 9.5V15M9 15v5M15 15v5'/>"),
    WAF:         _svg("<path d='M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z'/><path d='M5.5 11h13M12 4.5v14'/>"),
    PROXY:       _svg("<rect x='9.5' y='3' width='5' height='18' rx='1'/><path d='M2 8h6M5 5l-3 3 3 3'/><path d='M22 16h-6M19 13l3 3-3 3'/>"),
    VPN:         _svg("<rect x='5' y='11' width='14' height='9' rx='2'/><path d='M8 11V8a4 4 0 0 1 8 0v3'/><circle cx='12' cy='15.5' r='1.3'/>"),
    DNS:         _svg("<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18'/>"),
    DC:          _svg("<rect x='3' y='3' width='6.5' height='5' rx='1'/><rect x='3' y='16' width='6.5' height='5' rx='1'/><rect x='14.5' y='16' width='6.5' height='5' rx='1'/><path d='M6.25 8v3.5h11.5V16M6.25 11.5V16'/>"),
    SERVER:      _svg("<rect x='4' y='3' width='16' height='7' rx='1'/><rect x='4' y='14' width='16' height='7' rx='1'/><path d='M7.5 6.5h.01M7.5 17.5h.01M11 6.5h6M11 17.5h6'/>"),
    WORKSTATION: _svg("<rect x='3' y='4' width='18' height='12' rx='1'/><path d='M8 20h8M12 16v4'/>"),
    CLOUD:       _svg("<path d='M7 18a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.3A3.5 3.5 0 0 1 18 18z'/>"),
    INTERNET:    _svg("<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18'/>"),
    ISP:         _svg("<path d='M12 7v14M8.5 21h7'/><path d='M6 8.5a8 8 0 0 1 12 0M8.8 11a4.5 4.5 0 0 1 6.4 0'/>"),
    ATTACKER:    _svg("<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='3.5'/><path d='M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4'/>"),
    GENERIC:     _svg("<rect x='4' y='4' width='16' height='16' rx='2'/><circle cx='12' cy='12' r='3'/>")
  };
  var _ICON_ALIAS = {
    FIREWALL: "NGFW", PALOALTO: "NGFW", FORTIGATE: "NGFW", CHECKPOINT: "NGFW",
    PC: "WORKSTATION", CLIENT: "WORKSTATION", LAPTOP: "WORKSTATION", ENDPOINT: "WORKSTATION", HOST: "WORKSTATION", DESKTOP: "WORKSTATION",
    AD: "DC", DOMAIN_CONTROLLER: "DC", "DOMAIN CONTROLLER": "DC",
    WEB: "SERVER", WEBSERVER: "SERVER", APP: "SERVER", DB: "SERVER", DATABASE: "SERVER", MAIL: "SERVER",
    GATEWAY: "ROUTER", L3SWITCH: "SWITCH",
    WWW: "INTERNET", EXTERNAL: "INTERNET",
    ADVERSARY: "ATTACKER", C2: "ATTACKER", KALI: "ATTACKER"
  };
  var _GROUP_ICON = { security: "NGFW", network: "ROUTER", server: "SERVER", endpoint: "WORKSTATION", cloud: "CLOUD", other: "GENERIC" };

  // Resolve a definitive icon key from a hostname (most specific signal).
  function roleFromHost(hn) {
    var H = String(hn || "").toUpperCase();
    if (/ATTACK|ADVERS|KALI|\bC2\b|MALICIOUS|THREAT/.test(H)) return "ATTACKER";
    if (/INTERNET|\bWWW\b|EXTERNAL|PUBLIC-NET/.test(H)) return "INTERNET";
    if (/\bISP\b/.test(H)) return "ISP";
    if (/DNS/.test(H)) return "DNS";
    if (/\bAD\b|DC\b|DOMAIN/.test(H)) return "DC";
    if (/WAF/.test(H)) return "WAF";
    if (/PROXY/.test(H)) return "PROXY";
    if (/VPN/.test(H)) return "VPN";
    if (/NGFW|FIREWALL|\bFW\b|PERIM/.test(H)) return "NGFW";
    if (/WEB|MAIL|SMTP|SIEM|FILE|APP|\bDB\b|SQL|SERVER|SRV/.test(H)) return "SERVER";
    if (/CLOUD|\bVPC\b|AWS|AZURE|\bGCP\b/.test(H)) return "CLOUD";
    if (/SWITCH|\bSW\b|-SW|ACCESS-|CORE-SW|DMZ-SW/.test(H)) return "SWITCH";
    if (/ROUTER|\bRTR\b|EDGE|\bGW\b|GATEWAY/.test(H)) return "ROUTER";
    if (/\bWS\b|WS-|\bPC\b|LAPTOP|GUEST|CLIENT|WKS|DESKTOP/.test(H)) return "WORKSTATION";
    return null;
  }
  function iconFor(ntype, group, hn) {
    var r = roleFromHost(hn);
    if (r && SV_ICONS[r]) return SV_ICONS[r];
    var k = String(ntype || "").toUpperCase().trim();
    if (SV_ICONS[k]) return SV_ICONS[k];
    if (_ICON_ALIAS[k] && SV_ICONS[_ICON_ALIAS[k]]) return SV_ICONS[_ICON_ALIAS[k]];
    return SV_ICONS[_GROUP_ICON[group]] || SV_ICONS.GENERIC;
  }

  // ---- deterministic display metrics (display-only; Module 4 may override) -
  function hashStr(s) { var h = 2166136261; s = String(s); for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 16777619) >>> 0; } return h >>> 0; }
  function rng(seed) { var st = seed >>> 0; return function () { st = (st * 1664525 + 1013904223) >>> 0; return st / 4294967296; }; }
  function metricsFor(id, d) {
    if (d && d.metrics && typeof d.metrics.cpu === "number") return d.metrics;
    var r = rng(hashStr(id));
    var cpu = Math.round(6 + r() * 78), mem = Math.round(18 + r() * 70), util = Math.round(5 + r() * 80);
    var traffic = Math.round(r() * 920 + 30), lat = Math.round((r() * 38 + 0.4) * 10) / 10;
    return { cpu: cpu, mem: mem, util: util, traffic: traffic, latency: lat };
  }
  function edgeMetricsFor(eid) {
    var r = rng(hashStr(eid));
    var util = Math.round(4 + r() * 88), lat = Math.round((r() * 22 + 0.3) * 10) / 10;
    var bw = [1, 1, 10, 10, 25, 40][Math.floor(r() * 6)];
    var enc = r() > 0.45;
    var status = util > 88 ? "blocked" : util > 78 ? "congested" : "healthy";
    return { util: util, latency: lat, bw: bw, enc: enc, status: status };
  }
  function meterClass(p) { return p >= 85 ? "sv-hot" : p >= 60 ? "sv-warn" : "sv-ok"; }

  // ---- defensive extractors ----------------------------------------------
  function _ids(arr) {
    if (!Array.isArray(arr)) return [];
    if (arr.length && typeof arr[0] === "object")
      return arr.map(function (h) { return h.to || h.node || h.host || h.hostname || h.id || h.dst || h.target || h.name; }).filter(Boolean);
    return arr.slice();
  }
  function packetRoute(p) { return _ids(p.path || p.route || p.hops || p.trail || p.nodes || p.hostnames); }
  function packetKlass(p) {
    var k = p.klass || p["class"] || p.kind || p.category || p.type || "normal";
    var map = { normal: "http", internal: "http", dns: "dns", vpn: "vpn", suspicious: "ssh",
      blocked: "blocked", dropped: "blocked", malware: "malware" };
    return map[k] || "http";
  }
  function packetColor(p) {
    if (p.color) return p.color;
    var cls = p.klass || p["class"] || p.kind || p.type, colors = S.colors || {};
    return (cls && colors[cls]) || colors.normal || "#22c55e";
  }
  function attackRoute() { var a = S.attack || {}; return _ids(a.path || a.route || a.hops || a.longest_path || a.trail || a.nodes); }
  function facetGroups() { var v = []; (S.nodes || []).forEach(function (n) { if (n.group) v.push(n.group); }); return uniq(v).sort(); }

  // ---- supplemental styles owned by the renderer --------------------------
  function injectStyles() {
    if (document.getElementById("sv-dyn-style")) return;
    var s = el("style"); s.id = "sv-dyn-style";
    s.textContent =
      ".sv-packet-layer{position:absolute;inset:0;pointer-events:none;z-index:4;overflow:hidden;}" +
      ".sv-hovercard{position:absolute;z-index:9;min-width:212px;max-width:264px;padding:11px 13px;" +
      "background:var(--sv-glass,rgba(27,36,51,.72));backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);" +
      "border:1px solid var(--sv-border,#243044);border-radius:14px;box-shadow:var(--sv-shadow-lg);pointer-events:none;" +
      "opacity:0;transform:translateY(6px);transition:opacity .14s,transform .14s;font:12px var(--sv-font);color:var(--sv-text,#e6edf3);}" +
      ".sv-hovercard.sv-show{opacity:1;transform:translateY(0);}" +
      ".sv-hc-head{display:flex;gap:9px;align-items:center;margin-bottom:9px;}" +
      ".sv-hc-ico{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;border:1px solid var(--sv-border);background:var(--sv-surface-alt);}" +
      ".sv-hc-ico img{width:20px;height:20px;}" +
      ".sv-hc-name{font-weight:800;font-size:12.5px;letter-spacing:-.01em;}" +
      ".sv-hc-sub{color:var(--sv-text-muted);font-size:11px;}" +
      ".sv-hc-meta{display:flex;justify-content:space-between;font-size:11px;color:var(--sv-text-muted);margin:3px 0;}" +
      ".sv-hc-meta b{color:var(--sv-text);font-weight:700;}";
    document.head.appendChild(s);
  }

  // ----------------------------------------------------------- AssetConsole (drawer)
  function AssetConsole(root) {
    this.node = document.getElementById("socverse-panel") || el("div");
    this.node.id = "socverse-panel"; this.node.className = "sv-panel sv-hidden";
    if (!this.node.parentElement) root.appendChild(this.node);
  }
  AssetConsole.prototype.hide = function () { this.node.classList.add("sv-hidden"); };
  AssetConsole.prototype.show = function () {
    var n = this.node; n.classList.remove("sv-hidden"); n.classList.add("sv-slide");
    requestAnimationFrame(function () { n.classList.remove("sv-slide"); });
    n.scrollTop = 0;
  };
  AssetConsole.prototype._row = function (l, v, mono) { if (v == null || v === "") return ""; return '<div class="sv-row"><span>' + esc(l) + '</span><span class="' + (mono ? "sv-mono" : "") + '">' + esc(v) + "</span></div>"; };
  AssetConsole.prototype._meter = function (l, p) { p = Math.max(0, Math.min(100, Math.round(p))); return '<div class="sv-meter"><div class="sv-meter-top"><span>' + esc(l) + "</span><span>" + p + '%</span></div><div class="sv-meter-bar"><div class="sv-meter-fill ' + meterClass(p) + '" style="width:' + p + '%"></div></div></div>'; };
  AssetConsole.prototype._tags = function (items, cls) { if (!items || !items.length) return ""; return '<div class="sv-tags">' + items.map(function (it) { return '<span class="sv-tag ' + (cls || "") + '">' + esc(it) + "</span>"; }).join("") + "</div>"; };
  AssetConsole.prototype._sec = function (t, body) { if (!body) return ""; return '<div class="sv-section"><h4>' + esc(t) + "</h4>" + body + "</div>"; };
  AssetConsole.prototype.render = function (id) {
    var d = dev(id), kb = d.kb || {}, status = d.status || "healthy", self = this;
    var hn = host(id), m = metricsFor(id, d);
    var ic = iconFor(d.type, d.group, hn);

    var head = '<div class="sv-panel-head">' +
      '<div class="sv-panel-ico"><img alt="" src="' + ic + '"></div>' +
      '<div><div class="sv-panel-title">' + esc(hn) + '</div>' +
      '<div class="sv-panel-sub">' + esc(d.type || "device") + (d.vendor ? " &middot; " + esc(d.vendor) : "") + '</div></div>' +
      '<span class="sv-close">&times;</span></div>';

    var badges = '<div class="sv-section" style="display:flex;gap:8px;align-items:center;">' +
      '<span class="sv-badge sv-badge-' + esc(status) + '">' + esc(status) + "</span>" +
      (d.group ? '<span class="sv-tag">' + esc(d.group) + "</span>" : "") +
      (d.layer != null ? '<span class="sv-tag">L' + esc(d.layer) + "</span>" : "") + "</div>";

    var body = head + badges;
    body += this._sec("Overview", d.purpose ? '<div class="sv-row" style="display:block;color:var(--sv-text-muted);">' + esc(d.purpose) + "</div>" : "");
    body += this._sec("Live telemetry",
      this._meter("CPU", m.cpu) + this._meter("Memory", m.mem) + this._meter("Link utilization", m.util) +
      this._row("Throughput", m.traffic + " Mbps") + this._row("Latency", m.latency + " ms") +
      '<div class="sv-row"><span style="color:var(--sv-text-dim);font-size:10.5px;">metrics are illustrative (display-only)</span><span></span></div>');
    body += this._sec("Identity",
      this._row("Vendor", d.vendor) + this._row("OS", d.os) + this._row("Model", d.model) + this._row("Role", kb.role));
    var net = this._row("IP", d.ip, true) + this._row("MAC", d.mac, true);
    if (Array.isArray(d.interfaces) && d.interfaces.length)
      net += d.interfaces.map(function (i) { return self._row(i.name || "iface", (i.ip || "") + (i.up === false ? "  (down)" : ""), true); }).join("");
    body += this._sec("Network", net);
    if (Array.isArray(d.routes) && d.routes.length)
      body += this._sec("Routing", d.routes.slice(0, 8).map(function (r) { return self._row(r.destination || "0.0.0.0/0", "via " + (r.next_hop || r.interface || "-"), true); }).join(""));
    if (Array.isArray(d.open_ports) && d.open_ports.length)
      body += this._sec("Open ports", this._tags(d.open_ports.map(String), "sv-tag-port"));
    if (Array.isArray(d.osi_layers) && d.osi_layers.length)
      body += this._sec("OSI layers", this._tags(d.osi_layers.map(function (l) { return "L" + l; })));
    if (Array.isArray(kb.common_attacks) && kb.common_attacks.length)
      body += this._sec("Common attacks", this._tags(kb.common_attacks.map(function (a) { return a.name + (a.mitre ? " (" + a.mitre + ")" : ""); }), "sv-tag-risk"));
    if (Array.isArray(kb.detection) && kb.detection.length)
      body += this._sec("SOC detection", '<ul style="margin:0;padding-left:16px;color:var(--sv-text-muted);font-size:12px;line-height:1.6;">' + kb.detection.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>");
    if (Array.isArray(kb.hardening) && kb.hardening.length)
      body += this._sec("Hardening", '<ul style="margin:0;padding-left:16px;color:var(--sv-text-muted);font-size:12px;line-height:1.6;">' + kb.hardening.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>");
    if (Array.isArray(kb.cli_examples) && kb.cli_examples.length)
      body += this._sec("CLI examples", kb.cli_examples.map(function (c) { return '<div class="sv-code"><span class="sv-cmd">' + esc(c.label || "$") + "</span>\n" + esc(c.cmd || "") + "</div>"; }).join(""));

    this.node.innerHTML = body;
    var c = this.node.querySelector(".sv-close"); if (c) c.onclick = function () { self.hide(); };
    this.show();
  };

  // ----------------------------------------------------------- GraphRenderer
  function GraphRenderer(container) {
    var els = [];
    (S.nodes || []).forEach(function (n) {
      els.push({ data: { id: n.id, label: n.label || host(n.id), group: n.group || "other",
        ntype: n.type || "", status: n.status || "healthy", host: host(n.id) } });
    });
    (S.edges || []).forEach(function (e) {
      var s = e.source || e.src, t = e.target || e.dst; if (!s || !t) return;
      var eid = e.id || (s + "__" + t), em = edgeMetricsFor(eid);
      els.push({ data: { id: eid, source: s, target: t, lstatus: em.status, util: em.util, lat: em.latency, bw: em.bw, enc: em.enc } });
    });
    this.cy = cytoscape({
      container: container, elements: els, wheelSensitivity: 0.2, minZoom: 0.15, maxZoom: 3,
      style: [
        { selector: "node", style: {
          "shape": "round-rectangle",
          "background-color": function (n) { return GROUP_FILL[n.data("group")] || GROUP_FILL.other; },
          "background-image": function (n) { return iconFor(n.data("ntype"), n.data("group"), n.data("host")); },
          "background-fit": "none", "background-clip": "none",
          "background-width": "60%", "background-height": "60%",
          "background-position-x": "50%", "background-position-y": "50%",
          "border-width": 4, "border-color": function (n) { return STATUS_RING[n.data("status")] || STATUS_RING.healthy; },
          "label": "data(label)", "color": "#cbd5e1", "font-size": 9, "font-weight": 600,
          "text-valign": "bottom", "text-margin-y": 6, "text-max-width": "80px", "text-wrap": "ellipsis",
          "width": 46, "height": 46, "overlay-opacity": 0,
          "transition-property": "border-color, background-color, width, height, opacity", "transition-duration": "180ms" } },
        { selector: "node.sv-dim", style: { "opacity": 0.12 } },
        { selector: "node.sv-sel", style: { "border-color": "#38bdf8", "border-width": 7, "width": 56, "height": 56 } },
        { selector: "node.sv-lit", style: { "border-color": "#f97316", "border-width": 6, "width": 54, "height": 54,
          "overlay-color": "#f97316", "overlay-opacity": 0.18, "overlay-padding": 8 } },
        { selector: "edge", style: { "width": 2, "line-color": "#2a3a55", "target-arrow-color": "#2a3a55",
          "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.85 } },
        { selector: "edge[lstatus = 'congested']", style: { "line-color": "#f59e0b", "target-arrow-color": "#f59e0b", "line-style": "dashed" } },
        { selector: "edge[lstatus = 'blocked']", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444", "line-style": "dotted" } },
        { selector: "edge.sv-hl", style: { "width": 3.5, "line-color": "#38bdf8", "target-arrow-color": "#38bdf8", "z-index": 9 } },
        { selector: "edge.sv-dim", style: { "opacity": 0.07 } },
        { selector: "edge.sv-path", style: { "line-color": "#f97316", "target-arrow-color": "#f97316", "width": 4.5, "line-style": "solid", "z-index": 10 } }
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 34, rankSep: 100, edgeSep: 12 }
    });
  }
  GraphRenderer.prototype.fit = function () { this.cy.fit(undefined, 48); };

  // ----------------------------------------------------------- Minimap
  function Minimap(cy, root) {
    this.cy = cy; this.wrap = el("div", "sv-minimap"); this.canvas = el("canvas");
    this.canvas.width = 200; this.canvas.height = 132; this.wrap.appendChild(this.canvas); root.appendChild(this.wrap);
    this.ctx = this.canvas.getContext("2d"); this._scale = 1; this._ox = 0; this._oy = 0; this._bb = null;
    var self = this; this.canvas.addEventListener("click", function (ev) { self._onClick(ev); });
  }
  Minimap.prototype._compute = function () {
    var bb = this.cy.elements().boundingBox(); this._bb = bb;
    var pad = 9, w = this.canvas.width - pad * 2, h = this.canvas.height - pad * 2;
    this._scale = Math.min(w / (bb.w || 1), h / (bb.h || 1));
    this._ox = pad - bb.x1 * this._scale + (w - bb.w * this._scale) / 2;
    this._oy = pad - bb.y1 * this._scale + (h - bb.h * this._scale) / 2;
  };
  Minimap.prototype._mx = function (x) { return x * this._scale + this._ox; };
  Minimap.prototype._my = function (y) { return y * this._scale + this._oy; };
  Minimap.prototype._drawBase = function () {
    var ctx = this.ctx, cv = this.canvas, self = this;
    ctx.clearRect(0, 0, cv.width, cv.height); ctx.fillStyle = "#0b1120"; ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.strokeStyle = "#22324a"; ctx.lineWidth = 1;
    this.cy.edges().forEach(function (e) { var s = e.source().position(), t = e.target().position(); ctx.beginPath(); ctx.moveTo(self._mx(s.x), self._my(s.y)); ctx.lineTo(self._mx(t.x), self._my(t.y)); ctx.stroke(); });
    this.cy.nodes().forEach(function (n) { var p = n.position(); ctx.fillStyle = GROUP_FILL[n.data("group")] || GROUP_FILL.other; ctx.beginPath(); ctx.arc(self._mx(p.x), self._my(p.y), 2.4, 0, Math.PI * 2); ctx.fill(); });
  };
  Minimap.prototype._drawBox = function () {
    var ext = this.cy.extent(); this.ctx.strokeStyle = "#22d3ee"; this.ctx.lineWidth = 1.5;
    this.ctx.strokeRect(this._mx(ext.x1), this._my(ext.y1), (ext.x2 - ext.x1) * this._scale, (ext.y2 - ext.y1) * this._scale);
  };
  Minimap.prototype.draw = function () { try { this._compute(); this._drawBase(); this._drawBox(); } catch (e) {} };
  Minimap.prototype.updateViewport = function () { try { if (!this._bb) this._compute(); this._drawBase(); this._drawBox(); } catch (e) {} };
  Minimap.prototype._onClick = function (ev) {
    var r = this.canvas.getBoundingClientRect();
    var mx = (ev.clientX - r.left - this._ox) / this._scale, my = (ev.clientY - r.top - this._oy) / this._scale, z = this.cy.zoom();
    this.cy.pan({ x: this.cy.width() / 2 - mx * z, y: this.cy.height() / 2 - my * z }); this.updateViewport();
  };

  // ----------------------------------------------------------- PacketAnimator
  function PacketAnimator(cy, layer) { this.cy = cy; this.layer = layer; this.timer = null; this.dots = []; }
  PacketAnimator.prototype.clear = function () {
    if (this.timer) cancelAnimationFrame(this.timer); this.timer = null;
    var self = this; this.dots.forEach(function (d) { if (d.elt && d.elt.parentElement) self.layer.removeChild(d.elt); });
    this.dots = [];
    Array.prototype.slice.call(this.layer.querySelectorAll(".sv-trail")).forEach(function (t) { if (t.parentElement) t.parentElement.removeChild(t); });
  };
  PacketAnimator.prototype._modelPoint = function (positions, frac) {
    if (positions.length < 2) return positions[0] || null;
    var segs = positions.length - 1, t = frac * segs, i = Math.min(Math.floor(t), segs - 1), lt = t - i;
    var a = positions[i], b = positions[i + 1];
    return { x: a.x + (b.x - a.x) * lt, y: a.y + (b.y - a.y) * lt };
  };
  PacketAnimator.prototype._trail = function (x, y, color) {
    var t = el("div", "sv-trail"); t.style.color = color; t.style.transform = "translate(" + (x - 3.5) + "px," + (y - 3.5) + "px)";
    this.layer.appendChild(t); setTimeout(function () { if (t.parentElement) t.parentElement.removeChild(t); }, 560);
  };
  PacketAnimator.prototype.play = function (packets, opts) {
    this.clear(); opts = opts || {}; var self = this, cy = this.cy;
    (packets || []).forEach(function (p, idx) {
      var route = packetRoute(p); if (route.length < 2) return;
      var positions = route.map(function (id) { var n = cy.getElementById(id); return n && n.nonempty() ? n.position() : null; }).filter(Boolean);
      if (positions.length < 2) return;
      var col = packetColor(p), elt = el("div", "sv-packet sv-pk-" + packetKlass(p));
      elt.style.color = col; elt.style.background = col;
      self.layer.appendChild(elt);
      self.dots.push({ elt: elt, positions: positions, color: col, offset: (idx % 12) * 0.07, speed: 0.15 + (idx % 4) * 0.015, lastTrail: 0 });
    });
    var start = null, loop = opts.loop !== false;
    function frame(ts) {
      if (!start) start = ts;
      var elapsed = (ts - start) / 1000, z = cy.zoom(), pan = cy.pan(), active = false;
      self.dots.forEach(function (d) {
        var prog = elapsed * d.speed - d.offset;
        if (prog < 0) { d.elt.style.opacity = 0; active = true; return; }
        if (!loop && prog >= 1) { d.elt.style.opacity = 0; return; }
        active = true;
        var frac = loop ? prog % 1 : Math.min(prog, 1), mp = self._modelPoint(d.positions, frac);
        if (!mp) { d.elt.style.opacity = 0; return; }
        var sx = mp.x * z + pan.x, sy = mp.y * z + pan.y;
        d.elt.style.transform = "translate(" + (sx - 5.5) + "px," + (sy - 5.5) + "px)";
        d.elt.style.opacity = 1;
        if (elapsed - d.lastTrail > 0.07) { d.lastTrail = elapsed; self._trail(sx, sy, d.color); }
      });
      self.timer = active ? requestAnimationFrame(frame) : null;
    }
    if (self.dots.length) self.timer = requestAnimationFrame(frame);
    return self.dots.length;
  };

  // ----------------------------------------------------------- SocverseViz
  function SocverseViz() {
    injectStyles();
    this.root = document.getElementById("socverse-root");
    this.graph = new GraphRenderer(document.getElementById("cy"));
    this.cy = this.graph.cy;
    this.layer = el("div", "sv-packet-layer"); this.root.appendChild(this.layer);
    this.console = new AssetConsole(this.root);
    this.packets = new PacketAnimator(this.cy, this.layer);
    this.hover = el("div", "sv-hovercard"); this.root.appendChild(this.hover);
    this.atkTimers = []; this.mode = "play"; this.activeFacet = "";
    this._buildToolbar(); this._buildFacets(); this._buildLegend(); this._buildTimeline(); this._buildToast();
    this._wireGraph();
    this.minimap = new Minimap(this.cy, this.root);
    var self = this;
    this.cy.ready(function () {
      self.graph.fit(); self.minimap.draw();
      if ((S.packets || []).length) { if (!self.playAll()) self.attackMode(); }
      else if (attackRoute().length > 1) self.attackMode();
    });
    this.cy.on("pan zoom", function () { self.minimap.updateViewport(); });
    window.addEventListener("resize", function () { self.minimap.draw(); });
  }

  SocverseViz.prototype._wireGraph = function () {
    var self = this;
    this.cy.on("tap", "node", function (ev) { self.cy.nodes().removeClass("sv-sel"); ev.target.addClass("sv-sel"); self.console.render(ev.target.id()); });
    this.cy.on("tap", function (ev) { if (ev.target === self.cy) { self.console.hide(); self.cy.nodes().removeClass("sv-sel"); } });
    this.cy.on("mouseover", "node", function (ev) { ev.target.connectedEdges().addClass("sv-hl"); self._showHover(ev.target); });
    this.cy.on("mouseout", "node", function (ev) { ev.target.connectedEdges().removeClass("sv-hl"); self._hideHover(); });
    this.cy.on("mouseover", "edge", function (ev) { self._showEdgeHover(ev.target); });
    this.cy.on("mouseout", "edge", function () { self._hideHover(); });
    this.cy.on("pan zoom", function () { self._hideHover(); });
  };

  SocverseViz.prototype._showHover = function (n) {
    var id = n.id(), d = dev(id), m = metricsFor(id, d), status = d.status || "healthy";
    this.hover.innerHTML =
      '<div class="sv-hc-head"><div class="sv-hc-ico"><img alt="" src="' + iconFor(d.type, d.group, host(id)) + '"></div>' +
      '<div><div class="sv-hc-name">' + esc(host(id)) + '</div><div class="sv-hc-sub">' + esc(d.type || "device") + "</div></div></div>" +
      '<div class="sv-hc-meta"><span>Status</span><span class="sv-badge sv-badge-' + esc(status) + '">' + esc(status) + "</span></div>" +
      (d.ip ? '<div class="sv-hc-meta"><span>IP</span><b class="sv-mono">' + esc(d.ip) + "</b></div>" : "") +
      '<div class="sv-hc-meta"><span>CPU</span><b>' + m.cpu + '%</b></div>' +
      '<div class="sv-hc-meta"><span>Memory</span><b>' + m.mem + '%</b></div>' +
      '<div class="sv-hc-meta"><span>Throughput</span><b>' + m.traffic + ' Mbps</b></div>';
    this._placeHover(n.renderedPosition());
  };
  SocverseViz.prototype._showEdgeHover = function (e) {
    var d = e.data();
    this.hover.innerHTML =
      '<div class="sv-hc-head"><div><div class="sv-hc-name">' + esc(host(d.source)) + " &rarr; " + esc(host(d.target)) + "</div>" +
      '<div class="sv-hc-sub">link &middot; ' + esc(d.lstatus || "healthy") + "</div></div></div>" +
      '<div class="sv-hc-meta"><span>Bandwidth</span><b>' + esc(d.bw) + ' Gbps</b></div>' +
      '<div class="sv-hc-meta"><span>Utilization</span><b>' + esc(d.util) + '%</b></div>' +
      '<div class="sv-hc-meta"><span>Latency</span><b>' + esc(d.lat) + ' ms</b></div>' +
      '<div class="sv-hc-meta"><span>Encryption</span><b>' + (d.enc ? "TLS/IPsec" : "none") + "</b></div>";
    this._placeHover(e.midpoint ? e.midpoint() : e.source().renderedPosition());
  };
  SocverseViz.prototype._placeHover = function (rp) {
    var x = (rp.x || 0) + 18, y = (rp.y || 0) + 14, w = 264, vw = this.root.clientWidth;
    if (x + w > vw - 8) x = (rp.x || 0) - w - 18;
    this.hover.style.left = Math.max(8, x) + "px"; this.hover.style.top = Math.max(8, y) + "px";
    this.hover.classList.add("sv-show");
  };
  SocverseViz.prototype._hideHover = function () { this.hover.classList.remove("sv-show"); };

  SocverseViz.prototype._buildToolbar = function () {
    var self = this, bar = el("div", "sv-toolbar");
    bar.appendChild(el("div", "sv-brand", '<span class="sv-dot"></span>SOCVerse'));
    var search = el("div", "sv-search"); this.searchEl = el("input"); this.searchEl.type = "text"; this.searchEl.placeholder = "Search devices, IPs, types...";
    this.searchEl.addEventListener("input", function () { self._applyFilter(); }); search.appendChild(this.searchEl); bar.appendChild(search);
    bar.appendChild(el("div", "sv-spacer"));
    function mk(txt, fn, cls) { var b = el("button", "sv-btn" + (cls ? " " + cls : ""), txt); b.onclick = function () { fn(b); }; bar.appendChild(b); return b; }
    mk("Fit", function () { self.graph.fit(); self.minimap.updateViewport(); });
    this.btnPlay = mk("&#9654; Traffic", function () { self.playAll(); });
    this.btnAtk = mk("&#9888; Attack Path", function () { self.attackMode(); });
    this.btnTl = mk("Timeline", function () { self.toggleTimeline(); });
    mk("&#8635; Reset", function () { self.resetView(); }, "sv-btn-danger");
    this.root.appendChild(bar);
  };
  SocverseViz.prototype._buildFacets = function () {
    var self = this, wrap = el("div", "sv-facets"), groups = facetGroups();
    if (groups.length < 2) { this.facets = wrap; this.root.appendChild(wrap); return; }
    groups.forEach(function (g) {
      var c = el("button", "sv-chip", g); c.setAttribute("data-grp", g);
      c.onclick = function () { self.activeFacet = (self.activeFacet === g) ? "" : g; self._syncChips(); self._applyFilter(); };
      wrap.appendChild(c);
    });
    this.facets = wrap; this.root.appendChild(wrap);
  };
  SocverseViz.prototype._syncChips = function () {
    var self = this;
    Array.prototype.slice.call(this.facets.querySelectorAll(".sv-chip")).forEach(function (c) {
      c.classList.toggle("sv-on", c.getAttribute("data-grp") === self.activeFacet);
    });
  };
  SocverseViz.prototype._buildLegend = function () {
    var leg = el("div", "sv-legend"); leg.appendChild(el("div", "sv-leg-title", "Device groups"));
    [["security", "Security"], ["network", "Network"], ["server", "Server"], ["endpoint", "Endpoint"], ["cloud", "Cloud"]].forEach(function (p) {
      var r = el("div", "sv-leg-row"); r.innerHTML = '<span class="sv-leg-sw" style="background:' + GROUP_FILL[p[0]] + '"></span>' + p[1]; leg.appendChild(r);
    });
    leg.appendChild(el("div", "sv-leg-row", '<span class="sv-leg-sw" style="background:transparent;border:2px solid var(--sv-st-attack)"></span>ring = health'));
    this.root.appendChild(leg);
  };
  SocverseViz.prototype._buildToast = function () { this.toastEl = el("div", "sv-toast"); this.root.appendChild(this.toastEl); };
  SocverseViz.prototype.toast = function (msg) {
    var t = this.toastEl; t.textContent = msg; t.classList.add("sv-show");
    clearTimeout(this._toastT); this._toastT = setTimeout(function () { t.classList.remove("sv-show"); }, 1800);
  };

  SocverseViz.prototype._buildTimeline = function () {
    this.tl = el("div", "sv-timeline"); var route = attackRoute();
    if (route.length < 2) { this.root.appendChild(this.tl); if (this.btnTl) this.btnTl.style.display = "none"; return; }
    var html = "";
    for (var i = 0; i < route.length; i++) {
      html += '<div class="sv-tl-step"><div class="sv-tl-node" data-i="' + i + '">' +
        '<span class="sv-tl-dot"></span><span class="sv-tl-lbl">' + esc(host(route[i])) + "</span></div>";
      if (i < route.length - 1) html += '<span class="sv-tl-link"></span>';
      html += "</div>";
    }
    this.tl.innerHTML = html; this.root.appendChild(this.tl);
  };
  SocverseViz.prototype.toggleTimeline = function () {
    var on = this.tl.classList.toggle("sv-show");
    if (this.btnTl) this.btnTl.classList.toggle("sv-active", on);
  };
  SocverseViz.prototype._markTimeline = function (i) {
    var dots = this.tl.querySelectorAll(".sv-tl-node"), links = this.tl.querySelectorAll(".sv-tl-link");
    if (dots[i]) { var d = dots[i].querySelector(".sv-tl-dot"); if (d) d.classList.add("sv-done"); }
    if (links[i - 1]) links[i - 1].classList.add("sv-done");
  };
  SocverseViz.prototype._clearTimelineMarks = function () {
    Array.prototype.slice.call(this.tl.querySelectorAll(".sv-done")).forEach(function (n) { n.classList.remove("sv-done"); });
  };

  SocverseViz.prototype._focus = function (n) {
    var cy = this.cy; cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), 1.15) }, { duration: 300 });
    cy.nodes().removeClass("sv-sel"); n.addClass("sv-sel");
  };
  SocverseViz.prototype._applyFilter = function () {
    var term = (this.searchEl.value || "").trim().toLowerCase(), grp = this.activeFacet, first = null, count = 0;
    this.cy.nodes().forEach(function (n) {
      var id = n.id(), d = dev(id), ok = true;
      if (grp && n.data("group") !== grp) ok = false;
      if (term) { var hay = (id + " " + host(id) + " " + (n.data("ntype") || "") + " " + (d.ip || "")).toLowerCase(); if (hay.indexOf(term) === -1) ok = false; }
      if (ok) { n.removeClass("sv-dim"); count++; if (!first) first = n; } else n.addClass("sv-dim");
    });
    this.cy.edges().forEach(function (e) { if (e.source().hasClass("sv-dim") || e.target().hasClass("sv-dim")) e.addClass("sv-dim"); else e.removeClass("sv-dim"); });
    if (term && count === 1 && first) this._focus(first);
    this.minimap.updateViewport();
  };

  SocverseViz.prototype._clearAttack = function () {
    this.atkTimers.forEach(clearTimeout); this.atkTimers = [];
    this.cy.nodes().removeClass("sv-lit"); this.cy.edges().removeClass("sv-path");
    this._clearTimelineMarks();
  };

  SocverseViz.prototype.playAll = function () {
    this._clearAttack();
    this.cy.nodes().removeClass("sv-dim"); this.cy.edges().removeClass("sv-dim");
    var n = this.packets.play(S.packets || [], { loop: true });
    this.mode = "play";
    if (this.btnPlay) this.btnPlay.classList.add("sv-active");
    if (this.btnAtk) this.btnAtk.classList.remove("sv-active");
    if (n) this.toast(n + " packet flows animating");
    return n;
  };

  SocverseViz.prototype.attackMode = function () {
    var route = attackRoute(); if (route.length < 2) { this.toast("No attack path in this snapshot"); return 0; }
    this._clearAttack();
    var routeSet = {}; route.forEach(function (r) { routeSet[r] = 1; });
    this.cy.nodes().forEach(function (n) { n.toggleClass("sv-dim", !routeSet[n.id()]); });
    var self = this;
    this.cy.edges().forEach(function (e) {
      var on = false;
      for (var i = 0; i < route.length - 1; i++) { if ((e.data("source") === route[i] && e.data("target") === route[i + 1]) || (e.data("source") === route[i + 1] && e.data("target") === route[i])) { on = true; break; } }
      e.toggleClass("sv-dim", !on);
    });
    route.forEach(function (id, i) {
      var t = setTimeout(function () {
        var n = self.cy.getElementById(id); if (n && n.nonempty()) n.addClass("sv-lit");
        if (i > 0) { var e = self.cy.getElementById(route[i - 1] + "__" + route[i]); if (!e || !e.nonempty()) e = self.cy.getElementById(route[i] + "__" + route[i - 1]); if (e && e.nonempty()) e.addClass("sv-path"); }
        self._markTimeline(i);
      }, i * 240);
      self.atkTimers.push(t);
    });
    var col = (S.colors && (S.colors.malware || S.colors.suspicious || S.colors.blocked)) || "#ec4899";
    var klass = (S.attack && S.attack.success) ? "malware" : "suspicious";
    var pkts = []; for (var k = 0; k < 6; k++) pkts.push({ path: route, color: col, klass: klass });
    this.packets.play(pkts, { loop: true });
    this.tl.classList.add("sv-show"); if (this.btnTl) this.btnTl.classList.add("sv-active");
    this.mode = "attack";
    if (this.btnAtk) this.btnAtk.classList.add("sv-active");
    if (this.btnPlay) this.btnPlay.classList.remove("sv-active");
    this.toast("Attack path: " + route.map(host).join(" \u2192 "));
    return route.length;
  };

  SocverseViz.prototype.resetView = function () {
    this.searchEl.value = ""; this.activeFacet = ""; if (this.facets) this._syncChips();
    this._clearAttack();
    this.cy.nodes().removeClass("sv-dim sv-sel sv-lit"); this.cy.edges().removeClass("sv-dim sv-path sv-hl");
    this.packets.clear(); this.console.hide(); this._hideHover();
    this.tl.classList.remove("sv-show"); if (this.btnTl) this.btnTl.classList.remove("sv-active");
    this.graph.fit(); this.minimap.draw();
    if ((S.packets || []).length) { if (!this.playAll()) this.attackMode(); }
    else { this.mode = "play"; }
    this.toast("View reset");
  };

  function boot() { try { window.__socverse = new SocverseViz(); } catch (e) { console.error("SOCVerse viz failed:", e); } }
  if (document.readyState !== "loading") boot(); else document.addEventListener("DOMContentLoaded", boot);
})();
