/* SOCVerse interactive renderer - Modules 4A + 4B.
   GraphRenderer, AssetConsole, Minimap, PacketAnimator, Timeline, orchestrated
   by SocverseViz. Consumes window.SOCVERSE from snapshot.py. Route/color/path
   extraction is defensive so it adapts to the snapshot's exact field names. */
(function () {
  "use strict";
  var S = window.SOCVERSE || { nodes: [], edges: [], devices: {}, timeline: [], packets: [], colors: {}, soc: {}, attack: {} };

  var GROUP_FILL = { security: "#f43f5e", network: "#3b82f6", server: "#22c55e",
    endpoint: "#a855f7", cloud: "#06b6d4", other: "#94a3b8" };
  var STATUS_RING = { healthy: "#22c55e", warning: "#f59e0b", critical: "#ef4444",
    offline: "#64748b", "under-attack": "#f97316", compromised: "#ec4899" };

  function el(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }
  function esc(v) { if (v == null) return ""; return String(v).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function uniq(a) { return Array.from(new Set(a.filter(function (x) { return x != null && x !== ""; }))); }
  function dev(id) { return (S.devices && S.devices[id]) || { hostname: id }; }

  // ---- defensive extractors (adapt to snapshot field names) ----
  function _ids(arr) {
    if (!Array.isArray(arr)) return [];
    if (arr.length && typeof arr[0] === "object")
      return arr.map(function (h) { return h.to || h.node || h.host || h.hostname || h.id || h.dst || h.target || h.name; }).filter(Boolean);
    return arr.slice();
  }
  function packetRoute(p) { return _ids(p.path || p.route || p.hops || p.trail || p.nodes || p.hostnames); }
  function packetColor(p) {
    if (p.color) return p.color;
    var cls = p["class"] || p.klass || p.kind || p.category || p.type;
    var colors = S.colors || {};
    return (cls && colors[cls]) || colors.normal || "#22c55e";
  }
  function attackRoute() {
    var a = S.attack || {};
    return _ids(a.path || a.route || a.hops || a.longest_path || a.trail || a.nodes);
  }
  function tlDevice(e) { return e.device || e.host || e.hostname || e.source || e.src || e.node || e.target || null; }
  function tlText(e) { return e.text || e.message || e.summary || e.title || e.event || ""; }
  function tlTime(e) { return e.time || e.clock || e.timestamp || e.ts || ""; }
  function sevIndex(e) {
    var s = e.severity != null ? e.severity : e.level;
    if (typeof s === "number") return Math.max(0, Math.min(5, Math.round(s)));
    s = String(s || "").toLowerCase();
    var m = { info: 1, low: 2, notice: 1, medium: 3, warning: 3, high: 4, critical: 5 };
    return m[s] != null ? m[s] : 1;
  }
  function facetValues(field) {
    var vals = [];
    (S.nodes || []).forEach(function (n) {
      var d = dev(n.id), v;
      if (field === "group") v = n.group || d.group;
      else if (field === "type") v = n.type || d.type;
      else v = d.department || d.zone || d.location;
      if (v) vals.push(v);
    });
    return uniq(vals).sort();
  }

  // ----------------------------------------------------------- AssetConsole
  function AssetConsole(root) {
    this.node = document.getElementById("socverse-panel") || el("div");
    this.node.id = "socverse-panel"; this.node.className = "sv-console sv-hidden";
    if (!this.node.parentElement) root.appendChild(this.node);
  }
  AssetConsole.prototype.hide = function () { this.node.classList.add("sv-hidden"); };
  AssetConsole.prototype.show = function () { this.node.classList.remove("sv-hidden"); };
  AssetConsole.prototype._kv = function (l, v) { if (v == null || v === "") return ""; return '<div class="sv-kv"><span>' + esc(l) + "</span><span>" + esc(v) + "</span></div>"; };
  AssetConsole.prototype._list = function (items, fmt) { if (!items || !items.length) return ""; return '<ul class="sv-list">' + items.map(function (it) { return "<li>" + (fmt ? fmt(it) : esc(it)) + "</li>"; }).join("") + "</ul>"; };
  AssetConsole.prototype._sec = function (t, b) { if (!b) return ""; return '<div class="sv-sec"><div class="sv-sec-h">' + esc(t) + "</div>" + b + "</div>"; };
  AssetConsole.prototype.render = function (id) {
    var d = dev(id), kb = d.kb || {}, status = d.status || "healthy", self = this;
    var h = '<span class="sv-close">x</span><div class="sv-title">' + esc(d.hostname || id) + "</div>";
    h += '<div class="sv-badges"><span class="sv-badge sv-grp-' + esc(d.group || "other") + '">' + esc(d.type || "device") + "</span>" +
         '<span class="sv-badge sv-st-' + esc(status) + '">' + esc(status) + "</span></div>";
    if (kb.role) h += '<div class="sv-role">' + esc(kb.role) + "</div>";
    h += this._sec("Identity", this._kv("Vendor", d.vendor) + this._kv("OS", d.os) + this._kv("Model", d.model) +
      this._kv("Role", d.role) + this._kv("CPU", d.cpu) + this._kv("RAM", d.ram) + this._kv("Location", d.location) +
      this._kv("Department", d.department || d.zone));
    var net = this._kv("IP", d.ip) + this._kv("MAC", d.mac) + this._kv("Gateway", d.gateway);
    if (Array.isArray(d.interfaces)) net += this._list(d.interfaces, function (i) { return typeof i === "string" ? esc(i) : esc((i.name || i.id || "if") + "  " + (i.ip || "") + "  " + (i.mac || "")); });
    h += this._sec("Network", net);
    if (Array.isArray(d.routes) && d.routes.length) h += this._sec("Routing", this._list(d.routes, function (r) { return typeof r === "string" ? esc(r) : esc((r.dest || r.network || "") + " via " + (r.via || r.next_hop || r.gateway || "")); }));
    var svc = "";
    if (Array.isArray(d.services)) svc += this._list(d.services, function (s) { return typeof s === "string" ? esc(s) : esc((s.name || "") + "  " + (s.port || "") + "/" + (s.protocol || "")); });
    if (Array.isArray(d.ports)) svc += this._list(d.ports, function (p) { return typeof p === "object" ? esc((p.port || "") + "/" + (p.protocol || "") + "  " + (p.state || "")) : esc(p); });
    h += this._sec("Services & Ports", svc);
    if (d.osi) h += this._sec("OSI Layers", this._kv("Operates at", Array.isArray(d.osi) ? d.osi.join(", ") : d.osi));
    if (Array.isArray(kb.common_attacks) && kb.common_attacks.length) h += this._sec("Common Attacks",
      '<div class="sv-chips">' + kb.common_attacks.map(function (a) { return '<span class="sv-chip" title="' + esc(a.note || "") + '">' + esc(a.name) + (a.mitre ? " <em>" + esc(a.mitre) + "</em>" : "") + "</span>"; }).join("") + "</div>");
    h += this._sec("Detection", this._list(kb.detection));
    h += this._sec("SOC Investigation", this._list(kb.investigation));
    h += this._sec("Hardening", this._list(kb.hardening));
    if (Array.isArray(kb.cli_examples) && kb.cli_examples.length) h += this._sec("CLI Examples",
      '<div class="sv-cli">' + kb.cli_examples.map(function (c) { return '<div class="sv-cmd"><span>' + esc(c.label || "") + '</span><code>' + esc(c.cmd || "") + "</code></div>"; }).join("") + "</div>");
    if (Array.isArray(kb.rfcs) && kb.rfcs.length) h += this._sec("Reference RFCs", this._list(kb.rfcs, function (r) { return "<strong>" + esc(r.id) + "</strong> " + esc(r.title || ""); }));
    this.node.innerHTML = h;
    var c = this.node.querySelector(".sv-close"); if (c) c.onclick = function () { self.hide(); };
    this.show();
  };

  // ----------------------------------------------------------- GraphRenderer
  function GraphRenderer(container) {
    var els = [];
    (S.nodes || []).forEach(function (n) { els.push({ data: { id: n.id, label: n.label || n.id, group: n.group || "other", ntype: n.type || "", status: n.status || "healthy" } }); });
    (S.edges || []).forEach(function (e) { var s = e.source || e.src, t = e.target || e.dst; if (s && t) els.push({ data: { id: e.id || (s + "__" + t), source: s, target: t } }); });
    this.cy = cytoscape({
      container: container, elements: els, wheelSensitivity: 0.2, minZoom: 0.15, maxZoom: 3,
      style: [
        { selector: "node", style: {
          "background-color": function (n) { return GROUP_FILL[n.data("group")] || GROUP_FILL.other; },
          "border-width": 4, "border-color": function (n) { return STATUS_RING[n.data("status")] || STATUS_RING.healthy; },
          "label": "data(label)", "color": "#cbd5e1", "font-size": 9, "font-weight": 600,
          "text-valign": "bottom", "text-margin-y": 5, "width": 32, "height": 32,
          "transition-property": "border-color, background-color, width, height", "transition-duration": "180ms" } },
        { selector: "node.sv-dim", style: { "opacity": 0.12 } },
        { selector: "node.sv-sel", style: { "border-color": "#38bdf8", "border-width": 7, "width": 40, "height": 40 } },
        { selector: "edge", style: { "width": 2, "line-color": "#2a3a55", "target-arrow-color": "#2a3a55",
          "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
        { selector: "edge.sv-dim", style: { "opacity": 0.08 } },
        { selector: "edge.sv-path", style: { "line-color": "#f97316", "target-arrow-color": "#f97316", "width": 4.5 } }
      ],
      layout: { name: "dagre", rankDir: "LR", nodeSep: 34, rankSep: 95, edgeSep: 10 }
    });
  }
  GraphRenderer.prototype.fit = function () { this.cy.fit(undefined, 45); };

  // ----------------------------------------------------------- Minimap
  function Minimap(cy, root) {
    this.cy = cy; this.wrap = el("div", "sv-minimap"); this.canvas = el("canvas");
    this.canvas.width = 190; this.canvas.height = 130; this.wrap.appendChild(this.canvas); root.appendChild(this.wrap);
    this.ctx = this.canvas.getContext("2d"); this._bb = null; this._scale = 1; this._ox = 0; this._oy = 0;
    var self = this; this.canvas.addEventListener("click", function (ev) { self._onClick(ev); });
  }
  Minimap.prototype._compute = function () {
    var bb = this.cy.elements().boundingBox(); this._bb = bb;
    var pad = 8, w = this.canvas.width - pad * 2, h = this.canvas.height - pad * 2;
    this._scale = Math.min(w / (bb.w || 1), h / (bb.h || 1));
    this._ox = pad - bb.x1 * this._scale + (w - bb.w * this._scale) / 2;
    this._oy = pad - bb.y1 * this._scale + (h - bb.h * this._scale) / 2;
  };
  Minimap.prototype._mx = function (x) { return x * this._scale + this._ox; };
  Minimap.prototype._my = function (y) { return y * this._scale + this._oy; };
  Minimap.prototype._drawBase = function () {
    var ctx = this.ctx, cv = this.canvas, self = this;
    ctx.clearRect(0, 0, cv.width, cv.height); ctx.fillStyle = "#0b1220"; ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.strokeStyle = "#1e293b"; ctx.lineWidth = 1;
    this.cy.edges().forEach(function (e) { var s = e.source().position(), t = e.target().position(); ctx.beginPath(); ctx.moveTo(self._mx(s.x), self._my(s.y)); ctx.lineTo(self._mx(t.x), self._my(t.y)); ctx.stroke(); });
    this.cy.nodes().forEach(function (n) { var p = n.position(); ctx.fillStyle = GROUP_FILL[n.data("group")] || GROUP_FILL.other; ctx.beginPath(); ctx.arc(self._mx(p.x), self._my(p.y), 2.2, 0, Math.PI * 2); ctx.fill(); });
  };
  Minimap.prototype._drawBox = function () {
    var ext = this.cy.extent(); this.ctx.strokeStyle = "#38bdf8"; this.ctx.lineWidth = 1.5;
    this.ctx.strokeRect(this._mx(ext.x1), this._my(ext.y1), (ext.x2 - ext.x1) * this._scale, (ext.y2 - ext.y1) * this._scale);
  };
  Minimap.prototype.draw = function () { try { this._compute(); this._drawBase(); this._drawBox(); } catch (e) {} };
  Minimap.prototype.updateViewport = function () { try { if (!this._bb) this._compute(); this._drawBase(); this._drawBox(); } catch (e) {} };
  Minimap.prototype._onClick = function (ev) {
    var r = this.canvas.getBoundingClientRect();
    var mx = (ev.clientX - r.left - this._ox) / this._scale, my = (ev.clientY - r.top - this._oy) / this._scale, z = this.cy.zoom();
    this.cy.pan({ x: this.cy.width() / 2 - mx * z, y: this.cy.height() / 2 - my * z }); this.updateViewport();
  };

  // ----------------------------------------------------------- PacketAnimator (4B)
  function PacketAnimator(cy, layer) { this.cy = cy; this.layer = layer; this.timer = null; this.dots = []; }
  PacketAnimator.prototype.clear = function () {
    if (this.timer) cancelAnimationFrame(this.timer); this.timer = null;
    var self = this; this.dots.forEach(function (d) { if (d.elt && d.elt.parentElement) self.layer.removeChild(d.elt); });
    this.dots = []; this.cy.edges().removeClass("sv-path");
  };
  PacketAnimator.prototype._modelPoint = function (positions, frac) {
    if (positions.length < 2) return positions[0] || null;
    var segs = positions.length - 1, t = frac * segs, i = Math.min(Math.floor(t), segs - 1), lt = t - i;
    var a = positions[i], b = positions[i + 1];
    return { x: a.x + (b.x - a.x) * lt, y: a.y + (b.y - a.y) * lt };
  };
  PacketAnimator.prototype.play = function (packets, opts) {
    this.clear(); opts = opts || {}; var self = this, cy = this.cy;
    (packets || []).forEach(function (p, idx) {
      var route = packetRoute(p); if (route.length < 2) return;
      var positions = route.map(function (id) { var n = cy.getElementById(id); return n && n.nonempty() ? n.position() : null; }).filter(Boolean);
      if (positions.length < 2) return;
      var col = packetColor(p), elt = el("div", "sv-packet");
      elt.style.background = col; elt.style.boxShadow = "0 0 8px " + col;
      self.layer.appendChild(elt);
      self.dots.push({ elt: elt, positions: positions, offset: (idx % 12) * 0.07, speed: 0.16 + (idx % 4) * 0.015 });
    });
    if (opts.attackRoute && opts.attackRoute.length > 1)
      for (var i = 0; i < opts.attackRoute.length - 1; i++) {
        var e = cy.getElementById(opts.attackRoute[i] + "__" + opts.attackRoute[i + 1]);
        if (e && e.nonempty()) e.addClass("sv-path");
      }
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
        d.elt.style.transform = "translate(" + (mp.x * z + pan.x - 4.5) + "px," + (mp.y * z + pan.y - 4.5) + "px)";
        d.elt.style.opacity = 1;
      });
      self.timer = active ? requestAnimationFrame(frame) : null;
    }
    if (self.dots.length) self.timer = requestAnimationFrame(frame);
    return self.dots.length;
  };

  // ----------------------------------------------------------- SocverseViz
  function SocverseViz() {
    this.root = document.getElementById("socverse-root");
    this.graph = new GraphRenderer(document.getElementById("cy"));
    this.cy = this.graph.cy;
    this.layer = el("div", "sv-packet-layer"); this.root.appendChild(this.layer);
    this.console = new AssetConsole(this.root);
    this.packets = new PacketAnimator(this.cy, this.layer);
    this.filters = {}; this.mode = "play";
    this._wireGraph(); this._buildToolbar(); this._buildLegend(); this._buildTimeline();
    this.minimap = new Minimap(this.cy, this.root);
    var self = this;
    this.cy.ready(function () {
      self.graph.fit(); self.minimap.draw();
      if ((S.packets || []).length) { var n = self.playAll(); if (!n) self.attackMode(); }
      else if (attackRoute().length > 1) self.attackMode();
    });
    this.cy.on("pan zoom", function () { self.minimap.updateViewport(); });
    window.addEventListener("resize", function () { self.minimap.draw(); });
  }
  SocverseViz.prototype._wireGraph = function () {
    var self = this;
    this.cy.on("tap", "node", function (ev) { self.cy.nodes().removeClass("sv-sel"); ev.target.addClass("sv-sel"); self.console.render(ev.target.id()); });
    this.cy.on("tap", function (ev) { if (ev.target === self.cy) { self.console.hide(); self.cy.nodes().removeClass("sv-sel"); } });
  };
  SocverseViz.prototype._buildToolbar = function () {
    var self = this, bar = el("div", "sv-toolbar");
    bar.appendChild(el("div", "sv-brand", "SOC<em>Verse</em>"));
    this.searchEl = el("input", "sv-search"); this.searchEl.type = "text"; this.searchEl.placeholder = "Search devices...";
    this.searchEl.addEventListener("input", function () { self._applyFilter(); }); bar.appendChild(this.searchEl);
    [["group", "Group"], ["type", "Type"], ["department", "Department"]].forEach(function (pair) {
      var vals = facetValues(pair[0]); if (vals.length < 2) return;
      var sel = el("select", "sv-select"); sel.appendChild(new Option(pair[1] + ": All", ""));
      vals.forEach(function (v) { sel.appendChild(new Option(v, v)); });
      sel.addEventListener("change", function () { self._applyFilter(); }); self.filters[pair[0]] = sel; bar.appendChild(sel);
    });
    function mk(txt, fn) { var b = el("button", "sv-btn", txt); b.onclick = function () { fn(b); }; bar.appendChild(b); return b; }
    mk("+", function () { self._zoom(1.25); });
    mk("-", function () { self._zoom(0.8); });
    mk("Fit", function () { self.graph.fit(); self.minimap.updateViewport(); });
    this.btnPlay = mk("Play", function () { self.playAll(); self._setMode("play"); });
    this.btnAtk = mk("Attack Path", function () { self.attackMode(); self._setMode("attack"); });
    mk("Clear", function () { self.packets.clear(); });
    this.btnTl = mk("Timeline", function () { self.toggleTimeline(); });
    mk("Reset", function () { self.resetView(); });
    this._buildSoc(bar);
    this.root.appendChild(bar);
  };
  SocverseViz.prototype._buildSoc = function (bar) {
    var stats = (S.soc && S.soc.stats) || {};
    Object.keys(stats).filter(function (k) { return typeof stats[k] === "number"; }).slice(0, 4).forEach(function (k) {
      bar.appendChild(el("span", "sv-stat", "<span>" + esc(k.replace(/_/g, " ")) + "</span><b>" + esc(stats[k]) + "</b>"));
    });
  };
  SocverseViz.prototype._setMode = function (m) {
    this.mode = m;
    if (this.btnPlay) this.btnPlay.classList.toggle("sv-on", m === "play");
    if (this.btnAtk) this.btnAtk.classList.toggle("sv-on", m === "attack");
  };
  SocverseViz.prototype.playAll = function () { var n = this.packets.play(S.packets || [], { loop: true, attackRoute: attackRoute() }); this._setMode("play"); return n; };
  SocverseViz.prototype.attackMode = function () {
    var route = attackRoute(); if (route.length < 2) return 0;
    var col = (S.colors && (S.colors.suspicious || S.colors.malware || S.colors.blocked)) || "#f59e0b";
    var pkts = []; for (var i = 0; i < 6; i++) pkts.push({ path: route, color: col });
    var n = this.packets.play(pkts, { loop: true, attackRoute: route }); this._setMode("attack"); return n;
  };
  SocverseViz.prototype._buildLegend = function () {
    var leg = el("div", "sv-legend");
    [["security", "Security"], ["network", "Network"], ["server", "Server"], ["endpoint", "Endpoint"], ["cloud", "Cloud"]].forEach(function (p) {
      var r = el("div", "sv-leg-row"); r.innerHTML = '<span class="dot" style="background:' + GROUP_FILL[p[0]] + '"></span>' + p[1]; leg.appendChild(r);
    });
    leg.appendChild(el("div", "sv-leg-row", '<span class="dot" style="background:transparent;border:2px solid #f97316"></span>border = status'));
    this.root.appendChild(leg);
  };
  SocverseViz.prototype._buildTimeline = function () {
    var self = this; this.tl = el("div", "sv-timeline sv-hidden"); this.tl.innerHTML = "<h4>Event Timeline</h4>";
    (S.timeline || []).forEach(function (e) {
      var device = tlDevice(e), sev = sevIndex(e), row = el("div", "sv-tl-row");
      row.innerHTML = '<span class="sv-tl-dot sv-sev-' + sev + '"></span><span class="sv-tl-time">' + esc(tlTime(e)) +
        '</span><span class="sv-tl-text">' + esc(tlText(e)) + (device ? ' <em style="color:#7dd3fc">[' + esc(device) + "]</em>" : "") + "</span>";
      if (device) row.onclick = function () { var n = self.cy.getElementById(device); if (n && n.nonempty()) { self._focus(n); self.console.render(device); } };
      self.tl.appendChild(row);
    });
    this.root.appendChild(this.tl);
  };
  SocverseViz.prototype.toggleTimeline = function () { this.tl.classList.toggle("sv-hidden"); if (this.btnTl) this.btnTl.classList.toggle("sv-on", !this.tl.classList.contains("sv-hidden")); };
  SocverseViz.prototype._zoom = function (f) { var cy = this.cy; cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); this.minimap.updateViewport(); };
  SocverseViz.prototype._focus = function (n) { var cy = this.cy; cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 300 }); cy.nodes().removeClass("sv-sel"); n.addClass("sv-sel"); };
  SocverseViz.prototype._applyFilter = function () {
    var term = (this.searchEl.value || "").trim().toLowerCase();
    var g = this.filters.group ? this.filters.group.value : "", t = this.filters.type ? this.filters.type.value : "", dep = this.filters.department ? this.filters.department.value : "";
    var first = null, count = 0;
    this.cy.nodes().forEach(function (n) {
      var id = n.id(), d = dev(id), grp = n.data("group"), typ = n.data("ntype") || d.type, department = d.department || d.zone || d.location, ok = true;
      if (g && grp !== g) ok = false; if (t && typ !== t) ok = false; if (dep && department !== dep) ok = false;
      if (term) { var hay = (id + " " + (d.hostname || "") + " " + (typ || "") + " " + (d.ip || "")).toLowerCase(); if (hay.indexOf(term) === -1) ok = false; }
      if (ok) { n.removeClass("sv-dim"); count++; if (!first) first = n; } else n.addClass("sv-dim");
    });
    this.cy.edges().forEach(function (e) { if (e.source().hasClass("sv-dim") || e.target().hasClass("sv-dim")) e.addClass("sv-dim"); else e.removeClass("sv-dim"); });
    if (term && count === 1 && first) this._focus(first);
    this.minimap.updateViewport();
  };
  SocverseViz.prototype.resetView = function () {
    this.searchEl.value = ""; Object.keys(this.filters).forEach(function (k) { this.filters[k].value = ""; }, this);
    this.cy.nodes().removeClass("sv-dim sv-sel"); this.cy.edges().removeClass("sv-dim sv-path");
    this.packets.clear(); this.console.hide(); this.tl.classList.add("sv-hidden");
    this.graph.fit(); this.minimap.draw();
    if ((S.packets || []).length) { if (!this.playAll()) this.attackMode(); }
  };

  function boot() { try { window.__socverse = new SocverseViz(); } catch (e) { console.error("SOCVerse viz failed:", e); } }
  if (document.readyState !== "loading") boot(); else document.addEventListener("DOMContentLoaded", boot);
})();
