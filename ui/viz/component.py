"""Streamlit embed bridge: turns a VizSnapshot dict into an interactive iframe.

Responsibilities (single, narrow):
  * Load the three vendored JS libraries from `assets/` and inline them so the
    visualization has ZERO runtime network dependency.
  * Load the application renderer (`socverse_viz.css` / `socverse_viz.js`,
    shipped by Module 4). If they are absent, fall back to a small built-in
    bootstrap so the graph still draws - useful while Module 4 is in progress.
  * Assemble one self-contained HTML document with the snapshot injected as
    `window.SOCVERSE`, and embed it via `st.components.v1.html`.

`build_html()` imports no Streamlit and is therefore pure and unit-testable;
`render_network()` is the thin Streamlit-facing wrapper.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_ASSETS = Path(__file__).resolve().parent / "assets"

# Vendored libraries, inlined in this order (cytoscape, then dagre, then the
# dagre layout adapter which registers itself against both globals).
_VENDOR = ("cytoscape.min.js", "dagre.min.js", "cytoscape-dagre.js")

# Application renderer files (Module 4). Optional until then.
_APP_CSS = "socverse_viz.css"
_APP_JS = "socverse_viz.js"


@lru_cache(maxsize=None)
def _read(name: str) -> str:
    """Read an asset file as UTF-8 text, or '' if it does not exist."""
    path = _ASSETS / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _vendor_blocks() -> str:
    """All vendored libraries wrapped in <script> tags, in dependency order."""
    out = []
    for name in _VENDOR:
        code = _read(name)
        if not code:
            raise FileNotFoundError(
                f"Vendored asset missing: {_ASSETS / name}. "
                "Download the Cytoscape/dagre libraries into ui/viz/assets/."
            )
        out.append("<script>\n" + code + "\n</script>")
    return "\n".join(out)


def _app_css() -> str:
    return _read(_APP_CSS) or _DEFAULT_CSS


def _app_js() -> str:
    return _read(_APP_JS) or _DEFAULT_JS

def build_html(snapshot: dict[str, Any], *, height: int = 720) -> str:
    """Assemble the complete, standalone HTML document for the iframe.

    Pure function: given a snapshot it returns a string. No Streamlit, no disk
    writes beyond reading cached assets. Safe to call from tests.

    Injects the shared design-system CSS variables (config.theme.css_variables)
    so socverse_viz.css can reference --sv-* tokens. Falls back gracefully if
    the theme module is unavailable.
    """
    try:
        from config.theme import css_variables
        tokens = css_variables()
    except Exception:
        tokens = ":root{--sv-bg:#0a0e16;--sv-surface:#131a26;--sv-text:#e6edf3;}"

    data = json.dumps(snapshot, ensure_ascii=False)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<style>",
        tokens,
        "html,body{margin:0;padding:0;height:100%;"
        "background:var(--sv-bg,#0a0e16);"
        "font-family:var(--sv-font,'Inter',system-ui,sans-serif);"
        "color:var(--sv-text,#e6edf3);}",
        "#socverse-root{position:relative;width:100%;height:" + str(height) + "px;}",
        _app_css(),
        "</style></head><body>",
        '<div id="socverse-root">',
        '  <div id="cy"></div>',
        '  <div id="socverse-panel" class="sv-panel sv-hidden"></div>',
        "</div>",
        _vendor_blocks(),
        "<script>window.SOCVERSE = " + data + ";</script>",
        "<script>\n" + _app_js() + "\n</script>",
        "</body></html>",
    ]
    return "\n".join(parts)

def render_network(snapshot: dict[str, Any], *, height: int = 720) -> None:
    """Embed the interactive network in the current Streamlit container."""
    import streamlit.components.v1 as components

    components.html(build_html(snapshot, height=height),
                    height=height, scrolling=False)


# --------------------------------------------------------------------------
# Built-in fallback renderer. Intentionally minimal: it proves the data path
# and lets us preview the graph before Module 4 ships the full engine. Module 4
# overrides these by writing assets/socverse_viz.css and socverse_viz.js.
# --------------------------------------------------------------------------
_DEFAULT_CSS = """
#cy{position:absolute;inset:0;width:100%;height:100%;}
.sv-panel{position:absolute;top:12px;right:12px;width:320px;max-height:92%;
  overflow:auto;background:#111c33;color:#e5e7eb;border:1px solid #1e293b;
  border-radius:10px;padding:14px 16px;font:13px/1.5 ui-sans-serif,system-ui;
  box-shadow:0 12px 40px rgba(0,0,0,.45);}
.sv-panel h3{margin:0 0 4px;font-size:15px;color:#f8fafc;}
.sv-panel .sv-sub{color:#94a3b8;font-size:12px;margin-bottom:10px;}
.sv-panel .sv-row{display:flex;justify-content:space-between;gap:10px;
  padding:3px 0;border-bottom:1px solid #1e293b;}
.sv-panel .sv-row span:first-child{color:#94a3b8;}
.sv-hidden{display:none;}
.sv-close{float:right;cursor:pointer;color:#64748b;font-size:16px;}
"""

_DEFAULT_JS = r"""
(function () {
  var S = window.SOCVERSE || { nodes: [], edges: [], devices: {} };
  var GROUP = {
    security: "#ef4444", network: "#3b82f6", server: "#22c55e",
    endpoint: "#a855f7", cloud: "#06b6d4", other: "#94a3b8"
  };
  var STATUS = {
    healthy: "#22c55e", warning: "#f59e0b", critical: "#ef4444",
    offline: "#64748b", "under-attack": "#f97316", compromised: "#ec4899"
  };

  var els = [];
  (S.nodes || []).forEach(function (n) {
    els.push({ data: {
      id: n.id, label: n.label || n.id,
      group: n.group || "other", status: n.status || "healthy"
    }});
  });
  (S.edges || []).forEach(function (e) {
    var s = e.source || e.src, t = e.target || e.dst;
    if (s && t) els.push({ data: { id: e.id || (s + "__" + t), source: s, target: t }});
  });

  var cy = cytoscape({
    container: document.getElementById("cy"),
    elements: els,
    wheelSensitivity: 0.2,
    style: [
      { selector: "node", style: {
        "background-color": function (n) { return GROUP[n.data("group")] || GROUP.other; },
        "border-width": 3,
        "border-color": function (n) { return STATUS[n.data("status")] || STATUS.healthy; },
        "label": "data(label)", "color": "#e5e7eb",
        "font-size": 10, "text-valign": "bottom", "text-margin-y": 4,
        "width": 30, "height": 30
      }},
      { selector: "edge", style: {
        "width": 2, "line-color": "#334155",
        "target-arrow-color": "#334155", "target-arrow-shape": "triangle",
        "curve-style": "bezier"
      }},
      { selector: ".sv-sel", style: { "border-color": "#38bdf8", "border-width": 5 }}
    ],
    layout: { name: "dagre", rankDir: "LR", nodeSep: 36, rankSep: 90, edgeSep: 12 }
  });

  var panel = document.getElementById("socverse-panel");
  function row(k, v) {
    if (v === undefined || v === null || v === "") return "";
    return '<div class="sv-row"><span>' + k + '</span><span>' + v + "</span></div>";
  }
  cy.on("tap", "node", function (evt) {
    cy.nodes().removeClass("sv-sel");
    evt.target.addClass("sv-sel");
    var id = evt.target.id();
    var d = (S.devices && S.devices[id]) || {};
    var kb = d.kb || {};
    panel.innerHTML =
      '<span class="sv-close" onclick="this.parentElement.classList.add(\'sv-hidden\')">x</span>' +
      "<h3>" + (d.hostname || id) + "</h3>" +
      '<div class="sv-sub">' + (kb.role || d.type || "") + "</div>" +
      row("Type", d.type) + row("Vendor", d.vendor) + row("OS", d.os) +
      row("IP", d.ip) + row("Status", d.status) + row("Matched KB", kb.matched_type);
    panel.classList.remove("sv-hidden");
  });
  cy.on("tap", function (evt) { if (evt.target === cy) panel.classList.add("sv-hidden"); });

  cy.ready(function () { cy.fit(undefined, 40); });
})();
"""
