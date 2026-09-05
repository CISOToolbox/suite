/**
 * CISO Toolbox — Pilot AI side panel
 * Right-hand sliding panel for AI assistant interactions.
 * Same look & feel as Risk's ai_common.js panel, scoped to Pilot.
 */

// cisotoolbox_backend variant (P1 factored master): Pilot must NOT unwrap
// the Pilot backup format {"module":...,"data":[...]} when importing its own
// files. The flag is read at use time by the cisotoolbox_backend.js master —
// set here because pilot_ai_panel.js is the first Pilot-specific script
// loaded by index.html (no inline script, CSP).
window._CT_IMPORT_NO_UNWRAP = true;

(function() {
"use strict";

var _overlayEl: HTMLDivElement | null = null;
var _panelEl: HTMLDivElement | null = null;
var _titleEl: HTMLElement | null = null;
var _bodyEl: HTMLElement | null = null;
var _footerEl: HTMLElement | null = null;

window._aiEnsurePanel = function(): PilotAiPanelParts {
    if (_panelEl) return { panel: _panelEl, title: _titleEl!, body: _bodyEl!, footer: _footerEl! };

    _overlayEl = document.createElement("div");
    _overlayEl.className = "ai-overlay";
    var _ovMd: EventTarget | null = null;
    _overlayEl.addEventListener("mousedown", function(e) { _ovMd = e.target; });
    _overlayEl.addEventListener("click", function(e) { if (e.target === _overlayEl && _ovMd === _overlayEl) _aiClosePanel(); });
    document.body.appendChild(_overlayEl);

    _panelEl = document.createElement("div");
    _panelEl.className = "ai-panel";
    _panelEl.innerHTML =
        '<div class="ai-panel-header">' +
            '<span class="ai-panel-title">' + t("pilot.ai.assistant") + '</span>' +
            '<button class="ai-panel-close" id="ai-close-btn" title="' + t("pilot.action.close") + '">&times;</button>' +
        '</div>' +
        '<div class="ai-panel-body"></div>' +
        '<div class="ai-panel-footer"></div>';
    document.body.appendChild(_panelEl);

    _titleEl = _panelEl.querySelector(".ai-panel-title") as HTMLElement;
    _bodyEl = _panelEl.querySelector(".ai-panel-body") as HTMLElement;
    _footerEl = _panelEl.querySelector(".ai-panel-footer") as HTMLElement;
    (_panelEl.querySelector("#ai-close-btn") as HTMLElement).onclick = _aiClosePanel;

    return { panel: _panelEl, title: _titleEl, body: _bodyEl, footer: _footerEl };
};

window._aiOpenPanel = function(title?: string) {
    var p = _aiEnsurePanel();
    if (title) p.title.textContent = title;
    _overlayEl!.classList.add("open");
    _panelEl!.classList.add("open");
};

window._aiClosePanel = function() {
    if (_overlayEl) _overlayEl.classList.remove("open");
    if (_panelEl) _panelEl.classList.remove("open");
};

function _escLocal(v: unknown): string {
    // Local escape — pilot_ai_panel.js may be loaded before cisotoolbox.js's esc()
    return String(v == null ? "" : v)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

window._aiShowLoading = function(title?: string, msg?: string) {
    var p = _aiEnsurePanel();
    p.title.textContent = title || t("pilot.ai.assistant");
    p.body.innerHTML = '<div class="ct-ta-c ct-p-8"><div class="ai-spinner"></div><p class="ct-mt-4 ct-muted">' + _escLocal(msg || t("pilot.ai.analyzing")) + '</p></div>';
    p.footer.innerHTML = "";
    _aiOpenPanel();
};

window._aiShowError = function(title?: string, errMsg?: string) {
    var p = _aiEnsurePanel();
    p.title.textContent = title || t("pilot.ai.assistant");
    p.body.innerHTML = '<div class="ai-error">' + _escLocal(errMsg || t("pilot.ai.unknown_error")) + '</div>';
    p.footer.innerHTML = '<button class="ct-btn" data-click="_aiClosePanel">' + _escLocal(t("pilot.action.close")) + '</button>';
    _aiOpenPanel();
};

// CSS injected once
var style = document.createElement("style");
style.textContent = [
    ".ai-overlay { display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.3); z-index:500; }",
    ".ai-overlay.open { display:block; }",
    ".ai-panel { display:none; position:fixed; top:0; right:-720px; width:700px; max-width:90vw; height:100vh; background:var(--ct-surface); box-shadow:-4px 0 24px rgba(0,0,0,0.2); z-index:501; transition:right 0.3s; overflow-y:auto; display:flex; flex-direction:column; }",
    ".ai-panel.open { display:flex; right:0; }",
    ".ai-panel-header { display:flex; align-items:center; justify-content:space-between; padding:14px 16px; background:var(--ct-accent); color:var(--ct-onaccent); position:sticky; top:0; z-index:1; flex:0 0 auto; }",
    ".ai-panel-title { font-weight:700; font-size:0.95em; }",
    ".ai-panel-close { background:none; border:none; color:var(--ct-onaccent); font-size:1.4em; cursor:pointer; padding:0 4px; }",
    ".ai-panel-body { padding:16px; flex:1 1 auto; overflow-y:auto; }",
    ".ai-panel-footer { padding:12px 16px; border-top:1px solid var(--ct-surface-2); background:var(--ct-surface-2); flex:0 0 auto; display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; }",
    ".ai-card { background:var(--ct-surface-2); border:1px solid var(--ct-surface-2); border-radius:8px; padding:12px; margin-bottom:10px; }",
    ".ai-card-row { display:flex; align-items:flex-start; gap:10px; }",
    ".ai-card-cb { margin-top:3px; flex:0 0 auto; }",
    ".ai-card-content { flex:1 1 auto; min-width:0; }",
    ".ai-card-title { font-weight:600; font-size:0.9em; margin-bottom:4px; }",
    ".ai-card-meta { font-size:0.78em; color:var(--ct-ink-2); margin-bottom:6px; }",
    ".ai-card-reason { font-size:0.82em; color:var(--ct-ink-2); font-style:italic; line-height:1.4; }",
    ".ai-card-badges { margin-top:6px; display:flex; flex-wrap:wrap; gap:4px; }",
    ".ai-spinner { width:36px; height:36px; border:3px solid var(--ct-surface-2); border-top-color:var(--ct-accent); border-radius:50%; animation:ai-spin 0.8s linear infinite; margin:0 auto; }",
    "@keyframes ai-spin { to { transform:rotate(360deg); } }",
    ".ai-error { padding:16px; color:var(--ct-critical); background:var(--ct-critical-tint); border:1px solid var(--ct-critical-tint); border-radius:6px; font-size:0.85em; }",
    // AI buttons: no more overrides. They carry the core .ct-btn +
    // data-variant (primary / ghost / bare) and therefore inherit the default
    // theme-safe style.
    ".ai-empty { text-align:center; padding:30px; color:var(--ct-ink-2); font-size:0.88em; }"
].join("\n");
document.head.appendChild(style);

})();
