// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/connectors_common.js).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/*
 * connectors_common.js — shared connector helpers for CISO Toolbox.
 *
 * Mirror of ai_common.js for any module that exposes the /api/connectors
 * routes from shared/python/connectors_common.py.
 *
 * This file is COPIED into each app's app/js/ directory by the deploy
 * scripts — edit shared/js/connectors_common.js and propagate.
 *
 * Public API:
 *   _connRuntime()                   — lazy-fetch /api/connectors (cached)
 *   _connIsManaged()                 — bool, true when Pilot owns the config
 *   _connList()                      — array of {id, schema, configured, config}
 *   _connGet(id)                     — fetch a single connector incl. schema
 *   _connSave(id, body)              — PUT, throws Error with detail on 403/4xx
 *   _connTest(id)                    — POST .../test, returns {ok, message}
 *   _connRun(id)                     — POST .../run, returns the runner payload
 *   _connRenderForm(schema, current, lang) — returns inner HTML for a config form
 *   _connReadForm(schema, root)      — reads the form back into a body object
 *
 * Dependencies: shared cisotoolbox.js (esc, _safeDispatch), i18n.js (_locale).
 * BASE URL is taken from window._fetch's host module — connectors_common.js
 * uses its own _connFetch so it can surface 4xx detail messages cleanly
 * (the project's _fetch swallows the body).
 */
(function () {
    "use strict";
    var _runtimeCache = null;
    var _runtimePromise = null;
    function _base() {
        // Modules expose all routes under /api/* (same convention as _fetch).
        return "api";
    }
    function _connFetch(url, opts) {
        opts = opts || {};
        opts.credentials = "same-origin";
        if (opts.body && typeof opts.body === "object") {
            opts.headers = Object.assign({}, opts.headers || {}, { "Content-Type": "application/json" });
            opts.body = JSON.stringify(opts.body);
        }
        return fetch(_base() + url, opts).then(function (resp) {
            if (resp.status === 401) {
                window.location.href = "/login.html";
                throw new Error("Not authenticated");
            }
            if (resp.status === 204)
                return null;
            return resp.json().catch(function () { return null; }).then(function (json) {
                if (!resp.ok) {
                    var msg = (json && (json.detail || json.message)) || ("HTTP " + resp.status);
                    var err = new Error(msg);
                    err.status = resp.status;
                    err.body = json;
                    throw err;
                }
                return json;
            });
        });
    }
    function _connRuntime() {
        if (_runtimeCache)
            return Promise.resolve(_runtimeCache);
        if (_runtimePromise)
            return _runtimePromise;
        _runtimePromise = _connFetch("/connectors", { method: "GET" }).then(function (data) {
            _runtimeCache = data || { managed: false, connectors: [] };
            _runtimePromise = null;
            return _runtimeCache;
        }).catch(function (e) {
            _runtimePromise = null;
            // 404 = module doesn't expose connectors (older build) — treat as empty.
            if (e && e.status === 404) {
                _runtimeCache = { managed: false, connectors: [] };
                return _runtimeCache;
            }
            throw e;
        });
        return _runtimePromise;
    }
    function _connInvalidateCache() {
        _runtimeCache = null;
        _runtimePromise = null;
    }
    function _connIsManaged() {
        return _connRuntime().then(function (rt) { return !!rt.managed; });
    }
    function _connList() {
        return _connRuntime().then(function (rt) { return rt.connectors || []; });
    }
    function _connGet(id) {
        return _connFetch("/connectors/" + encodeURIComponent(id), { method: "GET" });
    }
    function _connSave(id, body) {
        return _connFetch("/connectors/" + encodeURIComponent(id), {
            method: "PUT",
            body: body
        }).then(function (r) {
            _connInvalidateCache();
            return r;
        });
    }
    function _connTest(id) {
        return _connFetch("/connectors/" + encodeURIComponent(id) + "/test", { method: "POST" });
    }
    function _connRun(id) {
        return _connFetch("/connectors/" + encodeURIComponent(id) + "/run", { method: "POST" });
    }
    // ── i18n helper ──────────────────────────────────────────────────
    function _connT(obj, lang) {
        if (!obj)
            return "";
        if (typeof obj === "string")
            return obj;
        var l = lang || (window._locale || "fr");
        return obj[l] || obj.fr || obj.en || "";
    }
    // ── Form rendering ───────────────────────────────────────────────
    function _connRenderForm(schema, current, lang) {
        if (!schema || !schema.fields)
            return "";
        var h = '';
        schema.fields.forEach(function (field) {
            var label = _connT(field.label, lang) || field.id;
            var help = _connT(field.help, lang);
            // Flat shape: field values are at the top level of `current`,
            // alongside meta keys (id, schema, configured). Field IDs may not
            // collide with reserved meta keys.
            var value = (current && current[field.id]) || "";
            var isSecret = !!field.secret;
            var inputType = isSecret ? "password" : "text";
            var required = field.required ? "required" : "";
            var pattern = field.pattern ? ' pattern="' + esc(field.pattern) + '"' : '';
            var placeholder = field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '';
            // Secret fields with value "configured" stay as the placeholder; the user
            // can either leave it (no-op) or overwrite it with a new secret.
            h += '<div class="conn-field" style="margin:14px 0">';
            h += '<label style="display:block;font-weight:600;margin-bottom:4px">' + esc(label);
            if (field.required)
                h += ' <span style="color:var(--ct-critical)">*</span>';
            h += '</label>';
            h += '<input type="' + inputType + '" data-conn-field="' + esc(field.id) + '" '
                + 'value="' + esc(value) + '" ' + required + pattern + placeholder
                + ' style="width:100%;padding:6px 10px;border:1px solid var(--ct-line);border-radius:6px;font-family:inherit;font-size:14px" />';
            if (help)
                h += '<div style="font-size:12px;color:var(--ct-ink-2);margin-top:4px">' + esc(help) + '</div>';
            h += '</div>';
        });
        return h;
    }
    function _connReadForm(schema, root) {
        var body = {};
        if (!schema || !schema.fields)
            return body;
        schema.fields.forEach(function (field) {
            var el = root.querySelector('[data-conn-field="' + field.id + '"]');
            if (!el)
                return;
            body[field.id] = el.value;
        });
        return body;
    }
    // ── Help / setup guide ───────────────────────────────────────────
    // The per-connector "how to configure the account/token/API key" text
    // lives at schema.prereqs.setup_guide ({fr,en}) — synthesised from each
    // plugin's setup_guide / setup_guide_en, or set in shared/connectors/*.json.
    function _connSetupGuide(schema, lang) {
        if (!schema)
            return "";
        var pre = schema.prereqs || {};
        return _connT(pre.setup_guide, lang) || _connT(schema.setup_guide, lang) || "";
    }
    // Returns a collapsible help block (toggle button + hidden panel) to prepend
    // to a config modal body. ct_modal is single-overlay, so we expand inline
    // instead of opening a second modal (which would discard the form).
    function _connHelpPanelHtml(schema, lang) {
        var guide = _connSetupGuide(schema, lang);
        if (!guide)
            return "";
        var btnLabel = (lang || window._locale || "fr") === "en"
            ? "How to configure this connector?" : "Comment configurer ce connecteur ?";
        var h = '<div class="conn-help" style="margin-bottom:14px">';
        h += '<button type="button" data-click="_connToggleHelp" data-pass-el '
            + 'style="display:inline-flex;align-items:center;gap:6px;background:var(--ct-canvas);'
            + 'border:1px solid var(--ct-line);border-radius:8px;padding:6px 12px;font-size:13px;'
            + 'font-weight:600;color:var(--ct-ink);cursor:pointer">'
            + esc(btnLabel) + '</button>';
        h += '<div data-conn-help-panel style="display:none;margin-top:8px;background:var(--ct-canvas);'
            + 'border:1px solid var(--ct-line);border-radius:8px;padding:12px 14px;font-size:13px;'
            + 'line-height:1.55;color:var(--ct-ink);white-space:pre-wrap">' + esc(guide) + '</div>';
        h += '</div>';
        return h;
    }
    // data-click handler: toggle the help panel next to the clicked button.
    function _connToggleHelp(el) {
        var wrap = (el && el.closest) ? el.closest(".conn-help") : null;
        var panel = (wrap ? wrap.querySelector("[data-conn-help-panel]")
            : document.querySelector("[data-conn-help-panel]"));
        if (panel)
            panel.style.display = panel.style.display === "block" ? "none" : "block";
    }
    // ── Expose ───────────────────────────────────────────────────────
    window._connRuntime = _connRuntime;
    window._connInvalidateCache = _connInvalidateCache;
    window._connIsManaged = _connIsManaged;
    window._connList = _connList;
    window._connGet = _connGet;
    window._connSave = _connSave;
    window._connTest = _connTest;
    window._connRun = _connRun;
    window._connT = _connT;
    window._connRenderForm = _connRenderForm;
    window._connReadForm = _connReadForm;
    window._connSetupGuide = _connSetupGuide;
    window._connHelpPanelHtml = _connHelpPanelHtml;
    window._connToggleHelp = _connToggleHelp;
})();
