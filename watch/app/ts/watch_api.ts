var WatchAPI: WatchApiType = (function() {
    "use strict";
    var BASE = "api";

    async function _fetch(path: string, opts?: WatchFetchOpts): Promise<any> {
        opts = opts || {};
        opts.credentials = "same-origin";
        if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
            opts.headers = Object.assign({"Content-Type": "application/json"}, opts.headers || {});
            opts.body = JSON.stringify(opts.body);
        }
        var r = await fetch(BASE + path, opts as RequestInit);
        if (r.status === 401) { window.location.href = "login.html"; return null; }
        if (r.status === 204) return null;
        if (!r.ok) {
            var detail = "";
            try {
                var errBody = await r.json();
                detail = errBody.detail || "";
            } catch(e2) {}
            if (!detail || detail.length > 200 || detail.includes("Traceback") || detail.includes("sqlalchemy")) {
                var msgs: Record<number, string> = {400: t("error.bad_request"), 403: t("error.forbidden"), 404: t("error.not_found"), 409: t("error.conflict"), 422: t("error.validation"), 500: t("error.server")};
                detail = msgs[r.status] || t("error.generic");
            }
            throw new Error(detail);
        }
        return r.json();
    }

    return {
        _fetch: _fetch,

        // ── Phase 1: scopes + recipients ────────────────────────
        listScopes:    function()              { return _fetch("/scopes"); },
        createScope:   function(data: Record<string, unknown>)          { return _fetch("/scopes", { method: "POST", body: data }); },
        getScope:      function(id: string)            { return _fetch("/scopes/" + encodeURIComponent(id)); },
        updateScope:   function(id: string, data: Record<string, unknown>)      { return _fetch("/scopes/" + encodeURIComponent(id), { method: "PATCH", body: data }); },
        deleteScope:   function(id: string)            { return _fetch("/scopes/" + encodeURIComponent(id), { method: "DELETE" }); },
        addRecipient:  function(id: string, data: { email: string; name?: string })      { return _fetch("/scopes/" + encodeURIComponent(id) + "/recipients", { method: "POST", body: data }); },
        removeRecipient: function(id: string, email: string)   { return _fetch("/scopes/" + encodeURIComponent(id) + "/recipients/" + encodeURIComponent(email), { method: "DELETE" }); },

        // ── Phase 2: watch targets ──────────────────────────────
        listTargets:   function(scopeId: string)               { return _fetch("/scopes/" + encodeURIComponent(scopeId) + "/targets"); },
        createTarget:  function(scopeId: string, data: Record<string, unknown>)         { return _fetch("/scopes/" + encodeURIComponent(scopeId) + "/targets", { method: "POST", body: data }); },
        updateTarget:  function(scopeId: string, tid: string, data: Record<string, unknown>)    { return _fetch("/scopes/" + encodeURIComponent(scopeId) + "/targets/" + encodeURIComponent(tid), { method: "PATCH", body: data }); },
        deleteTarget:  function(scopeId: string, tid: string)          { return _fetch("/scopes/" + encodeURIComponent(scopeId) + "/targets/" + encodeURIComponent(tid), { method: "DELETE" }); },

        // ── Phase 3: alerts + feeds ─────────────────────────────
        listAlerts:    function(params?: Record<string, string | number | boolean | null | undefined>) {
            var qs = "";
            if (params) {
                var bits: string[] = [];
                Object.keys(params).forEach(function(k) {
                    if (params[k] === null || params[k] === undefined || params[k] === "") return;
                    bits.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k] as string));
                });
                if (bits.length) qs = "?" + bits.join("&");
            }
            return _fetch("/alerts" + qs);
        },
        getAlert:      function(id: string) { return _fetch("/alerts/" + encodeURIComponent(id)); },
        setAlertStatus: function(id: string, data: { status: string; note?: string }) { return _fetch("/alerts/" + encodeURIComponent(id) + "/status", { method: "PATCH", body: data }); },
        bulkSetAlertStatus: function(data: { ids: string[]; status: string }) { return _fetch("/alerts/bulk-status", { method: "POST", body: data }); },
        getAlertAnalysis: function(id: string) {
            // Pass the active i18n locale so the backend prefers a cached
            // row in the user's language (falls back to any cached row).
            var lang = (typeof _locale !== "undefined") ? _locale : "fr";
            return _fetch("/alerts/" + encodeURIComponent(id) + "/analysis?language=" + encodeURIComponent(lang));
        },
        analyzeAlert:   function(id: string) {
            var lang = (typeof _locale !== "undefined") ? _locale : "fr";
            return _fetch("/alerts/" + encodeURIComponent(id) + "/analyze?language=" + encodeURIComponent(lang), { method: "POST", body: {} });
        },
        getAlertSbomImpact: function(id: string) { return _fetch("/alerts/" + encodeURIComponent(id) + "/sbom-impact"); },
        listFeeds:     function() { return _fetch("/feeds"); },
        runFeedNow:    function(source: string) { return _fetch("/feeds/" + encodeURIComponent(source) + "/run", { method: "POST", body: {} }); },

        // ── Phase 5: digest ─────────────────────────────────────
        previewDigest:  function(scopeId?: string) {
            var qs = scopeId ? ("?scope_id=" + encodeURIComponent(scopeId)) : "";
            // Returns HTML — bypass the JSON _fetch helper.
            return fetch(BASE + "/digest/preview" + qs, { credentials: "same-origin" }).then(function(r) {
                if (!r.ok) throw new Error("Preview failed");
                return r.text();
            });
        },
        listDigestRuns: function() { return _fetch("/digest/runs"); },
        getDigestBody:  function(runId: string) {
            // Returns HTML — bypass the JSON _fetch helper.
            return fetch(BASE + "/digest/runs/" + encodeURIComponent(runId) + "/body", { credentials: "same-origin" }).then(function(r) {
                if (r.status === 401) { window.location.href = "login.html"; return ""; }
                if (!r.ok) throw new Error("Fetch body failed");
                return r.text();
            });
        },
        sendDigestNow:  function(scopeId: string, kind: string) {
            return _fetch("/digest/scopes/" + encodeURIComponent(scopeId) + "/send?kind=" + encodeURIComponent(kind), { method: "POST", body: {} });
        },

        // ── Phase 6: dashboard ──────────────────────────────────
        getDashboard:  function() { return _fetch("/dashboard"); },

        // Pilot directory proxy — used by the recipient picker.
        getDirectory:  function()              { return _fetch("/directory"); },
    };
})();

// ─── Toolbar user pill (name + admin + logout) ──────────────────
function _initAuth(): void {
    fetch("auth/providers").then(function(r) { return r.json(); }).then(function(data) {
        if (!data.auth_enabled) return;
        fetch("auth/me", { credentials: "same-origin" }).then(function(r) {
            if (!r.ok) { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); return; }
            return r.json();
        }).then(function(user) {
            if (!user) return;
            window._currentUser = user;
            var right = document.getElementById("toolbar-right");
            if (!right) return;
            var h = "";
            h += '<span style="color:var(--ct-ink-1);font-size:var(--ct-text-label);margin:0 var(--ct-s1)">' + esc(user.name || user.email) + '</span>';
            h += '<button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_logout" title="Sign out">&#x23FB;</button>';
            var container = document.createElement("span");
            container.className = "ct-toolbar-right";
            container.style.cssText = "display:flex;align-items:center;gap:4px;margin-left:auto";
            container.innerHTML = h;
            right.parentNode!.insertBefore(container, right);
            fetch("auth/role", { credentials: "same-origin" }).then(function(rr) {
                return rr.ok ? rr.json() : {};
            }).then(function(roleInfo: any) {
                var role = roleInfo.role || "";
                window._moduleRole = role;
                if (role) document.body.classList.add("ct-role-" + role);
                if (user.role === "admin") document.body.classList.add("ct-role-admin");
            }).catch(function() {});
        });
    }).catch(function() {});
}
window._logout = function() {
    fetch("auth/logout", { method: "POST", credentials: "same-origin" })
        .finally(function() { window.location.href = "/auth/logout"; });
};
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", _initAuth);
else _initAuth();
