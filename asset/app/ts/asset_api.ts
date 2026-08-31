/**
 * Asset Management — REST API Client Layer
 *
 * Replaces localStorage with REST API calls.
 * Handles single-project persistence (auto-load, autosave).
 * Load BEFORE ai_common.js and Asset_app.js.
 */

(function() {
"use strict";

var BASE = "api";
var _activeId: string | null = null;
var _saveTimer: ReturnType<typeof setTimeout> | null = null;

async function _fetch(url: string, opts?: AssetFetchOpts): Promise<any> {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.credentials = "same-origin";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(BASE + url, opts as RequestInit);
    if (resp.status === 401) {
        var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp);
        throw new Error("Not authenticated");
    }
    if (resp.status === 403) {
        var errBody = "";
        try { errBody = await resp.text(); } catch(e) {}
        if (errBody.indexOf("pending") >= 0) {
            window.location.href = "/login.html?error=pending";
            throw new Error("Account pending");
        }
    }
    if (resp.status === 204) return null;
    if (!resp.ok) {
        var errText = "";
        try { errText = await resp.text(); } catch(e) {}
        throw new Error("API " + resp.status + ": " + errText.substring(0, 200));
    }
    return resp.json();
}

// ═══════════════════════════════════════════════════════════════
// API — project-level (blob save for autosave)
// ═══════════════════════════════════════════════════════════════

window.AssetAPI = {
    list: function() { return _fetch("/projects"); },
    get: function(id: string) { return _fetch("/projects/" + id); },
    create: function(data?: { name?: string; data?: any }) { return _fetch("/projects", { method: "POST", body: data || { name: "", data: {} } }); },
    update: function(id: string, data: { name?: string; data?: any }) { return _fetch("/projects/" + id, { method: "PUT", body: data }); },
    del: function(id: string) { return _fetch("/projects/" + id, { method: "DELETE" }); },
    duplicate: function(id: string) { return _fetch("/projects/" + id + "/duplicate", { method: "POST" }); },
    importFile: function(file: File) {
        var formData = new FormData();
        formData.append("file", file);
        return _fetch("/projects/import", { method: "POST", body: formData, headers: {} });
    },
    exportUrl: function(id: string) { return BASE + "/projects/" + id + "/export"; },

    importCsv: function(projectId: string, file: File) {
        var formData = new FormData();
        formData.append("file", file);
        return _fetch("/projects/" + projectId + "/import-csv", { method: "POST", body: formData, headers: {} });
    },

    saveFull: function(projectId: string, data: AssetData) {
        return _fetch("/projects/" + projectId, {
            method: "PUT",
            body: { name: (data.metadata && data.metadata.organization) || "", data: data }
        });
    },

    // ── Plugins (asset connectors: AD, Intune, EDR…) ──
    listAvailablePlugins: function() { return _fetch("/plugins/available"); },
    listPlugins:          function(pid: string)                          { return _fetch("/projects/" + pid + "/plugins"); },
    createPlugin:         function(pid: string, body: AssetPluginForm)   { return _fetch("/projects/" + pid + "/plugins", { method: "POST", body: body }); },
    patchPlugin:          function(pid: string, id: string, body: AssetPluginForm) { return _fetch("/projects/" + pid + "/plugins/" + id, { method: "PATCH", body: body }); },
    deletePlugin:         function(pid: string, id: string)              { return _fetch("/projects/" + pid + "/plugins/" + id, { method: "DELETE" }); },
    testPlugin:           function(pid: string, id: string)              { return _fetch("/projects/" + pid + "/plugins/" + id + "/test", { method: "POST" }); },
    testPluginConfig:     function(pid: string, body: AssetPluginForm)   { return _fetch("/projects/" + pid + "/plugins/test-config", { method: "POST", body: body }); },
    syncPlugin:           function(pid: string, id: string)              { return _fetch("/projects/" + pid + "/plugins/" + id + "/sync", { method: "POST" }); },
    pluginHistory:        function(pid: string, id: string)              { return _fetch("/projects/" + pid + "/plugins/" + id + "/history"); },

    // ── Measures (FEAT-22) ──
    listMeasures:   function(pid: string)                         { return _fetch("/projects/" + pid + "/measures"); },
    createMeasure:  function(pid: string, body: any)              { return _fetch("/projects/" + pid + "/measures", { method: "POST", body: body }); },
    patchMeasure:   function(pid: string, id: string, body: any)  { return _fetch("/projects/" + pid + "/measures/" + id, { method: "PATCH", body: body }); },
    deleteMeasure:  function(pid: string, id: string)             { return _fetch("/projects/" + pid + "/measures/" + id, { method: "DELETE" }); },

    // ── AI ──
    aiComplete: function(systemPrompt: string, userPrompt: string, provider?: string, model?: string) {
        return _fetch("/ai/complete", {
            method: "POST",
            body: { system: systemPrompt, user: userPrompt, provider: provider || (window._aiRuntime && window._aiRuntime.provider) || "anthropic", model: model || (window._aiRuntime && window._aiRuntime.model) || "claude-sonnet-4-6" }
        });
    },
    aiConfig: function() { return _fetch("/ai/config"); },
    aiGetKeys: function() { return _fetch("/ai/keys"); },
    aiSetKeys: function(data: any) { return _fetch("/ai/keys", { method: "PUT", body: data }); },

    // ── Auth ──
    authMe: function() { return fetch("auth/me", { credentials: "same-origin" }).then(function(r) { return r.ok ? r.json() : null; }); },
    authProviders: function() { return fetch("auth/providers").then(function(r) { return r.json(); }); },
    authLogout: function() { return fetch("auth/logout", { method: "POST", credentials: "same-origin" }).then(function() { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); }); },

    // ── User admin ──
    listUsers: function() { return _fetch("/users"); },
    updateUser: function(id: string, data: Record<string, string>) { return _fetch("/users/" + id, { method: "PUT", body: data }); }
};

// ═══════════════════════════════════════════════════════════════
// ACTIVE PROJECT ID GETTER
// ═══════════════════════════════════════════════════════════════

window.getActiveProjectId = function() { return _activeId; };

// ═══════════════════════════════════════════════════════════════
// AUTOSAVE — Debounced blob PUT
// ═══════════════════════════════════════════════════════════════

var _dataReady = false;
window._setDataReady = function() { _dataReady = true; };

// FEAT-33 — server_rev seen at load; sent with the blob PUT (409 = a
// server-initiated write happened since: reload instead of overwrite).
var _serverRev = 0;

// FEAT-33 — a stale blob PUT was refused: warn (blocking) then reload the
// authoritative server state. The stale bulk change is lost by design.
function _staleConflict(): void {
    alert(t("chrome.stale_conflict"));
    window.location.reload();
}

window._autoSave = function() {
    if (!_dataReady) return;
    if (_saveTimer) clearTimeout(_saveTimer);
    var saveId = _activeId;
    _saveTimer = setTimeout(function() {
        _saveTimer = null;  // FEAT-33: a fired timer must not keep blocking the focus refresh
        if (!saveId || String(saveId) !== String(_activeId)) return;
        var name = (D.metadata && D.metadata.organization) || "";
        AssetAPI.update(saveId, { name: name, data: JSON.parse(JSON.stringify(D)),
                              expected_server_rev: _serverRev } as any)
            .catch(function(err: any) {
                if (err && String(err.message || "").indexOf("API 409") === 0) { _staleConflict(); return; }
                console.error("Autosave failed:", err);
            });
    }, 800);
};

// Cancel a pending debounced autosave. Called before a connector sync so a
// stale blob PUT (old D.assets) can't clobber the rows the sync writes
// server-side (the blob PUT delete-all + re-inserts from D.assets).
window._cancelAutosave = function() {
    if (_saveTimer) { clearTimeout(_saveTimer); _saveTimer = null; }
};

// ═══════════════════════════════════════════════════════════════
// FILE IMPORT HOOK (blob save)
// ═══════════════════════════════════════════════════════════════

var _origLoadBuffer = window._loadBuffer;
if (_origLoadBuffer) {
    // Réassignation d'un global déclaré `declare function` → on passe par
    // l'interface Window ; le wrapper est volontairement void (iso source).
    (window as Window)._loadBuffer = function(buffer: ArrayBuffer, filename: string) {
        _origLoadBuffer!(buffer, filename);
        setTimeout(function() {
            if (_activeId) {
                AssetAPI.saveFull(_activeId, D);
            } else {
                AssetAPI.create({
                    name: (D.metadata && D.metadata.organization) || "",
                    data: JSON.parse(JSON.stringify(D))
                }).then(function(project: any) {
                    _activeId = project.id;
            _serverRev = (project as any).server_rev || 0;
                    localStorage.setItem("asset_active_project", _activeId!);
                });
            }
        }, 200);
    };
}

// ═══════════════════════════════════════════════════════════════
// INIT: LOAD PROJECT FROM API
// ═══════════════════════════════════════════════════════════════

window._appInitCallback = function() {

    function _loadAndRender(id: string): void {
        AssetAPI.get(id).then(function(project: any) {
            _activeId = project.id;
            _serverRev = (project as any).server_rev || 0;
            localStorage.setItem("asset_active_project", _activeId!);
            var pdata = typeof project.data === "string" ? JSON.parse(project.data) : (project.data || {});
            Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
            Object.assign(D, pdata);
            if (typeof _setDataReady === "function") _setDataReady();
            if (typeof _initDataAndRender === "function") _initDataAndRender();
            else if (typeof renderAll === "function") renderAll();
        }).catch(function() {
            _createAndRender();
        });
    }

    function _createAndRender(): void {
        var initData = typeof ASSET_INIT_DATA !== "undefined" ? JSON.parse(JSON.stringify(ASSET_INIT_DATA)) : {};
        AssetAPI.create({ name: "", data: initData }).then(function(project: any) {
            _activeId = project.id;
            _serverRev = (project as any).server_rev || 0;
            localStorage.setItem("asset_active_project", _activeId!);
            Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
            Object.assign(D, initData);
            if (typeof _setDataReady === "function") _setDataReady();
            if (typeof _initDataAndRender === "function") _initDataAndRender();
            else if (typeof renderAll === "function") renderAll();
        });
    }

    // Asset has a single shared inventory — no multi-project.
    AssetAPI.list().then(function(items: any[]) {
        if (items.length > 0) { _loadAndRender(items[0].id); }
        else { _createAndRender(); }
    }).catch(function() { _createAndRender(); });
};

// ═══════════════════════════════════════════════════════════════
// AUTH + TOOLBAR
// ═══════════════════════════════════════════════════════════════

// ─── Toolbar user pill (name + admin + logout) ──────────────────
function _initAuth(): void {
    fetch("auth/providers").then(function(r) { return r.json(); }).then(function(data) {
        if (!data.auth_enabled) return;
        fetch("auth/me", { credentials: "same-origin" }).then(function(r) {
            if (!r.ok) { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); return; }
            return r.json();
        }).then(function(user: CtAuthUser | undefined) {
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

// ═══════════════════════════════════════════════════════════════
// ADMIN PANEL
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// I18N
// ═══════════════════════════════════════════════════════════════

_registerTranslations("fr", {
    "admin.title": "Gestion des utilisateurs",
    "admin.user": "Utilisateur",
    "admin.role": "Rôle",
    "admin.ai": "IA",
    "admin.last_login": "Connexion",
    "admin.no_users": "Aucun utilisateur",
    "admin.ai_toggled": "Accès IA mis à jour",
    "admin.role_updated": "Rôle mis à jour"
});

_registerTranslations("en", {
    "admin.title": "User management",
    "admin.user": "User",
    "admin.role": "Role",
    "admin.ai": "AI",
    "admin.last_login": "Last login",
    "admin.no_users": "No users",
    "admin.ai_toggled": "AI access updated",
    "admin.role_updated": "Role updated"
});

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", _initAuth);
else _initAuth();


// FEAT-33 — refresh on tab focus when a server-initiated write happened
// while the tab was hidden. Skipped while local edits are in flight.
document.addEventListener("visibilitychange", function() {
    if (document.visibilityState !== "visible" || !_activeId || _saveTimer) return;
    AssetAPI.get(_activeId).then(function(project: any) {
        if (!project || (project.server_rev || 0) === _serverRev) return;
        _serverRev = project.server_rev || 0;
        var pdata = typeof project.data === "string" ? JSON.parse(project.data) : (project.data || {});
        Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
        Object.assign(D, pdata);
        if (typeof renderAll === "function") renderAll();
        showStatus(t("chrome.stale_refreshed"));
    }).catch(function() { /* offline — ignore */ });
});

})();
