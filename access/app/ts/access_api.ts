/**
 * Access Review — REST API Client Layer
 */
(function() {
"use strict";

var BASE = "api";
var _activeId: string | null = null;
var _saveTimer: ReturnType<typeof setTimeout> | null = null;

interface AccessFetchOpts {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    credentials?: RequestCredentials;
}

async function _fetch(url: string, opts?: AccessFetchOpts): Promise<any> {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.credentials = "same-origin";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(BASE + url, opts as RequestInit);
    if (resp.status === 401) { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); throw new Error("Not authenticated"); }
    if (resp.status === 403) {
        var errBody = ""; try { errBody = await resp.text(); } catch(e) {}
        if (errBody.indexOf("pending") >= 0) { window.location.href = "login.html?error=pending"; throw new Error("Account pending"); }
    }
    if (resp.status === 204) return null;
    if (!resp.ok) { var errText = ""; try { errText = await resp.text(); } catch(e) {} throw new Error("API " + resp.status + ": " + errText.substring(0, 200)); }
    return resp.json();
}

window.AccessAPI = {
    list: function() { return _fetch("/projects"); },
    get: function(id: string) { return _fetch("/projects/" + id); },
    create: function(data?: { name: string; data: unknown }) { return _fetch("/projects", { method: "POST", body: data || { name: "", data: {} } }); },
    update: function(id: string, data: { name: string; data: unknown }) { return _fetch("/projects/" + id, { method: "PUT", body: data }); },
    del: function(id: string) { return _fetch("/projects/" + id, { method: "DELETE" }); },
    saveFull: function(pid: string, data: AccessData) {
        return _fetch("/projects/" + pid, { method: "PUT", body: { name: (data.metadata && data.metadata.organization) || "", data: data } });
    },
    importFile: function(file: File) { var fd = new FormData(); fd.append("file", file); return _fetch("/projects/import", { method: "POST", body: fd, headers: {} }); },
    exportUrl: function(id: string) { return BASE + "/projects/" + id + "/export"; },

    // SI Users
    listSiUsers: function(pid: string) { return _fetch("/projects/" + pid + "/si-users"); },
    createSiUser: function(pid: string, data: Partial<AccessSiUser>) { return _fetch("/projects/" + pid + "/si-users", { method: "POST", body: data }); },
    patchSiUser: function(pid: string, uid: string, fields: Partial<AccessSiUser>) { return _fetch("/projects/" + pid + "/si-users/" + uid, { method: "PATCH", body: fields }); },
    deleteSiUser: function(pid: string, uid: string) { return _fetch("/projects/" + pid + "/si-users/" + uid, { method: "DELETE" }); },
    syncSiUsersFromPilot: function(pid: string) { return _fetch("/projects/" + pid + "/si-users/sync-from-pilot", { method: "POST" }); },
    importSiUsersCsv: function(pid: string, file: File) { var fd = new FormData(); fd.append("file", file); return _fetch("/projects/" + pid + "/si-users/import-csv", { method: "POST", body: fd, headers: {} }); },
    syncSiUsersFromHr: function(pid: string) { return _fetch("/projects/" + pid + "/si-users/sync-hr", { method: "POST" }); },
    listEntitlements: function(pid: string, uid: string) { return _fetch("/projects/" + pid + "/si-users/" + uid + "/entitlements"); },
    listEntitlementAudit: function(pid: string, uid: string) { return _fetch("/projects/" + pid + "/si-users/" + uid + "/entitlements/audit"); },
    createEntitlement: function(pid: string, uid: string, data: { perimetre_id: string; role: string }) { return _fetch("/projects/" + pid + "/si-users/" + uid + "/entitlements", { method: "POST", body: data }); },
    deleteEntitlement: function(pid: string, uid: string, eid: string) { return _fetch("/projects/" + pid + "/si-users/" + uid + "/entitlements/" + eid, { method: "DELETE" }); },

    // Applications
    listApps: function(pid: string) { return _fetch("/projects/" + pid + "/applications"); },
    createApp: function(pid: string, data: Partial<AccessApplication>) { return _fetch("/projects/" + pid + "/applications", { method: "POST", body: data }); },
    patchApp: function(pid: string, aid: string, fields: Partial<AccessApplication>) { return _fetch("/projects/" + pid + "/applications/" + aid, { method: "PATCH", body: fields }); },
    deleteApp: function(pid: string, aid: string) { return _fetch("/projects/" + pid + "/applications/" + aid, { method: "DELETE" }); },
    importAppsCsv: function(pid: string, file: File) { var fd = new FormData(); fd.append("file", file); return _fetch("/projects/" + pid + "/applications/import-csv", { method: "POST", body: fd, headers: {} }); },
    syncAppsFromAsset: function(pid: string) { return _fetch("/projects/" + pid + "/applications/sync-asset", { method: "POST" }); },

    // Reviews
    listReviews: function(pid: string, status?: string) { return _fetch("/projects/" + pid + "/reviews" + (status ? "?status=" + status : "")); },
    getReview: function(pid: string, rid: string) { return _fetch("/projects/" + pid + "/reviews/" + rid); },
    createReview: function(pid: string, data: { application_id: string }) { return _fetch("/projects/" + pid + "/reviews", { method: "POST", body: data }); },
    importCsv: function(pid: string, rid: string, file: File) { var fd = new FormData(); fd.append("file", file); return _fetch("/projects/" + pid + "/reviews/" + rid + "/import-csv", { method: "POST", body: fd, headers: {} }); },
    patchEntry: function(pid: string, rid: string, eid: string, fields: Partial<AccessReviewEntry>) { return _fetch("/projects/" + pid + "/reviews/" + rid + "/entries/" + eid, { method: "PATCH", body: fields }); },
    closeReview: function(pid: string, rid: string) { return _fetch("/projects/" + pid + "/reviews/" + rid + "/close", { method: "POST" }); },
    exportReview: function(pid: string | null, rid: string) { return BASE + "/projects/" + pid + "/reviews/" + rid + "/export"; },
    deleteReview: function(pid: string, rid: string) { return _fetch("/projects/" + pid + "/reviews/" + rid, { method: "DELETE" }); },

    // Measures
    listMeasures: function(pid: string) { return _fetch("/projects/" + pid + "/measures"); },
    createMeasure: function(pid: string, data: Partial<AccessMeasure>) { return _fetch("/projects/" + pid + "/measures", { method: "POST", body: data }); },
    patchMeasure: function(pid: string, mid: string, fields: Partial<AccessMeasure>) { return _fetch("/projects/" + pid + "/measures/" + mid, { method: "PATCH", body: fields }); },
    deleteMeasure: function(pid: string, mid: string) { return _fetch("/projects/" + pid + "/measures/" + mid, { method: "DELETE" }); },

    // Service Accounts
    listServiceAccounts: function(pid: string) { return _fetch("/projects/" + pid + "/service-accounts"); },
    createServiceAccount: function(pid: string, d: Partial<AccessServiceAccount>) { return _fetch("/projects/" + pid + "/service-accounts", { method: "POST", body: d }); },
    patchServiceAccount: function(pid: string, id: string, f: Partial<AccessServiceAccount>) { return _fetch("/projects/" + pid + "/service-accounts/" + id, { method: "PATCH", body: f }); },
    deleteServiceAccount: function(pid: string, id: string) { return _fetch("/projects/" + pid + "/service-accounts/" + id, { method: "DELETE" }); },

    // Plugins
    listAvailablePlugins: function() { return _fetch("/plugins/available"); },
    listPlugins: function(pid: string) { return _fetch("/projects/" + pid + "/plugins"); },
    createPlugin: function(pid: string, d: Record<string, unknown>) { return _fetch("/projects/" + pid + "/plugins", { method: "POST", body: d }); },
    patchPlugin: function(pid: string, id: string, f: Record<string, unknown>) { return _fetch("/projects/" + pid + "/plugins/" + id, { method: "PATCH", body: f }); },
    deletePlugin: function(pid: string, id: string) { return _fetch("/projects/" + pid + "/plugins/" + id, { method: "DELETE" }); },
    testPlugin: function(pid: string, id: string) { return _fetch("/projects/" + pid + "/plugins/" + id + "/test", { method: "POST" }); },
    testPluginConfig: function(pid: string, body: { plugin_type: string; config: Record<string, unknown> }) { return _fetch("/projects/" + pid + "/plugins/test-config", { method: "POST", body: body }); },
    importReviewFromConnector: function(pid: string, rid: string, body?: Record<string, unknown>) { return _fetch("/projects/" + pid + "/reviews/" + rid + "/import-connector", { method: "POST", body: body || {} }); },
    importReviewFromConnectorFile: function(pid: string, rid: string, file: File, pluginId?: string) { var fd = new FormData(); fd.append("file", file); if (pluginId) fd.append("plugin_id", pluginId); return _fetch("/projects/" + pid + "/reviews/" + rid + "/import-connector-file", { method: "POST", body: fd, headers: {} }); },
    pluginHistory: function(pid: string, id: string) { return _fetch("/projects/" + pid + "/plugins/" + id + "/history"); },

    // AI
    aiComplete: function(sys: string, usr: string, prov?: string, model?: string) { return _fetch("/ai/complete", { method: "POST", body: { system: sys, user: usr, provider: prov || (window._aiRuntime && window._aiRuntime.provider) || "anthropic", model: model || (window._aiRuntime && window._aiRuntime.model) || "claude-sonnet-4-6" } }); },
    aiConfig: function() { return _fetch("/ai/config"); },

    // Auth — relative URLs (no leading /)
    authMe: function() { return fetch("auth/me", { credentials: "same-origin" }).then(function(r) { return r.ok ? r.json() : null; }); },
    authProviders: function() { return fetch("auth/providers").then(function(r) { return r.json(); }); },
    authLogout: function() { return fetch("auth/logout", { method: "POST", credentials: "same-origin" }).then(function() { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); }); },
    listUsers: function() { return _fetch("/users"); },
    updateUser: function(id: string, data: Record<string, unknown>) { return _fetch("/users/" + id, { method: "PUT", body: data }); }
};

window.getActiveProjectId = function() { return _activeId; };

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
        AccessAPI.update(saveId, { name: (D.metadata && D.metadata.organization) || "", data: JSON.parse(JSON.stringify(D)),
                              expected_server_rev: _serverRev } as any)
            .catch(function(err: any) {
                if (err && String(err.message || "").indexOf("API 409") === 0) { _staleConflict(); return; }
                console.error("Autosave failed:", err);
            });
    }, 800);
};

var _origLoadBuffer = window._loadBuffer;
if (_origLoadBuffer) {
    // Reassigning a global declared with `declare function` → go through the
    // Window interface (cast); the wrapper is deliberately void (iso source).
    (window as Window)._loadBuffer = function(buffer: ArrayBuffer, filename: string) {
        _origLoadBuffer!(buffer, filename);
        setTimeout(function() {
            if (_activeId) { AccessAPI.saveFull(_activeId, D); }
            else { AccessAPI.create({ name: (D.metadata && D.metadata.organization) || "", data: JSON.parse(JSON.stringify(D)) }).then(function(p) { _activeId = p.id; localStorage.setItem("access_active_project", _activeId); }); }
        }, 200);
    };
}

window._appInitCallback = function() {
    // Check auth first with relative URLs
    fetch("auth/providers").then(function(r) { return r.json(); }).then(function(prov) {
        if (prov.auth_enabled) {
            return fetch("auth/me", { credentials: "same-origin" }).then(function(r) {
                if (r.status === 401) {
                    // Not authenticated — redirect to login.
                    var _rp = window.location.pathname.replace(/[^/]*$/, "");
                    window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp);
                    return null;
                }
                if (r.status === 403) {
                    // Authenticated but no role on this module — show a
                    // clear message rather than looping through login.
                    _showAccessDeniedPage();
                    return null;
                }
                if (!r.ok) { return null; }
                return r.json();
            });
        }
        return { email: "anonymous" };
    }).then(function(user) {
        if (!user) return;
        _doInit();
    }).catch(function() { _doInit(); });

    function _showAccessDeniedPage(): void {
        var html = ''
            + '<div style="max-width:480px;margin:var(--ct-s12) auto;padding:var(--ct-s8);background:var(--ct-surface);border:1px solid var(--ct-line);border-radius:var(--ct-r-xl);box-shadow:0 4px 12px rgba(0,0,0,0.04);text-align:center">'
            + '<div class="ct-text-page ct-mb-3">&#128274;</div>'
            + '<h2 style="margin:0 0 var(--ct-s2) 0;color:var(--ct-ink)">Accès refusé</h2>'
            + '<p style="color:var(--ct-ink-2);font-size:var(--ct-text-ui);line-height:1.5;margin:var(--ct-s4) 0">'
            + 'Vous êtes authentifié mais n\'avez pas de rôle attribué sur le module Access.'
            + '<br>Contactez un administrateur pour obtenir les droits d\'accès.'
            + '</p>'
            + '<button id="ct-logout-btn" '
            + 'style="margin-top:var(--ct-s3);padding:var(--ct-s2) var(--ct-s5);background:var(--ct-info);color:var(--ct-onsolid);border:0;border-radius:var(--ct-r-md);font-size:var(--ct-text-data);cursor:pointer">'
            + 'Se déconnecter</button>'
            + '</div>';
        document.body.innerHTML = html;
        var btn = document.getElementById("ct-logout-btn");
        if (btn) btn.addEventListener("click", function() {
            fetch("auth/logout", { method: "POST", credentials: "same-origin" })
                .finally(function() { window.location.href = "/login.html"; });
        });
    }

    function _doInit(): void {
        // Access has a single shared project — no multi-project, no localStorage.
        AccessAPI.list().then(function(items) {
            if (items.length > 0) { _load(items[0].id); }
            else { _createNew(); }
        }).catch(function() { _createNew(); });
    }
    function _load(id: string): void {
        AccessAPI.get(id).then(function(p) {
            _activeId = p.id;
            localStorage.setItem("access_active_project", _activeId);
            var d = typeof p.data === "string" ? JSON.parse(p.data) : (p.data || {});
            Object.keys(D).forEach(function(k) { delete (D as Record<string, unknown>)[k]; });
            Object.assign(D, d);
            if (typeof _setDataReady === "function") _setDataReady();
            if (typeof _initDataAndRender === "function") _initDataAndRender();
            else if (typeof renderAll === "function") renderAll();
        }).catch(function() {
            localStorage.removeItem("access_active_project");
            _createNew();
        });
    }
    function _createNew(): void {
        var init = typeof ACCESS_INIT_DATA !== "undefined" ? JSON.parse(JSON.stringify(ACCESS_INIT_DATA)) : {};
        AccessAPI.create({ name: "", data: init }).then(function(p) {
            _activeId = p.id;
            localStorage.setItem("access_active_project", _activeId);
            Object.keys(D).forEach(function(k) { delete (D as Record<string, unknown>)[k]; });
            Object.assign(D, init);
            if (typeof _setDataReady === "function") _setDataReady();
            if (typeof _initDataAndRender === "function") _initDataAndRender();
            else if (typeof renderAll === "function") renderAll();
        }).catch(function(e) { console.error("Access init failed:", e); });
    }
};

// ─── Toolbar user pill (name + admin + logout) ──────────────────
function _initAuth(): void {
    fetch("auth/providers").then(function(r) { return r.json(); }).then(function(data) {
        if (!data.auth_enabled) return;
        fetch("auth/me", { credentials: "same-origin" }).then(function(r) {
            if (!r.ok) { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); return; }
            return r.json();
        }).then(function(user: AccessAuthUser | undefined) {
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

_registerTranslations("fr", { "admin.title": "Gestion des utilisateurs", "admin.user": "Utilisateur", "admin.role": "Rôle", "admin.ai": "IA", "admin.last_login": "Connexion", "admin.no_users": "Aucun utilisateur", "admin.ai_toggled": "Accès IA mis à jour", "admin.role_updated": "Rôle mis à jour" });
_registerTranslations("en", { "admin.title": "User management", "admin.user": "User", "admin.role": "Role", "admin.ai": "AI", "admin.last_login": "Last login", "admin.no_users": "No users", "admin.ai_toggled": "AI access updated", "admin.role_updated": "Role updated" });

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", _initAuth);
else _initAuth();


// FEAT-33 — refresh on tab focus when a server-initiated write happened
// while the tab was hidden. Skipped while local edits are in flight.
document.addEventListener("visibilitychange", function() {
    if (document.visibilityState !== "visible" || !_activeId || _saveTimer) return;
    AccessAPI.get(_activeId).then(function(project: any) {
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
