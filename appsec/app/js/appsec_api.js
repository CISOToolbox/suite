var AppSecAPI = (function () {
    "use strict";
    var BASE = "api";
    async function _fetch(path, opts) {
        opts = opts || {};
        opts.credentials = "same-origin";
        if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
            opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
            opts.body = JSON.stringify(opts.body);
        }
        var r = await fetch(BASE + path, opts);
        if (r.status === 401) {
            window.location.href = "login.html";
            return null;
        }
        if (r.status === 204)
            return null;
        if (!r.ok) {
            var detail = "";
            try {
                var errBody = await r.json();
                detail = errBody.detail || "";
            }
            catch (e2) { }
            if (!detail || detail.length > 200 || detail.includes("Traceback") || detail.includes("sqlalchemy")) {
                var msgs = { 400: t("error.bad_request"), 403: t("error.forbidden"), 404: t("error.not_found"), 409: t("error.conflict"), 422: t("error.validation"), 500: t("error.server") };
                detail = msgs[r.status] || t("error.generic");
            }
            throw new Error(detail);
        }
        return r.json();
    }
    return {
        _fetch: _fetch, // exposed for audit-log and other direct calls
        listApps: function () { return _fetch("/applications"); },
        getApp: function (id) { return _fetch("/applications/" + id); },
        createApp: function (data) { return _fetch("/applications", { method: "POST", body: data }); },
        updateApp: function (id, data) { return _fetch("/applications/" + id, { method: "PATCH", body: data }); },
        deleteApp: function (id) { return _fetch("/applications/" + id, { method: "DELETE" }); },
        triggerScan: function (id) { return _fetch("/applications/" + id + "/scan", { method: "POST" }); },
        getFinding: function (id) { return _fetch("/findings/" + id); },
        listFindings: function (params) {
            var qs = Object.entries(params || {}).filter(function (e) { return e[1] !== null && e[1] !== undefined && e[1] !== ""; }).map(function (e) { return e[0] + "=" + encodeURIComponent(e[1]); }).join("&");
            return _fetch("/findings" + (qs ? "?" + qs : ""));
        },
        findingsStats: function (appId) { return _fetch("/findings/stats" + (appId ? "?app_id=" + appId : "")); },
        triageFinding: function (id, data) { return _fetch("/findings/" + id, { method: "PATCH", body: data }); },
        bulkTriageFindings: function (data) { return _fetch("/findings/bulk-triage", { method: "POST", body: data }); },
        analyzeFinding: function (id, opts) {
            var body = { finding_id: id };
            if (opts) {
                if (opts.lang)
                    body.lang = opts.lang;
                if (opts.context)
                    body.context = opts.context;
                if (opts.deep)
                    body.deep = true;
            }
            return _fetch("/ai/appsec/analyze-finding", { method: "POST", body: body });
        },
        listScans: function (appId) { return _fetch("/scans" + (appId ? "?app_id=" + appId : "")); },
        resetStuckScans: function (appId) { return _fetch("/scans/reset/" + appId, { method: "POST" }); },
        listMeasures: function () { return _fetch("/measures"); },
        updateMeasure: function (id, data) { return _fetch("/measures/" + id, { method: "PATCH", body: data }); },
        deleteMeasure: function (id) { return _fetch("/measures/" + id, { method: "DELETE" }); },
        listSBOM: function (params) {
            var qs = Object.entries(params || {}).filter(function (e) { return e[1] !== null && e[1] !== undefined && e[1] !== ""; }).map(function (e) { return e[0] + "=" + encodeURIComponent(e[1]); }).join("&");
            return _fetch("/sbom" + (qs ? "?" + qs : ""));
        },
    };
})();
// ─── Toolbar user pill (name + admin + logout) ──────────────────
function _initAuth() {
    fetch("auth/providers").then(function (r) { return r.json(); }).then(function (data) {
        if (!data.auth_enabled)
            return;
        fetch("auth/me", { credentials: "same-origin" }).then(function (r) {
            if (!r.ok) {
                var _rp = window.location.pathname.replace(/[^/]*$/, "");
                window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp);
                return;
            }
            return r.json();
        }).then(function (user) {
            if (!user)
                return;
            window._currentUser = user;
            var right = document.getElementById("toolbar-right");
            if (!right)
                return;
            var h = "";
            h += '<span style="color:var(--ct-ink-1);font-size:var(--ct-text-label);margin:0 var(--ct-s1)">' + esc(user.name || user.email) + '</span>';
            h += '<button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_logout" title="Sign out">&#x23FB;</button>';
            var container = document.createElement("span");
            container.className = "toolbar-right";
            container.style.cssText = "display:flex;align-items:center;gap:4px;margin-left:auto";
            container.innerHTML = h;
            right.parentNode.insertBefore(container, right);
            fetch("auth/role", { credentials: "same-origin" }).then(function (rr) {
                return rr.ok ? rr.json() : {};
            }).then(function (roleInfo) {
                var role = roleInfo.role || "";
                window._moduleRole = role;
                if (role)
                    document.body.classList.add("role-" + role);
                if (user.role === "admin")
                    document.body.classList.add("role-admin");
            }).catch(function () { });
        });
    }).catch(function () { });
}
window._logout = function () {
    fetch("auth/logout", { method: "POST", credentials: "same-origin" })
        .finally(function () { window.location.href = "/auth/logout"; });
};
if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", _initAuth);
else
    _initAuth();
