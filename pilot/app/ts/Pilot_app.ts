/**
 * CISO Toolbox — Pilot App
 * Dashboard, module portal, measures roadmap, user admin.
 */
(function() {
"use strict";

window.CT_CONFIG = {
    edition: "suite",
    module: "pilot",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
};

var _panel = "dashboard";
var _dashData: PilotDashboard | null = null;
var _measures: PilotMeasure[] = [];
var _groups: PilotMeasureGroup[] = [];          // FEAT-11 meta-measures
var _evidences: any[] = [];          // FEAT-08 consolidated evidence registry
var _evidenceSyncStatus = "";
var _evidenceFilter: { module: string; search: string } = { module: "", search: "" };
var _users: PilotUser[] = [];
var _modules: PilotModuleEntry[] = [];
var _projects: PilotProject[] = [];
var _editingProject: PilotProject | null = null;

var BASE = "api";

async function _fetch(url: string, opts?: PilotFetchInit): Promise<any> {
    opts = opts || {};
    opts.credentials = "same-origin";
    if (opts.body && typeof opts.body === "object") {
        opts.headers = opts.headers || {};
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(BASE + url, opts);
    if (resp.status === 401) { window.location.href = "/login.html"; throw new Error("Not authenticated"); }
    if (resp.status === 204) return null;
    if (!resp.ok) throw new Error("API " + resp.status);
    return resp.json();
}
// Expose for sibling panel modules (Pilot_kpis.js etc.)
window._fetch = _fetch;

// ═══════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════


// Badges Pilot — deux natures, deux primitives (spec §2).
//
// L'IDENTITÉ d'un module est une référence, pas une alerte : .ct-ref, avec les
// couleurs d'identité que le socle définit déjà par module. L'ancienne table
// locale faisait porter critical-tint à access, surface ET risk — trois modules
// qui s'affichaient en rouge, donc trois modules qui se lisaient comme un
// incident.
//
// Un ÉTAT se mappe sur un ton sémantique fermé, jamais sur une classe par
// valeur : c'est ce qui permet d'ajouter un statut sans ajouter de CSS.
var _PILOT_TONES: Record<string, string> = {
    completed: "low", termine: "low",
    in_progress: "info", en_cours: "info",
    planned: "medium", planifie: "medium",
    overdue: "critical", critical: "critical", high: "critical",
    on_hold: "neutral", medium: "medium", low: "low",
};

function _pilotTone(v?: string | null): string {
    return _PILOT_TONES[(v || "").toString()] || "neutral";
}

function _pilotModuleRef(mod?: string | null): string {
    var m = (mod || "").toString();
    return '<span class="ct-ref" data-module="' + esc(m) + '">' + esc(m) + '</span>';
}

function _initAuth() {
    fetch("/auth/providers").then(function(r) { return r.json(); }).then(function(data) {
        if (!data.auth_enabled) { _boot(); return; }
        fetch("/auth/me", { credentials: "same-origin" }).then(function(r) {
            if (!r.ok) { window.location.href = "/login.html"; return; }
            return r.json();
        }).then(function(user) {
            if (!user) return;
            window._currentUser = user;
            var right = document.getElementById("toolbar-right");
            if (right) {
                var h = "";
                h += '<span style="color:var(--ct-ink-1);font-size:var(--ct-text-label);margin:0 var(--ct-s1)">' + esc(user.name || user.email) + '</span>';
                h += '<button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_openNotifPrefs" title="' + t("notif.title") + '">' + _icon("bell", 15) + '</button>';
                h += '<button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_logout" title="' + t("pilot.auth.sign_out") + '">&#x23FB;</button>';
                right.innerHTML = h;
            }
            _boot();
        });
    }).catch(function() { _boot(); });
}

window._logout = function() {
    fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).then(function() { window.location.href = "/login.html"; });
};

// FEAT-34/35 — préférences de notification : modale partagée ct_notifprefs
window._openNotifPrefs = function() {
    if (!window.ct_notifprefs) return;
    var isAdmin = !!(window._currentUser && window._currentUser.role === "admin");
    window.ct_notifprefs.open({
        fetchPrefs: function() { return _fetch("/me/notification-prefs"); },
        savePrefs: function(prefs: Record<string, any>) { return _fetch("/me/notification-prefs", { method: "PUT", body: prefs }); },
        sendTest: function() { return _fetch("/me/notification-prefs/test", { method: "POST" }); },
        isAdmin: isAdmin,
        modules: _modules.map(function(m) { return m.id; })
    });
};

// ═══════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════

var _refreshTimer: number | null = null;

window.selectPanel = function(id: string) {
    _panel = id;
    document.querySelectorAll(".ct-rail-item").forEach(function(el) {
        var args = el.getAttribute("data-args");
        if (args) try { if (JSON.parse(args)[0] === id) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current"); } catch(e) {}
    });
    _renderPanel();
    // Auto-refresh dashboard every 30s when visible
    if (_refreshTimer) clearInterval(_refreshTimer);
    if (id === "dashboard") {
        _refreshTimer = setInterval(function() {
            _loadDashboard().then(function() { if (_panel === "dashboard") _renderPanel(); });
        }, 30000);
    }
    // Sync measures on entry into the measures panel so freshly created module measures appear immediately
    if (id === "measures") {
        _syncMeasuresBackground().then(function() { if (_panel === "measures") _renderPanel(); });
    }
    if (id === "evidences") {
        _syncEvidencesBackground().then(function() { if (_panel === "evidences") _renderPanel(); });
    }
    if (id === "backups") {
        // The activity journal must reflect what just happened in the
        // modules — refetch on every entry into the panel.
        _rstJournal = null;
    }
};

// Re-render the current panel — invoked by switchLang() (header toggle +
// settings drawer) so the in-page content, built in JS via t(), refreshes
// into the new language (data-i18n rail labels are handled separately by
// _applyStaticTranslations).
(window as unknown as { renderAll?: () => void }).renderAll = function() { _renderPanel(); };

function _renderPanel() {
    var c = document.getElementById("content")!;
    switch (_panel) {
        case "dashboard": _renderDashboard(c); break;
        case "projets": _renderProjects(c); break;
        case "measures": _renderMeasures(c); break;
        case "evidences": _renderEvidences(c); break;
        case "kpis": _renderKpis(c); break;
        case "directory": _renderDirectory(c); break;
        case "users": _renderUsers(c); break;
        case "backups": _renderBackups(c); break;
        case "restore": _panel = "backups"; _bkTab = "restore"; _renderBackups(c); break;
        case "connectors": window._renderConnectors(c); break;
        case "settings": _renderSettings(c); break;
        default: _renderDashboard(c);
    }
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════

function _renderDashboard(c: HTMLElement) {
    if (!_dashData) { c.innerHTML = '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.common.loading") + '</div>'; return; }
    var d = _dashData;
    var kpis = d.kpis || {};
    var h = '<h2 class="ct-mb-4">' + t("pilot.dashboard.title") + '</h2>';

    // ── Zone 2: KPIs consolidés ──
    h += '<div class="ct-kpigrid">';
    // Global posture (gauge) — ct-kpi shell holds the SVG gauge in the value
    // slot; the local .dash-kpi-gauge wrapper is kept purely to centre the SVG.
    var postureVal = kpis.posture_global;
    // Label computed from the score frontend-side (translated, re-renders on
    // language switch) rather than consuming the backend's fixed FR posture_label.
    var postureLabel = _postureLabel(postureVal);
    // Conditional tone from the score itself (mirrors _postureColor's bands):
    // >=70 green (low), 40-69 amber (high), <40 red (critical), null → neutral.
    var postureTone = _kpiTone(postureVal, { dir: "up", amber: 70, red: 40 });
    h += '<div class="ct-kpi"' + (postureTone ? ' data-tone="' + postureTone + '"' : '') + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
    h += '<div class="ct-kpi-label">' + esc(t("pilot.dashboard.global_posture")) + '</div>';
    if (postureVal != null) {
        h += '<div class="dash-kpi-gauge">' + _svgGauge(postureVal, 100, { size: 128, sublabel: postureLabel }) + '</div>';
    } else {
        h += '<div class="dash-kpi-empty">' + esc(t("pilot.common.no_data")) + '</div>';
    }
    h += '</div></div>';

    // Measures — neutral value, coloured pills for overdue/done
    h += '<div class="ct-kpi"><div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
    h += '<div class="ct-kpi-label">' + esc(t("pilot.dashboard.measures")) + '</div>';
    h += '<div class="ct-kpi-value">' + (kpis.measures_total || 0) + '</div>';
    h += '<div class="ct-kpi-split">';
    if ((kpis.measures_overdue || 0) > 0) {
        h += '<span class="ct-badge" data-tone="critical">' + esc(t("pilot.dashboard.overdue_n", { n: kpis.measures_overdue || 0 })) + '</span>';
    }
    if ((kpis.measures_done_last_30d || 0) > 0) {
        h += '<span class="ct-badge" data-tone="low">' + esc(t("pilot.dashboard.done_30d", { n: kpis.measures_done_last_30d || 0 })) + '</span>';
    }
    h += '</div>';
    h += '</div></div>';

    // Critical items — value-based tone: 0 reads green (low), >0 red (critical).
    var critCount = kpis.critical_count || 0;
    var critTone = _kpiTone(critCount, { bad: 1 });
    h += '<div class="ct-kpi"' + (critTone ? ' data-emphasis="value" data-tone="' + critTone + '"' : '') + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
    h += '<div class="ct-kpi-label">' + esc(t("pilot.dashboard.critical_items")) + '</div>';
    h += '<div class="ct-kpi-value">' + critCount + '</div>';
    var cbreak = kpis.critical_breakdown || {};
    h += '<div class="ct-kpi-split">';
    Object.keys(cbreak).sort().forEach(function(k) {
        h += '<span class="ct-badge" data-tone="neutral">' + esc(k) + ' ' + cbreak[k] + '</span>';
    });
    h += '</div>';
    h += '</div></div>';

    // FEAT-08 — cross-module evidence expiry (EvidenceCache); the legacy
    // compliance-only proofs_expired_10d feeds the badge detail.
    var evx = (kpis as any).evidences || {};
    var proofsExp = evx.expired || 0;
    var proofsSoon = evx.expiring_soon || 0;
    var proofsTone = _kpiTone(proofsExp, { bad: 1 });
    h += '<div class="ct-kpi"' + (proofsTone ? ' data-emphasis="value" data-tone="' + proofsTone + '"' : '') + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
    h += '<div class="ct-kpi-label">' + esc(t("pilot.dashboard.expired_proofs")) + '</div>';
    h += '<div class="ct-kpi-value">' + proofsExp + '</div>';
    h += '<div class="ct-kpi-split">';
    if (proofsSoon > 0) {
        h += '<span class="ct-badge" data-tone="medium">' + proofsSoon + ' ' + esc(t("pilot.dashboard.expiring_soon")) + '</span>';
    }
    if (proofsExp > 0) {
        h += '<span class="ct-badge" data-tone="critical">' + esc(t("pilot.dashboard.all_modules_badge")) + '</span>';
    }
    h += '</div>';
    h += '</div></div>';

    // ── Santé sauvegardes (FEAT-30 phase 3) — tuile compacte ──
    var bk = (d as any).backups;
    if (bk) {
        var bkStale = (bk.stanzas_stale || []).length;
        var bkFailed = (bk.restore_test_failed || []).length;
        var bkTone = (bkStale + bkFailed) > 0 ? "critical" : "low";
        h += '<div class="ct-kpi" data-emphasis="value" data-tone="' + bkTone + '"><div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
        h += '<div class="ct-kpi-label">' + esc(t("pilot.dashboard.backups")) + '</div>';
        h += '<div class="ct-kpi-value">' + ((bk.stanzas_total || 0) - bkStale) + '/' + (bk.stanzas_total || 0) + '</div>';
        h += '<div class="ct-kpi-split">';
        // Badges compacts (la tuile KPI est étroite) : le détail — noms de
        // modules, date du dernier test — vit dans l'infobulle.
        if (bkStale > 0) {
            h += '<span class="ct-badge" data-tone="critical" title="' + esc(bk.stanzas_stale.join(", ")) + '">' + esc(t("pilot.dashboard.backups_stale_n", { n: bkStale })) + '</span>';
        }
        if (bkFailed > 0) {
            h += '<span class="ct-badge" data-tone="critical" title="' + esc(bk.restore_test_failed.join(", ")) + '">' + esc(t("pilot.dashboard.restore_test_failed_n", { n: bkFailed })) + '</span>';
        } else if (bk.restore_test_at) {
            h += '<span class="ct-badge" data-tone="low" title="' + esc(new Date(bk.restore_test_at).toLocaleString()) + '">' + esc(t("pilot.dashboard.restore_test_ok_short")) + '</span>';
        }
        h += '</div></div></div>';
    }

    h += '</div>';  // /ct-kpigrid

    // Upcoming deadlines — titled list card (socle .ct-card, NOT a ct-kpi tile:
    // it holds a list of items, not a scalar value, so a KPI tile is too small).
    var upcoming = d.upcoming || [];
    h += '<div class="ct-card ct-mt-4">';
    h += '<div class="ct-card-head"><div class="ct-card-title">' + esc(t("pilot.dashboard.upcoming_deadlines")) + '</div></div>';
    h += '<div class="ct-card-body">';
    if (!upcoming.length) {
        h += '<div class="dash-kpi-empty">' + esc(t("pilot.dashboard.no_deadline")) + '</div>';
    } else {
        h += '<ul class="dash-upcoming">';
        upcoming.forEach(function(u) {
            var daysLabel = u.days_left != null ? (u.days_left === 0 ? t("pilot.common.today") : t("pilot.common.days_short", { n: u.days_left })) : u.date;
            var cls = (u.days_left != null && u.days_left <= 7) ? 'dash-upcoming-soon' : '';
            h += '<li class="' + cls + '"><span class="dash-upcoming-days">' + esc(daysLabel) + '</span> ' + esc(u.label) + '</li>';
        });
        h += '</ul>';
    }
    h += '</div></div>';

    // ── Zone 3: Grille modules riches ──
    var MODULE_ORDER = ["risk", "vendor", "compliance", "access", "surface", "asset", "appsec", "watch", "audit"];
    var sortedModules = (d.modules || []).slice().sort(function(a, b) {
        var ia = MODULE_ORDER.indexOf(a.id), ib = MODULE_ORDER.indexOf(b.id);
        if (ia < 0) ia = 99; if (ib < 0) ib = 99;
        return ia - ib;
    });
    h += '<h3 class="dash-section-title">' + t("pilot.modules.title") + '</h3>';
    h += '<div class="dash-modules">';
    sortedModules.forEach(function(m) {
        h += _renderModuleCard(m);
    });
    h += '</div>';

    // ── Zone 4: Activity feed ──
    h += '<h3 class="dash-section-title">' + t("pilot.dashboard.recent_activity") + '</h3>';
    h += '<div class="dash-activity">';
    var activity = d.activity || [];
    if (!activity.length) {
        h += '<div class="dash-kpi-empty">' + t("pilot.dashboard.no_activity") + '</div>';
    } else {
        h += '<ul class="dash-activity-list">';
        activity.forEach(function(ev) {
            var when = (ev.date || "").replace("T", " ").substring(0, 16);
            h += '<li>';
            h += '<span class="ct-ref" data-module="' + esc(ev.module || '') + '">' + esc(ev.module || '') + '</span>';
            h += '<span class="dash-activity-label">' + esc(ev.label || '') + '</span>';
            h += '<span class="dash-activity-date">' + esc(when) + '</span>';
            h += '</li>';
        });
        h += '</ul>';
    }
    h += '</div>';

    c.innerHTML = h;
}

function _renderModuleCard(m: PilotModuleEntry) {
    var stats = m.stats || {};
    var measures = stats.measures || {};
    var alerts = stats.alerts || [];
    var linkAttr = m.url ? ' data-click="_openModule" data-args=\'' + _da(m.url) + '\' class="ct-clickable"' : '';

    var h = '<div class="dash-module-card"' + linkAttr + '>';

    // ── 1. Header: icon + name (clickable) + status chip ──
    h += '<div class="dash-module-header">';
    h += '<span class="pilot-card-icon">' + _moduleIcon(m.id) + '</span>';
    h += '<span class="dash-module-name">' + esc(m.name) + '</span>';
    h += '<span class="pilot-card-status ' + esc(m.status || '') + '">' + esc(m.status || '') + '</span>';
    h += '</div>';

    // Inactive module — show placeholder and stop here
    if (m.status !== "active" || !stats || !stats.breakdown) {
        h += '<div class="dash-module-empty">';
        h += (m.status === "external" ? t("pilot.module.external") : (m.status === "unreachable" ? t("pilot.module.unreachable") : t("pilot.common.no_data")));
        h += '</div>';
        h += '</div>';
        return h;
    }

    // ── 2. Legend (entity count + label) above the chart ──
    h += '<div class="dash-module-legend">';
    h += '<strong>' + (stats.entity_count || 0) + '</strong> ' + esc(stats.entity_label || '').toLowerCase();
    h += '</div>';

    // ── 3. Chart (donut or bar) centred ──
    h += '<div class="dash-module-viz">';
    h += _svgBreakdown(stats.breakdown, { width: 260 });
    h += '</div>';

    // ── 4+5. Footer: alerts + measures, pushed to card bottom ──
    h += '<div class="dash-module-footer">';

    if (alerts.length) {
        h += '<div class="dash-module-alerts">';
        alerts.forEach(function(a) {
            h += '<div class="dash-alert dash-alert--' + esc(a.level || 'info') + '">' + esc(a.text || '') + '</div>';
        });
        h += '</div>';
    }

    h += '<div class="dash-module-measures">';
    if ((measures.total || 0) > 0) {
        var pct = measures.progress_pct || 0;
        h += '<div class="dash-measures-label">' + t("pilot.module.measures_progress", { completed: measures.completed || 0, total: measures.total || 0, pct: pct }) + '</div>';
        h += '<div class="dash-measures-bar"><div class="dash-measures-fill" style="width:' + pct + '%"></div></div>';
    } else {
        h += '<div class="dash-measures-label dash-measures-none">' + t("pilot.module.no_measures") + '</div>';
    }
    h += '</div>';

    h += '</div>'; // /dash-module-footer

    h += '</div>';
    return h;
}

function _openModule(url: string) {
    // Navigation sink — guarded because evidence URLs are user-entered
    // (a proof's `url` from any compliance user flows into the Pilot registry).
    if (!url) return;
    // Same-origin app deep-links (e.g. "/risk/#measures") navigate in place;
    // reject protocol-relative "//host" AND "/\host": browsers fold that
    // backslash to a slash, so it left this guard as a same-origin path and
    // arrived at the network layer as "//host" — off-site navigation.
    if (url.charAt(0) === "/" && url.charAt(1) !== "/" && url.charAt(1) !== "\\") {
        window.location.href = url; return;
    }
    // External links must be http(s) and open in a new tab with no opener.
    if (/^https?:\/\//i.test(url)) { window.open(url, "_blank", "noopener,noreferrer"); return; }
    // Anything else (javascript:, data:, protocol-relative, …) is refused.
}
window._openModule = _openModule;

function _moduleIcon(id: string) {
    return '<img src="img/modules/' + esc(id) + '.svg" alt="" style="width:24px;height:24px;vertical-align:middle">';
}

// ═══════════════════════════════════════════════════════════════
// MODULES
// ═══════════════════════════════════════════════════════════════

window._healthCheck = function() {
    _fetch("/modules/health-check", { method: "POST" }).then(function(r) {
        showStatus(t("pilot.modules.health_ok"));
        _loadModules().then(function() { _renderPanel(); });
    }).catch(function(e) { showStatus(t("pilot.modules.health_error", { msg: e.message || e }), true); });
};

// ═══════════════════════════════════════════════════════════════
// MEASURES
// ═══════════════════════════════════════════════════════════════

// FEAT-13 — deep-link to the exact measure in its source module. The module
// reads ?entity/?measure (shared ct_handleMeasureDeepLink) and opens its
// native editor; #measures keeps the hash-based panel selection working.
function _moduleMeasureUrl(em: PilotMeasure): string {
    return _moduleUrl(em.module) + "?entity=" + encodeURIComponent(em.entity_id || "")
        + "&measure=" + encodeURIComponent(em.source_id || "") + "#measures";
}

function _moduleUrl(modId: string) {
    for (var i = 0; i < _modules.length; i++) {
        if (_modules[i].id === modId) return _modules[i].external_url;
    }
    return "";
}

// Status order used by both views (list status select, kanban columns,
// drop-zone whitelist). Keep this single source of truth in sync with the
// backend Literal in src/routes/measures.py::MeasureUpdate.
var _MEASURE_STATUSES = ["backlog", "planned", "in_progress", "completed"];
var _measureView = (function() {
    try { return localStorage.getItem("pilot_measures_view") || "list"; }
    catch (e) { return "list"; }
})();
if (_measureView !== "list" && _measureView !== "kanban") _measureView = "list";

function _renderMeasures(c: HTMLElement) {
    var today = new Date().toISOString().split("T")[0];
    var h = '<div class="ct-flex ct-items-center ct-gap-3 ct-row-wrap"><h2 class="ct-m-0">' + t("pilot.measures.title") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-click="_syncMeasuresNow">&#x21bb; ' + t("pilot.action.sync") + '</button>';
    h += '<button class="ct-btn btn-ai mt-8" data-write data-click="_aiSuggestGroups" title="' + t("pilot.ai.groups_tooltip") + '">' + t("pilot.ai.groups_btn") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="_showNewMeasureForm">+ ' + t("pilot.measures.new") + '</button>';
    // View toggle (Liste / Kanban). Persisted in localStorage so the user
    // lands on their preferred view after a page reload.
    h += '<div class="pilot-view-toggle">';
    h += '<button class="pilot-view-btn' + (_measureView === "list" ? " active" : "") + '" data-click="_setMeasureView" data-args=\'' + _da("list") + '\'>' + t("pilot.view.list") + '</button>';
    h += '<button class="pilot-view-btn' + (_measureView === "kanban" ? " active" : "") + '" data-click="_setMeasureView" data-args=\'' + _da("kanban") + '\'>' + t("pilot.view.kanban") + '</button>';
    h += '</div>';
    h += '</div>';

    if (_syncStatus) h += '<div style="font-size:var(--ct-text-label);color:var(--ct-ink-2);margin:var(--ct-s2) 0 var(--ct-s3)">' + esc(_syncStatus) + '</div>';

    if (!_measures.length) {
        h += '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.measures.empty") + '</div>';
        c.innerHTML = h;
        return;
    }

    // ── Filter bar (shared between Liste and Kanban) ──────────────
    h += '<div class="pilot-actions ct-row-wrap ct-gap-2">';
    h += '<input type="text" id="filter-search" placeholder="' + t("pilot.common.search") + '" value="' + esc(_measureFilter.search || '') + '" data-input="_filterMeasures" data-pass-value class="ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta ct-minw-180">';
    h += '<select id="filter-module" data-change="_filterMeasures" data-pass-value class="ct-filter"><option value="">' + t("pilot.filter.all_modules") + '</option>';
    var seenMods: Record<string, boolean> = {};
    _measures.forEach(function(m) { seenMods[m.module] = true; });
    Object.keys(seenMods).sort().forEach(function(mod) {
        h += '<option value="' + esc(mod) + '"' + (_measureFilter.module === mod ? ' selected' : '') + '>' + esc(mod) + '</option>';
    });
    h += '</select>';
    // Project dropdown — alimenté par _projects + valeurs spéciales
    // "" = tous projets, "__none__" = actions non rattachées.
    h += '<select id="filter-project" data-change="_filterMeasures" data-pass-value class="ct-filter">';
    h += '<option value="">' + t("pilot.filter.all_projects") + '</option>';
    h += '<option value="__none__"' + (_measureFilter.project === "__none__" ? ' selected' : '') + '>' + t("pilot.filter.no_project") + '</option>';
    (_projects || []).slice().sort(function(a, b) {
        return (a.name || "").localeCompare(b.name || "");
    }).forEach(function(p) {
        h += '<option value="' + esc(p.id) + '"' + (_measureFilter.project === p.id ? ' selected' : '') + '>' + esc(p.name || "") + '</option>';
    });
    h += '</select>';
    // Status filter is only meaningful in list view — Kanban exposes the
    // 4 statuses as columns so re-hiding rows by status would be confusing.
    if (_measureView === "list") {
        h += '<select id="filter-status" data-change="_filterMeasures" data-pass-value class="ct-filter"><option value="">' + t("pilot.filter.all_statuses") + '</option>';
        _MEASURE_STATUSES.forEach(function(s) {
            h += '<option value="' + s + '"' + (_measureFilter.status === s ? ' selected' : '') + '>' + esc(t("pilot.measure.status." + s)) + '</option>';
        });
        h += '</select>';
        h += '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1"><input type="checkbox" id="filter-overdue"' + (_measureFilter.overdue ? ' checked' : '') + ' data-change="_filterMeasures" data-pass-value> ' + t("pilot.filter.overdue_only") + '</label>';
    }
    h += '</div>';

    // Build assigned set + measure→project map (needed by both views and
    // by the orphan filter / project filter).
    var assigned: Record<string, boolean> = {};
    var measureProject: Record<string, PilotProject> = {};
    (_projects || []).forEach(function(p) {
        (p.measures || []).forEach(function(pm) {
            assigned[pm.id] = true;
            measureProject[pm.id] = p;
        });
    });

    var q = (_measureFilter.search || "").toLowerCase();
    var filtered = _measures.filter(function(m) {
        if (_measureFilter.module && m.module !== _measureFilter.module) return false;
        if (_measureView === "list" && _measureFilter.status && m.status !== _measureFilter.status) return false;
        if (_measureView === "list" && _measureFilter.overdue) {
            if (!(m.due_date && m.due_date < today && m.status !== "completed")) return false;
        }
        // Orphan checkbox is list-only; in Kanban use the project dropdown
        // (__none__ option) to filter to "Sans projet".
        if (_measureView === "list" && _measureFilter.orphan && assigned[m.id]) return false;
        if (_measureFilter.project) {
            var p = measureProject[m.id];
            if (_measureFilter.project === "__none__") {
                if (p) return false;
            } else if (!p || p.id !== _measureFilter.project) {
                return false;
            }
        }
        if (q) {
            var haystack = ((m.title || "") + " " + (m.source_id || "") + " " + (m.assignee || "") + " " + (m.entity_name || "")).toLowerCase();
            if (haystack.indexOf(q) < 0) return false;
        }
        return true;
    });

    // FEAT-11 — measures linked in a meta-measure leave the individual
    // list/kanban; the group renders as ONE consolidated row/card.
    var memberOf: Record<string, PilotMeasureGroup> = {};
    _groups.forEach(function(g) { (g.members || []).forEach(function(mm) { memberOf[mm.id] = g; }); });
    // Un groupe passe les memes filtres que les mesures : il n'en subissait
    // que celui du module, si bien qu'une recherche sans resultat affichait
    // « 0 / 90 » au compteur pendant que les lignes de groupe restaient au
    // tableau. Un groupe est retenu des qu'un de ses membres correspond —
    // c'est ce qu'on attend d'une ligne consolidee.
    var groupsShown = _groups.filter(function(g) {
        var membres = g.members || [];
        if (_measureFilter.module
            && !membres.some(function(mm) { return mm.module === _measureFilter.module; })) return false;
        if (_measureView === "list" && _measureFilter.status && g.status !== _measureFilter.status) return false;
        if (_measureView === "list" && _measureFilter.overdue
            && !(g.due_date && g.due_date < today && g.status !== "completed")) return false;
        if (_measureFilter.project) {
            var lie = membres.some(function(mm) {
                var pr = measureProject[mm.id];
                return _measureFilter.project === "__none__" ? !pr : (pr && pr.id === _measureFilter.project);
            });
            if (!lie) return false;
        }
        if (_measureView === "list" && _measureFilter.orphan
            && membres.some(function(mm) { return assigned[mm.id]; })) return false;
        if (q) {
            var foin = (g.title || "") + " " + (g.ref || "") + " " + (g.responsible || "") + " "
                + membres.map(function(mm) { return (mm.title || "") + " " + (mm.source_id || ""); }).join(" ");
            if (foin.toLowerCase().indexOf(q) < 0) return false;
        }
        return true;
    });
    filtered = filtered.filter(function(m) { return !memberOf[m.id]; });

    // Le compteur parle d'ACTIONS, pas de lignes : une ligne de groupe en
    // represente plusieurs. Sans ce report, il annoncait « 79 / 90 » alors
    // qu'aucun filtre n'etait pose — les 11 membres de groupes manquaient.
    var shownCount = filtered.length
        + groupsShown.reduce(function(n, g) { return n + (g.members || []).length; }, 0);
    var orphanCount = filtered.filter(function(m) { return !measureProject[m.id]; }).length
        + groupsShown.reduce(function(n, g) {
            return n + (g.members || []).filter(function(mm) { return !measureProject[mm.id]; }).length;
        }, 0);
    h += '<div class="ct-text-label ct-muted ct-mb-2">' + t("pilot.measures.count", { shown: shownCount, total: _measures.length });
    if (orphanCount) h += ' &mdash; <span class="ct-text-high ct-strong">' + t("pilot.measures.orphan_count", { n: orphanCount }) + '</span>';
    h += '</div>';

    if (_measureView === "list") {
        // Filter: show orphans only (list view only)
        h += '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1 ct-mb-2"><input type="checkbox" id="filter-orphan"' + (_measureFilter.orphan ? ' checked' : '') + ' data-change="_filterMeasures" data-pass-value> ' + t("pilot.filter.orphan_only") + '</label>';
        h += _renderMeasuresList((_groupRows(groupsShown) as unknown as PilotMeasure[]).concat(filtered), measureProject, today);
        c.innerHTML = h;
        ct_bulkbar.attach({
            scope: "pilot-measures",
            label: t("pilot.measures.bulk_selected"),
            actions: [
                { id: "link", icon: "link", label: t("pilot.groups.link_action"),
                  onClick: "_linkSelectedMeasures" },
                { id: "delete", icon: "trash", label: t("pilot.action.delete"), danger: true,
                  onClick: "_bulkPilotMeasuresDelete",
                  confirm: { title: t("pilot.measures.bulk_delete_title"),
                             message: t("pilot.measures.bulk_delete_msg") } }
            ]
        });
        ct_bulkbar.update("pilot-measures");
    } else {
        h += _renderMeasuresKanban(filtered, measureProject, today);
        c.innerHTML = h;
        _wireKanbanDnD();
    }
}

function _renderMeasuresList(filtered: PilotMeasure[], measureProject: Record<string, PilotProject>, today: string) {
    return ct_table.render({
        rows: filtered,
        rowKey: "id",
        onRowClick: "_openMeasureRow",
        bulk: { scope: "pilot-measures" },
        rowClass: function(m) {
            return (m.due_date && m.due_date < today && m.status !== "completed") ? "row-overdue" : "";
        },
        columns: [
            { key: "module", label: t("pilot.col.module"), width: "110px",
              render: function(m) {
                  var mods: string[] = (m as Record<string, any>).__modules || [m.module];
                  return mods.map(function(mod: string) {
                      return '<span class="ct-ref" data-module="' + esc(mod) + '">' + esc(mod) + '</span>';
                  }).join(" ");
              } },
            { key: "source_id", label: t("pilot.col.ref"), width: "120px",
              render: function(m) {
                  var r = m as Record<string, any>;
                  if (r.__group_id) return '<span class="ct-badge" data-size="sm" data-tone="info" title="' + r.__member_count + ' ' + esc(t("pilot.groups.members_word")) + '">' + _icon("link", 10) + ' ' + esc(r.__ref || String(r.__member_count)) + '</span>';
                  return '<span class="ct-mono ct-text-meta">' + esc(m.source_id) + '</span>';
              } },
            { key: "title", label: t("pilot.col.measure"),
              render: function(m) {
                  var r = m as Record<string, any>;
                  var h2 = esc(m.title || "");
                  if (r.__diverged) h2 += ' <span class="ct-badge" data-size="sm" data-tone="medium" title="' + esc(t("pilot.groups.diverged_hint")) + '">' + esc(t("pilot.groups.diverged")) + '</span>';
                  return h2;
              } },
            { key: "entity", label: t("pilot.col.entity"), width: "160px",
              render: function(m) {
                  var e = m.entity_name || m.vendor_name || "";
                  if (!e) return '<span class="text-muted">—</span>';
                  var short = e.length > 22 ? e.slice(0, 20) + "…" : e;
                  return '<span title="' + esc(e) + '" class="ct-text-label">' + esc(short) + '</span>';
              } },
            { key: "project", label: t("pilot.col.project"), width: "140px",
              render: function(m) {
                  if ((m as Record<string, any>).__group_id) return '<span class="text-muted">&mdash;</span>';
                  var p = measureProject[m.id];
                  if (p) return '<span class="ct-badge" data-tone="info" title="'
                      + esc(p.name) + '">' + esc(p.name.length > 20 ? p.name.slice(0, 18) + '…' : p.name) + '</span>';
                  return '<span class="ct-badge" data-tone="medium">' + t("pilot.measures.no_project_badge") + '</span>';
              } },
            { key: "status", label: t("pilot.col.status"), width: "130px",
              render: function(m) {
                  var overdue = m.due_date && m.due_date < today && m.status !== "completed";
                  return '<span class="ct-badge" data-tone="' + _pilotTone(m.status) + (overdue ? ' overdue' : '') + '">'
                      + esc(t("pilot.measure.status." + m.status)) + (overdue ? ' \u26A0' : '') + '</span>';
              } },
            { key: "assignee", label: t("pilot.col.owner"),
              render: function(m) { return esc(m.assignee || ""); } },
            { key: "due_date", label: t("pilot.col.due_date"), width: "130px",
              render: function(m) {
                  var overdue = m.due_date && m.due_date < today && m.status !== "completed";
                  if (!m.due_date) return "";
                  return overdue
                      ? '<span class="ct-text-critical ct-strong">' + esc(m.due_date) + '</span>'
                      : esc(m.due_date);
              } }
        ]
    });
}

// Kanban view: 4 columns mapped to the canonical statuses. Each card is
// draggable; dropping it on another column triggers a PATCH on the
// measure's status with optimistic update + rollback on error.
function _renderMeasuresKanban(filtered: PilotMeasure[], measureProject: Record<string, PilotProject>, today: string) {
    // Bucket measures by status; sort each bucket by due_date asc
    // (overdue first, then upcoming, finally no-date).
    var buckets: Record<string, PilotMeasure[]> = {};
    _MEASURE_STATUSES.forEach(function(s) { buckets[s] = []; });
    filtered.forEach(function(m) {
        var s = _MEASURE_STATUSES.indexOf(m.status) >= 0 ? m.status : "planned";
        buckets[s].push(m);
    });
    Object.keys(buckets).forEach(function(s) {
        buckets[s].sort(function(a, b) {
            // null/empty due_date sinks to the bottom
            var da = a.due_date || "9999-12-31";
            var db = b.due_date || "9999-12-31";
            if (da < db) return -1;
            if (da > db) return 1;
            return (a.title || "").localeCompare(b.title || "");
        });
    });

    var h = '<div class="pilot-kanban">';
    _MEASURE_STATUSES.forEach(function(s) {
        var rows = buckets[s];
        h += '<div class="pilot-kanban-col" data-status="' + esc(s) + '">';
        h += '<div class="pilot-kanban-col-head ' + esc(s) + '">'
          +   '<span class="pilot-kanban-col-title">' + esc(t("pilot.measure.status." + s)) + '</span>'
          +   '<span class="pilot-kanban-col-count">' + rows.length + '</span>'
          + '</div>';
        h += '<div class="pilot-kanban-col-body" data-status="' + esc(s) + '">';
        _groups.forEach(function(g) {
            if ((g.status || "planned") !== s) return;
            h += _renderGroupCard(g, today);
        });
        rows.forEach(function(m) {
            var overdue = m.due_date && m.due_date < today && m.status !== "completed";
            var p = measureProject[m.id];
            h += '<div class="pilot-kanban-card' + (overdue ? ' overdue' : '') + '" draggable="true" data-measure-id="' + esc(m.id) + '" data-click="_openMeasureRow" data-args=\'' + _da({ id: m.id, module: m.module, source_id: m.source_id }) + '\'>';
            h += '<div class="pilot-kanban-card-top">';
            h += '<span class="ct-ref" data-size="sm" data-module="' + esc(m.module) + '">' + esc(m.module) + '</span>';
            h += '<span class="pilot-kanban-card-ref">' + esc(m.source_id || "") + '</span>';
            h += '</div>';
            h += '<div class="pilot-kanban-card-title">' + esc(m.title || t("pilot.common.untitled")) + '</div>';
            if (m.entity_name || m.vendor_name) {
                var e = m.entity_name || m.vendor_name || "";
                h += '<div class="pilot-kanban-card-entity" title="' + esc(e) + '">' + esc(e.length > 28 ? e.slice(0, 26) + "…" : e) + '</div>';
            }
            h += '<div class="pilot-kanban-card-foot">';
            if (p) {
                h += '<span class="ct-badge" data-size="sm" data-tone="info" title="' + esc(p.name) + '">'
                  + esc(p.name.length > 18 ? p.name.slice(0, 16) + "…" : p.name) + '</span>';
            } else {
                h += '<span class="ct-badge" data-size="sm" data-tone="medium">' + t("pilot.measures.no_project_badge") + '</span>';
            }
            if (m.due_date) {
                h += '<span class="pilot-kanban-card-due' + (overdue ? ' overdue' : '') + '">'
                  + esc(m.due_date) + (overdue ? ' \u26A0' : '') + '</span>';
            }
            h += '</div>';
            if (m.assignee) {
                h += '<div class="pilot-kanban-card-assignee">' + esc(m.assignee) + '</div>';
            }
            h += '</div>';
        });
        if (!rows.length) {
            h += '<div class="pilot-kanban-empty">—</div>';
        }
        h += '</div></div>';
    });
    h += '</div>';
    return h;
}

// HTML5 native drag-and-drop. Cards carry their id on dragstart; columns
// accept a drop and trigger an optimistic PATCH (rolled back on error).
function _wireKanbanDnD() {
    var cards = document.querySelectorAll<HTMLElement>(".pilot-kanban-card[draggable=\"true\"]");
    cards.forEach(function(card) {
        card.addEventListener("dragstart", function(e) {
            e.dataTransfer!.effectAllowed = "move";
            e.dataTransfer!.setData("text/plain", card.getAttribute("data-measure-id")!);
            card.classList.add("dragging");
        });
        card.addEventListener("dragend", function() {
            card.classList.remove("dragging");
        });
    });
    var cols = document.querySelectorAll<HTMLElement>(".pilot-kanban-col-body[data-status]");
    cols.forEach(function(col) {
        col.addEventListener("dragover", function(e) {
            e.preventDefault();
            e.dataTransfer!.dropEffect = "move";
            col.classList.add("drop-target");
        });
        col.addEventListener("dragleave", function() {
            col.classList.remove("drop-target");
        });
        col.addEventListener("drop", function(e) {
            e.preventDefault();
            col.classList.remove("drop-target");
            var id = e.dataTransfer!.getData("text/plain");
            var newStatus = col.getAttribute("data-status");
            if (!id || !newStatus) return;
            _moveMeasureStatus(id, newStatus);
        });
    });
}

// Optimistic status update: mutate local state and re-render first, then
// PATCH the server. On failure, restore the previous status and re-render.
function _moveMeasureStatus(measureId: string, newStatus: string) {
    var m = _measures.find(function(x) { return x.id === measureId; });
    if (!m) return;
    if (m.status === newStatus) return;  // no-op drop on the same column
    var prevStatus = m.status;
    m.status = newStatus;
    _renderPanel();
    _fetch("/measures/" + encodeURIComponent(measureId), {
        method: "PATCH", body: { status: newStatus }
    }).then(function() {
        showStatus(t("pilot.measures.status_set", { status: t("pilot.measure.status." + newStatus) }));
    }).catch(function(err) {
        m!.status = prevStatus;
        _renderPanel();
        showStatus(t("pilot.common.error_msg", { msg: err.message || err }), true);
    });
}

window._setMeasureView = function(view: string) {
    if (view !== "list" && view !== "kanban") return;
    _measureView = view;
    try { localStorage.setItem("pilot_measures_view", view); } catch (e) {}
    _renderPanel();
};

// ct_table passes the row object; open the edit modal via the existing
// module+source_id pair.

// ═══════════════════════════════════════════════════════════════
// FEAT-11 — meta-measures (measure groups)
// ═══════════════════════════════════════════════════════════════

function _groupDiverged(g: PilotMeasureGroup, mm: PilotMeasureGroupMember): boolean {
    return (mm.status || "") !== (g.status || "")
        || (mm.due_date || "") !== (g.due_date || "")
        || (mm.assignee || "") !== (g.responsible || "");
}

function _groupModulesBadge(g: PilotMeasureGroup): string {
    var mods: string[] = [];
    (g.members || []).forEach(function(mm) { if (mods.indexOf(mm.module) < 0) mods.push(mm.module); });
    return mods.join(" + ");
}

// Group rows blend into the measures table: same columns, canonical values,
// the module cell showing every member module (FEAT-11 UX rework).
function _groupRows(groups: PilotMeasureGroup[]): Array<Record<string, unknown>> {
    return groups.map(function(g) {
        var mods: string[] = [];
        (g.members || []).forEach(function(mm) { if (mods.indexOf(mm.module) < 0) mods.push(mm.module); });
        var diverged = (g.members || []).some(function(mm) { return _groupDiverged(g, mm); });
        return {
            id: "grp:" + g.id, __group_id: g.id, __modules: mods,
            __member_count: (g.members || []).length, __diverged: diverged,
            __ref: g.ref || "",
            module: mods.join("+"), source_id: g.ref || "",
            title: g.title || "", status: g.status || "planned",
            assignee: g.responsible || "", due_date: g.due_date || "",
            entity_name: "", vendor_name: ""
        };
    });
}


function _renderGroupCard(g: PilotMeasureGroup, today: string): string {
    var overdue = g.due_date && g.due_date < today && g.status !== "completed";
    var h = '<div class="pilot-kanban-card' + (overdue ? ' overdue' : '') + '" data-click="_openGroupRow" data-args=\'' + _da(g.id) + '\'>';
    h += '<div class="pilot-kanban-card-top"><span class="ct-badge" data-size="sm" data-tone="info">' + _icon("link", 10) + ' ' + esc(_groupModulesBadge(g)) + '</span>' + (g.ref ? ' <span class="ct-mono ct-text-meta ct-muted">' + esc(g.ref) + '</span>' : '') + '</div>';
    h += '<div class="pilot-kanban-card-title">' + esc(g.title || t("pilot.common.untitled")) + '</div>';
    h += '<div class="pilot-kanban-card-foot">';
    if (g.due_date) h += '<span class="ct-text-meta">' + esc(g.due_date) + '</span>';
    if (g.responsible) h += '<span class="ct-text-meta">' + esc(g.responsible) + '</span>';
    h += '</div></div>';
    return h;
}


window._openGroupMemberModule = function(gid: string, mid: string) {
    var g = _groups.find(function(x) { return x.id === gid; });
    var mm = g && (g.members || []).find(function(x) { return x.id === mid; });
    if (mm) window.open(_moduleMeasureUrl(mm as unknown as PilotMeasure), "_blank");
};

window._openGroupRow = function(gid: string) {
    var g0 = _groups.find(function(x) { return x.id === gid; });
    if (!g0 || !window.ct_measure_modal) return;
    var g = g0;
    var diverged = (g.members || []).some(function(mm) { return _groupDiverged(g, mm); });
    var mh = '<div class="ct-bordered ct-r-sm ct-p-2 ct-mb-2">';
    (g.members || []).forEach(function(mm) {
        var d = _groupDiverged(g, mm);
        mh += '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-1">';
        mh += '<span class="ct-ref" data-size="sm" data-module="' + esc(mm.module) + '">' + esc(mm.module) + '</span>';
        mh += '<span class="ct-flex-1 ct-text-label">' + esc(mm.title || "") + '</span>';
        if (d) mh += '<span title="' + esc(t("pilot.groups.diverged_hint")) + '">\u26A0</span>';
        mh += '<button class="ct-btn" data-size="xs" data-stop data-click="_openGroupMemberModule" data-args=\'' + _da(g!.id, mm.id) + '\'>\u2197</button>';
        mh += '<button class="ct-btn" data-size="xs" data-variant="danger" data-stop data-click="_detachGroupMember" data-args=\'' + _da(g!.id, mm.id) + '\'>' + esc(t("pilot.groups.detach")) + '</button>';
        mh += '</div>';
    });
    mh += '</div>';
    var extra: CtModalButton[] = [
        { id: "dissolve", label: t("pilot.groups.dissolve"), danger: true,
          result: function() { return { __dissolve: true }; } }
    ];
    if (diverged) extra.unshift({ id: "resync", label: t("pilot.groups.resync"),
                                  result: function() { return { __resync: true }; } });
    ct_measure_modal.open(
        { title: g.title, statut: g.status, responsable: g.responsible, echeance: g.due_date },
        {
            title: t("pilot.groups.modal_title") + (g.ref ? " \u00b7 " + g.ref : ""),
            headerHtml: mh,
            fieldMap: { statut: "status", responsable: "responsible", echeance: "due_date" },
            hideFields: ["type", "description"],
            journalReadOnly: true,
            statusOptions: [
                { value: "planned",     label: t("pilot.measure.status.planned") },
                { value: "in_progress", label: t("pilot.measure.status.in_progress") },
                { value: "completed",   label: t("pilot.measure.status.completed") },
                { value: "backlog",     label: t("pilot.measure.status.backlog") }
            ],
            defaultStatus: g.status || "planned",
            ownerPicker: { pickerId: "pilot-group-owner", directoryUrl: "api/directory", sourceUrl: null },
            extraButtons: extra
        }
    ).then(function(result) {
        if (!result) return;
        if (result.__resync) { window._resyncGroup!(g!.id); return; }
        if (result.__dissolve) {
            if (!confirm(t("pilot.groups.dissolve_confirm"))) return;
            _fetch("/measure-groups/" + g!.id, { method: "DELETE" }).then(function() {
                showStatus(t("pilot.groups.dissolved"));
                _loadMeasures().then(function() { _renderPanel(); });
            }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
            return;
        }
        _fetch("/measure-groups/" + g!.id, { method: "PATCH", body: {
            title: result.title, status: result.status,
            due_date: result.due_date || "", responsible: result.responsible || ""
        } }).then(function(updated) {
            var errs = (updated && updated.propagation_errors) || [];
            showStatus(errs.length ? t("pilot.groups.saved_with_errors", { n: errs.length }) : t("pilot.groups.saved"));
            _loadMeasures().then(function() { _renderPanel(); });
        }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
    });
};

window._linkSelectedMeasures = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope)).filter(function(id) { return id.indexOf("grp:") !== 0; });
    if (ids.length < 2) { showStatus(t("pilot.groups.need_two"), true); return; }
    var sel = _measures.filter(function(m) { return ids.indexOf(m.id) >= 0; });
    var defTitle = (sel[0] && sel[0].title) || "";
    var title = prompt(t("pilot.groups.title_prompt"), defTitle);
    if (title === null) return;
    _fetch("/measure-groups", { method: "POST", body: { measure_ids: ids, title: title } })
        .then(function(g) {
            ct_bulkbar.clear(scope);
            var errs = (g && g.propagation_errors) || [];
            showStatus(errs.length ? t("pilot.groups.saved_with_errors", { n: errs.length }) : t("pilot.groups.created"));
            _loadMeasures().then(function() { _renderPanel(); });
        })
        .catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
};

window._detachGroupMember = function(gid: string, mid: string) {
    if (window.ct_modal && typeof window.ct_modal.close === "function") window.ct_modal.close();
    _fetch("/measure-groups/" + gid + "/members/" + mid, { method: "DELETE" }).then(function(r) {
        showStatus(r && r.dissolved ? t("pilot.groups.dissolved") : t("pilot.groups.detached"));
        _loadMeasures().then(function() { _renderPanel(); });
    }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
};

window._resyncGroup = function(gid: string) {
    _fetch("/measure-groups/" + gid + "/resync", { method: "POST" }).then(function(g) {
        var errs = (g && g.propagation_errors) || [];
        showStatus(errs.length ? t("pilot.groups.saved_with_errors", { n: errs.length }) : t("pilot.groups.resynced"));
        _loadMeasures().then(function() { _renderPanel(); });
    }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
};


// FEAT-11 phase 2 — AI-suggested measure groupings (same measure raised by
// several modules). Mirrors _aiSuggestProjects: same panel, same _aiCall.
var _aiSuggestedGroups: Array<{ title?: string; measure_ids: string[]; reason?: string }> = [];

window._aiSuggestGroups = function() {
    if (!_measures.length) {
        _aiShowError(t("pilot.ai.groups_title"), t("pilot.ai.no_measures_sync"));
        return;
    }
    // Only ungrouped measures are candidates (one group per measure).
    var grouped: Record<string, boolean> = {};
    _groups.forEach(function(g) { (g.members || []).forEach(function(mm) { grouped[mm.id] = true; }); });
    var candidates = _measures.filter(function(m) { return !grouped[m.id]; });
    if (candidates.length < 2) {
        _aiShowError(t("pilot.ai.groups_title"), t("pilot.ai.groups_not_enough"));
        return;
    }

    _aiShowLoading(t("pilot.ai.groups_title"), t("pilot.ai.groups_analyzing", { n: candidates.length }));

    var system = "Tu es un assistant CISO. On te donne la liste des actions de remediation remontees par les differents modules d'une suite de gouvernance securite (Risk, Compliance, Vendor, Surface, AppSec, Access, Asset, Audit, Watch). " +
        "Une MEME action reelle existe souvent en double : remontee par un module Risk ET par un module Compliance par exemple (titres proches, meme objectif de securite, parfois meme responsable ou meme entite). " +
        "Ta tache : proposer des GROUPEMENTS d'actions qui representent la meme action reelle, pour les piloter en un seul point.\n" +
        "REGLES STRICTES :\n" +
        "  - Ne groupe que des actions qui sont TRES probablement la meme chose (meme objectif concret, pas seulement le meme theme general).\n" +
        "  - Chaque groupe contient au moins 2 actions ; une action apparait dans au plus un groupe.\n" +
        "  - Privilegie les doublons INTER-modules (modules differents) ; un doublon intra-module n'est propose que s'il est evident.\n" +
        "  - Donne a chaque groupe un titre court qui decrit l'action commune.\n" +
        "  - Justifie chaque groupe par UNE phrase qui cite les references groupees.\n" +
        "  - Si aucun doublon plausible n'existe, reponds avec une liste vide.\n" +
        "Reponds STRICTEMENT en JSON valide, sans texte autour, au format :\n" +
        "{ \"groups\": [{\"title\": \"<titre court>\", \"measure_ids\": [\"<id1>\", \"<id2>\"], \"reason\": \"<phrase>\"}] }";

    var user = "ACTIONS (id | module | reference | titre | entite | responsable | statut)\n" +
        candidates.map(function(m) {
            return m.id + " | " + m.module + " | " + m.source_id + " | " + (m.title || "") +
                " | " + (m.entity_name || "") + " | " + (m.assignee || "") + " | " + (m.status || "");
        }).join("\n");

    _aiCall(system, user).then(function(parsed) {
        _aiSuggestedGroups = (parsed && parsed.groups) || [];
        _aiRenderSuggestedGroups();
    }).catch(function(e) {
        _aiShowError(t("pilot.ai.groups_title"), t("pilot.ai.error", { msg: esc(e.message || String(e)) }));
    });
};

function _aiRenderSuggestedGroups() {
    var p = _aiEnsurePanel();
    p.title.textContent = t("pilot.ai.groups_proposed");
    var measureById: Record<string, PilotMeasure> = {};
    _measures.forEach(function(m) { measureById[m.id] = m; });

    var valid = (_aiSuggestedGroups || []).map(function(g) {
        var ids = (g.measure_ids || []).filter(function(id) { return measureById[id]; });
        return { title: g.title || "", measure_ids: ids, reason: g.reason || "" };
    }).filter(function(g) { return g.measure_ids.length >= 2; });
    _aiSuggestedGroups = valid;

    if (!valid.length) {
        p.body.innerHTML = '<div class="ai-empty">' + t("pilot.ai.groups_none") + '</div>';
        p.footer.innerHTML = '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.close") + '</button>';
        return;
    }

    var h = '<div class="ct-text-meta ct-muted ct-mb-3">' + t("pilot.ai.groups_summary", { n: valid.length }) + '</div>';
    valid.forEach(function(g, i) {
        h += '<div class="ai-card"><div class="ai-card-row">';
        h += '<input type="checkbox" class="ai-card-cb ai-group-cb" checked value="' + i + '">';
        h += '<div class="ai-card-content">';
        h += '<div class="ai-card-title">' + _icon("link", 12) + ' ' + esc(g.title || t("pilot.common.untitled")) + '</div>';
        h += '<div class="ai-card-badges">';
        g.measure_ids.forEach(function(id) {
            var m = measureById[id];
            h += '<span class="ct-ref" data-module="' + esc(m.module) + '" title="' + esc(m.title || "") + '">' + esc(m.module) + ' ' + esc(m.source_id) + '</span>';
        });
        h += '</div>';
        if (g.reason) h += '<div class="ai-card-reason ct-mt-1">' + esc(g.reason) + '</div>';
        h += '</div></div></div>';
    });
    p.body.innerHTML = h;
    p.footer.innerHTML = '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.cancel") + '</button>'
        + '<button class="ct-btn" data-variant="primary" data-click="_aiCreateSuggestedGroups">' + t("pilot.ai.groups_create") + '</button>';
}

window._aiCreateSuggestedGroups = function() {
    var checked: number[] = [];
    document.querySelectorAll<HTMLInputElement>(".ai-group-cb:checked").forEach(function(cb) {
        checked.push(parseInt(cb.value, 10));
    });
    if (!checked.length) { _aiClosePanel(); return; }
    var todo = checked.map(function(i) { return _aiSuggestedGroups[i]; }).filter(Boolean);
    var done = 0, errors = 0, propErrors = 0;
    function next(): void {
        var g = todo.shift();
        if (!g) {
            _aiClosePanel();
            var msg = errors ? t("pilot.ai.groups_created_errors", { n: done, e: errors })
                             : t("pilot.ai.groups_created", { n: done });
            if (propErrors) msg += " — " + t("pilot.groups.saved_with_errors", { n: propErrors });
            showStatus(msg, errors > 0 || propErrors > 0);
            _loadMeasures().then(function() { _renderPanel(); });
            return;
        }
        _fetch("/measure-groups", { method: "POST", body: { measure_ids: g.measure_ids, title: g.title } })
            .then(function(created) { done++; propErrors += ((created && created.propagation_errors) || []).length; next(); })
            .catch(function() { errors++; next(); });
    }
    next();
};

window._openMeasureRow = function(row: PilotMeasure) {
    var gid = (row as unknown as Record<string, any>).__group_id;
    if (gid) { window._openGroupRow!(gid); return; }
    if (row) window._openMeasure!(row.module, row.source_id);
};

window._bulkPilotMeasuresDelete = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope)).filter(function(id) { return id.indexOf("grp:") !== 0; });
    if (!ids.length) return;
    Promise.all(ids.map(function(id) {
        return _fetch("/measures/" + id, { method: "DELETE" });
    })).then(function() {
        showStatus(t("pilot.measures.deleted_n", { n: ids.length }));
        ct_bulkbar.clear(scope);
        _measures = _measures.filter(function(m) { return ids.indexOf(m.id) < 0; });
        _renderPanel();
    }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
};

function _showMeasureModal(em: PilotMeasure) {
    var isNative = em.module === "pilot";

    var headerHtml = '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-3">'
        + '<span class="ct-ref" data-module="' + esc(em.module) + '">' + esc(em.module) + '</span>'
        + '<span class="ct-mono ct-text-label ct-muted">' + esc(em.source_id) + '</span>'
        + '</div>'
        + (em.entity_name
            ? '<div class="ct-text-meta ct-muted ct-mb-3">' + t("pilot.measures.entity_prefix") + esc(em.entity_name) + '</div>'
            : '');

    var extraButtons: CtModalButton[] = [];
    if (!isNative) {
        extraButtons.push({
            id: "open_mod",
            label: t("pilot.measures.open_in", { module: em.module }) + " \u2197",
            result: function() { return { __open_module: true }; }
        });
    }

    // Build the project picker. Compute the current association from
    // _projects so the existing assignment is pre-selected and so the diff
    // logic in _saveMeasureEditFromValues can act on it.
    var currentProjectId = "";
    (_projects || []).forEach(function(p) {
        (p.measures || []).forEach(function(pm) {
            if (pm.id === em.id) currentProjectId = p.id || "";
        });
    });
    em.__project_id = currentProjectId;  // stash to diff later
    // ct_measure_modal injects an empty "—" option for selects, which
    // serves as "Sans projet" here. Just feed it the existing projects.
    var projectOpts = (_projects || []).slice().sort(function(a, b) {
        return (a.name || "").localeCompare(b.name || "");
    }).map(function(p) {
        return { value: p.id, label: p.name || "(sans nom)" };
    });

    ct_measure_modal.open(em, {
        title: isNative ? t("pilot.measures.edit_title") : em.source_id,
        hideFields: ["type"],
        onAddNote: function(_entry, fullLog) {
            (em as Record<string, any>).progress_log = fullLog;
            var orig = _measures.find(function(x) { return x.id === em.id; });
            if (orig) (orig as Record<string, any>).progress_log = fullLog;
            return _fetch("/measures/" + em.id, { method: "PATCH", body: { progress_log: fullLog } });
        },
        fieldMap: { statut: "status", responsable: "assignee", echeance: "due_date" },
        statusOptions: [
            { value: "planned",     label: t("pilot.measure.status.planned") },
            { value: "in_progress", label: t("pilot.measure.status.in_progress") },
            { value: "completed",   label: t("pilot.measure.status.completed") },
            { value: "backlog",     label: t("pilot.measure.status.backlog") }
        ],
        defaultStatus: "planned",
        titleReadOnly: !isNative,
        headerHtml: headerHtml,
        ownerPicker: { pickerId: "pilot-measure-owner", directoryUrl: "api/directory", sourceUrl: null },
        extraFields: [
            { key: "project_id", label: t("pilot.col.project"), type: "select",
              value: currentProjectId, options: projectOpts }
        ],
        extraButtons: extraButtons,
        onDelete: function() { _deleteMeasureEdit(em); }
    }).then(function(result) {
        _editingMeasure = null;
        if (!result) return;
        if (result.__deleted) return; // onDelete already invoked
        if (result.__open_module) { window.open(_moduleMeasureUrl(em), "_blank"); return; }
        _saveMeasureEditFromValues(em, result);
    });
}

function _saveMeasureEditFromValues(m: PilotMeasure, values: any) {
    if (!m || _savingMeasure) return;
    var patch: Record<string, any> = {};
    if (values.title != null && values.title !== (m.title || "")) patch.title = values.title;
    if (values.description != null && values.description !== (m.description || "")) patch.description = values.description;
    if (values.status != null && values.status !== m.status) patch.status = values.status;
    if (values.assignee != null && values.assignee !== (m.assignee || "")) patch.assignee = values.assignee;
    if (values.due_date != null && values.due_date !== (m.due_date || "")) patch.due_date = values.due_date;

    // Project association diff: handled out-of-band via project endpoints.
    var oldPid = m.__project_id || "";
    var newPid = (values.project_id != null ? String(values.project_id) : oldPid);
    var projectChanged = newPid !== oldPid;

    if (!Object.keys(patch).length && !projectChanged) { showStatus(t("pilot.common.no_changes")); return; }
    _savingMeasure = true;

    function _applyProjectDiff() {
        if (!projectChanged) return Promise.resolve();
        // 1) unlink from old project if any (best-effort: 404 = already gone)
        var p1 = oldPid
            ? _fetch("/projects/" + encodeURIComponent(oldPid) + "/measures/" + encodeURIComponent(m.id),
                     { method: "DELETE" }).catch(function() {})
            : Promise.resolve();
        // 2) link to new project if any
        return p1.then(function() {
            if (!newPid) return;
            return _fetch("/projects/" + encodeURIComponent(newPid) + "/measures",
                          { method: "POST", body: { measure_ids: [m.id] } });
        });
    }

    var patchPromise = Object.keys(patch).length
        ? _fetch("/measures/" + m.id, { method: "PATCH", body: patch })
        : Promise.resolve();

    patchPromise.then(_applyProjectDiff).then(function() {
        _savingMeasure = false;
        showStatus(t("pilot.measures.updated") + (projectChanged ? t("pilot.measures.project_included") : ""));
        Object.assign(m, patch);
        var orig = _measures.find(function(x) { return x.id === m.id; });
        if (orig) Object.assign(orig, patch);
        // Refresh _projects so the kanban project badge + project filter
        // dropdown reflect the new association immediately.
        var refresh = projectChanged ? _loadProjects() : Promise.resolve();
        refresh.then(function() { _renderPanel(); });
    }).catch(function(e) {
        _savingMeasure = false;
        showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true);
    });
}

function _deleteMeasureEdit(em: PilotMeasure) {
    if (!em) return;
    var msg = em.module === "pilot"
        ? t("pilot.measures.delete_confirm")
        : t("pilot.measures.delete_confirm_module", { module: em.module });
    ct_modal.confirm({ title: t("pilot.action.delete"), message: msg, danger: true }).then(function(ok) {
        if (!ok) return;
        _fetch("/measures/" + em.id, { method: "DELETE" }).then(function() {
            showStatus(t("pilot.measures.deleted"));
            _measures = _measures.filter(function(x) { return x.id !== em.id; });
            _editingMeasure = null;
            _renderPanel();
        }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
    });
}

var _measureFilter = { module: "", status: "", overdue: false, orphan: false, search: "", project: "" };
var _syncStatus = "";

window._filterMeasures = function() {
    var searchEl = document.getElementById("filter-search") as HTMLInputElement | null;
    var modSel = document.getElementById("filter-module") as HTMLSelectElement | null;
    var projSel = document.getElementById("filter-project") as HTMLSelectElement | null;
    var stSel = document.getElementById("filter-status") as HTMLSelectElement | null;
    var odCb = document.getElementById("filter-overdue") as HTMLInputElement | null;
    var orphanCb = document.getElementById("filter-orphan") as HTMLInputElement | null;
    _measureFilter.search = searchEl ? searchEl.value.toLowerCase() : "";
    _measureFilter.module = modSel ? modSel.value : "";
    _measureFilter.project = projSel ? projSel.value : "";
    _measureFilter.status = stSel ? stSel.value : "";
    _measureFilter.overdue = odCb ? odCb.checked : false;
    _measureFilter.orphan = orphanCb ? orphanCb.checked : false;
    var hadFocus = searchEl && document.activeElement === searchEl;
    var caretPos = searchEl ? searchEl.selectionStart : null;
    _renderPanel();
    if (hadFocus) {
        var newSearchEl = document.getElementById("filter-search") as HTMLInputElement | null;
        if (newSearchEl) {
            newSearchEl.focus();
            try { newSearchEl.setSelectionRange(caretPos, caretPos); } catch (e) {}
        }
    }
};

window._syncMeasuresNow = function() {
    _syncMeasuresBackground().then(function() { _renderPanel(); });
};

var _editingMeasure: PilotMeasure | null = null;
var _savingMeasure = false;

window._openMeasure = function(modId: string, sourceId: string) {
    var m = _measures.find(function(x) { return x.module === modId && x.source_id === sourceId; });
    if (!m) return;
    _editingMeasure = Object.assign({}, m);
    _showMeasureModal(_editingMeasure);
};

window._showNewMeasureForm = function() {
    // A native Pilot measure must belong to a remediation project — it stays a
    // TRANSVERSE measure, not a domain measure (spec reconciliation, decision B).
    var projectOpts = (_projects || []).slice().sort(function(a, b) {
        return (a.name || "").localeCompare(b.name || "");
    }).map(function(p) { return { value: p.id, label: p.name || "(sans nom)" }; });
    if (!projectOpts.length) {
        showStatus(t("pilot.measures.need_project"), true);
        return;
    }
    ct_measure_modal.open(null, {
        title: t("pilot.measures.new_title"),
        saveLabel: t("pilot.action.create"),
        hideFields: ["type"],
        journalReadOnly: true,
        fieldMap: { statut: "status", responsable: "assignee", echeance: "due_date" },
        statusOptions: [
            { value: "planned",     label: t("pilot.measure.status.planned") },
            { value: "in_progress", label: t("pilot.measure.status.in_progress") },
            { value: "completed",   label: t("pilot.measure.status.completed") },
            { value: "backlog",     label: t("pilot.measure.status.backlog") }
        ],
        defaultStatus: "planned",
        // Default to the first project: an empty selection used to close the
        // modal, drop the user's input and only flash a 3-second toast.
        extraFields: [{ key: "project_id", label: t("pilot.measures.remediation_project_required"), type: "select", value: projectOpts[0].value, options: projectOpts }],
        ownerPicker: { pickerId: "pilot-new-measure-owner", directoryUrl: "api/directory", sourceUrl: null }
    }).then(function(result) {
        if (!result || result.__deleted) return;
        if (!result.project_id) {
            showStatus(t("pilot.measures.must_attach_project"), true);
            return;
        }
        _fetch("/measures", { method: "POST", body: result }).then(function(created) {
            showStatus(t("pilot.measures.created", { ref: created.source_id }));
            _loadMeasures().then(function() { _renderPanel(); });
        }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message || e }), true); });
    });
};

function _syncMeasuresBackground() {
    _syncStatus = t("pilot.sync.in_progress");
    return _fetch("/measures/sync", { method: "POST" }).then(function(report) {
        var parts = [];
        for (var mod in report) {
            var r = report[mod];
            if (r.error) parts.push(t("pilot.sync.module_error", { mod: mod }));
            else parts.push(t("pilot.sync.module_measures", { mod: mod, n: r.added + r.updated }));
        }
        _syncStatus = t("pilot.sync.last_prefix") + new Date().toLocaleTimeString() + " (" + parts.join(", ") + ")";
    }).catch(function() {
        // Syncing is admin-only; a non-admin gets 403 here. That's expected —
        // don't surface it as an error, the cached measures still load below.
        _syncStatus = "";
    }).then(function() {
        // ALWAYS load the cached measures afterwards, whether or not the sync
        // ran. Otherwise a non-admin (403 on /sync) never reached _loadMeasures
        // and saw an empty list even when the cache was populated.
        return _loadMeasures();
    });
}

// ═══════════════════════════════════════════════════════════════
// PROJETS
// ═══════════════════════════════════════════════════════════════

function _renderProjects(c: HTMLElement) {
    if (_editingProject) { _renderProjectEdit(c); return; }

    var h = '<h2>' + t("pilot.projects.title") + '</h2>';
    h += '<div class="pilot-actions">';
    h += '<button class="ct-btn" data-variant="primary" data-click="_newProject">+ ' + t("pilot.projects.new") + '</button>';
    h += '<button class="ct-btn btn-ai" data-click="_aiSuggestProjects" title="' + t("pilot.projects.ai_plan_tooltip") + '">' + t("pilot.projects.ai_plan") + '</button>';
    h += '</div>';

    if (!_projects.length) {
        h += '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.projects.empty") + '</div>';
        c.innerHTML = h;
        return;
    }

    _projects.forEach(function(p) {
        var statusCls = p.status === "completed" ? "completed" : p.status === "in_progress" ? "in_progress" : "planned";
        var prioCls = p.priority === "critical" ? "critical" : p.priority === "high" ? "high" : "";
        h += '<div class="pilot-card ct-clickable" data-click="_editProject" data-args=\'' + _da(p.id) + '\'>';
        h += '<div class="pilot-card-header">';
        h += '<span class="pilot-card-title ct-flex-1">' + esc(p.name) + '</span>';
        if (prioCls) h += '<span class="ct-badge" data-tone="' + _pilotTone(prioCls) + '" style="margin-right:var(--ct-s1)">' + tEsc("pilot.project.priority." + p.priority) + '</span>';
        h += '<span class="ct-badge" data-tone="' + _pilotTone(statusCls) + '">' + tEsc("pilot.project.status." + p.status) + '</span>';
        // Suppression en ligne : bouton icône fantôme, qui vire au critique au survol.
            // C'était déjà le bon dessin, sous un nom local — la primitive le porte.
            h += '<button class="ct-btn" data-variant="danger" data-icon data-size="sm" title="' + t("pilot.action.delete") + '" data-click="_deleteProject" data-args=\'' + _da(p.id) + '\' data-stop>' + _icon("trash", 14) + '</button>';
        h += '</div>';
        if (p.responsible || p.due_date) {
            h += '<div class="ct-text-label ct-muted ct-mb-2">';
            if (p.responsible) h += esc(p.responsible);
            if (p.responsible && p.due_date) h += ' &mdash; ';
            if (p.due_date) h += t("pilot.projects.due_prefix") + esc(p.due_date);
            h += '</div>';
        }
        if ((p.measures_total || 0) > 0) {
            h += '<div class="ct-mb-1">';
            h += '<div class="ct-bg-line ct-r-sm ct-h-8 ct-overflow-hidden">';
            h += '<div style="background:var(--ct-low);height:100%;width:' + p.progress + '%;transition:width 0.3s"></div>';
            h += '</div>';
            h += '<div class="ct-text-label ct-muted ct-mt-1">' + t("pilot.projects.measures_progress", { completed: p.measures_completed || 0, total: p.measures_total || 0, pct: p.progress || 0 }) + '</div>';
            h += '</div>';
        }
        if (p.measures && p.measures.length) {
            h += '<div class="ct-text-label ct-muted">';
            p.measures.forEach(function(m) {
                h += '<span class="ct-ref" data-module="' + esc(m.module) + '" style="margin-right:var(--ct-s1);margin-bottom:var(--ct-s1)">' + esc(m.source_id) + '</span>';
            });
            h += '</div>';
        }
        h += '</div>';
    });
    c.innerHTML = h;
}

function _renderProjectEdit(c: HTMLElement) {
    var p = _editingProject!;
    var h = '<div class="ct-flex ct-items-center ct-gap-3 ct-mb-4">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="_backToProjects">&larr; ' + t("pilot.action.back") + '</button>';
    h += '<h2 class="ct-m-0">' + (p.id ? esc(p.name) : t("pilot.projects.new")) + '</h2>';
    // Action destructrice : la variante danger du socle — teintée au repos,
    // rouge plein au survol. En .btn + color inline elle n'annonçait rien et
    // ne suivait pas le thème.
    if (p.id) h += '<button class="ct-btn ct-ml-auto" data-variant="danger" data-click="_deleteProject" data-args=\'' + _da(p.id) + '\'>' + t("pilot.action.delete") + '</button>';
    h += '</div>';

    // Form
    h += '<div class="ct-grid ct-grid-2 ct-gap-3 ct-mb-5">';
    h += '<div><label class="pilot-label">' + t("pilot.projects.name_label") + '</label><input type="text" id="pj-name" class="ct-input" value="' + esc(p.name || '') + '"></div>';
    h += '<div><label class="pilot-label">' + t("pilot.col.owner") + '</label><div id="pj-responsible-slot"></div></div>';
    h += '<div><label class="pilot-label">' + t("pilot.col.status") + '</label><select id="pj-status" class="ct-select">';
    ["planned", "in_progress", "completed", "on_hold"].forEach(function(s) {
        h += '<option value="' + s + '"' + (p.status === s ? ' selected' : '') + '>' + t("pilot.project.status." + s) + '</option>';
    });
    h += '</select></div>';
    h += '<div><label class="pilot-label">' + t("pilot.projects.priority_label") + '</label><select id="pj-priority" class="ct-select">';
    ["low", "medium", "high", "critical"].forEach(function(s) {
        h += '<option value="' + s + '"' + (p.priority === s ? ' selected' : '') + '>' + t("pilot.project.priority." + s) + '</option>';
    });
    h += '</select></div>';
    h += '<div><label class="pilot-label">' + t("pilot.projects.start_date") + '</label><input type="date" id="pj-start" class="ct-input" value="' + esc(p.start_date || '') + '"></div>';
    h += '<div><label class="pilot-label">' + t("pilot.col.due_date") + '</label><input type="date" id="pj-due" class="ct-input" value="' + esc(p.due_date || '') + '"></div>';
    h += '</div>';
    h += '<div class="ct-mb-4"><label class="pilot-label">' + t("pilot.common.description") + '</label><textarea id="pj-desc" class="ct-textarea ct-w-full" rows="3">' + esc(p.description || '') + '</textarea></div>';

    h += '<div class="ct-flex ct-gap-2 ct-mb-6">';
    h += '<button class="ct-btn" data-variant="primary" data-click="_saveProject">' + t("pilot.action.save") + '</button>';
    var cascadeLabel = p.id ? '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1"><input type="checkbox" id="pj-cascade"> ' + t("pilot.projects.cascade_status") + '</label>' : '';
    h += cascadeLabel;
    h += '</div>';

    // Measures section
    if (p.id) {
        h += '<h3>' + t("pilot.projects.linked_measures", { n: (p.measures || []).length }) + '</h3>';
        if (p.measures && p.measures.length) {
            h += '<table class="ct-table"><thead><tr><th>' + t("pilot.col.module") + '</th><th>' + t("pilot.col.ref") + '</th><th>' + t("pilot.col.measure") + '</th><th>' + t("pilot.col.status") + '</th><th></th></tr></thead><tbody>';
            p.measures.forEach(function(m) {
                h += '<tr>';
                h += '<td><span class="ct-ref" data-module="' + esc(m.module) + '">' + esc(m.module) + '</span></td>';
                h += '<td class="ct-mono ct-text-meta">' + esc(m.source_id) + '</td>';
                h += '<td class="ct-clickable ct-text-accent" data-click="_openMeasure" data-args=\'' + _da(m.module, m.source_id) + '\'>' + esc(m.title) + '</td>';
                h += '<td><span class="ct-badge" data-tone="' + _pilotTone(m.status) + '">' + esc(t("pilot.measure.status." + m.status)) + '</span></td>';
                h += '<td><button class="ct-btn" data-variant="ghost" data-icon data-size="xs" data-click="_removeMeasure" data-args=\'' + _da(p.id, m.id) + '\'>' + _icon("trash", 14) + '</button></td>';
                h += '</tr>';
            });
            h += '</tbody></table>';
        }

        // Add measures picker
        h += '<div class="ct-mt-3">';
        h += '<h4 class="ct-text-meta ct-mb-2">' + t("pilot.projects.add_measures") + '</h4>';
        h += '<div class="ct-flex ct-gap-1 ct-mb-2 ct-items-center">';
        h += '<input type="text" id="pj-measure-search" placeholder="' + t("pilot.measures.search_measure") + '" class="ct-input ct-flex-1" data-input="_searchMeasuresToAdd" data-pass-value data-stop>';
        h += '<button class="ct-btn btn-ai" data-click="_aiSuggestMeasures" data-args=\'' + _da(p.id) + '\' title="' + t("pilot.projects.ai_suggest_tooltip") + '">' + t("pilot.projects.ai_suggest") + '</button>';
        h += '</div>';
        h += '<div id="pj-measure-results"></div>';
        h += '</div>';

    }

    c.innerHTML = h;
    // Responsable — shared ct_userpicker search field (mounted on the slot).
    setTimeout(function() {
        if (typeof ct_userpicker === "undefined" || !ct_userpicker.mount) return;
        ct_userpicker.mount({
            slotId: "pj-responsible-slot", pickerId: "pj-responsible",
            value: p.responsible || "", placeholder: t("pilot.common.search"),
            directoryUrl: "api/directory", sourceUrl: null,
        });
    }, 0);
}

window._newProject = function() {
    _editingProject = { name: "", status: "planned", priority: "medium", measures: [] };
    _renderPanel();
};

window._editProject = function(id: string) {
    _fetch("/projects/" + id).then(function(p) {
        _editingProject = p;
        _renderPanel();
    }).catch(function(e) { showStatus(t("pilot.projects.open_error", { msg: e.message || e }), true); });
};

window._backToProjects = function() {
    _editingProject = null;
    _loadProjects().then(function() { _renderPanel(); });
};

window._saveProject = function() {
    var nameVal = ((document.getElementById("pj-name") as HTMLInputElement).value || "").trim();
    if (!nameVal) {
        showStatus(t("pilot.projects.name_required"), true);
        var nm = document.getElementById("pj-name");
        if (nm) { nm.focus(); nm.style.borderColor = "var(--ct-critical)"; }
        return;
    }
    var data: Record<string, any> = {
        name: nameVal,
        description: (document.getElementById("pj-desc") as HTMLTextAreaElement).value,
        status: (document.getElementById("pj-status") as HTMLSelectElement).value,
        priority: (document.getElementById("pj-priority") as HTMLSelectElement).value,
        responsible: (typeof ct_userpicker !== "undefined" && ct_userpicker.getValue) ? ct_userpicker.getValue("pj-responsible") : "",
        start_date: (document.getElementById("pj-start") as HTMLInputElement).value || null,
        due_date: (document.getElementById("pj-due") as HTMLInputElement).value || null,
    };
    var cascadeEl = document.getElementById("pj-cascade") as HTMLInputElement | null;
    if (cascadeEl && cascadeEl.checked) data.cascade = true;

    var promise;
    if (_editingProject!.id) {
        promise = _fetch("/projects/" + _editingProject!.id, { method: "PUT", body: data });
    } else {
        promise = _fetch("/projects", { method: "POST", body: data });
    }
    promise.then(function(p) {
        _editingProject = p;
        showStatus(t("pilot.projects.saved"));
        _loadProjects().then(function() { _renderPanel(); });
    }).catch(function(e) { showStatus(t("pilot.common.save_error", { msg: e.message || e }), true); });
};

window._deleteProject = function(id: string) {
    if (!confirm(t("pilot.projects.delete_confirm"))) return;
    _fetch("/projects/" + id, { method: "DELETE" }).then(function() {
        _editingProject = null;
        showStatus(t("pilot.projects.deleted"));
        _loadProjects().then(function() { _renderPanel(); });
    });
};

window._removeMeasure = function(projectId: string, measureId: string) {
    _fetch("/projects/" + projectId + "/measures/" + measureId, { method: "DELETE" }).then(function() {
        _fetch("/projects/" + projectId).then(function(p) {
            _editingProject = p;
            _renderPanel();
        });
    });
};

function memberOfGroup(measureId: string): boolean {
    return _groups.some(function(g) {
        return (g.members || []).some(function(mm) { return mm.id === measureId; });
    });
}

window._searchMeasuresToAdd = function(val: string) {
    var q = (val || "").toLowerCase();
    var el = document.getElementById("pj-measure-results");
    if (!el) return;
    var existingIds = (_editingProject!.measures || []).map(function(m) { return m.id; });

    // Les groupes d'abord. Sur le plan d'action ils apparaissent comme UNE
    // ligne consolidee, donc on les cherchait ici sous leur titre de groupe —
    // en vain, la liste ne proposait que des mesures individuelles. Ajouter un
    // groupe rattache ses membres : le modele lie un projet a des mesures
    // (ProjectMeasure), un groupe n'est pas une entite rattachable.
    var groupResults = _groups.filter(function(g) {
        var membres = (g.members || []).filter(function(mm) { return existingIds.indexOf(mm.id) < 0; });
        if (!membres.length) return false;
        if (!q) return true;
        var foin = (g.title || "") + " " + (g.ref || "") + " "
            + membres.map(function(mm) { return (mm.title || "") + " " + (mm.source_id || ""); }).join(" ");
        return foin.toLowerCase().indexOf(q) >= 0;
    });

    var results = _measures.filter(function(m) {
        if (existingIds.indexOf(m.id) >= 0) return false;
        // Un membre de groupe s'ajoute avec son groupe, pas isolement : le
        // proposer deux fois laisserait rattacher la moitie d'un groupe.
        if (memberOfGroup(m.id)) return false;
        if (!q) return true;
        return ((m.title || "") + " " + (m.source_id || "") + " " + (m.module || "") + " " + (m.entity_name || "")).toLowerCase().indexOf(q) >= 0;
    });
    if (!results.length && !groupResults.length) {
        el.innerHTML = '<div class="ct-muted ct-text-meta">' + t("pilot.common.no_results") + '</div>'; return;
    }
    var h = '<div class="ct-mb-2"><button class="ct-btn ct-text-label" data-variant="primary" data-size="xs" data-click="_addSelectedMeasures">' + t("pilot.action.add_selection") + '</button></div>';
    h += '<table class="ct-table ct-text-label"><tbody>';
    groupResults.slice(0, 15).forEach(function(g) {
        var membres = (g.members || []).filter(function(mm) { return existingIds.indexOf(mm.id) < 0; });
        h += '<tr>';
        h += '<td class="ct-w-30"><input type="checkbox" class="pj-measure-cb" value="' + esc(membres.map(function(mm) { return mm.id; }).join(",")) + '" data-module="' + esc(t("pilot.groups.linked_badge")) + '" data-ref="' + esc(g.ref || "") + '" data-title="' + esc(g.title || "") + '"></td>';
        h += '<td><span class="ct-badge" data-tone="neutral">' + esc(t("pilot.groups.linked_badge")) + '</span></td>';
        h += '<td class="ct-mono ct-text-data">' + esc(g.ref || "") + '</td>';
        h += '<td>' + esc(g.title || "") + ' <span class="ct-muted ct-text-meta">(' + membres.length + ')</span></td>';
        h += '</tr>';
    });
    results.slice(0, 30).forEach(function(m) {
        h += '<tr>';
        h += '<td class="ct-w-30"><input type="checkbox" class="pj-measure-cb" value="' + esc(m.id) + '" data-title="' + esc(m.title) + '" data-ref="' + esc(m.source_id) + '" data-module="' + esc(m.module) + '"></td>';
        h += '<td><span class="ct-ref" data-module="' + esc(m.module) + '">' + esc(m.module) + '</span></td>';
        h += '<td class="ct-mono ct-text-data">' + esc(m.source_id) + '</td>';
        h += '<td>' + esc(m.title) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    el.innerHTML = h;
};

window._addSelectedMeasures = function() {
    if (!_editingProject || !_editingProject.id) return;
    var cbs = document.querySelectorAll<HTMLInputElement>(".pj-measure-cb:checked");
    if (!cbs.length) { showStatus(t("pilot.measures.none_selected")); return; }

    var ids: string[] = [];
    var lines: string[] = [];
    cbs.forEach(function(cb) {
        // Une case de groupe porte les identifiants de tous ses membres.
        cb.value.split(",").forEach(function(id) { if (id) ids.push(id); });
        lines.push("[" + cb.getAttribute("data-module") + "] " + cb.getAttribute("data-ref") + " — " + cb.getAttribute("data-title"));
    });

    _fetch("/projects/" + _editingProject.id + "/measures", { method: "POST", body: { measure_ids: ids } }).then(function(p) {
        _editingProject = p;
        // Append measure titles to description
        var descEl = document.getElementById("pj-desc") as HTMLTextAreaElement | null;
        var currentDesc = descEl ? descEl.value : (p.description || "");
        var addition = lines.join("\n");
        var newDesc = currentDesc ? currentDesc + "\n\n" + addition : addition;
        // Save description
        return _fetch("/projects/" + p.id, { method: "PUT", body: { description: newDesc } });
    }).then(function(p) {
        _editingProject = p;
        showStatus(t("pilot.measures.added_n", { n: ids.length }));
        _loadProjects().then(function() { _renderPanel(); });
    });
};

// ═══════════════════════════════════════════════════════════════
// AI ASSISTANT
// ═══════════════════════════════════════════════════════════════

function _aiCall(systemPrompt: string, userPrompt: string): Promise<any> {
    return _fetch("/ai/complete", {
        method: "POST",
        body: { system: systemPrompt, user: userPrompt,
                provider: (window._aiRuntime && window._aiRuntime.provider) || "anthropic",
                model: (window._aiRuntime && window._aiRuntime.model) || "claude-sonnet-4-6" }
    }).then(function(r) {
        var text = (r && r.text) || "";
        var match = text.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (match) text = match[1];
        try { return JSON.parse(text); } catch (e) {
            var first = text.indexOf("{");
            var last = text.lastIndexOf("}");
            if (first >= 0 && last > first) {
                try { return JSON.parse(text.substring(first, last + 1)); } catch (e2) {}
            }
            throw new Error(t("pilot.ai.invalid_response"));
        }
    });
}

var _aiSuggestedMeasures: { measure: PilotMeasure; reason: string }[] = [];
var _aiSuggestedProjects: { name?: string; description?: string; priority?: string; measure_ids: string[] }[] = [];
var _aiSuggestProjectId: string | null = null;

window._aiSuggestMeasures = function(projectId: string) {
    if (!_editingProject) return;
    var nameEl = document.getElementById("pj-name") as HTMLInputElement | null;
    var descEl = document.getElementById("pj-desc") as HTMLTextAreaElement | null;
    var name = nameEl ? nameEl.value.trim() : _editingProject.name;
    var desc = descEl ? descEl.value.trim() : (_editingProject.description || "");
    if (!name && !desc) {
        alert(t("pilot.projects.ai_need_name"));
        return;
    }
    var existingIds = (_editingProject.measures || []).map(function(m) { return m.id; });
    var available = _measures.filter(function(m) { return existingIds.indexOf(m.id) < 0; });
    if (!available.length) {
        _aiShowError(t("pilot.ai.suggested_measures"), t("pilot.ai.no_measures_available"));
        return;
    }

    _aiSuggestProjectId = projectId;
    _aiShowLoading(t("pilot.ai.suggested_for", { name: name }), t("pilot.ai.analyzing_project"));

    var system = "Tu es un assistant CISO qui aide a organiser un plan d'action de securite en projets thematiques. " +
                 "On te donne un projet (nom + description) et une liste d'actions candidates issues de differents modules (Risk, Compliance, Vendor, Asset, Access, Audit). " +
                 "Selectionne les actions qui correspondent le mieux au projet en te basant sur leur contenu et leur contexte. " +
                 "Reponds STRICTEMENT en JSON valide, sans texte autour, sans bloc markdown, au format : " +
                 "{\"measures\": [{\"id\": \"<id action>\", \"reason\": \"<phrase courte expliquant le rattachement>\"}]}. " +
                 "Choisis entre 3 et 15 actions pertinentes maximum. Si aucune action ne convient, renvoie {\"measures\": []}.";

    var user = "PROJET\nNom: " + name + "\nDescription: " + (desc || "(non renseignee)") + "\n\n" +
               "ACTIONS DISPONIBLES (id | module | reference | titre)\n" +
               available.map(function(m) {
                   return m.id + " | " + m.module + " | " + m.source_id + " | " + (m.title || "");
               }).join("\n");

    _aiCall(system, user).then(function(parsed) {
        var picks = (parsed && parsed.measures) || [];
        var byId: Record<string, PilotMeasure> = {};
        available.forEach(function(m) { byId[m.id] = m; });
        var rows = picks.map(function(p: any) {
            var m = byId[p.id];
            if (!m) return null;
            return { measure: m, reason: p.reason || "" };
        }).filter(Boolean) as { measure: PilotMeasure; reason: string }[];
        _aiSuggestedMeasures = rows;
        _aiRenderSuggestedMeasures(name);
    }).catch(function(e) {
        _aiShowError(t("pilot.ai.suggested_measures"), t("pilot.ai.error", { msg: esc(e.message || String(e)) }));
    });
};

function _aiRenderSuggestedMeasures(projectName: string) {
    var p = _aiEnsurePanel();
    p.title.textContent = t("pilot.ai.suggested_for", { name: projectName });
    if (!_aiSuggestedMeasures.length) {
        p.body.innerHTML = '<div class="ai-empty">' + t("pilot.ai.no_measures_proposed") + '</div>';
        p.footer.innerHTML = '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.close") + '</button>';
        return;
    }
    var h = '<div class="ct-text-meta ct-muted ct-mb-3">';
    h += t("pilot.ai.suggested_count", { n: _aiSuggestedMeasures.length });
    h += ' <button class="ct-btn" data-variant="ghost" data-size="sm" data-click="_aiToggleAllMeasures">' + t("pilot.ai.toggle_all") + '</button>';
    h += '</div>';
    _aiSuggestedMeasures.forEach(function(r, i) {
        var m = r.measure;
        h += '<div class="ai-card">';
        h += '<div class="ai-card-row">';
        h += '<input type="checkbox" class="ai-card-cb ai-meas-cb" checked value="' + esc(m.id) + '" data-idx="' + i + '">';
        h += '<div class="ai-card-content">';
        h += '<div class="ai-card-title">' + esc(m.title) + '</div>';
        h += '<div class="ai-card-meta"><span class="ct-ref" data-module="' + esc(m.module) + '">' + esc(m.module) + '</span> ' +
             '<span class="ct-mono">' + esc(m.source_id) + '</span>';
        if (m.entity_name && m.entity_name !== m.title) h += ' &middot; ' + esc(m.entity_name);
        h += '</div>';
        if (r.reason) h += '<div class="ai-card-reason">' + esc(r.reason) + '</div>';
        h += '</div></div></div>';
    });
    p.body.innerHTML = h;
    p.footer.innerHTML =
        '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.cancel") + '</button>' +
        '<button class="ct-btn" data-variant="primary" data-size="xs" data-click="_aiAddSuggestedMeasures">' + t("pilot.action.add_selection") + '</button>';
}

window._aiToggleAllMeasures = function() {
    var cbs = document.querySelectorAll<HTMLInputElement>(".ai-meas-cb");
    var anyUnchecked = false;
    cbs.forEach(function(cb) { if (!cb.checked) anyUnchecked = true; });
    cbs.forEach(function(cb) { cb.checked = anyUnchecked; });
};

window._aiAddSuggestedMeasures = function() {
    if (!_aiSuggestProjectId) return;
    var cbs = document.querySelectorAll<HTMLInputElement>(".ai-meas-cb:checked");
    if (!cbs.length) { showStatus(t("pilot.measures.none_selected")); return; }
    var ids: string[] = [];
    cbs.forEach(function(cb) { ids.push(cb.value); });
    _fetch("/projects/" + _aiSuggestProjectId + "/measures", { method: "POST", body: { measure_ids: ids } }).then(function(p) {
        _editingProject = p;
        _aiClosePanel();
        showStatus(t("pilot.measures.added_n", { n: ids.length }));
        _loadProjects().then(function() { _renderPanel(); });
    }).catch(function(e) {
        _aiShowError(t("pilot.ai.suggested_measures"), t("pilot.ai.add_error", { msg: esc(e.message || String(e)) }));
    });
};

var _aiSuggestedAdditions: { project_id?: string; measure_ids: string[]; reason?: string; project?: PilotProject }[] = [];

window._aiSuggestProjects = function() {
    if (!_measures.length) {
        _aiShowError(t("pilot.ai.action_plan"), t("pilot.ai.no_measures_sync"));
        return;
    }
    // Compute orphan measures (not yet linked to any project)
    var assigned: Record<string, boolean> = {};
    _projects.forEach(function(p) {
        (p.measures || []).forEach(function(m) { assigned[m.id] = true; });
    });
    var orphans = _measures.filter(function(m) { return !assigned[m.id]; });
    if (!orphans.length) {
        _aiShowError(t("pilot.ai.action_plan"), t("pilot.ai.all_attached"));
        return;
    }

    // Prompt for custom instructions before calling the AI
    var customInstruction = prompt(t("pilot.ai.custom_instructions_prompt"));
    if (customInstruction === null) return; // cancelled

    _aiShowLoading(t("pilot.ai.action_plan"), t("pilot.ai.analyzing_orphans", { n: orphans.length }));

    var system = "Tu es un assistant CISO qui aide a structurer un plan d'action en projets thematiques. " +
                 "On te donne : (1) la liste des PROJETS DEJA EXISTANTS avec leur description ET les actions qu'ils contiennent deja (cela revele le theme reel du projet), (2) la liste des ACTIONS ORPHELINES (actions qui ne sont rattachees a AUCUN projet pour l'instant). " +
                 "Pour decider du rattachement d'une action orpheline a un projet existant, base-toi PRINCIPALEMENT sur la similarite thematique entre l'action orpheline et les actions deja presentes dans le projet (meme module ? meme entite ? meme type d'action ? meme objectif de securite ?). La description du projet est secondaire — les actions qu'il contient deja sont la verite. " +
                 "Pour CHAQUE action orpheline, decide :\n" +
                 "  - SOIT la rattacher a un projet existant qui contient deja des actions du meme theme (privilegie tres fortement cette option) ;\n" +
                 "  - SOIT proposer un NOUVEAU projet thematique uniquement si AUCUN projet existant n'a d'action du meme theme.\n" +
                 "REGLES STRICTES :\n" +
                 "  - Ne propose JAMAIS un nouveau projet dont le theme est deja represente dans un projet existant (meme partiellement). Utilise l'ajout.\n" +
                 "  - Chaque action orpheline apparait dans au plus une recommandation.\n" +
                 "  - Justifie chaque rattachement par UNE phrase qui cite explicitement l'action existante du projet qui partage le theme (ex: 'Comme l'action RSK-012 deja presente, cette action traite de la gestion des acces privilegies').\n" +
                 "  - Si une action orpheline ne s'integre vraiment nulle part, ignore-la (ne la mets dans aucune sortie).\n" +
                 "  - Maximum 5 nouveaux projets, au moins 2 actions chacun.\n" +
                 "Reponds STRICTEMENT en JSON valide, sans texte autour, sans bloc markdown, au format :\n" +
                 "{\n" +
                 "  \"additions\": [{\"project_id\": \"<id>\", \"measure_ids\": [\"<id1>\"], \"reason\": \"<phrase qui cite une action existante du projet>\"}],\n" +
                 "  \"new_projects\": [{\"name\": \"<nom court>\", \"description\": \"<2-3 phrases>\", \"priority\": \"low|medium|high|critical\", \"measure_ids\": [\"<id1>\", \"<id2>\"]}]\n" +
                 "}";

    var user = "PROJETS EXISTANTS\n";
    if (_projects.length) {
        _projects.forEach(function(p) {
            user += "\n--- Projet " + p.id + " ---\n";
            user += "Nom: " + (p.name || "") + "\n";
            user += "Description: " + ((p.description || "(pas de description)").replace(/\n/g, " ")) + "\n";
            user += "Statut: " + (p.status || "?") + " | Priorite: " + (p.priority || "?") + "\n";
            var pms = p.measures || [];
            user += "Actions deja rattachees (" + pms.length + ") :\n";
            if (!pms.length) {
                user += "  (aucune action pour l'instant — base-toi uniquement sur le nom et la description)\n";
            } else {
                pms.slice(0, 25).forEach(function(m) {
                    user += "  - [" + m.module + "] " + m.source_id + " | " + (m.title || "") +
                            (m.entity_name && m.entity_name !== m.title ? " (" + m.entity_name + ")" : "") + "\n";
                });
                if (pms.length > 25) user += "  ... et " + (pms.length - 25) + " autre(s)\n";
            }
        });
    } else {
        user += "(aucun projet existant)\n";
    }

    user += "\n\nACTIONS ORPHELINES (id | module | reference | titre | entite | statut)\n" +
            orphans.map(function(m) {
                return m.id + " | " + m.module + " | " + m.source_id + " | " + (m.title || "") +
                       " | " + (m.entity_name || "") + " | " + (m.status || "");
            }).join("\n");

    if (customInstruction && customInstruction.trim()) {
        user += "\n\nINSTRUCTION SUPPLEMENTAIRE DE L'UTILISATEUR :\n" + customInstruction.trim();
    }

    _aiCall(system, user).then(function(parsed) {
        _aiSuggestedAdditions = (parsed && parsed.additions) || [];
        _aiSuggestedProjects = (parsed && parsed.new_projects) || [];
        _aiRenderSuggestedPlan();
    }).catch(function(e) {
        _aiShowError(t("pilot.ai.action_plan"), t("pilot.ai.error", { msg: esc(e.message || String(e)) }));
    });
};

function _aiRenderSuggestedPlan() {
    var p = _aiEnsurePanel();
    p.title.textContent = t("pilot.ai.action_plan_proposed");

    var measureById: Record<string, PilotMeasure> = {};
    _measures.forEach(function(m) { measureById[m.id] = m; });
    var projectById: Record<string, PilotProject> = {};
    _projects.forEach(function(pr) { projectById[pr.id!] = pr; });

    // Filter additions and new_projects to only valid measures
    var validAdditions = (_aiSuggestedAdditions || []).map(function(a) {
        var ids = (a.measure_ids || []).filter(function(id) { return measureById[id]; });
        return { project_id: a.project_id, measure_ids: ids, reason: a.reason || "", project: projectById[a.project_id!] };
    }).filter(function(a) { return a.project && a.measure_ids.length > 0; });

    var validNewProjects = (_aiSuggestedProjects || []).map(function(np) {
        var ids = (np.measure_ids || []).filter(function(id) { return measureById[id]; });
        return { name: np.name, description: np.description, priority: np.priority, measure_ids: ids };
    }).filter(function(np) { return np.measure_ids.length > 0; });

    if (!validAdditions.length && !validNewProjects.length) {
        p.body.innerHTML = '<div class="ai-empty">' + t("pilot.ai.no_action_proposed") + '</div>';
        p.footer.innerHTML = '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.close") + '</button>';
        return;
    }

    _aiSuggestedAdditions = validAdditions;
    _aiSuggestedProjects = validNewProjects;

    var totalMeasures = 0;
    validAdditions.forEach(function(a) { totalMeasures += a.measure_ids.length; });
    validNewProjects.forEach(function(np) { totalMeasures += np.measure_ids.length; });

    var h = '<div class="ct-text-meta ct-muted ct-mb-3">';
    h += t("pilot.ai.plan_summary", { total: totalMeasures, adds: validAdditions.length, news: validNewProjects.length });
    h += '</div>';

    if (validAdditions.length) {
        h += '<h4 style="font-size:var(--ct-text-meta);margin:var(--ct-s3) 0 var(--ct-s2);color:var(--ct-info-ink)">' + t("pilot.ai.additions_heading") + '</h4>';
        validAdditions.forEach(function(a, i) {
            h += '<div class="ai-card">';
            h += '<div class="ai-card-row">';
            h += '<input type="checkbox" class="ai-card-cb ai-add-cb" checked value="' + i + '">';
            h += '<div class="ai-card-content">';
            h += '<div class="ai-card-title">&rarr; ' + esc(a.project!.name) + '</div>';
            h += '<div class="ai-card-meta">' + t("pilot.ai.measures_to_add", { n: a.measure_ids.length }) + '</div>';
            h += '<div class="ai-card-badges">';
            a.measure_ids.forEach(function(id) {
                var m = measureById[id];
                h += '<span class="ct-ref" data-module="' + esc(m.module) + '" title="' + esc(m.title) + '">' + esc(m.source_id) + '</span>';
            });
            h += '</div>';
            if (a.reason) h += '<div class="ai-card-reason ct-mt-1">' + esc(a.reason) + '</div>';
            h += '</div></div></div>';
        });
    }

    if (validNewProjects.length) {
        h += '<h4 style="font-size:var(--ct-text-meta);margin:var(--ct-s4) 0 var(--ct-s2);color:var(--ct-info-ink)">' + t("pilot.ai.new_projects_heading") + '</h4>';
        validNewProjects.forEach(function(np, i) {
            h += '<div class="ai-card">';
            h += '<div class="ai-card-row">';
            h += '<input type="checkbox" class="ai-card-cb ai-newproj-cb" checked value="' + i + '">';
            h += '<div class="ai-card-content">';
            h += '<div class="ai-card-title">' + (np.name ? esc(np.name) : t("pilot.common.unnamed"));
            if (np.priority) h += ' <span class="ct-badge ct-ml-1" data-tone="' + _pilotTone(np.priority) + '">' + tEsc("pilot.project.priority." + np.priority) + '</span>';
            h += '</div>';
            if (np.description) h += '<div class="ai-card-reason" style="font-style:normal;margin-bottom:var(--ct-s1)">' + esc(np.description) + '</div>';
            h += '<div class="ai-card-meta">' + t("pilot.ai.measures_count_colon", { n: np.measure_ids.length }) + '</div>';
            h += '<div class="ai-card-badges">';
            np.measure_ids.forEach(function(id) {
                var m = measureById[id];
                h += '<span class="ct-ref" data-module="' + esc(m.module) + '" title="' + esc(m.title) + '">' + esc(m.source_id) + '</span>';
            });
            h += '</div></div></div></div>';
        });
    }

    p.body.innerHTML = h;
    p.footer.innerHTML =
        '<button class="ct-btn" data-click="_aiClosePanel">' + t("pilot.action.cancel") + '</button>' +
        '<button class="ct-btn" data-variant="primary" data-click="_aiApplySuggestedPlan">' + t("pilot.ai.apply_selection") + '</button>';
}

window._aiApplySuggestedPlan = function() {
    var addCbs = document.querySelectorAll<HTMLInputElement>(".ai-add-cb:checked");
    var newCbs = document.querySelectorAll<HTMLInputElement>(".ai-newproj-cb:checked");
    if (!addCbs.length && !newCbs.length) { showStatus(t("pilot.ai.no_action_selected")); return; }

    var pickedAdditions: typeof _aiSuggestedAdditions = [];
    addCbs.forEach(function(cb) {
        var idx = parseInt(cb.value);
        if (_aiSuggestedAdditions[idx]) pickedAdditions.push(_aiSuggestedAdditions[idx]);
    });
    var pickedNew: typeof _aiSuggestedProjects = [];
    newCbs.forEach(function(cb) {
        var idx = parseInt(cb.value);
        if (_aiSuggestedProjects[idx]) pickedNew.push(_aiSuggestedProjects[idx]);
    });

    _aiShowLoading(t("pilot.ai.action_plan"), t("pilot.ai.applying", { n: pickedAdditions.length + pickedNew.length }));

    var chain = Promise.resolve();
    var addedCount = 0;
    var createdCount = 0;

    pickedAdditions.forEach(function(a) {
        chain = chain.then(function() {
            return _fetch("/projects/" + a.project_id + "/measures", { method: "POST", body: { measure_ids: a.measure_ids } })
                .then(function() { addedCount += a.measure_ids.length; });
        });
    });

    pickedNew.forEach(function(np) {
        chain = chain.then(function() {
            return _fetch("/projects", { method: "POST", body: {
                name: (np.name || "Projet IA").trim(),
                description: np.description || "",
                status: "planned",
                priority: np.priority || "medium",
            }}).then(function(proj) {
                if (!np.measure_ids.length) return;
                return _fetch("/projects/" + proj.id + "/measures", { method: "POST", body: { measure_ids: np.measure_ids } });
            }).then(function() { createdCount++; });
        });
    });

    chain.then(function() {
        _aiClosePanel();
        var msg = [];
        if (addedCount) msg.push(t("pilot.measures.added_n", { n: addedCount }));
        if (createdCount) msg.push(t("pilot.projects.created_n", { n: createdCount }));
        showStatus(msg.join(", ") || t("pilot.ai.plan_applied"));
        _loadProjects().then(function() { _renderPanel(); });
    }).catch(function(e) {
        _aiShowError(t("pilot.ai.action_plan"), t("pilot.common.error_msg", { msg: esc(e.message || String(e)) }));
    });
};



// ═══════════════════════════════════════════════════════════════
// DIRECTORY (Personnel)
// ═══════════════════════════════════════════════════════════════

var _directory: PilotPerson[] = [];
// _editPerson state removed — person editing is driven by ct_modal now.

function _loadDirectory() {
    return _fetch("/directory").then(function(data) { _directory = data || []; });
}

function _renderDirectory(c: HTMLElement) {
    _loadDirectory().then(function() { _doRenderDirectory(c); }).catch(function() { _doRenderDirectory(c); });
}

function _doRenderDirectory(c: HTMLElement) {
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("pilot.directory.title", { n: _directory.length }) + '</h2>';
    h += '<div class="ct-flex ct-gap-1">';
    h += '<button class="ct-btn" data-variant="primary" data-click="_dirAddPerson">' + t("pilot.action.add") + '</button>';
    h += '<button class="ct-btn" data-click="_dirImportCsv">' + t("pilot.directory.import_csv") + '</button>';
    h += '<button class="ct-btn" data-click="_dirExportForAccess" title="' + t("pilot.directory.export_access_tooltip") + '">' + t("pilot.directory.export_access") + '</button>';
    h += '</div></div>';

    if (!_directory.length) { h += '<div class="ct-muted ct-p-5 ct-ta-c">' + t("pilot.directory.empty") + '</div>'; c.innerHTML = h; return; }

    h += '<table class="ct-table"><thead><tr>';
    h += '<th>' + t("pilot.directory.col_lastname") + '</th><th>' + t("pilot.directory.col_firstname") + '</th><th>' + t("pilot.directory.col_email") + '</th><th>' + t("pilot.directory.col_function") + '</th><th>' + t("pilot.directory.col_department") + '</th><th>' + t("pilot.col.status") + '</th><th>' + t("pilot.directory.col_site") + '</th>';
    h += '</tr></thead><tbody>';
    _directory.forEach(function(p, i) {
        var cls = p.statut === "inactif" ? ' style="opacity:0.5"' : '';
        var locked = p.sync_source === "access";
        h += '<tr' + cls + ' class="ct-clickable" data-click="_dirEditPerson" data-args=\'' + _da(i) + '\'>';
        h += '<td class="ct-strong">' + esc(p.nom)
           + (locked ? ' <span class="ct-badge" data-tone="medium" title="' + t("pilot.directory.hr_managed_tooltip") + '">' + t("pilot.directory.hr_badge") + '</span>' : '')
           + '</td>';
        h += '<td>' + esc(p.prenom) + '</td>';
        h += '<td class="ct-text-meta">' + esc(p.email) + '</td>';
        h += '<td class="ct-text-meta">' + esc(p.fonction) + '</td>';
        h += '<td class="ct-text-meta">' + esc(p.departement) + '</td>';
        h += '<td><span class="ct-badge" data-tone="' + _pilotTone(p.statut) + '">' + esc(t("pilot.directory.status." + p.statut)) + '</span></td>';
        h += '<td class="ct-text-meta">' + esc(p.site) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    c.innerHTML = h;
}

// NB: the manual "Importer depuis Access" button was removed — when an HR
// connector feeds Access, Access self-syncs its identities to Pilot
// (one-directional), and those rows are read-only here (sync_source="access").

// Open the unified ct_modal for creating or editing a Pilot personnel.
// On Save : POST (new) or PATCH (existing) then refresh the directory.
// On Delete (edit only) : confirms then DELETE.
function _dirOpenPersonModal(idx: number | null) {
    var isNew = (idx === null || idx === undefined);
    var p = isNew ? { nom: "", prenom: "", email: "", fonction: "", departement: "", statut: "actif", telephone: "", site: "", manager_email: "" } : (_directory[idx!] || {});
    var title = isNew ? t("pilot.directory.new_person") : ((p.prenom + " " + p.nom).trim() || p.email || t("pilot.directory.person"));
    // Read-only when fed from Access (HR connector). Identities flow
    // Access → Pilot only; editing/deleting here is disabled.
    var locked = !isNew && p.sync_source === "access";

    var body = '<div class="ct-tprm-form" style="border:none;padding:0">';
    if (locked) {
        body += '<div style="background:var(--ct-medium-tint);color:var(--ct-medium-ink);border-radius:var(--ct-r-md);padding:var(--ct-s2) var(--ct-s3);margin-bottom:var(--ct-s3);font-size:var(--ct-text-meta)">'
              + t("pilot.directory.access_locked_banner") + '</div>';
    }
    body += '<div class="ct-form-grid">';
    body +=   _dirModalField("nom",       t("pilot.directory.field_lastname"),  p.nom, "text", locked);
    body +=   _dirModalField("prenom",    t("pilot.directory.field_firstname"), p.prenom, "text", locked);
    body += '</div><div class="ct-form-grid">';
    body +=   _dirModalField("email",     t("pilot.directory.field_email"),     p.email, "email", locked);
    body +=   _dirModalField("fonction",  t("pilot.directory.col_function"),    p.fonction, "text", locked);
    body += '</div><div class="ct-form-grid">';
    body +=   _dirModalField("departement", t("pilot.directory.col_department"), p.departement, "text", locked);
    body +=   _dirModalSelect("statut",  t("pilot.col.status"),      ["actif", "inactif", "externe"], p.statut || "actif", locked, function(o) { return t("pilot.directory.status." + o); });
    body += '</div><div class="ct-form-grid">';
    body +=   _dirModalField("telephone", t("pilot.directory.field_phone"),  p.telephone, "tel", locked);
    body +=   _dirModalField("site",      t("pilot.directory.col_site"),     p.site, "text", locked);
    body += '</div>';
    if (locked) {
        body += _dirModalUserSelect("manager_email", t("pilot.directory.field_manager"), p.manager_email, p.email, true);
    } else {
        body += '<div class="ct-form-row"><label for="pdm-manager">' + esc(t("pilot.directory.field_manager")) + '</label><div id="pdm-manager-slot"></div></div>';
    }
    body += '</div>';

    var buttons: CtModalButton[] = [];
    if (locked) {
        // Read-only: just a close button, no save/delete.
        ct_modal.open({ title: title, body: body, size: "md", buttons: [{ id: "cancel", label: t("pilot.action.close") }] });
        return;
    }
    if (!isNew) {
        buttons.push({
            id: "delete", label: t("pilot.action.delete"), danger: true,
            result: function() {
                setTimeout(function() {
                    ct_modal.confirm({
                        title: t("pilot.directory.delete_title"),
                        message: t("pilot.directory.delete_msg"),
                        danger: true
                    }).then(function(ok) {
                        if (!ok) return;
                        _fetch("/directory/" + p.id, { method: "DELETE" }).then(function() {
                            showStatus(t("pilot.directory.person_deleted"));
                            _loadDirectory().then(function() { _renderPanel(); });
                        }).catch(function(e) { showStatus(e.message, true); });
                    });
                }, 0);
                return { __deleted: true };
            }
        });
    }
    buttons.push({ id: "cancel", label: t("pilot.action.cancel") });
    buttons.push({
        id: "save", label: t("pilot.action.save"), primary: true,
        result: function() {
            var data: Record<string, string> = {};
            ["nom","prenom","email","fonction","departement","statut","telephone","site"].forEach(function(k) {
                var el = document.getElementById("pdm-" + k) as HTMLInputElement | HTMLSelectElement | null;
                data[k] = el ? (el.value || "") : "";
            });
            if (!data.nom.trim() || !data.prenom.trim() || !data.email.trim()) {
                showStatus(t("pilot.directory.required_fields"), true);
                return false;
            }
            // Manager : le ct_userpicker rend un libellé ; on le résout en e-mail
            // contre l'annuaire (une personne ne peut être son propre manager).
            var mgrLabel = (typeof ct_userpicker !== "undefined" && ct_userpicker.getValue) ? (ct_userpicker.getValue("pdm-manager") || "").trim() : "";
            var mgrPerson = _directory.find(function(x: any) {
                return x.email !== p.email && (((x.prenom + " " + x.nom).trim() === mgrLabel) || (!!x.email && String(x.email).toLowerCase() === mgrLabel.toLowerCase()));
            });
            data.manager_email = mgrPerson ? (mgrPerson.email || "") : mgrLabel;
            return data;
        }
    });

    ct_modal.open({
        title: title,
        body: body,
        size: "md",
        buttons: buttons,
        onOpen: function() {
            if (locked || typeof ct_userpicker === "undefined" || !ct_userpicker.mount) return;
            var mgr = _directory.find(function(x: any) { return !!x.email && !!p.manager_email && String(x.email).toLowerCase() === String(p.manager_email).toLowerCase(); });
            var lbl = mgr ? ((mgr.prenom + " " + mgr.nom).trim() || mgr.email || "") : (p.manager_email || "");
            ct_userpicker.mount({ slotId: "pdm-manager-slot", pickerId: "pdm-manager", value: lbl, placeholder: t("pilot.common.search") || "Rechercher un utilisateur\u2026", directoryUrl: "api/directory", sourceUrl: null });
        }
    }).then(function(result: any) {
        if (!result || result.__deleted) return;
        var promise = isNew
            ? _fetch("/directory", { method: "POST", body: result })
            : _fetch("/directory/" + p.id, { method: "PATCH", body: result });
        promise.then(function() {
            showStatus(isNew ? t("pilot.directory.person_created") : t("pilot.directory.person_updated"));
            _loadDirectory().then(function() { _renderPanel(); });
        }).catch(function(e) { showStatus(e.message, true); });
    });
}

function _dirModalField(name: string, label: string, val: any, type?: string, disabled?: boolean) {
    return '<div class="ct-form-row"><label for="pdm-' + name + '">' + esc(label) + '</label>'
         + '<input type="' + (type || "text") + '" id="pdm-' + name + '" value="' + esc(String(val || "")) + '"' + (disabled ? " disabled" : "") + '></div>';
}
function _dirModalSelect(name: string, label: string, opts: string[], val: string, disabled?: boolean, labelFn?: (o: string) => string) {
    var h = '<div class="ct-form-row"><label for="pdm-' + name + '">' + esc(label) + '</label>'
          + '<select id="pdm-' + name + '"' + (disabled ? " disabled" : "") + '>';
    opts.forEach(function(o) {
        h += '<option value="' + esc(o) + '"' + (val === o ? " selected" : "") + '>' + esc(labelFn ? labelFn(o) : o) + '</option>';
    });
    return h + '</select></div>';
}
function _dirModalUserSelect(name: string, label: string, current?: string, excludeEmail?: string, disabled?: boolean) {
    var h = '<div class="ct-form-row"><label for="pdm-' + name + '">' + esc(label) + '</label>'
          + '<select id="pdm-' + name + '"' + (disabled ? " disabled" : "") + '>';
    h += '<option value=""' + (!current ? " selected" : "") + '>—</option>';
    var found = false;
    _directory.forEach(function(person: any) {
        if (excludeEmail && person.email === excludeEmail) return;  // a person cannot be their own manager
        if (!person.email) return;
        var lbl = (person.prenom + " " + person.nom).trim() || person.email;
        if (person.fonction) lbl += " (" + person.fonction + ")";
        var sel = (current === person.email);
        if (sel) found = true;
        h += '<option value="' + esc(person.email) + '"' + (sel ? " selected" : "") + '>' + esc(lbl) + '</option>';
    });
    // Retro-compat: a manager email not (yet) in the directory keeps its value.
    if (current && !found) {
        h += '<option value="' + esc(current) + '" selected>' + esc(current) + '</option>';
    }
    return h + '</select></div>';
}

window._dirAddPerson = function() { _dirOpenPersonModal(null); };
window._dirEditPerson = function(idx: any) { _dirOpenPersonModal(parseInt(idx)); };

// _dirDeletePerson + _editPerson state removed — deletion is now
// handled inline by the person modal's Supprimer button (ct_modal.confirm).

window._dirImportCsv = function() {
    var el = document.getElementById("csv-import-input") as HTMLInputElement | null;
    if (!el) return;
    el.value = "";
    el.onchange = function() {
        if (!el!.files || !el!.files[0]) return;
        var fd = new FormData();
        fd.append("file", el!.files[0]);
        fetch(BASE + "/directory/import-csv", { method: "POST", body: fd, credentials: "same-origin" })
            .then(function(r) { return r.json(); })
            .then(function(result) {
                showStatus(t("pilot.directory.imported_n", { n: result.imported }));
                _renderPanel();
            }).catch(function(e) { showStatus(e.message, true); });
    };
    el.click();
};

// Export the Pilot directory in a CSV format directly importable into an Access review.
// Format: type_compte;email;roles;groups
//   - type_compte = personnel for HR users, service for accounts whose email looks like a service account
//   - email       = directory email
//   - roles       = function (best proxy — Pilot doesn't store per-app rights)
//   - groups      = department (best proxy)
window._dirExportForAccess = function() {
    if (!_directory.length) {
        showStatus(t("pilot.directory.empty_export"), true);
        return;
    }
    function csvEscape(v: any) {
        var s = String(v == null ? "" : v);
        if (s.indexOf(";") >= 0 || s.indexOf('"') >= 0 || s.indexOf("\n") >= 0) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }
    var lines = ["type_compte;email;roles;groups"];
    var skipped = 0;
    _directory.forEach(function(p) {
        if (!p.email) { skipped++; return; }
        var typeCompte = "personnel";
        // Heuristic: emails like svc-*, svc.*, *@*.local, *service*, administrator → service account
        var em = (p.email || "").toLowerCase();
        if (/^svc[-._]/.test(em) || /service/.test(em) || /@[^@]*\.local$/.test(em) || em === "administrator") {
            typeCompte = "service";
        }
        lines.push([
            csvEscape(typeCompte),
            csvEscape(p.email),
            csvEscape(p.fonction || ""),
            csvEscape(p.departement || "")
        ].join(";"));
    });

    var csv = lines.join("\n") + "\n";
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    var today = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = "annuaire-pilot-pour-access-" + today + ".csv";
    document.body.appendChild(a);
    a.click();
    setTimeout(function() {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
    showStatus(t("pilot.directory.exported_n", { n: _directory.length - skipped }) + (skipped ? t("pilot.directory.skipped_n", { n: skipped }) : ""));
};

// ═══════════════════════════════════════════════════════════════
// USERS
// ═══════════════════════════════════════════════════════════════

function _renderUsers(c: HTMLElement) {
    _loadUsers().then(function() { _doRenderUsers(c); }).catch(function() { _doRenderUsers(c); });
}
// Per-module role definitions
var _MODULE_ROLES: Record<string, string[]> = {
    risk:       ["", "viewer", "editor", "admin"],
    vendor:     ["", "viewer", "manager", "control", "admin"],
    compliance: ["", "viewer", "editor", "admin"],
    audit:      ["", "viewer", "editor", "admin"],
    asset:      ["", "viewer", "contributor", "admin"],
    access:     ["", "manager", "control", "admin"],
    surface:    ["", "viewer", "triager", "admin"],
    appsec:     ["", "viewer", "triager", "admin"],
    watch:      ["", "viewer", "editor", "admin"]
};
var _MODULE_LABELS: Record<string, string> = { risk: "Risk", vendor: "Vendor", compliance: "Compl.", audit: "Audit", asset: "Asset", access: "Access", surface: "Surface", appsec: "AppSec", watch: "Watch" };

function _doRenderUsers(c: HTMLElement) {
    var h = '<h2>' + t("pilot.users.title") + '</h2>';
    if (!window._currentUser || window._currentUser.role !== "admin") {
        h += '<div class="ct-p-5 ct-muted">' + t("pilot.common.admin_only") + '</div>';
        c.innerHTML = h;
        return;
    }
    h += '<div class="ct-scroll-x"><table class="ct-table">';
    h += '<thead><tr><th>' + t("pilot.users.col_user") + '</th><th>' + t("pilot.directory.col_email") + '</th><th>' + t("pilot.users.col_pilot_role") + '</th>';
    Object.keys(_MODULE_ROLES).forEach(function(m) { h += '<th class="ct-ta-c ct-text-label">' + esc(_MODULE_LABELS[m]) + '</th>'; });
    h += '<th>' + t("pilot.users.col_ai") + '</th><th class="ct-text-label">' + t("pilot.users.col_login") + '</th><th></th></tr></thead><tbody>';

    _users.forEach(function(u) {
        var perms = u.permissions || {};
        h += '<tr>';
        h += '<td><div class="ct-flex ct-items-center ct-gap-1">';
        // L'avatar vient du fournisseur d'identite. La CSP le bloque, donc
        // l'image ne s'est jamais affichee : il ne restait qu'une requete vers
        // l'IdP depuis le navigateur de l'administrateur a chaque rendu de ce
        // tableau. On ne rend que ce que la suite sert elle-meme.
        if (u.picture && /^(\/|data:)/.test(u.picture)) {
            h += '<img src="' + esc(u.picture) + '" style="width:20px;height:20px;border-radius:50%">';
        }
        h += '<span>' + esc(u.name || "-") + '</span></div></td>';
        h += '<td class="ct-text-meta ct-muted">' + esc(u.email) + '</td>';
        h += '<td><select data-change="_changeRole" data-args=\'["' + u.id + '"]\' data-pass-value>';
        ["admin", "user", "viewer", "pending"].forEach(function(r) {
            h += '<option value="' + r + '"' + (u.role === r ? ' selected' : '') + '>' + t("pilot.users.role." + r) + '</option>';
        });
        h += '</select></td>';

        Object.keys(_MODULE_ROLES).forEach(function(m) {
            var roles = _MODULE_ROLES[m];
            var current = perms[m] || "";
            h += '<td class="ct-ta-c"><select data-change="_changeModPerm" data-args=\'["' + u.id + '","' + m + '"]\' data-pass-value style="font-size:var(--ct-text-label);padding:var(--ct-s1) var(--ct-s1);width:85px">';
            roles.forEach(function(r) {
                var label = r ? t("pilot.users.modrole." + r) : "—";
                h += '<option value="' + esc(r) + '"' + (current === r ? ' selected' : '') + '>' + esc(label) + '</option>';
            });
            h += '</select></td>';
        });

        h += '<td class="ct-ta-c"><input type="checkbox"' + (u.ai_enabled === "true" ? ' checked' : '') + ' data-change="_toggleAI" data-args=\'["' + u.id + '"]\' data-pass-el></td>';
        h += '<td class="ct-text-label ct-muted">' + (u.last_login ? u.last_login.split("T")[0] : "-") + '</td>';
        h += '<td class="ct-ta-c"><button class="ct-btn" data-variant="ghost" title="' + t("pilot.users.delete") + '"'
           + ' data-click="_deleteUser" data-args=\'["' + u.id + '","' + esc(u.email) + '"]\'>' + _icon("trash", 16) + '</button></td>';
        h += '</tr>';
    });
    h += '</tbody></table></div>';
    c.innerHTML = h;
}

window._changeRole = function(uid: string, role: string) {
    _fetch("/users/" + uid, { method: "PUT", body: { role: role } }).then(function() {
        showStatus(t("pilot.users.role_updated"));
        _loadUsers().then(function() { _renderPanel(); });
    });
};

window._deleteUser = function(uid: string, email: string) {
    if (!confirm(t("pilot.users.delete_confirm", { email: email }))) return;
    showStatus(t("pilot.users.deleting"));
    _fetch("/users/" + uid, { method: "DELETE" }).then(function(resp) {
        // A module that did not answer keeps its row: say so rather than
        // reporting a clean deletion.
        var failed = (resp && resp.failed) || [];
        showStatus(failed.length
            ? t("pilot.users.deleted_partial", { modules: failed.join(", ") })
            : t("pilot.users.deleted", { email: email }));
        _loadUsers().then(function() { _renderPanel(); });
    }).catch(function(e) {
        var msg = e.message || "";
        showStatus(t("pilot.common.error_msg", { msg: msg }));
    });
};

window._changeModPerm = function(uid: string, mod: string, role: string) {
    // Read all current permissions from the row
    var user = _users.find(function(u) { return u.id === uid; });
    var perms = Object.assign({}, (user && user.permissions) || {});
    perms[mod] = role;
    // Remove empty entries
    Object.keys(perms).forEach(function(k) { if (!perms[k]) delete perms[k]; });
    _fetch("/users/" + uid, { method: "PUT", body: { permissions: perms } }).then(function() {
        showStatus(t("pilot.users.perms_updated", { mod: mod }));
        _loadUsers().then(function() { if (_panel === "users") _renderPanel(); });
    });
};

window._toggleAI = function(uid: string, el: HTMLInputElement) {
    _fetch("/users/" + uid, { method: "PUT", body: { ai_enabled: el.checked ? "true" : "false" } }).then(function() { showStatus(t("pilot.users.ai_updated")); });
};

// ═══════════════════════════════════════════════════════════════
// BACKUPS
// ═══════════════════════════════════════════════════════════════

var _backupConfig: PilotBackupConfig | null = null;
var _backupList: PilotBackupEntry[] | null = null;

var _bkTab = "backups";
var _bkFilter = "all";
// Keys ticked in the history table. Kept out of the DOM so a re-render
// (filter change, refresh after an action) does not silently drop a
// selection the user still sees on screen.
var _bkSelected: Record<string, boolean> = {};

function _bkSelectedKeys(): string[] {
    return Object.keys(_bkSelected).filter(function(k) { return _bkSelected[k]; });
}

function _bkFilterChanged(val: string) {
    _bkFilter = val;
    _renderPanel();
}

function _bkSelectTab(tab: string) {
    _bkTab = tab;
    _renderPanel();
}

function _renderBackups(c: HTMLElement) {
    if (!window._currentUser || window._currentUser.role !== "admin") {
        c.innerHTML = '<h2>' + t("pilot.backups.title") + '</h2><div class="ct-p-5 ct-muted">' + t("pilot.common.admin_only") + '</div>';
        return;
    }
    // Une seule entrée « Sauvegardes » : deux onglets internes.
    var h = '<h2>' + t("pilot.backups.title") + '</h2>';
    h += '<div class="ct-btngroup ct-mb-4">';
    h += '<button class="ct-btn"' + (_bkTab === "backups" ? ' data-variant="primary"' : '') + ' data-click="_bkSelectTab" data-args=\'' + _da("backups") + '\'>' + t("pilot.backups.tab_backups") + '</button>';
    h += '<button class="ct-btn"' + (_bkTab === "restore" ? ' data-variant="primary"' : '') + ' data-click="_bkSelectTab" data-args=\'' + _da("restore") + '\'>' + t("pilot.nav.restore") + '</button>';
    h += '</div><div id="bk-tab-content"></div>';
    c.innerHTML = h;
    var inner = document.getElementById("bk-tab-content")!;
    if (_bkTab === "restore") _rstRender(inner);
    else _renderBackupsInner(inner);
}

function _renderBackupsInner(c: HTMLElement) {
    // Both caches, not just the config: every action that invalidates the
    // history sets `_backupList = null` while leaving `_backupConfig` in
    // place. Guarding on the config alone skipped the refetch and rendered a
    // null list as "no backups" — the history vanished after a delete and
    // only a full page reload brought it back.
    if (!_backupConfig || !_backupList) {
        c.innerHTML = '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.common.loading") + '</div>';
        Promise.all([
            _fetch("/backups/config").then(function(d) { _backupConfig = d; }),
            _fetch("/backups/list").then(function(d) { _backupList = d; })
        ]).then(function() { _renderBackupsInner(c); });
        return;
    }

    var h = "";

    // Config per module
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-3">' + t("pilot.backups.config_per_module") + '</h3>';
    h += '<table class="ct-table"><thead><tr><th>' + t("pilot.col.module") + '</th><th class="ct-ta-c">' + t("pilot.backups.col_active") + '</th><th>' + t("pilot.backups.col_frequency") + '</th><th>' + t("pilot.backups.col_retention") + '</th><th></th></tr></thead><tbody>';

    var moduleNames: Record<string, string> = {
        pilot: t("pilot.backups.module_pilot"),
        risk: "Risk (EBIOS RM)",
        vendor: "Vendor (TPRM)",
        compliance: "Compliance",
        audit: "Audit",
        asset: "Asset",
        access: "Access",
        surface: "Surface",
        appsec: "AppSec",
        watch: "Watch"
    };
    // Pilot first so users see that self-backup is supported. Keep this
    // list in sync with _saveBackupConfig() below and with
    // VALID_MODULES in pilot/src/routes/backups.py.
    ["pilot", "risk", "vendor", "compliance", "audit", "asset", "access", "surface", "appsec", "watch"].forEach(function(mod) {
        var cfg = _backupConfig![mod] || { enabled: false, frequency_hours: 24, retention_daily: 7, retention_weekly: 4, retention_monthly: 12 };
        h += '<tr>';
        h += '<td><span class="ct-ref" data-module="' + mod + '">' + (moduleNames[mod] || mod) + '</span></td>';
        h += '<td class="ct-ta-c"><input type="checkbox" id="bk-' + mod + '-enabled"' + (cfg.enabled ? ' checked' : '') + '></td>';
        h += '<td><select id="bk-' + mod + '-freq" class="ct-select ct-w-auto" data-size="xs">';
        [1, 6, 12, 24, 48, 168].forEach(function(h2) {
            var label = h2 < 24 ? t("pilot.backups.freq_hours", { n: h2 }) : t("pilot.backups.freq_days", { n: h2 / 24 });
            h += '<option value="' + h2 + '"' + (cfg.frequency_hours === h2 ? ' selected' : '') + '>' + label + '</option>';
        });
        h += '</select></td>';
        h += '<td class="ct-nowrap">'
            + '<input type="number" min="0" id="bk-' + mod + '-rd" class="ct-input ct-w-52" value="' + cfg.retention_daily + '" title="' + t("pilot.backups.daily_tooltip") + '"> ' + t("pilot.backups.unit_days")
            + ' <input type="number" min="0" id="bk-' + mod + '-rw" class="ct-input ct-w-52" value="' + cfg.retention_weekly + '" title="' + t("pilot.backups.weekly_tooltip") + '"> ' + t("pilot.backups.unit_weeks")
            + ' <input type="number" min="0" id="bk-' + mod + '-rm" class="ct-input ct-w-52" value="' + cfg.retention_monthly + '" title="' + t("pilot.backups.monthly_tooltip") + '"> ' + t("pilot.backups.unit_months")
            + '</td>';
        h += '<td><button class="ct-btn" data-size="xs" data-click="_runBackup" data-args=\'' + _da(mod) + '\'>' + t("pilot.backups.run") + '</button></td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    h += '<div class="ct-flex ct-gap-2 ct-mt-3">';
    h += '<button class="ct-btn" data-variant="primary" data-click="_saveBackupConfig">' + t("pilot.backups.save_config") + '</button>';
    h += '<button class="ct-btn" data-click="_runAllBackups">' + t("pilot.backups.run_all") + '</button>';
    h += '</div></div>';

    // Backup history
    h += '<div class="ct-bordered ct-r-lg ct-p-4">';
    h += '<div class="ct-flex ct-gap-3 ct-mb-3" style="align-items:center">';
    h += '<h3 class="ct-text-data" style="margin:0">' + t("pilot.backups.history") + '</h3>';
    if (_backupList && _backupList.length) {
        var mods: string[] = [];
        _backupList.forEach(function(b) { if (mods.indexOf(b.module) < 0) mods.push(b.module); });
        mods.sort();
        h += '<select class="ct-select ct-w-auto" data-size="xs" data-change="_bkFilterChanged" data-pass-value>';
        h += '<option value="all"' + (_bkFilter === "all" ? ' selected' : '') + '>' + t("pilot.backups.filter_all") + '</option>';
        mods.forEach(function(m2) {
            h += '<option value="' + esc(m2) + '"' + (_bkFilter === m2 ? ' selected' : '') + '>' + esc(m2) + '</option>';
        });
        h += '</select>';
    }
    h += '</div>';
    if (!_backupList || !_backupList.length) {
        h += '<div class="ct-muted ct-text-meta">' + t("pilot.backups.empty") + '</div>';
    } else {
        var shown = _backupList.filter(function(b) { return _bkFilter === "all" || b.module === _bkFilter; });
        // Groupé par module (puis plus récent d'abord) — la clé backup_<mod>_<ts>
        // trie naturellement par date dans un même module.
        shown.sort(function(a, b2) { return a.module === b2.module ? (a.key < b2.key ? 1 : -1) : (a.module < b2.module ? -1 : 1); });
        // Only what is on screen counts as "all": ticking the header while a
        // module filter is active must not select rows the user cannot see.
        var selectedShown = shown.filter(function(b) { return _bkSelected[b.key]; }).length;
        var nSel = _bkSelectedKeys().length;
        if (nSel) {
            h += '<div class="ct-flex ct-gap-2 ct-mb-3" style="align-items:center">';
            h += '<span class="ct-text-meta">' + t("pilot.backups.n_selected", { n: nSel }) + '</span>';
            h += '<button class="ct-btn" data-variant="danger" data-size="xs" data-click="_deleteSelectedBackups">'
               + t("pilot.backups.delete_selected") + '</button>';
            h += '<button class="ct-btn" data-size="xs" data-click="_bkClearSelection">'
               + t("pilot.backups.clear_selection") + '</button>';
            h += '</div>';
        }
        h += '<table class="ct-table"><thead><tr>';
        h += '<th class="ct-ta-c"><input type="checkbox" data-change="_bkToggleAll" data-pass-el'
           + (shown.length && selectedShown === shown.length ? ' checked' : '') + '></th>';
        h += '<th>' + t("pilot.col.module") + '</th><th>' + t("pilot.backups.col_date") + '</th><th>' + t("pilot.backups.col_items") + '</th><th>' + t("pilot.backups.col_size") + '</th><th></th></tr></thead><tbody>';
        shown.forEach(function(b) {
            var date = b.timestamp ? new Date(b.timestamp).toLocaleString() : b.key;
            h += '<tr>';
            h += '<td class="ct-ta-c"><input type="checkbox" data-change="_bkToggleOne" data-args=\'' + _da(b.key) + '\' data-pass-el'
               + (_bkSelected[b.key] ? ' checked' : '') + '></td>';
            h += '<td><span class="ct-ref" data-module="' + esc(b.module) + '">' + esc(b.module) + '</span></td>';
            h += '<td class="ct-text-meta">' + esc(date)
                + ((b as any).manual ? ' <span class="ct-badge" data-tone="info" title="' + esc((b as any).created_by || "") + '">' + t("pilot.backups.badge_manual") + '</span>' : '')
                + '</td>';
            h += '<td>' + b.items_count + '</td>';
            h += '<td class="ct-text-meta">' + t("pilot.backups.kb", { n: b.size_kb || 0 }) + '</td>';
            h += '<td><div class="ct-flex ct-gap-1">';
            h += '<button class="ct-btn" data-size="xs" data-click="_downloadBackup" data-args=\'' + _da(b.key) + '\' title="' + t("pilot.action.download") + '" data-size="xs" data-icon>&#8595;</button>';
            h += '<button class="ct-btn" data-size="xs" data-click="_restoreBackup" data-args=\'' + _da(b.key, b.module) + '\' title="' + t("pilot.backups.restore") + '" data-size="xs" data-icon>&#8634;</button>';
            h += '<button class="ct-btn" data-variant="danger" data-icon data-size="xs" data-click="_deleteBackup" data-args=\'' + _da(b.key) + '\' title="' + t("pilot.action.delete") + '">' + _icon("trash", 14) + '</button>';
            h += '</div></td></tr>';
        });
        h += '</tbody></table>';
    }
    h += '</div>';

    c.innerHTML = h;
}

window._saveBackupConfig = function() {
    var configs: PilotBackupModuleConfig[] = [];
    // Must mirror the module list rendered by _renderBackups above.
    // Keeping these two lists in sync is required — a stale entry here
    // throws when getElementById returns null and silently aborts the
    // whole save; a missing entry never gets persisted server-side.
    ["pilot", "risk", "vendor", "compliance", "audit", "asset", "access", "surface", "appsec", "watch"].forEach(function(mod) {
        var enabledEl = document.getElementById("bk-" + mod + "-enabled") as HTMLInputElement | null;
        var freqEl = document.getElementById("bk-" + mod + "-freq") as HTMLSelectElement | null;
        var rdEl = document.getElementById("bk-" + mod + "-rd") as HTMLInputElement | null;
        var rwEl = document.getElementById("bk-" + mod + "-rw") as HTMLInputElement | null;
        var rmEl = document.getElementById("bk-" + mod + "-rm") as HTMLInputElement | null;
        if (!enabledEl || !freqEl || !rdEl || !rwEl || !rmEl) return;
        configs.push({
            module: mod,
            enabled: enabledEl.checked,
            frequency_hours: parseInt(freqEl.value),
            retention_daily: Math.max(0, parseInt(rdEl.value) || 0),
            retention_weekly: Math.max(0, parseInt(rwEl.value) || 0),
            retention_monthly: Math.max(0, parseInt(rmEl.value) || 0),
        });
    });
    _fetch("/backups/config", { method: "PUT", body: { configs: configs } }).then(function(cfg) {
        _backupConfig = cfg;
        showStatus(t("pilot.backups.config_saved"));
    }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: (e && e.message) || t("pilot.common.failed") })); });
};

window._runBackup = function(mod: string) {
    showStatus(t("pilot.backups.running", { mod: mod }));
    _fetch("/backups/run/" + mod, { method: "POST" }).then(function(r) {
        showStatus(t("pilot.backups.done_items", { mod: mod, n: r.items }));
        _backupList = null;
        _backupConfig = null;
        _renderPanel();
    }).catch(function(e) { showStatus(t("pilot.common.error_msg", { msg: e.message })); });
};

window._runAllBackups = function() {
    showStatus(t("pilot.backups.running_all"));
    _fetch("/backups/run-all", { method: "POST" }).then(function(report) {
        var parts = [];
        for (var m in report) parts.push(m + ": " + report[m]);
        showStatus(t("pilot.backups.done_all", { detail: parts.join(", ") }));
        _backupList = null;
        _backupConfig = null;
        _renderPanel();
    }).catch(function(e) { showStatus(t("pilot.backups.failed", { msg: e.message || String(e) }), true); });
};

window._downloadBackup = function(key: string) {
    var a = document.createElement("a");
    a.href = "/api/backups/download/" + encodeURIComponent(key);
    a.download = key + ".json";
    a.click();
};

window._restoreBackup = function(key: string, mod: string) {
    if (!confirm(t("pilot.backups.restore_confirm", { mod: mod }))) return;
    showStatus(t("pilot.backups.restoring"));
    _fetch("/backups/restore/" + encodeURIComponent(key), { method: "POST" }).then(function(r) {
        // Confirmation bloquante : une restauration peut être longue et le
        // toast de 3 s se rate — l'admin doit savoir que c'est TERMINÉ.
        alert(t("pilot.backups.restored_confirm", { mod: r.module, n: r.restored })
            + (r.errors ? "\n" + t("pilot.backups.restore_errors", { n: r.errors }) : ""));
        _backupList = null;
        _renderPanel();
    }).catch(function(e) { alert(t("pilot.backups.restore_failed", { msg: e.message || String(e) })); });
};

window._deleteBackup = function(key: string) {
    if (!confirm(t("pilot.backups.delete_confirm"))) return;
    _fetch("/backups/" + encodeURIComponent(key), { method: "DELETE" }).then(function() {
        delete _bkSelected[key];
        _backupList = null;
        _renderPanel();
    });
};

window._bkToggleOne = function(key: string, el: HTMLInputElement) {
    if (el.checked) _bkSelected[key] = true; else delete _bkSelected[key];
    _renderPanel();
};

window._bkToggleAll = function(el: HTMLInputElement) {
    var list = _backupList || [];
    list.filter(function(b) { return _bkFilter === "all" || b.module === _bkFilter; })
        .forEach(function(b) {
            if (el.checked) _bkSelected[b.key] = true; else delete _bkSelected[b.key];
        });
    _renderPanel();
};

window._bkClearSelection = function() {
    _bkSelected = {};
    _renderPanel();
};

window._deleteSelectedBackups = function() {
    var keys = _bkSelectedKeys();
    if (!keys.length) return;
    if (!confirm(t("pilot.backups.delete_selected_confirm", { n: keys.length }))) return;
    showStatus(t("pilot.backups.deleting"));
    _fetch("/backups/delete-many", { method: "POST", body: { keys: keys } }).then(function(r) {
        _bkSelected = {};
        _backupList = null;
        showStatus(t("pilot.backups.deleted_n", { n: (r && r.deleted) || keys.length }));
        _renderPanel();
    }).catch(function(e) {
        showStatus(t("pilot.common.error_msg", { msg: e.message || "" }));
    });
};

// ═══════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════

var _settings: PilotSettings | null = null;

function _renderAiProviderFields(provider: string, s: PilotSettings) {
    var h = '';
    var bullets = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
    if (provider === "anthropic") {
        h += '<div class="ct-grid ct-grid-2 ct-gap-3">';
        h += '<div><label class="pilot-label">' + t("pilot.settings.model") + '</label><select id="set-ai-model" class="ct-select">';
        ["claude-sonnet-5", "claude-opus-5", "claude-fable-5", "claude-haiku-4-5-20251001", "claude-opus-4-8", "claude-sonnet-4-6"].forEach(function(m) {
            h += '<option value="' + m + '"' + (s.ai_model === m ? ' selected' : '') + '>' + m + '</option>';
        });
        h += '</select></div>';
        h += '<div><label class="pilot-label">' + t("pilot.settings.api_key_anthropic") + '</label>';
        h += '<input type="password" id="set-key-anthropic" class="ct-input" placeholder="sk-ant-..." value="' + (s.ai_key_anthropic === "configured" ? bullets : "") + '">';
        h += '<div style="font-size:var(--ct-text-label);color:' + (s.ai_key_anthropic === "configured" ? 'var(--ct-low)' : 'var(--ct-ink-2)') + ';margin-top:2px">' + (s.ai_key_anthropic === "configured" ? t("pilot.settings.key_configured") : t("pilot.settings.key_not_configured")) + '</div></div>';
        h += '</div>';
    } else if (provider === "openai") {
        h += '<div class="ct-grid ct-grid-2 ct-gap-3">';
        h += '<div><label class="pilot-label">' + t("pilot.settings.model") + '</label><select id="set-ai-model" class="ct-select">';
        ["gpt-5.6", "gpt-5.6-terra", "gpt-5.5", "gpt-5.4-mini", "gpt-4o"].forEach(function(m) {
            h += '<option value="' + m + '"' + (s.ai_model === m ? ' selected' : '') + '>' + m + '</option>';
        });
        h += '</select></div>';
        h += '<div><label class="pilot-label">' + t("pilot.settings.api_key_openai") + '</label>';
        h += '<input type="password" id="set-key-openai" class="ct-input" placeholder="sk-..." value="' + (s.ai_key_openai === "configured" ? bullets : "") + '">';
        h += '<div style="font-size:var(--ct-text-label);color:' + (s.ai_key_openai === "configured" ? 'var(--ct-low)' : 'var(--ct-ink-2)') + ';margin-top:2px">' + (s.ai_key_openai === "configured" ? t("pilot.settings.key_configured") : t("pilot.settings.key_not_configured")) + '</div></div>';
        h += '</div>';
    } else if (provider === "gemini") {
        h += '<div class="ct-grid ct-grid-2 ct-gap-3">';
        h += '<div><label class="pilot-label">' + t("pilot.settings.model") + '</label><select id="set-ai-model" class="ct-select">';
        ["gemini-3.6-flash", "gemini-3.5-flash-lite"].forEach(function(m) {
            h += '<option value="' + m + '"' + (s.ai_model === m ? ' selected' : '') + '>' + m + '</option>';
        });
        h += '</select></div>';
        h += '<div><label class="pilot-label">' + t("pilot.settings.api_key_gemini") + '</label>';
        h += '<input type="password" id="set-key-gemini" class="ct-input" placeholder="AIza..." value="' + (s.ai_key_gemini === "configured" ? bullets : "") + '">';
        h += '<div style="font-size:var(--ct-text-label);color:' + (s.ai_key_gemini === "configured" ? 'var(--ct-low)' : 'var(--ct-ink-2)') + ';margin-top:2px">' + (s.ai_key_gemini === "configured" ? t("pilot.settings.key_configured") : t("pilot.settings.key_not_configured")) + '</div></div>';
        h += '</div>';
    } else if (provider === "custom") {
        h += '<p class="ct-text-label ct-muted ct-mb-2">' + t("pilot.settings.custom_hint") + '</p>';
        h += '<div class="ct-grid ct-grid-2 ct-gap-3 ct-mb-2">';
        h += '<div><label class="pilot-label">' + t("pilot.settings.display_name") + '</label><input type="text" id="set-custom-label" class="ct-input" placeholder="Ollama Llama3" value="' + esc(s.ai_custom_label || '') + '"></div>';
        h += '<div><label class="pilot-label">' + t("pilot.settings.model") + '</label><input type="text" id="set-ai-model" class="ct-input" placeholder="llama3, mistral-large, ..." value="' + esc(s.ai_model || s.ai_custom_model || '') + '"></div>';
        h += '</div>';
        h += '<div class="ct-mb-2"><label class="pilot-label">' + t("pilot.settings.endpoint_url") + '</label><input type="text" id="set-custom-endpoint" class="ct-input" placeholder="http://ollama:11434/v1" value="' + esc(s.ai_custom_endpoint || '') + '"></div>';
        h += '<div><label class="pilot-label">' + t("pilot.settings.api_key_optional") + '</label><input type="password" id="set-custom-key" class="ct-input" placeholder="' + t("pilot.settings.no_auth_placeholder") + '" value="' + (s.ai_custom_key === "configured" ? bullets : "") + '"></div>';
    }
    return h;
}

function _bindAiKeyFocusHandlers() {
    ["set-key-anthropic", "set-key-openai", "set-key-gemini", "set-custom-key"].forEach(function(id) {
        var el = document.getElementById(id) as HTMLInputElement | null;
        if (el) el.onfocus = function() { var inp = this as HTMLInputElement; if (inp.value.indexOf("\u2022") >= 0) inp.value = ""; };
    });
}

function _renderSettings(c: HTMLElement) {
    // Language is a per-user, per-browser preference — shown to EVERY user,
    // unlike the rest of this panel which is admin-only.
    function _langBtn(lang: string, label: string): string {
        var on = _locale === lang;
        return '<button id="settings-lang-' + lang + '" style="padding:var(--ct-s2) var(--ct-s4);border:1px solid '
            + (on ? "var(--ct-accent)" : "var(--ct-line)")
            + ';border-radius:4px;cursor:pointer;font-size:0.85em;'
            + (on ? "background:var(--ct-accent);color:var(--ct-onaccent)" : "background:var(--ct-surface);color:var(--ct-ink)") + '">' + esc(label) + '</button>';
    }
    var langSection = '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">'
        + '<h3 class="ct-text-data ct-mb-3">' + esc(t("settings.language") || "Langue") + '</h3>'
        + '<div class="ct-flex ct-gap-2">' + _langBtn("fr", "Français") + _langBtn("en", "English") + '</div></div>';
    function wireLang() {
        ["fr", "en"].forEach(function(lang) {
            var b = document.getElementById("settings-lang-" + lang);
            if (b) b.onclick = function() { switchLang(lang, _renderPanel); };
        });
    }

    if (!window._currentUser || window._currentUser.role !== "admin") {
        c.innerHTML = '<h2>' + t("pilot.settings.title") + '</h2>' + langSection
            + '<div class="ct-p-5 ct-muted">' + t("pilot.settings.admin_only_rest") + '</div>';
        wireLang();
        return;
    }
    if (!_settings) {
        c.innerHTML = '<h2>' + t("pilot.settings.title") + '</h2><div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.common.loading") + '</div>';
        _fetch("/settings").then(function(s) { _settings = s; _renderSettings(c); });
        return;
    }

    var s = _settings;
    var h = '<h2>' + t("pilot.settings.title_cross") + '</h2>';
    h += '<p class="ct-text-label ct-muted ct-mb-5">' + t("pilot.settings.pushed_note") + '</p>';
    h += langSection;

    // Demo data toggle
    var demoOn = s.demo_mode !== "false";
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-2">' + t("pilot.settings.demo_data") + '</h3>';
    h += '<label class="ct-flex ct-items-center ct-gap-2 ct-clickable">';
    h += '<input type="checkbox" id="set-demo-mode"' + (demoOn ? ' checked' : '') + ' class="ct-w-auto">';
    h += '<span>' + t("pilot.settings.demo_toggle") + '</span>';
    h += '</label>';
    h += '<div class="ct-text-label ct-muted ct-mt-1">' + t("pilot.settings.demo_hint") + '</div>';
    h += '</div>';

    // AI section — progressive disclosure: pick provider, then show only relevant fields
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-3">' + t("pilot.settings.ai_section") + '</h3>';

    var providerLabels: Record<string, string> = { anthropic: "Anthropic (Claude)", openai: "OpenAI (GPT)", gemini: "Google (Gemini)", custom: s.ai_custom_label || "Custom LLM" };
    h += '<div class="ct-mb-3"><label class="pilot-label">' + t("pilot.settings.ai_provider_default") + '</label><select id="set-ai-provider" class="ct-select">';
    ["anthropic", "openai", "gemini", "custom"].forEach(function(p) {
        h += '<option value="' + p + '"' + (s.ai_provider === p ? ' selected' : '') + '>' + (providerLabels[p] || p) + '</option>';
    });
    h += '</select></div>';

    h += '<div id="ai-provider-fields">' + _renderAiProviderFields(s.ai_provider || "anthropic", s) + '</div>';
    h += '</div>';

    // Proxy section
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-3">' + t("pilot.settings.proxy_config") + '</h3>';
    h += '<p class="ct-text-label ct-muted ct-mb-3">' + t("pilot.settings.proxy_hint") + '</p>';

    h += '<div class="ct-grid ct-grid-2 ct-gap-3 ct-mb-3">';
    h += '<div><label class="pilot-label">HTTP_PROXY</label><input type="text" id="set-http-proxy" class="ct-input" placeholder="http://proxy:3128" value="' + esc(s.http_proxy || '') + '"></div>';
    h += '<div><label class="pilot-label">HTTPS_PROXY</label><input type="text" id="set-https-proxy" class="ct-input" placeholder="http://proxy:3128" value="' + esc(s.https_proxy || '') + '"></div>';
    h += '</div>';
    h += '<div><label class="pilot-label">NO_PROXY</label><input type="text" id="set-no-proxy" class="ct-input" placeholder="localhost,127.0.0.1,.internal" value="' + esc(s.no_proxy || '') + '"></div>';
    h += '</div>';

    // SMTP section — consumed by Watch (daily digest) and future module notifications.
    var bullets = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-3">' + t("pilot.settings.smtp_section") + '</h3>';
    h += '<p class="ct-text-label ct-muted ct-mb-3">' + t("pilot.settings.smtp_hint") + '</p>';
    h += '<div style="display:grid;grid-template-columns:2fr 1fr;gap:var(--ct-s3);margin-bottom:var(--ct-s3)">';
    h += '<div><label class="pilot-label">' + t("pilot.settings.smtp_host") + '</label><input type="text" id="set-smtp-host" class="ct-input" placeholder="smtp.example.com" value="' + esc(s.smtp_host || '') + '"></div>';
    h += '<div><label class="pilot-label">' + t("pilot.settings.smtp_port") + '</label><input type="text" id="set-smtp-port" class="ct-input" placeholder="587" value="' + esc(s.smtp_port || '') + '"></div>';
    h += '</div>';
    h += '<div class="ct-grid ct-grid-2 ct-gap-3 ct-mb-3">';
    h += '<div><label class="pilot-label">' + t("pilot.settings.smtp_user") + '</label><input type="text" id="set-smtp-user" class="ct-input" placeholder="watch@example.com" value="' + esc(s.smtp_user || '') + '"></div>';
    h += '<div><label class="pilot-label">' + t("pilot.settings.smtp_password") + '</label><input type="password" id="set-smtp-password" class="ct-input" placeholder="' + (s.smtp_password === "configured" ? bullets : '') + '" value="' + (s.smtp_password === "configured" ? bullets : '') + '">';
    h += '<div style="font-size:var(--ct-text-label);color:' + (s.smtp_password === "configured" ? 'var(--ct-low)' : 'var(--ct-ink-2)') + ';margin-top:2px">' + (s.smtp_password === "configured" ? t("pilot.settings.pwd_configured") : t("pilot.settings.pwd_not_configured")) + '</div></div>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:2fr 1fr;gap:var(--ct-s3)">';
    h += '<div><label class="pilot-label">' + t("pilot.settings.smtp_from") + '</label><input type="text" id="set-smtp-from" class="ct-input" placeholder="watch@example.com" value="' + esc(s.smtp_from || '') + '"></div>';
    h += '<div><label class="pilot-label">TLS</label><select id="set-smtp-tls" class="ct-select"><option value="true"' + ((s.smtp_tls || 'true') === 'true' ? ' selected' : '') + '>' + t("pilot.settings.tls_on") + '</option><option value="false"' + ((s.smtp_tls || '') === 'false' ? ' selected' : '') + '>' + t("pilot.settings.tls_off") + '</option></select></div>';
    h += '</div>';
    h += '</div>';

    // Save + Push
    h += '<div class="ct-flex ct-gap-2">';
    h += '<button class="ct-btn" data-variant="primary" data-click="_saveSettings">' + t("pilot.settings.save_push") + '</button>';
    h += '<button class="ct-btn" data-click="_resyncModules">' + t("pilot.settings.resync") + '</button>';
    h += '</div>';
    h += '<p class="ct-hint">' + t("pilot.settings.resync_hint") + '</p>';

    c.innerHTML = h;
    wireLang();

    // Re-render provider fields when provider changes
    var sel = document.getElementById("set-ai-provider") as HTMLSelectElement | null;
    if (sel) sel.onchange = function() {
        var box = document.getElementById("ai-provider-fields");
        if (box) {
            box.innerHTML = _renderAiProviderFields((this as HTMLSelectElement).value, _settings || {});
            _bindAiKeyFocusHandlers();
        }
    };

    _bindAiKeyFocusHandlers();
}

window._saveSettings = function() {
    function _val(id: string) { var el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null; return el ? el.value : null; }
    var data: Record<string, any> = {
        ai_provider: _val("set-ai-provider"),
        http_proxy: _val("set-http-proxy") || "",
        https_proxy: _val("set-https-proxy") || "",
        no_proxy: _val("set-no-proxy") || "",
    };
    var demoEl = document.getElementById("set-demo-mode") as HTMLInputElement | null;
    if (demoEl) data.demo_mode = demoEl.checked ? "true" : "false";
    var modelVal = _val("set-ai-model");
    if (modelVal !== null) data.ai_model = modelVal;
    // Only send AI keys if user typed a real value (not bullets)
    var kAnth = _val("set-key-anthropic");
    var kOai = _val("set-key-openai");
    if (kAnth && kAnth.indexOf("\u2022") < 0) data.ai_key_anthropic = kAnth;
    if (kOai && kOai.indexOf("\u2022") < 0) data.ai_key_openai = kOai;
    var kGem = _val("set-key-gemini");
    if (kGem && kGem.indexOf("\u2022") < 0) data.ai_key_gemini = kGem;
    // Custom LLM (only present when provider === "custom")
    var customEndpoint = _val("set-custom-endpoint");
    var customLabel = _val("set-custom-label");
    var customKey = _val("set-custom-key");
    if (customEndpoint !== null) data.ai_custom_endpoint = customEndpoint.trim();
    if (customLabel !== null) data.ai_custom_label = customLabel.trim();
    // Custom model is captured via set-ai-model when provider=custom; mirror to ai_custom_model
    if (data.ai_provider === "custom" && modelVal) data.ai_custom_model = modelVal.trim();
    if (customKey && customKey.indexOf("\u2022") < 0) data.ai_custom_key = customKey;

    // SMTP — only send password if user typed a real value (not the bullet
    // placeholder shown when a password is already configured).
    var smtpHost = _val("set-smtp-host");
    var smtpPort = _val("set-smtp-port");
    var smtpUser = _val("set-smtp-user");
    var smtpPassword = _val("set-smtp-password");
    var smtpFrom = _val("set-smtp-from");
    var smtpTls = _val("set-smtp-tls");
    if (smtpHost !== null) data.smtp_host = smtpHost.trim();
    if (smtpPort !== null) data.smtp_port = smtpPort.trim();
    if (smtpUser !== null) data.smtp_user = smtpUser.trim();
    if (smtpPassword && smtpPassword.indexOf("\u2022") < 0) data.smtp_password = smtpPassword;
    if (smtpFrom !== null) data.smtp_from = smtpFrom.trim();
    if (smtpTls !== null) data.smtp_tls = smtpTls;

    var hasKey = data.ai_key_anthropic || data.ai_key_openai || data.ai_key_gemini;
    showStatus(hasKey ? t("pilot.settings.validating_keys") : t("pilot.common.saving"));
    _fetch("/settings", { method: "PUT", body: data }).then(function(resp) {
        _settings = null;
        var msg = t("pilot.settings.saved_pushed");
        if (resp.validation) {
            for (var p in resp.validation) {
                if (resp.validation[p].valid) msg += t("pilot.settings.key_valid", { provider: p });
            }
        }
        showStatus(msg);
        _renderPanel();
    }).catch(function(e) {
        var msg = e.message || "";
        // Extract detail from API error
        if (msg.indexOf("400") >= 0) {
            try { msg = msg.split(": ").slice(1).join(": "); } catch(x) {}
        }
        showStatus(t("pilot.common.error_msg", { msg: msg }));
    });
};

// Re-push the stored settings without editing them. Needed after adding a
// module to the deployment: the registry gains a row, but nothing was ever
// sent to it until someone re-saved this page.
(window as any)._resyncModules = function() {
    showStatus(t("pilot.settings.resyncing"));
    _fetch("/settings/resync", { method: "POST", body: {} }).then(function(resp) {
        var push = resp.push || {};
        var ko: string[] = [];
        for (var m in push) if (push[m] !== "ok") ko.push(m + " (" + push[m] + ")");
        showStatus(ko.length
            ? t("pilot.settings.resync_partial", { modules: ko.join(", ") })
            : t("pilot.settings.resync_done", { count: String(Object.keys(push).length) }));
    }).catch(function(e) {
        showStatus(t("pilot.common.error_msg", { msg: e.message || "" }));
    });
};

// ═══════════════════════════════════════════════════════════════
// DATA LOADING
// ═══════════════════════════════════════════════════════════════

function _loadDashboard() { return _fetch("/dashboard").then(function(d) { _dashData = d; }); }
function _loadMeasures() {
    return Promise.all([
        _fetch("/measures"),
        _fetch("/measure-groups").catch(function() { return []; })
    ]).then(function(r) { _measures = r[0]; _groups = r[1] || []; });
}
function _loadEvidences() { return _fetch("/evidences").then(function(e) { _evidences = e || []; }).catch(function() { _evidences = []; }); }

function _syncEvidencesBackground() {
    _evidenceSyncStatus = t("pilot.sync.in_progress");
    return _fetch("/evidences/sync", { method: "POST" }).then(function(res: any) {
        var report = (res && res.report) || {};
        var parts: string[] = [];
        for (var mod in report) {
            var r = report[mod];
            if (r.error) parts.push(t("pilot.sync.module_error", { mod: mod }));
            else if (r.skipped) continue;
            else parts.push(mod + ": " + ((r.added || 0) + (r.updated || 0)));
        }
        _evidenceSyncStatus = t("pilot.sync.last_prefix") + new Date().toLocaleTimeString() + (parts.length ? " (" + parts.join(", ") + ")" : "");
        return _loadEvidences();
    }).catch(function() { _evidenceSyncStatus = t("pilot.sync.error"); });
}

window._syncEvidencesNow = function() {
    _syncEvidencesBackground().then(function() { if (_panel === "evidences") _renderPanel(); });
};

var _EV_STATUS_META: Record<string, { color: string }> = {
    expiree: { color: "var(--ct-critical)" },
    bientot: { color: "#f97316" },
    valide:  { color: "var(--ct-low)" },
    na:      { color: "#94a3b8" },
};

function _renderEvidences(c: HTMLElement) {
    var h = '<div class="ct-flex ct-items-center ct-gap-3 ct-row-wrap"><h2 class="ct-m-0">' + t("pilot.evidences.title") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="_syncEvidencesNow">&#x21bb; ' + t("pilot.action.sync") + '</button></div>';
    if (_evidenceSyncStatus) h += '<div style="font-size:var(--ct-text-label);color:var(--ct-ink-2);margin:var(--ct-s2) 0 var(--ct-s3)">' + esc(_evidenceSyncStatus) + '</div>';

    // Transverse expiration summary — the cross-module alert.
    var counts: Record<string, number> = { expiree: 0, bientot: 0, valide: 0, na: 0 };
    _evidences.forEach(function(e) { var s = e.status || "na"; counts[s] = (counts[s] || 0) + 1; });
    // Tuiles ct-kpi partagées (cohérence dashboard / watch).
    var evTones: Record<string, string> = { expiree: "critical", bientot: "medium", valide: "low", na: "" };
    h += '<div class="ct-kpigrid ct-mb-3">';
    ["expiree", "bientot", "valide", "na"].forEach(function(st) {
        var tone = evTones[st];
        var emphasized = (st === "expiree" && counts[st] > 0) || (st === "bientot" && counts[st] > 0);
        h += '<div class="ct-kpi"' + (tone && emphasized ? ' data-emphasis="value" data-tone="' + tone + '"' : '') + '>'
          + '<div class="ct-kpi-tone"></div><div class="ct-kpi-body">'
          + '<div class="ct-kpi-label">' + esc(t("pilot.evidence.status." + st)) + '</div>'
          + '<div class="ct-kpi-value">' + counts[st] + '</div>'
          + '</div></div>';
    });
    h += '</div>';

    if (!_evidences.length) {
        h += '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.evidences.empty") + '</div>';
        c.innerHTML = h; return;
    }

    // Filtres : module + recherche libre (libellé, entité, responsable,
    // tags, objets liés) — même patron que la page Actions.
    h += '<div class="pilot-actions ct-row-wrap ct-gap-2 ct-mb-2">';
    h += '<input type="text" id="ev-filter-search" placeholder="' + t("pilot.common.search") + '" value="' + esc(_evidenceFilter.search) + '" data-input="_filterEvidences" data-pass-value class="ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta ct-minw-180">';
    h += '<select id="ev-filter-module" data-change="_filterEvidences" data-pass-value class="ct-filter"><option value="">' + t("pilot.filter.all_modules") + '</option>';
    var evMods: Record<string, boolean> = {};
    _evidences.forEach(function(e) { if (e.module) evMods[e.module] = true; });
    Object.keys(evMods).sort().forEach(function(mod) {
        h += '<option value="' + esc(mod) + '"' + (_evidenceFilter.module === mod ? ' selected' : '') + '>' + esc(mod) + '</option>';
    });
    h += '</select></div>';

    var evShown = _evidences.filter(function(e) {
        if (_evidenceFilter.module && e.module !== _evidenceFilter.module) return false;
        var q = (_evidenceFilter.search || "").toLowerCase();
        if (q) {
            var hay = ((e.label || "") + " " + (e.entity_name || "") + " " + (e.owner || "") + " "
                     + (e.tags || []).join(" ") + " "
                     + (e.linked || []).map(function(l: any) { return l.object_id + " " + (l.label || ""); }).join(" ")).toLowerCase();
            if (hay.indexOf(q) < 0) return false;
        }
        return true;
    });
    if (evShown.length !== _evidences.length) {
        h += '<div class="ct-text-label ct-muted ct-mb-2">' + t("pilot.measures.count", { shown: evShown.length, total: _evidences.length }) + '</div>';
    }

    h += '<table class="ct-journal-body ct-collapse ct-text-meta"><thead><tr style="text-align:left;border-bottom:2px solid var(--ct-line)">';
    [t("pilot.col.module"), t("pilot.evidences.col_proof"), t("pilot.col.entity"), t("pilot.col.owner"), t("pilot.col.due_date"), t("pilot.col.status"), t("pilot.evidences.col_linked"), ""].forEach(function(col) { h += '<th class="ct-py-1 ct-px-2">' + col + '</th>'; });
    h += '</tr></thead><tbody>';
    evShown.forEach(function(e) {
        var evStatus = _EV_STATUS_META[e.status] ? e.status : "na";
        var sm = _EV_STATUS_META[evStatus];
        var linked = (e.linked || []).map(function(l: any) { return l.object_id; }).join(", ");
        // Cohérence tableaux : clic ligne = édition ; le lien vers la preuve
        // vit dans la dernière colonne.
        h += '<tr class="ct-clickable ct-border-bottom" data-click="_editEvidence" data-args=\'' + _da(e.module, e.source_id) + '\'>';
        h += '<td class="ct-py-1 ct-px-2"><span class="ct-ref" data-module="' + esc(e.module || "") + '">' + esc(e.module || "") + '</span></td>';
        h += '<td class="ct-py-1 ct-px-2">' + esc(e.label || e.source_id || "") + '</td>';
        h += '<td class="ct-py-1 ct-px-2">' + esc(e.entity_name || "") + '</td>';
        h += '<td class="ct-py-1 ct-px-2">' + esc(e.owner || "") + '</td>';
        h += '<td class="ct-py-1 ct-px-2">' + esc(e.date_expiration || "") + '</td>';
        h += '<td class="ct-py-1 ct-px-2"><span style="color:' + sm.color + ';font-weight:600">' + esc(t("pilot.evidence.status." + evStatus)) + '</span></td>';
        h += '<td class="ct-py-1 ct-px-2 ct-muted">' + esc(linked) + '</td>';
        h += '<td class="ct-py-1 ct-px-2 ct-ta-r">';
        if (e.url) {
            h += '<button class="ct-btn" data-size="xs" data-stop data-click="_openModule" data-args=\'' + _da(e.url) + '\' title="' + esc(e.url) + '">\u2197</button>';
        } else {
            h += '<span class="text-muted">&mdash;</span>';
        }
        h += '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    c.innerHTML = h;
}

window._filterEvidences = function() {
    var s0 = document.getElementById("ev-filter-search") as HTMLInputElement | null;
    var m0 = document.getElementById("ev-filter-module") as HTMLSelectElement | null;
    _evidenceFilter.search = s0 ? s0.value : "";
    _evidenceFilter.module = m0 ? m0.value : "";
    var focus = document.activeElement && (document.activeElement as HTMLElement).id;
    _renderPanel();
    if (focus === "ev-filter-search") {
        var s1 = document.getElementById("ev-filter-search") as HTMLInputElement | null;
        if (s1) { s1.focus(); s1.setSelectionRange(s1.value.length, s1.value.length); }
    }
};

window._editEvidence = function(module: string, sourceId: string) {
    var e = _evidences.find(function(x) { return x.module === module && x.source_id === sourceId; });
    if (!e) return;
    // Modules qui supportent le write-back d'évidence (FEAT-08) — le backend
    // renvoie de toute façon un 400 clair pour les autres.
    if (module !== "compliance" && module !== "vendor") {
        showStatus(t("pilot.evidences.edit_unsupported"), true);
        return;
    }
    var fields = module === "vendor" ? [
        { key: "label", label: t("pilot.evidences.field_label"), type: "text" },
        { key: "date_expiration", label: t("pilot.col.due_date"), type: "date" },
        { key: "url", label: t("pilot.evidences.field_link"), type: "text" }
    ] : [
        { key: "label", label: t("pilot.evidences.field_label"), type: "text" },
        { key: "owner", label: t("pilot.col.owner"), type: "picker" },
        { key: "date_obtention", label: t("pilot.evidences.field_obtained"), type: "date" },
        { key: "date_expiration", label: t("pilot.col.due_date"), type: "date" },
        { key: "url", label: t("pilot.evidences.field_link"), type: "text" },
        { key: "commentaire", label: t("pilot.evidences.field_comment"), type: "textarea" }
    ];
    var body = '<div class="ct-flex ct-col ct-gap-2">';
    fields.forEach(function(f) {
        var v = String(e[f.key] || "");
        body += '<label class="ct-flex ct-col ct-gap-1 ct-text-meta">' + esc(f.label);
        if (f.type === "picker") body += '<div id="ev-owner-slot"></div>';
        else if (f.type === "textarea") body += '<textarea id="ev-' + f.key + '" rows="2" class="ct-w-full">' + esc(v) + '</textarea>';
        else body += '<input type="' + f.type + '" id="ev-' + f.key + '" value="' + esc(v) + '" class="ct-w-full">';
        body += '</label>';
    });
    body += '</div>';
    ct_modal.open({
        title: t("pilot.evidences.edit_title", { name: e.label || sourceId }),
        body: body,
        onOpen: function() {
            if (typeof ct_userpicker === "undefined" || !ct_userpicker.mount) return;
            ct_userpicker.mount({
                slotId: "ev-owner-slot", pickerId: "ev-owner",
                value: String(e.owner || ""), placeholder: t("pilot.common.search"),
                directoryUrl: "api/directory", sourceUrl: null,
            });
        },
        buttons: [
            { id: "cancel", label: t("pilot.action.cancel") },
            { id: "save", primary: true, label: t("pilot.action.save"), result: function() {
                var data: Record<string, any> = {};
                fields.forEach(function(f) {
                    if (f.type === "picker") {
                        data[f.key] = (typeof ct_userpicker !== "undefined" && ct_userpicker.getValue)
                            ? ct_userpicker.getValue("ev-owner") : "";
                        return;
                    }
                    var el = document.getElementById("ev-" + f.key) as HTMLInputElement | HTMLTextAreaElement | null;
                    if (el) data[f.key] = el.value;
                });
                return data;
            } }
        ]
    }).then(function(data: any) {
        if (!data) return;
        _fetch("/evidences/" + encodeURIComponent(module) + "/" + encodeURIComponent(sourceId), {
            method: "PATCH", body: data
        }).then(function() {
            showStatus(t("pilot.evidences.updated"));
            _loadEvidences().then(function() { if (_panel === "evidences") _renderPanel(); });
        }).catch(function(err: any) { showStatus((err && err.message) || t("pilot.common.error"), true); });
    });
};
function _loadUsers() { return _fetch("/users").then(function(u) { _users = u; }).catch(function() { _users = []; }); }
function _loadModules() { return _fetch("/modules").then(function(m) { _modules = m; }); }
function _loadProjects() { return _fetch("/projects").then(function(p) { _projects = p; }).catch(function() { _projects = []; }); }

function _boot() {
    // Fill static [data-i18n] / [data-i18n-html] placeholders (help overlay
    // content lives in translation keys and the divs are empty in the HTML).
    _applyStaticTranslations();
    // First: load modules registry, then sync measures, then load everything
    _loadModules().then(function() {
        return _syncMeasuresBackground();
    }).then(function() {
        return Promise.all([_loadDashboard(), _loadUsers(), _loadProjects()]);
    }).then(function() {
        _renderPanel();
        // Refresh every 5 minutes
        setInterval(function() {
            _syncMeasuresBackground().then(function() {
                return _loadDashboard();
            }).then(function() {
                if (_panel === "dashboard" || _panel === "measures") _renderPanel();
            });
        }, 300000);
    }).catch(function(e) {
        console.error("Boot error:", e);
        _renderPanel();
    });
}


// ═══════════════════════════════════════════════════════════════
// RESTORE — point-in-time exploration & granular restore (FEAT-30 ph.2)
// ═══════════════════════════════════════════════════════════════

var _rstWindow: any = null;
var _rstModule = "";
var _rstSession: any = null;
var _rstPollTimer: number | null = null;
var _rstDiffs: Record<string, any> = {};
var _rstJournal: any[] | null = null;

function _rstRender(c: HTMLElement) {
    if (!_rstWindow) {
        c.innerHTML = '<div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.common.loading") + '</div>';
        _fetch("/restore/window").then(function(d: any) { _rstWindow = d; _rstRender(c); })
            .catch(function(e: any) { c.innerHTML = '<div class="ct-p-5 ct-muted">' + esc(e.message || String(e)) + '</div>'; });
        return;
    }

    var h = '<p class="ct-muted ct-mb-4">' + t("pilot.restore.intro") + '</p>';

    // ── Selector: module + instant ──
    h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<div class="ct-flex ct-gap-3 ct-flex-wrap" style="align-items:flex-end">';
    h += '<div><label class="ct-label">' + t("pilot.col.module") + '</label>'
        + '<select id="restore-module" class="ct-select" data-change="_rstModuleChanged" data-pass-value>';
    Object.keys(_rstWindow).forEach(function(m) {
        var w = _rstWindow[m];
        var dis = !w.from ? ' disabled' : '';
        h += '<option value="' + esc(m) + '"' + (m === _rstModule ? ' selected' : '') + dis + '>'
            + esc(m) + (w.from ? '' : ' (' + t("pilot.restore.no_backup") + ')') + '</option>';
    });
    h += '</select></div>';
    var modSel = _rstModule || Object.keys(_rstWindow)[0];
    var winSel = _rstWindow[modSel] || {};
    var minAttr = "";
    if (winSel.from) {
        // datetime-local wants local "YYYY-MM-DDTHH:MM" — bound to the window start.
        var df = new Date(winSel.from);
        var pl = function(n: number) { return (n < 10 ? "0" : "") + n; };
        minAttr = ' min="' + df.getFullYear() + "-" + pl(df.getMonth() + 1) + "-" + pl(df.getDate())
            + "T" + pl(df.getHours()) + ":" + pl(df.getMinutes()) + '"';
    }
    h += '<div><label class="ct-label">' + t("pilot.restore.instant") + '</label>'
        + '<input type="datetime-local" id="restore-time" class="ct-input" step="1"' + minAttr + '></div>';
    h += '<button class="ct-btn" data-variant="primary" data-click="_rstExplore">' + t("pilot.restore.explore") + '</button>';
    if (_rstSession) {
        h += '<button class="ct-btn" data-click="_rstCloseSession">' + t("pilot.restore.close_session") + '</button>';
    }
    h += '</div>';
    var mod = _rstModule || Object.keys(_rstWindow)[0];
    var win = _rstWindow[mod];
    if (win && win.from) {
        h += '<div class="ct-muted ct-mt-2" data-size="sm">' + t("pilot.restore.window_hint", { from: _rstFmtDT(win.from), to: _rstFmtDT(win.to) }) + '</div>';
    }
    h += '</div>';

    // ── Activité récente du module (journal serveur) : choisir un
    // ÉVÉNEMENT plutôt que deviner une heure ──
    if (_rstJournal === null) {
        _fetch("/restore/journal/" + encodeURIComponent(mod)).then(function(d: any) {
            _rstJournal = d || [];
            if (_panel === "backups" && _bkTab === "restore") _renderPanel();
        }).catch(function() { _rstJournal = []; });
    } else if (_rstJournal.length) {
        h += '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
        h += '<div class="ct-flex ct-gap-2" style="align-items:center;justify-content:space-between">';
        h += '<h3 class="ct-text-data ct-mb-1">' + t("pilot.restore.activity_title") + '</h3>';
        h += '<button class="ct-btn" data-size="xs" data-click="_rstRefreshJournal">' + t("pilot.restore.refresh") + '</button></div>';
        h += '<p class="ct-muted ct-mb-3" data-size="sm">' + t("pilot.restore.activity_hint") + '</p>';
        h += '<table class="ct-table" data-size="sm"><thead><tr><th>' + t("pilot.restore.col_when") + '</th><th>' + t("pilot.restore.col_who") + '</th><th>' + t("pilot.restore.col_action") + '</th><th>' + t("pilot.restore.col_target") + '</th><th></th></tr></thead><tbody>';
        _rstJournal.slice(0, 15).forEach(function(e: any) {
            h += '<tr><td class="ct-nowrap">' + esc(_rstFmtDT(e.logged_at)) + '</td>'
                + '<td>' + esc(e.user_email || "?") + '</td>'
                + '<td><code>' + esc(e.action) + '</code></td>'
                + '<td>' + esc(e.target || e.entity_id || "") + '</td>'
                + '<td class="ct-ta-r"><button class="ct-btn" data-size="xs" data-click="_rstExploreBefore" data-args=\'' + _da(e.logged_at) + '\'>' + t("pilot.restore.explore_before") + '</button></td></tr>';
        });
        h += '</tbody></table></div>';
    }

    // ── Session state ──
    if (_rstSession) {
        var s = _rstSession;
        if (s.status === "preparing") {
            h += '<div class="ct-bordered ct-r-lg ct-p-5 ct-ta-c ct-muted">' + t("pilot.restore.preparing") + '</div>';
        } else if (s.status === "error") {
            h += '<div class="ct-bordered ct-r-lg ct-p-4" data-tone="critical">' + t("pilot.restore.error") + ' : ' + esc(s.error || "?") + '</div>';
        } else if (s.status === "ready") {
            h += _rstObjectsTable(s);
        }
    }
    c.innerHTML = h;
    if (_rstSession && _rstSession.status === "preparing") _rstSchedulePoll();
}

function _rstFmtDT(iso: string | null): string {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleString(); } catch (e) { return String(iso); }
}

function _rstObjectsTable(s: any): string {
    var h = '<div class="ct-bordered ct-r-lg ct-p-4 ct-mb-5">';
    h += '<h3 class="ct-text-data ct-mb-1">' + t("pilot.restore.state_at", { module: esc(s.module || _rstModule), time: s.time ? _rstFmtDT(s.time) : t("pilot.restore.latest") }) + '</h3>';
    h += '<p class="ct-muted ct-mb-3" data-size="sm">' + t("pilot.restore.objects_hint") + '</p>';
    h += '<table class="ct-table"><thead><tr><th>' + t("pilot.restore.col_object") + '</th><th>' + t("pilot.restore.col_status") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_diff") + '</th><th></th></tr></thead><tbody>';
    (s.objects || []).forEach(function(o: any) {
        var badge = "";
        if (o.missing_live) badge = '<span class="ct-badge" data-tone="critical">' + t("pilot.restore.deleted_since") + '</span>';
        else if (o.created_after_t) badge = '<span class="ct-badge" data-tone="info">' + t("pilot.restore.created_after") + '</span>';
        else if (o.suspect) badge = '<span class="ct-badge" data-tone="high">' + t("pilot.restore.modified_since") + '</span>';
        else badge = '<span class="ct-badge" data-tone="low">' + t("pilot.restore.identical") + '</span>';
        h += '<tr><td>' + esc(o.name || o.id) + '</td><td>' + badge + '</td>';
        var d = _rstDiffs[o.id];
        h += '<td class="ct-ta-c">';
        if (o.created_after_t) {
            h += '—';
        } else if (d) {
            h += d.diff.identical ? t("pilot.restore.identical")
                : t("pilot.restore.diff_counts", { removed: _rstSumDiff(d, "removed_since_t"), changed: _rstSumDiff(d, "changed"), added: _rstSumDiff(d, "added_since_t") });
        } else {
            h += '<button class="ct-btn" data-size="xs" data-click="_rstObjDiff" data-args=\'' + _da(o.id) + '\'>' + t("pilot.restore.compute_diff") + '</button>';
        }
        h += '</td><td class="ct-ta-r">';
        if (!o.created_after_t) {
            h += '<button class="ct-btn" data-size="xs" data-variant="primary" data-click="_rstObjApply" data-args=\'' + _da(o.id, o.name || o.id) + '\'>' + t("pilot.restore.restore_object") + '</button>';
        }
        h += '</td></tr>';
        if (d && !d.diff.identical) {
            h += '<tr><td colspan="4" class="ct-muted" data-size="sm"><table class="ct-table" data-size="xs"><thead><tr><th>' + t("pilot.restore.col_collection") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_at_t") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_live") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_removed") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_changed") + '</th><th class="ct-ta-c">' + t("pilot.restore.col_added") + '</th></tr></thead><tbody>';
            (d.diff.collections || []).forEach(function(r: any) {
                h += '<tr><td>' + esc(r.collection) + '</td><td class="ct-ta-c">' + r.at_t + '</td><td class="ct-ta-c">' + r.live + '</td><td class="ct-ta-c">' + (r.removed_since_t || "") + '</td><td class="ct-ta-c">' + (r.changed || "") + '</td><td class="ct-ta-c">' + (r.added_since_t || "") + '</td></tr>';
                var ex = r.examples || {};
                var parts: string[] = [];
                if ((ex.removed || []).length) parts.push(t("pilot.restore.col_removed") + " : " + ex.removed.map(esc).join(", "));
                if ((ex.changed || []).length) parts.push(t("pilot.restore.col_changed") + " : " + ex.changed.map(esc).join(", "));
                if ((ex.added || []).length) parts.push(t("pilot.restore.col_added") + " : " + ex.added.map(esc).join(", "));
                if (parts.length) {
                    h += '<tr><td colspan="6" class="ct-muted" data-size="xs">' + parts.join(" · ") + '</td></tr>';
                }
            });
            h += '</tbody></table>';
            if ((d.journal || []).length) {
                h += '<div class="ct-mt-2 ct-muted" data-size="xs"><strong>' + t("pilot.restore.obj_activity") + '</strong> ';
                h += d.journal.slice(0, 5).map(function(e: any) {
                    return esc(_rstFmtDT(e.logged_at)) + " — " + esc(e.user_email || "?") + " — " + esc(e.action);
                }).join("<br>");
                h += '</div>';
            }
            h += '</td></tr>';
        }
    });
    h += '</tbody></table></div>';

    // ── N2 danger zone ──
    if ((s.module || _rstModule) !== "pilot") {
        h += '<div class="ct-bordered ct-r-lg ct-p-4" data-tone="critical">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("pilot.restore.n2_title") + '</h3>';
        h += '<p class="ct-muted ct-mb-3" data-size="sm">' + t("pilot.restore.n2_warning") + '</p>';
        h += '<button class="ct-btn" data-variant="danger" data-click="_rstPromote">' + t("pilot.restore.n2_button") + '</button>';
        h += '</div>';
    }
    return h;
}

function _rstSumDiff(d: any, key: string): number {
    var n = 0;
    (d.diff.collections || []).forEach(function(r: any) { n += r[key] || 0; });
    return n;
}

function _rstRefreshJournal() {
    _rstJournal = null;
    _renderPanel();
}

function _rstModuleChanged(val: string) {
    _rstModule = val;
    _rstSession = null;
    _rstDiffs = {};
    _rstJournal = null;
    _renderPanel();
}

function _rstExploreBefore(loggedAt: string) {
    var d = new Date(new Date(loggedAt).getTime() - 1000);
    var p2 = function(n: number) { return (n < 10 ? "0" : "") + n; };
    var time = d.getUTCFullYear() + "-" + p2(d.getUTCMonth() + 1) + "-" + p2(d.getUTCDate())
        + " " + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()) + ":" + p2(d.getUTCSeconds()) + "+00";
    var mod = (document.getElementById("restore-module") as HTMLSelectElement).value;
    _rstModule = mod;
    _rstDiffs = {};
    _fetch("/restore/sessions", { method: "POST", body: { module: mod, time: time } }).then(function() {
        _rstSession = { status: "preparing", module: mod, time: time };
        _renderPanel();
    }).catch(function(e: any) { showStatus(e.message || String(e), true); });
}

function _rstExplore() {
    var mod = (document.getElementById("restore-module") as HTMLSelectElement).value;
    var timeRaw = (document.getElementById("restore-time") as HTMLInputElement).value;
    var time: string | null = null;
    if (timeRaw) {
        // pgBackRest target format: "YYYY-MM-DD HH:MM:SS+00" (UTC), no ISO T/Z.
        var d = new Date(timeRaw);
        var p2 = function(n: number) { return (n < 10 ? "0" : "") + n; };
        time = d.getUTCFullYear() + "-" + p2(d.getUTCMonth() + 1) + "-" + p2(d.getUTCDate())
            + " " + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()) + ":" + p2(d.getUTCSeconds()) + "+00";
    }
    _rstModule = mod;
    _rstDiffs = {};
    _fetch("/restore/sessions", { method: "POST", body: { module: mod, time: time } }).then(function() {
        _rstSession = { status: "preparing", module: mod, time: time };
        _renderPanel();
    }).catch(function(e: any) { showStatus(e.message || String(e), true); });
}

function _rstSchedulePoll() {
    if (_rstPollTimer) window.clearTimeout(_rstPollTimer);
    _rstPollTimer = window.setTimeout(function() {
        if (!_rstSession || _panel !== "backups" || _bkTab !== "restore") return;
        _fetch("/restore/sessions/" + encodeURIComponent(_rstModule)).then(function(d: any) {
            _rstSession = d;
            _renderPanel();
        }).catch(function() { _rstSchedulePoll(); });
    }, 3000);
}

function _rstObjDiff(id: string) {
    _fetch("/restore/sessions/" + encodeURIComponent(_rstModule) + "/objects/" + encodeURIComponent(id) + "/diff")
        .then(function(d: any) { _rstDiffs[id] = d; _renderPanel(); })
        .catch(function(e: any) { showStatus(e.message || String(e), true); });
}

function _rstObjApply(id: string, name: string) {
    _confirmDialog(t("pilot.restore.confirm_title", { name: name }),
                   t("pilot.restore.confirm_body"),
                   { yes: t("pilot.restore.confirm_yes"), no: t("btn_cancel") }).then(function(ok) {
        if (!ok) return;
        showStatus(t("pilot.restore.restoring"));
        _fetch("/restore/sessions/" + encodeURIComponent(_rstModule) + "/objects/" + encodeURIComponent(id) + "/restore", { method: "POST", body: {} })
            .then(function() {
                showStatus(t("pilot.restore.restored", { name: name }));
                delete _rstDiffs[id];
                _fetch("/restore/sessions/" + encodeURIComponent(_rstModule)).then(function(d: any) { _rstSession = d; _renderPanel(); });
            })
            .catch(function(e: any) { showStatus(e.message || String(e), true); });
    });
}

function _rstPromote() {
    var mod = _rstModule;
    var typed = window.prompt(t("pilot.restore.n2_prompt", { module: mod }));
    if (typed === null) return;
    if (typed !== mod) { showStatus(t("pilot.restore.n2_mismatch"), true); return; }
    showStatus(t("pilot.restore.restoring"));
    _fetch("/restore/sessions/" + encodeURIComponent(mod) + "/promote", { method: "POST", body: { confirm: typed } })
        .then(function() { showStatus(t("pilot.restore.n2_done", { module: mod })); })
        .catch(function(e: any) { showStatus(e.message || String(e), true); });
}

function _rstCloseSession() {
    _fetch("/restore/sessions/" + encodeURIComponent(_rstModule), { method: "DELETE" })
        .then(function() { _rstSession = null; _rstDiffs = {}; _renderPanel(); })
        .catch(function(e: any) { showStatus(e.message || String(e), true); });
}

(window as any)._rstModuleChanged = _rstModuleChanged;
(window as any)._rstExplore = _rstExplore;
(window as any)._rstExploreBefore = _rstExploreBefore;
(window as any)._rstRefreshJournal = _rstRefreshJournal;
(window as any)._bkSelectTab = _bkSelectTab;
(window as any)._bkFilterChanged = _bkFilterChanged;
(window as any)._rstObjDiff = _rstObjDiff;
(window as any)._rstObjApply = _rstObjApply;
(window as any)._rstPromote = _rstPromote;
(window as any)._rstCloseSession = _rstCloseSession;

_initAuth();

})();
