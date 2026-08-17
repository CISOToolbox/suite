/* AppSec — Application Security Scanner (Surface UX pattern) */
"use strict";

window.CT_CONFIG = {
    edition: "suite",
    module: "appsec",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
};

// ═══════════════════════════════════════════════════════════════
// ICONS (same system as Surface)
// ═══════════════════════════════════════════════════════════════

var _ICON_PATHS: Record<string, string> = {
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>',
    play: '<polygon points="5 3 19 12 5 21 5 3"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    arrow_left: '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    package: '<line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
    cpu: '<rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
};
function _icon(name: string, size?: number, cls?: string): string {
    var p = _ICON_PATHS[name];
    if (!p) { var _sh = (window as any).CT_ICONS; if (_sh) p = _sh[name]; }  // fall back to shared CT_ICONS (globe, moon, sun, settings…)
    if (!p) return "";
    var sz = size || 16; var c = cls ? ' class="' + cls + '"' : '';
    return '<svg' + c + ' width="' + sz + '" height="' + sz + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ct-va-middle ct-no-shrink">' + p + '</svg>';
}

// ═══════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════

var _panel: string = "dashboard";
var _apps: AppSecApp[] = [];
var _findings: AppSecFinding[] = [];
var _scans: AppSecScan[] = [];
var _sbom: AppSecSbomEntry[] = [];
var _stats: AppSecStats = {};
var _selectedFinding: string | null = null;
var _selectedApp: string | null = null;
var _findingsFilter: AppSecFindingsFilter = { app_id: "", severity: "", scanner: "", status: "new", q: "", patch: "" };
var _sbomFilter: AppSecSbomFilter = { app_id: "", ecosystem: "", q: "", vulnerable_only: false };

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

// Le ton passe de la classe à l'attribut : une seule primitive, .ct-badge,
// et une sémantique fermée (critical|high|medium|low|info|neutral|accent) au
// lieu d'une classe par état.
function _sevBadge(sev?: string): string { return badgeTone(t("misc." + sev) || sev, esc(sev || "neutral")); }
// Tons du module : statuts de finding et de scan, scanners, criticite d'appli.
// Une seule table, pour que le meme etat porte le meme ton partout.
var _APPSEC_TONES: Record<string, string> = {
    // statuts de finding
    new: "critical", to_fix: "high", false_positive: "neutral", fixed: "low",
    // statuts de scan
    pending: "info", running: "info", completed: "low", failed: "critical", skipped: "neutral",
    // scanners (identite, pas gravite)
    trivy_fs: "info", trivy_image: "accent", gitleaks: "critical", semgrep: "low",
    // criticite d'application
    low: "low", medium: "medium", high: "high", critical: "critical",
};
function _appsecTone(v?: string | null): string {
    return _APPSEC_TONES[(v || "").toString()] || "neutral";
}
function _statusBadge(s?: string): string { return badgeTone(t("findings.status_" + s) || t("scans.status_" + s) || s, _appsecTone(s)); }
function _scannerLabel(s?: string): string { return t("scanner." + s) || (s as string); }
function _scannerBadge(s?: string): string { return badgeTone(_scannerLabel(s), _appsecTone(s)); }

// Patch-availability badge for a finding. Green when Trivy reports a
// fixed_version, red "Sans patch" for CVE findings without one, neutral
// for non-CVE findings (secrets, SAST).
// Compare deux versions segment par segment, numeriquement : "6.10.3" vient
// apres "6.9.7", ce qu'un tri lexicographique inverserait.
function _cmpVersion(a: string, b: string): number {
    var xs = a.split("."), ys = b.split(".");
    for (var i = 0; i < Math.max(xs.length, ys.length); i++) {
        var x = parseInt(xs[i] || "0", 10), y = parseInt(ys[i] || "0", 10);
        if (isNaN(x)) x = 0;
        if (isNaN(y)) y = 0;
        if (x !== y) return x - y;
    }
    return 0;
}

function _patchBadge(f?: AppSecFinding | null): string {
    if (!f || f.type !== "cve") return '<span class="text-muted">—</span>';
    var fx = (f.evidence && f.evidence.fixed_version) || "";
    if (!fx) {
        return '<span class="ct-badge" data-tone="critical">' + (t("findings.patch_none") || "Sans patch") + '</span>';
    }
    // Un scanner rend la version corrigee de CHAQUE branche maintenue : jusqu'a
    // une vingtaine pour une seule CVE. En faire une chaine unique donnait un
    // pave illisible et volait sa largeur a la colonne Cible. Un badge par
    // version, tries par branche croissante, et un badge de depassement qui
    // porte la liste entiere en infobulle.
    var versions = fx.split(",").map(function(v) { return v.trim(); }).filter(Boolean);
    versions.sort(_cmpVersion);
    if (versions.length === 1) {
        return '<span class="ct-badge" data-tone="low" title="' + esc(versions[0]) + '">&#10003; '
            + esc(versions[0]) + '</span>';
    }
    // Au-dela d'un badge, la coche se repete sans rien ajouter : le ton la porte deja.
    var MAX = 3;
    var html = versions.slice(0, MAX).map(function(v) {
        return '<span class="ct-badge" data-tone="low">' + esc(v) + '</span>';
    }).join("");
    if (versions.length > MAX) {
        html += '<span class="ct-badge" data-tone="neutral" title="' + esc(versions.join(", ")) + '">+'
            + (versions.length - MAX) + '</span>';
    }
    return '<span class="ct-flex ct-row-wrap ct-gap-1">' + html + '</span>';
}

// Measure status badge — distinct colors per state, reused across
// the Plan d'action table and the measure edit modal.
function _measureStatusBadge(statut?: string): string {
    // Un état métier se mappe sur un TON, pas sur un couple de couleurs posé en
    // inline : c'est le seul moyen que la bascule de thème le suive.
    var tones: Record<string, string> = {
        a_faire: "neutral", en_cours: "info", termine: "low", annule: "critical",
    };
    var label = t("measures.status_" + statut) || statut || "";
    return badgeTone(label, tones[statut as string] || "neutral");
}
function _fmtDate(iso?: string | null): string {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    try { return d.toLocaleString("sv-SE", {year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"}); }
    catch(e) { return d.toISOString().substring(0, 16).replace("T", " "); }
}
function _timeAgo(d?: string | null): string {
    if (!d) return t("apps.never") || "—";
    var diff = (Date.now() - new Date(d).getTime()) / 1000;
    if (diff < 60) return Math.floor(diff) + "s";
    if (diff < 3600) return Math.floor(diff / 60) + "min";
    if (diff < 86400) return Math.floor(diff / 3600) + "h";
    return Math.floor(diff / 86400) + "d";
}

// ═══════════════════════════════════════════════════════════════
// ROUTING
// ═══════════════════════════════════════════════════════════════

window.selectPanel = function(id: string) {
    _panel = id;
    _selectedFinding = null;
    _selectedApp = null;
    // Clear bulkbars from other scopes so the bottom bar doesn't linger
    // across panel switches (the bar is attached to document.body, not
    // the content area).
    if (window.ct_bulkbar) {
        ct_bulkbar.clear("appsec-findings");
        ct_bulkbar.clear("appsec-measures");
    }
    document.querySelectorAll(".ct-rail-item, .sidebar-item").forEach(function(el) {
        var args = el.getAttribute("data-args");
        var match = false;
        if (args) try { match = JSON.parse(args)[0] === id; } catch(e) {}
        el.classList.toggle("active", match);
        if (match) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
    });
    document.querySelector(".ct-rail, .sidebar")?.classList.remove("open");
    _loadAndRender();
};

// Re-render du panneau courant, sans re-fetch. Appelé par switchLang() lors de
// la bascule de langue (le shell attend un renderAll global) — sans ça, la
// traduction ne s'appliquait qu'après un rechargement de page.
(window as unknown as { renderAll?: () => void }).renderAll = renderPanel;

function _loadAndRender(): void {
    var p1 = AppSecAPI.listApps().then(function(d) { _apps = d || []; }).catch(function() { _apps = []; });
    var p2 = AppSecAPI.findingsStats().then(function(d) { _stats = d || {}; }).catch(function() { _stats = {}; });
    var p3 = AppSecAPI.listScans().then(function(d) { _scans = d || []; }).catch(function() { _scans = []; });
    Promise.all([p1, p2, p3]).then(function() { renderPanel(); });
}

function renderPanel(): void {
    var c = document.getElementById("content");
    if (!c) return;
    switch (_panel) {
        case "dashboard":    _renderDashboard(c); break;
        case "applications": _selectedFinding ? _renderFindingDetail(c) : (_selectedApp ? _renderAppDetail(c) : _renderApplications(c)); break;
        case "findings":     _selectedFinding ? _renderFindingDetail(c) : _renderFindings(c); break;
        case "sbom":         _renderSBOM(c); break;
        case "scans":        _renderScans(c); break;
        case "measures":     _renderMeasures(c); break;
        case "ignore_rules": _renderIgnoreRules(c); break;
        case "audit":        _renderAuditLog(c); break;
        default:             _renderDashboard(c);
    }
    var tr = document.getElementById("toolbar-right");
    if (tr && typeof _getSettingsButtonHTML === "function" && !tr.querySelector(".toolbar-settings")) {
        var _sh = _getSettingsButtonHTML();
        if (_sh) tr.insertAdjacentHTML("afterbegin", '<span class="toolbar-settings">' + _sh + '</span>');
    }
    if (tr && window.ct_notifprefs && !tr.querySelector(".toolbar-notif")) {
        tr.insertAdjacentHTML("afterbegin",
            '<span class="toolbar-notif"><button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_openNotifPrefs" title="' + t("notif.title") + '">' + _icon("bell", 15) + '</button></span>');
    }
    if (typeof _applyStaticTranslations === "function") _applyStaticTranslations();
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════

function _renderDashboard(c: HTMLElement): void {
    var s = _stats;
    var h = '<h2>' + t("dashboard.title") + '</h2>';
    h += '<div class="ct-kpigrid ct-mb-4">';
    h += '<div class="ct-kpi ct-clickable" data-click="_dashNav" data-args=\'["applications"]\'><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(t("dashboard.total_apps")) + '</div><div class="ct-kpi-value">' + _apps.length + '</div></div></div>';
    // Severity-count tiles carry their tone only when the count is > 0, so a
    // clean dashboard stays neutral instead of a wall of coloured zeros.
    var _nCrit = (s.critical || 0), _nHigh = (s.high || 0), _nMed = (s.medium || 0), _nLow = (s.low || 0);
    h += '<div class="ct-kpi ct-clickable" data-emphasis="value"' + (_nCrit > 0 ? ' data-tone="critical"' : '') + ' data-click="_dashNavSev" data-args=\'["critical"]\'><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(t("dashboard.critical")) + '</div><div class="ct-kpi-value">' + _nCrit + '</div></div></div>';
    h += '<div class="ct-kpi ct-clickable" data-emphasis="value"' + (_nHigh > 0 ? ' data-tone="high"' : '') + ' data-click="_dashNavSev" data-args=\'["high"]\'><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(t("dashboard.high")) + '</div><div class="ct-kpi-value">' + _nHigh + '</div></div></div>';
    h += '<div class="ct-kpi ct-clickable" data-emphasis="value"' + (_nMed > 0 ? ' data-tone="medium"' : '') + ' data-click="_dashNavSev" data-args=\'["medium"]\'><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(t("dashboard.medium")) + '</div><div class="ct-kpi-value">' + _nMed + '</div></div></div>';
    h += '<div class="ct-kpi ct-clickable" data-emphasis="value"' + (_nLow > 0 ? ' data-tone="low"' : '') + ' data-click="_dashNavSev" data-args=\'["low"]\'><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(t("dashboard.low")) + '</div><div class="ct-kpi-value">' + _nLow + '</div></div></div>';
    // Patch availability tile — actionable signal for prioritising remediation.
    if (s.cve_total && s.cve_total > 0) {
        var pct = Math.round(((s.cve_with_patch || 0) / s.cve_total) * 100);
        // Patchable coverage is a health rate: higher is better. Amber under
        // 90%, red under 70% — a low patchable ratio means stuck remediation.
        var _patchTone = _kpiTone(pct, { dir: "up", amber: 90, red: 70 });
        h += '<div class="ct-kpi ct-clickable" data-emphasis="value"' + (_patchTone ? ' data-tone="' + _patchTone + '"' : '') + ' data-click="_dashNavPatch" title="' + esc((s.cve_with_patch || 0) + " / " + s.cve_total + " CVE avec patch éditeur") + '">';
        h += '<div class="ct-kpi-tone"></div><div class="ct-kpi-body">';
        h += '<div class="ct-kpi-label">' + esc(t("dashboard.cve_patchable") || "CVE patchables") + ' <span class="fs-xs text-muted">(' + pct + '%)</span></div>';
        h += '<div class="ct-kpi-value">' + (s.cve_with_patch || 0) + '<span class="ct-text-label ct-muted">/' + s.cve_total + '</span></div>';
        h += '</div></div>';
    }
    h += '</div>';

    // By-app table with per-severity columns, sorted by total desc.
    var appSev = s.by_app_severity || {};
    var appKeys = Object.keys(s.by_app || {});
    if (appKeys.length > 0) {
        // Build rows with severity breakdown, sort by total descending.
        var sevs = ["critical", "high", "medium", "low", "info"];
        var rows = appKeys.map(function(app) {
            var sevData = appSev[app] || {};
            var total = 0;
            sevs.forEach(function(sv) { total += sevData[sv] || 0; });
            return { app: app, total: total, sevs: sevData };
        }).sort(function(a, b) { return b.total - a.total; });

        h += '<h3>' + t("dashboard.by_app") + '</h3>';
        h += '<table class="ct-table"><thead><tr><th>Application</th>';
        sevs.forEach(function(sv) { if (sv !== "info") h += '<th class="ct-ta-c">' + _sevBadge(sv) + '</th>'; });
        h += '<th class="ct-ta-c">Total</th></tr></thead><tbody>';
        rows.forEach(function(r) {
            var appObj = _apps.find(function(a) { return a.name === r.app; });
            var appId = appObj ? appObj.id : "";
            h += '<tr class="ct-clickable" data-click="_openAppFindings" data-args=\'' + _da(appId) + '\'>';
            h += '<td>' + esc(r.app) + '</td>';
            sevs.forEach(function(sv) {
                if (sv === "info") return;
                var n = r.sevs[sv] || 0;
                h += '<td style="text-align:center' + (n > 0 ? ";font-weight:600" : ";color:var(--ct-ink-2)") + '">' + n + '</td>';
            });
            h += '<td class="ct-ta-c ct-bold">' + r.total + '</td></tr>';
        });
        h += '</tbody></table>';
    }

    if (_scans.length > 0) {
        h += '<h3>' + t("dashboard.recent_scans") + '</h3>';
        h += '<table class="ct-table"><thead><tr><th>Application</th><th>' + t("scans.scanner") + '</th><th>' + t("scans.status") + '</th><th>' + t("scans.findings_count") + '</th><th></th></tr></thead><tbody>';
        for (var i = 0; i < Math.min(_scans.length, 10); i++) {
            var j = _scans[i];
            h += '<tr><td>' + esc(j.application_name) + '</td><td>' + _scannerBadge(j.scanner) + '</td>';
            h += '<td>' + _statusBadge(j.status);
            if (j.status === "failed" && j.error) {
                h += ' <span class="fs-xs ct-text-critical" title="' + esc(j.error) + '">&#9888;</span>';
            } else if (j.status === "skipped" && j.error) {
                h += ' <span class="fs-xs text-muted" title="' + esc(j.error) + '">&#9432;</span>';
            }
            h += '</td><td>' + j.findings_count + '</td>';
            h += '<td class="fs-xs text-muted">' + _timeAgo(j.created_at) + '</td></tr>';
        }
        h += '</tbody></table>';
    }
    c.innerHTML = h;
}

// ═══════════════════════════════════════════════════════════════
// APPLICATIONS (cards like Surface hosts)
// ═══════════════════════════════════════════════════════════════

function _renderApplications(c: HTMLElement): void {
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("apps.title") + ' <span class="text-muted fs-sm">(' + _apps.length + ')</span></h2>';
    h += '<span class="ct-flex-1"></span>';
    h += '<button class="ct-btn mt-8" data-write data-click="_scanAllApps">' + _icon("refresh", 14) + ' ' + t("apps.scan_all") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="showAddApp">' + _icon("plus", 14) + ' ' + t("apps.add") + '</button>';
    h += '</div>';

    if (_apps.length === 0) {
        h += '<p class="text-muted">' + t("apps.no_apps") + '</p>';
    } else {
        h += '<div class="app-cards-grid">';
        for (var i = 0; i < _apps.length; i++) {
            var a = _apps[i];
            var hasFindings = a.findings_critical || a.findings_high || a.findings_medium || a.findings_low;
            var scanners = (a.enabled_scanners || []).length;
            h += '<div class="app-card" data-click="_openAppFindings" data-args=\'' + _da(a.id) + '\'>';
            h += '<div class="app-card-top">';
            h += '<div class="app-card-name">' + esc(a.name) + '</div>';
            if (!a.enabled) h += '<span class="ct-badge app-badge" data-tone="neutral">OFF</span>';
            h += '<span class="ct-badge app-badge" data-tone="' + _appsecTone(a.criticality || "medium") + '">' + esc(a.criticality || "medium") + '</span>';
            h += '</div>';
            if (a.description) h += '<div class="app-card-label">' + esc(a.description) + '</div>';
            if (a.repo_url) h += '<div class="app-card-url">' + esc(a.repo_url) + '</div>';
            h += '<div class="app-card-meta">' + t("apps.last_scan") + ': ' + _timeAgo(a.last_scan_at) + '</div>';
            h += '<div class="app-card-findings' + (hasFindings ? '' : ' empty') + '">';
            if (hasFindings) {
                if (a.findings_critical) h += badgeTone(a.findings_critical + ' C', 'critical');
                if (a.findings_high) h += badgeTone(a.findings_high + ' H', 'high');
                if (a.findings_medium) h += badgeTone(a.findings_medium + ' M', 'medium');
                if (a.findings_low) h += badgeTone(a.findings_low + ' L', 'low');
            } else {
                h += t("findings.no_findings");
            }
            h += '</div>';
            h += '<div class="app-card-footer">';
            h += '<span>' + _icon("cpu", 14) + ' ' + scanners + ' scanners</span>';
            h += '<button class="ct-btn" data-variant="primary" data-size="sm" data-click="_triggerScan" data-args=\'' + _da(a.id) + '\' data-stop title="' + t("apps.scan_now") + '" data-icon>' + _icon("play", 14) + '</button>';
            h += '<button class="ct-btn" data-size="sm" data-click="_editAppDialog" data-args=\'' + _da(a.id) + '\' data-stop>' + _icon("edit", 14) + ' ' + t("apps.configure") + '</button>';
            h += '</div>';
            h += '</div>';
        }
        h += '</div>';
    }
    c.innerHTML = h;
}

function _openAppFindings(id: string | number): void {
    _selectedApp = String(id);
    _appDetailFilter = { severity: "", scanner: "", status: "", q: "" };
    _panel = "applications";
    _loadAndRender();
}

window._backToApps = function() { _selectedApp = null; renderPanel(); };

window._dashNav = function(panel: string) { selectPanel(panel); };
window._dashNavSev = function(sev: string) {
    _findingsFilter = { app_id: "", severity: sev, scanner: "", status: "new", q: "", patch: "" };
    selectPanel("findings");
};
window._dashNavPatch = function() {
    // Jump straight to active CVEs that have a vendor patch available —
    // the high-leverage triage list (quick wins).
    _findingsFilter = { app_id: "", severity: "", scanner: "", status: "new", q: "", patch: "available" };
    selectPanel("findings");
};

// ═══════════════════════════════════════════════════════════════
// APPLICATION DETAIL (config + findings + scan button)
// ═══════════════════════════════════════════════════════════════

async function _renderAppDetail(c: HTMLElement): Promise<void> {
    var app: AppSecApp;
    try { app = await AppSecAPI.getApp(_selectedApp); } catch(e: any) { c.innerHTML = '<p class="text-muted">Error: ' + esc(e.message) + '</p>'; return; }

    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="_backToApps">' + _icon("arrow_left", 14) + ' ' + t("findings.back") + '</button>';
    h += '<h2 class="ct-m-0 ct-flex-1">' + esc(app.name) + '</h2>';
    h += '<span class="ct-badge app-badge" data-tone="' + _appsecTone(app.criticality || "medium") + '">' + esc(app.criticality || "medium") + '</span>';
    if (!app.enabled) h += '<span class="ct-badge app-badge" data-tone="neutral">OFF</span>';
    h += '<button class="ct-btn" data-click="_editAppDialog" data-args=\'' + _da(app.id) + '\'>' + _icon("edit", 14) + ' ' + t("apps.configure") + '</button>';
    h += '<button class="ct-btn" data-variant="primary" data-click="_triggerScan" data-args=\'' + _da(app.id) + '\'>' + _icon("play", 14) + ' ' + t("apps.scan_now") + '</button>';
    h += '<button class="ct-btn admin-only" data-variant="danger" data-click="_deleteAppFromDetail" data-args=\'' + _da(app.id) + '\' data-icon>' + _icon("trash", 14) + '</button>';
    h += '</div>';

    // Config summary card
    h += '<div class="ct-bg-canvas ct-bordered ct-r-lg ct-p-3 ct-mb-4">';
    h += '<div style="display:grid;grid-template-columns:120px 1fr;gap:var(--ct-s1) var(--ct-s3);font-size:var(--ct-text-meta)">';
    if (app.repo_url) {
        h += '<span class="appsec-field-lbl ct-m-0">' + t("apps.repo_url") + '</span>';
        h += '<span style="font-family:monospace;word-break:break-all">' + esc(app.repo_url) + ' <span class="text-muted">(' + esc(app.repo_branch) + ')</span></span>';
    }
    if (app.docker_images && app.docker_images.length) {
        h += '<span class="appsec-field-lbl ct-m-0">' + t("apps.docker_images") + '</span>';
        h += '<span class="ct-mono ct-text-data">' + app.docker_images.map(function(i) { return esc(i); }).join('<br>') + '</span>';
    }
    h += '<span class="appsec-field-lbl ct-m-0">' + t("apps.scanners") + '</span>';
    h += '<span>' + (app.enabled_scanners || []).map(function(s) { return _scannerBadge(s); }).join(' ') + '</span>';
    h += '<span class="appsec-field-lbl ct-m-0">' + t("apps.last_scan") + '</span>';
    h += '<span>' + _fmtDate(app.last_scan_at) + '</span>';
    h += '<span class="appsec-field-lbl ct-m-0">' + t("apps.scan_freq") + '</span>';
    h += '<span>' + app.scan_frequency_hours + 'h</span>';
    h += '</div>';

    // Severity summary
    var hasFinding = app.findings_critical || app.findings_high || app.findings_medium || app.findings_low;
    if (hasFinding) {
        h += '<div style="display:flex;gap:var(--ct-s1);margin-top:var(--ct-s2);padding-top:10px;border-top:1px solid var(--ct-line)">';
        if (app.findings_critical) h += badgeTone(app.findings_critical + ' Critical', 'critical');
        if (app.findings_high) h += badgeTone(app.findings_high + ' High', 'high');
        if (app.findings_medium) h += badgeTone(app.findings_medium + ' Medium', 'medium');
        if (app.findings_low) h += badgeTone(app.findings_low + ' Low', 'low');
        h += '</div>';
    }
    h += '</div>';

    // Filter pills (same layout as main findings view)
    h += '<h3>' + t("findings.title") + '</h3>';
    var adf = _appDetailFilter;

    // Severity pills
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_severity") || "Sévérité") + '</span>';
    ["", "critical", "high", "medium", "low", "info"].forEach(function(sev) {
        var label = sev ? t("misc." + sev) : t("findings.all_severities");
        var active = adf.severity === sev ? " active" : "";
        h += '<button class="filter-pill' + active + (sev ? " pill-" + sev : "") + '" data-click="_adSetSev" data-args=\'' + _da(sev) + '\'>' + esc(label) + '</button>';
    });
    h += '</div>';

    // Status pills
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_status") || "Statut") + '</span>';
    [
        { v: "",               l: t("findings.all_statuses") },
        { v: "new",            l: t("findings.status_new") },
        { v: "to_fix",        l: t("findings.status_to_fix") },
        { v: "false_positive", l: t("findings.status_false_positive") },
        { v: "fixed",          l: t("findings.status_fixed") }
    ].forEach(function(o) {
        var on = adf.status === o.v ? " active" : "";
        h += '<button class="filter-pill status-pill-' + (o.v || "all") + on + '" data-click="_adSetStatus" data-args=\'' + _da(o.v) + '\'>' + esc(o.l) + '</button>';
    });
    h += '</div>';

    // Scanner pills
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_scanner") || "Scanner") + '</span>';
    [
        { v: "",             l: t("findings.all_scanners") },
        { v: "trivy_fs",    l: _scannerLabel("trivy_fs") },
        { v: "trivy_image", l: _scannerLabel("trivy_image") },
        { v: "gitleaks",    l: _scannerLabel("gitleaks") },
        { v: "semgrep",     l: _scannerLabel("semgrep") }
    ].forEach(function(o) {
        var scCls = o.v ? " scanner-pill-specific" : "";
        var on = adf.scanner === o.v ? " active" : "";
        h += '<button class="filter-pill scanner-pill' + scCls + on + '" data-click="_adSetScanner" data-args=\'' + _da(o.v) + '\'>' + esc(o.l) + '</button>';
    });
    h += '</div>';

    // Search
    h += '<div class="appsec-filters">';
    h += '<input type="search" class="appsec-filter ct-minw-180" placeholder="' + t("findings.search") + '" value="' + esc(adf.q || "") + '" data-input="_adSetSearch" data-pass-value>';
    h += '</div>';
    h += '<div id="app-detail-findings">' + t("ai.loading") + '</div>';

    c.innerHTML = h;
    _refreshAppDetailFindings();
}

var _appDetailFilter: { severity: string; scanner: string; status: string; q: string } = { severity: "", scanner: "", status: "", q: "" };

// Pill-based filters re-render the full panel so .active updates.
window._adSetSev = function(v: string) { _appDetailFilter.severity = v; renderPanel(); };
window._adSetScanner = function(v: string) { _appDetailFilter.scanner = v; renderPanel(); };
window._adSetStatus = function(v: string) { _appDetailFilter.status = v; renderPanel(); };
// Search only refreshes the table body.
window._adSetSearch = function(v: string) { _appDetailFilter.q = v; _refreshAppDetailFindings(); };

async function _refreshAppDetailFindings(): Promise<void> {
    var el = document.getElementById("app-detail-findings");
    if (!el) return;
    var params: AppSecQueryParams = { app_id: _selectedApp, limit: 300 };
    var adf = _appDetailFilter;
    if (adf.severity) params.severity = adf.severity;
    if (adf.scanner) params.scanner = adf.scanner;
    if (adf.status) params.status = adf.status;
    if (adf.q) params.q = adf.q;
    try {
        var data = await AppSecAPI.listFindings(params);
        var items = data.items || [];
        _lastFindingsItems = items;
        var fh = '';
        if (items.length === 0) {
            fh = '<p class="text-muted">' + t("findings.no_findings") + '</p>';
        } else {
            fh = ct_table.render({
                rows: items,
                rowKey: "id",
                onRowClick: "_openFindingRow",
                rowClass: function(f) { return "finding-row status-" + f.status; },
                bulk: { scope: "appsec-findings" },
                columns: [
                    { key: "severity", label: "", width: "50px",
                      render: function(f) { return _sevBadge(f.severity); } },
                    { key: "title", label: t("findings.col_title") || "Titre",
                      render: function(f) {
                          return esc(_findingTitle(f))
                              + (f.cve_id ? ' <span class="fs-xs text-muted">' + esc(f.cve_id) + '</span>' : '');
                      } },
                    { key: "target", label: t("findings.target"),
                      render: function(f) {
                          return '<span style="font-family:monospace;font-size:var(--ct-text-meta);word-break:break-all">'
                              + esc(f.target || "") + '</span>';
                      } },
                    { key: "scanner", label: "Scanner",
                      render: function(f) { return _scannerBadge(f.scanner); } },
                    { key: "patch", label: t("findings.col_patch") || "Patch", width: "132px",
                      render: function(f) { return _patchBadge(f as AppSecFinding); } },
                    { key: "status", label: "Status",
                      render: function(f) { return _statusBadge(f.status); } },
                    { key: "created_at", label: t("findings.first_seen"),
                      render: function(f) { return '<span class="fs-xs text-muted">' + esc(_fmtDate(f.created_at)) + '</span>'; } }
                ]
            });
            fh += '<p class="fs-xs text-muted">' + data.total + ' findings</p>';
        }
        el.innerHTML = fh;
        _setupFindingsBulkbar();
        ct_bulkbar.update("appsec-findings");
    } catch(e: any) {
        el.innerHTML = '<p class="text-muted">Error: ' + esc(e.message) + '</p>';
    }
}

// ── App modal ────────────────────────────────────────────────

window.showAddApp = function() { _showAppModal(null); };
window._editAppDialog = function(id: string | number) {
    var app = _apps.find(function(a) { return String(a.id) === String(id); });
    if (app) _showAppModal(app);
};

function _closeAppModal(): void { document.getElementById("app-modal-overlay")!.hidden = true; }
window._closeAppModal = _closeAppModal;

window._toggleImageSection = function() {
    var on = (document.getElementById("app-image-enabled") as HTMLInputElement).checked;
    document.getElementById("app-image-fields")!.style.display = on ? "" : "none";
};

function _showAppModal(app: AppSecApp | null): void {
    var isEdit = !!app;
    var overlay = document.getElementById("app-modal-overlay")!;
    var modal = document.getElementById("app-modal")!;

    var enabled = isEdit ? (app!.enabled_scanners || []) : ["trivy_fs", "gitleaks", "semgrep", "trivy_image"];
    var critOptions = ["critical", "high", "medium", "low"];

    var codeScanners = [
        {id: "trivy_fs", label: _scannerLabel("trivy_fs")},
        {id: "gitleaks", label: _scannerLabel("gitleaks")},
        {id: "semgrep", label: _scannerLabel("semgrep")},
    ];
    var imageEnabled = enabled.indexOf("trivy_image") >= 0;

    var h = '<div class="ct-modal-header"><span>' + esc(isEdit ? app!.name : t("apps.add")) + '</span><button class="appsec-modal-close" data-click="_closeAppModal">' + _icon("x", 18) + '</button></div>';
    h += '<div class="ct-modal-body">';

    // ── General ──
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.name") + '</label><input class="ct-input" id="app-name" value="' + esc(isEdit ? app!.name : "") + '"></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.description") + '</label><textarea class="ct-input" id="app-desc" rows="2">' + esc(isEdit ? app!.description : "") + '</textarea></div>';
    h += '<div class="ct-flex ct-gap-3"><div class="ct-field ct-flex-1"><label class="appsec-field-lbl">' + t("apps.criticality") + '</label><select class="ct-input" id="app-crit">';
    critOptions.forEach(function(cv) { h += '<option value="' + cv + '"' + ((isEdit ? app!.criticality : "medium") === cv ? " selected" : "") + '>' + esc(t("misc." + cv) || cv) + '</option>'; });
    h += '</select></div>';
    h += '<div class="ct-field ct-flex-1"><label class="appsec-field-lbl">' + t("apps.scan_freq") + '</label><input type="number" class="ct-input" id="app-freq" value="' + (isEdit ? app!.scan_frequency_hours : 24) + '" min="1"></div></div>';

    // ── Section 1: Code scanning (SAST, SCA, Secrets) ──
    h += '<fieldset class="app-section"><legend>' + _icon("code", 16) + ' ' + t("apps.section_code") + '</legend>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.repo_url") + '</label><input class="ct-input" id="app-repo" value="' + esc(isEdit ? app!.repo_url : "") + '" placeholder="https://github.com/org/repo.git"></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.repo_branch") + '</label><input class="ct-input" id="app-branch" value="' + esc(isEdit ? app!.repo_branch : "main") + '"></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.repo_token") + '</label><input type="password" class="ct-input" id="app-token" placeholder="' + (isEdit && app!.has_token ? "••••••••" : "ghp_...") + '"><div class="appsec-field-help">' + t("apps.token_hint") + '</div></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.scan_paths") + '</label><textarea class="ct-input" id="app-scan-paths" rows="2" placeholder="backend-clients/demo-docker/risk&#10;shared">' + esc(isEdit && app!.scan_paths ? app!.scan_paths.join("\n") : "") + '</textarea><div class="appsec-field-help">' + t("apps.scan_paths_hint") + '</div></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.scanners") + '</label>';
    codeScanners.forEach(function(s) {
        h += '<label class="scanner-check"><input type="checkbox" value="' + s.id + '"' + (enabled.indexOf(s.id) >= 0 ? " checked" : "") + '>' + esc(s.label) + '</label>';
    });
    h += '</div></fieldset>';

    // ── Section 2: Image scanning ──
    h += '<fieldset class="app-section"><legend>' + _icon("package", 16) + ' ' + t("apps.section_images") + '</legend>';
    h += '<div class="ct-field"><label class="scanner-check"><input type="checkbox" id="app-image-enabled" value="trivy_image"' + (imageEnabled ? " checked" : "") + ' data-change="_toggleImageSection"> ' + t("apps.image_scan_enabled") + '</label></div>';
    h += '<div id="app-image-fields" style="' + (imageEnabled ? "" : "display:none") + '">';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.docker_images") + '</label><textarea class="ct-input" id="app-images" rows="3" placeholder="ghcr.io/org/image:tag&#10;registry.example.com/app:latest">' + esc(isEdit && app!.docker_images ? app!.docker_images.join("\n") : "") + '</textarea><div class="appsec-field-help">' + t("apps.docker_images_hint") + '</div></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.image_token") + '</label><input type="password" class="ct-input" id="app-image-token" placeholder="' + (isEdit && app!.has_image_token ? "••••••••" : "ghp_...") + '"><div class="appsec-field-help">' + t("apps.image_token_hint") + '</div></div>';
    h += '</div></fieldset>';

    // ── Section 3: Notifications (FEAT-35) ──
    h += '<fieldset class="app-section"><legend>' + _icon("bell", 16) + ' ' + t("apps.section_notifications") + '</legend>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.notification_emails") + '</label>'
       + '<textarea class="ct-input" id="app-notif-emails" rows="3" placeholder="secu@example.com&#10;dev-team@example.com">'
       + esc(isEdit && app!.notification_emails ? app!.notification_emails.join("\n") : "")
       + '</textarea><div class="appsec-field-help">' + t("apps.notification_emails_hint") + '</div></div>';
    h += '<div class="ct-field"><label class="appsec-field-lbl">' + t("apps.notification_lang") + '</label><select class="ct-input" id="app-notif-lang">'
       + '<option value="en"' + ((isEdit ? (app!.notification_lang || "en") : "en") === "en" ? " selected" : "") + '>English</option>'
       + '<option value="fr"' + ((isEdit ? app!.notification_lang : "") === "fr" ? " selected" : "") + '>Français</option>'
       + '</select><div class="appsec-field-help">' + t("apps.notification_lang_hint") + '</div></div>';
    h += '</fieldset>';

    h += '</div>';

    h += '<div class="ct-modal-footer">';
    if (isEdit) {
        h += '<button class="ct-btn admin-only" data-variant="danger" data-click="_deleteApp" data-args=\'' + _da(app!.id) + '\' style="margin-right:auto">' + _icon("trash", 14) + ' ' + t("apps.delete") + '</button>';
        h += '<button class="ct-btn" data-click="_triggerScan" data-args=\'' + _da(app!.id) + '\'>' + _icon("play", 14) + ' ' + t("apps.scan_now") + '</button>';
    }
    h += '<button class="ct-btn" data-click="_closeAppModal">' + t("apps.cancel") + '</button>';
    h += '<button class="ct-btn" data-variant="primary" data-click="_saveApp" data-args=\'' + _da(isEdit ? app!.id : "") + '\'>' + _icon("check", 14) + ' ' + t("apps.save") + '</button>';
    h += '</div>';

    modal.innerHTML = h;
    overlay.hidden = false;
    var _mdTarget: EventTarget | null = null;
    overlay.onmousedown = function(e) { _mdTarget = e.target; };
    overlay.onclick = function(e) { if (e.target === overlay && _mdTarget === overlay) _closeAppModal(); };
}

window._saveApp = async function(appId: string | number) {
    var scanners: string[] = [];
    document.querySelectorAll<HTMLInputElement>("#app-modal .scanner-check input:checked").forEach(function(el) { scanners.push(el.value); });
    var imageEnabled = (document.getElementById("app-image-enabled") as HTMLInputElement).checked;
    if (imageEnabled) scanners.push("trivy_image");
    var data: AppSecAppPayload = {
        name: (document.getElementById("app-name") as HTMLInputElement).value.trim(),
        description: (document.getElementById("app-desc") as HTMLTextAreaElement).value.trim(),
        repo_url: (document.getElementById("app-repo") as HTMLInputElement).value.trim(),
        repo_branch: (document.getElementById("app-branch") as HTMLInputElement).value.trim() || "main",
        scan_paths: (document.getElementById("app-scan-paths") as HTMLTextAreaElement).value.split("\n").map(function(s){return s.trim().replace(/^\/+|\/+$/g,"");}).filter(Boolean),
        docker_images: imageEnabled ? (document.getElementById("app-images") as HTMLTextAreaElement).value.split("\n").map(function(s){return s.trim();}).filter(Boolean) : [],
        scan_frequency_hours: parseInt((document.getElementById("app-freq") as HTMLInputElement).value) || 24,
        criticality: (document.getElementById("app-crit") as HTMLSelectElement).value,
        enabled_scanners: scanners,
        notification_emails: (document.getElementById("app-notif-emails") as HTMLTextAreaElement).value.split("\n").map(function(s){return s.trim();}).filter(Boolean),
        notification_lang: (document.getElementById("app-notif-lang") as HTMLSelectElement).value,
    };
    var token = (document.getElementById("app-token") as HTMLInputElement).value.trim();
    if (token) {
        if (token.includes("/") || token.includes(" ") || token.includes(":")) {
            showStatus(t("apps.token_invalid")); return;
        }
        data.repo_token = token;
    }
    var imgToken = (document.getElementById("app-image-token") as HTMLInputElement).value.trim();
    if (imgToken) {
        if (imgToken.includes("/") || imgToken.includes(" ") || imgToken.includes(":")) {
            showStatus(t("apps.token_invalid")); return;
        }
        data.image_token = imgToken;
    }
    if (!data.name) return;
    if (data.scan_paths.some(function(p){ return p.indexOf("..") !== -1; })) {
        showStatus(t("apps.scan_paths_invalid")); return;
    }
    try {
        if (appId) await AppSecAPI.updateApp(appId, data); else await AppSecAPI.createApp(data);
        _closeAppModal();
        _loadAndRender();
        showStatus(t("settings.saved"));
    } catch (e: any) { showStatus("Error: " + e.message); }
};

window._deleteAppFromDetail = async function(id: string | number) {
    if (!confirm(t("apps.delete_confirm"))) return;
    try { await AppSecAPI.deleteApp(id); _selectedApp = null; _loadAndRender(); showStatus(t("apps.deleted")); }
    catch (e: any) { showStatus("Error: " + e.message); }
};

window._deleteApp = async function(id: string | number) {
    if (!confirm(t("apps.delete_confirm"))) return;
    try { await AppSecAPI.deleteApp(id); _closeAppModal(); _loadAndRender(); showStatus(t("apps.deleted")); }
    catch (e: any) { showStatus("Error: " + e.message); }
};

window._triggerScan = async function(id: string | number) {
    try { await AppSecAPI.triggerScan(id); showStatus(t("apps.scan_triggered")); }
    catch (e: any) { showStatus("Error: " + e.message); }
};

window._scanAllApps = async function() {
    var count = 0;
    for (var i = 0; i < _apps.length; i++) {
        if (_apps[i].enabled) {
            try { await AppSecAPI.triggerScan(_apps[i].id); count++; } catch(e) {}
        }
    }
    showStatus(t("apps.scan_all_triggered", {n: count}));
};

// ═══════════════════════════════════════════════════════════════
// FINDINGS LIST
// ═══════════════════════════════════════════════════════════════

function _renderFindings(c: HTMLElement): void {
    var f = _findingsFilter;
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("findings.title") + '</h2><span class="ct-flex-1"></span>';
    h += '</div>';

    // Filter pills — severity (with label for consistency with Surface)
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_severity") || "Sévérité") + '</span>';
    ["", "critical", "high", "medium", "low", "info"].forEach(function(sev) {
        var label = sev ? t("misc." + sev) : t("findings.all_severities");
        var active = f.severity === sev ? " active" : "";
        h += '<button class="filter-pill' + active + (sev ? " pill-" + sev : "") + '" data-click="_setFSev" data-args=\'' + _da(sev) + '\'>' + esc(label) + '</button>';
    });
    h += '</div>';

    // Status pills ("Tous" first)
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_status") || "Statut") + '</span>';
    [
        { v: "",               l: t("findings.all_statuses") },
        { v: "new",            l: t("findings.status_new") },
        { v: "to_fix",        l: t("findings.status_to_fix") },
        { v: "false_positive", l: t("findings.status_false_positive") },
        { v: "fixed",          l: t("findings.status_fixed") }
    ].forEach(function(o) {
        var on = f.status === o.v ? " active" : "";
        h += '<button class="filter-pill status-pill-' + (o.v || "all") + on + '" data-click="_setFStatus" data-args=\'' + _da(o.v) + '\'>' + esc(o.l) + '</button>';
    });
    h += '</div>';

    // Scanner pills ("Tous" first)
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_scanner") || "Scanner") + '</span>';
    [
        { v: "",             l: t("findings.all_scanners") },
        { v: "trivy_fs",    l: _scannerLabel("trivy_fs") },
        { v: "trivy_image", l: _scannerLabel("trivy_image") },
        { v: "gitleaks",    l: _scannerLabel("gitleaks") },
        { v: "semgrep",     l: _scannerLabel("semgrep") }
    ].forEach(function(o) {
        var on = f.scanner === o.v ? " active" : "";
        var scCls = o.v ? " scanner-pill-specific" : "";
        h += '<button class="filter-pill scanner-pill' + scCls + on + '" data-click="_setFScanner" data-args=\'' + _da(o.v) + '\'>' + esc(o.l) + '</button>';
    });
    h += '</div>';

    // Patch pills
    h += '<div class="filter-pills-row filter-pills-sm">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter_patch") || "Patch") + '</span>';
    [
        { v: "",            l: t("findings.all_patches") || "Tous" },
        { v: "available",   l: t("findings.patch_available") || "Avec patch" },
        { v: "unavailable", l: t("findings.patch_unavailable") || "Sans patch" }
    ].forEach(function(o) {
        var on = f.patch === o.v ? " active" : "";
        var cls = o.v === "available" ? " patch-pill-yes" : (o.v === "unavailable" ? " patch-pill-no" : "");
        h += '<button class="filter-pill' + cls + on + '" data-click="_setFPatch" data-args=\'' + _da(o.v) + '\'>' + esc(o.l) + '</button>';
    });
    h += '</div>';

    // App + Search row
    h += '<div class="appsec-filters">';
    h += '<select class="appsec-filter" data-change="_setFApp" data-pass-value><option value="">' + t("findings.all_apps") + '</option>';
    _apps.forEach(function(a) { h += '<option value="' + a.id + '"' + (f.app_id === String(a.id) ? " selected" : "") + '>' + esc(a.name) + '</option>'; });
    h += '</select>';
    h += '<input type="search" class="appsec-filter ct-minw-200" placeholder="' + t("findings.search") + '" value="' + esc(f.q || "") + '" data-input="_setFSearch" data-pass-value>';
    h += '</div>';

    c.innerHTML = h + '<div id="findings-body">' + t("ai.loading") + '</div>';
    _refreshFindingsBody();
}

async function _refreshFindingsBody(): Promise<void> {
    var el = document.getElementById("findings-body");
    if (!el) return;
    try {
        var params: AppSecQueryParams = Object.assign({ limit: 10000 }, _findingsFilter);
        var data = await AppSecAPI.listFindings(params);
        var items = data.items || [];
        _lastFindingsItems = items;
        var h = '';
        if (items.length === 0) {
            h = '<p class="text-muted">' + t("findings.no_findings") + '</p>';
        } else {
            h = ct_table.render({
                rows: items,
                rowKey: "id",
                onRowClick: "_openFindingRow",
                rowClass: function(f) { return "finding-row status-" + f.status; },
                bulk: { scope: "appsec-findings" },
                columns: [
                    { key: "severity", label: "", width: "50px",
                      render: function(f) { return _sevBadge(f.severity); } },
                    { key: "title", label: t("findings.col_title") || "Titre",
                      render: function(f) {
                          return esc(_findingTitle(f))
                              + (f.cve_id ? ' <span class="fs-xs text-muted">' + esc(f.cve_id) + '</span>' : '');
                      } },
                    { key: "target", label: t("findings.target"),
                      render: function(f) {
                          return '<span style="font-family:monospace;font-size:var(--ct-text-meta);word-break:break-all">'
                              + esc(f.target || "") + '</span>';
                      } },
                    { key: "application_name", label: "App",
                      render: function(f) { return esc(f.application_name || ""); } },
                    { key: "scanner", label: "Scanner",
                      render: function(f) { return _scannerBadge(f.scanner); } },
                    { key: "patch", label: t("findings.col_patch") || "Patch", width: "132px",
                      render: function(f) { return _patchBadge(f as AppSecFinding); } },
                    { key: "status", label: "Status",
                      render: function(f) { return _statusBadge(f.status); } }
                ]
            });
            h += '<p class="fs-xs text-muted">' + data.total + ' ' + t("findings.title").toLowerCase() + '</p>';
        }
        el.innerHTML = h;
        _setupFindingsBulkbar();
        // Replay current ct_bulkbar selection (in case of refresh during
        // active multi-select) — selection state is kept in ct_bulkbar
        // across table re-renders.
        ct_bulkbar.update("appsec-findings");
    } catch (e: any) { el.innerHTML = '<p class="text-muted">Error: ' + esc(e.message) + '</p>'; }
}

var _lastFindingsItems: AppSecFinding[] = [];

// Wrapper: ct_table passes the full row object to onRowClick; we only
// need the id for the existing _openFinding.
window._openFindingRow = function(row: any) { if (row && row.id) window._openFinding(row.id); };

function _refreshCurrentFindings(): void {
    if (_selectedApp && document.getElementById("app-detail-findings")) _refreshAppDetailFindings();
    else _refreshFindingsBody();
}

// Resolve an i18n key but fall back to a literal when t() returns the
// key verbatim (no translation registered).
function _i18n(key: string, fallback: string): string {
    var v = t(key);
    return (v && v !== key) ? v : fallback;
}

function _setupFindingsBulkbar(): void {
    ct_bulkbar.attach({
        scope: "appsec-findings",
        label: _i18n("findings.selected_n", "{n} finding(s) sélectionné(s)"),
        actions: [
            { id: "to_fix", icon: "check", label: t("findings.status_to_fix") || "À corriger",
              variant: "primary", onClick: "_bulkAppsecFindingsToFix" },
            { id: "fixed", icon: "check", label: t("findings.status_fixed") || "Corrigé",
              variant: "success", onClick: "_bulkAppsecFindingsFixed" },
            { id: "fp", icon: "x", label: t("findings.status_false_positive") || "Faux positif",
              variant: "muted", onClick: "_bulkAppsecFindingsFP" }
        ]
    });
}

function _bulkAppsecSetStatus(scope: string, status: string): void {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    AppSecAPI.bulkTriageFindings({ ids: ids, status: status }).then(function(r) {
        var msg = r.updated + " finding(s) → " + (t("findings.status_" + status) || status);
        if (r.measures_created) msg += " (1 remédiation créée)";
        showStatus(msg);
        ct_bulkbar.clear(scope);
        _refreshCurrentFindings();
    }).catch(function(e) { showStatus("Error: " + e.message); });
}

// "À corriger" on N findings → opens ct_measure_modal to capture the
// corrective measure fields (one measure covering all selected findings
// via Measure.finding_ids JSONB). Submit sends measure_* + ids to the
// bulk-triage endpoint which creates ONE Measure.
window._bulkAppsecFindingsToFix = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var selected = (_lastFindingsItems || []).filter(function(f) { return ids.indexOf(f.id) >= 0; });
    var defaultTitle = selected.length === 1
        ? _findingTitle(selected[0])
        : "Mesure corrective (" + ids.length + " findings)";
    var defaultDesc = selected.map(function(f) {
        return "- " + _findingTitle(f);
    }).join("\n");

    // Preview of covered findings injected as read-only HTML inside the modal
    var summary = '<div class="ct-text-label ct-muted ct-strong ct-mt-1">'
                + esc("Findings couverts") + ' (' + ids.length + ')</div>'
                + '<div class="ct-maxh-150 ct-scroll-y ct-bordered ct-r-md ct-p-2">'
                + selected.map(function(f) {
                      return '<div class="ct-py-1 ct-px-0">' + _sevBadge(f.severity) + ' '
                           + esc(_findingTitle(f).substring(0, 80)) + '</div>';
                  }).join("")
                + '</div>';

    ct_measure_modal.open({ title: defaultTitle, description: defaultDesc }, {
        title: "Créer une remédiation",
        saveLabel: "Créer la remédiation",
        hideFields: ["type", "statut"],
        ownerPicker: { pickerId: "appsec-bulk-owner", directoryUrl: "api/directory" },
        extraContent: summary
    }).then(function(data) {
        if (!data || data.__deleted) return;
        AppSecAPI.bulkTriageFindings({
            ids: ids,
            status: "to_fix",
            measure_title: data.title,
            measure_description: data.description,
            responsable: data.responsable,
            echeance: data.echeance
        }).then(function(r) {
            var msg = r.updated + " finding(s) → À corriger";
            if (r.measures_created) msg += " (1 remédiation créée)";
            showStatus(msg);
            ct_bulkbar.clear(scope);
            _refreshCurrentFindings();
        }).catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
    });
};

window._bulkAppsecFindingsFixed = function(scope: string) { _bulkAppsecSetStatus(scope, "fixed"); };
window._bulkAppsecFindingsFP = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var selected = (_lastFindingsItems || []).filter(function(f) { return ids.indexOf(f.id) >= 0; });

    // Justification modal — triage_notes is mandatory so the audit trail
    // explains WHY findings were dismissed as false positives.
    var h = '';
    h += '<p style="font-size:var(--ct-text-meta);color:var(--ct-ink-2);margin:0 0 var(--ct-s3)">'
       + esc(ids.length + " finding(s) seront marqués comme faux positifs.")
       + '</p>';
    h += '<label class="fs-sm ct-strong ct-block ct-mb-1">'
       + (t("findings.fp_bulk_label") || "Justification (obligatoire)")
       + ' <span class="ct-text-critical">*</span></label>';
    h += '<textarea id="fp-bulk-reason" rows="4" class="ct-journal-body ct-py-1 ct-px-2 ct-text-meta ct-bordered ct-r-sm ct-box" placeholder="'
       + esc(t("findings.fp_bulk_placeholder") || "Pourquoi ces findings sont-ils des faux positifs ?")
       + '"></textarea>';

    ct_modal.open({
        title: (t("findings.fp_bulk_title") || "Marquer en faux positif") + " (" + ids.length + ")",
        body: h,
        size: "md",
        buttons: [
            { id: "cancel", label: t("btn_cancel") || "Annuler" },
            { id: "save", primary: true, label: t("btn_confirm") || t("btn_save") || "Confirmer",
              result: function() {
                  var reason = ((document.getElementById("fp-bulk-reason") as HTMLTextAreaElement).value || "").trim();
                  if (!reason) {
                      showStatus(t("findings.fp_bulk_required") || "La justification est obligatoire", true);
                      return false;
                  }
                  return { triage_notes: reason };
              } }
        ]
    }).then(function(data: any) {
        if (!data) return;
        AppSecAPI.bulkTriageFindings({
            ids: ids,
            status: "false_positive",
            triage_notes: data.triage_notes
        }).then(function(r) {
            showStatus(r.updated + " finding(s) → " + (t("findings.status_false_positive") || "Faux positif"));
            ct_bulkbar.clear(scope);
            _refreshCurrentFindings();
            // Offer to create an ignore rule from the first finding as template.
            // The justification is reused as the default rule reason so the
            // operator doesn't have to retype it.
            if (selected.length > 0) {
                _offerIgnoreRuleFromFinding(selected[0], data.triage_notes);
            }
        }).catch(function(e) { showStatus("Error: " + e.message); });
    });
};

// Pill-based filters re-render the full panel so the .active class updates.
window._setFSev = function(v: string) { _findingsFilter.severity = v; renderPanel(); };
window._setFScanner = function(v: string) { _findingsFilter.scanner = v; renderPanel(); };
window._setFStatus = function(v: string) { _findingsFilter.status = v; renderPanel(); };
// Dropdown/input filters only need to refresh the table body.
window._setFApp = function(v: string) { _findingsFilter.app_id = v; _refreshFindingsBody(); };
window._setFSearch = function(v: string) { _findingsFilter.q = v; _refreshFindingsBody(); };
window._setFPatch = function(v: string) { _findingsFilter.patch = v; renderPanel(); };

// ═══════════════════════════════════════════════════════════════
// FINDING DETAIL (inline in content, like Surface)
// ═══════════════════════════════════════════════════════════════

window._openFinding = function(id: string) { _selectedFinding = id; renderPanel(); };
window._backToFindings = function() { _selectedFinding = null; renderPanel(); };

async function _renderFindingDetail(c: HTMLElement): Promise<void> {
    c.innerHTML = '<p class="text-muted">' + t("ai.loading") + '</p>';
    var f: AppSecFinding;
    try { f = await AppSecAPI.getFinding(_selectedFinding); } catch(e: any) { c.innerHTML = '<p class="text-muted">Error: ' + esc(e.message) + '</p>'; return; }

    // Build the module-specific subheader shown just under the title:
    // scanner badge + application name + first/last seen timestamps.
    var subheader = '<div class="ct-flex ct-gap-1 ct-items-center ct-row-wrap ct-mb-4">'
        + _scannerBadge(f.scanner)
        + (f.application_name ? '<span class="fs-sm text-muted">' + esc(f.application_name) + '</span>' : '')
        + '<span class="fs-xs text-muted ct-ml-auto">'
        +   esc(t("findings.first_seen")) + ' ' + esc(_fmtDate(f.created_at))
        +   ' · ' + esc(t("findings.last_seen")) + ' ' + esc(_fmtDate(f.last_seen_at))
        + '</span></div>';

    // Look up the linked measure if any (optional — frontend state is
    // populated by the measures panel; empty when that panel was never
    // visited, which is fine).
    var linked: AppSecMeasure | null = null;
    if (f.measure_id && Array.isArray(_appsecMeasures)) {
        linked = _appsecMeasures.find(function(x) { return x.id === f.measure_id; }) || null;
    }

    // _selectedFindingObj holds the full finding so the triage/delete
    // handlers can read its id without a second round-trip.
    _selectedFindingObj = f;

    // For CVE findings, surface the vendor patch info prominently so
    // operators don't have to parse raw evidence JSON.
    var extraRows: CtFvInfoRow[] = [];
    if (f.type === "cve") {
        var fx = (f.evidence && f.evidence.fixed_version) || "";
        if (fx) {
            extraRows.push({
                label: t("findings.patch_available") || "Patch disponible",
                valueHtml: '<span class="ct-badge" data-tone="low">&#10003; ' + esc(fx) + '</span>',
            });
        } else {
            extraRows.push({
                label: t("findings.patch_status") || "Patch éditeur",
                valueHtml: '<span class="ct-badge" data-tone="critical">' + (t("findings.patch_none") || "Aucun patch disponible") + '</span>',
            });
        }
        var inst = (f.evidence && f.evidence.installed_version) || "";
        if (inst) {
            extraRows.push({
                label: t("findings.installed_version") || "Version installée",
                value: inst,
            });
        }
    }

    var fd = Object.assign({}, f, { title: _findingTitle(f), description: _findingDesc(f) });
    c.innerHTML = ct_finding_view.render(fd, {
        backHandler: "_backToFindings",
        subheaderHtml: subheader,
        triageHandler: "_appsecTriageDetail",
        aiEnabled: !!(window._aiIsEnabled && window._aiIsEnabled()),
        aiHandler: "_aiTriageFinding",
        deleteHandler: "_deleteAppsecFinding",
        // null → undefined : CtFvRenderOpts.linkedMeasure n'admet pas null (même sémantique falsy).
        linkedMeasure: linked || undefined,
        infoRows: extraRows,
        // Share surface-card styling — appsec-card was never defined in
        // CSS so rows rendered without background/border. Using the same
        // class as Surface keeps the two views visually consistent.
        cardClass: "surface-card"
    });
}

var _selectedFindingObj: AppSecFinding | null = null;

function _runAppsecTriage(finding: AppSecFinding, status: string): Promise<void> {
    return ct_finding_view.openTriageModal(finding, status, {
        ownerPickerId: "appsec-triage-owner",
        directoryUrl: "api/directory"
    }).then(function(payload) {
        if (!payload) return;
        var body: Record<string, unknown> = { status: payload.status };
        if (payload.triage_notes != null) body.triage_notes = payload.triage_notes;
        if (payload.measure_title != null) body.measure_title = payload.measure_title;
        if (payload.measure_description != null) body.measure_description = payload.measure_description;
        if (payload.responsable != null) body.responsable = payload.responsable;
        if (payload.echeance != null) body.echeance = payload.echeance;
        return AppSecAPI.triageFinding(finding.id, body).then(function() {
            showStatus(t("settings.saved") || "Enregistré");
            // For false_positive: offer to create an ignore rule.
            if (payload.status === "false_positive") {
                _offerIgnoreRuleFromFinding(finding, payload.triage_notes || payload.notes || "");
            } else {
                _backToFindings();
            }
        }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
    });
}

/**
 * After a false_positive triage, ask the user if they want to create
 * an ignore rule so the same finding won't come back on future scans.
 * If yes, open the ignore rule modal pre-filled from the finding.
 */
function _offerIgnoreRuleFromFinding(finding: AppSecFinding, reason: string): void {
    // Les ignore rules sont admin-only côté backend (POST /ignore-rules →
    // require_admin) : ne pas proposer la création à un triager, il finirait
    // sur un 403.
    if (!document.body.classList.contains("role-admin")) { _backToFindings(); return; }
    ct_modal.confirm({
        title: t("ignore.offer_title") || "Créer une règle d'exclusion ?",
        message: (t("ignore.offer_body") || "Ce finding a été déclaré faux positif. Souhaitez-vous créer une règle pour ignorer automatiquement les findings similaires lors des prochains scans ?"),
        confirmLabel: t("ignore.offer_yes") || "Créer la règle",
        cancelLabel: t("ignore.offer_no") || "Non merci",
    }).then(function(yes) {
        if (!yes) { _backToFindings(); return; }
        _openIgnoreRuleFromFinding(finding, reason);
    });
}

function _openIgnoreRuleFromFinding(finding: AppSecFinding, reason: string): void {
    if (!window.ct_modal) { _backToFindings(); return; }
    _irCriteriaCount = 0;

    // Pre-fill criteria based on the finding's data.
    var prefill: AppSecIgnoreCriterion[] = [];
    if (finding.cve_id) {
        prefill.push({ type: "cve_id", value: finding.cve_id });
    }
    var ev = finding.evidence || {};
    if (ev.package) {
        prefill.push({ type: "package", value: ev.package + (ev.installed_version ? "@" + ev.installed_version : "") });
    }
    if (ev.rule_id || ev.rule) {
        var scanner = finding.scanner || "";
        var ruleId = ev.rule_id || ev.rule || "";
        prefill.push({ type: "scanner_rule", value: scanner + ":" + ruleId });
    }
    if (finding.target && !finding.cve_id && !ev.package) {
        prefill.push({ type: "target_pattern", value: finding.target });
    }
    // Ensure at least one criterion.
    if (prefill.length === 0) {
        prefill.push({ type: "cve_id", value: "" });
    }

    // Build app list with current finding's app pre-checked.
    var appId = finding.application_id ? String(finding.application_id) : "";

    var h = '<div class="ct-grid ct-gap-3">';
    h += _irAppScopeHTML(appId ? [appId] : []);

    // Criteria — pre-filled
    h += '<div><label class="fs-sm ct-strong">' + t("ignore.col_criteria") + ' <span class="ct-text-critical">*</span></label>';
    h += '<div id="ir-criteria-container" class="ct-mt-1">';
    prefill.forEach(function(p, idx) {
        _irCriteriaCount = idx + 1;
        h += '<div class="ir-crit-row" id="ir-crit-' + idx + '">';
        h += '<div style="flex:0 0 160px"><select id="ir-type-' + idx + '" class="ct-select">';
        ["cve_id", "package", "scanner_rule", "target_pattern", "severity", "ecosystem"].forEach(function(o) {
            h += '<option value="' + o + '"' + (o === p.type ? " selected" : "") + '>' + esc(t("ignore.type." + o) || o) + '</option>';
        });
        h += '</select></div>';
        h += '<input type="text" id="ir-val-' + idx + '" value="' + esc(p.value) + '" class="ct-flex-1 ct-p-1 ct-text-meta ct-bordered ct-r-sm">';
        h += '<button type="button" class="ct-bg-none ct-no-border ct-clickable ct-text-critical ct-text-section ct-py-1 ct-px-1" data-click="_irRemoveCrit" data-args=\'' + _da(idx) + '\'>&#10005;</button>';
        h += '</div>';
    });
    h += '</div>';
    h += '<button type="button" class="ct-btn ct-mt-1 admin-only" data-write data-variant="primary" data-size="xs" data-click="_irAddCrit">'
       + '+ ' + t("ignore.add_criterion") + '</button>';
    h += '</div>';

    // Reason — pre-filled
    h += '<div><label class="fs-sm ct-strong">' + t("ignore.col_reason") + ' <span class="ct-text-critical">*</span></label>';
    h += '<textarea id="ir-reason" class="ct-journal-body ct-py-1 ct-px-2 ct-text-meta ct-bordered ct-r-sm ct-box" rows="2">' + esc(reason) + '</textarea>';
    h += '</div></div>';

    ct_modal.open({
        title: t("ignore.add"),
        body: h, size: "lg",
        buttons: [
            { id: "cancel", label: t("btn_cancel") },
            { id: "save", primary: true, label: t("btn_save"),
              result: function() {
                  var reasonVal = ((document.getElementById("ir-reason") as HTMLTextAreaElement).value || "").trim();
                  if (!reasonVal) { showStatus(t("ignore.err_required"), true); return false; }
                  var appIds: string[] = [];
                  var _irAll = document.getElementById("ir-all-apps") as HTMLInputElement | null;
                  if (!_irAll || !_irAll.checked) {
                      document.querySelectorAll<HTMLInputElement>(".ir-app-cb:checked").forEach(function(cb) { appIds.push(cb.value); });
                  }
                  var criteria: AppSecIgnoreCriterion[] = [];
                  for (var i = 0; i < _irCriteriaCount; i++) {
                      var typeEl = document.getElementById("ir-type-" + i) as HTMLSelectElement | null;
                      var valEl = document.getElementById("ir-val-" + i) as HTMLInputElement | null;
                      if (!typeEl || !valEl) continue;
                      var v = (valEl.value || "").trim();
                      if (v) criteria.push({ type: typeEl.value, value: v });
                  }
                  if (criteria.length === 0) { showStatus(t("ignore.err_no_criteria"), true); return false; }
                  return { application_ids: appIds, criteria: criteria, reason: reasonVal };
              } }
        ]
    }).then(function(data) {
        if (!data) { _backToFindings(); return; }
        AppSecAPI._fetch("/ignore-rules", { method: "POST", body: data }).then(function() {
            showStatus(t("ignore.created"));
            _backToFindings();
        }).catch(function(e) { showStatus(e.message, true); _backToFindings(); });
    });
}

window._appsecTriageDetail = function(status: string) {
    if (!_selectedFindingObj) return;
    _runAppsecTriage(_selectedFindingObj, status);
};

window._deleteAppsecFinding = function() {
    if (!_selectedFindingObj) return;
    var f = _selectedFindingObj;
    ct_modal.confirm({
        title: t("fd.delete") || "Supprimer",
        message: t("fd.delete_confirm") || "Supprimer ce finding ? Cette action est irréversible.",
        danger: true
    }).then(function(ok) {
        if (!ok) return;
        // AppSec doesn't expose a dedicated DELETE /findings/{id} yet;
        // falling back to a triage to "fixed" is the nearest semantic.
        // TODO: add DELETE /api/findings/{id} backend route.
        AppSecAPI.triageFinding(f.id, { status: "fixed" }).then(function() {
            showStatus(t("fd.deleted") || "Finding marqué corrigé");
            _backToFindings();
        }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
    });
};

// First click: show the analysis form (optional analyst context + optional
// deep source-code analysis when the finding references a file). The actual
// call happens in _aiTriageRun so the analyst can add context first.
window._aiTriageFinding = function() {
    if (!_selectedFinding) return;
    var el = document.getElementById("ai-triage-result");
    if (!el) return;
    el.style.display = "block";
    var ev: any = (_selectedFindingObj && (_selectedFindingObj as any).evidence) || {};
    var hasFile = !!(ev && ev.file);
    var h = '<div class="appsec-ai-form">';
    h += '<h4>' + _icon("cpu", 16) + ' ' + esc(t("ai.triage_title")) + '</h4>';
    h += '<label class="appsec-field-lbl" for="appsec-ai-context">' + esc(t("ai.context_label")) + '</label>';
    h += '<textarea id="appsec-ai-context" rows="3" class="ct-journal-body ct-box ct-mt-1" placeholder="' + esc(t("ai.context_ph")) + '"></textarea>';
    if (hasFile) {
        h += '<label class="ct-flex ct-items-center ct-gap-1 ct-mt-2 ct-clickable">';
        h += '<input type="checkbox" id="appsec-ai-deep"><span class="fs-sm">' + esc(t("ai.deep_label")) + '</span></label>';
        h += '<p class="fs-sm text-muted" style="margin:var(--ct-s1) 0 0 var(--ct-s5)">' + esc(t("ai.deep_hint")) + '</p>';
    }
    h += '<div class="ct-mt-2"><button class="ct-btn btn-ai" data-click="_aiTriageRun">&#10024; ' + esc(t("ai.run")) + '</button></div>';
    h += '</div>';
    el.innerHTML = h;
};

// Endpoint métier : le prompt méthodologique + l'enrichissement NVD sont
// construits côté serveur (POST /api/ai/appsec/analyze-finding) à partir du
// finding chargé par id — même origine, donc la CSP stricte est satisfaite.
// La langue, le contexte analyste et l'option d'analyse approfondie (pull du
// fichier au commit scanné) sont transmis au backend.
window._aiTriageRun = async function() {
    if (!_selectedFinding) return;
    var el = document.getElementById("ai-triage-result");
    if (!el) return;
    var ctxEl = document.getElementById("appsec-ai-context") as HTMLTextAreaElement | null;
    var deepEl = document.getElementById("appsec-ai-deep") as HTMLInputElement | null;
    var opts: AppSecAnalyzeOpts = {
        lang: localStorage.getItem("ct_lang") || "fr",
        context: ctxEl ? ctxEl.value : "",
        deep: !!(deepEl && deepEl.checked),
    };
    el.innerHTML = '<p class="text-muted">' + t("ai.loading") + '</p>';
    try {
        var result: AppSecAiAnalysis = await AppSecAPI.analyzeFinding(_selectedFinding, opts);
        var rh = '<div class="appsec-ai-result">';
        rh += '<h4>' + _icon("cpu", 16) + ' ' + esc(t("ai.triage_title")) + '</h4>';
        var fpColor = result.is_probable_false_positive ? "var(--ct-high-ink)" : "var(--ct-low-ink)";
        var fpLabel = result.is_probable_false_positive ? t("ai.fp_true") : t("ai.fp_false");
        rh += '<p><span style="color:' + fpColor + ';font-weight:700">' + esc(fpLabel) + '</span> <span class="fs-sm text-muted">(' + esc(result.confidence || "") + ')</span>';
        if (result.severity_recommendation) rh += ' ' + _sevBadge(result.severity_recommendation);
        rh += '</p>';
        var note = result.deep_note ? t("ai.deepnote." + result.deep_note) : "";
        if (result.deep_used)
            rh += '<p class="fs-sm ct-text-accent-ink">' + esc(t("ai.deep_used")) + (note ? ' — ' + esc(note) : '') + '</p>';
        else if (opts.deep && note)
            rh += '<p class="fs-sm text-muted">' + esc(t("ai.deep_skipped")) + ' ' + esc(note) + '</p>';
        if (result.summary) rh += '<p class="fs-sm">' + esc(result.summary) + '</p>';
        if (result.remediation) rh += '<div class="ct-field"><span class="appsec-field-lbl">' + esc(t("ai.remediation")) + '</span><p class="fs-sm">' + esc(result.remediation) + '</p></div>';
        if (result.references && result.references.length > 0) {
            rh += '<div class="ct-field"><span class="appsec-field-lbl">' + esc(t("ai.references")) + '</span><ul class="fs-sm">';
            result.references.forEach(function(r: string) { rh += '<li>' + esc(r) + '</li>'; });
            rh += '</ul></div>';
        }
        rh += '</div>';
        el.innerHTML = rh;
    } catch (e: any) { el.innerHTML = '<div class="ai-error">' + esc(t("ai.error", {msg: e.message})) + '</div>'; }
};

// ═══════════════════════════════════════════════════════════════
// SBOM
// ═══════════════════════════════════════════════════════════════

var _sbomEcosystems: string[] = [];  // populated from API response

function _renderSBOM(c: HTMLElement): void {
    var f = _sbomFilter;
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("sbom.title") + '</h2><span class="ct-flex-1"></span>';
    h += '<a href="api/sbom/export?format=csv' + (f.app_id ? '&app_id=' + f.app_id : '') + '" class="ct-btn mt-8 ct-no-underline" data-write data-variant="primary">' + _icon("package", 14) + ' ' + t("sbom.export_csv") + '</a>';
    h += '</div>';

    h += '<div class="appsec-filters">';
    // App filter
    h += '<select class="appsec-filter" data-change="_setSApp" data-pass-value><option value="">' + t("findings.all_apps") + '</option>';
    _apps.forEach(function(a) { h += '<option value="' + a.id + '"' + (f.app_id === String(a.id) ? " selected" : "") + '>' + esc(a.name) + '</option>'; });
    h += '</select>';
    // Dynamic ecosystem filter (populated from API response)
    h += '<select class="appsec-filter" id="sbom-eco-select" data-change="_setSEco" data-pass-value><option value="">' + t("sbom.all_ecosystems") + '</option>';
    _sbomEcosystems.forEach(function(e) { h += '<option value="' + esc(e) + '"' + (f.ecosystem === e ? " selected" : "") + '>' + esc(e) + '</option>'; });
    h += '</select>';
    // Vulnerable only toggle
    h += '<label class="appsec-filter ct-inline-flex ct-items-center ct-gap-1 ct-clickable ct-text-meta">';
    h += '<input type="checkbox" id="sbom-vuln-only"' + (f.vulnerable_only ? ' checked' : '') + ' data-change="_setSVuln" data-pass-el>';
    h += ' ' + t("sbom.vulnerable_only") + '</label>';
    // Search
    h += '<input type="search" class="appsec-filter ct-minw-200" placeholder="' + t("sbom.search") + '" value="' + esc(f.q || "") + '" data-input="_setSSearch" data-pass-value>';
    h += '</div>';

    c.innerHTML = h + '<div id="sbom-body">' + t("ai.loading") + '</div>';
    _refreshSBOMBody();
}

async function _refreshSBOMBody(): Promise<void> {
    var el = document.getElementById("sbom-body");
    if (!el) return;
    try {
        var params: AppSecQueryParams = Object.assign({}, _sbomFilter);
        if (params.vulnerable_only) params.vulnerable_only = true;
        else delete params.vulnerable_only;
        var data = await AppSecAPI.listSBOM(params);
        var items = data.items || [];

        // Update ecosystem dropdown dynamically from the API response.
        if (data.ecosystems && data.ecosystems.length) {
            _sbomEcosystems = data.ecosystems;
            var ecoSel = document.getElementById("sbom-eco-select");
            if (ecoSel) {
                var ecoH = '<option value="">' + t("sbom.all_ecosystems") + '</option>';
                _sbomEcosystems.forEach(function(e) {
                    ecoH += '<option value="' + esc(e) + '"' + (_sbomFilter.ecosystem === e ? " selected" : "") + '>' + esc(e) + '</option>';
                });
                ecoSel.innerHTML = ecoH;
            }
        }

        var h = '';
        if (items.length === 0) {
            h = '<p class="text-muted">' + t("sbom.no_entries") + '</p>';
        } else {
            h = '<table class="ct-table"><thead><tr>';
            h += '<th>' + t("sbom.package") + '</th><th>' + t("sbom.version") + '</th>';
            h += '<th>' + t("sbom.ecosystem") + '</th><th>' + t("sbom.parent") + '</th>';
            h += '<th>' + t("sbom.license") + '</th><th>App</th><th>CVE</th>';
            h += '</tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {
                var e = items[i];
                h += '<tr><td><strong>' + esc(e.package_name) + '</strong>';
                if (!e.direct) h += ' <span class="fs-xs text-muted">(' + t("sbom.transitive") + ')</span>';
                h += '</td><td>' + esc(e.version) + '</td><td>' + esc(e.ecosystem) + '</td><td class="fs-sm">';
                if (e.parent_packages && e.parent_packages.length > 0) {
                    e.parent_packages.forEach(function(p, pi) {
                        var pName = p.split("@")[0] || p;
                        if (pi > 0) h += ', ';
                        h += '<a href="#" class="sbom-parent-link" data-click="_sbomFilterByPkg" data-args=\'' + _da(pName) + '\' data-stop>' + esc(p) + '</a>';
                    });
                } else { h += '<span class="text-muted">—</span>'; }
                h += '</td><td class="fs-sm">' + esc(e.license) + '</td>';
                h += '<td class="fs-sm">';
                if (e.application_names && e.application_names.length > 1) {
                    e.application_names.forEach(function(n, ni) {
                        if (ni > 0) h += ' ';
                        h += '<span style="display:inline-block;padding:var(--ct-s1) var(--ct-s1);border-radius:var(--ct-r-lg);background:var(--ct-info-tint);color:var(--ct-accent-ink);font-size:var(--ct-text-label)">' + esc(n) + '</span>';
                    });
                } else {
                    h += esc(e.application_name || "");
                }
                h += '</td>';
                h += '<td>';
                if (e.cve_details && e.cve_details.length > 0) {
                    e.cve_details.forEach(function(cv, ci) {
                        if (ci > 0) h += ' ';
                        var active = (cv.status === "new" || cv.status === "to_fix");
                        var tone = active ? "high" : "low";
                        var style = "text-decoration:none;font-size:0.75em" + (active ? "" : ";opacity:0.6");
                        h += '<a href="https://nvd.nist.gov/vuln/detail/' + esc(cv.id) + '" target="_blank" rel="noopener" class="ct-badge" data-tone="' + tone + '" style="' + style + '" title="' + esc(cv.id + " (" + cv.status + ")") + '">' + esc(cv.id) + '</a>';
                    });
                } else if (e.cve_ids && e.cve_ids.length > 0) {
                    e.cve_ids.forEach(function(cve, ci) {
                        if (ci > 0) h += ' ';
                        h += '<a href="https://nvd.nist.gov/vuln/detail/' + esc(cve) + '" target="_blank" rel="noopener" class="ct-badge ct-no-underline ct-text-label" data-tone="high" title="' + esc(cve) + '">' + esc(cve) + '</a>';
                    });
                }
                h += '</td></tr>';
            }
            h += '</tbody></table>';
            h += '<p class="fs-xs text-muted">' + data.total + ' packages</p>';
        }
        el.innerHTML = h;
    } catch (err: any) { el.innerHTML = '<p class="text-muted">Error: ' + esc(err.message) + '</p>'; }
}

window._setSApp = function(v: string) { _sbomFilter.app_id = v; _refreshSBOMBody(); };
window._setSEco = function(v: string) { _sbomFilter.ecosystem = v; _refreshSBOMBody(); };
window._setSSearch = function(v: string) { _sbomFilter.q = v; _refreshSBOMBody(); };
window._setSVuln = function(el: HTMLInputElement) { _sbomFilter.vulnerable_only = !!el.checked; _refreshSBOMBody(); };
window._sbomFilterByPkg = function(pkg: string) { _sbomFilter.q = pkg; _renderSBOM(document.getElementById("content")!); };

// ═══════════════════════════════════════════════════════════════
// SCANS
// ═══════════════════════════════════════════════════════════════

function _renderScans(c: HTMLElement): void {
    var isAdmin = !!(window._currentUser && window._currentUser.role === "admin");
    var h = '<h2>' + t("scans.title") + '</h2>';
    if (_scans.length === 0) {
        h += '<p class="text-muted">No scans yet</p>';
    } else {
        h += '<table class="ct-table"><thead><tr><th>Application</th><th>' + t("scans.scanner") + '</th><th>' + t("scans.status") + '</th><th>' + t("scans.findings_count") + '</th><th>' + t("scans.triggered_by") + '</th><th>Date</th><th>Error</th>';
        if (isAdmin) h += '<th></th>';
        h += '</tr></thead><tbody>';
        for (var i = 0; i < _scans.length; i++) {
            var s = _scans[i];
            h += '<tr><td>' + esc(s.application_name) + '</td><td>' + _scannerBadge(s.scanner) + '</td>';
            h += '<td>' + _statusBadge(s.status) + '</td><td>' + s.findings_count + '</td>';
            h += '<td class="fs-sm">' + esc(s.triggered_by) + '</td>';
            h += '<td class="fs-xs text-muted">' + _fmtDate(s.created_at) + '</td>';
            var msgColor = s.status === "failed" ? "var(--ct-critical)" : "var(--ct-ink-2)";
            h += '<td class="fs-xs" style="color:' + msgColor + ';max-width:200px;overflow:hidden;text-overflow:ellipsis" title="' + esc(s.error || "") + '">' + esc(s.error || "") + '</td>';
            if (isAdmin) {
                if (s.status === "running" || s.status === "pending") {
                    h += '<td><button class="ct-btn ct-text-critical ct-text-meta" data-variant="ghost" data-size="sm" data-click="_resetStuckScans" data-args=\'' + _da(s.application_id, s.application_name) + '\' title="' + esc(t("scans.reset_stuck_tip")) + '">' + esc(t("scans.reset_stuck")) + '</button></td>';
                } else {
                    h += '<td></td>';
                }
            }
            h += '</tr>';
        }
        h += '</tbody></table>';
    }
    c.innerHTML = h;
}

window._resetStuckScans = async function(appId: string | number, appName: string) {
    if (!confirm(t("scans.reset_confirm").replace("{name}", appName))) return;
    try {
        var res = await AppSecAPI.resetStuckScans(appId);
        showStatus(t("scans.reset_done").replace("{count}", String(res.reset_count || 0)));
        _loadAndRender();
    } catch (err: any) {
        showStatus("Error: " + (err.message || err));
    }
};

// ═══════════════════════════════════════════════════════════════
// IGNORE RULES (admin-only)
// ═══════════════════════════════════════════════════════════════

var _ignoreRules: AppSecIgnoreRule[] | null = null;
var _irCriteriaCount = 0; // counter for dynamic criteria rows in the modal

async function _renderIgnoreRules(c: HTMLElement): Promise<void> {
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("ignore.title") + '</h2><span class="ct-flex-1"></span>';
    h += '<button class="ct-btn mt-8 admin-only" data-write data-variant="primary" data-click="_addIgnoreRule">' + t("ignore.add") + '</button>';
    h += '</div>';
    h += '<p class="fs-sm text-muted ct-mb-3">' + t("ignore.help") + '</p>';
    h += '<div id="ignore-body"><p class="text-muted">' + t("ai.loading") + '</p></div>';
    c.innerHTML = h;
    _refreshIgnoreRules();
}

async function _refreshIgnoreRules(): Promise<void> {
    var el = document.getElementById("ignore-body");
    if (!el) return;
    try {
        _ignoreRules = await AppSecAPI._fetch("/ignore-rules");
        var rules = _ignoreRules || [];
        if (rules.length === 0) {
            el.innerHTML = '<p class="text-muted">' + t("ignore.empty") + '</p>';
            return;
        }
        var h = '<table class="ct-table ct-text-meta"><thead><tr>';
        h += '<th>' + t("ignore.col_criteria") + '</th>';
        h += '<th>' + t("ignore.col_scope") + '</th>';
        h += '<th>' + t("ignore.col_reason") + '</th>';
        h += '<th>' + t("ignore.col_by") + '</th>';
        h += '<th></th></tr></thead><tbody>';
        for (var i = 0; i < rules.length; i++) {
            var r = rules[i];
            // Criteria display: "CVE ID = CVE-* AND Severity = low"
            var critParts = (r.criteria || []).map(function(c) {
                return '<code class="ct-text-label">' + esc(t("ignore.type." + c.type) || c.type)
                     + '</code> = <code>' + esc(c.value) + '</code>';
            });
            var critHtml = critParts.join(' <span class="ct-text-critical ct-bold ct-text-label">AND</span> ');
            // Scope display
            var scope = (r.application_names && r.application_names.length)
                ? r.application_names.map(function(n) { return esc(n); }).join(', ')
                : t("ignore.all_apps");
            h += '<tr' + (!r.enabled ? ' style="opacity:0.5"' : '') + '>';
            h += '<td>' + critHtml + '</td>';
            h += '<td class="fs-sm">' + scope + '</td>';
            h += '<td class="fs-sm ct-maxw-200 ct-overflow-hidden ct-ellipsis" title="' + esc(r.reason) + '">' + esc(r.reason) + '</td>';
            h += '<td class="fs-xs text-muted">' + esc(r.created_by) + '</td>';
            h += '<td class="ct-ta-r ct-nowrap">';
            h += '<button class="filter-pill admin-only' + (r.enabled ? " active" : "") + '" style="font-size:var(--ct-text-label);padding:var(--ct-s1) var(--ct-s2);margin-right:var(--ct-s1)" data-click="_toggleIgnoreRule" data-args=\'' + _da(r.id, !r.enabled) + '\'>' + (r.enabled ? "ON" : "OFF") + '</button>';
            h += '<button class="ct-btn admin-only" data-size="xs" data-click="_editIgnoreRule" data-args=\'' + _da(r.id) + '\' title="' + esc(t("ignore.edit")) + '" data-icon>' + _icon("edit", 14) + '</button>';
            h += '<button class="ct-btn admin-only" data-size="xs" data-click="_deleteIgnoreRule" data-args=\'' + _da(r.id) + '\' title="' + esc(t("apps.delete")) + '" data-icon>' + _icon("trash", 14) + '</button>';
            h += '</td></tr>';
        }
        h += '</tbody></table>';
        el.innerHTML = h;
    } catch (e: any) {
        el.innerHTML = '<p class="ct-text-critical">' + esc(e.message) + '</p>';
    }
}

function _irTypeSelect(idx: number): string {
    var opts = ["cve_id", "package", "scanner_rule", "target_pattern", "severity", "ecosystem"];
    var h = '<select id="ir-type-' + idx + '" class="ct-select">';
    opts.forEach(function(o) { h += '<option value="' + o + '">' + esc(t("ignore.type." + o) || o) + '</option>'; });
    return h + '</select>';
}

function _irCriterionRow(idx: number): string {
    return '<div class="ir-crit-row" id="ir-crit-' + idx + '">'
        + '<div style="flex:0 0 160px">' + _irTypeSelect(idx) + '</div>'
        + '<input type="text" id="ir-val-' + idx + '" placeholder="CVE-2024-*, openssl*, test/*..." class="ct-flex-1 ct-p-1 ct-text-meta ct-bordered ct-r-sm">'
        + '<button type="button" class="ct-bg-none ct-no-border ct-clickable ct-text-critical ct-text-section ct-py-1 ct-px-1" data-click="_irRemoveCrit" data-args=\'' + _da(idx) + '\' title="Supprimer">&#10005;</button>'
        + '</div>';
}

function _irAppScopeHTML(selectedIds: string[]): string {
    var allChecked = !selectedIds || selectedIds.length === 0;
    var h = '<div><label class="fs-sm ct-strong">' + t("ignore.col_scope") + '</label>';
    h += '<div class="ct-mt-1">';
    h += '<label class="ct-block ct-text-meta ct-py-1 ct-px-1 ct-clickable ct-strong ct-border-bottom ct-mb-1">'
       + '<input type="checkbox" id="ir-all-apps"' + (allChecked ? " checked" : "") + ' data-change="_irToggleAllApps" style="margin-right:var(--ct-s1)">'
       + t("ignore.all_apps") + '</label>';
    h += '<input type="text" id="ir-app-search" placeholder="' + t("ignore.search_apps") + '" class="ct-w-full ct-py-1 ct-px-2 ct-text-meta ct-bordered ct-r-sm ct-mb-1" data-input="_irFilterApps" data-pass-value>';
    h += '<div id="ir-app-list" style="max-height:120px;overflow-y:auto;border:1px solid var(--ct-line);border-radius:4px;padding:4px;' + (allChecked ? "opacity:0.4;pointer-events:none" : "") + '">';
    _apps.forEach(function(a) {
        var checked = !allChecked && selectedIds.indexOf(String(a.id)) >= 0 ? " checked" : "";
        h += '<label class="ct-block ct-text-meta ct-p-1 ct-clickable">'
           + '<input type="checkbox" class="ir-app-cb" value="' + a.id + '"' + checked + '>'
           + esc(a.name) + '</label>';
    });
    h += '</div></div></div>';
    return h;
}

window._irToggleAllApps = function() {
    var allChecked = (document.getElementById("ir-all-apps") as HTMLInputElement).checked;
    var list = document.getElementById("ir-app-list")!;
    if (allChecked) {
        list.style.opacity = "0.4";
        list.style.pointerEvents = "none";
        document.querySelectorAll<HTMLInputElement>(".ir-app-cb").forEach(function(cb) { cb.checked = false; });
    } else {
        list.style.opacity = "";
        list.style.pointerEvents = "";
    }
};

window._addIgnoreRule = function() {
    if (!window.ct_modal) return;
    _irCriteriaCount = 1;

    var h = '<div class="ct-grid ct-gap-3">';
    h += _irAppScopeHTML([]);

    // Criteria — dynamic rows (AND)
    h += '<div>';
    h += '<label class="fs-sm ct-strong">' + (t("ignore.col_criteria") || "Critères") + ' <span class="ct-text-critical">*</span></label>';
    h += '<div id="ir-criteria-container" class="ct-mt-1">';
    h += _irCriterionRow(0);
    h += '</div>';
    h += '<button type="button" class="ct-btn ct-mt-1 admin-only" data-write data-variant="primary" data-size="xs" data-click="_irAddCrit">'
       + '+ ' + (t("ignore.add_criterion") || "Ajouter un critère (AND)") + '</button>';
    h += '</div>';

    // Reason
    h += '<div>';
    h += '<label class="fs-sm ct-strong">' + t("ignore.col_reason") + ' <span class="ct-text-critical">*</span></label>';
    h += '<textarea id="ir-reason" class="ct-journal-body ct-py-1 ct-px-2 ct-text-meta ct-bordered ct-r-sm ct-box" rows="2" placeholder="' + (t("ignore.reason_placeholder") || "Faux positif confirmé / Risque accepté / Non applicable...") + '"></textarea>';
    h += '</div>';

    h += '</div>';

    ct_modal.open({
        title: t("ignore.add"),
        body: h, size: "lg",
        buttons: [
            { id: "cancel", label: t("btn_cancel") },
            { id: "save", primary: true, label: t("btn_save"),
              result: function() {
                  var reason = ((document.getElementById("ir-reason") as HTMLTextAreaElement).value || "").trim();
                  if (!reason) { showStatus(t("ignore.err_required"), true); return false; }
                  // Collect selected apps (empty = all, including future apps)
                  var appIds: string[] = [];
                  var allApps = document.getElementById("ir-all-apps") as HTMLInputElement | null;
                  if (!allApps || !allApps.checked) {
                      document.querySelectorAll<HTMLInputElement>(".ir-app-cb:checked").forEach(function(cb) { appIds.push(cb.value); });
                  }
                  // Collect criteria
                  var criteria: AppSecIgnoreCriterion[] = [];
                  for (var i = 0; i < _irCriteriaCount; i++) {
                      var typeEl = document.getElementById("ir-type-" + i) as HTMLSelectElement | null;
                      var valEl = document.getElementById("ir-val-" + i) as HTMLInputElement | null;
                      if (!typeEl || !valEl) continue;
                      var v = (valEl.value || "").trim();
                      if (v) criteria.push({ type: typeEl.value, value: v });
                  }
                  if (criteria.length === 0) { showStatus(t("ignore.err_no_criteria") || "Au moins un critère requis", true); return false; }
                  return { application_ids: appIds, criteria: criteria, reason: reason };
              } }
        ]
    }).then(function(data) {
        if (!data) return;
        AppSecAPI._fetch("/ignore-rules", { method: "POST", body: data }).then(function(resp) {
            var msg = t("ignore.created");
            if (resp && resp.retroactive_count) msg += " (" + resp.retroactive_count + " finding(s) auto-triés)";
            showStatus(msg);
            _refreshIgnoreRules();
        }).catch(function(e) { showStatus(e.message, true); });
    });
};

window._irAddCrit = function() {
    var container = document.getElementById("ir-criteria-container");
    if (!container) return;
    container.insertAdjacentHTML("beforeend", _irCriterionRow(_irCriteriaCount));
    _irCriteriaCount++;
};

window._irRemoveCrit = function(idx: number) {
    var row = document.getElementById("ir-crit-" + idx);
    if (row) row.remove();
};

window._irFilterApps = function(q: string) {
    q = (q || "").toLowerCase();
    document.querySelectorAll<HTMLLabelElement>("#ir-app-list label").forEach(function(lbl) {
        lbl.style.display = !q || lbl.textContent!.toLowerCase().indexOf(q) >= 0 ? "" : "none";
    });
};

window._editIgnoreRule = function(ruleId: string) {
    if (!window.ct_modal || !_ignoreRules) return;
    var rule = _ignoreRules.find(function(r) { return r.id === ruleId; });
    if (!rule) return;

    var existingCriteria = rule.criteria || [];
    var existingAppIds = rule.application_ids || [];
    _irCriteriaCount = Math.max(existingCriteria.length, 1);

    var h = '<div class="ct-grid ct-gap-3">';
    h += _irAppScopeHTML(existingAppIds);

    // Criteria
    h += '<div><label class="fs-sm ct-strong">' + t("ignore.col_criteria") + ' <span class="ct-text-critical">*</span></label>';
    h += '<div id="ir-criteria-container" class="ct-mt-1">';
    existingCriteria.forEach(function(c, idx) {
        h += '<div class="ir-crit-row" id="ir-crit-' + idx + '">';
        h += '<div style="flex:0 0 160px"><select id="ir-type-' + idx + '" class="ct-select">';
        ["cve_id", "package", "scanner_rule", "target_pattern", "severity", "ecosystem"].forEach(function(o) {
            h += '<option value="' + o + '"' + (o === c.type ? " selected" : "") + '>' + esc(t("ignore.type." + o) || o) + '</option>';
        });
        h += '</select></div>';
        h += '<input type="text" id="ir-val-' + idx + '" value="' + esc(c.value || "") + '" class="ct-flex-1 ct-p-1 ct-text-meta ct-bordered ct-r-sm">';
        h += '<button type="button" class="ct-bg-none ct-no-border ct-clickable ct-text-critical ct-text-section ct-py-1 ct-px-1" data-click="_irRemoveCrit" data-args=\'' + _da(idx) + '\'>&#10005;</button>';
        h += '</div>';
    });
    h += '</div>';
    h += '<button type="button" class="ct-btn ct-mt-1 admin-only" data-write data-variant="primary" data-size="xs" data-click="_irAddCrit">'
       + '+ ' + t("ignore.add_criterion") + '</button>';
    h += '</div>';

    // Reason
    h += '<div><label class="fs-sm ct-strong">' + t("ignore.col_reason") + ' <span class="ct-text-critical">*</span></label>';
    h += '<textarea id="ir-reason" class="ct-journal-body ct-py-1 ct-px-2 ct-text-meta ct-bordered ct-r-sm ct-box" rows="2">' + esc(rule.reason || "") + '</textarea>';
    h += '</div></div>';

    ct_modal.open({
        title: t("ignore.edit") || "Modifier la règle",
        body: h, size: "lg",
        buttons: [
            { id: "cancel", label: t("btn_cancel") },
            { id: "save", primary: true, label: t("btn_save"),
              result: function() {
                  var reasonVal = ((document.getElementById("ir-reason") as HTMLTextAreaElement).value || "").trim();
                  if (!reasonVal) { showStatus(t("ignore.err_required"), true); return false; }
                  var appIds: string[] = [];
                  var _irAll = document.getElementById("ir-all-apps") as HTMLInputElement | null;
                  if (!_irAll || !_irAll.checked) {
                      document.querySelectorAll<HTMLInputElement>(".ir-app-cb:checked").forEach(function(cb) { appIds.push(cb.value); });
                  }
                  var criteria: AppSecIgnoreCriterion[] = [];
                  for (var i = 0; i < _irCriteriaCount; i++) {
                      var typeEl = document.getElementById("ir-type-" + i) as HTMLSelectElement | null;
                      var valEl = document.getElementById("ir-val-" + i) as HTMLInputElement | null;
                      if (!typeEl || !valEl) continue;
                      var v = (valEl.value || "").trim();
                      if (v) criteria.push({ type: typeEl.value, value: v });
                  }
                  if (criteria.length === 0) { showStatus(t("ignore.err_no_criteria"), true); return false; }
                  return { application_ids: appIds, criteria: criteria, reason: reasonVal };
              } }
        ]
    }).then(function(data) {
        if (!data) return;
        AppSecAPI._fetch("/ignore-rules/" + ruleId, { method: "PATCH", body: data }).then(function(resp) {
            var msg = t("ignore.updated") || "Règle mise à jour";
            if (resp && resp.retroactive_count) msg += " (" + resp.retroactive_count + " finding(s) auto-triés)";
            showStatus(msg);
            _refreshIgnoreRules();
        }).catch(function(e) { showStatus(e.message, true); });
    });
};

window._toggleIgnoreRule = function(ruleId: string, enable: boolean) {
    AppSecAPI._fetch("/ignore-rules/" + ruleId, { method: "PATCH", body: { enabled: enable } }).then(function() {
        _refreshIgnoreRules();
    }).catch(function(e) { showStatus(e.message, true); });
};

window._deleteIgnoreRule = function(ruleId: string) {
    if (!confirm(t("ignore.confirm_delete"))) return;
    AppSecAPI._fetch("/ignore-rules/" + ruleId, { method: "DELETE" }).then(function() {
        showStatus(t("ignore.deleted"));
        _refreshIgnoreRules();
    }).catch(function(e) { showStatus(e.message, true); });
};

// ═══════════════════════════════════════════════════════════════
// AUDIT LOG (admin-only)
// ═══════════════════════════════════════════════════════════════

var _auditFilter: { q: string } = { q: "" };

async function _renderAuditLog(c: HTMLElement): Promise<void> {
    var retention = 365;
    try { var rd = await AppSecAPI._fetch("/audit-log/retention"); retention = rd.audit_retention_days || 365; } catch(e) {}
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + (t("audit.title") || "Journal d'audit") + '</h2><span class="ct-flex-1"></span>';
    h += '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1">' + (t("audit.retention") || "Rétention") + ' <input type="number" class="ct-input ct-w-70" id="audit-retention" value="' + retention + '" min="30" max="3650"> ' + (t("audit.days") || "jours") + '</label>';
    h += '<button class="ct-btn" data-size="xs" data-click="_saveAuditRetention">' + (t("audit.apply") || "Appliquer") + '</button>';
    h += '<input type="search" class="appsec-filter ct-minw-200" placeholder="' + (t("audit.search") || "Rechercher...") + '" value="' + esc(_auditFilter.q || "") + '" data-input="_setAuditSearch" data-pass-value>';
    h += '</div>';
    h += '<div id="audit-body">' + t("ai.loading") + '</div>';
    c.innerHTML = h;
    _refreshAuditBody();
}

window._saveAuditRetention = async function() {
    var days = parseInt((document.getElementById("audit-retention") as HTMLInputElement).value) || 365;
    try {
        await AppSecAPI._fetch("/audit-log/retention", {method:"PUT", headers:{"Content-Type":"application/json"}, body: JSON.stringify({days: days})});
        showStatus(t("settings.saved"));
    } catch(e: any) { showStatus("Error: " + e.message); }
};

async function _refreshAuditBody(): Promise<void> {
    var el = document.getElementById("audit-body");
    if (!el) return;
    try {
        var params: { q?: string } = {};
        if (_auditFilter.q) params.q = _auditFilter.q;
        var qs = Object.entries(params).filter(function(e){return e[1];}).map(function(e){return e[0]+"="+encodeURIComponent(e[1] as string);}).join("&");
        var data = await AppSecAPI._fetch("/audit-log" + (qs ? "?" + qs : ""));
        var items = data.items || [];
        var h = '';
        if (items.length === 0) {
            h = '<p class="text-muted">' + (t("audit.empty") || "Aucune entrée") + '</p>';
        } else {
            h = '<table class="ct-table"><thead><tr>';
            h += '<th>' + (t("audit.col_date") || "Date") + '</th>';
            h += '<th>' + (t("audit.col_user") || "Utilisateur") + '</th>';
            h += '<th>' + (t("audit.col_action") || "Action") + '</th>';
            h += '<th>' + (t("audit.col_target") || "Cible") + '</th>';
            h += '<th>' + (t("audit.col_details") || "Détails") + '</th>';
            h += '<th>IP</th>';
            h += '</tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {
                var e = items[i];
                var d = new Date(e.logged_at);
                var dateStr = isNaN(d.getTime()) ? e.logged_at : d.toLocaleString();
                h += '<tr>';
                h += '<td class="fs-xs text-muted ct-nowrap">' + esc(dateStr) + '</td>';
                h += '<td class="fs-sm">' + esc(e.user_email || e.user_name || "—") + '</td>';
                var actionLabel = t("audit.action." + e.action);
                if (actionLabel === "audit.action." + e.action) actionLabel = e.action;
                h += '<td><span class="ct-badge ct-text-label" data-tone="' + _auditActionColor(e.action) + '">' + esc(actionLabel) + '</span></td>';
                h += '<td class="fs-sm ct-maxw-200 ct-overflow-hidden ct-ellipsis">' + esc(e.target || "—") + '</td>';
                h += '<td class="fs-xs text-muted ct-maxw-250 ct-overflow-hidden ct-ellipsis" title="' + esc(e.details || "") + '">' + esc(e.details || "—") + '</td>';
                h += '<td class="fs-xs text-muted">' + esc(e.ip_address || "") + '</td>';
                h += '</tr>';
            }
            h += '</tbody></table>';
            h += '<p class="fs-xs text-muted">' + data.total + ' ' + (t("audit.entries") || "entrées") + '</p>';
        }
        el.innerHTML = h;
    } catch (e: any) {
        el.innerHTML = '<p class="text-muted ct-text-critical">' + esc(e.message || String(e)) + '</p>';
    }
}

function _auditActionColor(action: string): string {
    if (action.includes("delete")) return "high";
    if (action.includes("triage")) return "medium";
    if (action.includes("create")) return "low";
    if (action.includes("scan")) return "info";
    return "low";
}

window._setAuditSearch = function(v: string) { _auditFilter.q = v; _refreshAuditBody(); };

// ═══════════════════════════════════════════════════════════════
// MEASURES (placeholder)
// ═══════════════════════════════════════════════════════════════

var _appsecMeasures: AppSecMeasure[] = [];

async function _renderMeasures(c: HTMLElement): Promise<void> {
    c.innerHTML = '<h2>' + t("nav.measures") + '</h2><p class="text-muted">' + t("ai.loading") + '</p>';
    try {
        _appsecMeasures = await AppSecAPI.listMeasures() || [];
    } catch (e: any) {
        c.innerHTML = '<h2>' + t("nav.measures") + '</h2><p class="text-muted">Erreur : ' + esc(e.message) + '</p>';
        return;
    }
    var h = '<h2>' + t("nav.measures") + '</h2>';
    if (!_appsecMeasures.length) {
        h += '<p class="text-muted">Aucune remédiation. Les remédiations sont créées depuis la vue Findings (bouton « À corriger »).</p>';
        c.innerHTML = h;
        return;
    }
    h += ct_table.render({
        rows: _appsecMeasures,
        rowKey: "id",
        onRowClick: "_editAppsecMeasureRow",
        bulk: { scope: "appsec-measures" },
        columns: [
            { key: "id", label: "ID", width: "100px" },
            { key: "title", label: "Titre",
              render: function(m) { return esc(m.title || ""); } },
            { key: "finding_ids", label: "Findings", width: "100px",
              render: function(m) {
                  var n = (m.finding_ids && m.finding_ids.length) ? m.finding_ids.length : (m.finding_id ? 1 : 0);
                  return '<span class="fs-sm text-muted">' + n + '</span>';
              } },
            { key: "statut", label: "Statut", width: "110px",
              render: function(m) { return _measureStatusBadge(m.statut); } },
            { key: "responsable", label: "Responsable",
              render: function(m) { return esc(m.responsable || ""); } },
            { key: "echeance", label: "Échéance", width: "120px",
              render: function(m) { return esc(m.echeance || ""); } }
        ]
    });
    c.innerHTML = h;

    // DELETE /measures est admin-only côté backend : ne pas proposer
    // l'action à un triager (il finirait sur un 403).
    var measureActions: CtBulkbarAction[] = [
        { id: "done", icon: "check", label: "Terminé", variant: "success",
          onClick: "_bulkAppsecMeasuresDone" }
    ];
    if (document.body.classList.contains("role-admin")) {
        measureActions.push({ id: "delete", icon: "trash", label: "Supprimer", danger: true,
            onClick: "_bulkAppsecMeasuresDelete",
            confirm: { title: "Supprimer {n} remédiation(s) ?", message: "Cette action est irréversible." } });
    }
    ct_bulkbar.attach({
        scope: "appsec-measures",
        label: "{n} remédiation(s) sélectionnée(s)",
        actions: measureActions
    });
    ct_bulkbar.update("appsec-measures");
}

window._bulkAppsecMeasuresDone = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    Promise.all(ids.map(function(id) { return AppSecAPI.updateMeasure(id, { statut: "termine" }); }))
        .then(function() {
            showStatus(ids.length + " remédiation(s) marquée(s) terminée(s)");
            ct_bulkbar.clear(scope);
            selectPanel("measures");
        })
        .catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
};

window._editAppsecMeasureRow = function(row: any) {
    var m = _appsecMeasures.find(function(x) { return x.id === row.id; });
    if (!m) return;
    ct_measure_modal.open(m, {
        title: m.id + " — " + (m.title || "Mesure"),
        hideFields: ["type"],
        statusOptions: [
            { value: "a_faire",  label: "À faire" },
            { value: "en_cours", label: "En cours" },
            { value: "termine",  label: "Terminé" }
        ],
        defaultStatus: "a_faire",
        ownerPicker: { pickerId: "appsec-measure-owner", directoryUrl: "api/directory" },
        onAddNote: function(_entry, fullLog) {
            (m as Record<string, any>).progress_log = fullLog;
            return AppSecAPI.updateMeasure(m!.id, { progress_log: fullLog } as any);
        },
        // DELETE /measures est admin-only : sans onDelete la modale
        // n'affiche pas le bouton Supprimer.
        onDelete: !document.body.classList.contains("role-admin") ? undefined : function() {
            ct_modal.confirm({
                title: "Supprimer la remédiation",
                message: "Cette action est irréversible.",
                danger: true
            }).then(function(ok) {
                if (!ok) return;
                AppSecAPI.deleteMeasure(m!.id).then(function() {
                    showStatus("Mesure supprimée");
                    selectPanel("measures");
                }).catch(function(e) { showStatus("Erreur : " + e.message, true); });
            });
        }
    }).then(function(result) {
        if (!result || result.__deleted) return;
        AppSecAPI.updateMeasure(m!.id, result).then(function() {
            showStatus("Mesure mise à jour");
            selectPanel("measures");
        }).catch(function(e) { showStatus("Erreur : " + e.message, true); });
    });
};

window._bulkAppsecMeasuresDelete = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    Promise.all(ids.map(function(id) { return AppSecAPI.deleteMeasure(id); }))
        .then(function() {
            showStatus(ids.length + " remédiation(s) supprimée(s)");
            ct_bulkbar.clear(scope);
            selectPanel("measures");
        })
        .catch(function(e) { showStatus("Erreur : " + e.message, true); });
};

// ═══════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════

window.AI_APP_CONFIG = { storagePrefix: "appsec" };

// Placeholder File-menu actions (wired in toolbar; real impl coming later)
window.importApps = function() { showStatus(t("feature.coming_soon")); };
window.exportReport = function() { showStatus(t("feature.coming_soon")); };

selectPanel("dashboard");

// FEAT-13 — deep-linked measure from Pilot (?measure=MES-xxx): open the
// native edit modal once the measures list is loaded (shared retry loop).
if (typeof window.ct_handleMeasureDeepLink === "function") {
    window.ct_handleMeasureDeepLink({ open: function(mid: string) {
        if (!_appsecMeasures.some(function(m: any) { return m.id === mid; })) return false;
        if (typeof selectPanel === "function") selectPanel("measures");
        if (typeof window._editAppsecMeasureRow === "function") window._editAppsecMeasureRow({ id: mid });
        return true;
    } });
}


// FEAT-35 — préférences de notification (modale partagée ct_notifprefs)
window._openNotifPrefs = function() {
    if (!window.ct_notifprefs) return;
    var isAdmin = !!(window._currentUser && window._currentUser.role === "admin");
    var cfg = (window.CT_CONFIG || {}) as Record<string, any>;
    var mods: string[] | null = cfg.modules ? (cfg.modules as Array<{ id: string }>).map(function(m) { return m.id; })
        : (cfg.deployed && cfg.deployed.length ? cfg.deployed as string[] : null);
    window.ct_notifprefs.open({
        fetchPrefs: function() { return AppSecAPI._fetch("/me/notification-prefs"); },
        savePrefs: function(prefs: Record<string, any>) { return AppSecAPI._fetch("/me/notification-prefs", { method: "PUT", body: prefs }); },
        sendTest: function() { return AppSecAPI._fetch("/me/notification-prefs/test", { method: "POST" }); },
        isAdmin: isAdmin,
        modules: mods
    });
};
