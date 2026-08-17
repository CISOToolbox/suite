/* Watch — Vulnerability Monitoring frontend (phases 0–1) */
"use strict";

window.CT_CONFIG = {
    edition: "suite",
    module: "watch",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
};

// ═══════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════

var _panel = "dashboard";
var _scopes: WatchScope[] = [];
var _directory: WatchDirectoryUser[] = [];      // Pilot directory cache (for recipient picker)
var _directoryLoaded = false;

// ═══════════════════════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════════════════════

function showStatus(msg: string, kind?: string | boolean): void {
    var el = document.getElementById("status-msg");
    if (!el) return;
    el.textContent = msg || "";
    el.className = "status" + (kind ? " status-" + kind : "");
    if (msg) setTimeout(function() {
        if (el!.textContent === msg) { el!.textContent = ""; el!.className = "status"; }
    }, 4000);
}

function _toggleSidebarMobile(): void {
    var sb = document.getElementById("sidebar");
    if (sb) sb.classList.toggle("open");
}

function _fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    try { return new Date(iso).toLocaleString(); } catch(e: any) { return iso; }
}

// ═══════════════════════════════════════════════════════════════
// PANEL ROUTER
// ═══════════════════════════════════════════════════════════════

function selectPanel(name: string): void {
    _panel = name;
    document.querySelectorAll(".ct-rail-item").forEach(function(el) {
        var args = el.getAttribute("data-args");
        var match = false;
        try { match = !!(args && JSON.parse(args)[0] === name); } catch(e: any) {}
        if (match) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
    });
    var sb = document.getElementById("sidebar");
    if (sb && sb.classList.contains("open")) sb.classList.remove("open");
    _render();
}

function _render(): Promise<void> | void {
    var c = document.getElementById("content");
    if (!c) return;
    // Static chrome + help panels live in index.html and are filled from the
    // dictionaries (data-i18n / data-i18n-html). Watch never applied them, so
    // the two help tabs — whose divs are empty in the HTML — stayed blank.
    if (typeof _applyStaticTranslations === "function") _applyStaticTranslations();
    // Clear the sticky bulkbar when leaving the alerts panel — selection
    // is panel-scoped, lingering chips on other tabs are confusing.
    if (_panel !== "alerts" && window.ct_bulkbar) {
        ct_bulkbar.clear("watch-alerts");
    }
    switch (_panel) {
        case "dashboard": return _renderDashboard(c);
        case "scopes":    return _renderScopes(c);
        case "alerts":    return _renderAlerts(c);
        case "digest":    return _renderDigest(c);
        case "sources":   return _renderSources(c);
        case "audit":     return _renderAudit(c);
        default:          return _renderDashboard(c);
    }
}

function _placeholder(title: string, subtitle: string): string {
    return '<div class="empty-state">'
        + '<h2 style="margin:0 0 var(--ct-s3) 0;color:var(--ct-ink-1)">' + esc(title) + '</h2>'
        + '<p class="ct-m-0 ct-text-ui">' + esc(subtitle) + '</p>'
        + '</div>';
}

async function _renderDashboard(c: HTMLElement): Promise<void> {
    c.innerHTML = '<div class="ct-p-6 ct-muted">' + esc(t("misc.loading")) + '</div>';
    var d: any;
    try { d = await WatchAPI.getDashboard(); }
    catch (e: any) {
        c.innerHTML = '<div class="empty-state ct-text-critical">'
            + esc(t("dashboard.load_error")) + ' — ' + esc(e.message || "") + '</div>';
        return;
    }
    d = d || {};

    var h = '';
    h += '<div class="panel-header ct-flex ct-items-center ct-row-between ct-mb-5 ct-py-0 ct-px-1">';
    h +=   '<h2 class="ct-m-0">' + esc(t("dashboard.title")) + '</h2>';
    h +=   '<button class="ct-btn" data-click="selectPanel" data-args=\'["alerts"]\'>' + esc(t("dashboard.open_alerts")) + ' →</button>';
    h += '</div>';

    // ── KPI tiles — socle ct-kpi (harmonisation FEAT-30 follow-up)
    function kpi(val: string | number, label: string, tone?: string): string {
        return '<div class="ct-kpi"' + (tone ? ' data-tone="' + tone + '" data-emphasis="value"' : '')
             + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(label)
             + '</div><div class="ct-kpi-value">' + esc(String(val)) + '</div></div></div>';
    }
    h += '<div class="ct-kpigrid ct-mb-4">';
    h += kpi(d.alerts_total || 0, t("dashboard.kpi.alerts_total"));
    h += kpi(d.alerts_kev || 0, t("dashboard.kpi.alerts_kev"), (d.alerts_kev || 0) > 0 ? "critical" : undefined);
    h += kpi(d.alerts_crit_high_30d || 0, t("dashboard.kpi.crit_high_30d"), (d.alerts_crit_high_30d || 0) > 0 ? "high" : undefined);
    h += kpi(d.alerts_new || 0, t("dashboard.kpi.alerts_new"), (d.alerts_new || 0) > 0 ? "info" : undefined);
    h += kpi(d.scopes_owned || 0, t("dashboard.kpi.scopes_owned"));
    h += kpi(d.scopes_shared || 0, t("dashboard.kpi.scopes_shared"));
    h += kpi(d.targets_enabled || 0, t("dashboard.kpi.targets_enabled"));
    h += '</div>';

    // ── Breakdowns (severity + source)
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--ct-s3);margin-bottom:var(--ct-s5)">';
    h += '<div class="ct-bg-alt ct-bordered ct-r-md ct-p-3">';
    h +=   '<div class="ct-strong ct-mb-2">' + esc(t("dashboard.severity_breakdown")) + '</div>';
    h +=   _watchBreakdown(d.severity_breakdown || [], _sevSeries);
    h += '</div>';
    h += '<div class="ct-bg-alt ct-bordered ct-r-md ct-p-3">';
    h +=   '<div class="ct-strong ct-mb-2">' + esc(t("dashboard.source_breakdown")) + '</div>';
    h +=   _watchBreakdown(d.source_breakdown || [], function() { return "blue"; });
    h += '</div>';
    h += '</div>';

    // ── Recent KEV / critical alerts
    h += '<div class="ct-strong ct-mb-2">' + esc(t("dashboard.recent_alerts")) + '</div>';
    var recent = d.recent_alerts || [];
    if (!recent.length) {
        h += '<div class="empty-state" style="border:1px solid var(--ct-line);border-radius:var(--ct-r-md)">' + esc(t("dashboard.recent_empty")) + '</div>';
    } else {
        h += '<table class="table">';
        h += '<thead><tr class="ct-bg-alt">';
        h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.id")) + '</th>';
        h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.title")) + '</th>';
        h +=   '<th class="ct-p-2">' + esc(t("alerts.col.severity")) + '</th>';
        h +=   '<th class="ct-p-2">KEV</th>';
        h +=   '<th class="ct-p-2">' + esc(t("alerts.col.published")) + '</th>';
        h += '</tr></thead><tbody>';
        recent.forEach(function(a: any) {
            h += '<tr class="ct-border-top ct-clickable" data-click="openAlertDetail" data-args=\'["' + esc(a.id) + '"]\'>';
            h +=   '<td class="ct-p-2 ct-mono ct-text-meta">' + esc(a.external_id) + '</td>';
            h +=   '<td class="ct-p-2">' + esc(a.title || "") + '</td>';
            h +=   '<td class="ct-p-2 ct-ta-c">' + _sevBadge(a.severity) + '</td>';
            h +=   '<td class="ct-p-2 ct-ta-c">' + (a.kev_listed ? '<span class="ct-kpi-tone ct-text-onsolid ct-py-1 ct-px-1 ct-r-sm ct-text-label ct-strong">KEV</span>' : '') + '</td>';
            h +=   '<td class="ct-p-2 ct-text-meta ct-muted">' + esc(_fmtDate(a.published_at)) + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
    }

    c.innerHTML = h;
}

function _watchBreakdown(items: { label: string; value: number }[], seriesFn: (label: string) => string): string {
    // Socle renderer (_svgBreakdown type "bar") — named series colors from
    // the shared palette, theme-aware; replaces the hand-rolled div bars.
    if (!items || !items.length) {
        return '<div class="ct-muted ct-text-data ct-py-2 ct-px-0">—</div>';
    }
    var buckets = items.map(function(it) {
        return { label: it.label, value: it.value || 0, color: seriesFn(it.label) };
    });
    return _svgBreakdown({ type: "bar", data: { buckets: buckets } }, { width: 300, labelWidth: 90 });
}

function _sevSeries(sev: string): string {
    switch ((sev || "").toLowerCase()) {
        case "critical": return "redMax";
        case "high":     return "red";
        case "medium":   return "orange";
        case "low":      return "green";
        default:         return "gray";
    }
}
async function _renderDigest(c: HTMLElement): Promise<void> {
    c.innerHTML = '<div class="ct-p-6 ct-muted">' + esc(t("misc.loading")) + '</div>';
    var runs: any[] = [];
    try { runs = await WatchAPI.listDigestRuns() || []; }
    catch (e: any) { runs = []; }

    var h = '';
    h += '<div class="panel-header ct-flex ct-items-center ct-row-between ct-mb-5 ct-py-0 ct-px-1">';
    h +=   '<h2 class="ct-m-0">' + esc(t("digest.title")) + '</h2>';
    h +=   '<button class="ct-btn" data-click="openDigestPreview">' + esc(t("digest.preview")) + '</button>';
    h += '</div>';

    h += '<div class="ct-bg-alt ct-bordered ct-r-sm ct-p-3 ct-mb-4 ct-text-meta ct-ink-1">' + esc(t("digest.settings_moved_hint")) + '</div>';

    // History
    h += '<div class="ct-strong ct-mb-2">' + esc(t("digest.history")) + '</div>';
    if (!runs.length) {
        h += '<div class="empty-state">' + esc(t("digest.history_empty")) + '</div>';
    } else {
        h += '<table class="table">';
        h += '<thead><tr class="ct-bg-alt"><th class="ct-ta-l ct-p-2">' + esc(t("digest.col.date")) + '</th><th class="ct-ta-l ct-p-2">' + esc(t("digest.col.kind")) + '</th><th class="ct-ta-l ct-p-2">' + esc(t("digest.col.recipient")) + '</th><th class="ct-p-2">' + esc(t("digest.col.alerts")) + '</th><th class="ct-ta-l ct-p-2">' + esc(t("digest.col.status")) + '</th><th class="ct-p-2"></th></tr></thead><tbody>';
        runs.forEach(function(r: any) {
            var sentTs = r.sent_at ? new Date(r.sent_at).toLocaleString() : esc(r.calendar_date);
            var kindLabel = (r.kind === "threat") ? t("digest.kind.threat") : t("digest.kind.vuln");
            var canView = (r.status === "sent" || r.status === "failed");
            h += '<tr class="ct-border-top">';
            h +=   '<td class="ct-p-2 ct-nowrap">' + esc(sentTs) + '</td>';
            h +=   '<td class="ct-p-2">' + esc(kindLabel) + '</td>';
            h +=   '<td class="ct-p-2">' + esc(r.user_email) + '</td>';
            h +=   '<td class="ct-p-2 ct-ta-r">' + esc(String(r.alerts_count || 0)) + '</td>';
            h +=   '<td class="ct-p-2">' + esc(r.status) + (r.error_message ? ' — <span class="ct-text-critical ct-text-meta">' + esc(r.error_message) + '</span>' : '') + '</td>';
            h +=   '<td class="ct-p-2 ct-ta-r">' + (canView ? '<button class="ct-btn ct-py-1 ct-px-2 ct-text-meta" data-click="openDigestBody" data-args=\'' + _da(r.id) + '\'>' + esc(t("digest.view")) + '</button>' : '') + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
    }
    c.innerHTML = h;
}

async function openDigestPreview(): Promise<void> {
    var html = "";
    try { html = await WatchAPI.previewDigest(); }
    catch (e: any) { showStatus(e.message || t("error.generic"), "error"); return; }
    var iframe = '<iframe sandbox="" style="width:100%;height:60vh;border:1px solid var(--ct-line)" srcdoc="' + esc(html) + '"></iframe>';
    ct_modal.open({
        title: t("digest.preview"),
        body: iframe,
        size: "lg",
        buttons: [{ label: t("misc.close"), kind: "secondary" }] as unknown as CtModalButton[]
    });
}

async function openDigestBody(runId: string): Promise<void> {
    var html = "";
    try { html = await WatchAPI.getDigestBody(runId); }
    catch (e: any) { showStatus(e.message || t("error.generic"), "error"); return; }
    var iframe = '<iframe sandbox="" style="width:100%;height:70vh;border:1px solid var(--ct-line)" srcdoc="' + esc(html) + '"></iframe>';
    ct_modal.open({
        title: t("digest.view_title"),
        body: iframe,
        size: "lg",
        buttons: [{ label: t("misc.close"), kind: "secondary" }] as unknown as CtModalButton[]
    });
}

async function forceSendDigest(scopeId: string, kind: string): Promise<void> {
    var msgKey = (kind === "threat") ? "scopes.modal.force_send_threat_confirm" : "scopes.modal.force_send_vuln_confirm";
    if (!confirm(t(msgKey))) return;
    showStatus(t("scopes.modal.force_send_running"), "info");
    try {
        var res = await WatchAPI.sendDigestNow(scopeId, kind);
        var msg = t("scopes.modal.force_send_done")
            .replace("{sent}", String(res.sent || 0))
            .replace("{failed}", String(res.failed || 0))
            .replace("{total}", String((res.recipients || []).length));
        showStatus(msg, (res.failed ? "error" : "ok"));
    } catch (e: any) {
        showStatus(e.message || t("error.generic"), "error");
    }
}
function _renderAudit(c: HTMLElement): void {
    if (typeof _renderAuditLog === "function") {
        _renderAuditLog(c);
    } else {
        c.innerHTML = _placeholder(t("audit.title"), t("phase0.coming_soon"));
    }
}

// ═══════════════════════════════════════════════════════════════
// SCOPES PANEL (Phase 1)
// ═══════════════════════════════════════════════════════════════

async function _renderScopes(c: HTMLElement): Promise<void> {
    c.innerHTML = '<div class="ct-p-6 ct-muted">' + esc(t("misc.loading")) + '</div>';
    try {
        _scopes = await WatchAPI.listScopes() || [];
    } catch (e: any) {
        c.innerHTML = '<div class="empty-state ct-text-critical">'
            + esc(t("scopes.load_error")) + ' — ' + esc(e.message || "") + '</div>';
        return;
    }

    var h = '';
    h += '<div class="panel-header ct-flex ct-items-center ct-row-between ct-mb-5 ct-py-0 ct-px-1">';
    h +=   '<h2 class="ct-m-0">' + esc(t("scopes.title")) + '</h2>';
    h +=   '<button class="ct-btn" data-variant="primary" data-click="openScopeCreate">+ ' + esc(t("scopes.new")) + '</button>';
    h += '</div>';

    if (_scopes.length === 0) {
        h += '<div class="empty-state">'
            + '<p style="margin:0 0 var(--ct-s2) 0;font-size:var(--ct-text-body);color:var(--ct-ink-1)">' + esc(t("scopes.empty_title")) + '</p>'
            + '<p class="ct-m-0 ct-text-data">' + esc(t("scopes.empty_hint")) + '</p>'
            + '</div>';
    } else {
        var owned = _scopes.filter(function(s) { return s.is_owner; });
        var shared = _scopes.filter(function(s) { return !s.is_owner; });
        h += _scopesGroup(t("scopes.section_owned"), owned, true);
        if (shared.length) h += _scopesGroup(t("scopes.section_shared"), shared, false);
    }
    c.innerHTML = h;
}

function _scopesGroup(title: string, list: WatchScope[], editable: boolean): string {
    var h = '<h3 style="margin:var(--ct-s5) var(--ct-s1) var(--ct-s2) var(--ct-s1);font-size:var(--ct-text-ui);color:var(--ct-ink-2);text-transform:uppercase;letter-spacing:0.05em">' + esc(title) + ' (' + list.length + ')</h3>';
    h += '<div class="scope-grid">';
    list.forEach(function(s) {
        h += _scopeCard(s, editable);
    });
    h += '</div>';
    return h;
}

function _scopeCard(s: WatchScope, editable: boolean): string {
    var nbRcp = (s.recipients || []).length;
    var h = '<div class="scope-card" data-click="openScopeDetails" data-args=\'' + _da(s.id) + '\'>';
    h +=   '<div class="ct-flex ct-items-start ct-row-between ct-gap-2">';
    h +=     '<div style="font-weight:600;font-size:var(--ct-text-body);line-height:1.3">' + esc(s.name) + '</div>';
    if (!editable) {
        h +=   '<span class="ct-bg-info-tint ct-text-info-ink ct-text-label ct-py-1 ct-px-1 ct-r-sm ct-nowrap" title="' + esc(t("scopes.shared_by") + " " + s.owner_email) + '">' + esc(t("scopes.badge_shared")) + '</span>';
    }
    h +=   '</div>';
    if (s.description) {
        var snippet = s.description!.length > 120 ? s.description!.substring(0, 120) + "…" : s.description!;
        h += '<p style="margin:var(--ct-s1) 0 var(--ct-s2) 0;color:var(--ct-ink-2);font-size:var(--ct-text-meta);line-height:1.4">' + esc(snippet) + '</p>';
    } else {
        h += '<p style="margin:var(--ct-s1) 0 var(--ct-s2) 0;color:var(--ct-ink-2);font-size:var(--ct-text-meta);font-style:italic">' + esc(t("scopes.no_description")) + '</p>';
    }
    h +=   '<div class="ct-flex ct-row-between ct-items-center ct-text-label ct-muted ct-mt-2">';
    h +=     '<span>' + esc(t("scopes.recipients_count").replace("{n}", String(nbRcp))) + '</span>';
    h +=     '<span>' + esc(_fmtDate(s.updated_at)) + '</span>';
    h +=   '</div>';
    h += '</div>';
    return h;
}

// ── Create / edit modal ──────────────────────────────────────────

function openScopeCreate(): void {
    _openScopeEditor(null);
}

async function openScopeDetails(id: string): Promise<void> {
    var s;
    try { s = await WatchAPI.getScope(id); }
    catch(e: any) { showStatus(e.message || t("error.generic"), "err"); return; }
    _openScopeEditor(s);
}

function _openScopeEditor(scope: WatchScope | null): void {
    var isNew = !scope;
    var canEdit = isNew || (scope && scope.is_owner);
    var h = '';
    h += '<div class="ct-p-1">';
    h +=   '<h3 style="margin:0 0 var(--ct-s4) 0">' + esc(isNew ? t("scopes.modal.new_title") : t("scopes.modal.edit_title")) + '</h3>';
    h +=   '<label class="ct-block ct-text-meta ct-ink-1 ct-mb-1">' + esc(t("scopes.modal.name_label")) + '</label>';
    h +=   '<input type="text" id="scope-name" value="' + esc(scope ? scope.name : "") + '" maxlength="200"' + (canEdit ? '' : ' readonly') + ' class="ct-w-full ct-p-2 ct-bordered ct-r-md ct-mb-3 ct-text-ui">';
    h +=   '<label class="ct-block ct-text-meta ct-ink-1 ct-mb-1">' + esc(t("scopes.modal.description_label")) + '</label>';
    h +=   '<textarea id="scope-description" rows="3" maxlength="10000"' + (canEdit ? '' : ' readonly') + ' class="ct-journal-body ct-py-2 ct-px-2 ct-bordered ct-r-md ct-mb-3 ct-font-inherit ct-text-data ct-resize-y">' + esc(scope ? scope.description : "") + '</textarea>';

    // ─────────────────────────────────────────────────────────────
    // Section A — VULNÉRABILITÉS (vuln digest cadence + thresholds + targets)
    // ─────────────────────────────────────────────────────────────
    var dEnabled = scope && scope.digest_enabled !== undefined ? !!scope.digest_enabled : true;
    var dHour = scope && scope.digest_hour !== undefined ? scope.digest_hour : 7;
    var dMin = scope && scope.digest_minute !== undefined ? scope.digest_minute : 0;
    var dTz = scope && scope.digest_timezone ? scope.digest_timezone : "Europe/Paris";
    var dSev = scope && scope.digest_severity_min ? scope.digest_severity_min : "critical";
    var dKev = scope && scope.digest_include_kev !== undefined ? !!scope.digest_include_kev : true;
    var dCvss = scope && scope.digest_cvss_min !== undefined && scope.digest_cvss_min !== null ? scope.digest_cvss_min : "";
    var dEpss = scope && scope.digest_epss_min !== undefined && scope.digest_epss_min !== null ? scope.digest_epss_min : "";
    h += '<div class="ct-mb-3 ct-bordered ct-r-lg ct-bg-alt ct-overflow-hidden">';
    h +=   '<label style="display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:' + (canEdit ? 'pointer' : 'default') + ';font-size:var(--ct-text-ui);font-weight:600;color:var(--ct-ink);background:var(--ct-surface-2);border-bottom:1px solid var(--ct-line)">';
    h +=     '<input type="checkbox" id="scope-digest-enabled"' + (dEnabled ? ' checked' : '') + (canEdit ? '' : ' disabled') + ' style="cursor:' + (canEdit ? 'pointer' : 'default') + ';transform:scale(1.15)">';
    h +=     '<span>' + esc(t("scopes.modal.section_vuln_title")) + '</span>';
    h +=     '<span class="ct-ml-auto ct-text-label ct-journal-sep ct-normal">' + esc(t("scopes.modal.section_vuln_subtitle")) + '</span>';
    h +=   '</label>';
    h +=   '<div id="vuln-config-body" style="padding:12px 14px;display:' + (dEnabled ? 'block' : 'none') + '">';
    // — Cadence
    h +=     '<div class="ct-text-label ct-muted ct-mb-2">' + esc(t("scopes.modal.digest_hint")) + '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-3">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-120">' + esc(t("scopes.modal.digest_time")) + '</label>';
    h +=       '<input type="number" id="scope-digest-hour" min="0" max="23" value="' + dHour + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-64 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<span class="ct-muted">:</span>';
    h +=       '<input type="number" id="scope-digest-minute" min="0" max="59" value="' + dMin + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-64 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-ml-2">' + esc(t("scopes.modal.digest_tz")) + '</label>';
    h +=       '<input type="text" id="scope-digest-tz" value="' + esc(dTz) + '" maxlength="64"' + (canEdit ? '' : ' readonly') + ' class="ct-flex-1 ct-minw-160 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=     '</div>';
    // — Thresholds
    h +=     '<div class="ct-text-data ct-strong ct-ink-1 ct-mb-1">' + esc(t("scopes.modal.thresholds_title")) + '</div>';
    h +=     '<div class="ct-text-label ct-muted ct-mb-2">' + esc(t("scopes.modal.thresholds_hint")) + '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-2">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-140">' + esc(t("scopes.modal.severity_min")) + '</label>';
    h +=       '<select id="scope-severity-min"' + (canEdit ? '' : ' disabled') + ' class="ct-select">';
    ["critical", "high", "medium", "low"].forEach(function(sv) {
        h +=     '<option value="' + sv + '"' + (dSev === sv ? ' selected' : '') + '>' + esc(t("scopes.modal.sev_" + sv)) + '</option>';
    });
    h +=       '</select>';
    h +=     '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-mb-2">';
    h +=       '<label style="display:flex;align-items:center;gap:8px;font-size:var(--ct-text-meta);color:var(--ct-ink-1);cursor:' + (canEdit ? 'pointer' : 'default') + '">';
    h +=         '<input type="checkbox" id="scope-include-kev"' + (dKev ? ' checked' : '') + (canEdit ? '' : ' disabled') + '>';
    h +=         esc(t("scopes.modal.include_kev"));
    h +=       '</label>';
    h +=     '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-2">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-140">' + esc(t("scopes.modal.cvss_min")) + '</label>';
    h +=       '<input type="number" id="scope-cvss-min" min="0" max="10" step="0.1" value="' + esc(String(dCvss)) + '" placeholder="' + esc(t("scopes.modal.threshold_off")) + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-90 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<span class="ct-text-label ct-muted">' + esc(t("scopes.modal.cvss_help")) + '</span>';
    h +=     '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-3">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-140">' + esc(t("scopes.modal.epss_min")) + '</label>';
    h +=       '<input type="number" id="scope-epss-min" min="0" max="1" step="0.01" value="' + esc(String(dEpss)) + '" placeholder="' + esc(t("scopes.modal.threshold_off")) + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-90 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<span class="ct-text-label ct-muted">' + esc(t("scopes.modal.epss_help")) + '</span>';
    h +=     '</div>';
    // — Targets (technologies surveillées) — needs an existing scope.
    h +=     '<div style="font-size:var(--ct-text-data);font-weight:600;color:var(--ct-ink-1);margin:var(--ct-s2) 0 var(--ct-s1) 0">' + esc(t("targets.title")) + '</div>';
    if (isNew) {
        h +=   '<div class="ct-text-meta ct-journal-sep ct-italic ct-py-1 ct-px-1">' + esc(t("targets.save_first")) + '</div>';
    } else {
        h +=   '<div id="scope-targets-list" class="ct-text-meta ct-muted">' + esc(t("misc.loading")) + '</div>';
        if (canEdit) {
            h += '<div class="ct-flex ct-gap-1 ct-mt-2 ct-items-center ct-row-wrap">';
            h +=   '<select id="target-kind" class="ct-select">';
            h +=     '<option value="cpe">' + esc(t("targets.kind.cpe")) + '</option>';
            h +=     '<option value="purl">' + esc(t("targets.kind.purl")) + '</option>';
            h +=     '<option value="keyword" selected>' + esc(t("targets.kind.keyword")) + '</option>';
            h +=   '</select>';
            h +=   '<input type="text" id="target-value" placeholder="' + esc(t("targets.value_placeholder")) + '" class="ct-flex-1 ct-minw-180 ct-py-2 ct-px-2 ct-bordered ct-r-md ct-text-data">';
            h +=   '<input type="text" id="target-label" placeholder="' + esc(t("targets.label_placeholder")) + '" style="flex:0.7;min-width:140px;padding:var(--ct-s2) var(--ct-s2);border:1px solid var(--ct-line);border-radius:var(--ct-r-md);font-size:var(--ct-text-data)">';
            h +=   '<button class="ct-btn" data-variant="primary" data-size="xs" data-click="addTargetToScope" data-args=\'' + _da(scope!.id) + '\'>+ ' + esc(t("targets.add")) + '</button>';
            h += '</div>';
            h += '<div class="ct-mt-2 ct-flex ct-gap-1 ct-row-wrap ct-items-center">';
            h +=   '<input type="text" id="target-version" placeholder="' + esc(t("targets.version_placeholder")) + '" style="flex:0.6;min-width:120px;padding:var(--ct-s2) var(--ct-s2);border:1px solid var(--ct-line);border-radius:var(--ct-r-md);font-size:var(--ct-text-meta)">';
            h +=   '<span class="ct-text-label ct-muted">' + esc(t("targets.version_help")) + '</span>';
            h += '</div>';
        }
    }
    h +=   '</div>';
    h += '</div>';

    // ─────────────────────────────────────────────────────────────
    // Section B — MENACES (threat digest + LLM context + threat topics)
    // ─────────────────────────────────────────────────────────────
    var tdEnabled = scope && scope.threat_digest_enabled !== undefined ? !!scope.threat_digest_enabled : true;
    var tdFreq = scope && scope.threat_digest_frequency ? scope.threat_digest_frequency : "weekly";
    var tdWday = scope && scope.threat_digest_weekday !== undefined ? scope.threat_digest_weekday : 0;
    var tdHour = scope && scope.threat_digest_hour !== undefined ? scope.threat_digest_hour : 8;
    var tdMin = scope && scope.threat_digest_minute !== undefined ? scope.threat_digest_minute : 0;
    var tdTz = scope && scope.threat_digest_timezone ? scope.threat_digest_timezone : "Europe/Paris";
    var tdPrompt = scope && scope.threat_prompt ? scope.threat_prompt : "";
    var tdWindowDays = scope && scope.threat_search_window_days ? scope.threat_search_window_days : 7;
    h += '<div class="ct-mb-3 ct-bordered ct-r-lg ct-bg-alt ct-overflow-hidden">';
    h +=   '<label style="display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:' + (canEdit ? 'pointer' : 'default') + ';font-size:var(--ct-text-ui);font-weight:600;color:var(--ct-ink);background:var(--ct-surface-2);border-bottom:1px solid var(--ct-line)">';
    h +=     '<input type="checkbox" id="scope-threat-digest-enabled"' + (tdEnabled ? ' checked' : '') + (canEdit ? '' : ' disabled') + ' style="cursor:' + (canEdit ? 'pointer' : 'default') + ';transform:scale(1.15)">';
    h +=     '<span>' + esc(t("scopes.modal.section_threat_title")) + '</span>';
    h +=     '<span class="ct-ml-auto ct-text-label ct-journal-sep ct-normal">' + esc(t("scopes.modal.section_threat_subtitle")) + '</span>';
    h +=   '</label>';
    h +=   '<div id="threat-config-body" style="padding:12px 14px;display:' + (tdEnabled ? 'block' : 'none') + '">';
    h +=     '<div class="ct-text-label ct-muted ct-mb-2">' + esc(t("scopes.modal.threat_digest_hint")) + '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-2">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-120">' + esc(t("scopes.modal.threat_digest_frequency")) + '</label>';
    h +=       '<select id="scope-threat-digest-frequency"' + (canEdit ? '' : ' disabled') + ' class="ct-select">';
    ["off", "daily", "weekly"].forEach(function(f) {
        h +=     '<option value="' + f + '"' + (tdFreq === f ? ' selected' : '') + '>' + esc(t("scopes.modal.threat_freq_" + f)) + '</option>';
    });
    h +=       '</select>';
    h +=       '<label id="scope-threat-weekday-label" style="font-size:var(--ct-text-meta);color:var(--ct-ink-1);margin-left:10px' + (tdFreq === "weekly" ? '' : ';display:none') + '">' + esc(t("scopes.modal.threat_digest_weekday")) + '</label>';
    h +=       '<select id="scope-threat-digest-weekday"' + (canEdit ? '' : ' disabled') + ' style="padding:5px 7px;border:1px solid var(--ct-line);border-radius:5px;font-size:var(--ct-text-meta)' + (tdFreq === "weekly" ? '' : ';display:none') + '">';
    ["mon","tue","wed","thu","fri","sat","sun"].forEach(function(d, idx) {
        h +=     '<option value="' + idx + '"' + (tdWday === idx ? ' selected' : '') + '>' + esc(t("scopes.modal.weekday_" + d)) + '</option>';
    });
    h +=       '</select>';
    h +=     '</div>';
    h +=     '<div id="scope-threat-time-row" style="display:' + (tdFreq === "off" ? 'none' : 'flex') + ';gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-120">' + esc(t("scopes.modal.threat_digest_time")) + '</label>';
    h +=       '<input type="number" id="scope-threat-digest-hour" min="0" max="23" value="' + tdHour + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-64 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<span class="ct-muted">:</span>';
    h +=       '<input type="number" id="scope-threat-digest-minute" min="0" max="59" value="' + tdMin + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-64 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-ml-2">' + esc(t("scopes.modal.digest_tz")) + '</label>';
    h +=       '<input type="text" id="scope-threat-digest-tz" value="' + esc(tdTz) + '" maxlength="64"' + (canEdit ? '' : ' readonly') + ' class="ct-flex-1 ct-minw-160 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=     '</div>';
    // — Free-form CISO prompt (M22) — sent to Claude+web_search at digest time.
    h +=     '<div class="ct-mb-3">';
    h +=       '<label class="ct-block ct-text-meta ct-ink-1 ct-mb-1">' + esc(t("scopes.modal.threat_prompt_label")) + '</label>';
    h +=       '<div class="ct-text-label ct-muted ct-mb-1">' + esc(t("scopes.modal.threat_prompt_hint")) + '</div>';
    h +=       '<textarea id="scope-threat-prompt" rows="8" maxlength="10000"' + (canEdit ? '' : ' readonly') + ' placeholder="' + esc(t("scopes.modal.threat_prompt_placeholder")) + '" class="ct-journal-body ct-py-2 ct-px-2 ct-bordered ct-r-md ct-font-inherit ct-text-meta ct-resize-y ct-box">' + esc(tdPrompt) + '</textarea>';
    h +=     '</div>';
    h +=     '<div class="ct-flex ct-gap-2 ct-items-center ct-row-wrap ct-mb-1">';
    h +=       '<label class="ct-text-meta ct-ink-1 ct-minw-120">' + esc(t("scopes.modal.threat_window_days_label")) + '</label>';
    h +=       '<input type="number" id="scope-threat-window-days" min="1" max="30" value="' + tdWindowDays + '"' + (canEdit ? '' : ' readonly') + ' class="ct-w-80 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta">';
    h +=       '<span class="ct-text-label ct-muted">' + esc(t("scopes.modal.threat_window_days_hint")) + '</span>';
    h +=     '</div>';
    h +=   '</div>';
    h += '</div>';

    // ─────────────────────────────────────────────────────────────
    // Section C — DESTINATAIRES (shared between both digests)
    // ─────────────────────────────────────────────────────────────
    if (!isNew) {
        h += '<h4 style="margin:var(--ct-s4) 0 var(--ct-s2) 0;font-size:var(--ct-text-ui)">' + esc(t("scopes.modal.recipients_title")) + '</h4>';
        h += '<div id="scope-recipients-list"></div>';
        if (canEdit) {
            h += '<div class="ct-mt-2">';
            h +=   '<input type="text" id="scope-recipient-input" placeholder="' + esc(t("scopes.modal.recipient_picker_placeholder")) + '" list="scope-directory" data-input="onRecipientInputChange" data-args=\'' + _da(scope!.id) + '\' data-pass-value="true" class="ct-input">';
            h +=   '<datalist id="scope-directory"></datalist>';
            h +=   '<div id="scope-recipient-add-action" style="margin-top:var(--ct-s2);min-height:30px"></div>';
            h += '</div>';
        }
    }

    h +=   '<div class="ct-flex ct-justify-end ct-gap-2 ct-mt-6 ct-row-wrap">';
    if (!isNew && canEdit) {
        h +=   '<button class="ct-btn" data-variant="danger" data-click="confirmDeleteScope" data-args=\'' + _da(scope!.id) + '\'>' + esc(t("scopes.modal.delete")) + '</button>';
        h +=   '<span class="ct-flex-1"></span>';
    }
    // Admin-only force-send buttons. Only visible on existing scopes and
    // only when the toolbar resolved the user as admin (body.role-admin).
    var isAdmin = (document.body && document.body.classList.contains("role-admin"));
    if (!isNew && isAdmin) {
        h +=   '<button class="ct-btn" data-click="forceSendDigest" data-args=\'' + _da(scope!.id, "vuln") + '\' title="' + esc(t("scopes.modal.force_send_vuln_hint")) + '">' + esc(t("scopes.modal.force_send_vuln")) + '</button>';
        h +=   '<button class="ct-btn" data-click="forceSendDigest" data-args=\'' + _da(scope!.id, "threat") + '\' title="' + esc(t("scopes.modal.force_send_threat_hint")) + '">' + esc(t("scopes.modal.force_send_threat")) + '</button>';
    }
    h +=     '<button class="ct-btn" data-click="_closeModal">' + esc(t("misc.close")) + '</button>';
    if (canEdit) {
        h +=   '<button class="ct-btn" data-variant="primary" data-click="saveScope" data-args=\'' + _da(isNew ? null : scope!.id) + '\'>' + esc(t("misc.save")) + '</button>';
    }
    h +=   '</div>';
    h += '</div>';

    ct_modal.open({ body: h, size: "lg" });

    // Frequency → toggle weekday picker + hour/minute/tz row visibility.
    var freqSel = document.getElementById("scope-threat-digest-frequency") as HTMLSelectElement | null;
    if (freqSel) {
        freqSel.addEventListener("change", function() {
            var f = freqSel!.value;
            var wlbl = document.getElementById("scope-threat-weekday-label");
            var wsel = document.getElementById("scope-threat-digest-weekday");
            var trow = document.getElementById("scope-threat-time-row");
            if (wlbl) wlbl.style.display = (f === "weekly") ? "" : "none";
            if (wsel) wsel.style.display = (f === "weekly") ? "" : "none";
            if (trow) trow.style.display = (f === "off") ? "none" : "flex";
        });
    }

    // Section toggles → show/hide the associated config body.
    var vulnToggle = document.getElementById("scope-digest-enabled") as HTMLInputElement | null;
    var vulnBody = document.getElementById("vuln-config-body");
    if (vulnToggle && vulnBody) {
        vulnToggle.addEventListener("change", function() {
            vulnBody!.style.display = vulnToggle!.checked ? "block" : "none";
        });
    }
    var threatToggle = document.getElementById("scope-threat-digest-enabled") as HTMLInputElement | null;
    var threatBody = document.getElementById("threat-config-body");
    if (threatToggle && threatBody) {
        threatToggle.addEventListener("change", function() {
            threatBody!.style.display = threatToggle!.checked ? "block" : "none";
        });
    }

    if (!isNew) {
        _renderRecipientsList(scope!);
        if (canEdit) _loadDirectoryIntoDatalist();
        _loadAndRenderTargets(scope!);
    }
}

async function _loadAndRenderTargets(scope: WatchScope): Promise<void> {
    var box = document.getElementById("scope-targets-list");
    if (!box) return;
    try {
        var targets = await WatchAPI.listTargets(scope.id);
        _renderTargetsList(box, scope, targets);
    } catch(e: any) {
        box.innerHTML = '<div class="ct-text-critical ct-text-meta">' + esc(t("targets.load_error")) + '</div>';
    }
}

function _renderTargetsList(box: HTMLElement, scope: WatchScope, targets: WatchTarget[]): void {
    if (!targets || targets.length === 0) {
        box.innerHTML = '<div class="ct-journal-sep ct-italic ct-text-meta ct-py-1 ct-px-1">' + esc(t("targets.empty")) + '</div>';
        return;
    }
    var h = '<div class="ct-flex ct-body ct-gap-1">';
    targets.forEach(function(tg) {
        // Les trois fonds etaient des hex en dur : ils restaient clairs en theme
        // sombre. Le ton du socle suit le theme, la classe garde la typographie.
        var _kindTone = tg.kind === "cpe" ? "medium" : tg.kind === "purl" ? "info" : "low";
        var kindBadge = '<span class="ct-badge target-kind-badge" data-tone="' + _kindTone + '">' + esc(tg.kind) + '</span>';
        var ver = tg.version_constraint ? ' <span class="ct-muted ct-text-label">' + esc(tg.version_constraint) + '</span>' : '';
        var enabled = tg.enabled ? "" : ' <span class="ct-journal-sep ct-text-label ct-italic">(' + esc(t("targets.disabled")) + ')</span>';
        var lbl = tg.label ? ' — <em class="ct-muted">' + esc(tg.label) + '</em>' : '';
        h += '<div class="target-row" style="display:flex;align-items:center;justify-content:space-between;padding:6px 8px;border:1px solid var(--ct-line);border-radius:6px;background:' + (tg.enabled ? "#fff" : "var(--ct-surface-2)") + ';font-size:0.88em">';
        h +=   '<div style="overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0">' + kindBadge + '<code style="background:none;padding:0;font-size:var(--ct-text-ui)">' + esc(tg.value) + '</code>' + ver + lbl + enabled + '</div>';
        if (scope.is_owner) {
            h += '<div class="ct-flex ct-gap-1 ct-ml-2">';
            h +=   '<button data-click="toggleTargetEnabled" data-args=\'' + _da(scope.id, tg.id, !tg.enabled) + '\' title="' + esc(tg.enabled ? t("targets.disable") : t("targets.enable")) + '" class="ct-bg-none ct-no-border ct-clickable ct-muted ct-py-1 ct-px-1 ct-text-meta">' + (tg.enabled ? "⏸" : "▶") + '</button>';
            h +=   '<button data-click="removeTargetFromScope" data-args=\'' + _da(scope.id, tg.id) + '\' title="' + esc(t("targets.remove")) + '" style="background:none;border:none;cursor:pointer;color:var(--ct-critical);padding:var(--ct-s1) var(--ct-s1);font-size:var(--ct-text-body);line-height:1">×</button>';
            h += '</div>';
        }
        h += '</div>';
    });
    h += '</div>';
    box.innerHTML = h;
}

async function addTargetToScope(scopeId: string): Promise<void> {
    var kind = (document.getElementById("target-kind") as HTMLSelectElement).value;
    var value = ((document.getElementById("target-value") as HTMLInputElement).value || "").trim();
    var label = ((document.getElementById("target-label") as HTMLInputElement).value || "").trim();
    var version = ((document.getElementById("target-version") as HTMLInputElement).value || "").trim();
    if (!value) { showStatus(t("targets.error.value_required"), "err"); return; }
    try {
        await WatchAPI.createTarget(scopeId, { kind: kind, value: value, label: label, version_constraint: version, enabled: true });
        (document.getElementById("target-value") as HTMLInputElement).value = "";
        (document.getElementById("target-label") as HTMLInputElement).value = "";
        (document.getElementById("target-version") as HTMLInputElement).value = "";
        var s = await WatchAPI.getScope(scopeId);
        await _loadAndRenderTargets(s);
        showStatus(t("targets.added"), "ok");
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

async function toggleTargetEnabled(scopeId: string, targetId: string, enabled: boolean): Promise<void> {
    try {
        await WatchAPI.updateTarget(scopeId, targetId, { enabled: enabled });
        var s = await WatchAPI.getScope(scopeId);
        await _loadAndRenderTargets(s);
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

async function removeTargetFromScope(scopeId: string, targetId: string): Promise<void> {
    try {
        await WatchAPI.deleteTarget(scopeId, targetId);
        var s = await WatchAPI.getScope(scopeId);
        await _loadAndRenderTargets(s);
        showStatus(t("targets.removed"), "ok");
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

function _renderRecipientsList(scope: WatchScope): void {
    var box = document.getElementById("scope-recipients-list");
    if (!box) return;
    var rcps = scope.recipients || [];
    if (rcps.length === 0) {
        box.innerHTML = '<div class="ct-journal-sep ct-italic ct-text-meta ct-py-1 ct-px-1">' + esc(t("scopes.modal.no_recipients")) + '</div>';
        return;
    }
    var h = '<div class="ct-flex ct-row-wrap ct-gap-1">';
    rcps.forEach(function(r) {
        var label = r.name ? (r.name + " <" + r.email + ">") : r.email;
        h += '<span class="recipient-chip">';
        h +=   esc(label);
        if (scope.is_owner) {
            h += '<button data-click="removeRecipientFromScope" data-args=\'' + _da(scope.id, r.email) + '\' title="' + esc(t("scopes.modal.recipient_remove")) + '" style="background:none;border:none;color:var(--ct-info-ink);cursor:pointer;padding:0;font-size:var(--ct-text-section);line-height:1">×</button>';
        }
        h += '</span>';
    });
    h += '</div>';
    box.innerHTML = h;
}

async function _loadDirectoryIntoDatalist(): Promise<void> {
    if (!_directoryLoaded) {
        try { _directory = await WatchAPI.getDirectory() || []; }
        catch(e: any) { _directory = []; }
        _directoryLoaded = true;
    }
    var dl = document.getElementById("scope-directory");
    if (!dl) return;
    var h = "";
    _directory.forEach(function(u) {
        var email = (u.email || "").trim();
        if (!email) return;
        var label = ((u.prenom || "") + " " + (u.nom || "")).trim() || (u.name || "");
        h += '<option value="' + esc(email) + '"' + (label ? ' label="' + esc(label) + '"' : '') + '></option>';
    });
    dl.innerHTML = h;
}

// ── Actions ──────────────────────────────────────────────────────

async function saveScope(id: string | null): Promise<void> {
    var name = ((document.getElementById("scope-name") as HTMLInputElement).value || "").trim();
    var description = ((document.getElementById("scope-description") as HTMLTextAreaElement).value || "").trim();
    if (!name) { showStatus(t("scopes.error.name_required"), "err"); return; }
    var enabledEl = document.getElementById("scope-digest-enabled") as HTMLInputElement | null;
    var hourEl = document.getElementById("scope-digest-hour") as HTMLInputElement | null;
    var minEl = document.getElementById("scope-digest-minute") as HTMLInputElement | null;
    var tzEl = document.getElementById("scope-digest-tz") as HTMLInputElement | null;
    var hour = parseInt((hourEl && hourEl.value) as string, 10);
    var minute = parseInt((minEl && minEl.value) as string, 10);
    if (isNaN(hour) || hour < 0 || hour > 23) { showStatus(t("scopes.error.digest_hour"), "err"); return; }
    if (isNaN(minute) || minute < 0 || minute > 59) { showStatus(t("scopes.error.digest_minute"), "err"); return; }
    // ── Thresholds (per-scope, OR semantics) ────────────────────
    var sevEl = document.getElementById("scope-severity-min") as HTMLSelectElement | null;
    var kevEl = document.getElementById("scope-include-kev") as HTMLInputElement | null;
    var cvssEl = document.getElementById("scope-cvss-min") as HTMLInputElement | null;
    var epssEl = document.getElementById("scope-epss-min") as HTMLInputElement | null;
    // Empty value semantics differ between create and update:
    //   - On update (PATCH), Pydantic collapses missing/null to None,
    //     so the API uses -1.0 as the explicit "clear the gate" sentinel.
    //   - On create (POST), there's no prior value to clear; ScopeCreate
    //     only accepts None or [0..max], so we must send null instead of
    //     -1.0 (which would fail the ge=0.0 validation → 422).
    var cvssRaw = cvssEl ? (cvssEl.value || "").trim() : "";
    var epssRaw = epssEl ? (epssEl.value || "").trim() : "";
    var emptySentinel = id ? -1.0 : null;
    var cvssVal = cvssRaw === "" ? emptySentinel : parseFloat(cvssRaw);
    var epssVal = epssRaw === "" ? emptySentinel : parseFloat(epssRaw);
    if (cvssRaw !== "" && (isNaN(cvssVal!) || cvssVal! < 0 || cvssVal! > 10)) {
        showStatus(t("scopes.error.cvss_min"), "err"); return;
    }
    if (epssRaw !== "" && (isNaN(epssVal!) || epssVal! < 0 || epssVal! > 1)) {
        showStatus(t("scopes.error.epss_min"), "err"); return;
    }
    // ── Threat digest cadence + free-form prompt + search window ──
    var tdEnEl = document.getElementById("scope-threat-digest-enabled") as HTMLInputElement | null;
    var tdFreqEl = document.getElementById("scope-threat-digest-frequency") as HTMLSelectElement | null;
    var tdWdayEl = document.getElementById("scope-threat-digest-weekday") as HTMLSelectElement | null;
    var tdHourEl = document.getElementById("scope-threat-digest-hour") as HTMLInputElement | null;
    var tdMinEl = document.getElementById("scope-threat-digest-minute") as HTMLInputElement | null;
    var tdTzEl = document.getElementById("scope-threat-digest-tz") as HTMLInputElement | null;
    var tdPromptEl = document.getElementById("scope-threat-prompt") as HTMLTextAreaElement | null;
    var tdWindowDaysEl = document.getElementById("scope-threat-window-days") as HTMLInputElement | null;
    var tdHour = parseInt((tdHourEl && tdHourEl.value) as string, 10);
    var tdMin = parseInt((tdMinEl && tdMinEl.value) as string, 10);
    if (isNaN(tdHour) || tdHour < 0 || tdHour > 23) { showStatus(t("scopes.error.digest_hour"), "err"); return; }
    if (isNaN(tdMin) || tdMin < 0 || tdMin > 59) { showStatus(t("scopes.error.digest_minute"), "err"); return; }
    var tdWindowDays = parseInt((tdWindowDaysEl && tdWindowDaysEl.value) || "7", 10);
    if (isNaN(tdWindowDays) || tdWindowDays < 1 || tdWindowDays > 30) {
        showStatus(t("scopes.error.threat_window_days"), "err"); return;
    }
    var payload = {
        name: name,
        description: description,
        digest_enabled: !!(enabledEl && enabledEl.checked),
        digest_hour: hour,
        digest_minute: minute,
        digest_timezone: (tzEl && tzEl.value || "Europe/Paris").trim(),
        digest_severity_min: (sevEl && sevEl.value) || "critical",
        digest_include_kev: !!(kevEl && kevEl.checked),
        digest_cvss_min: cvssVal,
        digest_epss_min: epssVal,
        threat_digest_enabled: !!(tdEnEl && tdEnEl.checked),
        threat_digest_frequency: (tdFreqEl && tdFreqEl.value) || "weekly",
        threat_digest_weekday: parseInt((tdWdayEl && tdWdayEl.value) || "0", 10),
        threat_digest_hour: tdHour,
        threat_digest_minute: tdMin,
        threat_digest_timezone: (tdTzEl && tdTzEl.value || "Europe/Paris").trim(),
        threat_prompt: (tdPromptEl && tdPromptEl.value || "").trim(),
        threat_search_window_days: tdWindowDays,
    };
    try {
        if (id) {
            await WatchAPI.updateScope(id, payload);
            showStatus(t("scopes.saved"), "ok");
        } else {
            await WatchAPI.createScope(payload);
            showStatus(t("scopes.created"), "ok");
        }
        _closeModal();
        await _renderScopes(document.getElementById("content")!);
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

async function confirmDeleteScope(id: string): Promise<void> {
    if (!confirm(t("scopes.confirm_delete"))) return;
    try {
        await WatchAPI.deleteScope(id);
        showStatus(t("scopes.deleted"), "ok");
        _closeModal();
        await _renderScopes(document.getElementById("content")!);
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

function _validEmail(v: string): boolean {
    v = (v || "").trim().toLowerCase();
    if (v.length < 3 || v.indexOf("@") < 1 || v.split("@").length !== 2) return false;
    var domain = v.split("@")[1];
    return !!domain && domain.indexOf(".") > 0;
}

function onRecipientInputChange(scopeId: string, val: string): void {
    var box = document.getElementById("scope-recipient-add-action");
    if (!box) return;
    var email = (val || "").trim().toLowerCase();
    if (!email) { box.innerHTML = ""; return; }
    if (!_validEmail(email)) {
        box.innerHTML = '<span class="ct-muted ct-text-meta">' + esc(t("scopes.modal.invalid_email")) + '</span>';
        return;
    }
    var match = _directory.find(function(u) { return (u.email || "").toLowerCase() === email; });
    var label: string, hint = "";
    if (match) {
        var name = ((match.prenom || "") + " " + (match.nom || "")).trim() || (match.name || email);
        label = t("scopes.modal.recipient_add_known").replace("{name}", name);
    } else {
        label = t("scopes.modal.recipient_add_external");
        hint = '<span class="ct-journal-sep ct-text-label ct-ml-2">' + esc(t("scopes.modal.external_hint")) + '</span>';
    }
    box.innerHTML = '<button class="ct-btn" data-variant="primary" data-size="xs" data-click="addRecipientToScope" data-args=\'' + _da(scopeId) + '\'>+ ' + esc(label) + '</button>' + hint;
}

async function addRecipientToScope(scopeId: string): Promise<void> {
    var inp = document.getElementById("scope-recipient-input") as HTMLInputElement;
    var email = (inp.value || "").trim().toLowerCase();
    if (!_validEmail(email)) { showStatus(t("scopes.modal.invalid_email"), "err"); return; }
    // Try to find a name from directory cache.
    var name = "";
    var match = _directory.find(function(u) { return (u.email || "").toLowerCase() === email; });
    if (match) name = ((match.prenom || "") + " " + (match.nom || "")).trim() || (match.name || "");
    try {
        await WatchAPI.addRecipient(scopeId, { email: email, name: name });
        inp.value = "";
        var box = document.getElementById("scope-recipient-add-action");
        if (box) box.innerHTML = "";
        // Re-fetch the scope to refresh the chip list with server data.
        var s = await WatchAPI.getScope(scopeId);
        _renderRecipientsList(s);
        showStatus(t("scopes.recipient_added"), "ok");
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

async function removeRecipientFromScope(scopeId: string, email: string): Promise<void> {
    try {
        await WatchAPI.removeRecipient(scopeId, email);
        var s = await WatchAPI.getScope(scopeId);
        _renderRecipientsList(s);
        showStatus(t("scopes.recipient_removed"), "ok");
    } catch(e: any) {
        showStatus(e.message || t("error.generic"), "err");
    }
}

function _closeModal(): void {
    if (typeof ct_modal !== "undefined" && ct_modal.close) ct_modal.close();
}

// ═══════════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════════

function _boot(): void {
    _render();
}

// ═══════════════════════════════════════════════════════════════
// ALERTS PANEL (Phase 3)
// ═══════════════════════════════════════════════════════════════

var _alertFilters: WatchAlertFilters = { severity: "", status: "", source: "", scope_id: "", kev_only: false, q: "" };
var _alertSearchTimer: ReturnType<typeof setTimeout> | null = null;
var _alertsCache: WatchAlert[] = [];

function _sevBadge(sev: string | null | undefined): string {
    var colors: Record<string, string> = {
        critical: "#c0392b", high: "#e67e22", medium: "#f1c40f",
        low: "#95a5a6", unknown: "#bdc3c7"
    };
    var c = colors[(sev || "").toLowerCase()] || "#bdc3c7";
    return '<span style="display:inline-block;background:' + c + ';color:var(--ct-onsolid);padding:2px 8px;border-radius:10px;font-size:var(--ct-text-label);font-weight:600;text-transform:uppercase">' + esc(sev || "unknown") + '</span>';
}

async function _renderAlerts(c: HTMLElement): Promise<void> {
    // Load scopes for the scope-filter dropdown.
    if (!_scopes.length) {
        try { _scopes = await WatchAPI.listScopes() || []; } catch (e: any) { _scopes = []; }
    }

    // Paint the panel shell (header + filters + empty results zone) only
    // once — subsequent filter / search changes refresh `#alerts-rows-zone`
    // alone, which preserves <input> focus and caret position while the
    // user types. Previously we re-rendered the whole panel on every
    // keystroke and lost focus.
    var h = '';
    h += '<div class="panel-header ct-flex ct-items-center ct-row-between ct-mb-3 ct-py-0 ct-px-1 ct-row-wrap ct-gap-2">';
    h +=   '<h2 class="ct-m-0">' + esc(t("alerts.title")) + '</h2>';
    h +=   '<div class="ct-flex ct-gap-1 ct-items-center ct-row-wrap">';
    h +=     '<input type="search" id="alerts-search" data-input="onAlertSearch" data-pass-value="true" value="' + esc(_alertFilters.q || "") + '" placeholder="' + esc(t("alerts.filter.search_placeholder")) + '" class="ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-minw-220 ct-text-meta">';
    h +=     '<select data-change="setAlertFilter" data-args=\'["severity"]\' data-pass-value="true" class="ct-filter">';
    h +=       '<option value="">' + esc(t("alerts.filter.severity_all")) + '</option>';
    ["critical","high","medium","low","unknown"].forEach(function(s) {
        h += '<option value="' + s + '"' + (_alertFilters.severity === s ? ' selected' : '') + '>' + esc(s) + '</option>';
    });
    h +=     '</select>';
    h +=     '<select data-change="setAlertFilter" data-args=\'["status"]\' data-pass-value="true" class="ct-filter">';
    h +=       '<option value="">' + esc(t("alerts.filter.status_all")) + '</option>';
    ["new","ack","in_progress","dismissed","resolved"].forEach(function(s) {
        h += '<option value="' + s + '"' + (_alertFilters.status === s ? ' selected' : '') + '>' + esc(t("alerts.status." + s)) + '</option>';
    });
    h +=     '</select>';
    h +=     '<select data-change="setAlertFilter" data-args=\'["source"]\' data-pass-value="true" class="ct-filter">';
    h +=       '<option value="">' + esc(t("alerts.filter.source_all")) + '</option>';
    ["nvd","osv","kev","certfr","cisa","cisa_ics","cert_eu","ncsc_uk"].forEach(function(s) {
        h += '<option value="' + s + '"' + (_alertFilters.source === s ? ' selected' : '') + '>' + esc(s) + '</option>';
    });
    h +=     '</select>';
    h +=     '<select data-change="setAlertFilter" data-args=\'["scope_id"]\' data-pass-value="true" class="ct-filter">';
    h +=       '<option value="">' + esc(t("alerts.filter.scope_all")) + '</option>';
    _scopes.forEach(function(sc) {
        h += '<option value="' + esc(sc.id) + '"' + (_alertFilters.scope_id === sc.id ? ' selected' : '') + '>' + esc(sc.name) + '</option>';
    });
    h +=     '</select>';
    h +=     '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1"><input type="checkbox" data-change="setAlertKev" data-pass-checked="true"' + (_alertFilters.kev_only ? ' checked' : '') + '> ' + esc(t("alerts.filter.kev_only")) + '</label>';
    h +=   '</div>';
    h += '</div>';
    h += '<div id="alerts-rows-zone"><div class="ct-p-6 ct-muted">' + esc(t("misc.loading")) + '</div></div>';

    c.innerHTML = h;
    await _refreshAlertsRows();
}

async function _refreshAlertsRows(): Promise<void> {
    var zone = document.getElementById("alerts-rows-zone");
    if (!zone) return;

    var rows: WatchAlert[] = [];
    try {
        rows = await WatchAPI.listAlerts({
            severity: _alertFilters.severity,
            status: _alertFilters.status,
            source: _alertFilters.source,
            scope_id: _alertFilters.scope_id,
            kev_only: _alertFilters.kev_only ? "true" : "",
            search: _alertFilters.q || ""
        }) || [];
    } catch (e: any) {
        zone.innerHTML = '<div class="empty-state ct-text-critical">'
            + esc(t("alerts.load_error")) + ' — ' + esc(e.message || "") + '</div>';
        return;
    }
    _alertsCache = rows;

    if (rows.length === 0) {
        zone.innerHTML = '<div class="empty-state">' + esc(t("alerts.empty")) + '</div>';
        return;
    }

    var h = '<table class="table">';
    h += '<thead><tr class="ct-bg-alt">';
    h +=   '<th class="ct-bulk-col" style="padding:var(--ct-s2);width:32px">'
        +    '<input type="checkbox" data-bulk-scope="watch-alerts" data-bulk-all'
        +    ' data-click="_watchAlertsBulkToggleAll" data-stop>'
        +  '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.source")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.id")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.title")) + '</th>';
    h +=   '<th class="ct-ta-c ct-p-2">' + esc(t("alerts.col.severity")) + '</th>';
    h +=   '<th class="ct-ta-c ct-p-2">CVSS</th>';
    h +=   '<th class="ct-ta-c ct-p-2">KEV</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.scopes")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.published")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("alerts.col.status")) + '</th>';
    h += '</tr></thead><tbody>';

    rows.forEach(function(a) {
        var scopes: Record<string, boolean> = {};
        (a.matches || []).forEach(function(m) { scopes[m.scope_name] = true; });
        var scopeList = Object.keys(scopes).join(", ");
        h += '<tr class="ct-border-top ct-clickable" data-click="openAlertDetail" data-args=\'["' + esc(a.id) + '"]\'>';
        h += '<td class="ct-bulk-col ct-p-2 ct-ta-c" data-stop>'
          +    '<input type="checkbox" data-bulk-scope="watch-alerts"'
          +    ' data-bulk-key="' + esc(a.id) + '"'
          +    ' data-click="_watchAlertsBulkToggle"'
          +    ' data-args=\'["' + esc(a.id) + '"]\' data-stop>'
          +  '</td>';
        h += '<td class="ct-p-2">' + esc(a.source) + '</td>';
        h += '<td class="ct-p-2 ct-mono ct-text-meta">' + esc(a.external_id) + '</td>';
        h += '<td style="padding:var(--ct-s2);max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(a.title) + '">' + esc(a.title) + '</td>';
        h += '<td class="ct-p-2 ct-ta-c">' + _sevBadge(a.severity) + '</td>';
        h += '<td class="ct-p-2 ct-ta-c">' + (a.cvss_score != null ? esc(a.cvss_score.toFixed(1)) : "—") + '</td>';
        h += '<td class="ct-p-2 ct-ta-c">' + (a.kev_listed ? '<span class="ct-text-critical ct-bold">!</span>' : "") + '</td>';
        h += '<td class="ct-p-2 ct-text-meta ct-ink-1">' + esc(scopeList) + '</td>';
        h += '<td class="ct-p-2 ct-text-meta ct-muted">' + esc(_fmtDate(a.published_at || a.ingested_at)) + '</td>';
        h += '<td class="ct-p-2 ct-text-meta">' + esc(t("alerts.status." + (a.status || "new"))) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';

    zone.innerHTML = h;

    // Wire ct_bulkbar — actions apply the per-user triage status to every
    // selected alert in a single backend call. Selection state lives in
    // ct_bulkbar and survives table re-renders (filter/search changes).
    if (window.ct_bulkbar) {
        ct_bulkbar.attach({
            scope: "watch-alerts",
            label: t("alerts.bulk.selected_n") || "{n} alerte(s) sélectionnée(s)",
            actions: [
                { id: "ack",        icon: "check", label: t("alerts.status.ack"),
                  variant: "primary", onClick: "_watchAlertsBulkSetStatus" },
                { id: "in_progress", icon: "edit", label: t("alerts.status.in_progress"),
                  variant: "primary", onClick: "_watchAlertsBulkSetStatus" },
                { id: "resolved",   icon: "check", label: t("alerts.status.resolved"),
                  variant: "success", onClick: "_watchAlertsBulkSetStatus" },
                { id: "dismissed",  icon: "x", label: t("alerts.status.dismissed"),
                  variant: "muted", onClick: "_watchAlertsBulkSetStatus" }
            ]
        });
        ct_bulkbar.update("watch-alerts");
    }
}

// Toggle one row's selection. `data-stop` on the wrapping <td> prevents
// the row's openAlertDetail click from also firing.
window._watchAlertsBulkToggle = function(alertId: string) {
    if (window.ct_bulkbar) ct_bulkbar.toggle("watch-alerts", alertId);
};

// Header checkbox: select/deselect every row currently in the DOM.
window._watchAlertsBulkToggleAll = function() {
    if (!window.ct_bulkbar) return;
    var boxes = document.querySelectorAll(
        'input[type="checkbox"][data-bulk-scope="watch-alerts"][data-bulk-key]'
    );
    var allBox = document.querySelector(
        'input[type="checkbox"][data-bulk-scope="watch-alerts"][data-bulk-all]'
    );
    var checked = allBox ? (allBox as HTMLInputElement).checked : true;
    var keys: string[] = [];
    if (checked) {
        for (var i = 0; i < boxes.length; i++) keys.push(boxes[i].getAttribute("data-bulk-key")!);
        ct_bulkbar.setSelection("watch-alerts", keys);
    } else {
        ct_bulkbar.clear("watch-alerts");
    }
};

// Bulk action dispatcher — same signature as appsec's _bulkAppsec*.
window._watchAlertsBulkSetStatus = function(scope: string, status: string) {
    if (!window.ct_bulkbar) return;
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    WatchAPI.bulkSetAlertStatus({ ids: ids, status: status }).then(function(r: any) {
        var label = t("alerts.status." + status) || status;
        var msg = (r.updated || 0) + " " + (t("alerts.bulk.applied") || "alerte(s) → ") + label;
        if (r.skipped) msg += " (" + r.skipped + " " + (t("alerts.bulk.skipped") || "ignorée(s)") + ")";
        if (typeof showStatus === "function") showStatus(msg);
        ct_bulkbar.clear(scope);
        _refreshAlertsRows();
    }).catch(function(e) {
        if (typeof showStatus === "function") showStatus("Erreur: " + (e.message || e), true);
    });
};

function setAlertFilter(field: string, val: string): void {
    (_alertFilters as any)[field] = val || "";
    _refreshAlertsRows();
}
function setAlertKev(val: string | boolean): void {
    _alertFilters.kev_only = !!(val === true || val === "true" || val === "on");
    _refreshAlertsRows();
}
function onAlertSearch(val: string): void {
    // Debounce so we don't spam the backend on every keystroke. 250 ms
    // gives a snappy feel without flooding ILIKE queries on 16K+ rows.
    // We refresh ONLY the table zone (#alerts-rows-zone) so the search
    // <input> stays in the DOM and keeps focus + caret position while the
    // user keeps typing.
    if (_alertSearchTimer) clearTimeout(_alertSearchTimer);
    _alertSearchTimer = setTimeout(function() {
        _alertFilters.q = (val || "").trim();
        _refreshAlertsRows();
    }, 250);
}

async function openAlertDetail(alertId: string): Promise<void> {
    var a: any;
    try {
        a = await WatchAPI.getAlert(alertId);
    } catch (e: any) {
        showStatus(e.message || t("error.generic"), "error");
        return;
    }
    // Best-effort cached analysis fetch (null if not yet generated).
    var analysis: WatchAnalysis | null = null;
    try { analysis = await WatchAPI.getAlertAnalysis(alertId); } catch (e: any) {}
    window._currentAlertId = alertId;
    window._currentAnalysis = analysis;
    var h = '';
    h += '<div class="ct-mb-2 ct-flex ct-items-center ct-gap-2 ct-row-wrap">';
    h +=   _sevBadge(a.severity);
    h +=   '<code class="ct-text-data">' + esc(a.source) + ':' + esc(a.external_id) + '</code>';
    if (a.kev_listed) h += '<span class="ct-kpi-tone ct-text-onsolid ct-py-1 ct-px-2 ct-r-lg ct-text-label ct-strong">KEV</span>';
    if (a.cvss_score != null) h += '<span class="ct-text-meta ct-ink-1">CVSS ' + esc(a.cvss_score.toFixed(1)) + '</span>';
    if (a.epss_score != null) h += '<span class="ct-text-meta ct-ink-1">EPSS ' + esc((a.epss_score * 100).toFixed(1)) + '%</span>';
    h += '</div>';
    h += '<h3 style="margin:0 0 var(--ct-s2) 0">' + esc(a.title) + '</h3>';
    if (a.summary) {
        h += '<p style="white-space:pre-wrap;color:var(--ct-ink-1);line-height:1.5;max-height:240px;overflow-y:auto;background:var(--ct-surface-2);padding:var(--ct-s2);border-radius:var(--ct-r-sm)">' + esc(a.summary) + '</p>';
    }
    // SBOM impact placeholder — filled asynchronously after modal is shown.
    h += '<div class="ct-mt-3 ct-mb-1 ct-strong">' + esc(t("alerts.detail.sbom_impact")) + '</div>';
    h += '<div id="alert-sbom-body" class="ct-bg-alt ct-bordered ct-r-sm ct-p-2 ct-minh-40 ct-text-data">';
    h +=   '<div class="ct-muted">' + esc(t("misc.loading")) + '</div>';
    h += '</div>';
    h += '<div class="ct-mt-3 ct-mb-1 ct-strong">' + esc(t("alerts.detail.matches")) + '</div>';
    if (!a.matches || !a.matches.length) {
        h += '<div class="ct-muted">' + esc(t("alerts.detail.no_matches")) + '</div>';
    } else {
        h += '<table class="ct-journal-body ct-collapse ct-mb-3">';
        a.matches.forEach(function(m: any) {
            h += '<tr class="ct-border-top"><td class="ct-p-1">' + esc(m.scope_name) + '</td><td class="ct-p-1 ct-mono ct-text-meta">' + esc(m.match_kind) + ':' + esc(m.match_value) + '</td><td class="ct-p-1 ct-muted ct-text-meta">' + esc(m.target_label || "") + '</td></tr>';
        });
        h += '</table>';
    }
    // AI analysis section (cached or generate-on-demand).
    h += '<div style="margin:var(--ct-s3) 0 var(--ct-s1) 0;display:flex;align-items:center;justify-content:space-between">';
    h +=   '<div class="ct-strong">' + esc(t("alerts.detail.analysis")) + '</div>';
    h +=   '<div>';
    h +=     '<button class="ct-btn ct-text-meta" data-click="runAlertAnalysis">' + esc(analysis ? t("alerts.detail.analyze_refresh") : t("alerts.detail.analyze")) + '</button>';
    h +=   '</div>';
    h += '</div>';
    h += '<div id="alert-analysis-body" class="ct-bg-alt ct-bordered ct-r-sm ct-p-2 ct-minh-40 ct-text-data">';
    if (analysis && analysis.sections) {
        var labels: Record<string, string> = {
            executive_summary: t("alerts.detail.exec_summary"),
            technical_detail: t("alerts.detail.technical"),
            exploitation_status: t("alerts.detail.exploit"),
            affected_components: t("alerts.detail.affected"),
            business_impact: t("alerts.detail.impact"),
            recommended_actions: t("alerts.detail.actions"),
            references_curated: t("alerts.detail.refs_curated"),
            confidence: t("alerts.detail.confidence")
        };
        ["executive_summary","technical_detail","exploitation_status","affected_components","business_impact","recommended_actions","references_curated","confidence"].forEach(function(k) {
            var v = analysis!.sections![k] || "";
            if (!v) return;
            h += '<div class="ct-mb-1"><span class="ct-muted ct-strong">' + esc(labels[k] || k) + ':</span> ' + esc(v) + '</div>';
        });
        h += '<div class="ct-mt-2 ct-muted ct-text-meta">' + esc(analysis.provider) + ' / ' + esc(analysis.model) + ' — ' + esc(_fmtDate(analysis.generated_at)) + '</div>';
    } else {
        h += '<div class="ct-muted">' + esc(t("alerts.detail.no_analysis")) + '</div>';
    }
    h += '</div>';

    if (a.references_json && a.references_json.length) {
        h += '<div style="margin:var(--ct-s2) 0;font-weight:600">' + esc(t("alerts.detail.references")) + '</div>';
        h += '<ul style="margin:0 0 var(--ct-s3) 0;padding-left:20px;max-height:120px;overflow-y:auto">';
        a.references_json.forEach(function(r: any) {
            var url = String(r || "");
            if (!url) return;
            h += '<li class="ct-text-meta"><a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a></li>';
        });
        h += '</ul>';
    }
    h += '<div class="ct-mt-3 ct-mb-1 ct-strong">' + esc(t("alerts.detail.triage")) + '</div>';
    h += '<select id="alert-status-sel" style="padding:var(--ct-s1) var(--ct-s2);margin-right:var(--ct-s2)">';
    ["new","ack","in_progress","dismissed","resolved"].forEach(function(s) {
        h += '<option value="' + s + '"' + (a.status === s ? ' selected' : '') + '>' + esc(t("alerts.status." + s)) + '</option>';
    });
    h += '</select>';
    h += '<textarea id="alert-status-note" placeholder="' + esc(t("alerts.detail.note_ph")) + '" style="width:100%;height:80px;margin-top:var(--ct-s2);padding:var(--ct-s2);font-family:inherit">' + esc(a.note || "") + '</textarea>';

    ct_modal.open({
        title: esc(a.source) + ":" + esc(a.external_id),
        body: h,
        size: "lg",
        buttons: [
            { id: "cancel", label: t("misc.close") },
            { id: "save", label: t("misc.save"), primary: true, result: function() {
                var status = (document.getElementById("alert-status-sel") as HTMLSelectElement).value;
                var note = (document.getElementById("alert-status-note") as HTMLTextAreaElement).value;
                return { status: status, note: note };
            }}
        ]
    }).then(async function(raw) {
        var res = raw as { status: string; note: string } | null;
        if (!res) return;
        try {
            await WatchAPI.setAlertStatus(a.id, { status: res.status, note: res.note });
            showStatus(t("alerts.status_saved"), "success");
            _render();
        } catch (e: any) {
            showStatus(e.message || t("error.generic"), "error");
        }
    });
    // Fire SBOM impact lookup after modal is in DOM.
    _fillSbomImpact(alertId);
}

async function _fillSbomImpact(alertId: string): Promise<void> {
    var body = document.getElementById("alert-sbom-body");
    if (!body) return;
    var data: any;
    try { data = await WatchAPI.getAlertSbomImpact(alertId); }
    catch (e: any) {
        body.innerHTML = '<div class="ct-muted">' + esc(t("alerts.detail.sbom_unavailable")) + '</div>';
        return;
    }
    if (!data || data.configured === false) {
        body.innerHTML = '<div class="ct-muted">' + esc(t("alerts.detail.sbom_not_configured")) + '</div>';
        return;
    }
    if (data.error) {
        body.innerHTML = '<div class="ct-muted">' + esc(t("alerts.detail.sbom_unavailable")) + '</div>';
        return;
    }
    var findings: any[] = data.matched_findings || [];
    var sbom: any[] = data.matched_sbom || [];
    var apps: string[] = data.applications || [];
    if (!findings.length && !sbom.length) {
        body.innerHTML = '<div class="ct-muted">' + esc(t("alerts.detail.sbom_none")) + '</div>';
        return;
    }
    var h = '';
    if (apps.length) {
        h += '<div class="ct-mb-2"><strong>' + esc(t("alerts.detail.sbom_apps")) + ':</strong> ' + apps.map(esc).join(", ") + '</div>';
    }
    if (findings.length) {
        h += '<div class="ct-mb-1 ct-strong ct-text-meta ct-muted">' + esc(t("alerts.detail.sbom_findings")) + ' (' + findings.length + ')</div>';
        h += '<table class="ct-journal-body ct-collapse ct-mb-2 ct-text-meta">';
        findings.slice(0, 20).forEach(function(f) {
            h += '<tr class="ct-border-top">';
            h +=   '<td class="ct-p-1">' + esc(f.application_name || f.application_id) + '</td>';
            h +=   '<td class="ct-p-1 ct-mono">' + esc(f.target || "") + '</td>';
            h +=   '<td class="ct-p-1">' + _sevBadge(f.severity || "") + '</td>';
            h +=   '<td class="ct-p-1 ct-muted">' + esc(f.status || "") + '</td>';
            h += '</tr>';
        });
        h += '</table>';
    }
    if (sbom.length) {
        h += '<div class="ct-mb-1 ct-strong ct-text-meta ct-muted">' + esc(t("alerts.detail.sbom_packages")) + ' (' + sbom.length + ')</div>';
        h += '<table class="ct-journal-body ct-collapse ct-text-meta">';
        sbom.slice(0, 20).forEach(function(s) {
            h += '<tr class="ct-border-top">';
            h +=   '<td class="ct-p-1">' + esc(s.application_name || s.application_id) + '</td>';
            h +=   '<td class="ct-p-1 ct-mono">' + esc(s.package_name) + '@' + esc(s.version || "?") + '</td>';
            h +=   '<td class="ct-p-1 ct-muted">' + esc(s.ecosystem || "") + '</td>';
            h += '</tr>';
        });
        h += '</table>';
        if (sbom.length > 20) {
            h += '<div class="ct-mt-1 ct-muted ct-text-label">' + esc(t("alerts.detail.sbom_more").replace("{n}", String(sbom.length - 20))) + '</div>';
        }
    }
    body.innerHTML = h;
}

async function runAlertAnalysis(): Promise<void> {
    var alertId = window._currentAlertId;
    if (!alertId) return;
    var body = document.getElementById("alert-analysis-body");
    if (body) body.innerHTML = '<div class="ct-muted">' + esc(t("alerts.detail.analyze_pending")) + '</div>';
    try {
        var analysis = await WatchAPI.analyzeAlert(alertId);
        // Re-render the modal to surface the new analysis cleanly.
        ct_modal.close();
        openAlertDetail(alertId);
    } catch (e: any) {
        if (body) body.innerHTML = '<div class="ct-text-critical">' + esc(e.message || t("error.generic")) + '</div>';
    }
}

// ═══════════════════════════════════════════════════════════════
// SOURCES PANEL (Phase 3 — read-only for users, run-now for admin)
// ═══════════════════════════════════════════════════════════════

async function _renderSources(c: HTMLElement): Promise<void> {
    c.innerHTML = '<div class="ct-p-6 ct-muted">' + esc(t("misc.loading")) + '</div>';
    var rows: any[] = [];
    try { rows = await WatchAPI.listFeeds() || []; }
    catch (e: any) {
        c.innerHTML = '<div class="empty-state ct-text-critical">'
            + esc(t("sources.load_error")) + ' — ' + esc(e.message || "") + '</div>';
        return;
    }

    var isAdmin = (window._currentUser && window._currentUser.role === "admin");
    var h = '';
    h += '<div class="panel-header ct-flex ct-items-center ct-row-between ct-mb-5 ct-py-0 ct-px-1">';
    h +=   '<h2 class="ct-m-0">' + esc(t("sources.title")) + '</h2>';
    h += '</div>';

    if (rows.length === 0) {
        h += '<div class="empty-state">' + esc(t("sources.empty")) + '</div>';
        c.innerHTML = h;
        return;
    }

    h += '<table class="table">';
    h += '<thead><tr class="ct-bg-alt">';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("sources.col.source")) + '</th>';
    h +=   '<th class="ct-ta-r ct-p-2" title="' + esc(t("sources.col.total_in_db_hint")) + '">' + esc(t("sources.col.total_in_db")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("sources.col.last_sync")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("sources.col.next_due")) + '</th>';
    h +=   '<th class="ct-ta-r ct-p-2" title="' + esc(t("sources.col.last_batch_hint")) + '">' + esc(t("sources.col.last_batch_new")) + '</th>';
    h +=   '<th class="ct-ta-r ct-p-2" title="' + esc(t("sources.col.last_batch_hint")) + '">' + esc(t("sources.col.last_batch_seen")) + '</th>';
    h +=   '<th class="ct-ta-l ct-p-2">' + esc(t("sources.col.last_error")) + '</th>';
    if (isAdmin) h += '<th class="ct-p-2"></th>';
    h += '</tr></thead><tbody>';
    rows.forEach(function(r) {
        h += '<tr class="ct-border-top">';
        h +=   '<td class="ct-p-2 ct-mono">' + esc(r.source) + '</td>';
        h +=   '<td class="ct-p-2 ct-ta-r ct-strong">' + esc(String(r.total_in_db || 0)) + '</td>';
        h +=   '<td class="ct-p-2 ct-text-meta ct-ink-1">' + esc(_fmtDate(r.last_success_at || r.last_sync_at)) + '</td>';
        h +=   '<td class="ct-p-2 ct-text-meta ct-ink-1">' + esc(_fmtDate(r.next_due_at)) + '</td>';
        h +=   '<td class="ct-p-2 ct-ta-r ct-muted">' + esc(String(r.items_new || 0)) + '</td>';
        h +=   '<td class="ct-p-2 ct-ta-r ct-muted">' + esc(String(r.items_seen || 0)) + '</td>';
        h +=   '<td class="ct-p-2 ct-text-meta ct-text-critical">' + esc(r.last_error || "") + '</td>';
        if (isAdmin) h += '<td class="ct-p-2"><button class="ct-btn" data-click="runFeedNow" data-args=\'["' + esc(r.source) + '"]\'>' + esc(t("sources.run_now")) + '</button></td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    c.innerHTML = h;
}

async function runFeedNow(source: string): Promise<void> {
    showStatus(t("sources.running") + " " + source + "…");
    try {
        await WatchAPI.runFeedNow(source);
        showStatus(t("sources.run_ok") + " " + source, "success");
        _render();
    } catch (e: any) {
        showStatus(e.message || t("error.generic"), "error");
    }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", _boot);
else _boot();
