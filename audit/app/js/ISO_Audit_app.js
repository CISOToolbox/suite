// ═══════════════════════════════════════════════════════════════════════
// ISO Audit — CONFIG & DATA
// ═══════════════════════════════════════════════════════════════════════
window.CT_CONFIG = {
    edition: "suite",
    module: "audit",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
    autosaveKey: "iso_audit_autosave",
    initDataVar: "ISO_AUDIT_INIT_DATA",
    labelKey: "audit.label",
    filePrefix: "ISO_Audit",
    getSociete: function (d) { return d && d.meta ? d.meta.name : ""; },
    getDate: function (d) { return d && d.meta ? d.meta.date : ""; }
};
// FEAT-36 — schema versioning (rev 1 = normalized baseline; bump + add a
// migration + archive a fixture whenever the exported data model changes).
window.SCHEMA_REV = 1;
let D = JSON.parse(JSON.stringify(window.ISO_AUDIT_INIT_DATA || {}));
const CONTROLS = window.ISO_AUDIT_CONTROLS || [];
const DOMAINS = window.ISO_AUDIT_DOMAINS || [];
const QUESTIONS = window.ISO_AUDIT_QUESTIONS || {};
window.AI_APP_CONFIG = {
    storagePrefix: "isoaudit",
    settingsExtraHTML: function () { return typeof _demoSettingsHTML === "function" ? _demoSettingsHTML() : ""; },
    onSettingsRendered: function () { if (typeof _wireDemoSettings === "function")
        _wireDemoSettings(); }
};
let _currentPanel = "dashboard";
// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════
const STATUS_MAP = {
    c: { label: function () { return t("audit.status.c"); }, color: "var(--ct-low)", tone: "low" },
    ncmaj: { label: function () { return t("audit.status.ncmaj"); }, color: "var(--ct-critical)", tone: "critical" },
    ncmin: { label: function () { return t("audit.status.ncmin"); }, color: "var(--ct-high)", tone: "high" },
    ps: { label: function () { return t("audit.status.ps"); }, color: "var(--ct-medium)", tone: "medium" },
    pp: { label: function () { return t("audit.status.pp"); }, color: "var(--ct-info)", tone: "info" },
    na: { label: function () { return t("audit.status.na"); }, color: "var(--ct-neutral)", tone: "neutral" }
};
function statusLabel(s) { return STATUS_MAP[s] ? STATUS_MAP[s].label() : ""; }
function statusColor(s) { return STATUS_MAP[s] ? STATUS_MAP[s].color : "var(--ct-neutral)"; }
function statusTone(s) { return STATUS_MAP[s] ? STATUS_MAP[s].tone : "neutral"; }
function getCtrl(id) { return CONTROLS.find(function (c) { return c.id === id; }); }
// Bilingual referential: control titles/descriptions, domain labels
// and audit questions follow the language via _rt / _locale.
function ctrlT(c) { return _rt(c, "t"); }
function ctrlDesc(c) { return _rt(c, "desc"); }
function domLabel(d) { return _rt(d, "label"); }
function ctrlQuestions(id) {
    var en = window.ISO_AUDIT_QUESTIONS_EN;
    if (_locale === "en" && en && en[id])
        return en[id];
    return QUESTIONS[id] || [];
}
var _EMPTY_FINDING = { status: "", preuve: "", constats: "", ecart_critere: "", ecart_constat: "", ecart_cause: "", ecart_action: "", images: [] };
function getFinding(id) {
    if (!D.findings[id])
        D.findings[id] = { status: "", preuve: "", constats: "", ecart_critere: "", ecart_constat: "", ecart_cause: "", ecart_action: "", images: [] };
    if (!D.findings[id].images)
        D.findings[id].images = [];
    return D.findings[id];
}
// Read-only variant — does not mutate D.findings (for exports)
function readFinding(id) {
    return D.findings[id] || _EMPTY_FINDING;
}
function domainControls(domainId) {
    return CONTROLS.filter(function (c) { return c.d === domainId; });
}
function isEcart(status) { return status === "ncmaj" || status === "ncmin" || status === "ps" || status === "pp"; }
/** Type guard: status counted in the stats (equivalent of the old `S[s] !== undefined`). */
function _isStatusKey(s) {
    return s === "c" || s === "ncmaj" || s === "ncmin" || s === "ps" || s === "pp" || s === "na";
}
// ═══════════════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════════════
function selectPanel(panelId) {
    _currentPanel = panelId;
    document.querySelector(".ct-rail, .sidebar")?.classList.remove("open");
    _updateSidebarAccordion(panelId);
    document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.remove("active"); });
    var panel = document.getElementById("panel-" + panelId);
    if (panel)
        panel.classList.add("active");
    if (panelId === "dashboard")
        renderDashboard();
    else if (panelId.startsWith("domain-"))
        renderDomain(panelId.replace("domain-", ""));
    else if (panelId === "docreview" && typeof renderDocReview === "function")
        renderDocReview();
    else if (panelId === "planning" && typeof renderPlanning === "function")
        renderPlanning();
    else if (panelId === "journal")
        renderJournal();
    else if (panelId === "measures" && typeof window._renderAuditMeasures === "function")
        window._renderAuditMeasures();
}
window.selectPanel = selectPanel;
// ═══════════════════════════════════════════════════════════════════════
// META FIELDS
// ═══════════════════════════════════════════════════════════════════════
function onMetaChange(field, val) {
    _saveState();
    D.meta[field] = val;
    if (field === "name")
        document.getElementById("header-subtitle").textContent = val;
    _autoSave();
    showStatus(t("audit.status.modified"));
}
window.onMetaChange = onMetaChange;
function renderMeta() {
    document.getElementById("header-subtitle").textContent = D.meta.name || "";
    // Update meta inputs
    var fields = ["name", "ref", "date", "auditor", "scope"];
    fields.forEach(function (f) {
        var el = document.getElementById("meta-" + f);
        if (el && el.value !== (D.meta[f] || ""))
            el.value = D.meta[f] || "";
    });
    var hdsEl = document.getElementById("meta-hds");
    if (hdsEl && hdsEl.value !== (D.meta.hds || "non"))
        hdsEl.value = D.meta.hds || "non";
}
// ═══════════════════════════════════════════════════════════════════════
// CONTROL RENDERING
// ═══════════════════════════════════════════════════════════════════════
function cardHTML(c, f) {
    var hasEcart = isEcart(f.status);
    var h = '<div class="ctrl-card" id="card-' + c.id + '">';
    // Header
    h += '<div class="ctrl-card-header">';
    h += '<span class="ctrl-id">' + esc(c.id) + '</span>';
    h += '<span class="ctrl-title">' + esc(ctrlT(c)) + '</span>';
    if (c.hds)
        h += '<span class="ctrl-hds">HDS</span>';
    h += '<div class="ctrl-actions">';
    if (ctrlQuestions(c.id).length)
        h += '<button class="btn-questions" data-click="toggleQuestions" data-args=\'' + _da(c.id) + '\'>' + t("audit.btn.questions") + '</button>';
    h += '</div>';
    h += '</div>';
    // Description
    h += '<div class="ctrl-desc">' + esc(ctrlDesc(c)) + '</div>';
    // Status buttons
    h += '<div class="status-bar">';
    ["c", "ncmaj", "ncmin", "ps", "pp", "na"].forEach(function (s) {
        h += '<div class="status-btn' + (f.status === s ? ' active' : '') + '" data-status="' + s + '" data-click="setStatus" data-args=\'' + _da(c.id, s) + '\'>' + statusLabel(s) + '</div>';
    });
    h += '</div>';
    // Fields
    h += '<div class="ctrl-fields">';
    h += '<div class="ctrl-field"><label>' + t("audit.field.preuve") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "preuve") + '\' data-pass-value>' + esc(f.preuve) + '</textarea></div>';
    h += '<div class="ctrl-field"><label>' + t("audit.field.constats") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "constats") + '\' data-pass-value>' + esc(f.constats) + '</textarea></div>';
    h += '</div>';
    // Ecart fields (only if NC/PS/PP)
    if (hasEcart) {
        h += '<div class="ecart-fields">';
        h += '<div class="ctrl-field"><label>' + t("audit.field.ecart_critere") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "ecart_critere") + '\' data-pass-value>' + esc(f.ecart_critere) + '</textarea></div>';
        h += '<div class="ctrl-field"><label>' + t("audit.field.ecart_constat") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "ecart_constat") + '\' data-pass-value>' + esc(f.ecart_constat) + '</textarea></div>';
        h += '<div class="ctrl-field"><label>' + t("audit.field.ecart_cause") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "ecart_cause") + '\' data-pass-value>' + esc(f.ecart_cause) + '</textarea></div>';
        h += '<div class="ctrl-field"><label>' + t("audit.field.ecart_action") + '</label><textarea data-change="setField" data-args=\'' + _da(c.id, "ecart_action") + '\' data-pass-value>' + esc(f.ecart_action) + '</textarea></div>';
        // Suite mode: corrective actions linked to this control (audit_api.js)
        if (typeof window._auditControlMeasuresHTML === "function")
            h += window._auditControlMeasuresHTML(c.id);
        h += '</div>';
    }
    // Questions panel
    if (ctrlQuestions(c.id).length) {
        h += '<div class="questions-panel" id="questions-' + c.id + '">';
        ctrlQuestions(c.id).forEach(function (q) {
            h += '<div class="question-item"><button class="btn-copy-q" data-click="copyQuestion" data-args=\'' + _da(q) + '\'>' + t("audit.btn.copy") + '</button><span>' + esc(q) + '</span></div>';
        });
        h += '</div>';
    }
    // Images container (rendered async by ISO_Audit_images.js)
    var imgCount = (f.images && f.images.length) || 0;
    h += '<div class="img-section">';
    h += '<div class="img-section-header">📷 ' + t("audit.images.title") + (imgCount > 0 ? ' (' + imgCount + ')' : '') + '</div>';
    h += '<div id="images-' + c.id.replace(/\./g, "-") + '"></div>';
    h += '</div>';
    h += '</div>';
    return h;
}
var _filterStatus = "";
var _filterHDS = "";
var _filterText = "";
function renderDomain(domainId) {
    var contentEl = document.getElementById("domain-" + domainId + "-content");
    if (!contentEl)
        return;
    var controls = domainControls(domainId);
    // Filters bar
    var h = '<div class="audit-filters-bar">';
    h += '<select class="filter-select" data-change="onFilterStatus" data-pass-value>';
    h += '<option value="">' + t("audit.filter.all_status") + '</option>';
    ["c", "ncmaj", "ncmin", "ps", "pp", "na"].forEach(function (s) {
        h += '<option value="' + s + '"' + (_filterStatus === s ? ' selected' : '') + '>' + statusLabel(s) + '</option>';
    });
    h += '<option value="_empty"' + (_filterStatus === "_empty" ? ' selected' : '') + '>' + t("audit.status.non_audite") + '</option>';
    h += '</select>';
    h += '<select class="filter-select" data-change="onFilterHDS" data-pass-value>';
    h += '<option value="">' + t("audit.filter.all_hds") + '</option>';
    h += '<option value="hds"' + (_filterHDS === "hds" ? ' selected' : '') + '>' + t("audit.filter.hds_only") + '</option>';
    h += '</select>';
    h += '<input class="filter-search" type="text" placeholder="' + esc(t("audit.filter.search")) + '" value="' + esc(_filterText) + '" data-change="onFilterText" data-pass-value>';
    h += '</div>';
    // Filtered controls
    var shown = 0;
    controls.forEach(function (c) {
        var f = getFinding(c.id);
        // Apply filters
        if (_filterStatus === "_empty" && f.status !== "")
            return;
        if (_filterStatus && _filterStatus !== "_empty" && f.status !== _filterStatus)
            return;
        if (_filterHDS === "hds" && !c.hds)
            return;
        if (_filterText) {
            var q = _filterText.toLowerCase();
            if (c.id.toLowerCase().indexOf(q) < 0 && ctrlT(c).toLowerCase().indexOf(q) < 0 && ctrlDesc(c).toLowerCase().indexOf(q) < 0 && (f.constats || "").toLowerCase().indexOf(q) < 0 && (f.preuve || "").toLowerCase().indexOf(q) < 0)
                return;
        }
        h += cardHTML(c, f);
        shown++;
    });
    h += '<div class="filter-count">' + t("audit.filter.count", { shown: shown, total: controls.length }) + '</div>';
    contentEl.innerHTML = h;
    // Render image thumbnails (async from IndexedDB)
    if (typeof renderImages === "function") {
        controls.forEach(function (c) { renderImages(c.id); });
    }
}
// ═══════════════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════════════
function setStatus(ctrlId, status) {
    _saveState();
    var f = getFinding(ctrlId);
    f.status = (f.status === status) ? "" : status; // Toggle
    _autoSave();
    logEntry("status", { ctrl: ctrlId, status: f.status });
    // Re-render current domain
    if (_currentPanel.startsWith("domain-"))
        renderDomain(_currentPanel.replace("domain-", ""));
    updateSidebarBadges();
    showStatus(t("audit.status.status_changed", { ctrl: ctrlId, status: statusLabel(f.status) || t("audit.status.non_audite") }));
}
window.setStatus = setStatus;
function setField(ctrlId, field, val) {
    var f = getFinding(ctrlId);
    f[field] = val;
    _autoSave();
    logEntry("field", { ctrl: ctrlId, field: field });
}
window.setField = setField;
function onFilterStatus(val) { _filterStatus = val; if (_currentPanel.startsWith("domain-"))
    renderDomain(_currentPanel.replace("domain-", "")); }
function onFilterHDS(val) { _filterHDS = val; if (_currentPanel.startsWith("domain-"))
    renderDomain(_currentPanel.replace("domain-", "")); }
function onFilterText(val) { _filterText = val; if (_currentPanel.startsWith("domain-"))
    renderDomain(_currentPanel.replace("domain-", "")); }
window.onFilterStatus = onFilterStatus;
window.onFilterHDS = onFilterHDS;
window.onFilterText = onFilterText;
function toggleQuestions(ctrlId) {
    var panel = document.getElementById("questions-" + ctrlId);
    if (panel)
        panel.classList.toggle("open");
}
window.toggleQuestions = toggleQuestions;
function copyQuestion(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
        showStatus(t("audit.btn.copy") + " ✓");
    }
}
window.copyQuestion = copyQuestion;
// ═══════════════════════════════════════════════════════════════════════
// SIDEBAR BADGES
// ═══════════════════════════════════════════════════════════════════════
function updateSidebarBadges() {
    DOMAINS.forEach(function (dom) {
        var badge = document.getElementById("badge-" + dom.id);
        if (!badge)
            return;
        var controls = domainControls(dom.id);
        var audited = controls.filter(function (c) { return getFinding(c.id).status !== ""; }).length;
        badge.textContent = audited + "/" + controls.length;
        badge.className = "sidebar-badge" + (audited === controls.length && controls.length > 0 ? " complete" : "");
    });
}
// ═══════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════
function computeStats() {
    var S = { total: CONTROLS.length, audited: 0, c: 0, ncmaj: 0, ncmin: 0, ps: 0, pp: 0, na: 0, score: 0, grade: "", gradeColor: "", domains: {} };
    CONTROLS.forEach(function (ctrl) {
        var f = getFinding(ctrl.id);
        if (f.status) {
            S.audited++;
            if (_isStatusKey(f.status))
                S[f.status]++;
        }
    });
    var scored = S.audited - S.na;
    S.score = scored > 0 ? Math.round(((S.c * 1 + S.pp * 0.75 + S.ps * 0.5 + S.ncmin * 0.25) / scored) * 100) : 0;
    S.grade = S.score >= 80 ? "A" : S.score >= 65 ? "B" : S.score >= 50 ? "C" : S.score >= 35 ? "D" : "E";
    S.gradeColor = S.score >= 65 ? "var(--ct-low)" : S.score >= 50 ? "var(--ct-medium)" : S.score >= 35 ? "var(--ct-high)" : "var(--ct-critical)";
    S.gradeTone = S.score >= 65 ? "low" : S.score >= 50 ? "medium" : S.score >= 35 ? "high" : "critical";
    // Per domain
    S.domains = {};
    DOMAINS.forEach(function (dom) {
        var ctrls = domainControls(dom.id);
        var ds = { total: ctrls.length, audited: 0, c: 0, ncmaj: 0, ncmin: 0, ps: 0, pp: 0, na: 0, score: 0 };
        ctrls.forEach(function (ctrl) {
            var f = getFinding(ctrl.id);
            if (f.status) {
                ds.audited++;
                if (_isStatusKey(f.status))
                    ds[f.status]++;
            }
        });
        var dsScored = ds.audited - ds.na;
        ds.score = dsScored > 0 ? Math.round(((ds.c * 1 + ds.pp * 0.75 + ds.ps * 0.5 + ds.ncmin * 0.25) / dsScored) * 100) : 0;
        S.domains[dom.id] = ds;
    });
    return S;
}
// ═══════════════════════════════════════════════════════════════════════
// DASHBOARD RENDERING (Enhanced)
// ═══════════════════════════════════════════════════════════════════════
function renderDashboard() {
    renderMeta();
    var S = computeStats();
    var el = document.getElementById("dashboard-content");
    if (!el)
        return;
    var h = '';
    // KPI boxes row
    function kpi(val, label, tone) {
        return '<div class="ct-kpi"' + (tone ? ' data-tone="' + tone + '" data-emphasis="value"' : '')
            + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + label
            + '</div><div class="ct-kpi-value">' + val + '</div></div></div>';
    }
    h += '<div class="ct-kpigrid ct-mb-4">';
    h += kpi(S.total, t("audit.dash.total"));
    h += kpi(S.audited, t("audit.dash.audited"));
    h += kpi(S.c, t("audit.dash.conformes"), S.c > 0 ? "low" : undefined);
    h += kpi(S.ncmaj, t("audit.dash.nc_maj"), S.ncmaj > 0 ? "critical" : undefined);
    h += kpi(S.ncmin, t("audit.dash.nc_min"), S.ncmin > 0 ? "high" : undefined);
    h += kpi(S.ps, t("audit.dash.ps"), S.ps > 0 ? "medium" : undefined);
    h += kpi(S.pp, t("audit.dash.pp"), S.pp > 0 ? "info" : undefined);
    h += kpi(S.na, t("audit.dash.na"));
    h += kpi(S.score + '%', t("audit.dash.score"), S.gradeTone);
    h += kpi(S.grade, t("audit.dash.grade_level"), S.gradeTone);
    h += '</div>';
    // Generate report button (only if AI is enabled)
    if (typeof _aiIsEnabled === "function" && _aiIsEnabled()) {
        h += '<div style="margin-bottom:16px;text-align:right"><button class="btn-report" data-click="generateReport">' + t("audit.dash.generate_report") + '</button></div>';
    }
    // Charts row: Gauge + Donut + Radar (radar slightly enlarged)
    h += '<div class="dash-charts-grid">';
    h += '<div class="dash-card"><h3>' + t("audit.dash.gauge_title") + '</h3>';
    h += '<div class="dash-chart">' + buildGauge(S) + '</div>';
    h += '<div style="font-size:0.72em;color:var(--ct-ink-2);margin-top:6px">' + t("audit.dash.maturity_formula") + '</div>';
    h += '</div>';
    h += '<div class="dash-card"><h3>' + t("audit.dash.donut_title") + '</h3>';
    h += '<div class="dash-chart">' + buildDonut(S) + '</div>';
    h += '</div>';
    h += '<div class="dash-card dash-radar-card"><h3>' + t("audit.dash.radar_title") + '</h3>';
    h += '<div class="dash-chart">' + buildRadar(S) + '</div>';
    h += '</div>';
    h += '</div>';
    // Stacked bar chart per domain
    h += '<div class="dash-card" style="margin-bottom:16px"><h3>' + t("audit.dash.stacked_title") + '</h3>';
    h += buildStackedBars(S);
    h += '</div>';
    // Domain score bars
    h += '<div class="dash-card" style="margin-bottom:16px"><h3>' + t("audit.dash.by_domain") + '</h3>';
    h += buildDomainBars(S);
    h += '</div>';
    // HDS breakdown
    if (D.meta.hds === "oui" || D.meta.hds === "partiel") {
        h += '<div class="dash-card" style="margin-bottom:16px"><h3>' + t("audit.dash.hds_title") + '</h3>';
        h += buildHDSBreakdown(S);
        h += '</div>';
    }
    // NC table
    var ecarts = [];
    CONTROLS.forEach(function (c) {
        var f = getFinding(c.id);
        if (isEcart(f.status))
            ecarts.push({ ctrl: c, finding: f });
    });
    // Sort by severity: ncmaj first, then ncmin, ps, pp
    var sevOrder = { ncmaj: 0, ncmin: 1, ps: 2, pp: 3 };
    // BUG FIX (TS port): the original used `|| 9` — ncmaj (0, falsy) was
    // sorted last instead of first. `??` preserves the 0.
    ecarts.sort(function (a, b) { return (sevOrder[a.finding.status] ?? 9) - (sevOrder[b.finding.status] ?? 9); });
    if (ecarts.length > 0) {
        h += '<div class="dash-card"><h3>' + t("audit.dash.nc_table") + ' (' + ecarts.length + ')</h3>';
        h += '<table class="ct-table"><thead><tr><th>ID</th><th>' + t("audit.dash.nc_control") + '</th><th>Statut</th><th>' + t("audit.field.ecart_constat") + '</th><th>' + t("audit.field.ecart_action") + '</th></tr></thead><tbody>';
        ecarts.forEach(function (e) {
            h += '<tr><td><strong>' + esc(e.ctrl.id) + '</strong></td>';
            h += '<td>' + esc(ctrlT(e.ctrl)) + '</td>';
            h += '<td>' + badgeTone(statusLabel(e.finding.status), statusTone(e.finding.status)) + '</td>';
            h += '<td>' + esc(e.finding.ecart_constat || e.finding.constats || "") + '</td>';
            h += '<td>' + esc(e.finding.ecart_action || "") + '</td></tr>';
        });
        h += '</tbody></table></div>';
    }
    el.innerHTML = h;
}
// ═══════════════════════════════════════════════════════════════════════
// GAUGE SVG
// ═══════════════════════════════════════════════════════════════════════
function buildGauge(S) {
    var score = S.score;
    var r = 75, cx = 110, cy = 90, sw = 14;
    var startAngle = -Math.PI;
    var endAngle = 0;
    var angle = startAngle + (endAngle - startAngle) * (score / 100);
    var bgX1 = cx + r * Math.cos(startAngle), bgY1 = cy + r * Math.sin(startAngle);
    var fgX = cx + r * Math.cos(angle), fgY = cy + r * Math.sin(angle);
    var la = (angle - startAngle) > Math.PI ? 1 : 0;
    // Tick marks
    var ticks = "";
    [0, 25, 50, 75, 100].forEach(function (tick) {
        var ta = startAngle + (endAngle - startAngle) * (tick / 100);
        var x1 = cx + (r - 8) * Math.cos(ta), y1 = cy + (r - 8) * Math.sin(ta);
        var x2 = cx + (r + 2) * Math.cos(ta), y2 = cy + (r + 2) * Math.sin(ta);
        ticks += '<line x1="' + x1.toFixed(1) + '" y1="' + y1.toFixed(1) + '" x2="' + x2.toFixed(1) + '" y2="' + y2.toFixed(1) + '" stroke="var(--ct-line)" stroke-width="1.5"/>';
    });
    var svg = '<svg viewBox="0 0 220 130">';
    // Background arc
    svg += '<path d="M' + bgX1.toFixed(1) + ' ' + bgY1.toFixed(1) + ' A ' + r + ' ' + r + ' 0 0 1 ' + (cx + r).toFixed(1) + ' ' + cy + '" fill="none" stroke="var(--ct-line)" stroke-width="' + sw + '" stroke-linecap="round"/>';
    // Score arc
    if (score > 0) {
        svg += '<path d="M' + bgX1.toFixed(1) + ' ' + bgY1.toFixed(1) + ' A ' + r + ' ' + r + ' 0 ' + la + ' 1 ' + fgX.toFixed(1) + ' ' + fgY.toFixed(1) + '" fill="none" stroke="' + S.gradeColor + '" stroke-width="' + sw + '" stroke-linecap="round"/>';
    }
    svg += ticks;
    svg += '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" font-size="22" font-weight="700" fill="' + S.gradeColor + '">' + score + '%</text>';
    svg += '<text x="' + cx + '" y="' + (cy + 14) + '" text-anchor="middle" font-size="10" fill="var(--ct-ink-2)">' + t("audit.dash.score") + '</text>';
    svg += '<text x="' + cx + '" y="' + (cy + 30) + '" text-anchor="middle" font-size="14" font-weight="600" fill="' + S.gradeColor + '">' + t("audit.dash.grade_level") + ' ' + S.grade + '</text>';
    svg += '</svg>';
    return svg;
}
// ═══════════════════════════════════════════════════════════════════════
// DONUT SVG (Enhanced with inner/outer ring)
// ═══════════════════════════════════════════════════════════════════════
function buildDonut(S) {
    var data = [
        { label: t("audit.status.c"), value: S.c, color: statusColor("c") },
        { label: t("audit.status.ncmaj"), value: S.ncmaj, color: statusColor("ncmaj") },
        { label: t("audit.status.ncmin"), value: S.ncmin, color: statusColor("ncmin") },
        { label: t("audit.status.ps"), value: S.ps, color: statusColor("ps") },
        { label: t("audit.status.pp"), value: S.pp, color: statusColor("pp") },
        { label: t("audit.status.na"), value: S.na, color: statusColor("na") }
    ].filter(function (d) { return d.value > 0; });
    var todo = S.total - S.audited;
    if (todo > 0)
        data.push({ label: t("audit.dash.non_audited"), value: todo, color: "var(--ct-line)" });
    if (data.length === 0)
        return '<div style="text-align:center;color:var(--ct-ink-2);padding:20px">&mdash;</div>';
    var total = data.reduce(function (sum, d) { return sum + d.value; }, 0);
    var cx = 80, cy = 80, outerR = 70, innerR = 42;
    var svg = '<svg viewBox="0 0 160 160">';
    var angle = -Math.PI / 2;
    data.forEach(function (d) {
        var a = (d.value / total) * 2 * Math.PI;
        if (a < 0.01) {
            angle += a;
            return;
        }
        var x1 = cx + outerR * Math.cos(angle), y1 = cy + outerR * Math.sin(angle);
        var x2 = cx + outerR * Math.cos(angle + a), y2 = cy + outerR * Math.sin(angle + a);
        var xi1 = cx + innerR * Math.cos(angle), yi1 = cy + innerR * Math.sin(angle);
        var xi2 = cx + innerR * Math.cos(angle + a), yi2 = cy + innerR * Math.sin(angle + a);
        var la = a > Math.PI ? 1 : 0;
        svg += '<path d="M' + x1.toFixed(2) + ' ' + y1.toFixed(2) + ' A ' + outerR + ' ' + outerR + ' 0 ' + la + ' 1 ' + x2.toFixed(2) + ' ' + y2.toFixed(2) + ' L ' + xi2.toFixed(2) + ' ' + yi2.toFixed(2) + ' A ' + innerR + ' ' + innerR + ' 0 ' + la + ' 0 ' + xi1.toFixed(2) + ' ' + yi1.toFixed(2) + ' Z" fill="' + d.color + '" opacity="0.85"/>';
        angle += a;
    });
    svg += '<circle cx="' + cx + '" cy="' + cy + '" r="38" fill="var(--ct-surface)"/>';
    svg += '<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" font-size="18" font-weight="700" fill="var(--ct-ink)">' + S.audited + '</text>';
    svg += '<text x="' + cx + '" y="' + (cy + 12) + '" text-anchor="middle" font-size="8" fill="var(--ct-ink-2)">' + t("audit.dash.audited").toUpperCase() + '</text>';
    svg += '</svg>';
    // Legend
    svg += '<div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-top:8px">';
    data.forEach(function (d) {
        svg += '<span style="font-size:0.72em"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + d.color + ';margin-right:3px"></span>' + esc(d.label) + ' ' + d.value + '</span>';
    });
    svg += '</div>';
    return svg;
}
// ═══════════════════════════════════════════════════════════════════════
// RADAR CHART SVG (Feature 3)
// ═══════════════════════════════════════════════════════════════════════
function buildRadar(S) {
    var size = 500;
    var cx = size / 2, cy = size / 2;
    var r = size * 0.28;
    var n = DOMAINS.length;
    var levels = 4;
    function polarToXY(idx, radius) {
        var angle = (2 * Math.PI * idx) / n - Math.PI / 2;
        return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
    }
    var svg = '<svg viewBox="0 0 ' + size + ' ' + size + '" class="radar-svg">';
    // Grid polygons
    for (var l = 1; l <= levels; l++) {
        var lr = r * (l / levels);
        var pts = '';
        for (var i = 0; i < n; i++) {
            var p = polarToXY(i, lr);
            pts += (i === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1);
        }
        svg += '<path d="' + pts + 'Z" fill="none" stroke="var(--ct-line)" stroke-width="0.5"/>';
        // Level label on first axis
        var lp = polarToXY(0, lr);
        svg += '<text x="' + (lp.x + 4).toFixed(1) + '" y="' + (lp.y + 3).toFixed(1) + '" font-size="7" fill="var(--ct-ink-2)">' + (l * 25) + '%</text>';
    }
    // Axes
    for (var i = 0; i < n; i++) {
        var p = polarToXY(i, r);
        svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + p.x.toFixed(1) + '" y2="' + p.y.toFixed(1) + '" stroke="var(--ct-line)" stroke-width="0.5"/>';
    }
    // Data polygon
    var dpts = '';
    DOMAINS.forEach(function (dom, idx) {
        var ds = S.domains[dom.id];
        var val = ds && ds.score > 0 ? ds.score / 100 : 0;
        var p = polarToXY(idx, r * val);
        dpts += (idx === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1);
    });
    svg += '<path d="' + dpts + 'Z" fill="var(--ct-accent-tint)" stroke="var(--ct-accent)" stroke-width="1.5"/>';
    // Data points and labels
    DOMAINS.forEach(function (dom, idx) {
        var ds = S.domains[dom.id];
        var val = ds && ds.score > 0 ? ds.score / 100 : 0;
        var p = polarToXY(idx, r * val);
        svg += '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="3" fill="var(--ct-accent)"/>';
        // Label — domain name
        var labelR = r + 35;
        var lp = polarToXY(idx, labelR);
        var anchor = lp.x < cx - 10 ? "end" : lp.x > cx + 10 ? "start" : "middle";
        svg += '<text x="' + lp.x.toFixed(1) + '" y="' + (lp.y + 4).toFixed(1) + '" text-anchor="' + anchor + '" font-size="11" fill="var(--ct-ink-2)" font-weight="600">' + esc(domLabel(dom)) + '</text>';
        // Score % near point
        if (val > 0) {
            var sp = polarToXY(idx, r * val + 12);
            svg += '<text x="' + sp.x.toFixed(1) + '" y="' + (sp.y - 2).toFixed(1) + '" text-anchor="middle" font-size="7" fill="var(--ct-accent)" font-weight="500">' + ds.score + '%</text>';
        }
    });
    svg += '</svg>';
    return svg;
}
// ═══════════════════════════════════════════════════════════════════════
// STACKED BAR CHART
// ═══════════════════════════════════════════════════════════════════════
function buildStackedBars(S) {
    var h = '';
    DOMAINS.forEach(function (dom) {
        var ds = S.domains[dom.id];
        if (!ds)
            return;
        var total = ds.total || 1;
        var segs = [
            { val: ds.c, color: statusColor("c") },
            { val: ds.pp, color: statusColor("pp") },
            { val: ds.ps, color: statusColor("ps") },
            { val: ds.ncmin, color: statusColor("ncmin") },
            { val: ds.ncmaj, color: statusColor("ncmaj") },
            { val: ds.na, color: statusColor("na") },
            { val: ds.total - ds.audited, color: "var(--ct-line)" }
        ];
        h += '<div class="stacked-row">';
        h += '<div class="stacked-label">' + esc(domLabel(dom)) + ' <span style="color:var(--ct-ink-2);font-size:0.85em">' + ds.total + ' mesures</span></div>';
        h += '<div class="stacked-track">';
        segs.forEach(function (seg) {
            if (seg.val > 0)
                h += '<div class="stacked-seg" style="width:' + (seg.val / total * 100).toFixed(1) + '%;background:' + seg.color + '"></div>';
        });
        h += '</div></div>';
    });
    return h;
}
// ═══════════════════════════════════════════════════════════════════════
// HDS BREAKDOWN
// ═══════════════════════════════════════════════════════════════════════
function buildHDSBreakdown(S) {
    var hds = { total: 0, c: 0, nc: 0, other: 0 };
    var nonhds = { total: 0, c: 0, nc: 0, other: 0 };
    CONTROLS.forEach(function (ctrl) {
        var f = getFinding(ctrl.id);
        var target = ctrl.hds ? hds : nonhds;
        target.total++;
        if (f.status === "c")
            target.c++;
        else if (f.status === "ncmaj" || f.status === "ncmin")
            target.nc++;
        else if (f.status)
            target.other++;
    });
    var h = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">';
    h += buildHDSBar(hds, "HDS (" + hds.total + ")");
    h += buildHDSBar(nonhds, "Non-HDS (" + nonhds.total + ")");
    h += '</div>';
    return h;
}
function buildHDSBar(F, label) {
    var total = F.total || 1;
    var rows = [
        { l: t("audit.dash.hds_conformes"), v: F.c, color: statusColor("c") },
        { l: t("audit.dash.hds_nc"), v: F.nc, color: statusColor("ncmaj") },
        { l: t("audit.dash.hds_other"), v: F.other, color: statusColor("ps") }
    ];
    var h = '<div><div style="font-weight:600;font-size:0.85em;margin-bottom:6px">' + esc(label) + '</div>';
    rows.forEach(function (r) {
        h += '<div class="hds-bar-row">';
        h += '<span class="hds-bar-label">' + esc(r.l) + '</span>';
        h += '<div class="hds-bar-track"><div class="hds-bar-fill" style="width:' + (r.v / total * 100).toFixed(1) + '%;background:' + r.color + '"></div></div>';
        h += '<span class="hds-bar-count" style="color:' + r.color + '">' + r.v + '</span>';
        h += '</div>';
    });
    h += '</div>';
    return h;
}
function buildDomainBars(S) {
    var h = '<div style="display:flex;flex-direction:column;gap:6px">';
    DOMAINS.forEach(function (dom) {
        var ds = S.domains[dom.id];
        if (!ds)
            return;
        var scorePct = ds.score;
        var scoreColor = scorePct >= 80 ? "var(--ct-low)" : scorePct >= 50 ? "var(--ct-medium)" : "var(--ct-critical)";
        h += '<div style="display:flex;align-items:center;gap:8px;font-size:0.8em">';
        h += '<span style="min-width:160px;font-weight:600">' + esc(domLabel(dom)) + '</span>';
        h += '<div style="flex:1;height:16px;background:var(--ct-surface-2);border-radius:8px;overflow:hidden;position:relative">';
        if (ds.c > 0)
            h += '<div style="position:absolute;height:100%;width:' + (ds.c / ds.total * 100) + '%;background:var(--ct-low)"></div>';
        if (ds.ncmaj > 0)
            h += '<div style="position:absolute;height:100%;left:' + (ds.c / ds.total * 100) + '%;width:' + (ds.ncmaj / ds.total * 100) + '%;background:var(--ct-critical)"></div>';
        if (ds.ncmin > 0)
            h += '<div style="position:absolute;height:100%;left:' + ((ds.c + ds.ncmaj) / ds.total * 100) + '%;width:' + (ds.ncmin / ds.total * 100) + '%;background:var(--ct-high)"></div>';
        if (ds.ps > 0)
            h += '<div style="position:absolute;height:100%;left:' + ((ds.c + ds.ncmaj + ds.ncmin) / ds.total * 100) + '%;width:' + (ds.ps / ds.total * 100) + '%;background:var(--ct-medium)"></div>';
        if (ds.pp > 0)
            h += '<div style="position:absolute;height:100%;left:' + ((ds.c + ds.ncmaj + ds.ncmin + ds.ps) / ds.total * 100) + '%;width:' + (ds.pp / ds.total * 100) + '%;background:var(--ct-info)"></div>';
        h += '</div>';
        h += '<span style="min-width:40px;text-align:right;font-weight:600;color:' + scoreColor + '">' + scorePct + '%</span>';
        h += '</div>';
    });
    h += '</div>';
    return h;
}
// ═══════════════════════════════════════════════════════════════════════
// JOURNAL
// ═══════════════════════════════════════════════════════════════════════
function logEntry(type, data) {
    if (!D.journal)
        D.journal = [];
    D.journal.unshift({
        ts: new Date().toISOString(),
        type: type,
        author: D.meta.auditor || "",
        data: data
    });
    if (D.journal.length > 2000)
        D.journal.length = 2000;
}
function renderJournal() {
    var el = document.getElementById("journal-content");
    if (!el)
        return;
    if (!D.journal || D.journal.length === 0) {
        el.innerHTML = '<div style="color:var(--ct-ink-2);text-align:center;padding:20px">' + t("audit.journal.empty") + '</div>';
        return;
    }
    var h = '';
    D.journal.forEach(function (entry) {
        var d = new Date(entry.ts);
        var time = d.toLocaleDateString(_locale === "en" ? "en-GB" : "fr-FR") + " " + d.toLocaleTimeString(_locale === "en" ? "en-GB" : "fr-FR", { hour: "2-digit", minute: "2-digit" });
        var typeLabel = t("audit.journal.type_" + entry.type) || entry.type;
        var typeColor = entry.type === "status" ? "var(--ct-info)" : entry.type === "field" ? "var(--ct-neutral)" : entry.type === "create" ? "var(--ct-low)" : "var(--ct-ink-2)";
        var text = "";
        if (entry.data) {
            if (entry.data.ctrl)
                text += entry.data.ctrl;
            if (entry.data.status)
                text += " → " + statusLabel(entry.data.status);
            if (entry.data.field)
                text += "." + entry.data.field;
        }
        h += '<div class="journal-entry">';
        h += '<span class="journal-time">' + esc(time) + '</span>';
        h += '<span class="journal-type" style="background:' + typeColor + ';color:white">' + esc(typeLabel) + '</span>';
        h += '<span class="journal-text">' + esc(text) + '</span>';
        if (entry.author)
            h += '<span style="font-size:0.8em;color:var(--ct-ink-2)">' + esc(entry.author) + '</span>';
        h += '</div>';
    });
    el.innerHTML = h;
}
// ═══════════════════════════════════════════════════════════════════════
// GLOBAL SEARCH (Feature 1 — Ctrl+K)
// ═══════════════════════════════════════════════════════════════════════
var _searchScope = "all";
function openSearch() {
    var overlay = document.getElementById("search-overlay");
    if (!overlay)
        return;
    overlay.classList.add("open");
    var inp = document.getElementById("search-input");
    if (inp) {
        inp.value = "";
        inp.focus();
    }
    document.getElementById("search-results").innerHTML = '<div class="search-no-results">' + t("audit.search.type_to_search") + '</div>';
    document.getElementById("search-count").textContent = "";
}
window.openSearch = openSearch;
function closeSearch() {
    var overlay = document.getElementById("search-overlay");
    if (overlay)
        overlay.classList.remove("open");
}
window.closeSearch = closeSearch;
function onSearchScope(val) {
    _searchScope = val;
    onSearchInput(document.getElementById("search-input").value || "");
}
window.onSearchScope = onSearchScope;
function onSearchInput(val) {
    var q = (val || "").toLowerCase().trim();
    var resultsEl = document.getElementById("search-results");
    var countEl = document.getElementById("search-count");
    if (!q || q.length < 2) {
        resultsEl.innerHTML = '<div class="search-no-results">' + t("audit.search.type_to_search") + '</div>';
        countEl.textContent = "";
        return;
    }
    var results = [];
    var reEscape = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var re = new RegExp('(' + reEscape + ')', 'gi');
    CONTROLS.forEach(function (ctrl) {
        var f = D.findings[ctrl.id] || {};
        // Filter by scope
        if (_searchScope === "nc" && f.status !== "ncmaj" && f.status !== "ncmin")
            return;
        var fields = [];
        if (_searchScope === "all") {
            fields.push({ k: "Mesure", v: ctrl.t || "" });
            fields.push({ k: "Description", v: ctrl.desc || "" });
            fields.push({ k: "ID", v: ctrl.id || "" });
        }
        if (_searchScope === "all" || _searchScope === "findings" || _searchScope === "nc") {
            fields.push({ k: "Preuves", v: f.preuve || "" });
            fields.push({ k: "Constats", v: f.constats || "" });
            fields.push({ k: "Constat écart", v: f.ecart_constat || "" });
            fields.push({ k: "Cause", v: f.ecart_cause || "" });
            fields.push({ k: "Action", v: f.ecart_action || "" });
            fields.push({ k: "Critère", v: f.ecart_critere || "" });
        }
        var matchField = null, matchVal = "";
        for (var i = 0; i < fields.length; i++) {
            if (fields[i].v.toLowerCase().indexOf(q) >= 0) {
                matchField = fields[i].k;
                matchVal = fields[i].v;
                break;
            }
        }
        if (!matchField)
            return;
        // Build snippet
        var idx = matchVal.toLowerCase().indexOf(q);
        var start = Math.max(0, idx - 30);
        var end = Math.min(matchVal.length, idx + q.length + 50);
        var snippet = (start > 0 ? "..." : "") + matchVal.substring(start, end) + (end < matchVal.length ? "..." : "");
        // Escape then highlight
        var safeSnippet = esc(snippet).replace(re, '<mark>$1</mark>');
        results.push({ ctrl: ctrl, f: f, matchField: matchField, snippet: safeSnippet });
    });
    countEl.textContent = t("audit.search.count", { count: results.length });
    if (!results.length) {
        resultsEl.innerHTML = '<div class="search-no-results">' + t("audit.search.no_results") + '</div>';
        return;
    }
    var h = "";
    var shown = Math.min(results.length, 50);
    for (var i = 0; i < shown; i++) {
        var r = results[i];
        var statusH = "";
        if (r.f.status && STATUS_MAP[r.f.status]) {
            statusH = '<span class="ct-badge" data-tone="' + statusTone(r.f.status) + '" style="margin-left:6px">' + esc(statusLabel(r.f.status)) + '</span>';
        }
        h += '<div class="search-result-item" data-click="goToSearchResult" data-args=\'' + _da(r.ctrl.id) + '\'>';
        h += '<span class="search-result-id">' + esc(r.ctrl.id) + '</span>';
        h += '<div class="search-result-content">';
        h += '<div class="search-result-title">' + esc(ctrlT(r.ctrl)) + statusH + '</div>';
        h += '<div class="search-result-match"><em style="font-size:0.9em;color:var(--ct-ink-2)">' + esc(r.matchField) + '</em> — ' + r.snippet + '</div>';
        h += '</div></div>';
    }
    if (results.length > 50) {
        h += '<div style="text-align:center;padding:10px;font-size:0.78em;color:var(--ct-ink-2)">' + t("audit.search.more", { count: results.length - 50 }) + '</div>';
    }
    resultsEl.innerHTML = h;
}
window.onSearchInput = onSearchInput;
function goToSearchResult(ctrlId) {
    closeSearch();
    var ctrl = getCtrl(ctrlId);
    if (!ctrl)
        return;
    selectPanel("domain-" + ctrl.d);
    // Scroll to card after render
    setTimeout(function () {
        var card = document.getElementById("card-" + ctrlId);
        if (card)
            card.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 150);
}
window.goToSearchResult = goToSearchResult;
// Click outside search panel to close
document.addEventListener("click", function (e) {
    var overlay = document.getElementById("search-overlay");
    if (overlay && overlay.classList.contains("open") && e.target === overlay) {
        closeSearch();
    }
});
// Keyboard shortcuts
document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        openSearch();
    }
    if (e.key === "Escape") {
        var overlay = document.getElementById("search-overlay");
        if (overlay && overlay.classList.contains("open")) {
            closeSearch();
        }
    }
    if (e.key === "Enter" && document.activeElement && document.activeElement.id === "search-input") {
        var first = document.querySelector(".search-result-item");
        if (first)
            first.click();
    }
});
// ═══════════════════════════════════════════════════════════════════════
// AI REPORT GENERATION (Feature 4)
// ═══════════════════════════════════════════════════════════════════════
function generateReport() {
    if (typeof _aiCallAPI !== "function" || typeof _aiEnsurePanel !== "function") {
        showStatus(t("audit.report.no_ai"));
        return;
    }
    // Check API key
    if (typeof _aiGetApiKey === "function" && !_aiGetApiKey()) {
        _aiShowError(t("audit.report.title"), t("audit.report.no_ai"));
        _aiOpenPanel(t("audit.report.title"));
        return;
    }
    var S = computeStats();
    // Build domain scores summary
    var domainLines = "";
    DOMAINS.forEach(function (dom) {
        var ds = S.domains[dom.id];
        domainLines += "- " + domLabel(dom) + " : " + ds.score + "% (" + ds.audited + "/" + ds.total + " audités)\n";
    });
    // Build NC details
    var ncLines = "";
    CONTROLS.forEach(function (c) {
        var f = getFinding(c.id);
        if (f.status === "ncmaj" || f.status === "ncmin") {
            ncLines += "- [" + f.status.toUpperCase() + "] " + c.id + " " + ctrlT(c) + "\n";
            if (f.ecart_constat)
                ncLines += "  Constat: " + f.ecart_constat + "\n";
            if (f.ecart_cause)
                ncLines += "  Cause: " + f.ecart_cause + "\n";
            if (f.ecart_action)
                ncLines += "  Action: " + f.ecart_action + "\n";
        }
    });
    var systemPrompt = "You are an ISO 27001 lead auditor writing a formal audit report in French. " +
        "Write a structured report with: executive summary, scope, methodology, key findings, non-conformities analysis, " +
        "recommendations, and conclusion. Use formal language. Replace actual client/auditor names with [CLIENT] and [AUDITOR].";
    var userPrompt = "Génère un rapport d'audit ISO 27001 basé sur ces données :\n\n" +
        "INFORMATIONS GÉNÉRALES:\n" +
        "- Client: [CLIENT]\n" +
        "- Référence: " + (D.meta.ref || "N/A") + "\n" +
        "- Date: " + (D.meta.date || "N/A") + "\n" +
        "- Auditeur: [AUDITOR]\n" +
        "- Périmètre: " + (D.meta.scope || "N/A") + "\n" +
        "- HDS: " + (D.meta.hds || "non") + "\n\n" +
        "STATISTIQUES GLOBALES:\n" +
        "- Total contrôles: " + S.total + "\n" +
        "- Audités: " + S.audited + "/" + S.total + "\n" +
        "- Conformes: " + S.c + "\n" +
        "- NC majeures: " + S.ncmaj + "\n" +
        "- NC mineures: " + S.ncmin + "\n" +
        "- Points sensibles: " + S.ps + "\n" +
        "- Pistes de progrès: " + S.pp + "\n" +
        "- N/A: " + S.na + "\n" +
        "- Score: " + S.score + "% (Grade " + S.grade + ")\n\n" +
        "SCORES PAR DOMAINE:\n" + domainLines + "\n" +
        "NON-CONFORMITÉS:\n" + (ncLines || "Aucune non-conformité identifiée.\n");
    _aiShowLoading(t("audit.report.title"));
    _aiOpenPanel(t("audit.report.title"));
    _aiCallAPI(systemPrompt, userPrompt).then(function (response) {
        if (!response) {
            _aiShowError(t("audit.report.title"), t("audit.report.error"));
            return;
        }
        window._lastAIReport = response;
        var p = _aiEnsurePanel();
        p.title.textContent = t("audit.report.title");
        p.body.innerHTML = '<div style="white-space:pre-wrap;font-size:0.88em;line-height:1.6;padding:8px">' + esc(response) + '</div>';
        p.footer.innerHTML = '<button class="ct-pwd-btn ct-pwd-ok" id="export-report-word" style="background:var(--ct-accent)">' + t("audit.report.export_word") + '</button>'
            + '<button class="ct-pwd-btn ct-pwd-ok" id="copy-report-btn">' + t("audit.report.copy") + '</button>';
        document.getElementById("copy-report-btn").onclick = function () {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(response);
                showStatus(t("audit.report.copied"));
            }
        };
        document.getElementById("export-report-word").onclick = function () {
            _exportAIReportAsWord(response);
        };
    }).catch(function (err) {
        _aiShowError(t("audit.report.title"), t("audit.report.error") + ": " + (err.message || err));
    });
}
window.generateReport = generateReport;
// Export functions are in ISO_Audit_export.js
function _exportAIReportAsWord(text) {
    // JSZip 3.10.1, vendored under js/vendor/ — same-origin, so the app CSP
    // keeps script-src 'self' with no CDN entry and the export works offline.
    _loadAsset("js/vendor/jszip.min.js", function () {
        var m = D.meta;
        function xmlEsc(s) { return (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
        function wp(txt, opts) {
            opts = opts || {};
            var sz = opts.sz || "22";
            var bold = opts.bold ? "<w:b/>" : "";
            var italic = opts.italic ? "<w:i/>" : "";
            var color = opts.color ? '<w:color w:val="' + opts.color + '"/>' : "";
            var align = opts.align ? '<w:jc w:val="' + opts.align + '"/>' : "";
            var spacing = '<w:spacing w:after="' + (opts.after || 120) + '" w:before="' + (opts.before || 0) + '"/>';
            return '<w:p><w:pPr>' + align + spacing + '</w:pPr><w:r><w:rPr>' + bold + italic + '<w:sz w:val="' + sz + '"/><w:szCs w:val="' + sz + '"/>' + color + '</w:rPr><w:t xml:space="preserve">' + xmlEsc(txt) + '</w:t></w:r></w:p>';
        }
        var body = "";
        // Cover
        body += wp("", { after: 600 });
        body += wp("Rapport d'audit ISO 27001", { sz: "48", bold: true, color: "2C3E50", align: "center", after: 40 });
        body += wp("Généré par l'assistant IA", { sz: "22", color: "999999", align: "center", italic: true, after: 400 });
        body += wp(m.name || "[Client]", { sz: "36", bold: true, align: "center", after: 60 });
        body += wp((m.ref || "") + " — " + (m.date || ""), { sz: "22", color: "666666", align: "center", after: 400 });
        body += '<w:p><w:r><w:br w:type="page"/></w:r></w:p>';
        // Convert AI text to Word paragraphs
        var lines = text.split("\n");
        lines.forEach(function (line) {
            var trimmed = line.trim();
            if (!trimmed) {
                body += wp("", { after: 60 });
            }
            else if (trimmed.match(/^#{3}\s/)) {
                var h3Text = trimmed.replace(/^#{3}\s+/, "");
                body += wp(h3Text, { sz: "24", bold: true, color: "3498DB", before: 200, after: 80 });
            }
            else if (trimmed.match(/^#{2}\s/)) {
                var h2Text = trimmed.replace(/^#{2}\s+/, "");
                body += wp(h2Text, { sz: "26", bold: true, color: "2C3E50", before: 240, after: 120 });
            }
            else if (trimmed.match(/^#\s/)) {
                var h1Text = trimmed.replace(/^#\s+/, "");
                body += wp(h1Text, { sz: "32", bold: true, color: "2C3E50", before: 360, after: 120 });
            }
            else if (trimmed.match(/^[-•]\s/)) {
                // Bullet point
                var bullet = "• " + trimmed.replace(/^[-•]\s+/, "");
                body += wp(bullet, { sz: "20", after: 60 });
            }
            else if (trimmed.match(/^\d+\.\s/)) {
                // Numbered item
                body += wp(trimmed, { sz: "20", after: 60 });
            }
            else if (trimmed.match(/^\*\*.+\*\*/)) {
                // Bold text
                var boldText = trimmed.replace(/\*\*/g, "");
                body += wp(boldText, { sz: "20", bold: true, after: 80 });
            }
            else {
                body += wp(trimmed, { sz: "20", after: 80 });
            }
        });
        // Build OOXML
        var ooxml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            + '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" mc:Ignorable="w14 wp14">'
            + "<w:body>"
            + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr>'
            + body
            + "</w:body></w:document>";
        var contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
        var rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
        var wordRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>';
        var fname = _safeFileName((m.ref || "audit") + "_rapport_IA") + ".docx";
        var zip = new JSZip();
        zip.file("[Content_Types].xml", contentTypes);
        zip.folder("_rels").file(".rels", rels);
        zip.folder("word").file("document.xml", ooxml);
        zip.folder("word/_rels").file("document.xml.rels", wordRels);
        zip.generateAsync({ type: "blob", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }).then(function (blob) {
            _downloadBlob(blob, fname);
            showStatus(t("audit.report.word_exported"));
        });
    });
}
// ═══════════════════════════════════════════════════════════════════════
// ENSURE KEYS (data migration)
// ═══════════════════════════════════════════════════════════════════════
function ensureKeys() {
    if (!D.meta)
        D.meta = {};
    var metaDefaults = { name: "", ref: "", date: "", auditor: "", scope: "", hds: "non" };
    var meta = D.meta;
    for (var k in metaDefaults) {
        if (!(k in meta))
            meta[k] = metaDefaults[k];
    }
    if (!D.findings)
        D.findings = {};
    if (!D.doc_review)
        D.doc_review = {};
    if (!D.journal)
        D.journal = [];
    if (!D.timers)
        D.timers = {};
    if (!D.planning)
        D.planning = { params: {}, slots: [] };
}
// ═══════════════════════════════════════════════════════════════════════
// SNAPSHOTS / HISTORY
// ═══════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
// RENDER ALL
// ═══════════════════════════════════════════════════════════════════════
function renderAll() {
    try {
        // Refresh toolbar right — settings button only. The GitHub repo link
        // is a frontend-variant affordance (public opensource app); the suite
        // build is the integrated governance product and, like every other
        // suite module, shows no repo link.
        var tr = document.getElementById("toolbar-right");
        if (tr)
            tr.innerHTML = (typeof _getSettingsButtonHTML === "function" ? _getSettingsButtonHTML() : "");
        _applyStaticTranslations();
        // Show/hide AI report menu item
        var menuReport = document.getElementById("menu-report");
        if (menuReport)
            menuReport.style.display = (typeof _aiIsEnabled === "function" && _aiIsEnabled()) ? "" : "none";
        renderMeta();
        updateSidebarBadges();
        // Re-render current panel
        if (_currentPanel === "dashboard")
            renderDashboard();
        else if (_currentPanel.startsWith("domain-"))
            renderDomain(_currentPanel.replace("domain-", ""));
        else if (_currentPanel === "journal")
            renderJournal();
        else if (_currentPanel === "docreview" && typeof renderDocReview === "function")
            renderDocReview();
        else if (_currentPanel === "planning" && typeof renderPlanning === "function")
            renderPlanning();
    }
    catch (e) {
        console.error("renderAll error:", e);
    }
}
function _initDataAndRender(afterFn) {
    // FEAT-36 — normalize + replay schema migrations on EVERY load path
    // (file, snapshot, session, API): idempotent, refuses future revs.
    if (typeof ctSchemaMigrate === "function") {
        try {
            ctSchemaMigrate(D);
        }
        catch (e) {
            alert(e && e.message ? e.message : String(e));
        }
    }
    ensureKeys();
    renderAll();
    if (afterFn)
        afterFn();
}
// ═══════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", function () {
    // Backend mode (suite): audit_api.js owns the boot — it loads the
    // active stored audit from the API, then calls _initDataAndRender.
    if (typeof window._appInitCallback === "function") {
        window._appInitCallback();
        selectPanel("dashboard");
        return;
    }
    _checkAutoSaveBanner();
    _initDataAndRender();
    selectPanel("dashboard");
});
