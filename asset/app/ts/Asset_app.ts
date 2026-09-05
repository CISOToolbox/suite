/**
 * CISO Toolbox — Asset Management
 *
 * Data model stored in D (global, used by cisotoolbox.js autosave):
 *   assets[], groupes[], metadata{}
 */

var ASSET_INIT_DATA: AssetData = { assets: [], groupes: [], metadata: { organization: "", created: "" } };
window.CT_CONFIG = {
    edition: "suite",
    module: "asset",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
    autosaveKey: "asset_autosave",
    initDataVar: "ASSET_INIT_DATA",
    filePrefix: "Asset",
    labelKey: "toolbar.subtitle",
    getSociete: function(d) { return (d.metadata && d.metadata.organization) || ""; },
    getDate: function(d) { return (d.metadata && d.metadata.created) || ""; }
};

// FEAT-36 — schema versioning (rev 1 = normalized baseline; bump + add a
// migration + archive a fixture whenever the exported data model changes).
window.SCHEMA_REV = 1;


var D: AssetData = JSON.parse(JSON.stringify(ASSET_INIT_DATA));
var _panel = "dashboard";
var _selectedAsset: number | null = null;
var _selectedGroupe: number | null = null;
var _groupeTab = "info";

window.AI_APP_CONFIG = {
    storagePrefix: "asset"
};

function renderAll(): void {
    var tr = document.getElementById("toolbar-right");
    if (tr) tr.innerHTML = _getSettingsButtonHTML();
    _applyStaticTranslations();
    renderPanel();
}

function _initDataAndRender(cb?: () => void): void {
    // FEAT-36 — normalize + replay schema migrations on EVERY load path
    // (file, snapshot, session, API): idempotent, refuses future revs.
    if (typeof ctSchemaMigrate === "function") {
        try { ctSchemaMigrate(D); } catch (e: any) { alert(e && e.message ? e.message : String(e)); }
    }

    _panel = "dashboard";
    _selectedAsset = null;
    _selectedGroupe = null;
    renderAll();
    if (cb) cb();
}

// Built-in types shipped with the app. Custom types are stored in
// D.custom_asset_types = [{id, label, label_en, color}] and live
// alongside these in dropdowns / stats / badges.
var ASSET_TYPES_BUILTIN = [
    "terminal_mobile", "poste_physique", "poste_virtuel",
    "serveur_physique", "serveur_virtuel", "systeme_exploitation",
    "application", "donnees"
];

function _getCustomTypes(): AssetCustomType[] {
    return (typeof D !== "undefined" && Array.isArray(D.custom_asset_types))
        ? D.custom_asset_types : [];
}

// Full list of type IDs used everywhere the app iterates over types.
function _getAssetTypes(): string[] {
    return ASSET_TYPES_BUILTIN.concat(_getCustomTypes().map(function(x) { return x.id; }));
}

// Backwards-compat alias — callers that reference ASSET_TYPES as a
// property still work; we expose it as a getter-backed array.
var ASSET_TYPES: string[] = new Proxy<string[]>([], {
    get: function(_, prop) {
        var arr = _getAssetTypes();
        if (prop === "length") return arr.length;
        if (prop === Symbol.iterator) return arr[Symbol.iterator].bind(arr);
        if (typeof (arr as any)[prop] === "function") return (arr as any)[prop].bind(arr);
        return (arr as any)[prop];
    }
});

// ═══════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════

function selectPanel(id: string): void {
    _panel = id;
    _selectedAsset = null;
    _selectedGroupe = null;
    _groupeTab = "info";
    if (id === "measures") _measuresLoaded = false;  // always fetch fresh on open
    document.querySelector(".ct-rail, .sidebar")?.classList.remove("open");
    _updateSidebarAccordion(id);
    renderPanel();
}

function renderPanel(): void {
    var c = document.getElementById("content")!;
    switch (_panel) {
        case "dashboard": c.innerHTML = renderDashboard(); break;
        case "assets": c.innerHTML = _selectedAsset !== null ? renderAssetDetail() : renderAssetList(); break;
        case "groupes": c.innerHTML = _selectedGroupe !== null ? renderGroupeDetail() : renderGroupeList(); break;
        case "dependances": c.innerHTML = renderDependances(); break;
        case "echeances": c.innerHTML = renderEcheances(); break;
        case "measures": renderMeasuresPanel(c); break;
        case "plugins": renderPluginsPanel(c); break;
        default: c.innerHTML = renderDashboard();
    }
    _setupTable("asset-list-table");
    _setupTable("groupe-assets-table");
    _updateEcheanceBadge();
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function _genId(prefix: string, arr: { id?: string }[]): string {
    var max = 0;
    arr.forEach(function(x) {
        var n = parseInt((x.id || "").replace(/\D/g, "")) || 0;
        if (n > max) max = n;
    });
    return prefix + String(max + 1).padStart(3, "0");
}

function _typeLabel(type: string): string {
    var i18n = t("asset.type." + type);
    // t() returns the key itself (or empty) when the key is missing —
    // detect that so we can fall through to the custom types list.
    if (i18n && i18n !== "asset.type." + type) return i18n;
    var custom = _getCustomTypes().find(function(x) { return x.id === type; });
    if (custom) {
        var lang = (typeof _locale !== "undefined" && _locale) ? _locale : "fr";
        return (lang === "en" && custom.label_en) || custom.label || type;
    }
    return type;
}

function _typeColor(type: string): string {
    var colors: Record<string, string> = {
        terminal_mobile: "#7c3aed", poste_physique: "#2563eb", poste_virtuel: "#0891b2",
        serveur_physique: "#dc2626", serveur_virtuel: "#ea580c", systeme_exploitation: "#65a30d",
        application: "#d97706", donnees: "#be185d"
    };
    if (colors[type]) return colors[type];
    var custom = _getCustomTypes().find(function(x) { return x.id === type; });
    if (custom && custom.color) return custom.color;
    return "var(--ct-ink-2)";
}

// CT series-color names for the dashboard donut. _svgDonut resolves color
// NAMES through _svgSeriesColor, never raw hex — these mirror the hues of
// _typeColor; custom types cycle through the fallback palette.
var _TYPE_SERIES: Record<string, string> = {
    terminal_mobile: "violet", poste_physique: "blue", poste_virtuel: "cyan",
    serveur_physique: "redDark", serveur_virtuel: "orange",
    systeme_exploitation: "green", application: "amber", donnees: "pink"
};
var _TYPE_SERIES_FALLBACK = ["indigo", "teal", "purple", "dark", "gray"];

function _critLabel(val: number | string): string { return t("asset.crit." + val) || String(val); }
function _critColor(val: number): string {
    var c = ["", "#22c55e", "#eab308", "#f97316", "var(--ct-critical)", "#dc2626"];
    return c[val] || "var(--ct-ink-2)";
}

function _statusLabel(s: string): string { return t("asset.statut." + s) || s; }

function _card(val: string | number, label: string, cls?: string): string {
    var tone = cls === "warning" ? "high" : (cls === "critical" || cls === "high" || cls === "medium" || cls === "low" ? cls : "");
    var a = tone ? ' data-emphasis="value" data-tone="' + tone + '"' : '';
    return '<div class="ct-kpi"' + a + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(label) + '</div><div class="ct-kpi-value">' + val + '</div></div></div>';
}

function _badge(text: string, bg: string, color?: string): string {
    return '<span style="padding:2px 8px;border-radius:10px;font-size:var(--ct-text-label);font-weight:700;background:' + bg + ';color:' + (color || "white") + '">' + esc(text) + '</span>';
}

function _typeBadge(type: string): string {
    var c = _typeColor(type);
    return '<span class="ct-badge" data-type="' + esc(type) + '" style="background:' + c + '20;color:' + c + '">' + esc(_typeLabel(type)) + '</span>';
}

function _critBadge(val: number): string {
    var c = _critColor(val);
    return '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + c + '"></span> ' + esc(_critLabel(val));
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════

function renderDashboard(): string {
    var a = D.assets, g = D.groupes;
    var withGroup = a.filter(function(x) { return (x.groupe_ids || []).length > 0; }).length;
    var critical = a.filter(function(x) { return x.criticite >= 4; }).length;
    var eol = a.filter(function(x) {
        return ctDateStatus(x.fin_support, 90) === "soon";
    }).length;

    var ech = _echeances();
    var renouv = ech.filter(function(e) { return e.kind === "licence" && (e.bucket === "due" || e.bucket === "expired"); }).length;
    var expirees = ech.filter(function(e) { return e.bucket === "expired"; }).length;

    var h = '<h2>' + t("dashboard.title") + '</h2>';
    h += '<div class="ct-kpigrid ct-mb-4">';
    h += _card(a.length, t("dashboard.total_assets"), "");
    h += _card(g.length, t("dashboard.total_groupes"), "");
    h += _card(a.length - withGroup, t("dashboard.sans_groupe"), _kpiTone(a.length - withGroup, { warn: 1 }));
    h += _card(critical, t("dashboard.critiques"), _kpiTone(critical, { bad: 1 }));
    h += _card(eol, t("dashboard.fin_support_90j"), _kpiTone(eol, { warn: 1 }));
    h += _card(renouv, t("dashboard.renouv"), _kpiTone(renouv, { warn: 1 }));
    h += _card(expirees, t("dashboard.expirees"), _kpiTone(expirees, { bad: 1 }));
    h += '</div>';

    // Upcoming deadlines (top 6) + timeline of the 8 nearest ones
    if (ech.length) {
        h += '<div class="dash-section">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("dashboard.echeances") + '</h3>';
        var evs: CtTimelineEvent[] = ech.slice(0, 8).map(function(e) {
            return {
                date: e.date,
                label: (e.asset.nom || String(e.asset.id)) + " — " + t("echeance.kind_" + e.kind),
                status: e.bucket === "expired" ? "overdue" : e.bucket === "due" ? "in_progress" : "planned"
            };
        });
        h += '<div class="ct-mb-2">' + window._svgTimeline({ events: evs }, { width: 480 }) + '</div>';
        ech.slice(0, 6).forEach(function(e) {
            var c = _echeanceColor(e.bucket);
            h += '<div class="ct-flex ct-items-center ct-gap-2 ct-py-1 ct-px-0 ct-text-meta ct-clickable" data-click="openEcheanceAsset" data-args=\'' + _da(e.asset.id) + '\'>';
            h += '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + c + '"></span>';
            h += '<span class="ct-strong ct-flex-1">' + esc(e.asset.nom || e.asset.id) + '</span>';
            h += '<span class="ct-muted">' + esc(t("echeance.kind_" + e.kind)) + '</span>';
            h += '<span style="color:' + c + ';font-weight:600;min-width:80px;text-align:right">' + esc(_echeanceDaysLabel(e.days)) + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }

    // Type breakdown (donut). Iterate over the types actually present so the
    // centre total always equals D.assets.length, even for a legacy/unknown
    // type value; known types keep the declared order.
    if (a.length > 0) {
        var counts: Record<string, number> = {};
        a.forEach(function(x) { var k = x.type || "?"; counts[k] = (counts[k] || 0) + 1; });
        var ordered: string[] = [];
        ASSET_TYPES.forEach(function(type) { if (counts[type]) ordered.push(type); });
        Object.keys(counts).sort().forEach(function(type) { if (ordered.indexOf(type) < 0) ordered.push(type); });
        var fb = 0;
        var segs: CtDonutSegment[] = ordered.map(function(type) {
            var color = _TYPE_SERIES[type] || _TYPE_SERIES_FALLBACK[(fb++) % _TYPE_SERIES_FALLBACK.length];
            return { label: _typeLabel(type), value: counts[type], color: color };
        });
        h += '<div class="dash-section">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("dashboard.par_type") + '</h3>';
        h += window._svgDonut({ center_label: a.length, segments: segs }, { size: 150, thickness: 22 });
        h += '</div>';
    }

    // Group coverage
    if (g.length > 0) {
        h += '<div class="dash-section">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("dashboard.groupes") + '</h3>';
        g.forEach(function(gr) {
            var n = (gr.asset_ids || []).length;
            h += '<div class="ct-flex ct-items-center ct-gap-2 ct-py-1 ct-px-0 ct-text-meta">';
            h += '<span class="ct-strong ct-flex-1">' + esc(gr.nom) + '</span>';
            h += '<span class="ct-muted">' + n + ' ' + t("nav.assets").toLowerCase() + '</span>';
            h += _critBadge(gr.criticite || 1);
            h += '</div>';
        });
        h += '</div>';
    }

    return h;
}

// ═══════════════════════════════════════════════════════════════
// ÉCHÉANCES (licence renewal + fin_support + fin_vie)
// ═══════════════════════════════════════════════════════════════

// Flat, date-sorted list of upcoming/overdue deadlines across all assets.
// Each entry: { asset, kind: "licence"|"support"|"vie", date, days, bucket }.
// Buckets: expired (date<today) · due (<= today+lead) · upcoming (<= 90j).
function _echeances(): AssetEcheance[] {
    var now = new Date();
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    var out: AssetEcheance[] = [];
    function add(asset: AssetItem, kind: AssetEcheanceKind, dateStr: string | undefined, lead: number) {
        if (!dateStr) return;
        var d = new Date(dateStr);
        if (isNaN(d.getTime())) return;
        var days = Math.round((d.getTime() - today.getTime()) / 86400000);
        var bucket: AssetEcheanceBucket;
        if (days < 0) bucket = "expired";
        else if (days <= lead) bucket = "due";
        else if (days <= 90) bucket = "upcoming";
        else return;
        out.push({ asset: asset, kind: kind, date: dateStr, days: days, bucket: bucket });
    }
    (D.assets || []).forEach(function(a) {
        var lic = a.licence || {};
        var lead = parseInt(String(lic.preavis_jours));
        if (isNaN(lead)) lead = 30;
        add(a, "licence", lic.date_renouvellement, lead);
        add(a, "support", a.fin_support, 90);
        add(a, "vie", a.fin_vie, 90);
    });
    out.sort(function(x, y) { return x.days - y.days; });
    return out;
}

function _echeanceColor(bucket: AssetEcheanceBucket | string): string {
    return bucket === "expired" ? "#dc2626" : bucket === "due" ? "#f97316" : "#eab308";
}

function _echeanceDaysLabel(days: number): string {
    if (days === 0) return t("echeance.today");
    if (days < 0) return t("echeance.days_ago", { n: -days });
    return t("echeance.days_left", { n: days });
}

function _updateEcheanceBadge(): void {
    var el = document.getElementById("ech-badge");
    if (!el) return;
    var n = _echeances().filter(function(e) { return e.bucket === "expired" || e.bucket === "due"; }).length;
    el.textContent = n > 0 ? String(n) : "";
    el.style.display = n > 0 ? "" : "none";
}

window.openEcheanceAsset = function(id: string) {
    var idx = D.assets.findIndex(function(x) { return x.id === id; });
    if (idx < 0) return;
    _panel = "assets";
    _selectedAsset = idx;
    _updateSidebarAccordion("assets");
    renderPanel();
};

function renderEcheances(): string {
    var items = _echeances();
    var alerts = items.filter(function(e) { return e.bucket === "expired" || e.bucket === "due"; });

    var h = '<div class="ct-flex ct-items-center ct-row-between ct-mb-3 ct-row-wrap ct-gap-2">';
    h += '<h2 class="ct-m-0">' + t("nav.echeances") + '</h2>';
    if (items.length) {
        h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="exportEcheancesIcs">&#128197; ' + t("echeance.export_ics") + '</button>';
    }
    h += '</div>';

    if (!items.length) {
        h += '<div class="ct-empty-state">' + t("echeance.empty") + '</div>';
        return h;
    }

    h += '<div class="ct-muted ct-text-meta ct-mb-2">'
       + t("echeance.summary", { alerts: alerts.length, total: items.length }) + '</div>';

    h += '<table id="echeance-table"><thead><tr>';
    h += '<th class="ct-w-120">' + t("echeance.col_kind") + '</th>';
    h += '<th>' + t("asset.col_nom") + '</th>';
    h += '<th>' + t("asset.col_type") + '</th>';
    h += '<th class="ct-w-110">' + t("echeance.col_date") + '</th>';
    h += '<th class="ct-w-120">' + t("echeance.col_remaining") + '</th>';
    h += '</tr></thead><tbody>';

    items.forEach(function(e) {
        var c = _echeanceColor(e.bucket);
        h += '<tr class="ct-clickable" data-click="openEcheanceAsset" data-args=\'' + _da(e.asset.id) + '\'>';
        h += '<td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + c + ';margin-right:6px"></span>'
           + esc(t("echeance.kind_" + e.kind)) + '</td>';
        h += '<td class="ct-strong">' + esc(e.asset.nom || e.asset.id) + '</td>';
        h += '<td>' + _typeBadge(e.asset.type) + '</td>';
        h += '<td class="ct-text-meta">' + esc(e.date) + '</td>';
        h += '<td style="font-size:var(--ct-text-meta);color:' + c + ';font-weight:600">' + esc(_echeanceDaysLabel(e.days)) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    return h;
}

// Build an iCalendar (.ics) with one VEVENT per due date and a VALARM
// lead so Outlook/Google fire a real reminder. Pure vanilla, no dep.
function exportEcheancesIcs(): void {
    var items = _echeances();
    if (!items.length) { showStatus(t("echeance.empty"), true); return; }

    function pad(n: number) { return n < 10 ? "0" + n : "" + n; }
    function dval(dateStr: string) { return dateStr.replace(/-/g, ""); }
    var org = (D.metadata && D.metadata.organization) || "CISO Toolbox";

    var lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//CISO Toolbox//Asset//FR", "CALSCALE:GREGORIAN", "METHOD:PUBLISH"];
    items.forEach(function(e, i) {
        var lic = e.asset.licence || {};
        var lead = e.kind === "licence" ? (parseInt(String(lic.preavis_jours)) || 30) : 90;
        var summary = t("echeance.ics_summary_" + e.kind, { asset: e.asset.nom || e.asset.id });
        var d = dval(e.date);
        var uid = "asset-" + e.asset.id + "-" + e.kind + "-" + d + "@cisotoolbox";
        lines.push("BEGIN:VEVENT");
        lines.push("UID:" + uid);
        lines.push("DTSTART;VALUE=DATE:" + d);
        lines.push("SUMMARY:" + _icsEsc(summary));
        lines.push("DESCRIPTION:" + _icsEsc(org + " — " + (e.asset.nom || e.asset.id)
            + (lic.reference ? " (" + lic.reference + ")" : "")));
        lines.push("BEGIN:VALARM");
        lines.push("TRIGGER:-P" + lead + "D");
        lines.push("ACTION:DISPLAY");
        lines.push("DESCRIPTION:" + _icsEsc(summary));
        lines.push("END:VALARM");
        lines.push("END:VEVENT");
    });
    lines.push("END:VCALENDAR");

    var blob = new Blob([lines.join("\r\n")], { type: "text/calendar;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "echeances-assets.ics";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showStatus(t("echeance.ics_done"));
}
window.exportEcheancesIcs = exportEcheancesIcs;

// RFC 5545 text escaping for SUMMARY/DESCRIPTION values.
function _icsEsc(s: unknown): string {
    return String(s == null ? "" : s)
        .replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,")
        .replace(/\r?\n/g, "\\n");
}

// ═══════════════════════════════════════════════════════════════
// ASSET LIST
// ═══════════════════════════════════════════════════════════════

var _assetFilter = "";
var _assetTypeFilter = "";
var _assetCritFilter = "";
var _assetStatutFilter = "";
var _assetSort: AssetSortState | null = null;           // { key, direction: "asc"|"desc" }
var _assetHiddenCols: Record<string, boolean> | null = null;     // { colKey: true } — null = not yet loaded
var _ASSET_COLS_LS_KEY = "ct_asset_hidden_cols";
function _defaultHiddenCols(): Record<string, boolean> {
    return { localisation: true, os: true, last_login_at: true, ip_address: true };
}
function _loadHiddenCols(): Record<string, boolean> {
    try {
        var raw = localStorage.getItem(_ASSET_COLS_LS_KEY);
        if (raw) { var o = JSON.parse(raw); if (o && typeof o === "object") return o as Record<string, boolean>; }
    } catch (e) { /* localStorage unavailable → fall back to defaults */ }
    return _defaultHiddenCols();
}
function _saveHiddenCols(): void {
    try { localStorage.setItem(_ASSET_COLS_LS_KEY, JSON.stringify(_assetHiddenCols || {})); } catch (e) { /* ignore */ }
}

window._sortAssets = function(key: string) {
    if (_assetSort && _assetSort.key === key) {
        _assetSort.direction = _assetSort.direction === "asc" ? "desc" : "asc";
    } else {
        _assetSort = { key: key, direction: "asc" };
    }
    renderPanel();
};

window._toggleAssetColsPopup = function() {
    var p = document.getElementById("asset-cols-popup");
    if (!p) return;
    p.style.display = p.style.display === "none" ? "block" : "none";
};

window._toggleAssetCol = function(key: string, el: HTMLInputElement) {
    if (!_assetHiddenCols) _assetHiddenCols = {};
    if (el && typeof el.checked === "boolean") {
        if (el.checked) delete _assetHiddenCols[key];
        else _assetHiddenCols[key] = true;
    }
    _saveHiddenCols();
    renderPanel();
};

// Close the cols popup on outside click
document.addEventListener("click", function(e: MouseEvent) {
    var popup = document.getElementById("asset-cols-popup");
    if (!popup || popup.style.display === "none") return;
    var btn = (e.target as Element).closest('[data-click="_toggleAssetColsPopup"]');
    var inside = (e.target as Element).closest("#asset-cols-popup");
    if (!btn && !inside) popup.style.display = "none";
});

function filterAssets(val: string): void {
    _assetFilter = (val || "").toLowerCase();
    renderPanel();
    // Re-focus the search input after the DOM rebuild and restore caret.
    var el = document.getElementById("asset-search") as HTMLInputElement | null;
    if (el) {
        el.focus();
        try { var p = el.value.length; el.setSelectionRange(p, p); } catch (e) {}
    }
}
window.filterAssets = filterAssets;
function filterAssetType(val: string): void { _assetTypeFilter = val || ""; renderPanel(); }
window.filterAssetType = filterAssetType;
function filterAssetCrit(val: string): void { _assetCritFilter = val || ""; renderPanel(); }
window.filterAssetCrit = filterAssetCrit;
function filterAssetStatut(val: string): void { _assetStatutFilter = val || ""; renderPanel(); }
window.filterAssetStatut = filterAssetStatut;

function renderAssetList(): string {
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("nav.assets") + '</h2>';
    h += '<div class="ct-flex ct-gap-1">';
    h += '<button class="ct-btn mt-8" data-write data-size="xs" data-click="refreshConnectors">' + (t("asset.refresh_connectors") || "Rafraîchir les connecteurs") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-size="xs" data-click="openAssetTypesModal">' + (t("asset.manage_types") || "Gérer les types") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-size="xs" data-click="addAsset">' + t("asset.add") + '</button>';
    h += '</div></div>';

    // Filters
    h += '<div class="ct-flex ct-gap-2 ct-mb-3 ct-row-wrap">';
    h += '<input type="text" id="asset-search" placeholder="' + esc(t("asset.search")) + '" class="ct-flex-1 ct-minw-150 ct-py-1 ct-px-2 ct-bordered ct-r-md ct-text-meta" value="' + esc(_assetFilter) + '" data-input="filterAssets" data-pass-value>';
    h += '<select class="ct-filter" data-change="filterAssetType" data-pass-value>';
    h += '<option value="">' + t("asset.all_types") + '</option>';
    ASSET_TYPES.forEach(function(type) {
        h += '<option value="' + type + '"' + (_assetTypeFilter === type ? " selected" : "") + '>' + esc(_typeLabel(type)) + '</option>';
    });
    h += '</select>';
    h += '<select class="ct-filter" data-change="filterAssetCrit" data-pass-value>';
    h += '<option value="">' + t("asset.all_crit") + '</option>';
    for (var ci = 1; ci <= 5; ci++) h += '<option value="' + ci + '"' + (_assetCritFilter == String(ci) ? " selected" : "") + '>' + esc(_critLabel(ci)) + '</option>';
    h += '</select>';
    h += '<select class="ct-filter" data-change="filterAssetStatut" data-pass-value>';
    h += '<option value="">' + (t("asset.all_statuts") || "Tous les statuts") + '</option>';
    ["actif", "inactif", "en_cours", "retire"].forEach(function(s) {
        h += '<option value="' + s + '"' + (_assetStatutFilter === s ? " selected" : "") + '>' + esc(_statusLabel(s)) + '</option>';
    });
    h += '</select>';
    h += '</div>';

    // Table
    var filtered = D.assets.filter(function(a) {
        if (_assetTypeFilter && a.type !== _assetTypeFilter) return false;
        if (_assetCritFilter && String(a.criticite) != _assetCritFilter) return false;
        if (_assetStatutFilter && (a.statut || "actif") !== _assetStatutFilter) return false;
        if (_assetFilter) {
            var q = _assetFilter;
            return (a.nom || "").toLowerCase().indexOf(q) >= 0 || (a.id || "").toLowerCase().indexOf(q) >= 0 || (a.proprietaire || "").toLowerCase().indexOf(q) >= 0;
        }
        return true;
    });

    if (!filtered.length) {
        h += '<div class="ct-empty-state">' + t("asset.empty") + '</div>';
        return h;
    }

    // Enrich rows with groupes names so ct_table renderer stays O(1)
    var rows = filtered.map(function(a) {
        var gNames = (a.groupe_ids || []).map(function(gid) {
            var g = D.groupes.find(function(x) { return x.id === gid; });
            return g ? g.nom : "";
        }).filter(Boolean).join(", ");
        return Object.assign({}, a, { __groupes_names: gNames });
    });

    // Apply client-side sort if the user clicked a header
    if (_assetSort && _assetSort.key) {
        var sk = _assetSort.key, dir = _assetSort.direction === "desc" ? -1 : 1;
        rows.sort(function(x, y) {
            var a = (x as Record<string, any>)[sk], b = (y as Record<string, any>)[sk];
            // Enriched helpers + timestamps
            if (sk === "groupes") { a = x.__groupes_names || ""; b = y.__groupes_names || ""; }
            if (sk === "last_login_at") {
                a = a ? Date.parse(a) : 0;
                b = b ? Date.parse(b) : 0;
            }
            if (a == null) a = "";
            if (b == null) b = "";
            if (typeof a === "number" && typeof b === "number") return (a - b) * dir;
            return String(a).localeCompare(String(b)) * dir;
        });
    }

    // Column definitions — all possible columns; hidden ones are
    // filtered out just before passing to ct_table.
    var allCols: CtTableColumn[] = [
        { key: "id", label: "ID", sortable: true, width: "80px",
          render: function(a) { return '<span class="ct-strong ct-muted ct-text-label">' + esc(a.id) + '</span>'; } },
        { key: "nom", label: t("asset.col_nom"), sortable: true,
          render: function(a) { return '<strong>' + esc(a.nom) + '</strong>'; } },
        { key: "type", label: t("asset.col_type"), sortable: true, width: "140px",
          render: function(a) { return _typeBadge(a.type); } },
        { key: "criticite", label: t("asset.col_crit"), sortable: true, width: "90px",
          render: function(a) { return _critBadge(a.criticite || 1); } },
        { key: "proprietaire", label: t("asset.col_proprio"), sortable: true,
          render: function(a) { return '<span class="ct-text-meta">' + esc(a.proprietaire || "") + '</span>'; } },
        { key: "localisation", label: t("asset.col_localisation") || "Localisation", sortable: true,
          render: function(a) { return '<span class="ct-text-label">' + esc(a.localisation || "-") + '</span>'; } },
        { key: "os", label: t("asset.col_os") || "OS", sortable: true,
          render: function(a) {
              var os = a.os || "";
              var v = a.version || "";
              if (!os && !v) return '<span class="text-muted">-</span>';
              return '<span class="ct-text-label">' + esc(os) + (v ? ' <span class="text-muted">(' + esc(v) + ')</span>' : '') + '</span>';
          } },
        { key: "ip_address", label: t("asset.col_ip") || "IP", sortable: true, width: "130px",
          render: function(a) { return a.ip_address ? '<span class="ct-text-label ct-mono">' + esc(a.ip_address) + '</span>' : '<span class="text-muted">-</span>'; } },
        { key: "groupes", label: t("asset.col_groupes"), sortable: true,
          render: function(a) { return '<span class="ct-text-label ct-muted">' + esc(a.__groupes_names || "-") + '</span>'; } },
        { key: "statut", label: t("asset.col_statut"), sortable: true, width: "100px",
          render: function(a) { return esc(_statusLabel(a.statut || "actif")); } },
        { key: "fin_support", label: t("asset.col_fin_support"), sortable: true, width: "110px",
          render: function(a) { return '<span class="ct-text-label">' + esc(a.fin_support || "-") + '</span>'; } },
        { key: "last_login_at", label: t("asset.col_last_login") || "Dernière connexion", sortable: true, width: "140px",
          render: function(a) {
              if (!a.last_login_at) return '<span class="text-muted">—</span>';
              var d = new Date(a.last_login_at);
              if (isNaN(d.getTime())) return '<span class="text-muted">—</span>';
              var daysAgo = Math.floor((Date.now() - d.getTime()) / 86400000);
              var color = daysAgo > 180 ? "var(--ct-critical)" : (daysAgo > 60 ? "var(--ct-high)" : "");
              return '<span style="font-size:var(--ct-text-label)' + (color ? ";color:" + color : "") + '" title="' + esc(a.last_login_at) + (daysAgo >= 0 ? " (il y a " + daysAgo + " j)" : "") + '">'
                  + esc(d.toISOString().slice(0, 10)) + '</span>';
          } }
    ];
    // Default: localisation + os + last_login_at are hidden until the
    // user opts in via the cols popup.
    if (_assetHiddenCols === null) {
        _assetHiddenCols = _loadHiddenCols();
    }
    var visibleCols = allCols.filter(function(c) { return !_assetHiddenCols![c.key]; });

    // "Colonnes" toolbar — button + popup listing ALL columns with checkboxes
    h += '<div style="position:relative;display:inline-block;margin-bottom:var(--ct-s2)">';
    h += '<button class="ct-btn mt-8" data-write data-size="xs" data-click="_toggleAssetColsPopup">' + (t("asset.columns") || "Colonnes") + '</button>';
    var popupId = "asset-cols-popup";
    var popup = '<div class="asset-cols-popup" id="' + popupId + '" style="display:none;position:absolute;top:100%;left:0;margin-top:var(--ct-s1);background:var(--ct-surface);border:1px solid var(--ct-line);border-radius:var(--ct-r-md);box-shadow:0 4px 12px rgba(0,0,0,0.08);padding:var(--ct-s2);z-index:50;min-width:200px">';
    allCols.forEach(function(c) {
        var checked = !_assetHiddenCols![c.key];
        popup += '<label class="ct-block ct-text-label ct-p-1 ct-clickable">'
              +  '<input type="checkbox"' + (checked ? " checked" : "") + ' data-change="_toggleAssetCol" data-args=\'' + _da(c.key) + '\' data-pass-el> '
              +  esc(c.label) + '</label>';
    });
    popup += '</div>';
    h += popup;
    h += '</div>';

    h += ct_table.render({
        rows: rows,
        rowKey: "id",
        onRowClick: "_openAssetRow",
        bulk: { scope: "asset-list" },
        sortHandler: "_sortAssets",
        initialSort: _assetSort || {},
        columns: visibleCols
    });

    setTimeout(function() {
        if (!window.ct_bulkbar) return;
        ct_bulkbar.attach({
            scope: "asset-list",
            label: t("asset.selected_n") || "{n} actif(s) sélectionné(s)",
            actions: [
                { id: "edit", icon: "edit", label: t("asset.bulk_edit") || "Modifier",
                  onClick: "_bulkAssetsEdit" },
                { id: "group", icon: "plus", label: t("asset.bulk_add_group") || "Ajouter à un groupe",
                  onClick: "_bulkAssetsAddToGroup" },
                { id: "retire", icon: "check", label: t("asset.bulk_retire") || "Marquer retiré", variant: "warning",
                  onClick: "_bulkAssetsRetire" },
                { id: "delete", icon: "trash", label: t("btn_delete") || "Supprimer", danger: true,
                  onClick: "_bulkAssetsDelete",
                  confirm: { title: "Supprimer {n} actif(s) ?", message: "Les dépendances et groupes liés seront aussi nettoyés. Action irréversible." } }
            ]
        });
        ct_bulkbar.update("asset-list");
    }, 0);

    return h;
}

window._openAssetRow = function(row: Record<string, any>) {
    var idx = D.assets.findIndex(function(a) { return a.id === row.id; });
    if (idx >= 0) { _selectedAsset = idx; renderPanel(); }
};

window._bulkAssetsRetire = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var count = 0;
    D.assets.forEach(function(a) {
        if (ids.indexOf(a.id) >= 0) { a.statut = "retire"; count++; }
    });
    _save();
    ct_bulkbar.clear(scope);
    showStatus(count + " " + (t("asset.bulk_retire_done") || "actif(s) marqué(s) retiré(s)"));
    renderPanel();
};

window._bulkAssetsAddToGroup = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope)) as string[];
    if (!ids.length) return;
    if (!window.ct_modal) return;
    if (!D.groupes.length) {
        showStatus(t("asset.bulk_add_group_none") || "Aucun groupe — créez-en un d'abord", true);
        return;
    }
    var sel = '<select id="bulk-group" class="ct-w-full">';
    D.groupes.forEach(function(g) {
        sel += '<option value="' + esc(g.id) + '">' + esc(g.nom || g.id) + '</option>';
    });
    sel += '</select>';
    var body = '<div class="ct-text-meta ct-mb-2">'
             + esc(t("asset.bulk_add_group_field") || "Groupe cible") + '</div>' + sel;
    ct_modal.open({
        title: (t("asset.bulk_add_group_title") || "Ajouter {n} actif(s) à un groupe")
            .replace("{n}", String(ids.length)),
        body: body,
        size: "sm",
        buttons: [
            { id: "cancel", label: t("btn_cancel") || "Annuler" },
            { id: "add", primary: true, label: t("btn_add") || "Ajouter",
              result: function() {
                  var el = document.getElementById("bulk-group") as HTMLSelectElement | null;
                  return el && el.value ? el.value : false;
              } }
        ]
    }).then(function(gid: any) {
        if (!gid) return;
        var n = _linkAssetsToGroup(ids, gid);
        ct_bulkbar.clear(scope);
        showStatus(n + " " + (t("asset.bulk_add_group_done") || "actif(s) ajouté(s) au groupe"));
        renderPanel();
    });
};

window._bulkAssetsEdit = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    if (!window.ct_modal) return;

    // Built-in types + custom types defined through "Gérer les types".
    var types = _getAssetTypes();
    var statuts = ["actif", "inactif", "en_cours", "retire"];

    function row(label: string, fieldHtml: string) {
        return '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-2">'
             + '<label style="flex:0 0 150px;font-size:var(--ct-text-meta)">' + esc(label) + '</label>'
             + '<div class="ct-flex-1">' + fieldHtml + '</div></div>';
    }
    function checkbox(id: string) {
        return '<input type="checkbox" id="bulk-apply-' + id + '" style="margin-right:var(--ct-s1)" title="Appliquer ce champ">';
    }

    var h = '<div class="ct-text-label ct-muted ct-mb-3">'
          + 'Coche les champs à modifier. Les champs non cochés sont ignorés (les valeurs existantes sont préservées).</div>';

    // Type — built-in i18n + custom types via _typeLabel fallback.
    var typeSel = '<select id="bulk-type" class="ct-w-full">';
    types.forEach(function(t_) {
        typeSel += '<option value="' + esc(t_) + '">' + esc(_typeLabel(t_)) + '</option>';
    });
    typeSel += '</select>';
    h += row("Type", checkbox("type") + typeSel);

    // Criticality
    var critSel = '<select id="bulk-crit" class="ct-w-full">';
    for (var i = 1; i <= 5; i++) {
        critSel += '<option value="' + i + '">' + i + ' — ' + esc(t("asset.crit." + i) || "") + '</option>';
    }
    critSel += '</select>';
    h += row(t("asset.col_crit") || "Criticité", checkbox("crit") + critSel);

    // Owner
    h += row(t("asset.col_proprio") || "Propriétaire",
             checkbox("proprio")
           + '<input type="text" id="bulk-proprio" class="ct-w-full" placeholder="Laisse vide pour effacer">');

    // Statut
    var statSel = '<select id="bulk-statut" class="ct-w-full">';
    statuts.forEach(function(s) {
        statSel += '<option value="' + s + '">' + esc(t("asset.statut." + s) || s) + '</option>';
    });
    statSel += '</select>';
    h += row(t("asset.col_statut") || "Statut", checkbox("statut") + statSel);

    // OS
    h += row(t("asset.col_os") || "OS",
             checkbox("os")
           + '<input type="text" id="bulk-os" class="ct-w-full" placeholder="Windows 11, Ubuntu 22.04...">');

    ct_modal.open({
        title: (t("asset.bulk_edit_title") || "Modifier {n} actif(s)").replace("{n}", String(ids.length)),
        body: h,
        size: "md",
        buttons: [
            { id: "cancel", label: t("btn_cancel") || "Annuler" },
            { id: "save", primary: true, label: t("btn_save") || "Enregistrer",
              result: function() {
                  var changes: Record<string, string> = {};
                  ["type", "crit", "proprio", "statut", "os"].forEach(function(k) {
                      var cb = document.getElementById("bulk-apply-" + k) as HTMLInputElement | null;
                      if (cb && cb.checked) {
                          var el = document.getElementById("bulk-" + k) as HTMLInputElement | HTMLSelectElement | null;
                          if (el) changes[k] = el.value;
                      }
                  });
                  if (!Object.keys(changes).length) { showStatus("Aucun champ sélectionné", true); return false; }
                  return changes;
              } }
        ]
    }).then(function(changes: any) {
        if (!changes) return;
        var count = 0;
        D.assets.forEach(function(a) {
            if (ids.indexOf(a.id) < 0) return;
            var patch: Record<string, any> = {};
            if ("type" in changes)   { a.type = changes.type;                          _markManual(a, "type");         patch.type = a.type; }
            if ("crit" in changes)   { a.criticite = parseInt(changes.crit, 10) || 2;  _markManual(a, "criticite");    patch.criticite = a.criticite; }
            if ("proprio" in changes){ a.proprietaire = changes.proprio;               _markManual(a, "proprietaire"); patch.proprietaire = a.proprietaire; }
            if ("statut" in changes) { a.statut = changes.statut;                      _markManual(a, "statut");       patch.statut = a.statut; }
            if ("os" in changes)     { a.os = changes.os;                              _markManual(a, "os");           patch.os = a.os; }
            if (typeof _persist === "function") {
                _persist("asset", a.id, patch);
            }
            count++;
        });
        // Fallback: if the backend has no per-entity PATCH wiring, _persist
        // is a no-op and we still need to flush the in-memory D.
        if (typeof _save === "function") _save();
        ct_bulkbar.clear(scope);
        showStatus(count + " actif(s) mis à jour");
        renderPanel();
    });
};

window._bulkAssetsDelete = function(scope: string) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var idSet: Record<string, boolean> = {}; ids.forEach(function(id) { idSet[id] = true; });
    D.assets = D.assets.filter(function(a) { return !idSet[a.id]; });
    // Clean references in groupes + depends_on
    D.groupes.forEach(function(g) {
        g.asset_ids = (g.asset_ids || []).filter(function(id) { return !idSet[id]; });
    });
    D.assets.forEach(function(x) {
        x.depends_on = (x.depends_on || []).filter(function(id) { return !idSet[id]; });
    });
    _save();
    ct_bulkbar.clear(scope);
    showStatus(ids.length + " " + (t("asset.bulk_delete_done") || "actif(s) supprimé(s)"));
    renderPanel();
};

function openAsset(idx: string | number): void { _selectedAsset = parseInt(String(idx)); renderPanel(); }
window.openAsset = openAsset;

function addAsset(): void {
    D.assets.push({
        id: _genId("A-", D.assets), nom: "", type: "application", description: "",
        criticite: 2, proprietaire: "", localisation: "", quantite: 1,
        os: "", version: "", fournisseur: "", fin_support: "", fin_vie: "",
        statut: "actif", notes: "", groupe_ids: [], depends_on: [],
        licence: { date_renouvellement: "", preavis_jours: 30, cout: "", devise: "EUR", reference: "", contact: "" }
    });
    _selectedAsset = D.assets.length - 1;
    renderPanel();
    _save();
}
window.addAsset = addAsset;

// ═══════════════════════════════════════════════════════════════
// CUSTOM ASSET TYPES (stored in D.custom_asset_types)
// ═══════════════════════════════════════════════════════════════

window.openAssetTypesModal = function() {
    if (!window.ct_modal) { showStatus("ct_modal not loaded", true); return; }
    if (!Array.isArray(D.custom_asset_types)) D.custom_asset_types = [];
    _renderAssetTypesModal();
};

function _renderAssetTypesModal(): void {
    var h = '<div class="ct-text-meta ct-muted ct-mb-2">'
          + esc(t("asset.types_help") || "Les types personnalisés s'ajoutent aux 8 types prédéfinis. Ils apparaissent dans le dropdown Type des actifs et la répartition par type.")
          + '</div>';

    // Existing custom types
    var customs = D.custom_asset_types || [];
    h += '<h4 style="margin:var(--ct-s2) 0 var(--ct-s1) 0;font-size:var(--ct-text-ui)">' + (t("asset.types_custom") || "Types personnalisés") + '</h4>';
    if (customs.length === 0) {
        h += '<p class="text-muted ct-text-meta">' + (t("asset.types_empty") || "Aucun type personnalisé.") + '</p>';
    } else {
        h += '<table class="ct-w-full ct-text-meta ct-mb-3 ct-table">';
        h += '<thead><tr><th>Id</th><th>Label FR</th><th>Label EN</th><th>' + (t("asset.types_color") || "Couleur") + '</th><th></th></tr></thead><tbody>';
        customs.forEach(function(ct, i) {
            h += '<tr>';
            h += '<td><code class="ct-text-label">' + esc(ct.id) + '</code></td>';
            h += '<td>' + esc(ct.label || "") + '</td>';
            h += '<td>' + esc(ct.label_en || "") + '</td>';
            h += '<td><span style="display:inline-block;width:16px;height:16px;border-radius:3px;vertical-align:middle;background:' + esc(ct.color || "var(--ct-ink-2)") + '"></span> <code class="ct-text-label">' + esc(ct.color || "") + '</code></td>';
            h += '<td class="ct-ta-r"><button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-variant="danger" data-click="_deleteCustomType" data-args=\'' + _da(i) + '\' data-size="xs" data-icon>' + _icon("trash", 14) + '</button></td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
    }

    // Add form
    h += '<h4 style="margin:var(--ct-s3) 0 var(--ct-s1) 0;font-size:var(--ct-text-ui)">' + (t("asset.types_add") || "Ajouter un type") + '</h4>';
    h += '<div style="display:grid;grid-template-columns:repeat(2, 1fr);gap:var(--ct-s2);margin-bottom:var(--ct-s2)">';
    h += '<div><label class="ct-text-label">Id <span class="ct-text-critical">*</span></label>';
    h += '<input type="text" id="nt-id" placeholder="equipement_reseau" class="ct-input" pattern="[a-z0-9_]+"></div>';
    h += '<div><label class="ct-text-label">' + (t("asset.types_color") || "Couleur") + '</label>';
    h += '<input type="color" id="nt-color" value="var(--ct-ink-2)" style="width:100%;height:32px;padding:var(--ct-s1)"></div>';
    h += '<div><label class="ct-text-label">Label FR <span class="ct-text-critical">*</span></label>';
    h += '<input type="text" id="nt-label" placeholder="Équipement réseau" class="ct-input"></div>';
    h += '<div><label class="ct-text-label">Label EN</label>';
    h += '<input type="text" id="nt-label-en" placeholder="Network equipment" class="ct-input"></div>';
    h += '</div>';

    ct_modal.open({
        title: (t("asset.manage_types") || "Gérer les types d'actifs"),
        body: h,
        size: "lg",
        buttons: [
            { id: "close", label: (t("btn_close") || "Fermer") },
            { id: "add", primary: true, label: (t("asset.types_add") || "Ajouter ce type"),
              result: function() {
                  var id = ((document.getElementById("nt-id") as HTMLInputElement).value || "").trim().toLowerCase().replace(/[^a-z0-9_]/g, "_");
                  var label = ((document.getElementById("nt-label") as HTMLInputElement).value || "").trim();
                  var labelEn = ((document.getElementById("nt-label-en") as HTMLInputElement).value || "").trim();
                  var color = (document.getElementById("nt-color") as HTMLInputElement).value || "var(--ct-ink-2)";
                  if (!id || !label) { showStatus(t("asset.types_err_missing") || "Id et Label FR requis", true); return false; }
                  // Conflict with built-in?
                  if (ASSET_TYPES_BUILTIN.indexOf(id) >= 0) { showStatus(t("asset.types_err_builtin") || "Cet ID est déjà pris par un type prédéfini", true); return false; }
                  // Conflict with existing custom?
                  if ((D.custom_asset_types || []).some(function(x) { return x.id === id; })) {
                      showStatus(t("asset.types_err_dup") || "Un type avec cet ID existe déjà", true);
                      return false;
                  }
                  return { id: id, label: label, label_en: labelEn, color: color };
              } }
        ]
    }).then(function(newType: any) {
        if (!newType) return;
        if (!Array.isArray(D.custom_asset_types)) D.custom_asset_types = [];
        D.custom_asset_types.push(newType);
        if (typeof _save === "function") _save();
        showStatus((t("asset.types_added") || "Type ajouté") + " : " + newType.label);
        // Re-open to show the updated list and let the user add more.
        setTimeout(_renderAssetTypesModal, 100);
    });
}

window._deleteCustomType = function(idx: number) {
    var customs = D.custom_asset_types || [];
    var ct = customs[idx];
    if (!ct) return;
    // Check if any asset still uses this type.
    var inUse = (D.assets || []).filter(function(a) { return a.type === ct.id; }).length;
    var msg = inUse > 0
        ? ((t("asset.types_in_use") || "Ce type est utilisé par {n} actif(s). Supprimer quand même ?").replace("{n}", String(inUse)))
        : (t("asset.types_confirm_delete") || "Supprimer ce type ?");
    if (!confirm(msg)) return;
    customs.splice(idx, 1);
    if (typeof _save === "function") _save();
    showStatus(t("asset.types_removed") || "Type supprimé");
    setTimeout(_renderAssetTypesModal, 100);
};

function deleteAsset(): void {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    if (!a) return;
    _ctConfirm(t("asset.confirm_delete"), t("asset.confirm_delete_body", { nom: a.nom }), function() {
        var aid = a.id;
        D.assets.splice(_selectedAsset!, 1);
        // Remove from groupes
        D.groupes.forEach(function(g) {
            g.asset_ids = (g.asset_ids || []).filter(function(id) { return id !== aid; });
        });
        // Remove from depends_on
        D.assets.forEach(function(x) {
            x.depends_on = (x.depends_on || []).filter(function(id) { return id !== aid; });
        });
        _selectedAsset = null;
        renderPanel();
        _save();
    });
}
window.deleteAsset = deleteAsset;

// ═══════════════════════════════════════════════════════════════
// ASSET DETAIL
// ═══════════════════════════════════════════════════════════════

function renderAssetDetail(): string {
    var a = D.assets[_selectedAsset!];
    if (!a) return renderAssetList();

    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToAssets">&laquo; ' + t("nav.assets") + '</button>';
    h += '<h2 class="ct-m-0">' + esc(a.nom || t("asset.new")) + '</h2>';
    h += _typeBadge(a.type);
    h += '<span class="ct-flex-1"></span>';
    h += '<button class="ct-btn mt-8" data-write data-variant="danger" data-click="deleteAsset">' + t("btn_delete") + '</button>';
    h += '</div>';

    // Manual-override banner — shows which fields are locked against
    // connector overwrites and offers a one-click release.
    var manualFields = _getManualFields(a);
    if (manualFields.length > 0) {
        h += '<div class="manual-lock-banner">';
        h += '<span>&#128274; <strong>' + (t("asset.manual_lock_title") || "Édits manuels protégés") + '</strong> : '
           + (t("asset.manual_lock_body") || "les champs suivants ne seront pas écrasés par les synchros connecteur — ")
           + '<em>' + manualFields.map(function(f) { return esc(_fieldLabel(f)); }).join(", ") + '</em></span>';
        h += '<span class="ct-flex-1"></span>';
        h += '<button class="ct-btn mt-8" data-write data-size="xs" data-click="_clearManualLocks">'
           + (t("asset.manual_lock_release") || "Réautoriser les connecteurs")
           + '</button>';
        h += '</div>';
    }

    h += '<div class="ct-tprm-form">';
    h += '<div class="ct-form-grid">';
    h += _formField("nom", t("asset.col_nom"), "text", a.nom);
    h += _formSelect("type", t("asset.col_type"), ASSET_TYPES.map(function(t2) { return { v: t2, l: _typeLabel(t2) }; }), a.type);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += '<div class="ct-form-row"><label>' + esc(t("asset.col_proprio")) + '</label>' + _dirPicker(a.proprietaire, "saveAssetField", _da("proprietaire")) + '</div>';
    h += _formField("localisation", t("asset.localisation"), "text", a.localisation);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _formField("fournisseur", t("asset.fournisseur"), "text", a.fournisseur);
    h += _formField("quantite", t("asset.quantite"), "number", a.quantite);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _formField("os", t("asset.os"), "text", a.os);
    h += _formField("version", t("asset.version"), "text", a.version);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _formField("ip_address", t("asset.col_ip") || "IP", "text", a.ip_address);
    h += '<div></div>';
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _formField("fin_support", t("asset.col_fin_support"), "date", a.fin_support);
    h += _formField("fin_vie", t("asset.fin_vie"), "date", a.fin_vie);
    h += '</div>';

    // Licence / support contract cycle
    var lic = a.licence || {};
    h += '<div class="form-section">' + t("licence.section") + '</div>';
    h += '<div class="ct-form-grid">';
    h += _licField("date_renouvellement", t("licence.date_renouvellement"), "date", lic.date_renouvellement);
    h += _licField("preavis_jours", t("licence.preavis_jours"), "number", lic.preavis_jours != null ? lic.preavis_jours : 30);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _licField("cout", t("licence.cout"), "text", lic.cout);
    h += _licField("devise", t("licence.devise"), "text", lic.devise || "EUR");
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _licField("reference", t("licence.reference"), "text", lic.reference);
    h += _licField("contact", t("licence.contact"), "text", lic.contact);
    h += '</div>';

    h += '<div class="ct-form-grid">';
    h += _formSelect("criticite", t("asset.col_crit"), [1,2,3,4,5].map(function(v) { return { v: v, l: _critLabel(v) }; }), a.criticite);
    h += _formSelect("statut", t("asset.col_statut"), ["actif","inactif","en_cours","retire"].map(function(s) { return { v: s, l: _statusLabel(s) }; }), a.statut);
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("asset.description") + '</label>';
    h += '<textarea id="asset-description" rows="3" data-change="saveAssetField" data-args=\'["description"]\' data-pass-value>' + esc(a.description || "") + '</textarea>';
    if (window._aiIsEnabled != null && _aiIsEnabled()) {
        h += '<button class="ct-btn btn-ai" data-size="xs" data-click="aiSuggestDescription">&#10024; ' + t("ai.suggest_description") + '</button>';
    }
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("asset.notes") + '</label>';
    h += '<textarea rows="2" data-change="saveAssetField" data-args=\'["notes"]\' data-pass-value>' + esc(a.notes || "") + '</textarea></div>';

    // Dependencies (assets + groupes)
    h += '<div class="form-section">' + t("asset.dependances") + '</div>';
    var deps = (a.depends_on || []).map(function(id): AssetDepView | null {
        var asset = D.assets.find(function(x) { return x.id === id; });
        if (asset) return { id: asset.id, nom: asset.nom, badge: _typeBadge(asset.type), kind: "asset" };
        var grp = D.groupes.find(function(x) { return x.id === id; });
        if (grp) return { id: grp.id, nom: grp.nom, badge: _badge(t("nav.groupes"), "var(--ct-ink-2)"), kind: "groupe" };
        return null;
    }).filter(Boolean) as AssetDepView[];
    if (deps.length) {
        deps.forEach(function(d) {
            h += '<div class="ct-flex ct-items-center ct-gap-1 ct-py-1 ct-px-0 ct-text-meta">';
            h += d.badge + ' <span>' + esc(d.nom) + '</span>';
            h += '<button class="ct-btn ct-ml-auto" data-variant="danger" data-size="xs" data-icon data-click="removeAssetDep" data-args=\'' + _da(d.id) + '\'>' + _icon("trash", 14) + '</button>';
            h += '</div>';
        });
    } else {
        h += '<div class="ct-muted ct-text-meta">-</div>';
    }
    h += _depSearchInput("addAssetDep", "asset-dep-search", a.id, a.depends_on || []);

    // Reverse dependencies
    var revDeps = D.assets.filter(function(x) { return (x.depends_on || []).indexOf(a.id) >= 0; });
    var revGrpDeps = D.groupes.filter(function(g) { return (g.depends_on_groups || []).indexOf(a.id) >= 0; });
    if (revDeps.length || revGrpDeps.length) {
        h += '<div class="form-section">' + t("asset.used_by") + '</div>';
        revDeps.forEach(function(d) {
            h += '<div class="ct-text-meta ct-py-1 ct-px-0">' + _typeBadge(d.type) + ' ' + esc(d.nom) + '</div>';
        });
        revGrpDeps.forEach(function(g) {
            h += '<div class="ct-text-meta ct-py-1 ct-px-0">' + _badge(t("nav.groupes"), "var(--ct-ink-2)") + ' ' + esc(g.nom) + '</div>';
        });
    }

    // Group membership
    h += '<div class="form-section">' + t("asset.groupes") + '</div>';
    var gList = (a.groupe_ids || []).map(function(gid) { return D.groupes.find(function(x) { return x.id === gid; }); }).filter(Boolean) as AssetGroupe[];
    if (gList.length) {
        gList.forEach(function(g) {
            h += '<div class="ct-flex ct-items-center ct-gap-1 ct-py-1 ct-px-0 ct-text-meta">';
            h += '<span class="ct-strong">' + esc(g.nom) + '</span>';
            h += '<button class="ct-btn ct-ml-auto" data-variant="danger" data-size="xs" data-icon data-click="removeAssetGroupe" data-args=\'' + _da(g.id) + '\'>' + _icon("trash", 14) + '</button>';
            h += '</div>';
        });
    } else {
        h += '<div class="ct-muted ct-text-meta">-</div>';
    }
    h += '<select class="ct-mt-1 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-label" data-change="addAssetGroupe" data-pass-value>';
    h += '<option value="">+ ' + t("asset.add_groupe") + '</option>';
    D.groupes.forEach(function(g) {
        if ((a.groupe_ids || []).indexOf(g.id) >= 0) return;
        h += '<option value="' + esc(g.id) + '">' + esc(g.nom) + '</option>';
    });
    h += '</select>';

    h += '</div>';
    return h;
}

function _formField(name: string, label: string, type: string, val: string | number | null | undefined): string {
    return '<div class="ct-form-row"><label>' + esc(label) + '</label>'
        + '<input type="' + type + '" value="' + esc(String(val != null ? val : "")) + '" data-change="saveAssetField" data-args=\'["' + name + '"]\' data-pass-value></div>';
}

function _formSelect(name: string, label: string, opts: { v: string | number; l: string }[], val: string | number | null | undefined): string {
    var h = '<div class="ct-form-row"><label>' + esc(label) + '</label><select data-change="saveAssetField" data-args=\'["' + name + '"]\' data-pass-value>';
    opts.forEach(function(o) {
        h += '<option value="' + esc(String(o.v)) + '"' + (String(val) === String(o.v) ? " selected" : "") + '>' + esc(o.l) + '</option>';
    });
    return h + '</select></div>';
}

// Fields a connector can set on an asset. Editing any of these marks
// the field as "manual" in sources.fields so the backend merge layer
// won't let a subsequent sync overwrite the human edit.
// Keep in sync with _CONNECTOR_FIELDS in asset/src/routes/plugins.py.
var _MANUAL_OVERRIDE_FIELDS = [
    "type", "description", "criticite", "proprietaire", "localisation",
    "os", "version", "fournisseur", "fin_support", "fin_vie",
    "statut", "ip_address", "nom",
];

function _markManual(asset: AssetItem | null | undefined, field: string): void {
    if (!asset || _MANUAL_OVERRIDE_FIELDS.indexOf(field) < 0) return;
    asset.sources = asset.sources || {};
    asset.sources.fields = asset.sources.fields || {};
    asset.sources.fields[field] = "manual";
}

function _getManualFields(asset: AssetItem | null | undefined): string[] {
    var f = (asset && asset.sources && asset.sources.fields) || {};
    return Object.keys(f).filter(function(k) { return f[k] === "manual"; });
}

function _fieldLabel(field: string): string {
    var map: Record<string, string> = {
        type: t("asset.col_type"),
        description: t("asset.description"),
        criticite: t("asset.col_crit"),
        proprietaire: t("asset.col_proprio"),
        localisation: t("asset.col_localisation"),
        os: t("asset.col_os"),
        version: t("asset.version"),
        fournisseur: t("asset.fournisseur"),
        fin_support: t("asset.col_fin_support"),
        fin_vie: t("asset.fin_vie"),
        statut: t("asset.col_statut"),
        ip_address: t("asset.col_ip"),
        nom: t("asset.col_nom"),
    };
    return map[field] || field;
}

window._clearManualLocks = function() {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    if (!a || !a.sources || !a.sources.fields) return;
    var f = a.sources.fields;
    Object.keys(f).forEach(function(k) { if (f[k] === "manual") delete f[k]; });
    _save();
    renderPanel();
    showStatus(t("asset.manual_lock_cleared") || "Verrous retirés — les prochaines synchros pourront écraser ces champs");
};

function saveAssetField(field: string, val: any): void {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    if (!a) return;
    if (field === "criticite" || field === "quantite") val = parseInt(val) || 1;
    (a as any)[field] = val;
    _markManual(a, field);
    _save();
}
window.saveAssetField = saveAssetField;

function _licField(name: string, label: string, type: string, val: string | number | null | undefined): string {
    return '<div class="ct-form-row"><label>' + esc(label) + '</label>'
        + '<input type="' + type + '" value="' + esc(String(val != null ? val : "")) + '" data-change="saveLicenceField" data-args=\'["' + name + '"]\' data-pass-value></div>';
}

function saveLicenceField(field: string, val: any): void {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    if (!a) return;
    if (!a.licence) a.licence = {};
    if (field === "preavis_jours") val = parseInt(val) || 0;
    (a.licence as any)[field] = val;
    _markManual(a, "licence");
    _save();
}
window.saveLicenceField = saveLicenceField;

function backToAssets(): void { _selectedAsset = null; renderPanel(); }
window.backToAssets = backToAssets;

function _depSearchInput(handler: string, listId: string, excludeId: string, existingIds: string[]): string {
    var h = '<div class="ct-flex ct-gap-1 ct-mt-1">';
    h += '<input type="text" list="' + listId + '" id="' + listId + '-input" placeholder="' + esc(t("asset.search_dep")) + '" class="ct-flex-1 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-label">';
    h += '<button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-variant="primary" data-click="' + handler + '">+</button>';
    h += '</div>';
    h += '<datalist id="' + listId + '">';
    D.assets.forEach(function(x) {
        if (x.id === excludeId || existingIds.indexOf(x.id) >= 0) return;
        h += '<option value="' + esc(x.id) + '">' + esc(x.id + " — " + x.nom + " (" + _typeLabel(x.type) + ")") + '</option>';
    });
    D.groupes.forEach(function(g) {
        if (g.id === excludeId || existingIds.indexOf(g.id) >= 0) return;
        h += '<option value="' + esc(g.id) + '">' + esc(g.id + " — " + g.nom + " (" + t("nav.groupes") + ")") + '</option>';
    });
    h += '</datalist>';
    return h;
}

function addAssetDep(): void {
    if (_selectedAsset === null) return;
    var input = document.getElementById("asset-dep-search-input") as HTMLInputElement | null;
    var id = input ? input.value.trim().split(" — ")[0].trim() : "";
    if (!id) return;
    var a = D.assets[_selectedAsset];
    if (!a.depends_on) a.depends_on = [];
    var exists = D.assets.some(function(x) { return x.id === id; }) || D.groupes.some(function(x) { return x.id === id; });
    if (exists && a.depends_on.indexOf(id) < 0) a.depends_on.push(id);
    renderPanel(); _save();
}
window.addAssetDep = addAssetDep;

function removeAssetDep(id: string): void {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    a.depends_on = (a.depends_on || []).filter(function(x) { return x !== id; });
    renderPanel(); _save();
}
window.removeAssetDep = removeAssetDep;

function addAssetGroupe(gid: string): void {
    if (!gid || _selectedAsset === null) return;
    _linkAssetsToGroup([D.assets[_selectedAsset].id], gid);
    renderPanel();
}
window.addAssetGroupe = addAssetGroupe;

function removeAssetGroupe(gid: string): void {
    if (_selectedAsset === null) return;
    var a = D.assets[_selectedAsset];
    a.groupe_ids = (a.groupe_ids || []).filter(function(x) { return x !== gid; });
    var g = D.groupes.find(function(x) { return x.id === gid; });
    if (g) g.asset_ids = (g.asset_ids || []).filter(function(x) { return x !== a.id; });
    renderPanel(); _save();
}
window.removeAssetGroupe = removeAssetGroupe;

// ═══════════════════════════════════════════════════════════════
// GROUPE LIST
// ═══════════════════════════════════════════════════════════════

function renderGroupeList(): string {
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("nav.groupes") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-size="xs" data-click="addGroupe">' + t("groupe.add") + '</button>';
    h += '</div>';

    if (!D.groupes.length) {
        h += '<div class="ct-empty-state">' + t("groupe.empty") + '</div>';
        return h;
    }

    D.groupes.forEach(function(g, i) {
        var n = (g.asset_ids || []).length;
        h += '<div class="ct-groupe-card" data-click="openGroupe" data-args=\'' + _da(i) + '\'>';
        h += '<div class="ct-flex ct-items-center ct-gap-2">';
        h += '<strong class="ct-flex-1">' + esc(g.nom || t("groupe.new")) + '</strong>';
        h += _critBadge(g.criticite || 1);
        h += '</div>';
        if (g.principe) h += '<div class="ct-text-label ct-journal-sep ct-mt-1 ct-overflow-hidden ct-ellipsis ct-nowrap">' + esc(g.principe) + '</div>';
        h += '<div class="ct-flex ct-gap-3 ct-mt-1 ct-text-label ct-muted">';
        h += '<span>' + n + ' ' + t("nav.assets").toLowerCase() + '</span>';
        var raciOk = g.raci && (g.raci as any).installation && (g.raci as any).installation.r;
        h += '<span>' + t("groupe.raci") + ': ' + (raciOk ? "✓" : "—") + '</span>';
        h += '</div>';
        h += '</div>';
    });
    return h;
}

function openGroupe(idx: string | number): void { _selectedGroupe = parseInt(String(idx)); _groupeTab = "info"; renderPanel(); }
window.openGroupe = openGroupe;

function addGroupe(): void {
    D.groupes.push({
        id: _genId("G-", D.groupes), nom: "", principe: "", criticite: 2,
        raci: {
            installation: { r: "", a: "", c: "", i: "" },
            mco: { r: "", a: "", c: "", i: "" },
            mcs: { r: "", a: "", c: "", i: "" }
        },
        politique_sauvegarde: { frequence: "", retention: "", type: "", site_distant: false, teste: false, dernier_test: "", notes: "" },
        politique_supervision: { outil: "", perimetre: "", alerting: false, h24: false, notes: "" },
        politique_maj: { frequence: "", fenetre: "", validation: "", critique_delai: "", notes: "" },
        asset_ids: [], depends_on_groups: [], notes: ""
    });
    _selectedGroupe = D.groupes.length - 1;
    renderPanel(); _save();
}
window.addGroupe = addGroupe;

function deleteGroupe(): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    _ctConfirm(t("groupe.confirm_delete"), t("groupe.confirm_delete_body", { nom: g.nom }), function() {
        var gid = g.id;
        D.groupes.splice(_selectedGroupe!, 1);
        D.assets.forEach(function(a) {
            a.groupe_ids = (a.groupe_ids || []).filter(function(id) { return id !== gid; });
        });
        _selectedGroupe = null;
        renderPanel(); _save();
    });
}
window.deleteGroupe = deleteGroupe;

// ═══════════════════════════════════════════════════════════════
// GROUPE DETAIL
// ═══════════════════════════════════════════════════════════════

function renderGroupeDetail(): string {
    var g = D.groupes[_selectedGroupe!];
    if (!g) return renderGroupeList();

    var h = '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-1 ct-row-wrap">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToGroupes">&laquo; ' + t("nav.groupes") + '</button>';
    h += '<h2 class="ct-m-0">' + esc(g.nom || t("groupe.new")) + '</h2>';
    h += '<span class="ct-flex-1"></span>';
    h += '<button class="ct-btn mt-8" data-write data-variant="danger" data-click="deleteGroupe">' + t("btn_delete") + '</button>';
    h += '</div>';

    // Tabs
    var tabs = ["info", "raci", "politiques", "actifs", "deps"];
    h += '<div class="vendor-tabs">';
    tabs.forEach(function(tab) {
        h += '<button class="vendor-tab' + (_groupeTab === tab ? " active" : "") + '" data-click="switchGroupeTab" data-args=\'' + _da(tab) + '\'>' + t("groupe.tab_" + tab) + '</button>';
    });
    h += '</div>';

    switch (_groupeTab) {
        case "info": h += _renderGroupeInfo(g); break;
        case "raci": h += _renderGroupeRaci(g); break;
        case "politiques": h += _renderGroupePolitiques(g); break;
        case "actifs": h += _renderGroupeActifs(g); break;
        case "deps": h += _renderGroupeDeps(g); break;
    }
    return h;
}

function switchGroupeTab(tab: string): void { _groupeTab = tab; renderPanel(); }
window.switchGroupeTab = switchGroupeTab;

function backToGroupes(): void { _selectedGroupe = null; renderPanel(); }
window.backToGroupes = backToGroupes;

function _renderGroupeInfo(g: AssetGroupe): string {
    var h = '<div class="ct-tprm-form">';
    h += '<div class="ct-form-grid">';
    h += _gField("nom", t("groupe.nom"), "text", g.nom);
    h += _gSelect("criticite", t("asset.col_crit"), [1,2,3,4,5].map(function(v) { return { v: v, l: _critLabel(v) }; }), g.criticite);
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("groupe.principe") + '</label>';
    h += '<textarea id="groupe-principe" rows="4" data-change="saveGroupeField" data-args=\'["principe"]\' data-pass-value>' + esc(g.principe || "") + '</textarea>';
    if (window._aiIsEnabled != null && _aiIsEnabled()) {
        h += '<button class="ct-btn btn-ai" data-size="xs" data-click="aiSuggestPrincipe">&#10024; ' + t("ai.suggest_principe") + '</button>';
    }
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("asset.notes") + '</label>';
    h += '<textarea rows="2" data-change="saveGroupeField" data-args=\'["notes"]\' data-pass-value>' + esc(g.notes || "") + '</textarea></div>';
    h += '</div>';
    return h;
}

var RACI_DEFAULTS = ["installation", "mco", "mcs"];

function _ensureRaciArray(g: AssetGroupe): void {
    if (Array.isArray(g.raci)) return;
    // Migrate from old object format or init defaults
    var arr: AssetRaciRow[] = [];
    if (g.raci && typeof g.raci === "object" && !Array.isArray(g.raci)) {
        Object.keys(g.raci).forEach(function(k) {
            var row = (g.raci as AssetRaciLegacy)[k] || {};
            arr.push({ activite: k, r: row.r || "", a: row.a || "", c: row.c || "", i: row.i || "" });
        });
    }
    if (!arr.length) {
        RACI_DEFAULTS.forEach(function(act) {
            arr.push({ activite: act, r: "", a: "", c: "", i: "" });
        });
    }
    g.raci = arr;
}

function _renderGroupeRaci(g: AssetGroupe): string {
    _ensureRaciArray(g);
    var roles: (keyof AssetRaciCells)[] = ["r", "a", "c", "i"];

    var h = '<div class="ct-tprm-form">';
    if (window._aiIsEnabled != null && _aiIsEnabled()) {
        h += '<button class="ct-btn btn-ai ct-mb-3" data-size="xs" data-click="aiSuggestRaci">&#10024; ' + t("ai.suggest_raci") + '</button>';
    }
    h += '<table class="raci-table"><thead><tr><th>' + t("groupe.raci_activite") + '</th>';
    roles.forEach(function(r) { h += '<th>' + t("groupe.raci_" + r) + '</th>'; });
    h += '<th class="ct-w-30"></th></tr></thead><tbody>';

    (g.raci as AssetRaciRow[]).forEach(function(row, idx) {
        var label = t("groupe.act_" + row.activite) || row.activite;
        var isDefault = RACI_DEFAULTS.indexOf(row.activite) >= 0;
        h += '<tr>';
        if (isDefault) {
            h += '<td class="ct-strong ct-text-meta">' + esc(label) + '</td>';
        } else {
            h += '<td><input type="text" value="' + esc(row.activite) + '" class="ct-w-full ct-p-1 ct-bordered ct-r-sm ct-text-meta ct-strong" data-change="saveRaciActivite" data-args=\'' + _da(idx) + '\' data-pass-value></td>';
        }
        roles.forEach(function(r) {
            h += '<td><input type="text" value="' + esc(row[r] || "") + '" class="ct-input" data-change="saveRaciCell" data-args=\'' + _da(idx, r) + '\' data-pass-value></td>';
        });
        h += '<td>';
        if (!isDefault) {
            h += '<button class="ct-btn" data-variant="danger" data-size="xs" data-icon data-click="removeRaciRow" data-args=\'' + _da(idx) + '\'>' + _icon("trash", 14) + '</button>';
        }
        h += '</td></tr>';
    });
    h += '</tbody></table>';
    h += '<button class="ct-btn mt-8 ct-mt-2 ct-text-label" data-write data-variant="primary" data-size="xs" data-click="addRaciRow">+ ' + t("groupe.raci_add_row") + '</button>';
    h += '</div>';
    return h;
}

function saveRaciCell(idx: number, role: string, val: string): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    _ensureRaciArray(g);
    if ((g.raci as AssetRaciRow[])[idx]) ((g.raci as AssetRaciRow[])[idx] as any)[role] = val;
    _save();
}
window.saveRaciCell = saveRaciCell;

function saveRaciActivite(idx: number, val: string): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    _ensureRaciArray(g);
    if ((g.raci as AssetRaciRow[])[idx]) (g.raci as AssetRaciRow[])[idx].activite = val;
    _save();
}
window.saveRaciActivite = saveRaciActivite;

function addRaciRow(): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    _ensureRaciArray(g);
    (g.raci as AssetRaciRow[]).push({ activite: "", r: "", a: "", c: "", i: "" });
    renderPanel(); _save();
}
window.addRaciRow = addRaciRow;

function removeRaciRow(idx: string | number): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    _ensureRaciArray(g);
    idx = parseInt(String(idx));
    var raci = g.raci as AssetRaciRow[];
    if (raci[idx] && RACI_DEFAULTS.indexOf(raci[idx].activite) < 0) {
        raci.splice(idx, 1);
        renderPanel(); _save();
    }
}
window.removeRaciRow = removeRaciRow;

function _renderGroupePolitiques(g: AssetGroupe): string {
    var h = '<div class="ct-tprm-form">';
    if (window._aiIsEnabled != null && _aiIsEnabled()) {
        h += '<button class="ct-btn btn-ai ct-mb-3" data-size="xs" data-click="aiSuggestPolitiques">&#10024; ' + t("ai.suggest_politiques") + '</button>';
    }

    // Backup policy
    var ps = g.politique_sauvegarde || {};
    h += '<div class="form-section">' + t("groupe.pol_sauvegarde") + '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolField("politique_sauvegarde", "frequence", t("groupe.pol_frequence"), ps.frequence);
    h += _gPolField("politique_sauvegarde", "retention", t("groupe.pol_retention"), ps.retention);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolField("politique_sauvegarde", "type", t("groupe.pol_type_sauv"), ps.type);
    h += _gPolField("politique_sauvegarde", "dernier_test", t("groupe.pol_dernier_test"), ps.dernier_test, "date");
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolCheck("politique_sauvegarde", "site_distant", t("groupe.pol_site_distant"), ps.site_distant);
    h += _gPolCheck("politique_sauvegarde", "teste", t("groupe.pol_teste"), ps.teste);
    h += '</div>';
    h += _gPolTextarea("politique_sauvegarde", "notes", t("asset.notes"), ps.notes);

    // Monitoring policy
    var pm = g.politique_supervision || {};
    h += '<div class="form-section">' + t("groupe.pol_supervision") + '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolField("politique_supervision", "outil", t("groupe.pol_outil"), pm.outil);
    h += _gPolField("politique_supervision", "perimetre", t("groupe.pol_perimetre"), pm.perimetre);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolCheck("politique_supervision", "alerting", t("groupe.pol_alerting"), pm.alerting);
    h += _gPolCheck("politique_supervision", "h24", t("groupe.pol_h24"), pm.h24);
    h += '</div>';
    h += _gPolTextarea("politique_supervision", "notes", t("asset.notes"), pm.notes);

    // Update policy
    var pu = g.politique_maj || {};
    h += '<div class="form-section">' + t("groupe.pol_maj") + '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolField("politique_maj", "frequence", t("groupe.pol_frequence"), pu.frequence);
    h += _gPolField("politique_maj", "fenetre", t("groupe.pol_fenetre"), pu.fenetre);
    h += '</div>';
    h += '<div class="ct-form-grid">';
    h += _gPolField("politique_maj", "validation", t("groupe.pol_validation"), pu.validation);
    h += _gPolField("politique_maj", "critique_delai", t("groupe.pol_critique_delai"), pu.critique_delai);
    h += '</div>';
    h += _gPolTextarea("politique_maj", "notes", t("asset.notes"), pu.notes);

    h += '</div>';
    return h;
}

function _renderGroupeActifs(g: AssetGroupe): string {
    var members = (g.asset_ids || []).map(function(id) { return D.assets.find(function(x) { return x.id === id; }); }).filter(Boolean) as AssetItem[];

    var h = '<div class="ct-tprm-form">';
    if (members.length) {
        h += '<table id="groupe-assets-table"><thead><tr>';
        h += '<th>ID</th><th>' + t("asset.col_nom") + '</th><th>' + t("asset.col_type") + '</th><th>' + t("asset.col_crit") + '</th><th class="ct-w-30"></th>';
        h += '</tr></thead><tbody>';
        members.forEach(function(a) {
            h += '<tr>';
            h += '<td class="ct-text-label ct-muted">' + esc(a.id) + '</td>';
            h += '<td class="ct-strong">' + esc(a.nom) + '</td>';
            h += '<td>' + _typeBadge(a.type) + '</td>';
            h += '<td>' + _critBadge(a.criticite || 1) + '</td>';
            h += '<td><button class="ct-btn" data-variant="danger" data-size="xs" data-icon data-click="removeGroupeAsset" data-args=\'' + _da(a.id) + '\'>' + _icon("trash", 14) + '</button></td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
    } else {
        h += '<div class="ct-muted ct-text-meta ct-mb-2">-</div>';
    }

    h += '<button class="ct-btn mt-8 ct-mt-2 ct-text-label ct-py-1 ct-px-3" data-write data-variant="primary" data-click="_openGroupeAssetPicker">'
       + _icon("plus", 14) + ' ' + (t("groupe.add_assets") || "Ajouter des actifs") + '</button>';
    h += '</div>';
    return h;
}

// Multi-select picker: pick several assets (searchable checklist) to add to
// the current group in one go.
window._openGroupeAssetPicker = function() {
    if (_selectedGroupe === null || !window.ct_modal) return;
    var g = D.groupes[_selectedGroupe];
    var candidates = D.assets.filter(function(a) { return (g.asset_ids || []).indexOf(a.id) < 0; });
    if (!candidates.length) {
        showStatus(t("groupe.pick_assets_none") || "Tous les actifs sont déjà dans ce groupe", true);
        return;
    }
    var h = '<input type="text" id="grp-pick-search" placeholder="' + esc(t("asset.search") || "Rechercher...")
          + '" data-input="_groupePickerFilter" data-pass-value autocomplete="off"'
          + ' class="ct-w-full ct-py-1 ct-px-2 ct-bordered ct-r-md ct-text-meta ct-mb-2">';
    h += '<div id="grp-pick-list" style="max-height:340px;overflow:auto;border:1px solid var(--ct-line);border-radius:var(--ct-r-md)">';
    candidates.forEach(function(a) {
        var search = esc(((a.id || "") + " " + (a.nom || "") + " " + _typeLabel(a.type)).toLowerCase());
        h += '<label class="grp-pick-row" data-search="' + search + '"'
           + ' class="ct-flex ct-items-center ct-gap-2 ct-py-1 ct-px-2 ct-text-meta ct-clickable ct-border-bottom">'
           + '<input type="checkbox" class="grp-pick-cb" value="' + esc(a.id) + '"> '
           + '<span class="ct-muted ct-text-label">' + esc(a.id) + '</span> '
           + '<span class="ct-strong">' + esc(a.nom || "") + '</span> '
           + _typeBadge(a.type) + '</label>';
    });
    h += '</div>';
    ct_modal.open({
        title: (t("groupe.pick_assets_title") || "Ajouter des actifs à « {nom} »").replace("{nom}", esc(g.nom || g.id)),
        body: h,
        size: "md",
        buttons: [
            { id: "cancel", label: t("btn_cancel") || "Annuler" },
            { id: "add", primary: true, label: t("btn_add") || "Ajouter",
              result: function() {
                  var boxes = Array.from(document.querySelectorAll("#grp-pick-list .grp-pick-cb:checked")) as HTMLInputElement[];
                  var ids = boxes.map(function(b) { return b.value; });
                  if (!ids.length) { showStatus(t("groupe.pick_assets_empty") || "Aucun actif sélectionné", true); return false; }
                  return ids;
              } }
        ]
    }).then(function(ids: any) {
        if (!ids || !ids.length) return;
        var n = _linkAssetsToGroup(ids, g.id);
        showStatus(n + " " + (t("groupe.assets_added") || "actif(s) ajouté(s)"));
        renderPanel();
    });
};

window._groupePickerFilter = function(val: string) {
    var q = (val || "").toLowerCase().trim();
    var rows = Array.from(document.querySelectorAll("#grp-pick-list .grp-pick-row")) as HTMLElement[];
    rows.forEach(function(r) {
        var s = r.getAttribute("data-search") || "";
        r.style.display = (!q || s.indexOf(q) >= 0) ? "" : "none";
    });
};

// Link asset(s) to a group — bidirectional (asset.groupe_ids ↔ group.asset_ids),
// deduped. Shared by every add path (single from asset detail, single from
// group edit, bulk from the asset list, multi from the group picker).
// Caller re-renders; this only mutates D + persists. Returns links added.
function _linkAssetsToGroup(assetIds: string[], groupId: string): number {
    var g = D.groupes.find(function(x) { return x.id === groupId; });
    if (!g) return 0;
    if (!g.asset_ids) g.asset_ids = [];
    var count = 0;
    assetIds.forEach(function(aid) {
        var a = D.assets.find(function(x) { return x.id === aid; });
        if (!a) return;
        if (!a.groupe_ids) a.groupe_ids = [];
        if (a.groupe_ids.indexOf(groupId) < 0) a.groupe_ids.push(groupId);
        // Count only NEW memberships — assets already in the group (or a
        // duplicated id in the input) don't inflate the "added" total.
        if (g!.asset_ids!.indexOf(aid) < 0) { g!.asset_ids!.push(aid); count++; }
    });
    if (count && typeof _save === "function") _save();
    return count;
}

function addGroupeAsset(aid: string): void {
    if (!aid || _selectedGroupe === null) return;
    _linkAssetsToGroup([aid], D.groupes[_selectedGroupe].id);
    renderPanel();
}
window.addGroupeAsset = addGroupeAsset;

function removeGroupeAsset(aid: string): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    g.asset_ids = (g.asset_ids || []).filter(function(x) { return x !== aid; });
    var a = D.assets.find(function(x) { return x.id === aid; });
    if (a) a.groupe_ids = (a.groupe_ids || []).filter(function(x) { return x !== g.id; });
    renderPanel(); _save();
}
window.removeGroupeAsset = removeGroupeAsset;

// ── Groupe dependencies tab ──────────────────────────────────

function _renderGroupeDeps(g: AssetGroupe): string {
    if (!g.depends_on_groups) g.depends_on_groups = [];
    var deps = g.depends_on_groups.map(function(id): AssetDepView | null {
        var grp = D.groupes.find(function(x) { return x.id === id; });
        if (grp) return { id: grp.id, nom: grp.nom, badge: _badge(t("nav.groupes"), "var(--ct-ink-2)"), kind: "groupe" };
        var asset = D.assets.find(function(x) { return x.id === id; });
        if (asset) return { id: asset.id, nom: asset.nom, badge: _typeBadge(asset.type), kind: "asset" };
        return null;
    }).filter(Boolean) as AssetDepView[];

    var h = '<div class="ct-tprm-form">';
    h += '<div class="form-section" style="margin-top:0;border-top:none;padding-top:0">' + t("groupe.depends_on") + '</div>';
    if (deps.length) {
        deps.forEach(function(d) {
            h += '<div class="ct-flex ct-items-center ct-gap-1 ct-py-1 ct-px-0 ct-text-meta">';
            h += d.badge + ' <span>' + esc(d.nom) + '</span>';
            h += '<button class="ct-btn ct-ml-auto" data-variant="danger" data-size="xs" data-icon data-click="removeGroupeDep" data-args=\'' + _da(d.id) + '\'>' + _icon("trash", 14) + '</button>';
            h += '</div>';
        });
    } else {
        h += '<div class="ct-muted ct-text-meta ct-mb-2">-</div>';
    }
    h += _depSearchInput("addGroupeDep", "groupe-dep-search", g.id, g.depends_on_groups);

    // Reverse: who depends on this group
    var revGroups = D.groupes.filter(function(x) { return (x.depends_on_groups || []).indexOf(g.id) >= 0; });
    var revAssets = D.assets.filter(function(x) { return (x.depends_on || []).indexOf(g.id) >= 0; });
    if (revGroups.length || revAssets.length) {
        h += '<div class="form-section">' + t("asset.used_by") + '</div>';
        revGroups.forEach(function(x) {
            h += '<div class="ct-text-meta ct-py-1 ct-px-0">' + _badge(t("nav.groupes"), "var(--ct-ink-2)") + ' ' + esc(x.nom) + '</div>';
        });
        revAssets.forEach(function(x) {
            h += '<div class="ct-text-meta ct-py-1 ct-px-0">' + _typeBadge(x.type) + ' ' + esc(x.nom) + '</div>';
        });
    }

    h += '</div>';
    return h;
}

function addGroupeDep(): void {
    if (_selectedGroupe === null) return;
    var input = document.getElementById("groupe-dep-search-input") as HTMLInputElement | null;
    var id = input ? input.value.trim().split(" — ")[0].trim() : "";
    if (!id) return;
    var g = D.groupes[_selectedGroupe];
    if (!g.depends_on_groups) g.depends_on_groups = [];
    var exists = D.assets.some(function(x) { return x.id === id; }) || D.groupes.some(function(x) { return x.id === id; });
    if (exists && id !== g.id && g.depends_on_groups.indexOf(id) < 0) g.depends_on_groups.push(id);
    renderPanel(); _save();
}
window.addGroupeDep = addGroupeDep;

function removeGroupeDep(id: string): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    g.depends_on_groups = (g.depends_on_groups || []).filter(function(x) { return x !== id; });
    renderPanel(); _save();
}
window.removeGroupeDep = removeGroupeDep;

// Groupe field helpers
function _gField(name: string, label: string, type: string, val: string | null | undefined): string {
    return '<div class="ct-form-row"><label>' + esc(label) + '</label>'
        + '<input type="' + type + '" value="' + esc(String(val != null ? val : "")) + '" data-change="saveGroupeField" data-args=\'["' + name + '"]\' data-pass-value></div>';
}

function _gSelect(name: string, label: string, opts: { v: string | number; l: string }[], val: string | number | null | undefined): string {
    var h = '<div class="ct-form-row"><label>' + esc(label) + '</label><select data-change="saveGroupeField" data-args=\'["' + name + '"]\' data-pass-value>';
    opts.forEach(function(o) {
        h += '<option value="' + esc(String(o.v)) + '"' + (String(val) === String(o.v) ? " selected" : "") + '>' + esc(o.l) + '</option>';
    });
    return h + '</select></div>';
}

function _gPolField(pol: string, field: string, label: string, val: string | undefined, type?: string): string {
    return '<div class="ct-form-row"><label>' + esc(label) + '</label>'
        + '<input type="' + (type || "text") + '" value="' + esc(String(val || "")) + '" data-change="saveGroupePol" data-args=\'' + _da(pol, field) + '\' data-pass-value></div>';
}

function _gPolCheck(pol: string, field: string, label: string, val: boolean | undefined): string {
    return '<div class="ct-form-row"><label style="display:inline-flex;align-items:center;gap:var(--ct-s1);cursor:pointer;text-transform:none">'
        + '<input type="checkbox"' + (val ? " checked" : "") + ' data-change="saveGroupePolCheck" data-args=\'' + _da(pol, field) + '\' data-pass-el> ' + esc(label) + '</label></div>';
}

function _gPolTextarea(pol: string, field: string, label: string, val: string | undefined): string {
    return '<div class="ct-form-row"><label>' + esc(label) + '</label>'
        + '<textarea rows="2" data-change="saveGroupePol" data-args=\'' + _da(pol, field) + '\' data-pass-value>' + esc(val || "") + '</textarea></div>';
}

function saveGroupeField(field: string, val: any): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    if (field === "criticite") val = parseInt(val) || 1;
    (g as any)[field] = val;
    _save();
}
window.saveGroupeField = saveGroupeField;

function saveGroupePol(pol: string, field: string, val: string): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    if (!(g as any)[pol]) (g as any)[pol] = {};
    (g as any)[pol][field] = val;
    _save();
}
window.saveGroupePol = saveGroupePol;

function saveGroupePolCheck(pol: string, field: string, el: HTMLInputElement): void {
    if (_selectedGroupe === null) return;
    var g = D.groupes[_selectedGroupe];
    if (!(g as any)[pol]) (g as any)[pol] = {};
    (g as any)[pol][field] = el.checked;
    _save();
}
window.saveGroupePolCheck = saveGroupePolCheck;

// ═══════════════════════════════════════════════════════════════
// DEPENDENCIES VIEW
// ═══════════════════════════════════════════════════════════════

function renderDependances(): string {
    var h = '<h2>' + t("nav.dependances") + '</h2>';

    if (!D.groupes.length && !D.assets.length) {
        h += '<div class="ct-empty-state">' + t("asset.empty") + '</div>';
        return h;
    }

    // Matrix: groups x asset types
    if (D.groupes.length) {
        h += '<div class="dash-section">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("dep.matrix_title") + '</h3>';
        h += '<div class="ct-scroll-x"><table><thead><tr><th>' + t("nav.groupes") + '</th>';
        ASSET_TYPES.forEach(function(type) {
            h += '<th class="ct-text-label ct-ta-c">' + esc(_typeLabel(type)) + '</th>';
        });
        h += '<th class="ct-ta-c">Total</th></tr></thead><tbody>';

        D.groupes.forEach(function(g) {
            h += '<tr><td class="ct-strong ct-text-meta">' + esc(g.nom) + '</td>';
            var total = 0;
            ASSET_TYPES.forEach(function(type) {
                var count = (g.asset_ids || []).filter(function(aid) {
                    var a = D.assets.find(function(x) { return x.id === aid; });
                    return a && a.type === type;
                }).length;
                total += count;
                h += '<td style="text-align:center;font-size:var(--ct-text-meta);color:' + (count > 0 ? "var(--ct-ink)" : "var(--ct-ink-2)") + '">' + (count || "-") + '</td>';
            });
            h += '<td class="ct-ta-c ct-strong">' + total + '</td></tr>';
        });
        h += '</tbody></table></div></div>';
    }

    // Asset dependency chains
    var withDeps = D.assets.filter(function(a) { return (a.depends_on || []).length > 0; });
    if (withDeps.length) {
        h += '<div class="dash-section">';
        h += '<h3 class="ct-text-data ct-mb-2">' + t("dep.chains_title") + '</h3>';
        withDeps.forEach(function(a) {
            h += '<div class="ct-py-1 ct-px-0 ct-text-meta">';
            h += '<span class="ct-strong">' + esc(a.nom) + '</span>';
            h += ' <span class="ct-muted">→</span> ';
            h += (a.depends_on || []).map(function(did) {
                var d = D.assets.find(function(x) { return x.id === did; });
                return d ? esc(d.nom) : esc(did);
            }).join(", ");
            h += '</div>';
        });
        h += '</div>';
    }

    return h;
}

// ═══════════════════════════════════════════════════════════════
// CONFIRM DIALOG (reuse pattern from shared)
// ═══════════════════════════════════════════════════════════════

function _ctConfirm(title: string, body: string, onYes: () => void): void {
    var ov = document.getElementById("confirm-overlay")!;
    document.getElementById("confirm-title")!.textContent = title;
    document.getElementById("confirm-body")!.textContent = body;
    ov.style.display = "flex";
    var btnOui = document.getElementById("confirm-oui")!;
    var btnNon = document.getElementById("confirm-non")!;
    function close() { ov.style.display = "none"; btnOui.onclick = null; btnNon.onclick = null; }
    btnOui.onclick = function() { close(); onYes(); };
    btnNon.onclick = close;
}

// ═══════════════════════════════════════════════════════════════
// CSV IMPORT
// ═══════════════════════════════════════════════════════════════

function importCsvDialog(): void {
    var el = document.getElementById("csv-input") as HTMLInputElement | null;
    if (!el) return;
    el.value = "";
    el.onchange = function() {
        if (!el!.files || !el!.files[0]) return;
        _importCsvFile(el!.files[0]);
    };
    el.click();
}
window.importCsvDialog = importCsvDialog;

function _importCsvFile(file: File): void {
    if (window.AssetAPI != null && window.getActiveProjectId != null) {
        var pid = getActiveProjectId();
        if (!pid) { showStatus(t("csv.no_project"), true); return; }
        AssetAPI.importCsv(pid, file).then(function(result: any) {
            if (result && result.data) {
                Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
                Object.assign(D, result.data);
                _panel = "assets";
                _selectedAsset = null;
                renderAll();
            }
            showStatus(t("csv.imported", { count: result.imported || 0 }));
        }).catch(function(e) {
            showStatus(t("csv.error") + ": " + e.message, true);
        });
    } else {
        // Fallback: client-side CSV parsing (opensource mode)
        var reader = new FileReader();
        reader.onload = function(e) {
            _parseCsvLocal(e.target!.result as string);
        };
        reader.readAsText(file);
    }
}

function _parseCsvLocal(text: string): void {
    var lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
    if (lines.length < 2) { showStatus(t("csv.error"), true); return; }

    var firstLine = lines[0];
    var sep = firstLine.split(";").length > firstLine.split(",").length ? ";" : ",";
    var headers = _csvSplit(firstLine, sep).map(function(h) { return h.trim().toLowerCase().replace(/[ -]/g, "_"); });

    var colMap: Record<string, string> = {
        nom: "nom", name: "nom", asset: "nom", actif: "nom",
        type: "type", categorie: "type", category: "type",
        criticite: "criticite", criticality: "criticite", crit: "criticite",
        proprietaire: "proprietaire", owner: "proprietaire", responsable: "proprietaire",
        localisation: "localisation", location: "localisation", site: "localisation",
        quantite: "quantite", quantity: "quantite", qty: "quantite",
        os: "os", systeme: "os",
        version: "version",
        fournisseur: "fournisseur", vendor: "fournisseur", supplier: "fournisseur",
        fin_support: "fin_support", end_of_support: "fin_support", eos: "fin_support",
        fin_vie: "fin_vie", end_of_life: "fin_vie", eol: "fin_vie",
        statut: "statut", status: "statut", etat: "statut",
        description: "description", desc: "description",
        notes: "notes", remarques: "notes", comments: "notes"
    };

    var typeAliases: Record<string, string> = {
        mobile: "terminal_mobile", smartphone: "terminal_mobile", tablette: "terminal_mobile",
        desktop: "poste_physique", pc: "poste_physique", poste: "poste_physique",
        vdi: "poste_virtuel",
        server: "serveur_physique", serveur: "serveur_physique",
        vm: "serveur_virtuel", virtual: "serveur_virtuel", container: "serveur_virtuel",
        app: "application", software: "application", logiciel: "application", saas: "application",
        data: "donnees", database: "donnees", db: "donnees", bdd: "donnees"
    };
    var validTypes = ["terminal_mobile","poste_physique","poste_virtuel","serveur_physique","serveur_virtuel","systeme_exploitation","application","donnees"];

    var count = 0;
    for (var i = 1; i < lines.length; i++) {
        if (!lines[i].trim()) continue;
        var vals = _csvSplit(lines[i], sep);
        var mapped: Record<string, string> = {};
        for (var j = 0; j < headers.length; j++) {
            var field = colMap[headers[j]];
            if (field && vals[j]) mapped[field] = vals[j].trim();
        }
        if (!mapped.nom) continue;

        var assetType = (mapped.type || "application").toLowerCase().replace(/[ -]/g, "_");
        if (validTypes.indexOf(assetType) < 0) assetType = typeAliases[assetType] || "application";

        var crit = parseInt(mapped.criticite) || 2;
        crit = Math.max(1, Math.min(5, crit));

        D.assets.push({
            id: _genId("A-", D.assets),
            nom: mapped.nom,
            type: assetType,
            description: mapped.description || "",
            criticite: crit,
            proprietaire: mapped.proprietaire || "",
            localisation: mapped.localisation || "",
            quantite: parseInt(mapped.quantite) || 1,
            os: mapped.os || "",
            version: mapped.version || "",
            fournisseur: mapped.fournisseur || "",
            fin_support: mapped.fin_support || "",
            fin_vie: mapped.fin_vie || "",
            statut: mapped.statut || "actif",
            notes: mapped.notes || "",
            groupe_ids: [],
            depends_on: []
        });
        count++;
    }

    _panel = "assets";
    _selectedAsset = null;
    renderPanel();
    _save();
    showStatus(t("csv.imported", { count: count }));
}

function _csvSplit(line: string, sep: string): string[] {
    var result: string[] = [], current = "", inQuotes = false;
    for (var i = 0; i < line.length; i++) {
        var ch = line[i];
        if (ch === '"') { inQuotes = !inQuotes; continue; }
        if (ch === sep && !inQuotes) { result.push(current); current = ""; continue; }
        current += ch;
    }
    result.push(current);
    return result;
}

function _save(): void { if (window._autoSave) window._autoSave(); else if (window._debouncedSave) window._debouncedSave(); }

// ═══════════════════════════════════════════════════════════════
// AI ASSISTANT
// ═══════════════════════════════════════════════════════════════

// AI features — Phase 2 domain endpoints. The asset-management
// methodology (system prompt) now lives server-side in
// src/routes/ai.py. These functions only collect structured data,
// POST it to the domain endpoint, and render the structured response.
// See docs/CHANTIER_IA_BACKEND.md §Phase 2.

interface AssetAiMeta {
    methodology_context: string;
    organization: string;
}

function _aiMeta(): AssetAiMeta {
    return {
        methodology_context: window._aiGetContext != null ? (_aiGetContext() || "") : "",
        organization: (D.metadata && D.metadata.organization) || ""
    };
}

async function _aiPost(feature: string, payload: Record<string, unknown>): Promise<any> {
    var resp = await fetch("api/ai/asset/" + feature, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({} as Record<string, unknown>, _aiMeta(), payload))
    });
    if (!resp.ok) {
        var errTxt = await resp.text();
        throw new Error("API " + resp.status + ": " + errTxt.substring(0, 200));
    }
    return resp.json();
}

function aiSuggestDescription(): void {
    if (_selectedAsset === null || !(window._aiIsEnabled != null && _aiIsEnabled())) return;
    var a = D.assets[_selectedAsset];
    _aiShowLoading(t("ai.loading"));
    _aiPost("suggest-description", {
        nom: a.nom || "",
        type_label: _typeLabel(a.type),
        proprietaire: a.proprietaire || "",
        fournisseur: a.fournisseur || "",
        os: a.os || "",
        criticite_label: _critLabel(a.criticite)
    }).then(function(resp) {
        _aiClosePanel();
        var text = (resp.text || "").trim();
        a.description = text;
        var el = document.getElementById("asset-description") as HTMLTextAreaElement | null;
        if (el) el.value = text;
        _save();
        showStatus(t("ai.done"));
    }).catch(function(e) {
        _aiShowError(t("ai.error"), e.message || String(e));
    });
}
window.aiSuggestDescription = aiSuggestDescription;

function aiSuggestPrincipe(): void {
    if (_selectedGroupe === null || !(window._aiIsEnabled != null && _aiIsEnabled())) return;
    var g = D.groupes[_selectedGroupe];
    var members = (g.asset_ids || []).map(function(id) { return D.assets.find(function(x) { return x.id === id; }); }).filter(Boolean) as AssetItem[];

    _aiShowLoading(t("ai.loading"));
    _aiPost("suggest-principe", {
        nom: g.nom || "",
        criticite_label: _critLabel(g.criticite || 1),
        members: members.map(function(a) { return a.nom + " (" + _typeLabel(a.type) + ")"; })
    }).then(function(resp) {
        _aiClosePanel();
        var text = (resp.text || "").trim();
        g.principe = text;
        var el = document.getElementById("groupe-principe") as HTMLTextAreaElement | null;
        if (el) el.value = text;
        _save();
        showStatus(t("ai.done"));
    }).catch(function(e) {
        _aiShowError(t("ai.error"), e.message || String(e));
    });
}
window.aiSuggestPrincipe = aiSuggestPrincipe;

function aiSuggestRaci(): void {
    if (_selectedGroupe === null || !(window._aiIsEnabled != null && _aiIsEnabled())) return;
    var g = D.groupes[_selectedGroupe];
    _ensureRaciArray(g);

    _aiShowLoading(t("ai.loading"));
    _aiPost("suggest-raci", {
        nom: g.nom || "",
        principe: g.principe || "",
        criticite_label: _critLabel(g.criticite || 1),
        existing_activities: (g.raci as AssetRaciRow[]).map(function(r) { return r.activite; })
    }).then(function(resp) {
        _aiClosePanel();
        var raci = resp && resp.raci;
        if (Array.isArray(raci) && raci.length && raci[0].activite) {
            g.raci = raci;
            renderPanel();
            _save();
            showStatus(t("ai.done"));
        } else {
            showStatus(t("ai.error"), true);
        }
    }).catch(function(e) {
        _aiShowError(t("ai.error"), e.message || String(e));
    });
}
window.aiSuggestRaci = aiSuggestRaci;

function aiSuggestPolitiques(): void {
    if (_selectedGroupe === null || !(window._aiIsEnabled != null && _aiIsEnabled())) return;
    var g = D.groupes[_selectedGroupe];
    var members = (g.asset_ids || []).map(function(id) { return D.assets.find(function(x) { return x.id === id; }); }).filter(Boolean) as AssetItem[];

    _aiShowLoading(t("ai.loading"));
    _aiPost("suggest-policies", {
        nom: g.nom || "",
        principe: g.principe || "",
        criticite_label: _critLabel(g.criticite || 1),
        members: members.map(function(a) { return a.nom + " (" + _typeLabel(a.type) + ")"; })
    }).then(function(resp) {
        _aiClosePanel();
        if (resp) {
            if (resp.politique_sauvegarde) g.politique_sauvegarde = Object.assign(g.politique_sauvegarde || {}, resp.politique_sauvegarde);
            if (resp.politique_supervision) g.politique_supervision = Object.assign(g.politique_supervision || {}, resp.politique_supervision);
            if (resp.politique_maj) g.politique_maj = Object.assign(g.politique_maj || {}, resp.politique_maj);
            renderPanel();
            _save();
            showStatus(t("ai.done"));
        } else {
            showStatus(t("ai.error"), true);
        }
    }).catch(function(e) {
        _aiShowError(t("ai.error"), e.message || String(e));
    });
}
window.aiSuggestPolitiques = aiSuggestPolitiques;

// (Init block moved to the very bottom so all plugin helpers below
//  are defined before _initDataAndRender() fires.)


// ═══════════════════════════════════════════════════════════════
// CONNECTORS (plugins) — AD / Intune / EDR / …
// Pulls asset inventories from external sources via the backend
// plugin framework. UI: list + add/edit modal + test + sync + history.
// ═══════════════════════════════════════════════════════════════

var _pluginList: AssetPlugin[] = [];
var _availablePlugins: AssetPluginTypeDef[] = [];
var _pluginsLoaded = false;

function _loadPlugins(cb?: () => void): void {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid || window.AssetAPI == null) { if (cb) cb(); return; }
    Promise.all([
        AssetAPI.listPlugins(pid),
        _availablePlugins.length ? Promise.resolve(_availablePlugins) : AssetAPI.listAvailablePlugins()
    ]).then(function(res) {
        _pluginList = res[0] || [];
        _availablePlugins = res[1] || [];
        _pluginsLoaded = true;
        if (cb) cb();
    }).catch(function(e) {
        console.error("Load plugins:", e);
        if (cb) cb();
    });
}

function renderPluginsPanel(c: HTMLElement): void {
    if (!_pluginsLoaded) {
        c.innerHTML = '<div class="ct-p-5 ct-muted">...</div>';
        _loadPlugins(function() { renderPanel(); });
        return;
    }
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + (t("plg.title") || "Connecteurs") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="showPluginModal">' + (t("plg.add") || "Ajouter un connecteur") + '</button>';
    h += '</div>';

    if (!_pluginList.length) {
        h += '<div class="ct-empty-state">' + (t("plg.empty") || "Aucun connecteur configure. Cliquez sur Ajouter pour synchroniser des actifs depuis AD, Intune, EDR, etc.") + '</div>';
        c.innerHTML = h;
        return;
    }

    _pluginList.forEach(function(p) {
        var statusCls = p.last_sync_status === "success" ? "ok"
                      : (p.last_sync_status === "error" ? "ko" : "");
        h += '<div class="ct-groupe-card ct-clickable ct-userpicker ct-mb-2" data-click="showPluginModal" data-args=\'' + _da(p.id) + '\' title="' + esc(t("plg.edit") || "Modifier") + '">';
        h += '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-1 ct-row-wrap">';
        h += '<strong>' + esc(p.label || p.plugin_type) + '</strong>';
        h += '<span class="ct-badge" data-tone="info">' + esc(p.plugin_type) + '</span>';
        h += '<span class="ct-compliance-tag ' + (p.enabled ? "ok" : "ko") + '">'
           + (p.enabled ? (t("plg.enabled") || "Actif") : (t("plg.disabled") || "Inactif")) + '</span>';
        if (p.last_sync_status) {
            h += '<span class="ct-compliance-tag ' + statusCls + '">' + esc(p.last_sync_status) + '</span>';
        }
        h += '</div>';

        h += '<div class="ct-text-label ct-muted ct-mb-2">';
        h += (t("plg.schedule") || "Planification") + ' : ' + esc(p.schedule || "manual");
        h += ' &middot; ' + (t("plg.priority") || "Priorité") + ' : ' + esc(String(p.priority != null ? p.priority : 100));
        if (p.last_sync_at) {
            h += ' &middot; ' + (t("plg.last_sync") || "Dernière sync") + ' : ' + esc(p.last_sync_at.split("T")[0]);
        }
        h += '</div>';

        h += '<div class="ct-flex ct-gap-1 ct-row-wrap">';
        h += '<button class="ct-btn mt-8" data-write data-size="xs" data-stop data-click="testAssetPlugin" data-args=\'' + _da(p.id) + '\'>' + (t("plg.test") || "Tester") + '</button>';
        h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-size="xs" data-stop data-click="syncAssetPlugin" data-args=\'' + _da(p.id) + '\'>' + (t("plg.sync") || "Synchroniser") + '</button>';
        h += '<button class="ct-btn mt-8" data-write data-size="xs" data-stop data-click="showAssetPluginHistory" data-args=\'' + _da(p.id) + '\'>' + (t("plg.history") || "Historique") + '</button>';
        h += '<button class="ct-btn mt-8" data-write data-variant="danger" data-size="xs" data-stop data-click="deleteAssetPlugin" data-args=\'' + _da(p.id) + '\'>' + (t("btn_delete") || "Supprimer") + '</button>';
        h += '</div>';
        h += '</div>';
    });
    c.innerHTML = h;
}

// ── Add/edit modal — dynamic form built from the plugin config_schema
window.showPluginModal = function(pluginId?: string) {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid) { showStatus("No active project", true); return; }
    if (!window.ct_modal) { showStatus("ct_modal not loaded", true); return; }
    var existing = pluginId ? _pluginList.find(function(p) { return p.id === pluginId; }) : null;

    // Available plugin types (for a new connector) — render as card grid
    var typeOpts = _availablePlugins.map(function(ap) {
        return { value: ap.type, label: ap.label };
    });

    var initialType = existing ? existing.plugin_type : (typeOpts[0] && typeOpts[0].value) || "";
    var typeIndex: Record<string, AssetPluginTypeDef> = {};
    _availablePlugins.forEach(function(ap) { typeIndex[ap.type] = ap; });

    function _buildBody(currentType: string) {
        var tdef = typeIndex[currentType];
        var h = '';
        // Carry the edited plugin id so _collectPluginForm/_testCurrentForm
        // can reopen the modal on the same plugin (empty when creating).
        h += '<input type="hidden" id="aplg-id" value="' + esc(existing ? existing.id : "") + '">';
        // Type selector (only for new plugins)
        if (!existing) {
            h += '<label>' + (t("plg.type") || "Type de connecteur") + '</label>';
            h += '<select id="aplg-type" data-change="_aplgTypeChanged" data-pass-value class="ct-w-full ct-mb-2">';
            typeOpts.forEach(function(o) {
                h += '<option value="' + esc(o.value) + '"' + (o.value === currentType ? " selected" : "") + '>' + esc(o.label) + '</option>';
            });
            h += '</select>';
        } else {
            h += '<input type="hidden" id="aplg-type" value="' + esc(existing.plugin_type) + '">';
        }
        // Label
        h += '<label>' + (t("plg.label") || "Libellé") + '</label>';
        h += '<input type="text" id="aplg-label" value="' + esc(existing ? existing.label : "") + '" placeholder="AD Corp" class="ct-w-full">';

        // Setup guide (collapsible)
        if (tdef && tdef.setup_guide) {
            h += '<details style="margin:var(--ct-s2) 0;border:1px solid var(--ct-line);border-radius:var(--ct-r-sm);padding:var(--ct-s1);background:var(--ct-surface-2)">';
            h += '<summary class="ct-clickable ct-text-label ct-text-info">' + (t("plg.setup_guide") || "Guide de configuration") + '</summary>';
            h += '<div style="margin-top:var(--ct-s1);font-size:var(--ct-text-label);line-height:1.5;white-space:pre-wrap">' + esc(tdef.setup_guide) + '</div>';
            h += '</details>';
        }

        // Config fields
        h += '<div id="aplg-config-fields">';
        h += _renderPluginConfigFields(tdef, existing ? existing.config : {});
        h += '</div>';

        // Schedule + priority + enabled
        h += '<div style="display:flex;gap:var(--ct-s2);align-items:flex-end;margin-top:var(--ct-s2)">';
        h += '<label class="ct-flex-1">' + (t("plg.schedule") || "Planification") + '<select id="aplg-schedule" class="ct-w-full">';
        ["manual", "daily", "weekly"].forEach(function(s) {
            h += '<option value="' + s + '"' + (existing && existing.schedule === s ? " selected" : "") + '>' + esc(s) + '</option>';
        });
        h += '</select></label>';
        h += '<label style="flex:0 0 120px" title="' + esc(t("plg.priority_help") || "Plus la valeur est haute, plus ce connecteur gagne en cas de conflit sur un champ.") + '">'
           + (t("plg.priority") || "Priorité")
           + '<input type="number" id="aplg-priority" min="0" max="1000" value="'
           + esc(String(existing && existing.priority != null ? existing.priority : 100))
           + '" class="ct-w-full"></label>';
        h += '<label class="ct-flex ct-items-center ct-gap-1 ct-text-meta">'
           + '<input type="checkbox" id="aplg-enabled"' + (existing && existing.enabled ? " checked" : "") + '> '
           + (t("plg.enabled") || "Actif") + '</label>';
        h += '</div>';
        h += '<div class="ct-text-label ct-muted ct-mt-1">'
           + esc(t("plg.priority_help") || "Priorité (0-1000) : plus la valeur est haute, plus ce connecteur gagne en cas de conflit sur un champ commun avec un autre connecteur pour le même host.")
           + '</div>';

        return h;
    }

    ct_modal.open({
        title: existing ? (t("plg.edit") || "Modifier le connecteur") : (t("plg.add") || "Ajouter un connecteur"),
        body: _buildBody(initialType),
        size: "md",
        buttons: [
            { id: "test", label: t("plg.test") || "Tester",
              result: function() {
                  setTimeout(_testCurrentForm, 0);
                  return { __test: true };
              } },
            { id: "cancel", label: t("btn_cancel") || "Annuler" },
            { id: "save", primary: true, label: t("btn_save") || "Enregistrer",
              result: function() {
                  var data = _collectPluginForm();
                  if (!data) return false;
                  return data;
              } }
        ]
    }).then(function(result: any) {
        if (!result || result.__test) return;
        var promise = existing
            ? AssetAPI.patchPlugin(pid!, existing.id, result)
            : AssetAPI.createPlugin(pid!, result);
        promise.then(function() {
            _pluginsLoaded = false;
            _loadPlugins(function() {
                if (typeof _panel !== "undefined" && _panel !== "plugins") {
                    selectPanel("plugins");
                } else {
                    renderPanel();
                }
            });
            showStatus(existing ? "Connecteur mis à jour" : "Connecteur créé");
        }).catch(function(e) {
            showStatus((existing ? "Modif échouée : " : "Création échouée : ") + (e.message || String(e)), true);
        });
    });
};

window._aplgTypeChanged = function(val: string) {
    // Re-render only the config fields section so the user keeps
    // any label/schedule input they already filled.
    var tdef = _availablePlugins.find(function(ap) { return ap.type === val; });
    var container = document.getElementById("aplg-config-fields");
    if (container) container.innerHTML = _renderPluginConfigFields(tdef, {});
};

function _renderPluginConfigFields(tdef: AssetPluginTypeDef | undefined, values?: Record<string, any> | null): string {
    if (!tdef || !Array.isArray(tdef.config_schema)) return "";
    values = values || {};
    var h = '<div class="ct-mt-2 ct-mb-1 ct-text-label ct-strong ct-muted">'
          + (t("plg.config") || "Configuration") + '</div>';
    tdef.config_schema.forEach(function(f) {
        var id = "aplg-cfg-" + f.key;
        var val = values[f.key];
        var label = esc(f.label || f.key) + (f.required ? ' <span class="ct-text-critical">*</span>' : '');
        if (f.type === "checkbox") {
            var checked = (val == null)
                ? (f.default === true)
                : (val === true || val === "true" || val === "on" || val === 1);
            h += '<div class="ct-mb-1"><label class="ct-inline-flex ct-items-center ct-gap-1 ct-text-label ct-clickable">'
              + '<input type="checkbox" id="' + id + '" data-aplg-key="' + esc(f.key) + '"' + (checked ? " checked" : "") + '> '
              + label + '</label></div>';
        } else if (f.type === "textarea") {
            h += '<label class="ct-block ct-text-label ct-mt-1">' + label + '</label>';
            h += '<textarea id="' + id + '" data-aplg-key="' + esc(f.key) + '" rows="3" class="ct-w-full">' + esc(String(val == null ? "" : val)) + '</textarea>';
        } else {
            var inputType = f.type === "password" ? "password" : (f.type === "number" ? "number" : "text");
            h += '<label class="ct-block ct-text-label ct-mt-1">' + label + '</label>';
            h += '<input type="' + inputType + '" id="' + id + '" data-aplg-key="' + esc(f.key) + '" value="' + esc(String(val == null ? "" : val)) + '" placeholder="' + esc(f.placeholder || "") + '" class="ct-w-full">';
        }
    });
    return h;
}

function _collectPluginForm(): AssetPluginForm | null {
    var typeEl = document.getElementById("aplg-type") as HTMLInputElement | HTMLSelectElement | null;
    var labelEl = document.getElementById("aplg-label") as HTMLInputElement | null;
    var scheduleEl = document.getElementById("aplg-schedule") as HTMLSelectElement | null;
    var enabledEl = document.getElementById("aplg-enabled") as HTMLInputElement | null;
    var priorityEl = document.getElementById("aplg-priority") as HTMLInputElement | null;
    if (!typeEl) { showStatus("Form missing", true); return null; }
    var pluginType = (typeEl.value || "").trim();
    if (!pluginType) { showStatus("Type de connecteur manquant", true); return null; }

    var config: Record<string, any> = {};
    document.querySelectorAll<HTMLInputElement>("[data-aplg-key]").forEach(function(el) {
        var key = el.getAttribute("data-aplg-key")!;
        if (el.type === "checkbox") config[key] = !!el.checked;
        else config[key] = el.value;
    });

    var prio = 100;
    if (priorityEl) {
        var n = parseInt(priorityEl.value, 10);
        if (!isNaN(n)) prio = Math.max(0, Math.min(1000, n));
    }

    var idEl = document.getElementById("aplg-id") as HTMLInputElement | null;
    return {
        plugin_type: pluginType,
        label: (labelEl && labelEl.value) || "",
        enabled: !!(enabledEl && enabledEl.checked),
        priority: prio,
        schedule: (scheduleEl && scheduleEl.value) || "manual",
        config: config,
        filters: {},
        plugin_id: (idEl && idEl.value) || undefined,
    };
}

function _testCurrentForm(): void {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid) return;
    var data = _collectPluginForm();
    if (!data) return;
    showStatus(t("plg.testing") || "Test de connexion en cours...");
    AssetAPI.testPluginConfig(pid, data).then(function(r: any) {
        if (r.ok) {
            showStatus((t("plg.test_ok") || "Connexion OK") + (r.details ? " — " + r.details : ""));
        } else {
            showStatus((t("plg.test_fail") || "Échec : ") + (r.error || ""), true);
        }
        // Reopen the modal with same data (ct_modal closed on button click)
        setTimeout(function() { window.showPluginModal!(data!.plugin_id); }, 100);
    }).catch(function(e) {
        showStatus(e.message || String(e), true);
    });
}

window.testAssetPlugin = function(pluginId: string) {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid) return;
    showStatus(t("plg.testing") || "Test en cours...");
    AssetAPI.testPlugin(pid, pluginId).then(function(r: any) {
        if (r.ok) showStatus((t("plg.test_ok") || "Connexion OK") + (r.details ? " — " + r.details : ""));
        else showStatus((t("plg.test_fail") || "Échec : ") + (r.error || ""), true);
    }).catch(function(e) { showStatus(e.message || String(e), true); });
};

window.syncAssetPlugin = function(pluginId: string) {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid) return;
    var p = _pluginList.find(function(x) { return x.id === pluginId; });
    var msg = (t("plg.confirm_sync") || "Lancer la synchronisation ? Elle peut prendre plusieurs secondes.");
    if (!confirm(msg)) return;
    if (window._cancelAutosave) window._cancelAutosave();
    showStatus(t("plg.syncing") || "Synchronisation en cours...");
    AssetAPI.syncPlugin(pid, pluginId).then(function(r: any) {
        var tpl = t("plg.sync_done") ||
            "Sync terminée : {found} trouvés, {created} créés, {updated} mis à jour, {unchanged} inchangés";
        var extra = "";
        if (r.assets_retired) {
            extra += " (" + r.assets_retired + " retiré(s) — absent(s) du connecteur)";
        }
        if (r.assets_reactivated) {
            extra += " (" + r.assets_reactivated + " réactivé(s))";
        }
        if (r.assets_merged_hosts) {
            extra += " (" + r.assets_merged_hosts + " fusion(s) cross-connecteur)";
        }
        showStatus(tpl
            .replace("{found}", r.assets_found || 0)
            .replace("{created}", r.assets_created || 0)
            .replace("{updated}", r.assets_updated || 0)
            .replace("{unchanged}", r.assets_unchanged || 0)
            + extra);
        if (r.connector_errors_count && r.connector_errors_count > 0) {
            showStatus(r.connector_errors_count + " erreur(s) connecteur — voir logs serveur", true);
        }
        // Reload D so new assets appear in the list
        AssetAPI.get(pid!).then(function(prj: any) {
            var d = typeof prj.data === "string" ? JSON.parse(prj.data) : (prj.data || {});
            Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
            Object.assign(D, d);
            _pluginsLoaded = false;
            _loadPlugins(function() { renderPanel(); });
        });
    }).catch(function(e) { showStatus(e.message || String(e), true); });
};

// Refresh = sync every ENABLED connector in sequence (avoids the per-user
// rate limiter and DB contention), then reload D once. Counters are
// aggregated across connectors, including retired/reactivated from the
// reconciliation pass.
window.refreshConnectors = function() {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid || window.AssetAPI == null) return;
    function run() {
        var enabled = _pluginList.filter(function(p) { return p.enabled; });
        if (!enabled.length) {
            showStatus(t("plg.refresh_none") || "Aucun connecteur activé à synchroniser.", true);
            return;
        }
        var msg = (t("plg.confirm_refresh") || "Rafraîchir les {n} connecteur(s) activé(s) ?")
            .replace("{n}", String(enabled.length));
        if (!confirm(msg)) return;
        if (window._cancelAutosave) window._cancelAutosave();
        showStatus(t("plg.syncing") || "Synchronisation en cours...");
        var agg: any = { found: 0, created: 0, updated: 0, unchanged: 0, retired: 0, reactivated: 0, errors: 0 };
        var i = 0;
        function next() {
            if (i >= enabled.length) { finish(); return; }
            var p = enabled[i++];
            AssetAPI.syncPlugin(pid!, p.id).then(function(r: any) {
                agg.found += r.assets_found || 0;
                agg.created += r.assets_created || 0;
                agg.updated += r.assets_updated || 0;
                agg.unchanged += r.assets_unchanged || 0;
                agg.retired += r.assets_retired || 0;
                agg.reactivated += r.assets_reactivated || 0;
                agg.errors += r.connector_errors_count || 0;
                next();
            }).catch(function() { agg.errors++; next(); });
        }
        function finish() {
            var tpl = t("plg.sync_done") ||
                "Sync terminée : {found} trouvés, {created} créés, {updated} mis à jour, {unchanged} inchangés";
            var extra = "";
            if (agg.retired) extra += " (" + agg.retired + " retiré(s) — absent(s) des connecteurs)";
            if (agg.reactivated) extra += " (" + agg.reactivated + " réactivé(s))";
            showStatus(tpl
                .replace("{found}", agg.found)
                .replace("{created}", agg.created)
                .replace("{updated}", agg.updated)
                .replace("{unchanged}", agg.unchanged)
                + extra);
            if (agg.errors > 0) {
                showStatus(agg.errors + " erreur(s) connecteur — voir logs serveur", true);
            }
            AssetAPI.get(pid!).then(function(prj: any) {
                var d = typeof prj.data === "string" ? JSON.parse(prj.data) : (prj.data || {});
                Object.keys(D).forEach(function(k) { delete (D as unknown as Record<string, unknown>)[k]; });
                Object.assign(D, d);
                _pluginsLoaded = false;
                _loadPlugins(function() { renderPanel(); });
            });
        }
        next();
    }
    if (_pluginsLoaded) run(); else _loadPlugins(run);
};

window.deleteAssetPlugin = function(pluginId: string) {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid) return;
    var p = _pluginList.find(function(x) { return x.id === pluginId; });
    var name = (p && p.label) || pluginId;
    if (!confirm((t("plg.confirm_delete") || "Supprimer le connecteur") + " \"" + name + "\" ?")) return;
    AssetAPI.deletePlugin(pid, pluginId).then(function() {
        _pluginsLoaded = false;
        _loadPlugins(function() { renderPanel(); });
        showStatus("Connecteur supprimé");
    }).catch(function(e) { showStatus(e.message || String(e), true); });
};

window.showAssetPluginHistory = function(pluginId: string) {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid || !window.ct_modal) return;
    AssetAPI.pluginHistory(pid, pluginId).then(function(jobs) {
        var h = '';
        if (!jobs.length) {
            h = '<div class="ct-empty-state">' + (t("plg.history_empty") || "Aucun historique.") + '</div>';
        } else {
            h = '<table class="ct-w-full ct-text-meta">';
            h += '<thead><tr>'
              + '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom">Date</th>'
              + '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom ct-w-110">Statut</th>'
              + '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom">Trouvés</th>'
              + '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom">Créés</th>'
              + '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom">MAJ</th>'
              + '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom">=</th>'
              + '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom">Erreur</th>'
              + '</tr></thead><tbody>';
            jobs.forEach(function(j) {
                var cls = j.status === "success" ? "ok" : (j.status === "error" ? "ko" : "");
                var ts = j.started_at ? j.started_at.replace("T", " ").split(".")[0].slice(0, 16) : "-";
                h += '<tr>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-nowrap">' + esc(ts) + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt"><span class="ct-compliance-tag ' + cls + '">' + esc(j.status) + '</span></td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.assets_found != null ? j.assets_found : "-") + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.assets_created != null ? j.assets_created : "-") + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.assets_updated != null ? j.assets_updated : "-") + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.assets_unchanged != null ? j.assets_unchanged : "-") + '</td>';
                var err = j.error_message || "";
                h += '<td style="padding:var(--ct-s1) var(--ct-s2);border-bottom:1px solid var(--ct-surface-2);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--ct-text-label);color:var(--ct-critical)" title="' + esc(err) + '">' + esc(err || "-") + '</td>';
                h += '</tr>';
            });
            h += '</tbody></table>';
        }
        ct_modal.open({
            title: (t("plg.history") || "Historique") + " — " + pluginId,
            body: '<div style="max-height:60vh;overflow-y:auto">' + h + '</div>',
            size: "lg",
            buttons: [{ id: "close", primary: true, label: (t("btn_close") || "Fermer") }],
        });
    }).catch(function(e) { showStatus(e.message || String(e), true); });
};


// ═══════════════════════════════════════════════════════════════
// MEASURES (FEAT-22) — action plan, per-entity REST (outside the blob)
// ═══════════════════════════════════════════════════════════════

var _measureList: AssetMeasure[] = [];
var _measuresLoaded = false;

var _MES_STATUS = [
    { value: "a_faire",  key: "measure.status.a_faire",  fallback: "À faire" },
    { value: "en_cours", key: "measure.status.en_cours", fallback: "En cours" },
    { value: "termine",  key: "measure.status.termine",  fallback: "Terminé" },
];

function _mesStatutLabel(s: string): string {
    var o = _MES_STATUS.find(function(x) { return x.value === s; });
    return o ? (t(o.key) || o.fallback) : s;
}

function _loadMeasures(cb?: () => void): void {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid || window.AssetAPI == null) { _measureList = []; _measuresLoaded = true; if (cb) cb(); return; }
    AssetAPI.listMeasures(pid).then(function(list) {
        _measureList = list || [];
        _measuresLoaded = true;
        if (cb) cb();
    }).catch(function(e) {
        console.error("Load measures:", e);
        _measureList = []; _measuresLoaded = true; if (cb) cb();
    });
}

function renderMeasuresPanel(c: HTMLElement): void {
    if (!_measuresLoaded) {
        c.innerHTML = '<div class="ct-p-5 ct-muted">' + (t("common.loading") || "Chargement…") + '</div>';
        _loadMeasures(function() { renderPanel(); });
        return;
    }
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2 class="ct-m-0">' + (t("nav.mesures") || "Actions") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="_newAssetMeasure">' + (t("measure.new") || "Nouvelle action") + '</button>';
    h += '</div>';
    if (!_measureList.length) {
        h += '<div class="ct-empty-state">' + (t("mes.empty") || "Aucune action. Les échéances d'actifs en génèrent automatiquement, ou créez-en une.") + '</div>';
        c.innerHTML = h;
        return;
    }
    var today = new Date().toISOString().slice(0, 10);
    h += '<table class="ct-table"><thead><tr>';
    h += '<th>' + (t("mes.col.id") || "ID") + '</th>';
    h += '<th>' + (t("measure.field.title") || "Intitulé") + '</th>';
    h += '<th>' + (t("measure.field.statut") || "Statut") + '</th>';
    h += '<th>' + (t("measure.field.responsable") || "Responsable") + '</th>';
    h += '<th>' + (t("measure.field.echeance") || "Échéance") + '</th>';
    h += '<th>' + (t("mes.col.origine") || "Origine") + '</th></tr></thead><tbody>';
    _measureList.forEach(function(m) {
        var overdue = !!(m.echeance && m.echeance < today && m.statut !== "termine");
        h += '<tr class="ct-clickable" data-click="_editAssetMeasureRow" data-args=\'' + _da(m.id) + '\'>';
        h += '<td>' + esc(m.id) + '</td>';
        h += '<td>' + esc(m.title || "") + '</td>';
        h += '<td>' + esc(_mesStatutLabel(m.statut)) + '</td>';
        h += '<td>' + esc(m.responsable || "") + '</td>';
        h += '<td' + (overdue ? ' class="ct-measure-overdue"' : '') + '>' + esc(m.echeance || "") + '</td>';
        h += '<td>' + (m.origine === "echeance"
            ? '<span class="ct-badge" data-tone="info" data-size="sm">' + (t("mes.auto") || "auto") + '</span>'
            : esc(t("mes.manual") || "manuelle")) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    c.innerHTML = h;
}

function _measureModalBaseOpts(): any {
    return {
        hideFields: ["type"],
        statusOptions: _MES_STATUS.map(function(s) { return { value: s.value, label: t(s.key) || s.fallback }; }),
        defaultStatus: "a_faire",
        ownerPicker: { pickerId: "asset-measure-owner", directoryUrl: "api/directory" },
    };
}

function _reloadMeasures(): void { _measuresLoaded = false; selectPanel("measures"); }

function _newAssetMeasure(): void {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    if (!pid || !window.ct_measure_modal) return;
    var opts = _measureModalBaseOpts();
    opts.title = t("measure.new") || "Nouvelle action";
    window.ct_measure_modal!.open(null, opts).then(function(result: any) {
        if (!result) return;
        AssetAPI.createMeasure(pid!, result).then(function() {
            _reloadMeasures();
            if (typeof showStatus === "function") showStatus(t("measure.created") || "Mesure créée");
        }).catch(function(e: any) {
            if (typeof showStatus === "function") showStatus(e.message || String(e), true);
        });
    });
}

function _editAssetMeasureRow(id: string): void {
    var pid = window.getActiveProjectId != null ? getActiveProjectId() : null;
    var m = _measureList.find(function(x) { return x.id === id; });
    if (!pid || !m || !window.ct_measure_modal) return;
    var opts = _measureModalBaseOpts();
    opts.title = m.id;
    opts.onAddNote = function(_entry: any, fullLog: any) {
        (m as any).progress_log = fullLog;
        return AssetAPI.patchMeasure(pid!, m!.id, { progress_log: fullLog });
    };
    opts.onDelete = function() {
        if (!confirm(t("measure.confirm_delete") || "Supprimer cette action ?")) return;
        AssetAPI.deleteMeasure(pid!, m!.id).then(function() {
            _reloadMeasures();
        }).catch(function(e: any) {
            if (typeof showStatus === "function") showStatus(e.message || String(e), true);
        });
    };
    window.ct_measure_modal!.open(m, opts).then(function(result: any) {
        if (!result || result.__deleted) return;
        var patch: any = {};
        ["title", "description", "statut", "responsable", "echeance"].forEach(function(k) {
            if (result[k] !== undefined) patch[k] = result[k];
        });
        AssetAPI.patchMeasure(pid!, m!.id, patch).then(function() {
            _reloadMeasures();
        }).catch(function(e: any) {
            if (typeof showStatus === "function") showStatus(e.message || String(e), true);
        });
    });
}

// ═══════════════════════════════════════════════════════════════
// INIT — defer to _appInitCallback if set (backend mode)
// ═══════════════════════════════════════════════════════════════

if (typeof window._appInitCallback === "function") {
    window._appInitCallback();
} else {
    _initDataAndRender();
}

// FEAT-13 — deep-linked measure from Pilot (?measure=MES-xxx): open the
// native edit modal once the measures list is loaded (shared retry loop).
// Asset has a single shared inventory — no entity targeting needed.
if (typeof window.ct_handleMeasureDeepLink === "function") {
    window.ct_handleMeasureDeepLink({ open: function(mid: string) {
        // The measures list loads lazily when the panel renders — select the
        // panel on the FIRST attempt so the retry loop finds the list
        // populated on a later tick.
        if (_panel !== "measures" && typeof selectPanel === "function") selectPanel("measures");
        if (!_measureList.some(function(m: any) { return m.id === mid; })) return false;
        _editAssetMeasureRow(mid);
        return true;
    } });
}
