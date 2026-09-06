/**
 * CISO Toolbox — Access Rights Review
 */
var ACCESS_INIT_DATA: AccessData = { si_users: [], applications: [], reviews: [], measures: [], service_accounts: [], metadata: { organization: "", created: "" } };
window.CT_CONFIG = {
    edition: "suite", module: "access",
    deployed: ["risk", "compliance", "audit", "vendor", "asset", "pilot", "appsec", "surface", "access", "watch"],
    autosaveKey: "access_autosave", initDataVar: "ACCESS_INIT_DATA", filePrefix: "AccessReview",
    labelKey: "toolbar.subtitle",
    getSociete: function(d) { return (d.metadata && d.metadata.organization) || ""; },
    getDate: function(d) { return (d.metadata && d.metadata.created) || ""; }
};

// FEAT-36 — schema versioning (rev 1 = normalized baseline; bump + add a
// migration + archive a fixture whenever the exported data model changes).
window.SCHEMA_REV = 1;

var D: AccessData = JSON.parse(JSON.stringify(ACCESS_INIT_DATA));
var _panel = "dashboard";
var _selectedUser: number | null = null, _selectedApp: number | null = null, _selectedReview: number | null = null, _selectedSA: number | null = null;
// When a review is opened from a perimeter/application page, remember it so
// exiting the review returns there instead of the reviews list.
var _reviewReturn: { app: number } | null = null;
// Reviews-list section toggles (default: in-progress + overdue-to-start).
var _reviewListFilter: Record<string, boolean> | null = null;

window.AI_APP_CONFIG = { storagePrefix: "access" };

/** Alert computed on a review entry (admin / former staff / orphan…). */
type AccessEntryWarning = { code: string; label: string; title: string };

/** Enriched Applications table row (reviewer names + last review). */
type AccessAppRow = AccessApplication & { __reviewer_names: string; __last_review: string };

function renderAll(): void {
    var tr = document.getElementById("toolbar-right");
    if (tr) {
        // Preserve auth buttons (injected by _initAuth), only update settings button
        var existing = tr.querySelector(".toolbar-settings");
        if (!existing) {
            var settingsHtml = _getSettingsButtonHTML();
            if (settingsHtml) tr.insertAdjacentHTML("afterbegin", '<span class="toolbar-settings">' + settingsHtml + '</span>');
        }
    }
    _applyStaticTranslations();
    renderPanel();
}
function _initDataAndRender(cb?: () => void): void {
    // FEAT-36 — normalize + replay schema migrations on EVERY load path
    // (file, snapshot, session, API): idempotent, refuses future revs.
    if (typeof ctSchemaMigrate === "function") {
        try { ctSchemaMigrate(D); } catch (e: any) { alert(e && e.message ? e.message : String(e)); }
    }
 _panel = "dashboard"; _selectedUser = _selectedApp = _selectedReview = _selectedSA = null; renderAll(); _loadPlugins(function() { renderPanel(); }); _installLiveReload(); if (cb) cb(); }

// ─── Live refresh: catch Pilot → Access personnel-sync pushes ────
// Pilot pushes personnel changes asynchronously; the Access backend
// updates DB rows immediately but the browser has no SSE channel.
// We reload the project payload when:
//   - the tab regains focus after being hidden (user switches from
//     Pilot to Access) — covers the most common workflow
//   - while the Users or Reviews panel is displayed, poll every 30 s
var _liveReloadInstalled = false;
var _liveReloadTimer: ReturnType<typeof setTimeout> | null = null;
var _liveReloadInFlight = false;

function _reloadProjectData(onAfter?: (() => void) | Event): void {
    // Caller may pass an `onAfter` continuation that runs after D is
    // refreshed (typical use: set _panel / _selectedReview, then render).
    // If a reload is already in flight, subsequent callers are ignored
    // — the first one will render for everyone.
    if (_liveReloadInFlight) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) return;
    _liveReloadInFlight = true;
    AccessAPI.get(pid).then(function(p) {
        var d = typeof p.data === "string" ? JSON.parse(p.data) : (p.data || {});
        Object.keys(D).forEach(function(k) { delete (D as Record<string, unknown>)[k]; });
        Object.assign(D, d);
        if (typeof onAfter === "function") {
            try { onAfter(); } catch (e) { console.error(e); }
        }
        // Avoid clobbering in-flight UI edits (detail view mid-typing):
        // we re-render only list panels that display Pilot-sourced data.
        if (_panel === "users" || _panel === "reviews" || _panel === "dashboard") {
            renderPanel();
        }
    }).catch(function() {})
      .finally(function() { _liveReloadInFlight = false; });
}

function _installLiveReload(): void {
    if (_liveReloadInstalled) return;
    _liveReloadInstalled = true;

    // 1) Tab-focus: user comes back from Pilot, reload.
    window.addEventListener("focus", _reloadProjectData);
    document.addEventListener("visibilitychange", function() {
        if (!document.hidden) _reloadProjectData();
    });

    // 2) Polling while on panels that show Pilot-sourced data.
    //    30 s is a good balance between freshness and API load.
    function _scheduleTick(): void {
        if (_liveReloadTimer) clearTimeout(_liveReloadTimer);
        _liveReloadTimer = setTimeout(function() {
            if (!document.hidden && (_panel === "users" || _panel === "reviews")) {
                _reloadProjectData();
            }
            _scheduleTick();
        }, 30000);
    }
    _scheduleTick();
}

// ═══════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════
function selectPanel(id: string): void { _panel = id; _selectedUser = _selectedApp = _selectedReview = _selectedSA = null; document.querySelector(".ct-rail, .sidebar")?.classList.remove("open"); _updateSidebarAccordion(id); renderPanel(); }
function renderPanel(): void {
    var c = document.getElementById("content")!;
    switch (_panel) {
        case "dashboard": c.innerHTML = renderDashboard(); break;
        case "users": c.innerHTML = _selectedUser !== null ? renderUserDetail() : renderUserList(); break;
        case "apps": c.innerHTML = _selectedApp !== null ? renderAppDetail() : renderAppList(); break;
        case "reviews": c.innerHTML = _selectedReview !== null ? renderReviewDetail() : renderReviewList(); break;
        case "service_accounts": c.innerHTML = _selectedSA !== null ? renderSADetail() : renderSAList(); break;
        case "measures": c.innerHTML = renderMeasureList(); break;
        case "plugins": c.innerHTML = renderPlugins(); break;
        default: c.innerHTML = renderDashboard();
    }
}
function _updateSidebarAccordion(id: string): void { document.querySelectorAll(".ct-rail-item").forEach(function(el) { var a = el.getAttribute("data-args"); if (a && a.indexOf('"' + id + '"') >= 0) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current"); }); }

// BUG-25: renderPanel() replaces the whole #content subtree, search input
// included, so typing lost focus and caret on every keystroke. Re-render,
// then re-focus the same input (found by id) and restore the caret.
function _renderKeepingFocus(inputId: string): void {
    var prev = document.getElementById(inputId) as HTMLInputElement | null;
    var caret = prev && prev === document.activeElement ? prev.selectionStart : null;
    renderPanel();
    var next = document.getElementById(inputId) as HTMLInputElement | null;
    if (next && caret !== null) {
        next.focus();
        try { next.setSelectionRange(caret, caret); } catch (e) { /* type=email etc. */ }
    }
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════
function _genId(prefix: string, arr: { id?: string }[]): string { var max = 0; arr.forEach(function(x) { var n = parseInt((x.id || "").replace(/\D/g, "")) || 0; if (n > max) max = n; }); return prefix + String(max + 1).padStart(3, "0"); }
function _today(): string { return new Date().toISOString().split("T")[0]; }
function _compTag(ok?: boolean): string { return '<span class="ct-compliance-tag ' + (ok ? "ok" : "ko") + '">' + (ok ? "✓" : "✗") + '</span>'; }

// Sensibilisation card: connector-driven cumulative training history + computed
// compliance (read-only). Falls back to the manual proof card when there is no
// PSAT history yet (users not covered by the awareness connector).
function _sensibilisationCard(u: any): string {
    var hist = (u && u.sensibilisation_history) || {};
    var camps = Object.keys(hist);
    if (camps.length === 0) {
        return _proofCard("sensibilisation", t("user.sensibilisation"),
            u.sensibilisation, u.sensibilisation_date, u.sensibilisation_justification,
            "sensibilisation", "sensibilisation_date", "sensibilisation_justification");
    }
    var today = new Date().toISOString().slice(0, 10);
    var ok = !!u.sensibilisation;
    var h = '<div class="proof-card' + (ok ? ' proof-card--ok' : '') + '">';
    h += '<div class="proof-card__head">';
    h += '<span class="proof-card__title ct-inline-flex ct-items-center ct-gap-1">';
    h += '<span aria-hidden="true" style="display:inline-block;width:1.1em;text-align:center;font-weight:700;color:' + (ok ? 'var(--ct-low)' : 'var(--ct-critical)') + '">' + (ok ? '✓' : '✗') + '</span>';
    h += esc(t("user.sensibilisation")) + '</span>';
    h += '<span class="ct-compliance-tag ct-ml-auto ' + (ok ? 'ok' : 'ko') + '">' + esc(ok ? t("sensi.compliant") : t("sensi.noncompliant")) + '</span>';
    h += '</div>';
    // Timeline: overdue first, then in-progress, then completed (by due/date).
    var rows = camps.map(function(name) {
        var e = hist[name] || {};
        var completed = !!e.completed;
        var overdue = !completed && !!e.due_date && String(e.due_date) < today;
        return { name: name, e: e, completed: completed, overdue: overdue,
                 rank: overdue ? 0 : (completed ? 2 : 1) };
    });
    rows.sort(function(a, b) { return a.rank - b.rank || (a.name < b.name ? -1 : 1); });
    h += '<div class="ct-mt-1 ct-text-meta ct-flex ct-body ct-gap-1">';
    rows.forEach(function(r) {
        var icon, color, detail;
        if (r.completed) {
            icon = '✓'; color = 'var(--ct-low)';
            detail = t("sensi.completed_on") + ' ' + esc(String(r.e.completion_date || '?'));
        } else if (r.overdue) {
            icon = '⚠'; color = 'var(--ct-critical)';
            detail = t("sensi.overdue_since") + ' ' + esc(String(r.e.due_date || '?'));
        } else {
            icon = '⧗'; color = 'var(--ct-ink-2)';
            detail = t("sensi.due") + ' ' + esc(String(r.e.due_date || '?'));
        }
        h += '<div style="display:flex;gap:var(--ct-s1);align-items:baseline">';
        h += '<span style="color:' + color + ';font-weight:700;width:1.1em;text-align:center">' + icon + '</span>';
        h += '<span class="ct-flex-1"><b>' + esc(r.name) + '</b> — <span class="ct-muted">' + detail + '</span></span>';
        h += '</div>';
    });
    h += '</div>';
    h += '<div class="ct-text-label ct-muted ct-mt-1">' + esc(t("sensi.connector_note")) + '</div>';
    h += '</div>';
    return h;
}
// Module tones: a single table, so that review, warning, criticality and
// measure status all speak the same language as the rest of the suite.
var _ACCESS_TONES: Record<string, string> = {
    // risk levels
    critical: "critical", high: "high", medium: "medium", low: "low",
    // review statuses
    en_cours: "info", cloturee: "low", planifiee: "neutral",
    // measure statuses
    a_faire: "neutral", termine: "low", annule: "critical",
    // warning codes
    admin: "medium", ancien: "critical", orphan: "critical", externe: "accent",
    nomfa: "high", nosensi: "high", nopol: "high", service: "info",
};
function _accessTone(v?: string | null): string {
    return _ACCESS_TONES[(v || "").toString()] || "neutral";
}

// IdP account active/disabled badge. undefined/null = unknown (connector didn't report).
function _accountTag(enabled?: boolean | null): string {
    if (enabled === true) return '<span class="ct-badge" data-tone="low">' + (t("user.account_active") || "Actif") + '</span>';
    if (enabled === false) return '<span class="ct-badge" data-tone="critical">' + (t("user.account_disabled") || "Désactivé") + '</span>';
    return '<span class="text-muted">—</span>';
}
function _statusLabel(s: string): string { return t("user.statut." + s) || s; }
function _freqLabel(f: string): string { return t("app.freq." + f) || f; }
// BUG-27: aligned on the backend table (routes/internal.py _freq_days) so the
// dashboard and the Pilot alert agree on what "overdue" means.
function _freqDays(f: string): number { return ({ mensuelle: 31, trimestrielle: 92, semestrielle: 183, annuelle: 365 } as Record<string, number>)[f] || 183; }
// BUG-27: a perimeter with no closed review is due at created_at + frequency —
// not instantly overdue the moment it is created. Unknown creation date (legacy
// blob rows) = treat as fresh, never as overdue. A MALFORMED closed_at counts
// as overdue (the data claims a review happened but its date is unusable) —
// same contract as the backend review_overdue().
function _isReviewOverdue(app: AccessApplication, lastClosedAt: string | null): boolean {
    var freq = _freqDays(app.frequence_revue);
    if (lastClosedAt) {
        var ms = new Date(lastClosedAt).getTime();
        if (isNaN(ms)) return true;
        return (Date.now() - ms) / 86400000 > freq;
    }
    var anchor = app.created_at || "";
    if (!anchor) return false;
    var ms2 = new Date(anchor).getTime();
    if (isNaN(ms2)) return false;
    return (Date.now() - ms2) / 86400000 > freq;
}
function _decisionLabel(d: string): string { return t("review.decision." + d) || d; }
function _card(val: string | number, label: string, cls?: string): string {
    var tone = cls === "warning" ? "high" : (cls === "critical" || cls === "high" || cls === "medium" || cls === "low" ? cls : "");
    var a = tone ? ' data-emphasis="value" data-tone="' + tone + '"' : '';
    return '<div class="ct-kpi"' + a + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + esc(label) + '</div><div class="ct-kpi-value">' + val + '</div></div></div>';
}

function _findApp(id: string): AccessApplication | undefined { return D.applications.find(function(a) { return a.id === id; }); }
function _findUser(email: string | null | undefined): AccessSiUser | undefined {
    var key = (email || "").trim().toLowerCase();
    if (!key) return undefined;
    return D.si_users.find(function(u) {
        return u.email && u.email.trim().toLowerCase() === key;
    });
}

// Resolve the SiUser matching a review entry. Tries si_user_id first,
// then falls back to email/login match — the si_user_id may point to a
// SiUser that was deleted, renamed, or never existed (old imports).
function _resolveEntryUser(e: AccessReviewEntry | null | undefined): AccessSiUser | undefined {
    if (!e) return undefined;
    if (e.si_user_id) {
        var byId = D.si_users.find(function(u) { return u.id === e.si_user_id; });
        if (byId) return byId;
    }
    return _findUser(e.email_or_login);
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════
function renderDashboard(): string {
    var active = D.reviews.filter(function(r) { return r.status === "en_cours"; }).length;
    var closed = D.reviews.filter(function(r) { return r.status === "cloturee"; }).length;
    var mDone = D.measures.filter(function(m) { return m.statut === "termine"; }).length;
    var nc = D.measures.length;
    var compPol = D.si_users.length ? Math.round(D.si_users.filter(function(u) { return u.politique_validee; }).length / D.si_users.length * 100) : 0;
    var compMfa = D.si_users.length ? Math.round(D.si_users.filter(function(u) { return u.mfa_active; }).length / D.si_users.length * 100) : 0;

    var h = '<h2>' + t("dashboard.title") + '</h2>';
    h += '<div class="ct-kpigrid ct-mb-6">';
    h += _card(D.si_users.length, t("dashboard.users"));
    h += _card(D.applications.length, t("dashboard.apps"));
    h += _card(active, t("dashboard.active_reviews"), _kpiTone(active, { warn: 1 }));
    h += _card(closed, t("dashboard.closed_reviews"));
    h += _card(nc, t("dashboard.measures"));
    var mProgress = nc ? Math.round(mDone / nc * 100) : null;
    h += _card(nc ? mProgress + "%" : "-", t("dashboard.measures_progress"), _kpiTone(mProgress, { dir: "up", amber: 90, red: 70 }));
    var saTotal = (D.service_accounts || []).length;
    var saOverdue = _countRotationOverdue();
    h += _card(saTotal, t("dashboard.service_accounts"));
    h += _card(saOverdue, t("dashboard.rotation_overdue"), _kpiTone(saOverdue, { bad: 1 }));
    var saExpiring = _countExpiringSoon();
    h += _card(saExpiring, t("dashboard.sa_expiring"), _kpiTone(saExpiring, { bad: 1 }));
    var plgActive = _pluginList.filter(function(p) { return p.enabled; }).length;
    h += _card(plgActive + '/' + _pluginList.length, t("nav.plugins"));
    h += '</div>';

    // Compliance overview
    if (D.si_users.length) {
        h += '<div class="ct-mt-4 ct-mb-4"><h3 class="ct-text-data ct-mb-2">' + t("dashboard.compliance") + '</h3>';
        h += '<div class="ct-flex ct-gap-4 ct-row-wrap ct-text-meta">';
        h += '<div>' + t("user.politique_validee") + ': <strong>' + compPol + '%</strong></div>';
        h += '<div>' + t("user.mfa_active") + ': <strong>' + compMfa + '%</strong></div>';
        h += '</div></div>';
    }

    // Overdue reviews
    var overdue: AccessApplication[] = [];
    D.applications.forEach(function(app) {
        var lastClosed: string | null = null;
        D.reviews.forEach(function(r) {
            if (r.application_id === app.id && r.status === "cloturee" && r.closed_at) {
                if (!lastClosed || r.closed_at > lastClosed) lastClosed = r.closed_at;
            }
        });
        if (_isReviewOverdue(app, lastClosed)) overdue.push(app);
    });
    if (overdue.length) {
        h += '<div class="ct-mt-4 ct-mb-4"><h3 class="ct-text-data ct-mb-2 ct-text-critical">' + t("dashboard.overdue") + '</h3>';
        overdue.forEach(function(app) {
            h += '<div class="ct-text-meta ct-py-1 ct-px-0"><span class="ct-badge" data-tone="critical">' + esc(app.nom) + '</span> <span class="ct-muted">' + esc(_freqLabel(app.frequence_revue)) + '</span></div>';
        });
        h += '</div>';
    }
    return h;
}

// ═══════════════════════════════════════════════════════════════
// USERS
// ═══════════════════════════════════════════════════════════════
var _userFilter = "";

function renderUserList(): string {
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("nav.users") + ' (' + D.si_users.length + ')</h2>';
    h += '<input type="text" id="user-search" placeholder="' + esc(t("user.search") || "Rechercher...") + '" value="' + esc(_userFilter) + '" class="ct-flex-1 ct-maxw-300 ct-py-1 ct-px-2 ct-bordered ct-r-sm ct-text-meta" data-input="_filterUsers" data-pass-value>';
    // When an HR connector is active, HR (via Access) is the source of
    // identities and self-syncs to Pilot — pulling FROM Pilot is the wrong
    // direction, so the "Sync Pilot" button is hidden (no bidirectional sync).
    var _hrActive = (_pluginList || []).some(function(p) { return p.plugin_type === "hr_generic" && p.enabled; });
    if (!_hrActive) {
        h += '<button class="ct-btn mt-8 access-link" data-write data-click="syncUsersFromPilot" title="' + esc(t("user.sync_pilot_tooltip") || "Importer/mettre a jour depuis l'annuaire Pilot") + '">' + (t("user.sync_pilot") || "Sync Pilot") + '</button>';
    }
    // Sync RH only when an HR connector (hr_generic) is actually configured.
    if ((_pluginList || []).some(function(p) { return p.plugin_type === "hr_generic"; })) {
        h += '<button class="ct-btn mt-8" data-write data-click="syncUsersFromHr" title="' + esc(t("user.sync_hr_tooltip") || "Importer/mettre a jour depuis le connecteur RH") + '">' + (t("user.sync_hr") || "Sync RH") + '</button>';
    }
    h += '<button class="ct-btn mt-8" data-write data-click="importUsersCsv">' + (t("user.import_csv") || "Importer CSV") + '</button>';
    h += '<a href="javascript:void(0)" class="access-link" data-click="downloadUsersCsvTemplate" style="font-size:var(--ct-text-label);align-self:center;text-decoration:underline">' + (t("user.csv_template") || "Modèle CSV") + '</a>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="addUser">' + t("user.add") + '</button></div>';
    if (!D.si_users.length) { h += '<div class="ct-empty-state">' + t("user.empty") + '</div>'; return h; }

    var q = _userFilter.toLowerCase();
    var filtered = D.si_users.filter(function(u) {
        if (!q) return true;
        return ((u.id || "") + " " + (u.nom || "") + " " + (u.prenom || "") + " " + (u.email || "") + " " + (u.fonction || "")).toLowerCase().indexOf(q) >= 0;
    });

    if (!filtered.length) { h += '<div class="ct-empty-state">' + (t("user.no_results") || "Aucun résultat") + '</div>'; return h; }

    h += ct_table.render({
        rows: filtered,
        rowKey: "id",
        onRowClick: "_openUserRow",
        bulk: { scope: "access-users" },
        columns: [
            { key: "id", label: "ID", width: "90px",
              render: function(u: Record<string, any>) { return '<span class="ct-text-label ct-muted">' + esc(u.id) + '</span>'; } },
            { key: "nom", label: t("user.nom"),
              render: function(u: Record<string, any>) { return '<strong>' + esc(u.nom) + '</strong>'; } },
            { key: "prenom", label: t("user.prenom"),
              render: function(u: Record<string, any>) { return esc(u.prenom); } },
            { key: "email", label: "Email",
              render: function(u: Record<string, any>) { return '<span>' + esc(u.email) + '</span>'; } },
            { key: "statut", label: t("user.statut_label"), width: "130px",
              render: function(u: Record<string, any>) { return esc(_statusLabel(u.statut)); } },
            { key: "fonction", label: t("user.fonction"),
              render: function(u: Record<string, any>) { return '<span>' + esc(u.fonction) + '</span>'; } },
            { key: "last_login_at", label: t("user.last_login") || "Dernière connexion", width: "150px",
              render: function(u: Record<string, any>) {
                  if (!u.last_login_at) return '<span>—</span>';
                  var d = new Date(u.last_login_at);
                  if (isNaN(d.getTime())) return '<span>—</span>';
                  // Color cue: > 90d ago = red, > 30d = orange, else normal
                  var daysAgo = Math.floor((Date.now() - d.getTime()) / 86400000);
                  var color = daysAgo > 90 ? "var(--ct-critical)" : (daysAgo > 30 ? "var(--ct-medium)" : "");
                  return '<span style="font-size:var(--ct-text-label)' + (color ? ";color:" + color : "") + '" title="' + esc(u.last_login_at) + '">'
                      + esc(d.toISOString().slice(0, 10)) + '</span>';
              } },
            { key: "compliance", label: t("user.compliance"), width: "120px",
              render: function(u: Record<string, any>) { return _compTag(u.politique_validee) + ' ' + _compTag(u.mfa_active) + ' ' + _compTag(u.sensibilisation); } }
        ]
    });

    setTimeout(function() {
        if (!window.ct_bulkbar) return;
        ct_bulkbar.attach({
            scope: "access-users",
            label: t("user.selected_n") || "{n} utilisateur(s) sélectionné(s)",
            actions: [
                { id: "delete", icon: "trash", label: t("btn_delete") || "Supprimer", danger: true,
                  onClick: "_bulkDeleteUsers",
                  confirm: { title: "Supprimer {n} utilisateur(s) ?", message: "Cette action est irréversible." } }
            ]
        });
        ct_bulkbar.update("access-users");
    }, 0);

    return h;
}

window._filterUsers = function(val) { _userFilter = val || ""; _renderKeepingFocus("user-search"); };

var _syncPilotInFlight = false;
window.syncUsersFromPilot = function() {
    if (_syncPilotInFlight) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) { showStatus("Backend not available", true); return; }
    _ctConfirm(
        t("user.sync_pilot_confirm_title") || "Synchroniser depuis Pilot",
        t("user.sync_pilot_confirm_body") || "Les utilisateurs de l'annuaire Pilot seront importes ou mis a jour (nom, prenom, fonction). Les flags de conformite existants ne sont pas ecrases. Continuer ?",
        function() {
            _syncPilotInFlight = true;
            showStatus(t("user.sync_pilot_running") || "Synchronisation Pilot en cours...");
            AccessAPI.syncSiUsersFromPilot(pid!).then(function(r) {
                var base = t("user.sync_pilot_ok") ||
                    "Sync Pilot : {created} cree(s), {updated} mis a jour, {skipped} ignore(s) (sur {total} dans Pilot)";
                showStatus(base
                    .replace("{created}", String(r.created))
                    .replace("{updated}", String(r.updated))
                    .replace("{skipped}", String(r.skipped))
                    .replace("{total}", String(r.total_pilot)));
                // Reload D via the shared guard to avoid clobbering a
                // concurrent live-reload (focus/polling).
                _reloadProjectData();
            }).catch(function(e) {
                showStatus((t("user.sync_pilot_fail") || "Erreur sync Pilot : ") + (e.message || e), true);
            }).finally(function() { _syncPilotInFlight = false; });
        }
    );
};

// Import users into the referential from a CSV file (reuses the global
// #csv-import-input hidden input). Reloads D after import so a subsequent
// blob autosave doesn't clobber the freshly imported rows.
window.importUsersCsv = function() {
    var el = document.getElementById("csv-import-input") as HTMLInputElement; if (!el) return;
    el.value = "";
    el.onchange = function() {
        if (!el.files || !el.files[0]) return;
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (!pid || !window.AccessAPI) { showStatus("Backend not available", true); return; }
        AccessAPI.importSiUsersCsv(pid, el.files[0]).then(function(r) {
            var base = t("user.csv_imported") ||
                "Import CSV : {created} cree(s), {updated} mis a jour, {skipped} ignore(s)";
            showStatus(base
                .replace("{created}", String(r.created))
                .replace("{updated}", String(r.updated))
                .replace("{skipped}", String(r.skipped)));
            _reloadProjectData();
        }).catch(function(e) { showStatus(e.message || String(e), true); });
    };
    el.click();
};

// Download a ready-to-fill CSV template for the user referential import.
window.downloadUsersCsvTemplate = function() {
    var header = "prenom;nom;email;fonction;equipe;type_compte;date_fin_contrat;manager;statut";
    var example = "Claire;Dubois;claire.dubois@example.com;Responsable Qualité;Qualité;salarie;;;actif\n"
        + "Marc;Lefevre;marc.lefevre@example.com;Ingénieur DevOps;Plateforme;prestataire;2026-12-31;claire.dubois@example.com;actif\n"
        + "Sofia;Nguyen;sofia.nguyen@example.com;Stagiaire SOC;Sécurité;stagiaire;2026-08-31;marc.lefevre@example.com;recrutement";
    var csv = header + "\n" + example + "\n";
    var blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "modele_utilisateurs.csv";
    link.click();
    URL.revokeObjectURL(link.href);
};

// Sync the referential from the enabled HR connector(s). Reloads D after.
window.syncUsersFromHr = function() {
    if (_syncPilotInFlight) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) { showStatus("Backend not available", true); return; }
    _syncPilotInFlight = true;
    showStatus(t("user.sync_hr_running") || "Synchronisation RH en cours...");
    AccessAPI.syncSiUsersFromHr(pid).then(function(r) {
        var base = t("user.sync_hr_ok") ||
            "Sync RH : {created} cree(s), {updated} mis a jour, {skipped} ignore(s)";
        showStatus(base
            .replace("{created}", String(r.created))
            .replace("{updated}", String(r.updated))
            .replace("{skipped}", String(r.skipped)));
        _reloadProjectData();
    }).catch(function(e) {
        showStatus((t("user.sync_hr_fail") || "Erreur sync RH : ") + (e.message || e), true);
    }).finally(function() { _syncPilotInFlight = false; });
};

window._openUserRow = function(row) {
    var idx = D.si_users.findIndex(function(u) { return u.id === row.id; });
    if (idx >= 0) { _selectedUser = idx; renderPanel(); }
};

window._bulkDeleteUsers = function(scope) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    D.si_users = D.si_users.filter(function(u) { return ids.indexOf(u.id) < 0; });
    _purgeUserRefs(ids);
    if (pid && window.AccessAPI && (AccessAPI as Partial<AccessApi>).deleteSiUser) {
        ids.forEach(function(uid) {
            AccessAPI.deleteSiUser(pid!, uid).catch(function(e) { console.error("Delete user:", e); });
        });
    }
    _save();
    ct_bulkbar.clear(scope);
    showStatus(t("user.bulk_deleted", { n: String(ids.length) }));
    renderPanel();
};

function openUser(i: number | string): void { _selectedUser = parseInt(i as string); renderPanel(); } window.openUser = openUser;
function addUser(): void {
    D.si_users.push({
        id: _genId("USR-", D.si_users), nom: "", prenom: "", email: "",
        statut: "actif", type_compte: "salarie", fonction: "",
        equipe: "", date_fin_contrat: "", manager_email: "",
        politique_validee: false, politique_date: "", politique_justification: "",
        mfa_active: false, mfa_date: "", mfa_justification: "",
        sensibilisation: false, sensibilisation_date: "", sensibilisation_justification: "", sensibilisation_history: {},
        background_check: false, background_check_date: "", background_check_justification: "",
        background_check_url: "",
        nda_signed: false, nda_date: "", nda_justification: "",
    });
    _selectedUser = D.si_users.length - 1; renderPanel(); _save();
} window.addUser = addUser;
function backToUsers(): void { _selectedUser = null; renderPanel(); } window.backToUsers = backToUsers;
// Nothing cascades on the database side: application_id, review_entry_id and
// reviewers are free-form strings, with no foreign key (the model's cascades
// only cover project_id). So the links are cleaned up here, and _save()
// republishes the whole blob.
//
// A measure is not deleted along with the review that gave birth to it: it is
// assigned work, with an owner and a due date. It gets detached instead.
// Review entries, on the other hand, are never rewritten: a review is a dated
// record, and the entry already carries frozen email_or_login / nom / prenom
// — _resolveEntryUser returns undefined and the display falls back on those.
function _detachMeasures(entryIds: string[]): number {
    if (!entryIds.length) return 0;
    var n = 0;
    (D.measures || []).forEach(function(m) {
        if (m.review_entry_id && entryIds.indexOf(m.review_entry_id) >= 0) {
            m.review_entry_id = ""; n++;
        }
    });
    return n;
}

function _purgeUserRefs(ids: string[]): number {
    var n = 0;
    (D.applications || []).forEach(function(a) {
        var before = (a.reviewers || []).length;
        a.reviewers = (a.reviewers || []).filter(function(rid) { return ids.indexOf(rid) < 0; });
        n += before - a.reviewers.length;
    });
    return n;
}

// Deletes the reviews of these applications, after detaching their measures.
function _purgeAppRefs(ids: string[]): void {
    var doomed = (D.reviews || []).filter(function(r) { return ids.indexOf(r.application_id) >= 0; });
    _detachMeasures(_entryIdsOf(doomed));
    D.reviews = (D.reviews || []).filter(function(r) { return ids.indexOf(r.application_id) < 0; });
}

function _entryIdsOf(reviews: AccessReview[]): string[] {
    var ids: string[] = [];
    reviews.forEach(function(r) {
        (r.entries || []).forEach(function(e) { if (e.id) ids.push(e.id); });
    });
    return ids;
}

function deleteUser(): void {
    if (_selectedUser === null) return;
    var u = D.si_users[_selectedUser];
    var uid = u.id;
    var asReviewer = (D.applications || []).filter(function(a) {
        return (a.reviewers || []).indexOf(uid) >= 0;
    });
    var body = t("user.confirm_delete_body", { nom: u.nom + " " + u.prenom });
    if (asReviewer.length) body += " " + t("user.confirm_delete_reviewer", { n: String(asReviewer.length) });
    _ctConfirm(t("user.confirm_delete"), body, function() {
        _purgeUserRefs([uid]);
        D.si_users.splice(_selectedUser!, 1); _selectedUser = null; renderPanel(); _save();
    });
} window.deleteUser = deleteUser;

function renderUserDetail(): string {
    var u = D.si_users[_selectedUser!]; if (!u) return renderUserList();
    var lockedByPilot = u.sync_source === "pilot";
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToUsers">&laquo; ' + t("nav.users") + '</button>';
    h += '<h2 class="ct-m-0">' + esc((u.prenom + " " + u.nom).trim() || t("user.new")) + '</h2>';
    if (lockedByPilot) {
        h += '<span title="' + esc(t("user.managed_by_pilot_tooltip") || "Ces champs d\'identite sont synchronises depuis Pilot et ne peuvent pas etre modifies ici") + '" style="display:inline-flex;align-items:center;gap:var(--ct-s1);padding:var(--ct-s1) var(--ct-s2);border-radius:var(--ct-r-xl);background:var(--ct-accent-tint);color:var(--access-accent-on-tint,var(--ct-accent));font-size:var(--ct-text-label);font-weight:600">🔒 ' + (t("user.managed_by_pilot") || "Géré par Pilot") + '</span>';
    }
    h += '<span class="ct-flex-1"></span>';
    h += '<button class="ct-btn mt-8" data-write data-variant="danger" data-click="deleteUser">' + t("btn_delete") + '</button></div>';

    h += '<div class="ct-tprm-form"><div class="ct-form-grid">';
    h += _field("nom",    t("user.nom"),    "text", u.nom,    lockedByPilot);
    h += _field("prenom", t("user.prenom"), "text", u.prenom, lockedByPilot);
    h += '</div><div class="ct-form-grid">';
    h += _field("email",    "Email",           "email", u.email,    lockedByPilot);
    h += _field("fonction", t("user.fonction"), "text", u.fonction, lockedByPilot);
    h += '</div><div class="ct-form-grid">';
    h += _sel("statut", t("user.statut_label"),
              ["actif", "ancien", "recrutement"].map(function(s) { return { v: s, l: _statusLabel(s) }; }),
              u.statut, lockedByPilot);
    h += _sel("type_compte", t("user.type_compte_label") || "Type",
              ["salarie", "prestataire", "stagiaire", "alternant"].map(function(s) {
                  return { v: s, l: t("user.type_compte." + s) || s };
              }),
              u.type_compte || "salarie");
    h += '</div><div class="ct-form-grid">';
    h += _field("equipe", t("user.equipe") || "Équipe", "text", u.equipe);
    // Manager — shared user picker (ct_userpicker), mounted post-render on the
    // slot below. Stores the selected user's email in manager_email.
    h += '<div class="ct-form-row"><label>' + esc(t("user.manager") || "Manager") + '</label><div id="user-manager-slot"></div></div>';
    h += '</div>';
    // Contract end date — required/relevant for every type except salarie.
    if ((u.type_compte || "salarie") !== "salarie") {
        h += '<div class="ct-form-grid">';
        h += _field("date_fin_contrat", t("user.date_fin_contrat") || "Date de fin de contrat", "date", u.date_fin_contrat);
        h += '</div>';
    }

    // Compliance proofs — a control turns green only when both a date and a
    // justification are filled (no manual checkbox).
    h += '<div class="form-section">' + t("user.compliance") + '</div>';
    h += '<div style="font-size:var(--ct-text-label);color:var(--ct-ink-2);margin:calc(-1 * var(--ct-s1)) 0 var(--ct-s2)">' + esc(t("user.compliance_hint")) + '</div>';
    h += '<div class="proof-grid">';
    h += _proofCard("politique",       t("user.politique_validee"),
                    u.politique_validee, u.politique_date, u.politique_justification,
                    "politique_validee", "politique_date", "politique_justification");
    h += _proofCard("mfa",              t("user.mfa_active"),
                    u.mfa_active, u.mfa_date, u.mfa_justification,
                    "mfa_active", "mfa_date", "mfa_justification");
    h += _sensibilisationCard(u);
    h += _proofCard("background_check", t("user.background_check") || "Background check",
                    u.background_check, u.background_check_date, u.background_check_justification,
                    "background_check", "background_check_date", "background_check_justification");
    // NDA — mandatory for prestataires, displayed only then to keep the UI tidy.
    if ((u.type_compte || "salarie") === "prestataire") {
        h += _proofCard("nda", t("user.nda") || "NDA signé",
                        u.nda_signed, u.nda_date, u.nda_justification,
                        "nda_signed", "nda_date", "nda_justification");
    }
    h += '</div>';
    // Legacy background-check URL — kept editable when present, hidden otherwise.
    if (u.background_check_url) {
        h += '<div>';
        h += _field("background_check_url",
                    (t("user.background_check_url") || "Background check (URL legacy)"),
                    "url", u.background_check_url);
        h += '</div>';
    }
    h += '</div>';
    // Requested entitlements (loaded async from a dedicated API, never blob).
    h += '<div class="form-section">' + t("user.entitlements") + '</div>';
    h += '<div id="user-entitlements">' + esc(t("user.ent_loading") || "Chargement…") + '</div>';
    setTimeout(_mountManagerPicker, 0);
    setTimeout(_loadEntitlements, 0);
    return h;
}

var _mgrHandle: { getValue: () => string } | null = null;

// Mount the shared user picker on the manager slot (post-render).
function _mountManagerPicker(): void {
    var up = window.ct_userpicker;
    if (!up || _selectedUser === null) return;
    var uu = D.si_users[_selectedUser]; if (!uu) return;
    var cur = uu.manager_email || "";
    var curSu = D.si_users.find(function(x) { return !!x.email && x.email.toLowerCase() === cur.toLowerCase(); });
    var initLabel = curSu ? ((curSu.prenom + " " + curSu.nom).trim() || curSu.email || "") : cur;
    up.mount({
        slotId: "user-manager-slot",
        pickerId: "access-user-manager",
        value: initLabel,
        placeholder: t("user.manager_search") || "Rechercher un utilisateur…",
        directoryUrl: "api/directory",
    }).then(function(handle) {
        _mgrHandle = handle;
        ["access-user-manager-search", "access-user-manager-plain"].forEach(function(eid) {
            var el = document.getElementById(eid);
            if (el) { el.addEventListener("blur", _commitManager); el.addEventListener("change", _commitManager); }
        });
        var wrap = document.getElementById("access-user-manager-wrap");
        if (wrap) wrap.addEventListener("click", function() { setTimeout(_commitManager, 0); });
    });
}

// Resolve the picked label back to an email against the referential
// (managers are users in D.si_users) and persist it on manager_email.
function _commitManager(): void {
    if (_selectedUser === null || !_mgrHandle) return;
    var target = D.si_users[_selectedUser]; if (!target) return;
    var label = (_mgrHandle.getValue() || "").trim();
    var su = D.si_users.find(function(x) {
        if (x.id === target.id) return false;
        return ((x.prenom + " " + x.nom).trim() === label)
            || (!!x.email && x.email.toLowerCase() === label.toLowerCase());
    });
    var val = su ? (su.email || label) : label;
    if ((target.manager_email || "") === val) return;
    target.manager_email = val;
    _save();
}

// Proof bool field → its date + justification fields (FEAT-15 Lot 3:
// a proof can only be checked when both are filled).
var _PROOF_FIELDS: Record<string, { date: string; justif: string }> = {
    politique_validee: { date: "politique_date", justif: "politique_justification" },
    mfa_active: { date: "mfa_date", justif: "mfa_justification" },
    sensibilisation: { date: "sensibilisation_date", justif: "sensibilisation_justification" },
    background_check: { date: "background_check_date", justif: "background_check_justification" },
    nda_signed: { date: "nda_date", justif: "nda_justification" },
};
var _PROOF_EVIDENCE_TO_BOOL: Record<string, string> = {};
Object.keys(_PROOF_FIELDS).forEach(function(b) {
    _PROOF_EVIDENCE_TO_BOOL[_PROOF_FIELDS[b].date] = b;
    _PROOF_EVIDENCE_TO_BOOL[_PROOF_FIELDS[b].justif] = b;
});

function _proofHasEvidence(u: Record<string, unknown>, boolField: string): boolean {
    var ev = _PROOF_FIELDS[boolField];
    return !!String(u[ev.date] || "").trim() && !!String(u[ev.justif] || "").trim();
}

function saveUserField(field: string, val: string): void {
    if (_selectedUser === null) return;
    var u = D.si_users[_selectedUser] as Record<string, unknown>;
    u[field] = val;
    var rerender = field === "type_compte";  // NDA card visibility
    // Conformity is derived: editing a proof's date/comment re-evaluates the
    // green ✓ (compliant only when both are filled).
    var boolField = _PROOF_EVIDENCE_TO_BOOL[field];
    if (boolField) {
        var nowOk = _proofHasEvidence(u, boolField);
        if (!!u[boolField] !== nowOk) { u[boolField] = nowOk; rerender = true; }
    }
    _save();
    if (rerender) renderPanel();
}
window.saveUserField = saveUserField;

function saveUserCheck(field: string, el: HTMLInputElement): void {
    if (_selectedUser === null) return;
    (D.si_users[_selectedUser] as Record<string, unknown>)[field] = el.checked;
    _save();
}
window.saveUserCheck = saveUserCheck;

// ── Requested entitlements (FEAT-15 Lot 4) ──────────────────────
var _entitlements: AccessEntitlement[] = [];
var _entAudit: AccessEntitlementAudit[] = [];
var _entDraftPerim = "";

// Close the perimeter dropdown when clicking outside it (registered once).
document.addEventListener("click", function(e) {
    var dd = document.getElementById("ent-perim-dd");
    if (dd && !(e.target as Element).closest("#ent-perim-dd, #ent-perim-search")) dd.hidden = true;
});

window._entPerimOpen = function() {
    var dd = document.getElementById("ent-perim-dd"); if (dd) dd.hidden = false;
};
window._entPerimSearch = function(query) {
    var dd = document.getElementById("ent-perim-dd"); if (!dd) return;
    dd.hidden = false;
    var q = (query || "").toLowerCase();
    dd.querySelectorAll(".ent-perim-item").forEach(function(it) {
        (it as HTMLElement).style.display = ((it.textContent || "").toLowerCase().indexOf(q) >= 0) ? "" : "none";
    });
};
window._entPickPerim = function(perimId) {
    _entDraftPerim = perimId || "";
    _renderEntitlements();
};

// Mirror of the backend RBAC: admin, or the actor is in the target user's
// ascending manager chain (direct manager, manager's manager, …).
function _canEditEntitlements(target: AccessSiUser): boolean {
    var cu = window._currentUser;
    if (!cu) return true;  // no auth = full access
    if (window._moduleRole === "admin" || cu.role === "admin") return true;
    var actor = String(cu.email || "").trim().toLowerCase();
    if (!actor) return false;
    var byEmail: Record<string, AccessSiUser> = {};
    D.si_users.forEach(function(x) { if (x.email) byEmail[x.email.toLowerCase()] = x; });
    var visited: Record<string, boolean> = {};
    var cur: AccessSiUser | undefined = target;
    for (var i = 0; i < 10; i++) {
        var mgr: string = cur ? String(cur.manager_email || "").trim().toLowerCase() : "";
        if (!mgr || visited[mgr]) break;
        if (mgr === actor) return true;
        visited[mgr] = true; cur = byEmail[mgr];
    }
    return false;
}

function _loadEntitlements(): void {
    if (_selectedUser === null) return;
    var u = D.si_users[_selectedUser]; if (!u) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) { var s0 = document.getElementById("user-entitlements"); if (s0) s0.innerHTML = ""; return; }
    var uid = u.id;
    Promise.all([AccessAPI.listEntitlements(pid, uid), AccessAPI.listEntitlementAudit(pid, uid)]).then(function(res) {
        if (_selectedUser === null || D.si_users[_selectedUser].id !== uid) return;  // user changed meanwhile
        _entitlements = res[0] || [];
        _entAudit = res[1] || [];
        _renderEntitlements();
    }).catch(function(e) {
        var s = document.getElementById("user-entitlements");
        if (s) s.textContent = (e && e.message) || "Erreur";
    });
}

function _perimLabel(pid: string): string {
    var p = D.applications.find(function(a) { return a.id === pid; });
    return p ? (p.nom || pid) : pid;
}

function _renderEntitlements(): void {
    var slot = document.getElementById("user-entitlements");
    if (!slot || _selectedUser === null) return;
    var u = D.si_users[_selectedUser]; if (!u) return;
    var canEdit = _canEditEntitlements(u);
    var h = "";
    // Add zone first (above the recap table).
    if (canEdit) {
        var perim = D.applications.find(function(a) { return a.id === _entDraftPerim; });
        var roleOpts = ((perim && perim.roles) || []).map(function(r) { return { id: r, label: r }; });
        h += '<div class="ct-flex ct-gap-2 ct-items-start ct-row-wrap ct-mb-2">';
        // Perimeter — plain search combobox: filtered list, shows the name as
        // text once picked (no tag chip).
        h += '<div class="ct-userpicker ct-minw-220 ct-flex-1">';
        h += '<input type="text" id="ent-perim-search" autocomplete="off" value="' + esc(_entDraftPerim ? _perimLabel(_entDraftPerim) : "") + '" placeholder="' + esc(t("user.ent_search_perim") || "Rechercher un périmètre...") + '" class="ct-input" data-input="_entPerimSearch" data-pass-value data-click="_entPerimOpen" data-stop>';
        h += '<div id="ent-perim-dd" hidden style="position:absolute;left:0;right:0;top:100%;background:var(--ct-surface);border:1px solid var(--ct-line);border-radius:0 0 4px 4px;max-height:220px;overflow-y:auto;z-index:30;box-shadow:0 4px 12px rgba(0,0,0,0.12)">';
        D.applications.forEach(function(a) {
            h += '<div class="ent-perim-item ct-py-1 ct-px-2 ct-clickable ct-text-meta" data-click="_entPickPerim" data-args=\'' + _da(a.id) + '\' data-stop>' + esc(a.nom || a.id) + '</div>';
        });
        if (!D.applications.length) h += '<div class="ct-py-1 ct-px-2 ct-muted ct-text-label">' + esc(t("app.empty") || "Aucun périmètre") + '</div>';
        h += '</div></div>';
        // Roles — multi-select with search (chips are fine here).
        h += '<div class="ct-minw-220 ct-flex-1">' + (window.ctRefSelect ? window.ctRefSelect("ent-roles", "", roleOpts, { hideId: true, placeholder: t("user.ent_search_role") || "Rechercher un rôle...", emptyText: roleOpts.length ? (t("user.ent_select_roles") || "Rôles...") : (t("user.ent_no_roles") || "(aucun rôle défini)") }) : "") + '</div>';
        h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-size="xs" data-click="addEntitlement"' + (_entDraftPerim ? "" : " disabled") + '>' + esc(t("user.ent_add") || "Ajouter") + '</button>';
        h += '</div>';
    }
    if (!_entitlements.length) {
        h += '<div class="ct-empty-state ct-py-2 ct-px-0">' + esc(t("user.ent_empty") || "Aucune habilitation demandée") + '</div>';
    } else {
        h += '<table class="ct-w-full ct-text-meta ct-mb-2"><thead><tr>';
        h += '<th class="ct-ta-l">' + esc(t("user.ent_perimetre")) + '</th>';
        h += '<th class="ct-ta-l">' + esc(t("user.ent_role")) + '</th>';
        h += '<th class="ct-ta-l">' + esc(t("user.ent_requested_by")) + '</th><th></th></tr></thead><tbody>';
        _entitlements.forEach(function(e) {
            h += '<tr><td>' + esc(_perimLabel(e.perimetre_id)) + '</td>';
            h += '<td>' + esc(e.role || "—") + '</td>';
            h += '<td class="ct-muted">' + esc(e.created_by || "—") + (e.created_at ? ' · ' + esc(e.created_at.slice(0, 10)) : "") + '</td>';
            h += '<td class="ct-ta-r">' + (canEdit ? '<button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-variant="danger" data-click="removeEntitlement" data-args=\'' + _da(e.id) + '\' data-size="xs" data-icon>' + _icon("trash", 14) + '</button>' : "") + '</td></tr>';
        });
        h += '</tbody></table>';
    }
    if (_entAudit.length) {
        h += '<details><summary class="ct-clickable ct-text-label ct-muted">' + esc(t("user.ent_audit_title") || "Journal des habilitations") + ' (' + _entAudit.length + ')</summary>';
        h += '<table class="ct-w-full ct-text-label ct-mt-1"><tbody>';
        _entAudit.forEach(function(a) {
            var act = t("user.ent_action." + a.action) || a.action;
            var detail = a.field ? (esc(a.field) + ": " + esc(a.old_value || "∅") + " → " + esc(a.new_value || "∅")) : esc(a.new_value || a.old_value || "");
            h += '<tr><td class="ct-muted ct-nowrap">' + esc((a.at || "").slice(0, 16).replace("T", " ")) + '</td>';
            h += '<td>' + esc(act) + '</td><td>' + detail + '</td>';
            h += '<td class="ct-muted">' + esc(a.actor || "") + '</td></tr>';
        });
        h += '</tbody></table></details>';
    }
    slot.innerHTML = h;
    // Register the roles multi-select (callbacks + tag rendering).
    if (canEdit && window.ctRefRegister) {
        window.ctRefRegister("ent-roles", { hideId: true, emptyText: "", labelFor: function(id) { return id; } });
    }
}

window.addEntitlement = function() {
    if (_selectedUser === null || !_entDraftPerim) return;
    var u = D.si_users[_selectedUser]; if (!u) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) return;
    var roles: string[] = [];
    document.querySelectorAll("#ent-roles-dd input:checked").forEach(function(el) { roles.push((el as HTMLInputElement).value); });
    if (!roles.length) roles = [""];  // perimeter-level entitlement (no specific role)
    var perimId = _entDraftPerim;
    var uid = u.id;
    // Sequential, not parallel: each POST computes the next ENT- id from the
    // committed state, so concurrent creates don't collide on the primary key.
    roles.reduce(function(chain, r) {
        return chain.then(function() { return AccessAPI.createEntitlement(pid!, uid, { perimetre_id: perimId, role: r }); });
    }, Promise.resolve() as Promise<unknown>)
        .then(function() { _entDraftPerim = ""; _loadEntitlements(); })
        .catch(function(e) { showStatus((e && e.message) || "Erreur", true); });
};

window.removeEntitlement = function(eid) {
    if (_selectedUser === null) return;
    var u = D.si_users[_selectedUser]; if (!u) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) return;
    AccessAPI.deleteEntitlement(pid, u.id, eid).then(function() { _loadEntitlements(); })
        .catch(function(e) { showStatus((e && e.message) || "Erreur", true); });
};

function _field(name: string, label: string, type: string, val: unknown, disabled?: boolean): string {
    var extra = disabled ? ' disabled style="background:var(--ct-surface-2);color:var(--access-disabled-ink,var(--ct-ink-1));cursor:not-allowed"' : '';
    return '<div class="ct-form-row"><label>' + esc(label) + '</label><input type="' + type + '" value="' + esc(String(val != null ? val : "")) + '"' + extra + ' data-change="saveUserField" data-args=\'["' + name + '"]\' data-pass-value></div>';
}

function _sel(name: string, label: string, opts: { v: string; l: string }[], val: string | undefined, disabled?: boolean): string {
    var extra = disabled ? ' disabled style="background:var(--ct-surface-2);color:var(--access-disabled-ink,var(--ct-ink-1));cursor:not-allowed"' : '';
    var h = '<div class="ct-form-row"><label>' + esc(label) + '</label><select' + extra + ' data-change="saveUserField" data-args=\'["' + name + '"]\' data-pass-value>';
    opts.forEach(function(o) { h += '<option value="' + esc(String(o.v)) + '"' + (String(val) === String(o.v) ? " selected" : "") + '>' + esc(o.l) + '</option>'; });
    return h + '</select></div>';
}

// Single proof card — checkbox (title), date, free-text justification.
// All three fields share the same wire format so adding a new proof
// (e.g. "health check", "training X") only requires a new _proofCard() call.
function _proofCard(id: string, label: string, _checked: boolean | undefined, dateVal: string | undefined, justif: string | undefined, fieldBool: string, fieldDate: string, fieldJustif: string): string {
    // Conformity is DERIVED: a control is compliant (green ✓) only when both a
    // date and a justification are present — no manual checkbox (FEAT-15 Lot 3).
    var ok = !!String(dateVal || "").trim() && !!String(justif || "").trim();
    var h = '<div class="proof-card' + (ok ? ' proof-card--ok' : '') + '">';
    h += '<div class="proof-card__head">';
    h += '<span class="proof-card__title ct-inline-flex ct-items-center ct-gap-1">';
    h += '<span aria-hidden="true" style="display:inline-block;width:1.1em;text-align:center;font-weight:700;color:' + (ok ? 'var(--ct-low)' : 'var(--ct-ink-2)') + '">' + (ok ? '✓' : '○') + '</span>';
    h += esc(label) + '</span>';
    h += '<input type="date" class="proof-card__date" value="' + esc(String(dateVal || "")) + '" data-change="saveUserField" data-args=\'["' + esc(fieldDate) + '"]\' data-pass-value>';
    h += '</div>';
    h += '<textarea class="proof-card__justif" rows="2" placeholder="' + esc(t("user.justification_placeholder") || "Justification, lien, référence…") + '" data-change="saveUserField" data-args=\'["' + esc(fieldJustif) + '"]\' data-pass-value>' + esc(String(justif || "")) + '</textarea>';
    h += '</div>';
    return h;
}

// ═══════════════════════════════════════════════════════════════
// APPLICATIONS
// ═══════════════════════════════════════════════════════════════
var _appFilter = "";

function renderAppList(): string {
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<h2 class="ct-m-0">' + t("nav.apps") + ' (' + D.applications.length + ')</h2>';
    h += '<input type="text" id="app-search" placeholder="' + esc(t("app.search") || "Rechercher...") + '" value="' + esc(_appFilter) + '" style="flex:1;max-width:280px;padding:var(--ct-s1) var(--ct-s2);border:1px solid var(--ct-line);border-radius:var(--ct-r-sm);font-size:var(--ct-text-meta)" data-input="_filterApps" data-pass-value>';
    h += '<div class="ct-flex ct-gap-1">';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="addApp">' + t("app.add") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-click="importAppsCsv">' + t("app.import_csv") + '</button>';
    h += '<button class="ct-btn mt-8" data-write data-click="syncAppsFromAsset">' + t("app.sync_asset") + '</button>';
    h += '</div></div>';
    if (!D.applications.length) { h += '<div class="ct-empty-state">' + t("app.empty") + '</div>'; return h; }

    var q = _appFilter.toLowerCase();
    // Enrich rows with derived info so the table renderer doesn't re-scan D.reviews per row
    var lastByApp: Record<string, string> = {};
    D.reviews.forEach(function(r) {
        if (r.status === "cloturee" && r.closed_at && (!lastByApp[r.application_id] || r.closed_at > lastByApp[r.application_id])) {
            lastByApp[r.application_id] = r.closed_at;
        }
    });
    var rows = D.applications.map(function(a): AccessAppRow {
        var revNames = (a.reviewers || []).map(function(rid) {
            var su = D.si_users.find(function(u) { return u.id === rid; });
            return su ? (su.prenom + " " + su.nom).trim() : rid;
        }).join(", ");
        return Object.assign({}, a, {
            __reviewer_names: revNames,
            __last_review: lastByApp[a.id] || ""
        });
    }).filter(function(a) {
        if (!q) return true;
        return ((a.id || "") + " " + (a.nom || "") + " " + (a.url || "") + " " + (a.__reviewer_names || "")).toLowerCase().indexOf(q) >= 0;
    });

    if (!rows.length) { h += '<div class="ct-empty-state">' + (t("app.no_results") || "Aucune application trouvée") + '</div>'; return h; }

    h += ct_table.render({
        rows: rows,
        rowKey: "id",
        onRowClick: "_openAppRow",
        bulk: { scope: "access-apps" },
        columns: [
            { key: "id", label: "ID", width: "90px",
              render: function(a: Record<string, any>) { return '<span class="ct-text-label ct-muted">' + esc(a.id) + '</span>'; } },
            { key: "nom", label: t("app.nom"),
              render: function(a: Record<string, any>) { return '<strong>' + esc(a.nom) + '</strong>'; } },
            { key: "url", label: "URL",
              render: function(a: Record<string, any>) { return '<span>' + esc(a.url || "-") + '</span>'; } },
            { key: "reviewers", label: t("app.reviewers"),
              render: function(a: Record<string, any>) { return '<span>' + esc(a.__reviewer_names || "-") + '</span>'; } },
            { key: "frequence_revue", label: t("app.frequence"), width: "130px",
              render: function(a: Record<string, any>) { return '<span data-tone="info">' + esc(_freqLabel(a.frequence_revue)) + '</span>'; } },
            { key: "last_review", label: t("app.last_review"), width: "130px",
              render: function(a: Record<string, any>) { return '<span>' + esc(a.__last_review || "-") + '</span>'; } }
        ]
    });

    setTimeout(function() {
        if (!window.ct_bulkbar) return;
        ct_bulkbar.attach({
            scope: "access-apps",
            label: t("app.selected_n") || "{n} application(s) sélectionnée(s)",
            actions: [
                { id: "delete", icon: "trash", label: t("btn_delete") || "Supprimer", danger: true,
                  onClick: "_bulkDeleteApps",
                  confirm: { title: "Supprimer {n} application(s) ?", message: "Les revues liées resteront orphelines. Action irréversible." } }
            ]
        });
        ct_bulkbar.update("access-apps");
    }, 0);

    return h;
}

window._filterApps = function(val) { _appFilter = val || ""; _renderKeepingFocus("app-search"); };

window._openAppRow = function(row) {
    var idx = D.applications.findIndex(function(a) { return a.id === row.id; });
    if (idx >= 0) { _selectedApp = idx; renderPanel(); }
};

window._bulkDeleteApps = function(scope) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    D.applications = D.applications.filter(function(a) { return ids.indexOf(a.id) < 0; });
    _purgeAppRefs(ids);
    if (_selectedReview !== null) _selectedReview = null;
    if (pid && window.AccessAPI && (AccessAPI as Partial<AccessApi>).deleteApp) {
        ids.forEach(function(aid) {
            AccessAPI.deleteApp(pid!, aid).catch(function(e) { console.error("Delete app:", e); });
        });
    }
    _save();
    ct_bulkbar.clear(scope);
    showStatus(t("app.bulk_deleted", { n: String(ids.length) }));
    renderPanel();
};

function openApp(i: number | string): void { _selectedApp = parseInt(i as string); renderPanel(); } window.openApp = openApp;
function addApp(): void {
    D.applications.push({ id: _genId("APP-", D.applications), nom: "", url: "", reviewers: [], frequence_revue: "semestrielle", owner_email: "", type: "application", roles: [], created_at: new Date().toISOString().slice(0, 10) });
    _selectedApp = D.applications.length - 1; renderPanel(); _save();
} window.addApp = addApp;
function backToApps(): void { _selectedApp = null; renderPanel(); } window.backToApps = backToApps;
function deleteApp(): void {
    if (_selectedApp === null) return;
    var a = D.applications[_selectedApp];
    var aid = a.id;
    var appReviews = (D.reviews || []).filter(function(r) { return r.application_id === aid; });
    var entryIds = _entryIdsOf(appReviews);
    var attached = (D.measures || []).filter(function(m) {
        return m.review_entry_id && entryIds.indexOf(m.review_entry_id) >= 0;
    }).length;
    var body2 = t("app.confirm_delete_body", { nom: a.nom });
    if (appReviews.length) body2 += " " + t("app.confirm_delete_cascade", { r: String(appReviews.length), m: String(attached) });
    _ctConfirm(t("app.confirm_delete"), body2, function() {
        // The reviews of a deleted application are no longer reachable:
        // every view lists them by application. Keeping them would amount
        // to counting them in the indicators without being able to open them.
        _purgeAppRefs([aid]);
        if (_selectedReview !== null) _selectedReview = null;
        D.applications.splice(_selectedApp!, 1); _selectedApp = null; renderPanel(); _save();
    });
} window.deleteApp = deleteApp;

function renderAppDetail(): string {
    var a = D.applications[_selectedApp!]; if (!a) return renderAppList();
    var appReviews = (D.reviews || []).filter(function(r) { return r.application_id === a.id; });
    var activeReviews = appReviews.filter(function(r) { return r.status === "en_cours"; });
    var closedReviews = appReviews.filter(function(r) { return r.status === "cloturee"; });
    var lastClosed = closedReviews.slice().sort(function(a, b) { return (b.closed_at || "").localeCompare(a.closed_at || ""); })[0];

    // Header
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToApps">&laquo; ' + t("nav.apps") + '</button>';
    h += '<h2 class="ct-m-0">' + esc(a.nom || t("app.new")) + '</h2>';
    if (a.url) h += '<a href="' + esc(a.url) + '" target="_blank" rel="noopener noreferrer" class="access-link ct-text-label ct-no-underline" title="Ouvrir l\'application">&#x2197;</a>';
    h += '<span class="ct-flex-1"></span>';
    // BUG-24: no mt-8 inside a .ct-row (flex align-center) and one data-size
    // for both buttons — otherwise they sit at different heights/offsets.
    h += '<button class="ct-btn" data-write data-variant="primary" data-size="xs" style="margin-right:var(--ct-s1)" data-click="startReview" data-args=\'' + _da(a.id) + '\'>' + t("review.start") + '</button>';
    h += '<button class="ct-btn" data-write data-variant="danger" data-size="xs" data-click="deleteApp">' + t("btn_delete") + '</button></div>';

    // Stat cards
    h += '<div class="app-stats">';
    h += _card(appReviews.length, t("review.entries"));
    h += _card(activeReviews.length, "en cours", activeReviews.length ? "warning" : "");
    h += _card(closedReviews.length, "cloturees");
    h += _card((a.reviewers || []).length, t("app.reviewers"));
    if (lastClosed) {
        h += _card(esc(lastClosed.closed_at || "—"), "derniere revue");
    }
    h += '</div>';

    // Two-column layout: form on left, reviews on right
    h += '<div>';

    // Left: form
    h += '<div>';

    // Section Identite
    h += '<div>';
    h += '<div class="app-section-title">Informations</div>';
    h += '<div class="app-field"><label class="app-field-lbl">' + t("app.nom") + '</label>';
    h += '<input type="text" class="app-field-input" value="' + esc(a.nom || "") + '" data-change="saveAppField" data-args=\'["nom"]\' data-pass-value placeholder="' + esc(t("app.nom")) + '"></div>';

    h += '<div class="app-field"><label class="app-field-lbl">' + t("app.type") + '</label>';
    h += '<select class="app-field-input" data-change="saveAppField" data-args=\'["type"]\' data-pass-value>';
    ["application", "infrastructure", "physique"].forEach(function(ty) {
        h += '<option value="' + ty + '"' + ((a.type || "application") === ty ? " selected" : "") + '>' + esc(t("app.type." + ty)) + '</option>';
    });
    h += '</select></div>';

    h += '<div class="app-field"><label class="app-field-lbl">URL</label>';
    h += '<input type="url" class="app-field-input" value="' + esc(a.url || "") + '" data-change="saveAppField" data-args=\'["url"]\' data-pass-value placeholder="https://..."></div>';

    // Owner — shared user picker (ct_userpicker), mounted post-render on the
    // slot below (same pattern as the user manager). Stores an email.
    h += '<div class="app-field"><label class="app-field-lbl">' + t("app.owner_email") + '</label>';
    h += '<div id="app-owner-slot"></div></div>';
    setTimeout(_mountOwnerPicker, 0);

    h += '<div class="app-field"><label class="app-field-lbl">' + t("app.frequence") + '</label>';
    h += '<select class="app-field-input" data-change="saveAppField" data-args=\'["frequence_revue"]\' data-pass-value>';
    ["trimestrielle", "semestrielle", "annuelle"].forEach(function(f) {
        h += '<option value="' + f + '"' + (a.frequence_revue === f ? " selected" : "") + '>' + esc(_freqLabel(f)) + '</option>';
    });
    h += '</select></div>';

    h += '<div class="app-field"><label class="app-field-lbl">' + t("app.roles") + '</label>';
    h += '<textarea class="app-field-input" rows="3" data-change="saveAppRoles" data-pass-value placeholder="' + esc(t("app.roles_hint")) + '">' + esc((a.roles || []).join("\n")) + '</textarea></div>';
    h += '</div>'; // end section informations

    // Section Reviewers
    h += '<div>';
    h += '<div class="app-section-title">' + t("app.reviewers") + '</div>';
    var currentReviewers = a.reviewers || [];
    if ((window as Window)._dirGetSource && _dirGetSource() === "pilot") {
        h += _dirMultiPicker(currentReviewers, "addAppReviewer", "removeAppReviewer");
    } else {
        if (currentReviewers.length) {
            h += '<div>';
            currentReviewers.forEach(function(rid) {
                var su = D.si_users.find(function(u) { return u.id === rid; });
                var fullName = su ? (su.prenom + " " + su.nom).trim() : (_dirResolve ? _dirResolve(rid) : rid);
                var initials = "?";
                if (su) initials = ((su.prenom || "")[0] || "") + ((su.nom || "")[0] || "");
                h += '<div>';
                h += '<span class="app-reviewer-avatar">' + esc(initials.toUpperCase()) + '</span>';
                h += '<span class="app-reviewer-info"><span class="app-reviewer-name">' + esc(fullName) + '</span>';
                if (su && su.email) h += '<span class="app-reviewer-email">' + esc(su.email) + '</span>';
                h += '</span>';
                h += '<button class="ct-btn" data-variant="danger" data-size="xs" data-icon title="Retirer" data-click="removeAppReviewer" data-args=\'' + _da(rid) + '\'>' + _icon("trash", 14) + '</button>';
                h += '</div>';
            });
            h += '</div>';
        } else {
            h += '<div class="app-empty-hint">Aucun reviseur assigne</div>';
        }
        h += '<select class="app-field-input" data-change="addAppReviewer" data-pass-value>';
        h += '<option value="">+ ' + t("app.add_reviewer") + '</option>';
        D.si_users.forEach(function(u) {
            if (currentReviewers.indexOf(u.id) >= 0) return;
            h += '<option value="' + esc(u.id) + '">' + esc((u.prenom + " " + u.nom).trim() + " — " + u.email) + '</option>';
        });
        h += '</select>';
    }
    h += '</div>'; // end section reviewers

    h += '</div>';

    // Right: reviews list
    h += '<div class="app-detail-col">';
    h += '<h3 style="font-size:var(--ct-text-ui);margin:0 0 var(--ct-s2)">Revues d\'acces</h3>';
    if (!appReviews.length) {
        h += '<div class="ct-empty-state ct-p-5">Aucune revue. Cliquez sur "' + t("review.start") + '" pour en demarrer une.</div>';
    } else {
        if (activeReviews.length) {
            h += '<div style="font-size:var(--ct-text-label);font-weight:600;color:var(--ct-ink-2);margin:var(--ct-s2) 0 var(--ct-s1);text-transform:uppercase">En cours</div>';
            activeReviews.forEach(function(r) {
                var origIdx = D.reviews.indexOf(r);
                var total = (r.entries || []).length;
                var decided = (r.entries || []).filter(function(e) { return e.decision !== "pending"; }).length;
                var pct = total ? Math.round(decided / total * 100) : 0;
                h += '<div class="app-review-row" data-click="openReview" data-args=\'' + _da(origIdx) + '\'>';
                h += '<div class="ct-flex-1 ct-minw-0">';
                h += '<div class="ct-strong ct-text-meta">' + esc(r.id) + ' <span class="ct-badge" data-tone="info" data-size="sm">' + t("review.en_cours") + '</span></div>';
                h += '<div class="ct-text-label ct-muted ct-mt-1">' + t("review.started") + ' ' + esc(r.started_at) + ' &middot; ' + decided + '/' + total + ' (' + pct + '%)</div>';
                if (total) h += '<div class="progress-bar ct-mt-1"><div class="progress-bar-fill" style="width:' + pct + '%"></div></div>';
                h += '</div>';
                h += '<button class="app-review-del" title="Supprimer cette revue" data-click="deleteReviewFromApp" data-args=\'' + _da(r.id) + '\' data-stop>' + _icon("trash", 14) + '</button>';
                h += '</div>';
            });
        }
        if (closedReviews.length) {
            h += '<div style="font-size:var(--ct-text-label);font-weight:600;color:var(--ct-ink-2);margin:var(--ct-s3) 0 var(--ct-s1);text-transform:uppercase">Historique</div>';
            closedReviews.slice().sort(function(a, b) { return (b.closed_at || "").localeCompare(a.closed_at || ""); }).forEach(function(r) {
                var origIdx = D.reviews.indexOf(r);
                var nc = (r.entries || []).filter(function(e) { return e.decision === "non_conforme"; }).length;
                h += '<div class="app-review-row closed" data-click="openReview" data-args=\'' + _da(origIdx) + '\'>';
                h += '<div class="ct-flex-1 ct-minw-0">';
                h += '<div class="ct-strong ct-text-meta">' + esc(r.id) + ' <span class="ct-badge" data-tone="low" data-size="sm">' + t("review.cloturee") + '</span></div>';
                h += '<div class="ct-text-label ct-muted ct-mt-1">' + esc(r.closed_at) + ' &middot; ' + ((r.entries || []).length) + ' ' + t("review.entries") + (nc ? ', <span class="ct-text-critical">' + nc + ' NC</span>' : '') + '</div>';
                h += '</div>';
                h += '</div>';
            });
        }
    }
    h += '</div>';

    h += '</div>'; // end grid
    return h;
}

window.deleteReviewFromApp = function(reviewId) {
    var r = D.reviews.find(function(x) { return x.id === reviewId; });
    if (!r) return;
    if (r.status !== "en_cours") { showStatus(t("review.delete_closed"), true); return; }
    var entryIds = _entryIdsOf([r]);
    var attached = (D.measures || []).filter(function(m) {
        return m.review_entry_id && entryIds.indexOf(m.review_entry_id) >= 0;
    }).length;
    var msg = t("review.confirm_delete", { id: reviewId });
    if (attached) msg += " " + t("review.confirm_delete_measures", { m: String(attached) });
    if (!confirm(msg)) return;
    var done = function() {
        _detachMeasures(entryIds);
        D.reviews = D.reviews.filter(function(x) { return x.id !== reviewId; });
        if (_selectedReview !== null && D.reviews[_selectedReview] && D.reviews[_selectedReview].id === reviewId) _selectedReview = null;
        renderPanel();
        // No granular route carries the detaching of measures:
        // the blob has to be republished, including in the API branch.
        _save();
        showStatus(t("review.deleted"));
    };
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        AccessAPI.deleteReview(pid, reviewId).then(done)
            .catch(function(e) { showStatus(e.message || t("error"), true); });
    } else {
        done();
    }
};
function saveAppField(field: string, val: string): void { if (_selectedApp === null) return; (D.applications[_selectedApp] as Record<string, unknown>)[field] = val; _save(); } window.saveAppField = saveAppField;

var _ownerHandle: { getValue: () => string } | null = null;
var _OWNER_EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// Mount the shared user picker on the perimeter-owner slot (post-render) —
// same pattern as the user manager picker. Stores the owner's EMAIL.
function _mountOwnerPicker(): void {
    var up = window.ct_userpicker;
    if (!up || _selectedApp === null) return;
    var a = D.applications[_selectedApp]; if (!a) return;
    var cur = a.owner_email || "";
    var curSu = D.si_users.find(function(x) { return !!x.email && x.email.toLowerCase() === cur.toLowerCase(); });
    var initLabel = curSu ? ((curSu.prenom + " " + curSu.nom).trim() || curSu.email || "") : cur;
    up.mount({
        slotId: "app-owner-slot",
        pickerId: "access-app-owner",
        value: initLabel,
        placeholder: t("app.owner_search") || "Rechercher un utilisateur…",
        directoryUrl: "api/directory",
    }).then(function(handle) {
        _ownerHandle = handle;
        ["access-app-owner-search", "access-app-owner-plain"].forEach(function(eid) {
            var el = document.getElementById(eid);
            if (el) { el.addEventListener("blur", _commitOwner); el.addEventListener("change", _commitOwner); }
        });
        var wrap = document.getElementById("access-app-owner-wrap");
        if (wrap) wrap.addEventListener("click", function() { setTimeout(_commitOwner, 0); });
    });
}

// Resolve the picked label back to an email against the referential and
// persist it on owner_email. The backend rejects non-emails (422), so a
// label that resolves to nothing is refused here with a status message.
function _commitOwner(): void {
    if (_selectedApp === null || !_ownerHandle) return;
    var a = D.applications[_selectedApp]; if (!a) return;
    var label = (_ownerHandle.getValue() || "").trim();
    var su = D.si_users.find(function(x) {
        return ((x.prenom + " " + x.nom).trim() === label)
            || (!!x.email && x.email.toLowerCase() === label.toLowerCase());
    });
    var val = su ? (su.email || "") : label;
    if (val && !_OWNER_EMAIL_RE.test(val)) {
        showStatus(t("app.owner_invalid") || "Propriétaire : email introuvable", true);
        return;
    }
    if ((a.owner_email || "") === val) return;
    saveAppField("owner_email", val);
}
function saveAppRoles(val: string): void {
    if (_selectedApp === null) return;
    var roles = (val || "").split(/[\n,]/).map(function(r) { return r.trim(); }).filter(function(r) { return !!r; });
    D.applications[_selectedApp].roles = roles;
    _save();
} window.saveAppRoles = saveAppRoles;
function addAppReviewer(uid: string): void {
    if (!uid || _selectedApp === null) return;
    var a = D.applications[_selectedApp];
    if (!a.reviewers) a.reviewers = [];
    if (a.reviewers.indexOf(uid) < 0) a.reviewers.push(uid);
    renderPanel(); _save();
} window.addAppReviewer = addAppReviewer;
function removeAppReviewer(uid: string): void {
    if (_selectedApp === null) return;
    var a = D.applications[_selectedApp];
    a.reviewers = (a.reviewers || []).filter(function(id) { return id !== uid; });
    renderPanel(); _save();
} window.removeAppReviewer = removeAppReviewer;
function importAppsCsv(): void {
    var el = document.getElementById("csv-import-input") as HTMLInputElement; if (!el) return;
    el.value = "";
    el.onchange = function() {
        if (!el.files || !el.files[0]) return;
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (!pid || !window.AccessAPI) return;
        AccessAPI.importAppsCsv(pid, el.files[0]).then(function(result) {
            showStatus(t("app.csv_imported", { count: result.imported }));
            _reloadProjectData();
        }).catch(function(e) { showStatus(e.message, true); });
    };
    el.click();
} window.importAppsCsv = importAppsCsv;

function syncAppsFromAsset(): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) return;
    showStatus(t("app.syncing"));
    AccessAPI.syncAppsFromAsset(pid).then(function(result) {
        showStatus(t("app.sync_done", { count: result.imported, total: result.total_assets_found || 0 }));
        _reloadProjectData();
    }).catch(function(e) { showStatus(e.message, true); });
} window.syncAppsFromAsset = syncAppsFromAsset;

// ═══════════════════════════════════════════════════════════════
// REVIEWS
// ═══════════════════════════════════════════════════════════════
// Perimeters overdue for a review = no active review AND (never reviewed OR
// last closed review older than the configured frequency). Same rule as the
// dashboard's "overdue" card.
function _appsToStart(): AccessApplication[] {
    var out: AccessApplication[] = [];
    D.applications.forEach(function(app) {
        var hasActive = D.reviews.some(function(r) { return r.application_id === app.id && r.status === "en_cours"; });
        if (hasActive) return;
        var lastClosed = D.reviews
            .filter(function(r) { return r.application_id === app.id && r.status === "cloturee" && r.closed_at; })
            .sort(function(a, b) { return (b.closed_at || "").localeCompare(a.closed_at || ""); })[0];
        if (_isReviewOverdue(app, lastClosed ? lastClosed.closed_at! : null)) out.push(app);
    });
    return out;
}

function renderReviewList(): string {
    var h = '<h2>' + t("nav.reviews") + '</h2>';
    var active = D.reviews.filter(function(r) { return r.status === "en_cours"; });
    var closed = D.reviews.filter(function(r) { return r.status === "cloturee"; });
    var toStart = _appsToStart();

    // Default view: in-progress + overdue-to-start; closed hidden until asked.
    if (!_reviewListFilter) _reviewListFilter = { en_cours: true, a_demarrer: true, closed: false };
    var f = _reviewListFilter;

    var chip = function(key: string, label: string, n: number): string {
        return '<button class="review-filter-chip' + (f[key] ? ' active' : '') + '" data-click="_toggleReviewListFilter" data-args=\'' + _da(key) + '\'>'
            + esc(label) + ' <span class="review-filter-count">' + n + '</span></button>';
    };
    h += '<div class="review-filter-bar">';
    h += chip("en_cours", t("review.f_active") || "En cours", active.length);
    h += chip("a_demarrer", t("review.f_to_start") || "À démarrer", toStart.length);
    h += chip("closed", t("review.f_closed") || "Clôturées", closed.length);
    h += '</div>';

    if (f.a_demarrer && toStart.length) {
        h += '<h3 style="font-size:var(--ct-text-data);margin:var(--ct-s3) 0 var(--ct-s2);color:var(--ct-critical)">' + (t("review.to_start") || "À démarrer (échéance dépassée)") + '</h3>';
        toStart.forEach(function(app) {
            h += '<div class="ct-groupe-card ct-flex ct-items-center ct-gap-2">';
            h += '<div class="ct-flex-1 ct-minw-0"><strong>' + esc(app.nom || app.id) + '</strong> <span class="ct-badge" data-tone="info">' + esc(_freqLabel(app.frequence_revue)) + '</span></div>';
            h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-size="xs" data-click="startReview" data-args=\'' + _da(app.id) + '\' data-stop>' + t("review.start") + '</button>';
            h += '</div>';
        });
    }

    if (f.en_cours && active.length) {
        h += '<h3 style="font-size:var(--ct-text-data);margin:var(--ct-s3) 0 var(--ct-s2)">' + t("review.active") + '</h3>';
        active.forEach(function(r, idx) {
            var origIdx = D.reviews.indexOf(r);
            var app = _findApp(r.application_id);
            var total = (r.entries || []).length, decided = (r.entries || []).filter(function(e) { return e.decision !== "pending"; }).length;
            h += '<div class="ct-groupe-card ct-userpicker" data-click="openReview" data-args=\'' + _da(origIdx) + '\'>';
            h += '<button class="app-review-del" style="position:absolute;top:8px;right:8px" title="Supprimer cette revue" data-click="deleteReviewFromApp" data-args=\'' + _da(r.id) + '\' data-stop>' + _icon("trash", 14) + '</button>';
            h += '<div class="ct-flex ct-items-center ct-gap-2"><strong>' + esc(app ? app.nom : r.application_id) + '</strong> <span class="ct-badge" data-tone="info">' + t("review.en_cours") + '</span></div>';
            h += '<div class="ct-text-label ct-muted ct-mt-1">' + t("review.started") + ' ' + esc(r.started_at) + ' — ' + decided + '/' + total + ' ' + t("review.decided") + '</div>';
            if (total) { h += '<div class="progress-bar"><div class="progress-bar-fill" style="width:' + Math.round(decided / total * 100) + '%"></div></div>'; }
            h += '</div>';
        });
    }

    if (f.closed && closed.length) {
        h += '<h3 style="font-size:var(--ct-text-data);margin:var(--ct-s4) 0 var(--ct-s2)">' + t("review.history") + '</h3>';
        closed.forEach(function(r) {
            var origIdx = D.reviews.indexOf(r);
            var app = _findApp(r.application_id);
            var nc = (r.entries || []).filter(function(e) { return e.decision === "non_conforme"; }).length;
            h += '<div class="ct-groupe-card" style="opacity:0.8" data-click="openReview" data-args=\'' + _da(origIdx) + '\'>';
            h += '<div class="ct-flex ct-items-center ct-gap-2"><strong>' + esc(app ? app.nom : r.application_id) + '</strong> <span class="ct-badge" data-tone="low">' + t("review.cloturee") + '</span></div>';
            h += '<div class="ct-text-label ct-muted ct-mt-1">' + esc(r.closed_at) + ' — ' + (r.entries || []).length + ' ' + t("review.entries") + (nc ? ', ' + nc + ' NC' : '') + '</div>';
            h += '</div>';
        });
    }

    var shownAny = (f.en_cours && active.length) || (f.a_demarrer && toStart.length) || (f.closed && closed.length);
    if (!shownAny) h += '<div class="ct-empty-state">' + t("review.empty") + '</div>';
    return h;
}
window._toggleReviewListFilter = function(key: string) {
    if (!_reviewListFilter) _reviewListFilter = { en_cours: true, a_demarrer: true, closed: false };
    _reviewListFilter[key] = !_reviewListFilter[key];
    renderPanel();
};
function openReview(i: number | string): void {
    // Opened from a perimeter page? remember it so we return there on exit.
    var fromApp = (_panel === "apps" && _selectedApp !== null);
    _reviewReturn = fromApp ? { app: _selectedApp! } : null;
    _selectedReview = parseInt(i as string);
    _panel = "reviews";
    _selectedApp = null;
    _selectedUser = null;
    _reviewFilters = null;  // reset filters when switching to a different review
    _updateSidebarAccordion(fromApp ? "apps" : "reviews");
    renderPanel();
} window.openReview = openReview;
function backToReviews(): void {
    _selectedReview = null; _reviewFilters = null;
    if (_reviewReturn) { _selectedApp = _reviewReturn.app; _reviewReturn = null; _panel = "apps"; _updateSidebarAccordion("apps"); }
    renderPanel();
} window.backToReviews = backToReviews;

function startReview(appId: string): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        AccessAPI.createReview(pid, { application_id: appId }).then(function(rev) {
            D.reviews.push(rev); _panel = "reviews"; _selectedReview = D.reviews.length - 1; renderPanel();
        }).catch(function(e) { showStatus(e.message, true); });
    } else {
        D.reviews.push({ id: _genId("REV-", D.reviews), application_id: appId, status: "en_cours", started_at: _today(), closed_at: "", closed_by: "", entries: [] });
        _panel = "reviews"; _selectedReview = D.reviews.length - 1; renderPanel(); _save();
    }
} window.startReview = startReview;

var _ADMIN_KEYWORDS = /(^|[\s,;_\-/.()\[\]])(admin|admins|administrator|administrators|administrateur|root|sudoers|wheel|manager|gestionnaire|domain admins|enterprise admins|schema admins|account operators|backup operators|privileged|priv)([\s,;_\-/.()\[\]]|$)/i;

function _hasAdminRights(e: AccessReviewEntry): boolean {
    var blob = (e.roles || "") + " " + (e.groups || "");
    return _ADMIN_KEYWORDS.test(blob);
}

function _highlightAdminTerms(text: string | undefined): string {
    if (!text) return "-";
    return esc(text).replace(/(admin\w*|administrator\w*|administrateur\w*|root|sudoers|wheel|manager\w*|gestionnaire\w*|privileged|priv|backup operators|account operators|domain admins|enterprise admins|schema admins)/gi, '<mark class="admin-term">$1</mark>');
}

// Return an array of warning labels for a review entry.
// Each warning has a code, a short label, and a tooltip explaining why it's flagged.
function _findServiceAccount(identifier: string | null | undefined): AccessServiceAccount | null {
    if (!identifier) return null;
    var key = identifier.toLowerCase().trim();
    return (D.service_accounts || []).find(function(sa) {
        return (sa.identifier && sa.identifier.toLowerCase().trim() === key)
            || (sa.name && sa.name.toLowerCase().trim() === key);
    }) || null;
}

function _getEntryWarnings(e: AccessReviewEntry, su: AccessSiUser | undefined): AccessEntryWarning[] {
    var warnings: AccessEntryWarning[] = [];
    if (_hasAdminRights(e)) {
        warnings.push({ code: "admin", label: "ADMIN", title: "Compte avec droits d'administration (admin/root/manager detecte dans les groupes ou roles)" });
    }
    // Service account declared → no need to flag it as "personnel orphan".
    // Tag it with a neutral badge showing it's a recognised service account.
    var sa = _findServiceAccount(e.email_or_login);
    if (sa) {
        warnings.push({ code: "service", label: "COMPTE SERVICE", title: "Compte de service declare (" + (sa.name || sa.identifier) + ")" });
    }
    if (su) {
        var statut = (su.statut || "").toLowerCase();
        if (statut === "ancien") {
            warnings.push({ code: "ancien", label: "ANCIEN", title: "Ancien collaborateur (statut=ancien) — le compte aurait du etre supprime" });
        }
        if (statut === "prestataire") {
            warnings.push({ code: "externe", label: "EXTERNE", title: "Prestataire externe — duree limitee a verifier" });
        }
        if (su.mfa_active === false) {
            warnings.push({ code: "nomfa", label: "NO MFA", title: "MFA non active dans l'annuaire" });
        }
        if (su.sensibilisation === false) {
            warnings.push({ code: "nosensi", label: "NO SENSI", title: "Sensibilisation a la securite non signee" });
        }
        if (su.politique_validee === false) {
            warnings.push({ code: "nopol", label: "NO POL", title: "Politique de securite non validee" });
        }
    } else if (e.email_or_login && !sa) {
        // No HR match AND not a declared service account → real orphan
        warnings.push({ code: "orphan", label: "ORPHELIN", title: "Compte non trouve dans l'annuaire RH — verifier sa legitimite" });
    }
    return warnings;
}

function renderReviewDetail(): string {
    var r = D.reviews[_selectedReview!]; if (!r) return renderReviewList();
    var app = _findApp(r.application_id);
    var isClosed = r.status === "cloturee";
    var entries = r.entries || [];
    var decided = entries.filter(function(e) { return e.decision !== "pending"; }).length;
    var nc = entries.filter(function(e) { return e.decision === "non_conforme"; }).length;
    var warnedCount = entries.filter(function(e) {
        var su = _resolveEntryUser(e);
        return _getEntryWarnings(e, su).length > 0;
    }).length;

    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToReviews">&laquo; ' + (_reviewReturn ? esc(app ? app.nom : t("nav.apps")) : t("nav.reviews")) + '</button>';
    h += '<h2 class="ct-m-0">' + esc(app ? app.nom : r.application_id) + '</h2>';
    h += '<span class="ct-badge" data-tone="' + _accessTone(r.status) + '">' + tEsc("review." + r.status) + '</span>';
    h += '<span class="ct-flex-1"></span>';
    if (!isClosed) {
        // Auto-import button — visible only when a connector is linked
        // to this application. Picks the enabled plugin (or first) server-side.
        var linkedPlugins = (_pluginList || []).filter(function(p) { return p.application_id === r.application_id; });
        if (linkedPlugins.length) {
            var enabled = linkedPlugins.filter(function(p) { return p.enabled; });
            var pluginToUse = enabled[0] || linkedPlugins[0];
            var plgLabel = pluginToUse.label || pluginToUse.plugin_type;
            h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="importReviewFromConnector" title="' + esc((t("review.import_connector_tooltip") || "Importer depuis") + " " + plgLabel) + '">'
              + (t("review.import_connector") || "Import connecteur") + ' &#x2699;</button>';
        }
        h += '<button class="ct-btn mt-8" data-write data-click="importReviewCsv">' + t("review.import_csv") + '</button>';
        h += '<a href="javascript:void(0)" class="access-link" data-click="downloadCsvTemplate" style="font-size:var(--ct-text-label);margin-left:var(--ct-s2);text-decoration:underline;align-self:center">' + t("review.csv_template") + '</a>';
        if (entries.length && decided === entries.length) h += '<button class="ct-btn mt-8 ct-ml-1" data-write data-variant="primary" data-click="closeReview">' + t("review.close") + '</button>';
    }
    if (isClosed) h += '<a href="' + esc(AccessAPI.exportReview(getActiveProjectId(), r.id)) + '" class="ct-btn mt-8 ct-no-underline ct-ml-1" data-write data-variant="primary">' + t("review.export") + '</a>';
    h += '</div>';

    h += '<div class="review-summary">';
    h += '<span>' + t("review.started") + ': ' + esc(r.started_at) + '</span>';
    if (isClosed) h += '<span>' + t("review.closed_at") + ': ' + esc(r.closed_at) + ' (' + esc(r.closed_by) + ')</span>';
    h += '<span class="count">' + decided + '/' + entries.length + ' ' + t("review.decided") + '</span>';
    if (nc) h += '<span class="ct-text-critical count">' + nc + ' NC</span>';
    if (warnedCount) h += '<span class="count admin-count" title="Entrees avec au moins une alerte (admin, ancien collaborateur, MFA inactif, etc.)">&#9888; ' + warnedCount + ' alerte' + (warnedCount > 1 ? 's' : '') + '</span>';
    h += '</div>';

    if (!entries.length) {
        h += '<div class="ct-empty-state">' + t("review.no_entries") + '</div>';
        return h;
    }

    // Build enriched rows once (si_user lookup, warnings, last login)
    var now = Date.now();
    var enriched = entries.map(function(e, idx) {
        var su = _resolveEntryUser(e);
        var warnings = _getEntryWarnings(e, su);
        // Prefer the value stored on the review entry (populated at
        // import time, survives SiUser deletion). Fall back to the
        // matched SiUser for legacy entries that predate the column.
        var lastLogin = (e && e.last_login_at) ? e.last_login_at
                        : (su && su.last_login_at ? su.last_login_at : "");
        var daysSince: number | null = null;
        if (lastLogin) {
            var d = new Date(lastLogin);
            if (!isNaN(d.getTime())) daysSince = Math.floor((now - d.getTime()) / 86400000);
        }
        return {
            entry: e, idx: idx, su: su,
            suName: su ? (su.prenom + " " + su.nom).trim() : "",
            warnings: warnings,
            isAdmin: warnings.some(function(w) { return w.code === "admin"; }),
            isCritical: warnings.some(function(w) { return w.code === "ancien" || w.code === "orphan"; }),
            lastLogin: lastLogin,
            daysSince: daysSince  // null = never logged or no data
        };
    });

    // Pre-compute counts for each filter so badges show the number
    var nAdmin = enriched.filter(function(x) { return x.isAdmin; }).length;
    var nStale90 = enriched.filter(function(x) { return x.daysSince !== null && x.daysSince > 90; }).length;
    var nNeverLogged = enriched.filter(function(x) { return x.daysSince === null; }).length;
    var nAlerts = enriched.filter(function(x) { return x.warnings.length > 0; }).length;
    var nPending = enriched.filter(function(x) { return x.entry.decision === "pending"; }).length;

    if (!_reviewFilters) _reviewFilters = { admin: false, stale90: false, never_logged: false, alerts: false, pending: false };

    // Filter pills — toggle via data-click
    var pill = function(key: string, label: string, count: number, color?: string): string {
        var active = !!_reviewFilters![key];
        var bg = active ? (color || "var(--ct-info)") : "var(--ct-surface-2)";
        var border = active ? bg : "var(--ct-line)";
        return '<button class="review-pill' + (active ? " active" : "") + '" data-click="_toggleReviewFilter" data-args=\'' + _da(key) + '\' style="background:' + bg + ';border:1px solid ' + border + ';padding:3px 10px;border-radius:14px;font-size:var(--ct-text-label);cursor:pointer;white-space:nowrap">'
            + esc(label) + ' <strong style="opacity:0.85">' + count + '</strong></button>';
    };
    h += '<div style="display:flex;gap:var(--ct-s1);flex-wrap:wrap;margin:var(--ct-s2) 0 var(--ct-s3);align-items:center">';
    h += '<span style="font-size:var(--ct-text-label);color:var(--ct-ink-2);margin-right:var(--ct-s1)">' + (t("review.filter_label") || "Filtres :") + '</span>';
    h += pill("admin",        t("review.filter_admin")        || "Droits admin",                nAdmin,       "var(--ct-critical)");
    h += pill("stale90",      t("review.filter_stale")        || "Derniere connexion > 90 j",   nStale90,     "var(--ct-medium)");
    h += pill("never_logged", t("review.filter_never")        || "Jamais connecte / inconnu",   nNeverLogged, "var(--ct-ink-2)");
    h += pill("alerts",       t("review.filter_alerts")       || "Avec alertes",                nAlerts,      "#b45309");
    if (!isClosed) h += pill("pending", t("review.filter_pending") || "En attente de decision", nPending, "var(--ct-ink-2)");
    var anyActive = Object.keys(_reviewFilters).some(function(k) { return _reviewFilters![k]; });
    if (anyActive) {
        h += '<button data-click="_clearReviewFilters" style="background:transparent;border:none;color:var(--ct-ink-2);font-size:var(--ct-text-label);cursor:pointer;text-decoration:underline;padding:var(--ct-s1) var(--ct-s1)">'
          + (t("review.filter_clear") || "Reinitialiser") + '</button>';
    }
    h += '</div>';

    // Apply filters
    var visible = enriched.filter(function(x) {
        if (_reviewFilters!.admin         && !x.isAdmin)                 return false;
        if (_reviewFilters!.stale90       && !(x.daysSince !== null && x.daysSince > 90)) return false;
        if (_reviewFilters!.never_logged  && x.daysSince !== null)       return false;
        if (_reviewFilters!.alerts        && !x.warnings.length)         return false;
        if (_reviewFilters!.pending       && x.entry.decision !== "pending") return false;
        return true;
    });

    if (!visible.length) {
        h += '<div class="ct-empty-state">' + (t("review.no_matches") || "Aucune entree ne correspond aux filtres actifs.") + '</div>';
        return h;
    }
    if (visible.length !== entries.length) {
        h += '<div class="ct-text-label ct-muted ct-mb-2">' + visible.length + ' / ' + entries.length + ' ' + (t("review.entries_filtered") || "entrees affichees") + '</div>';
    }

    h += '<table><thead><tr><th class="ct-w-60">#</th><th>' + t("review.type_compte") + '</th><th>' + t("review.email_login") + '</th><th>' + (t("review.name") || "Nom Prénom") + '</th><th>' + t("review.matched_user") + '</th><th>' + t("review.roles") + '</th><th>' + t("review.groups") + '</th><th class="ct-w-140">' + (t("user.last_login") || "Derniere connexion") + '</th><th class="ct-w-90">' + (t("user.account_enabled") || "Compte") + '</th><th class="ct-w-160">' + t("review.decision_label") + '</th></tr></thead><tbody>';

    visible.forEach(function(x) {
        var e = x.entry, su = x.su, warnings = x.warnings;
        var rowCls = "entry-row";
        if (x.isCritical) rowCls += " critical-flag";
        else if (warnings.length) rowCls += " admin-flag";
        h += '<tr class="' + rowCls + '">';
        h += '<td class="ct-text-label ct-muted">' + (x.idx + 1) + '</td>';
        h += '<td class="ct-text-label">' + esc(e.type_compte) + '</td>';
        h += '<td class="ct-text-meta ct-strong">';
        warnings.forEach(function(w) {
            h += '<span class="ct-badge warn-badge" data-fill data-tone="' + _accessTone(w.code) + '" title="' + esc(w.title) + '">&#9888; ' + esc(w.label) + '</span> ';
        });
        h += esc(e.email_or_login) + '</td>';
        // Connector-provided identity (shown even for orphans). Falls back to
        // the matched SI user's name when the connector didn't supply one.
        var _nom = e.nom || (su && su.nom) || "";
        var _prenom = e.prenom || (su && su.prenom) || "";
        var _full = ((_prenom + " " + _nom).trim());
        h += '<td class="ct-text-label">' + (_full ? esc(_full) : '<span class="ct-muted">—</span>') + '</td>';
        h += '<td class="ct-text-label">' + (x.suName ? esc(x.suName) : '<span class="ct-muted">—</span>') + '</td>';
        h += '<td class="ct-text-label">' + (x.isAdmin ? _highlightAdminTerms(e.roles || "-") : esc(e.roles || "-")) + '</td>';
        h += '<td class="ct-text-label">' + (x.isAdmin ? _highlightAdminTerms(e.groups || "-") : esc(e.groups || "-")) + '</td>';
        // Last login cell
        if (x.lastLogin) {
            var color = x.daysSince !== null && x.daysSince > 90 ? "var(--ct-critical)" : (x.daysSince !== null && x.daysSince > 30 ? "var(--ct-medium)" : "");
            var dateStr = x.lastLogin.slice(0, 10);
            h += '<td style="font-size:var(--ct-text-label)' + (color ? ";color:" + color : "") + '" title="' + esc(x.lastLogin) + (x.daysSince !== null ? " (il y a " + x.daysSince + " j)" : "") + '">' + esc(dateStr) + '</td>';
        } else {
            h += '<td class="ct-text-label ct-muted">—</td>';
        }
        // Account active/disabled cell — prefer the entry value, fall back to SiUser.
        var acctEnabled = (e && e.account_enabled !== undefined && e.account_enabled !== null) ? e.account_enabled
                          : (su && su.account_enabled !== undefined ? su.account_enabled : null);
        h += '<td>' + _accountTag(acctEnabled) + '</td>';
        h += '<td class="ct-text-meta">';
        if (isClosed) {
            // Closed review: the decision is a statement of fact, not a control.
            h += '<span class="ct-badge" data-tone="' + (e.decision === "conforme" ? "low" : e.decision === "non_conforme" ? "critical" : "neutral") + '">' + esc(_decisionLabel(e.decision)) + '</span>';
        } else {
            // .ct-choice: the state goes through aria-pressed (announced by screen
            // readers) and the color through data-tone, on the selected option only.
            h += '<div class="ct-choice" data-size="xs">';
            h += '<button type="button" data-tone="low" aria-pressed="' + (e.decision === "conforme") + '" data-click="setDecision" data-args=\'' + _da(x.idx, "conforme") + '\'>✓</button> ';
            h += '<button type="button" data-tone="critical" aria-pressed="' + (e.decision === "non_conforme") + '" data-click="setDecision" data-args=\'' + _da(x.idx, "non_conforme") + '\'>✗</button>';
            h += '</div>';
        }
        h += '</td></tr>';
    });
    h += '</tbody></table>';
    return h;
}

var _reviewFilters: Record<string, boolean> | null = null;

window._toggleReviewFilter = function(key) {
    if (!_reviewFilters) _reviewFilters = {};
    _reviewFilters[key] = !_reviewFilters[key];
    renderPanel();
};

window._clearReviewFilters = function() {
    _reviewFilters = null;
    renderPanel();
};

function setDecision(idx: number | string, decision: AccessDecision): void {
    if (_selectedReview === null) return;
    var r = D.reviews[_selectedReview]; if (!r || r.status !== "en_cours") return;
    var entry = (r.entries || [])[parseInt(idx as string)]; if (!entry) return;
    var oldDecision = entry.decision;
    var isNewNonConforme = decision === "non_conforme"
        && oldDecision !== "non_conforme"
        && !D.measures.some(function(m) { return m.review_entry_id === entry.id; });

    if (isNewNonConforme && window.ct_measure_modal) {
        // Open the unified measure modal BEFORE persisting the decision.
        // - On save : patch entry + POST measure
        // - On cancel : do nothing (decision stays pending)
        _openNonConformeMeasureModal(r, entry, idx);
        return;
    }

    _applyDecision(r, entry, idx, decision);
} window.setDecision = setDecision;

function _applyDecision(r: AccessReview, entry: AccessReviewEntry, idx: number | string, decision: AccessDecision): void {
    entry.decision = decision;
    entry.decided_at = _today();
    entry.decided_by = (window._currentUser && window._currentUser.name) || "";

    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        AccessAPI.patchEntry(pid, r.id, entry.id, {
            decision: decision, decided_by: entry.decided_by, decided_at: entry.decided_at
        }).then(function() {
            _reloadProjectData();
        }).catch(function(e) { console.error("Patch entry failed:", e); });
    } else {
        _save();
    }
    renderPanel();
}

function _openNonConformeMeasureModal(r: AccessReview, entry: AccessReviewEntry, idx: number | string): void {
    var app = _findApp(r.application_id);
    var appName = app ? app.nom : r.application_id;
    var accountName = entry.email_or_login || entry.id;
    var prefilledTitle = "Correction non conformité habilitation " + accountName
        + " sur application " + appName;

    ct_measure_modal.open(
        { id: "", title: prefilledTitle, description: "", statut: "a_faire", responsable: "", echeance: "" },
        {
            title: t("measure.add") || "Nouvelle action",
            hideFields: ["type"],
            statusOptions: [
                { value: "a_faire",  label: t("measure.s.a_faire")  || "À faire" },
                { value: "en_cours", label: t("measure.s.en_cours") || "En cours" },
                { value: "termine",  label: t("measure.s.termine")  || "Terminé" }
            ],
            defaultStatus: "a_faire",
            ownerPicker: { pickerId: "access-nc-measure-owner", directoryUrl: "api/directory" }
        }
    ).then(function(result) {
        if (!result) return;  // cancel → keep decision pending

        // 1. Apply the decision (patch entry)
        entry.decision = "non_conforme";
        entry.decided_at = _today();
        entry.decided_by = (window._currentUser && window._currentUser.name) || "";
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;

        var patchPromise: Promise<unknown> = (pid && window.AccessAPI)
            ? AccessAPI.patchEntry(pid, r.id, entry.id, {
                decision: "non_conforme",
                decided_by: entry.decided_by,
                decided_at: entry.decided_at
              })
            : Promise.resolve();

        // 2. Create the measure with the edited values, linked to the entry
        var measurePayload: AccessMeasure = {
            id: _genId("MES-", D.measures),
            review_entry_id: entry.id,
            title: (result.title || prefilledTitle).trim(),
            description: result.description || "",
            statut: result.statut || "a_faire",
            responsable: result.responsable || "",
            echeance: result.echeance || ""
        };

        patchPromise.then(function() {
            if (pid && window.AccessAPI && (AccessAPI as Partial<AccessApi>).createMeasure) {
                return AccessAPI.createMeasure(pid, measurePayload);
            }
            D.measures.push(measurePayload);
            return null;
        }).then(function() {
            // Reload to get freshly-assigned server IDs and any cascades
            if (pid && window.AccessAPI) {
                return AccessAPI.get(pid).then(function(p) {
                    var d = typeof p.data === "string" ? JSON.parse(p.data) : (p.data || {});
                    Object.keys(D).forEach(function(k) { delete (D as Record<string, unknown>)[k]; });
                    Object.assign(D, d);
                });
            }
            _save();
        }).then(function() {
            showStatus(t("review.measure_created") || "Mesure de correction créée");
            renderPanel();
        }).catch(function(e) {
            showStatus((t("review.measure_create_fail") || "Erreur : ") + (e.message || e), true);
        });
    });
}

function importReviewCsv(): void {
    if (_selectedReview === null) return;
    var el = document.getElementById("csv-import-input") as HTMLInputElement; if (!el) return;
    el.value = "";
    el.onchange = function() { if (el.files && el.files[0]) _doImportCsv(el.files[0]); };
    el.click();
} window.importReviewCsv = importReviewCsv;

function downloadCsvTemplate(): void {
    var header = "type_compte;email;roles;groups";
    var example = "personnel;jean.dupont@example.com;Admin,Lecteur;Direction,Finance\n"
        + "personnel;marie.martin@example.com;Lecteur;RH\n"
        + "service;svc-backup@local;;Batch";
    var csv = header + "\n" + example + "\n";
    var blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "modele_revue_droits.csv";
    link.click();
    URL.revokeObjectURL(link.href);
} window.downloadCsvTemplate = downloadCsvTemplate;

function _doImportCsv(file: File): void {
    var r = D.reviews[_selectedReview!]; if (!r) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        AccessAPI.importCsv(pid, r.id, file).then(function(result) {
            showStatus(t("review.csv_imported", { count: result.imported, matched: result.matched!, unmatched: result.unmatched! }));
            _reloadProjectData();
        }).catch(function(e) { showStatus(e.message, true); });
    }
}

// Triggers a connector sync scoped to the current review's application
// and populates the review entries in one shot. The backend resolves
// which plugin to use (first enabled, or first linked).
var _importReviewInFlight = false;

// Shared handling of a connector import result (API or file-based).
function _onConnectorImportResult(result: AccessConnectorImportResult): void {
    var base = t("review.import_connector_ok") ||
               "Import connecteur : {imported} entrée(s) ({matched} rattaché(s), {unmatched} sans correspondance, {duplicates} ignoré(s), {disabled} désactivé(s) retiré(s))";
    var msg = base
        .replace("{imported}", String(result.imported))
        .replace("{matched}", String(result.matched))
        .replace("{unmatched}", String(result.unmatched))
        .replace("{duplicates}", String(result.skipped_duplicates))
        .replace("{disabled}", String(result.removed_disabled || 0));
    showStatus(msg);
    if (result.connector_errors_count && result.connector_errors_count > 0) {
        showStatus(result.connector_errors_count + " erreur(s) connecteur — voir les logs serveur", true);
    }
    _reloadProjectData();
}

// Resolve which linked connector the import button targets (same rule as
// the backend: prefer an enabled plugin, else the first linked one).
function _reviewConnector(applicationId: string): AccessPlugin | null {
    var linked = (_pluginList || []).filter(function(p) { return p.application_id === applicationId; });
    if (!linked.length) return null;
    var enabled = linked.filter(function(p) { return p.enabled; });
    return enabled[0] || linked[0];
}

window.importReviewFromConnector = function() {
    if (_importReviewInFlight) return;
    if (_selectedReview === null) return;
    var r = D.reviews[_selectedReview]; if (!r) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) { showStatus("Backend not available", true); return; }

    var pc = _reviewConnector(r.application_id);
    if (pc && pc.accepts_file) { _importReviewFromConnectorFile(pid, r.id, pc); return; }

    _ctConfirm(
        t("review.import_connector_confirm_title") || "Importer depuis le connecteur",
        t("review.import_connector_confirm_body") || "La synchronisation peut prendre quelques secondes. Continuer ?",
        function() {
            _importReviewInFlight = true;
            showStatus(t("review.import_connector_running") || "Synchronisation en cours...");
            AccessAPI.importReviewFromConnector(pid!, r.id).then(_onConnectorImportResult).catch(function(e) {
                showStatus((t("review.import_connector_fail") || "Erreur import : ") + (e.message || e), true);
            }).finally(function() { _importReviewInFlight = false; });
        }
    );
};

// File-based connector: prompt for the export file, then upload it with
// the import request (the file is parsed in-request, never stored).
function _importReviewFromConnectorFile(pid: string, rid: string, pc: AccessPlugin): void {
    var el = document.getElementById("connector-file-input") as HTMLInputElement; if (!el) return;
    el.value = "";
    el.onchange = function() {
        var file = el.files && el.files[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) { showStatus(t("plg.file_too_large"), true); return; }
        _importReviewInFlight = true;
        showStatus(t("review.import_connector_running") || "Synchronisation en cours...");
        AccessAPI.importReviewFromConnectorFile(pid, rid, file, pc.id).then(_onConnectorImportResult).catch(function(e) {
            showStatus((t("review.import_connector_fail") || "Erreur import : ") + (e.message || e), true);
        }).finally(function() { _importReviewInFlight = false; });
    };
    showStatus(t("review.import_connector_pick_file") || "Sélectionnez le fichier d'export à importer");
    el.click();
}

function closeReview(): void {
    if (_selectedReview === null) return;
    var r = D.reviews[_selectedReview]; if (!r) return;
    var pending = (r.entries || []).filter(function(e) { return e.decision === "pending"; });
    if (pending.length) { showStatus(t("review.pending_remain", { count: pending.length }), true); return; }
    _ctConfirm(t("review.confirm_close"), t("review.confirm_close_body"), function() {
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (pid && window.AccessAPI) {
            AccessAPI.closeReview(pid, r.id).then(function() {
                _reloadProjectData(function() {
                    _selectedReview = null;
                    _reviewFilters = null;
                    if (_reviewReturn) { _selectedApp = _reviewReturn.app; _reviewReturn = null; _panel = "apps"; }
                    else { _panel = "reviews"; }
                });
                showStatus(t("review.closed_ok"));
            }).catch(function(e) { showStatus(e.message, true); });
        } else {
            r.status = "cloturee"; r.closed_at = _today(); r.closed_by = ""; _save();
            _selectedReview = null; renderPanel(); showStatus(t("review.closed_ok"));
        }
    }, t("review.confirm_close_btn") || "Valider", t("btn_cancel") || "Annuler");
} window.closeReview = closeReview;

// ═══════════════════════════════════════════════════════════════
// SERVICE ACCOUNTS
// ═══════════════════════════════════════════════════════════════
var _ROT_DAYS: Record<string, number> = { "30d": 30, "60d": 60, "90d": 90, "180d": 180, "365d": 365, "540d": 540, "730d": 730 };
function _isRotationOverdue(sa: AccessServiceAccount): boolean {
    // FEAT-42: an account with no secret has nothing to rotate.
    if (sa.secret_storage === "none") return false;
    var days = _ROT_DAYS[sa.rotation_policy]; if (!days) return false;
    if (!sa.last_rotation) return true;
    try { return (Date.now() - new Date(sa.last_rotation).getTime()) / 86400000 > days; } catch (e) { return false; }
}
function _countRotationOverdue(): number { return (D.service_accounts || []).filter(_isRotationOverdue).length; }
// FEAT-42 — days until date_expiration (negative = expired), null when unset.
// Date-only arithmetic (UTC midnight vs UTC midnight) so the FE agrees with
// the backend's date.fromisoformat comparison on the expiry day itself.
function _expiryDaysLeft(sa: AccessServiceAccount): number | null {
    if (!sa.date_expiration) return null;
    try {
        var ms = new Date(sa.date_expiration + "T00:00:00Z").getTime();
        if (isNaN(ms)) return null;
        var todayMs = new Date(new Date().toISOString().slice(0, 10) + "T00:00:00Z").getTime();
        return Math.round((ms - todayMs) / 86400000);
    } catch (e) { return null; }
}
function _expiryBadge(sa: AccessServiceAccount): string {
    var left = _expiryDaysLeft(sa);
    if (left === null) return "";
    if (left < 0) return ' <span class="ct-badge" data-tone="critical" data-size="sm">' + t("svc.expired") + '</span>';
    if (left <= 30) return ' <span class="ct-badge" data-tone="high" data-size="sm">' + t("svc.expires_soon", { days: String(left) }) + '</span>';
    return "";
}
function _countExpiringSoon(): number {
    return (D.service_accounts || []).filter(function(sa) {
        var left = _expiryDaysLeft(sa); return left !== null && left <= 30;
    }).length;
}
function _riskColor(r: string): string { return ({ critical: "var(--ct-critical)", high: "var(--ct-high)", medium: "var(--ct-medium)", low: "var(--ct-low)" } as Record<string, string>)[r] || "var(--ct-neutral)"; }
function _storageLabel(s: string): string { return t("svc.storage." + s) || s; }
function _rotationLabel(r: string): string { return t("svc.rotation." + r) || r; }
function _riskLabel(r: string): string { return t("svc.risk." + r) || r; }
function _platformLabel(p: string): string { return t("svc.platform." + p) || p; }

function renderSAList(): string {
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("svc.title") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="addServiceAccount">' + t("svc.add") + '</button></div>';
    if (!(D.service_accounts || []).length) { h += '<div class="ct-empty-state">' + t("svc.empty") + '</div>'; return h; }
    // BUG-26: without .ct-table the global `th,td` rule applies
    // (text-align:left + vertical-align:top) — badges and the delete button
    // sat at odd corners. .ct-table brings the shared middle alignment.
    h += '<table class="ct-table"><thead><tr><th>' + t("svc.name") + '</th><th>' + t("svc.identifier") + '</th><th>' + t("svc.platform") + '</th><th>' + t("svc.application") + '</th><th>' + t("svc.secret_storage") + '</th><th>' + t("svc.rotation_policy") + '</th><th>' + t("svc.date_expiration") + '</th><th>' + t("svc.risk_level") + '</th><th></th></tr></thead><tbody>';
    D.service_accounts.forEach(function(sa, i) {
        var app = _findApp(sa.application_id);
        var overdue = _isRotationOverdue(sa);
        h += '<tr class="ct-clickable" data-click="openSA" data-args=\'' + _da(i) + '\'>';
        h += '<td class="ct-strong">' + esc(sa.name || "-") + '</td>';
        h += '<td class="ct-text-meta">' + esc(sa.identifier || "-") + '</td>';
        h += '<td class="ct-text-meta">' + esc(sa.platform ? _platformLabel(sa.platform) : "-") + '</td>';
        h += '<td class="ct-text-meta">' + esc(app ? app.nom : (sa.application_id || "-")) + '</td>';
        h += '<td class="ct-text-meta">' + esc(_storageLabel(sa.secret_storage)) + '</td>';
        h += '<td class="ct-text-meta">';
        h += esc(_rotationLabel(sa.rotation_policy));
        if (overdue) h += ' <span class="ct-badge" data-tone="critical" data-size="sm">' + t("svc.rotation_overdue") + '</span>';
        h += '</td>';
        h += '<td class="ct-text-meta">' + esc(sa.date_expiration || "-") + _expiryBadge(sa) + '</td>';
        h += '<td><span class="ct-badge" data-fill data-tone="' + _accessTone(sa.risk_level) + '">' + esc(_riskLabel(sa.risk_level)) + '</span></td>';
        h += '<td class="ct-ta-r"><button class="ct-btn ct-py-1 ct-px-2 ct-text-label" data-write data-variant="danger" data-click="deleteServiceAccount" data-args=\'' + _da(i) + '\' data-stop>' + t("btn_delete") + '</button></td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    return h;
}

function openSA(i: number | string): void { _selectedSA = parseInt(i as string); renderPanel(); } window.openSA = openSA;
function backToSA(): void { _selectedSA = null; renderPanel(); } window.backToSA = backToSA;

function addServiceAccount(): void {
    var sa: AccessServiceAccount = { id: _genId("SVC-", D.service_accounts || []), name: "", identifier: "", platform: "", application_id: "", purpose: "", secret_storage: "unknown", rotation_policy: "unknown", last_rotation: "", date_expiration: "", owners: [], risk_level: "medium", notes: "" };
    if (!D.service_accounts) D.service_accounts = [];
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        AccessAPI.createServiceAccount(pid, sa).then(function(created) {
            D.service_accounts.push(created);
            _selectedSA = D.service_accounts.length - 1; renderPanel();
        }).catch(function(e) { showStatus(e.message, true); });
    } else {
        D.service_accounts.push(sa);
        _selectedSA = D.service_accounts.length - 1; renderPanel(); _save();
    }
} window.addServiceAccount = addServiceAccount;

function deleteServiceAccount(idx0: number | string): void {
    var idx = parseInt(idx0 as string);
    var sa = (D.service_accounts || [])[idx]; if (!sa) return;
    _ctConfirm(t("svc.confirm_delete", { name: sa.name }), "", function() {
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (pid && window.AccessAPI) {
            AccessAPI.deleteServiceAccount(pid, sa.id).then(function() {
                D.service_accounts.splice(idx, 1); _selectedSA = null; renderPanel();
            }).catch(function(e) { showStatus(e.message, true); });
        } else {
            D.service_accounts.splice(idx, 1); _selectedSA = null; renderPanel(); _save();
        }
    });
} window.deleteServiceAccount = deleteServiceAccount;

function renderSADetail(): string {
    var sa = (D.service_accounts || [])[_selectedSA!]; if (!sa) return renderSAList();
    var h = '<div class="ct-row ct-row-wrap ct-mb-3">';
    h += '<button class="ct-btn" data-variant="ghost" data-size="sm" data-click="backToSA">&laquo; ' + t("svc.title") + '</button>';
    h += '<h2 class="ct-m-0">' + esc(sa.name || t("svc.add")) + '</h2>';
    if (_isRotationOverdue(sa)) h += '<span class="ct-badge" data-tone="critical">' + t("svc.rotation_overdue") + '</span>';
    h += _expiryBadge(sa);
    h += '<span class="ct-flex-1"></span>';
    h += '<button class="ct-btn" data-size="xs" data-write data-variant="danger" data-click="deleteServiceAccount" data-args=\'' + _da(_selectedSA) + '\'>' + t("btn_delete") + '</button></div>';

    h += '<div class="ct-tprm-form"><div class="ct-form-grid">';
    h += _saField("name", t("svc.name"), "text", sa.name);
    h += _saField("identifier", t("svc.identifier"), "text", sa.identifier);
    h += '</div><div class="ct-form-grid">';
    h += _saSel("platform", t("svc.platform"), ["", "azure", "aws", "gcp", "on-prem", "saas", "other"].map(function(p) { return { v: p, l: p ? _platformLabel(p) : "-" }; }), sa.platform);
    h += _saSel("application_id", t("svc.application"), [{ v: "", l: "-" }].concat(D.applications.map(function(a) { return { v: a.id, l: a.nom || a.id }; })), sa.application_id);
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("svc.purpose") + '</label><textarea rows="2" class="ct-journal-body ct-bordered ct-r-sm ct-p-1 ct-text-meta ct-resize-y" data-change="saveSAField" data-args=\'["purpose"]\' data-pass-value>' + esc(sa.purpose || "") + '</textarea></div>';
    h += '<div class="ct-form-grid">';
    h += _saSel("secret_storage", t("svc.secret_storage"), ["vault", "env_var", "key_management", "hardcoded", "other", "none", "unknown"].map(function(s) { return { v: s, l: _storageLabel(s) }; }), sa.secret_storage);
    h += _saSel("rotation_policy", t("svc.rotation_policy"), ["30d", "60d", "90d", "180d", "365d", "540d", "730d", "never", "unknown"].map(function(r) { return { v: r, l: _rotationLabel(r) }; }), sa.rotation_policy);
    h += '</div><div class="ct-form-grid">';
    h += _saField("last_rotation", t("svc.last_rotation"), "date", sa.last_rotation);
    h += _saField("date_expiration", t("svc.date_expiration"), "date", sa.date_expiration);
    h += '</div><div class="ct-form-grid">';
    h += _saSel("risk_level", t("svc.risk_level"), ["critical", "high", "medium", "low"].map(function(r) { return { v: r, l: _riskLabel(r) }; }), sa.risk_level);
    h += '</div>';
    h += '<div class="ct-form-row"><label>' + t("svc.notes") + '</label><textarea rows="2" class="ct-journal-body ct-bordered ct-r-sm ct-p-1 ct-text-meta ct-resize-y" data-change="saveSAField" data-args=\'["notes"]\' data-pass-value>' + esc(sa.notes || "") + '</textarea></div>';
    h += '</div>';
    return h;
}

function saveSAField(field: string, val: string): void {
    if (_selectedSA === null) return;
    var sa = D.service_accounts[_selectedSA]; if (!sa) return;
    (sa as Record<string, unknown>)[field] = val;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI) {
        var patch: Record<string, any> = {}; patch[field] = val;
        AccessAPI.patchServiceAccount(pid, sa.id, patch).catch(function(e) { console.error("Patch SA failed:", e); });
    } else { _save(); }
} window.saveSAField = saveSAField;

function _saField(name: string, label: string, type: string, val: unknown): string { return '<div class="ct-form-row"><label>' + esc(label) + '</label><input type="' + type + '" value="' + esc(String(val != null ? val : "")) + '" data-change="saveSAField" data-args=\'["' + name + '"]\' data-pass-value></div>'; }
function _saSel(name: string, label: string, opts: { v: string; l: string }[], val: string | undefined): string { var h = '<div class="ct-form-row"><label>' + esc(label) + '</label><select data-change="saveSAField" data-args=\'["' + name + '"]\' data-pass-value>'; opts.forEach(function(o) { h += '<option value="' + esc(String(o.v)) + '"' + (String(val) === String(o.v) ? " selected" : "") + '>' + esc(o.l) + '</option>'; }); return h + '</select></div>'; }

// ═══════════════════════════════════════════════════════════════
// MEASURES
// ═══════════════════════════════════════════════════════════════
function _accessMeasureStatusBadge(statut: string): string {
    var label = t("measure.s." + statut) || statut || "";
    return '<span class="ct-badge" data-tone="' + _accessTone(statut) + '">' + esc(label) + '</span>';
}

function renderMeasureList(): string {
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("nav.measures") + '</h2>';
    h += '<div class="ct-flex ct-gap-2">';
    h += '<button class="ct-btn mt-8" data-write data-click="_refreshMeasures" title="' + esc(t("measure.refresh") || "Rafraîchir") + '">&#x21bb;</button>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="addMeasure">' + t("measure.add") + '</button>';
    h += '</div></div>';
    if (!D.measures.length) { h += '<div class="ct-empty-state">' + t("measure.empty") + '</div>'; return h; }

    h += ct_table.render({
        rows: D.measures,
        rowKey: "id",
        onRowClick: "_editAccessMeasureRow",
        bulk: { scope: "access-measures" },
        columns: [
            { key: "id", label: "ID", width: "100px" },
            { key: "title", label: t("measure.title"),
              render: function(m: Record<string, any>) { return esc(m.title || ""); } },
            { key: "statut", label: t("measure.statut"), width: "110px",
              render: function(m: Record<string, any>) { return _accessMeasureStatusBadge(m.statut); } },
            { key: "responsable", label: t("measure.responsable"),
              render: function(m: Record<string, any>) { return esc(m.responsable || ""); } },
            { key: "echeance", label: t("measure.echeance"), width: "120px",
              render: function(m: Record<string, any>) { return esc(m.echeance || ""); } }
        ]
    });

    setTimeout(function() {
        if (!window.ct_bulkbar) return;
        ct_bulkbar.attach({
            scope: "access-measures",
            label: t("measure.selected_n") || "{n} action(s) sélectionnée(s)",
            actions: [
                { id: "done", icon: "check", label: t("measure.s.termine") || "Terminé", variant: "success",
                  onClick: "_bulkAccessMeasuresDone" },
                { id: "delete", icon: "trash", label: t("btn_delete") || "Supprimer", danger: true,
                  onClick: "_bulkAccessMeasuresDelete",
                  confirm: { title: "Supprimer {n} action(s) ?", message: "Cette action est irréversible." } }
            ]
        });
        ct_bulkbar.update("access-measures");
    }, 0);

    return h;
}

window._refreshMeasures = function() {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (pid && window.AccessAPI && (AccessAPI as Partial<AccessApi>).listMeasures) {
        AccessAPI.listMeasures(pid).then(function(list) {
            D.measures = list || [];
            showStatus("Mesures rafraîchies (" + D.measures.length + ")");
            renderPanel();
        }).catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
    } else {
        window.location.reload();
    }
};

window._editAccessMeasureRow = function(row) {
    var m = D.measures.find(function(x) { return x.id === row.id; });
    if (!m) return;
    if (!window.ct_measure_modal) return;
    ct_measure_modal.open(m, {
        title: m.id + " — " + (m.title || t("measure.add")),
        hideFields: ["type"],
        statusOptions: [
            { value: "a_faire",  label: t("measure.s.a_faire")  || "À faire" },
            { value: "en_cours", label: t("measure.s.en_cours") || "En cours" },
            { value: "termine",  label: t("measure.s.termine")  || "Terminé" }
        ],
        defaultStatus: "a_faire",
        ownerPicker: { pickerId: "access-measure-owner", directoryUrl: "api/directory" },
        onAddNote: function(_entry, fullLog) {
            (m as Record<string, any>).progress_log = fullLog;
            var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
            if (pid && window.AccessAPI && (AccessAPI as Partial<AccessApi>).patchMeasure)
                return AccessAPI.patchMeasure(pid, m!.id, { progress_log: fullLog } as any);
        },
        onDelete: function() {
            ct_modal.confirm({
                title: "Supprimer l'action",
                message: "Cette action est irréversible.",
                danger: true
            }).then(function(ok) {
                if (!ok) return;
                var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
                var doLocal = function() {
                    var idx = D.measures.findIndex(function(x) { return x.id === m!.id; });
                    if (idx >= 0) D.measures.splice(idx, 1);
                    _save();
                    renderPanel();
                };
                if (pid && window.AccessAPI) {
                    AccessAPI.deleteMeasure(pid, m!.id).then(doLocal)
                        .catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
                } else { doLocal(); }
            });
        }
    }).then(function(result) {
        if (!result || result.__deleted) return;
        var allowed = ["title", "description", "statut", "responsable", "echeance", "progress_log"];
        var patch: Record<string, any> = {};
        allowed.forEach(function(k) { if (result[k] !== undefined) patch[k] = result[k]; });
        Object.keys(patch).forEach(function(k) { (m as Record<string, any>)[k] = patch[k]; });
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (pid && window.AccessAPI) {
            AccessAPI.patchMeasure(pid, m!.id, patch)
                .catch(function(e) { console.error("Patch measure failed:", e); });
        }
        _save();
        renderPanel();
    });
};

window._bulkAccessMeasuresDone = function(scope) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    var locals = ids.map(function(id) {
        var m = D.measures.find(function(x) { return x.id === id; });
        if (m) m.statut = "termine";
        return m;
    }).filter(Boolean);
    var done = function() {
        showStatus(ids.length + " action(s) marquée(s) terminée(s)");
        ct_bulkbar.clear(scope);
        _save();
        renderPanel();
    };
    if (pid && window.AccessAPI) {
        Promise.all(ids.map(function(id) { return AccessAPI.patchMeasure(pid!, id, { statut: "termine" }); }))
            .then(done).catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
    } else { done(); }
};

window._bulkAccessMeasuresDelete = function(scope) {
    var ids = Array.from(ct_bulkbar.getSelection(scope));
    if (!ids.length) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    var doLocal = function() {
        D.measures = D.measures.filter(function(m) { return ids.indexOf(m.id) < 0; });
        showStatus(ids.length + " action(s) supprimée(s)");
        ct_bulkbar.clear(scope);
        _save();
        renderPanel();
    };
    if (pid && window.AccessAPI) {
        Promise.all(ids.map(function(id) { return AccessAPI.deleteMeasure(pid!, id); }))
            .then(doLocal).catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
    } else { doLocal(); }
};

function addMeasure(): void {
    if (!window.ct_measure_modal) return;
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    var newId = _genId("MES-", D.measures);
    ct_measure_modal.open({ id: newId, title: "", description: "", statut: "a_faire", responsable: "", echeance: "" }, {
        title: t("measure.add"),
        hideFields: ["type"],
        statusOptions: [
            { value: "a_faire",  label: t("measure.s.a_faire")  || "À faire" },
            { value: "en_cours", label: t("measure.s.en_cours") || "En cours" },
            { value: "termine",  label: t("measure.s.termine")  || "Terminé" }
        ],
        defaultStatus: "a_faire",
        ownerPicker: { pickerId: "access-measure-owner", directoryUrl: "api/directory" }
    }).then(function(result) {
        if (!result) return;
        var m: AccessMeasure = {
            id: newId,
            review_entry_id: "",
            title: result.title || "",
            description: result.description || "",
            statut: result.statut || "a_faire",
            responsable: result.responsable || "",
            echeance: result.echeance || ""
        };
        var finish = function() { D.measures.push(m); _save(); renderPanel(); };
        if (pid && window.AccessAPI) {
            AccessAPI.createMeasure(pid, m).then(function(created) {
                if (created && created.id) m.id = created.id;
                finish();
            }).catch(function(e) { showStatus("Erreur : " + (e.message || e), true); });
        } else { finish(); }
    });
} window.addMeasure = addMeasure;

// ═══════════════════════════════════════════════════════════════
// PLUGINS (CONNECTORS)
// ═══════════════════════════════════════════════════════════════
var _pluginList: AccessPlugin[] = [], _availablePlugins: AccessAvailablePlugin[] = [], _pluginsLoaded = false;

function _loadPlugins(cb?: () => void): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid || !window.AccessAPI) { if (cb) cb(); return; }
    Promise.all([
        AccessAPI.listPlugins(pid),
        _availablePlugins.length ? Promise.resolve(_availablePlugins) : AccessAPI.listAvailablePlugins()
    ]).then(function(res) {
        _pluginList = res[0] || [];
        _availablePlugins = res[1] || [];
        _pluginsLoaded = true;
        if (cb) cb();
    }).catch(function(e) { console.error("Load plugins:", e); if (cb) cb(); });
}

function renderPlugins(): string {
    if (!_pluginsLoaded) { _loadPlugins(function() { renderPanel(); }); return '<div class="ct-p-5 ct-muted">...</div>'; }
    var h = '<div class="ct-row ct-row-between ct-mb-3">';
    h += '<h2>' + t("plg.title") + '</h2>';
    h += '<button class="ct-btn mt-8" data-write data-variant="primary" data-click="showPluginModal">' + t("plg.add") + '</button></div>';

    if (!_pluginList.length) { h += '<div class="ct-empty-state">' + t("plg.empty") + '</div>'; return h; }

    _pluginList.forEach(function(p) {
        var statusCls = p.last_sync_status === "success" ? "ok" : (p.last_sync_status === "error" ? "ko" : "");
        h += '<div class="ct-groupe-card ct-userpicker ct-clickable" data-click="showPluginModal" data-args=\'' + _da(p.id) + '\'>';
        h += '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-1">';
        h += '<strong>' + esc(p.label || p.plugin_type) + '</strong>';
        h += '<span class="ct-badge" data-tone="info">' + esc(p.plugin_type) + '</span>';
        h += '<span class="ct-compliance-tag ' + (p.enabled ? "ok" : "ko") + '">' + (p.enabled ? t("plg.enabled") : t("plg.disabled")) + '</span>';
        h += '</div>';

        h += '<div class="ct-text-label ct-muted ct-mb-2">';
        h += t("plg.schedule") + ': ' + esc(t("plg.schedule." + p.schedule) || p.schedule);
        if (p.last_sync_at) h += ' &middot; ' + t("plg.last_sync") + ': ' + esc(p.last_sync_at.split("T")[0]);
        if (p.last_sync_status) h += ' <span class="ct-compliance-tag ' + statusCls + '">' + esc(t("plg.status." + p.last_sync_status) || p.last_sync_status) + '</span>';
        h += '</div>';

        h += '<div class="ct-flex ct-gap-1 ct-row-wrap">';
        h += '<button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-stop data-click="testPlugin" data-args=\'' + _da(p.id) + '\'>' + t("plg.test") + '</button>';
        h += '<button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-stop data-click="showPluginHistory" data-args=\'' + _da(p.id) + '\'>' + t("plg.history") + '</button>';
        h += '<button class="ct-btn mt-8 ct-text-label ct-py-1 ct-px-2" data-write data-variant="danger" data-stop data-click="deletePlugin" data-args=\'' + _da(p.id) + '\'>' + t("btn_delete") + '</button>';
        h += '</div>';
        h += '</div>';
    });
    return h;
}

function showPluginModal(pluginId?: string): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid) return;
    var existing = pluginId ? _pluginList.find(function(p) { return p.id === pluginId; }) : null;

    var ov = document.getElementById("confirm-overlay")!;
    var title = existing ? esc(existing.label || existing.plugin_type) : t("plg.add");

    var h = '<div style="max-width:500px;max-height:80vh;overflow-y:auto">';
    h += '<div class="ct-pwd-title">' + title + '</div>';

    // Type selector (only for new plugins — card grid with search)
    if (!existing) {
        h += '<div class="ct-mb-2"><label class="ct-strong ct-text-meta">' + t("plg.type") + '</label>';
        h += '<input type="text" id="plg-search" placeholder="' + esc(t("plg.search_placeholder")) + '" class="ct-w-full ct-p-1 ct-mt-1 ct-mb-2 ct-bordered ct-r-sm ct-text-meta" data-input="_plgSearchFilter" data-pass-value autocomplete="off">';
        h += '<input type="hidden" id="plg-type" value="">';
        h += '<div id="plg-type-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:var(--ct-s1);max-height:200px;overflow-y:auto">';
        _availablePlugins.forEach(function(ap) {
            h += '<div class="plg-type-card" data-click="_plgSelectType" data-args=\'' + _da(ap.type) + '\'>';
            h += '<div class="ct-strong">' + esc(ap.label) + '</div>';
            h += '</div>';
        });
        h += '</div></div>';
        if (!_availablePlugins.length) h += '<div class="ct-text-label ct-muted">' + t("plg.no_plugins_available") + '</div>';
    }

    // Label
    h += '<div class="ct-mb-2"><label class="ct-strong ct-text-meta">' + t("plg.label") + '</label>';
    h += '<input type="text" id="plg-label" value="' + esc(existing ? existing.label : "") + '" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm"></div>';

    // Setup guide (collapsible)
    h += '<div id="plg-guide-wrap">';
    if (existing) {
        var apg = _availablePlugins.find(function(a) { return a.type === existing!.plugin_type; });
        if (apg) h += _renderPluginGuide(apg);
    }
    h += '</div>';

    // Config fields container
    h += '<div id="plg-config-fields">';
    if (existing) {
        var ap = _availablePlugins.find(function(a) { return a.type === existing!.plugin_type; });
        if (ap && ap.config_schema) {
            h += _renderConfigFields(ap.config_schema, existing.config || {});
        }
    }
    h += '</div>';

    // Group filters
    h += '<div class="ct-mb-2"><label class="ct-strong ct-text-meta">' + t("plg.group_filters") + '</label>';
    h += '<input type="text" id="plg-filters" value="' + esc((existing && existing.group_filters || []).join(", ")) + '" placeholder="group1, group2" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm"></div>';

    // Application
    h += '<div class="ct-mb-2"><label class="ct-strong ct-text-meta">' + t("plg.application") + '</label>';
    h += '<select id="plg-app" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm">';
    h += '<option value="">--</option>';
    D.applications.forEach(function(a) {
        h += '<option value="' + esc(a.id) + '"' + (existing && existing.application_id === a.id ? " selected" : "") + '>' + esc(a.nom) + '</option>';
    });
    h += '</select></div>';

    // Schedule
    h += '<div class="ct-mb-2"><label class="ct-strong ct-text-meta">' + t("plg.schedule") + '</label>';
    h += '<select id="plg-schedule" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm">';
    ["manual", "daily", "weekly"].forEach(function(s) {
        h += '<option value="' + s + '"' + (existing && existing.schedule === s ? " selected" : "") + '>' + esc(t("plg.schedule." + s) || s) + '</option>';
    });
    h += '</select></div>';

    // Enabled
    h += '<div class="ct-mb-2"><label class="ct-inline-flex ct-items-center ct-gap-1 ct-clickable ct-text-meta"><input type="checkbox" id="plg-enabled"' + (existing && existing.enabled ? " checked" : "") + '> ' + t("plg.enabled") + '</label></div>';

    // Test button — uses form values (not DB), so works before saving too
    h += '<div class="ct-mb-2"><button class="ct-btn mt-8 ct-bg-accent ct-text-label" data-write data-variant="primary" data-click="_plgTestInline" data-args=\'' + _da(existing ? existing.id : "") + '\'>' + t("plg.test") + '</button> <span id="plg-test-result" class="ct-text-label"></span></div>';

    h += '<div class="ct-flex ct-gap-2 ct-justify-end ct-mt-3">';
    h += '<button class="ct-btn" data-click="_plgCancel">' + t("btn_cancel") + '</button>';
    h += '<button class="ct-btn" data-variant="primary" data-click="_plgSave" data-args=\'' + _da(existing ? existing.id : "") + '\'>' + (existing ? "OK" : t("plg.add")) + '</button>';
    h += '</div></div>';

    var panel = ov.querySelector<HTMLElement>(".ct-pwd-panel")!;
    panel.innerHTML = h;
    ov.style.display = "flex";
} window.showPluginModal = showPluginModal;

function _renderConfigFields(schema: AccessPluginConfigField[], values: Record<string, any>): string {
    var h = '<div class="ct-mb-1 ct-strong ct-text-meta">' + t("plg.config") + '</div>';
    schema.forEach(function(f) {
        var rawVal = values[f.key];
        var val = rawVal != null ? rawVal : "";
        if (f.type === "checkbox") {
            // Render checkbox inline with the label (no block wrap)
            var checked = (rawVal === true || rawVal === "true" || rawVal === "on" || rawVal === 1);
            h += '<div class="ct-mb-2"><label class="ct-text-label ct-inline-flex ct-items-center ct-gap-1 ct-clickable">';
            h += '<input type="checkbox" data-config-key="' + esc(f.key) + '" data-config-type="checkbox"' + (checked ? " checked" : "") + '> ';
            h += esc(f.label || f.key) + (f.required ? ' *' : '') + '</label></div>';
            return;
        }
        if (f.type === "select" && Array.isArray(f.options)) {
            h += '<div class="ct-mb-2"><label class="ct-text-label">' + esc(f.label || f.key) + (f.required ? ' *' : '') + '</label>';
            h += '<select data-config-key="' + esc(f.key) + '" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm ct-text-meta">';
            f.options.forEach(function(opt: any) {
                var ov = opt.value !== undefined ? opt.value : opt;
                var ol = opt.label !== undefined ? opt.label : ov;
                h += '<option value="' + esc(String(ov)) + '"' + (String(val) === String(ov) ? " selected" : "") + '>' + esc(ol) + '</option>';
            });
            h += '</select></div>';
            return;
        }
        if (f.type === "textarea") {
            h += '<div class="ct-mb-2"><label class="ct-text-label">' + esc(f.label || f.key) + (f.required ? ' *' : '') + '</label>';
            h += '<textarea data-config-key="' + esc(f.key) + '" rows="' + (f.rows || 3) + '" placeholder="' + esc(f.placeholder || "") + '" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm ct-text-meta ct-font-inherit">' + esc(String(val)) + '</textarea></div>';
            return;
        }
        // Default: text or password
        h += '<div class="ct-mb-2"><label class="ct-text-label">' + esc(f.label || f.key) + (f.required ? ' *' : '') + '</label>';
        var inputType = f.type === "password" ? "password" : "text";
        h += '<input type="' + inputType + '" data-config-key="' + esc(f.key) + '" value="' + esc(String(val)) + '" placeholder="' + esc(f.placeholder || "") + '" class="ct-w-full ct-p-1 ct-mt-1 ct-bordered ct-r-sm ct-text-meta"></div>';
    });
    return h;
}

window._plgSearchFilter = function(query) {
    var grid = document.getElementById("plg-type-grid");
    if (!grid) return;
    var q = (query || "").toLowerCase();
    var cards = grid.querySelectorAll<HTMLElement>(".plg-type-card");
    cards.forEach(function(card) {
        var label = (card.textContent || "").toLowerCase();
        card.style.display = label.indexOf(q) >= 0 ? "" : "none";
    });
};

window._plgSelectType = function(type) {
    var hidden = document.getElementById("plg-type") as HTMLInputElement | null;
    if (hidden) hidden.value = type;
    var grid = document.getElementById("plg-type-grid");
    if (grid) {
        grid.querySelectorAll<HTMLElement>(".plg-type-card").forEach(function(c) {
            var args = c.getAttribute("data-args");
            var isSelected = args && args.indexOf('"' + type + '"') >= 0;
            c.style.borderColor = isSelected ? "var(--ct-ink)" : "var(--ct-line)";
            c.style.background = isSelected ? "rgba(37,99,235,0.06)" : "";
        });
    }
    window._plgTypeChanged!();
};

window._plgCancel = function() {
    var ov = document.getElementById("confirm-overlay");
    if (!ov) return;
    ov.style.display = "none";
    // Reset any inline width override applied by a wide modal (history)
    var panel = ov.querySelector<HTMLElement>(".ct-pwd-panel");
    if (panel) { panel.style.maxWidth = ""; panel.style.width = ""; }
};

window._plgTypeChanged = function() {
    var typeVal = (document.getElementById("plg-type") as HTMLInputElement).value;
    var container = document.getElementById("plg-config-fields");
    var guideWrap = document.getElementById("plg-guide-wrap");
    if (!typeVal || !container) { if (container) container.innerHTML = ""; if (guideWrap) guideWrap.innerHTML = ""; return; }
    var ap = _availablePlugins.find(function(a) { return a.type === typeVal; });
    container.innerHTML = ap && ap.config_schema ? _renderConfigFields(ap.config_schema, {}) : "";
    if (guideWrap) guideWrap.innerHTML = ap ? _renderPluginGuide(ap) : "";
};

function _renderPluginGuide(ap: AccessAvailablePlugin): string {
    var lang = localStorage.getItem("ct_lang") || "fr";
    var guide = (lang === "en" && ap.setup_guide_en) ? ap.setup_guide_en : (ap.setup_guide || ap.setup_guide_en || "");
    if (!guide) return "";
    var lines = guide.split("\n").map(function(l) { return esc(l); }).join("<br>");
    return '<details class="ct-mb-3 ct-bordered ct-r-md ct-p-2 ct-bg-alt">' +
        '<summary class="ct-clickable ct-strong ct-text-meta ct-text-info">' + esc(t("plg.setup_guide")) + '</summary>' +
        '<div style="margin-top:var(--ct-s2);font-size:var(--ct-text-label);line-height:1.6;white-space:pre-wrap;font-family:inherit">' + lines + '</div>' +
        '</details>';
}

// Test connection using the CURRENT form values (not DB). This lets
// the user test before saving, avoiding the confusing scenario where
// an edit isn't reflected in the test result.
window._plgTestInline = function(pluginId) {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid) return;
    var span = document.getElementById("plg-test-result");
    if (span) span.textContent = "...";

    // Collect config from the live form
    var config: Record<string, any> = {};
    document.querySelectorAll<HTMLInputElement>("[data-config-key]").forEach(function(el) {
        var key = el.getAttribute("data-config-key")!;
        if (el.type === "checkbox" || el.getAttribute("data-config-type") === "checkbox") {
            config[key] = !!el.checked;
        } else {
            config[key] = el.value;
        }
    });

    // Resolve plugin_type: from hidden field (new) or from existing plugin data
    var pluginType = ((document.getElementById("plg-type") || {}) as HTMLInputElement).value || "";
    if (!pluginType && pluginId) {
        var existing = _pluginList.find(function(p) { return p.id === pluginId; });
        if (existing) pluginType = existing.plugin_type;
    }

    AccessAPI.testPluginConfig(pid, { plugin_type: pluginType, config: config }).then(function(r) {
        if (span) {
            span.textContent = r.ok ? t("plg.test_ok") : (t("plg.test_fail") + ": " + (r.error || ""));
            span.style.color = r.ok ? "var(--ct-low)" : "var(--ct-critical)";
        }
    }).catch(function(e) { if (span) { span.textContent = e.message; span.style.color = "var(--ct-critical)"; } });
};

var _plgSaveInFlight = false;

window._plgSave = function(existingId) {
    if (_plgSaveInFlight) return;  // guard against double-click / double-dispatch
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid) return;

    var config: Record<string, any> = {};
    document.querySelectorAll<HTMLInputElement>("[data-config-key]").forEach(function(el) {
        var key = el.getAttribute("data-config-key")!;
        if (el.type === "checkbox" || el.getAttribute("data-config-type") === "checkbox") {
            config[key] = !!el.checked;
        } else {
            config[key] = el.value;
        }
    });

    var filtersRaw = ((document.getElementById("plg-filters") || {}) as HTMLInputElement).value || "";
    var filters = filtersRaw ? filtersRaw.split(",").map(function(s) { return s.trim(); }).filter(Boolean) : [];

    var body: Record<string, unknown> = {
        label: ((document.getElementById("plg-label") || {}) as HTMLInputElement).value || "",
        config: config,
        group_filters: filters,
        application_id: ((document.getElementById("plg-app") || {}) as HTMLSelectElement).value || "",
        schedule: ((document.getElementById("plg-schedule") || {}) as HTMLSelectElement).value || "manual",
        enabled: !!((document.getElementById("plg-enabled") || {}) as HTMLInputElement).checked
    };

    var promise: Promise<AccessPlugin>;
    if (existingId) {
        promise = AccessAPI.patchPlugin(pid, existingId, body);
    } else {
        body.plugin_type = ((document.getElementById("plg-type") || {}) as HTMLInputElement).value || "";
        if (!body.plugin_type) { showStatus("Select a connector type", true); return; }
        promise = AccessAPI.createPlugin(pid, body);
    }

    _plgSaveInFlight = true;
    // Visually disable the OK button while the request is in flight
    var okBtn = document.querySelector<HTMLButtonElement>("#confirm-overlay .ct-pwd-ok");
    if (okBtn) { okBtn.disabled = true; okBtn.style.opacity = "0.6"; }

    promise.then(function() {
        document.getElementById("confirm-overlay")!.style.display = "none";
        _pluginsLoaded = false;
        _loadPlugins(function() { renderPanel(); });
        showStatus(existingId ? "OK" : t("plg.add") + " OK");
    }).catch(function(e) {
        showStatus(e.message, true);
    }).finally(function() {
        _plgSaveInFlight = false;
        if (okBtn) { okBtn.disabled = false; okBtn.style.opacity = ""; }
    });
};

function testPlugin(pluginId: string): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid) return;
    AccessAPI.testPlugin(pid, pluginId).then(function(r) {
        showStatus(r.ok ? t("plg.test_ok") : (t("plg.test_fail") + ": " + (r.error || "")), !r.ok);
    }).catch(function(e) { showStatus(e.message, true); });
} window.testPlugin = testPlugin;

function deletePlugin(pluginId: string): void {
    var p = _pluginList.find(function(x) { return x.id === pluginId; });
    _ctConfirm(t("plg.confirm_delete", { name: (p && p.label) || pluginId }), "", function() {
        var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
        if (!pid) return;
        AccessAPI.deletePlugin(pid, pluginId).then(function() {
            _pluginsLoaded = false;
            _loadPlugins(function() { renderPanel(); });
            showStatus("OK");
        }).catch(function(e) { showStatus(e.message, true); });
    });
} window.deletePlugin = deletePlugin;

function showPluginHistory(pluginId: string): void {
    var pid = (window as Window).getActiveProjectId ? getActiveProjectId() : null;
    if (!pid) return;
    AccessAPI.pluginHistory(pid, pluginId).then(function(jobs) {
        var ov = document.getElementById("confirm-overlay")!;
        // Override the standard narrow panel width — override the inline
        // width on .pwd-panel so the table isn't crammed.
        var panel = ov.querySelector<HTMLElement>(".ct-pwd-panel")!;
        panel.style.maxWidth = "min(95vw, 1000px)";
        panel.style.width = "100%";
        var h = '<div style="max-height:85vh;overflow-y:auto">';
        h += '<div class="ct-pwd-title ct-mb-4">' + t("plg.history") + '</div>';
        if (!jobs.length) {
            h += '<div class="ct-empty-state">' + (t("plg.history_empty") || "Aucun historique de synchronisation pour ce connecteur.") + '</div>';
        } else {
            h += '<table class="ct-w-full ct-text-meta">'
              +  '<thead><tr>'
              +    '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom">' + (t("plg.history_date") || "Date") + '</th>'
              +    '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom ct-w-110">' + (t("plg.history_status") || "Statut") + '</th>'
              +    '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom ct-w-90">' + (t("plg.history_found") || "Trouvés") + '</th>'
              +    '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom ct-w-90">' + (t("plg.history_created") || "Créés") + '</th>'
              +    '<th class="ct-ta-r ct-py-1 ct-px-2 ct-border-bottom ct-w-90">' + (t("plg.history_updated") || "MAJ") + '</th>'
              +    '<th class="ct-ta-l ct-py-1 ct-px-2 ct-border-bottom">' + (t("plg.history_error") || "Erreur") + '</th>'
              +  '</tr></thead><tbody>';
            jobs.forEach(function(j) {
                var statusCls = j.status === "success" ? "ok" : (j.status === "error" ? "ko" : "");
                var startedRaw = j.started_at || "";
                var startedFmt = startedRaw ? startedRaw.replace("T", " ").split(".")[0].slice(0, 16) : "-";
                h += '<tr>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-nowrap">' + esc(startedFmt) + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt"><span class="ct-compliance-tag ' + statusCls + '">' + esc(t("plg.status." + j.status) || j.status) + '</span></td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.users_found != null ? j.users_found : "-") + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.users_created != null ? j.users_created : "-") + '</td>';
                h += '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-ta-r">' + (j.users_updated != null ? j.users_updated : "-") + '</td>';
                var errMsg = j.error_message || "";
                h += '<td style="padding:var(--ct-s1) var(--ct-s2);border-bottom:1px solid var(--ct-surface-2);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--ct-text-label);color:var(--ct-critical)" title="' + esc(errMsg) + '">' + esc(errMsg || "-") + '</td>';
                h += '</tr>';
            });
            h += '</tbody></table>';
        }
        h += '<div class="ct-flex ct-justify-end ct-mt-4"><button class="ct-btn" data-click="_plgCancel">' + (t("btn_close") || t("btn_cancel") || "Fermer") + '</button></div>';
        h += '</div>';
        panel.innerHTML = h;
        ov.style.display = "flex";
    }).catch(function(e) { showStatus(e.message, true); });
} window.showPluginHistory = showPluginHistory;

// ═══════════════════════════════════════════════════════════════
// CONFIRM + SAVE
// ═══════════════════════════════════════════════════════════════
function _ctConfirm(title: string, body: string, onYes: () => void, okLabel?: string, cancelLabel?: string): void {
    var ov = document.getElementById("confirm-overlay")!;
    var panel = ov.querySelector<HTMLElement>(".ct-pwd-panel")!;
    // Reset any width override applied by a wide modal before
    // reusing the panel for a regular confirm dialog.
    panel.style.maxWidth = "";
    panel.style.width = "";
    // Rebuild the panel from scratch — other flows (e.g. showPluginModal)
    // inject their own HTML into this shared overlay and destroy the
    // confirm-title / confirm-body / confirm-oui / confirm-non children.
    panel.innerHTML =
        '<div class="ct-pwd-title" id="confirm-title"></div>' +
        '<div id="confirm-body" class="ct-text-data ct-mb-3"></div>' +
        '<div class="ct-flex ct-gap-2 ct-justify-end">' +
            '<button class="ct-btn" id="confirm-non"></button>' +
            '<button class="ct-btn" data-variant="primary" id="confirm-oui"></button>' +
        '</div>';
    document.getElementById("confirm-title")!.textContent = title;
    document.getElementById("confirm-body")!.textContent = body;
    ov.style.display = "flex";
    var btnOui = document.getElementById("confirm-oui")!, btnNon = document.getElementById("confirm-non")!;
    btnOui.textContent = okLabel || t("btn_yes") || "Oui";
    btnNon.textContent = cancelLabel || t("btn_no") || "Non";
    function close(): void { ov.style.display = "none"; btnOui.onclick = null; btnNon.onclick = null; }
    btnOui.onclick = function() { close(); onYes(); };
    btnNon.onclick = close;
}
function _save(): void { if (window._autoSave) window._autoSave(); else if (window._debouncedSave) window._debouncedSave(); }

// ═══════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════
if (typeof window._appInitCallback === "function") { window._appInitCallback(); }
else { _initDataAndRender(); }

// FEAT-13 — deep-linked measure from Pilot (?measure=MES-xxx): open the
// native edit modal once the measures list is loaded (shared retry loop).
if (typeof window.ct_handleMeasureDeepLink === "function") {
    window.ct_handleMeasureDeepLink({ open: function(mid) {
        var ms = (D && D.measures) || [];
        if (!ms.some(function(m) { return m.id === mid; })) return false;
        if (typeof selectPanel === "function") selectPanel("measures");
        if (typeof window._editAccessMeasureRow === "function") window._editAccessMeasureRow({ id: mid });
        return true;
    } });
}
