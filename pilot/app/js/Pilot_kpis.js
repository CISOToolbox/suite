/**
 * Pilot KPI panel — synthetic dashboard + clickable cards + unified detail modal.
 *
 * Backend contract:
 *   GET    /api/kpis                       — list with mappings + latest snapshot
 *   GET    /api/kpis/{code}/snapshots      — time series
 *   POST   /api/kpis/{code}/manual         — user-auth ingest wrapper
 *   PATCH  /api/kpis/{code}                — admin: target/thresholds/active/mappings
 *   POST   /api/kpis                       — admin: create custom KPI
 *   DELETE /api/kpis/{code}                — admin: drop a custom KPI
 *   POST   /api/kpis/auto-compute          — admin: run a compute pass now
 *
 * UX overview
 * -----------
 * Top of panel is a synthetic dashboard: overall donut (green / amber / red
 * / no-data) + per-category stoplight strip. Below, the catalogue is shown
 * as a grouped grid (by NIST CSF function). Each card is fully clickable —
 * a click opens a single "detail" modal that consolidates: current value,
 * sparkline, recent history, framework anchors, and (admin) inline tuning
 * + referential association/dissociation + delete.
 *
 * Auto KPIs are opt-in: the catalogue seed inserts them with active=false,
 * so the scheduler doesn't compute them until an admin explicitly toggles
 * "Activer" on the card. External (manual / plugin) KPIs start active so
 * users can immediately enter or push values.
 */
(function () {
    "use strict";
    var _kpiData = null; // last GET /api/kpis response
    var _filterCat = "all";
    var _filterFw = "all";
    var _filterSrc = "all";
    var _filterStatus = "active"; // 'all' | 'active' | 'inactive'
    function _catLabel(c) { return t("pilot.kpi.cat." + c); }
    // Catalogue KPIs are bilingual (name_fr/name_en + description_fr/description_en).
    // Render the active-language variant, falling back to FR, so titles and
    // descriptions follow the language toggle (and re-render with the panel).
    function _kpiName(k) { return (_locale === "en" && k.name_en) ? k.name_en : k.name_fr; }
    function _kpiDesc(k) { return (_locale === "en" && k.description_en) ? k.description_en : (k.description_fr || ""); }
    var CAT_ORDER = ["govern", "identify", "protect", "detect", "respond", "recover"];
    var FW_LABELS = {
        NIST_CSF_2: "NIST CSF 2.0",
        ISO_27001_2022: "ISO 27001:2022",
        ISO_27004_2016: "ISO 27004:2016",
        CIS_v8: "CIS v8",
        DORA: "DORA",
        NIS2: "NIS2"
    };
    var FW_ORDER = ["NIST_CSF_2", "ISO_27001_2022", "ISO_27004_2016", "CIS_v8", "DORA", "NIS2"];
    // ── Color / posture per (value, direction, target, amber, red) ──
    // Three zones delimited by thresholds:
    //   RED    = past the red threshold (critical breach)
    //   AMBER  = past the amber threshold OR not yet at target
    //   GREEN  = at/beyond target (conforme to the objective)
    function _kpiHealth(k) {
        if (k.latest == null)
            return { color: "grey", label: t("pilot.kpi.status.no_data") };
        // Connector-computed severity (e.g. PSAT awareness: due-date aware —
        // green while there is still time, amber < 15 j, red past due) takes
        // precedence over the generic value/threshold zones when present.
        var cc = k.connector_config;
        if (cc && cc.severity) {
            if (cc.severity === "red")
                return { color: "red", label: t("pilot.kpi.status.critical") };
            if (cc.severity === "amber")
                return { color: "amber", label: t("pilot.kpi.status.overdue") };
            return { color: "green", label: t("pilot.kpi.status.compliant") };
        }
        var v = k.latest.value;
        var tgt = k.target, a = k.threshold_amber, r = k.threshold_red;
        if (k.direction === "higher_better") {
            if (r != null && v < r)
                return { color: "red", label: t("pilot.kpi.status.critical") };
            if (a != null && v < a)
                return { color: "amber", label: t("pilot.kpi.status.watch") };
            if (tgt != null && v < tgt)
                return { color: "amber", label: t("pilot.kpi.status.below_target") };
            return { color: "green", label: t("pilot.kpi.status.compliant") };
        }
        else {
            if (r != null && v > r)
                return { color: "red", label: t("pilot.kpi.status.critical") };
            if (a != null && v > a)
                return { color: "amber", label: t("pilot.kpi.status.watch") };
            if (tgt != null && v > tgt)
                return { color: "amber", label: t("pilot.kpi.status.above_target") };
            return { color: "green", label: t("pilot.kpi.status.compliant") };
        }
    }
    function _fmtValue(k) {
        if (k.latest == null)
            return "—";
        var v = k.latest.value;
        if (k.unit === "%")
            return v.toFixed(1) + " %";
        if (k.unit === "days")
            return v.toFixed(1) + " j";
        if (k.unit === "count")
            return Math.round(v).toString();
        if (k.unit === "currency")
            return v.toLocaleString() + " €";
        return v.toString();
    }
    function _fmtThreshold(v, unit) {
        if (v == null)
            return "—";
        if (unit === "%")
            return v + " %";
        if (unit === "days")
            return v + " j";
        if (unit === "count")
            return Math.round(v).toString();
        return v.toString();
    }
    function _fmtSource(src) {
        if (!src)
            return "";
        if (src === "auto")
            return t("pilot.kpi.src_auto_short");
        if (src.indexOf("manual:") === 0)
            return t("pilot.kpi.src_manual") + " · " + src.substring(7);
        if (src.indexOf("plugin:") === 0)
            return t("pilot.kpi.src_plugin") + " · " + src.substring(7);
        return src;
    }
    function _isAdmin() {
        return !!(window._currentUser && window._currentUser.role === "admin");
    }
    // ── AI framework suggestions (B4) ──────────────────────────────
    // undefined = not yet fetched, null = no provider configured, string = provider id
    var _aiProviderCache;
    function _aiProviderP() {
        if (_aiProviderCache !== undefined)
            return Promise.resolve(_aiProviderCache);
        return _fetch("/ai/config").then(function (cfg) {
            _aiProviderCache = (cfg && cfg.anthropic_configured) ? "anthropic"
                : (cfg && cfg.openai_configured) ? "openai" : null;
            return _aiProviderCache;
        }).catch(function () { _aiProviderCache = null; return null; });
    }
    // Tolerant JSON-array extraction from an LLM reply (strips code fences / prose).
    function _parseJsonArray(txt) {
        if (!txt)
            return [];
        var s = String(txt).replace(/```json/gi, "").replace(/```/g, "").trim();
        var a = s.indexOf("["), b = s.lastIndexOf("]");
        if (a >= 0 && b > a)
            s = s.substring(a, b + 1);
        try {
            var v = JSON.parse(s);
            return Array.isArray(v) ? v : [];
        }
        catch (e) {
            return [];
        }
    }
    function _kpiByCode(code) {
        return (_kpiData || []).filter(function (k) { return k.code === code; })[0];
    }
    function _numOrNull(id) {
        var v = document.getElementById(id).value;
        if (v === "")
            return null;
        var n = parseFloat(v);
        return isNaN(n) ? null : n;
    }
    // A framework is an identity, not a level: the tone only encodes a
    // difference of family. .kpi-fw-badge stays as a modifier (compact
    // rectangular chip), the background and the ink come from the base layer.
    var _FW_TONES = {
        "nist-csf-2": "info", "iso-27001-2022": "low", "cis-v8": "medium",
        "dora": "accent", "nis2": "critical", "iso-27004-2016": "info",
    };
    function _fwTone(framework) {
        return _FW_TONES[(framework || "").toLowerCase().replace(/_/g, "-")] || "neutral";
    }
    // ── Loaders ──────────────────────────────────────────────────────
    function _loadKpis() {
        return _fetch("/kpis").then(function (d) { _kpiData = d || []; });
    }
    function _reloadAndRerender() {
        return _loadKpis().then(function () {
            window._renderKpis(document.getElementById("content"));
        });
    }
    // ─────────────────────────────────────────────────────────────────
    // SYNTHETIC OVERVIEW
    // ─────────────────────────────────────────────────────────────────
    function _renderOverview() {
        var actives = _kpiData.filter(function (k) { return k.active; });
        var counts = { green: 0, amber: 0, red: 0, grey: 0 };
        var byCat = {};
        CAT_ORDER.forEach(function (c) { byCat[c] = []; });
        actives.forEach(function (k) {
            var hl = _kpiHealth(k);
            counts[hl.color]++;
            (byCat[k.category_primary] || (byCat[k.category_primary] = [])).push({
                code: k.code, color: hl.color, name: _kpiName(k)
            });
        });
        var total = actives.length;
        var donut = window._svgDonut({
            center_label: counts.green + "/" + total,
            segments: [
                { label: t("pilot.kpi.seg_compliant"), value: counts.green, color: "green" },
                { label: t("pilot.kpi.seg_watch"), value: counts.amber, color: "orange" },
                { label: t("pilot.kpi.seg_critical"), value: counts.red, color: "red" },
                { label: t("pilot.kpi.seg_no_data"), value: counts.grey, color: "gray" }
            ]
        }, { size: 160, thickness: 22 });
        // Posture score (same formula used by Pilot dashboard.py)
        var scoreTotal = counts.green * 100 + counts.amber * 50;
        var scoreDen = counts.green + counts.amber + counts.red;
        var postureScore = scoreDen > 0 ? Math.round(scoreTotal / scoreDen) : null;
        var postureLbl = postureScore == null ? t("pilot.kpi.seg_no_data") :
            (postureScore < 40 ? t("pilot.kpi.posture.faible") :
                postureScore < 60 ? t("pilot.kpi.posture.modere") :
                    postureScore < 80 ? t("pilot.kpi.posture.bon") : t("pilot.kpi.posture.excellent"));
        var h = '<div class="kpi-overview">';
        // Top row: donut + stats side by side
        h += '<div class="kpi-overview-top">';
        h += '<div class="kpi-overview-donut">' + donut + '</div>';
        h += '<div class="kpi-overview-stats">';
        h += '<div class="kpi-overview-headline">' + t("pilot.kpi.global_posture") + ' ' +
            (postureScore != null ? '<span class="kpi-overview-score">' + postureScore + '/100 · ' + esc(postureLbl) + '</span>' : '') +
            '</div>';
        h += '<div class="kpi-overview-stat-row">';
        h += '<span class="kpi-stat kpi-stat--green"><strong>' + counts.green + '</strong> ' + t("pilot.kpi.stat_compliant") + '</span>';
        h += '<span class="kpi-stat kpi-stat--amber"><strong>' + counts.amber + '</strong> ' + t("pilot.kpi.stat_watch") + '</span>';
        h += '<span class="kpi-stat kpi-stat--red"><strong>' + counts.red + '</strong> ' + t("pilot.kpi.stat_critical") + '</span>';
        h += '<span class="kpi-stat kpi-stat--grey"><strong>' + counts.grey + '</strong> ' + t("pilot.kpi.stat_no_data") + '</span>';
        h += '</div>';
        h += '</div>';
        h += '</div>';
        // Bottom row: full-width strip of NIST CSF functions as columns
        h += '<div class="kpi-overview-cats">';
        CAT_ORDER.forEach(function (cat) {
            var arr = byCat[cat] || [];
            h += '<div class="kpi-overview-cat">';
            h += '<div class="kpi-overview-cat-label">' + esc(_catLabel(cat)) +
                ' <span class="kpi-overview-cat-count">' + arr.length + '</span></div>';
            h += '<div class="kpi-overview-cat-strip">';
            if (!arr.length) {
                h += '<span class="kpi-overview-cat-empty">—</span>';
            }
            else {
                arr.forEach(function (item) {
                    h += '<span class="kpi-light kpi-light--' + item.color +
                        '" title="' + esc(item.name) +
                        '" data-click="_kpiOpenDetail" data-args=\'' + _da(item.code) + '\'></span>';
                });
            }
            h += '</div>';
            h += '</div>';
        });
        h += '</div>';
        h += '</div>';
        return h;
    }
    // ─────────────────────────────────────────────────────────────────
    // MAIN RENDER
    // ─────────────────────────────────────────────────────────────────
    window._renderKpis = function _renderKpis(c) {
        if (_kpiData == null) {
            c.innerHTML = '<h2>' + t("pilot.kpi.title") + '</h2><div class="ct-ta-c ct-p-8 ct-muted">' + t("pilot.kpi.loading") + '</div>';
            _loadKpis().then(function () { _renderKpis(c); });
            return;
        }
        var h = '<h2 class="ct-mb-2">' + t("pilot.kpi.title") + '</h2>';
        h += '<div class="ct-muted ct-text-meta ct-mb-4">' + t("pilot.kpi.intro") + '</div>';
        // Synthetic overview (only counts ACTIVE KPIs)
        h += _renderOverview();
        // Toolbar
        h += '<div class="kpi-toolbar">';
        h += '<select id="kpi-filter-status" class="ct-select ct-w-auto" data-change="_kpiSetFilter" data-args=\'["status"]\' data-pass-value="1">';
        h += '<option value="active"' + (_filterStatus === "active" ? " selected" : "") + '>' + t("pilot.kpi.filter_active_only") + '</option>';
        h += '<option value="inactive"' + (_filterStatus === "inactive" ? " selected" : "") + '>' + t("pilot.kpi.filter_inactive") + '</option>';
        h += '<option value="all"' + (_filterStatus === "all" ? " selected" : "") + '>' + t("pilot.kpi.filter_all") + '</option>';
        h += '</select>';
        h += '<select id="kpi-filter-cat" class="ct-select ct-w-auto" data-change="_kpiSetFilter" data-args=\'["cat"]\' data-pass-value="1">';
        h += '<option value="all"' + (_filterCat === "all" ? " selected" : "") + '>' + t("pilot.kpi.filter_all_cats") + '</option>';
        CAT_ORDER.forEach(function (k) {
            h += '<option value="' + k + '"' + (_filterCat === k ? " selected" : "") + '>' + esc(_catLabel(k)) + '</option>';
        });
        h += '</select>';
        h += '<select id="kpi-filter-fw" class="ct-select ct-w-auto" data-change="_kpiSetFilter" data-args=\'["fw"]\' data-pass-value="1">';
        h += '<option value="all"' + (_filterFw === "all" ? " selected" : "") + '>' + t("pilot.kpi.filter_all_fw") + '</option>';
        FW_ORDER.forEach(function (k) {
            h += '<option value="' + k + '"' + (_filterFw === k ? " selected" : "") + '>' + esc(FW_LABELS[k]) + '</option>';
        });
        h += '</select>';
        h += '<select id="kpi-filter-src" class="ct-select ct-w-auto" data-change="_kpiSetFilter" data-args=\'["src"]\' data-pass-value="1">';
        ['all', 'auto', 'external'].forEach(function (s) {
            var lbl = s === 'all' ? t("pilot.kpi.filter_all_src") : (s === 'auto' ? t("pilot.kpi.src_automatic") : t("pilot.kpi.src_manual_plugin"));
            h += '<option value="' + s + '"' + (_filterSrc === s ? " selected" : "") + '>' + lbl + '</option>';
        });
        h += '</select>';
        h += '<span class="ct-flex-1"></span>';
        if (_isAdmin()) {
            h += '<button class="ct-btn" data-click="_kpiAutoCompute">' + t("pilot.kpi.recompute_now") + '</button>';
            // Count inactive auto KPIs to badge the picker button.
            var inactAuto = _kpiData.filter(function (k) { return !k.active && k.source_type === "auto"; }).length;
            h += '<button class="ct-btn" data-click="_kpiOpenAutoPicker">' + t("pilot.kpi.add_auto");
            if (inactAuto > 0)
                h += ' <span class="ct-badge kpi-btn-badge" data-fill data-tone="info">' + inactAuto + '</span>';
            h += '</button>';
            h += '<button class="ct-btn" data-variant="primary" data-click="_kpiOpenCreate">' + t("pilot.kpi.add_custom") + '</button>';
        }
        h += '</div>';
        // Filter the catalogue
        var visible = _kpiData.filter(function (k) {
            if (_filterStatus === "active" && !k.active)
                return false;
            if (_filterStatus === "inactive" && k.active)
                return false;
            if (_filterCat !== "all" && k.category_primary !== _filterCat)
                return false;
            if (_filterSrc !== "all" && k.source_type !== _filterSrc)
                return false;
            if (_filterFw !== "all" && !(k.mappings || []).some(function (m) { return m.framework === _filterFw; }))
                return false;
            return true;
        });
        if (!visible.length) {
            h += '<div class="ct-p-8 ct-ta-c ct-muted">' + t("pilot.kpi.none_match") + '</div>';
            c.innerHTML = h;
            return;
        }
        var byCat = {};
        CAT_ORDER.forEach(function (k) { byCat[k] = []; });
        visible.forEach(function (k) {
            (byCat[k.category_primary] || (byCat[k.category_primary] = [])).push(k);
        });
        CAT_ORDER.forEach(function (cat) {
            var arr = byCat[cat];
            if (!arr || !arr.length)
                return;
            h += '<h3 class="kpi-cat-title">' + esc(_catLabel(cat)) + '</h3>';
            h += '<div class="kpi-grid">';
            arr.forEach(function (k) { h += _kpiCard(k); });
            h += '</div>';
        });
        c.innerHTML = h;
    };
    // ─────────────────────────────────────────────────────────────────
    // CARD
    // ─────────────────────────────────────────────────────────────────
    // True for indicators refreshed automatically (scheduler or a connector),
    // as opposed to manually-entered ones.
    function _kpiAutoSynced(k) {
        return k.source_type === "auto" || k.source_module === "connector";
    }
    // ISO timestamp → "DD/MM/YYYY HH:MM" in the viewer's local time.
    function _fmtSyncDate(iso) {
        if (!iso)
            return "";
        var d = new Date(iso);
        if (isNaN(d.getTime()))
            return iso.substring(0, 10);
        function p(n) { return (n < 10 ? "0" : "") + n; }
        return p(d.getDate()) + "/" + p(d.getMonth() + 1) + "/" + d.getFullYear()
            + " " + p(d.getHours()) + ":" + p(d.getMinutes());
    }
    // Compact card: title · value (with status) · thresholds. Click for details.
    // Migrated to the core .ct-kpi-adv primitive. Health→tone mapping:
    // green→low, amber→high, red→critical, grey→neutral (identical to the
    // legacy rendering, where amber used --ct-high and grey the muted ink).
    function _kpiCard(k) {
        var health = _kpiHealth(k);
        var valueStr = _fmtValue(k);
        var tone = health.color === "green" ? "low"
            : health.color === "amber" ? "high"
                : health.color === "red" ? "critical" : "neutral";
        var src = k.source_type === "auto" ? "auto" : "ext";
        var h = '<div class="ct-kpi-adv ct-clickable" data-tone="' + tone + '"'
            + (k.active ? '' : ' data-state="inactive"')
            + ' data-click="_kpiOpenDetail" data-args=\'' + _da(k.code) + '\' role="button" tabindex="0">';
        h += '<div class="ct-kpi-tone"></div>';
        h += '<div class="ct-kpi-adv-body">';
        h += '<div class="ct-kpi-adv-head"><div class="ct-kpi-adv-title">' + esc(_kpiName(k)) + '</div>';
        h += '<span class="ct-kpi-adv-src" data-src="' + src + '">' + (src === "auto" ? "AUTO" : "EXT") + '</span>';
        if (!k.active)
            h += '<span class="ct-kpi-adv-pill">' + t("pilot.kpi.inactive_badge") + '</span>';
        h += '</div>';
        h += '<div class="ct-kpi-adv-valrow"><span class="ct-kpi-adv-value">' + esc(valueStr) + '</span>';
        h += '<span class="ct-kpi-adv-status" data-tone="' + tone + '">' + esc(health.label) + '</span></div>';
        h += '<div class="ct-kpi-adv-meta">';
        h += '<span>' + t("pilot.kpi.target") + ' <b>' + esc(_fmtThreshold(k.target, k.unit)) + '</b></span>';
        h += '<span>' + t("pilot.kpi.amber") + ' <b>' + esc(_fmtThreshold(k.threshold_amber, k.unit)) + '</b></span>';
        h += '<span>' + t("pilot.kpi.red") + ' <b>' + esc(_fmtThreshold(k.threshold_red, k.unit)) + '</b></span>';
        h += '</div>';
        if (_kpiAutoSynced(k) && k.last_synced_at) {
            h += '<div class="ct-kpi-adv-foot">'
                + t("pilot.kpi.last_sync") + ' : ' + esc(_fmtSyncDate(k.last_synced_at)) + '</div>';
        }
        h += '</div>'; // /ct-kpi-adv-body
        h += '</div>'; // /ct-kpi-adv
        return h;
    }
    // ─────────────────────────────────────────────────────────────────
    // FILTERS
    // ─────────────────────────────────────────────────────────────────
    window._kpiSetFilter = function (field, value) {
        // When invoked from a link (no native value), the second arg is the
        // explicit value embedded in data-args; when from a select, it's the
        // pass-value. data-args carries either [field] or [field, value].
        if (field === "cat")
            _filterCat = value;
        else if (field === "fw")
            _filterFw = value;
        else if (field === "src")
            _filterSrc = value;
        else if (field === "status")
            _filterStatus = value;
        var c = document.getElementById("content");
        window._renderKpis(c);
    };
    // ─────────────────────────────────────────────────────────────────
    // UNIFIED DETAIL MODAL
    // ─────────────────────────────────────────────────────────────────
    window._kpiOpenDetail = function (code) {
        var k = _kpiByCode(code);
        if (!k)
            return;
        var cc = k.connector_config || {};
        // Fetch recent snapshots for sparkline + mini table; for awareness KPIs
        // also pull the per-campaign detail (overdue users) for the modal.
        var snapsP = _fetch("/kpis/" + encodeURIComponent(code) + "/snapshots?limit=30");
        var awP = (cc.detail === "awareness")
            ? _fetch("/awareness").catch(function () { return null; })
            : Promise.resolve(null);
        var aiP = _isAdmin() ? _aiProviderP() : Promise.resolve(null);
        Promise.all([snapsP, awP, aiP]).then(function (res) {
            var snaps = res[0] || [];
            var aw = res[1];
            var aiProvider = res[2] || null;
            var health = _kpiHealth(k);
            var awHtml = (aw && cc.campaign) ? _kpiAwarenessSection(aw, cc.campaign) : "";
            var body = _renderDetailBody(k, health, snaps, awHtml, aiProvider);
            ct_modal.open({
                title: _kpiName(k) + " · " + k.code,
                body: body,
                // "large" is not a ct_modal size ("lg" expected) → falls back to the default size.
                // Original bug kept as-is (iso-functional), logged in the P3b report.
                size: "large",
                buttons: _isAdmin()
                    ? [
                        { id: "cancel", label: t("pilot.action.cancel") },
                        { id: "save", label: t("pilot.action.save"), primary: true,
                            result: function () { return window._kpiDetailSaveTune(k.code); } }
                    ]
                    : [
                        { id: "close", label: t("pilot.action.close"), primary: true }
                    ]
            });
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
        });
    };
    // Awareness drill-down: the overdue users for THIS campaign (FEAT-18).
    function _kpiAwarenessSection(aw, campaignName) {
        var camps = (aw && aw.campaigns) || [];
        var c = null;
        for (var i = 0; i < camps.length; i++) {
            if (camps[i].name === campaignName) {
                c = camps[i];
                break;
            }
        }
        if (!c)
            return '';
        var col = _postureColor(Number(c.pct || 0), 100);
        var lateN = c.completed_late || 0;
        var notDone = c.overdue || 0;
        var h = '<div class="kpi-detail-section ct-mt-3">';
        h += '<div class="kpi-detail-section-title">' + t("pilot.kpi.detail") + ' — ' + esc(campaignName) + '</div>';
        h += '<div class="ct-text-data ct-muted ct-mb-2">'
            + '<strong style="color:' + col + '">' + (c.completed || 0) + ' / ' + (c.assigned || 0) + '</strong> ' + t("pilot.kpi.aw_completed")
            + (lateN ? ' · <strong class="ct-text-medium">' + lateN + ' ' + t("pilot.kpi.aw_late") + '</strong>' : '')
            + (notDone ? ' · <strong style="color:var(--danger,var(--ct-critical))">' + notDone + ' ' + (notDone > 1 ? t("pilot.kpi.aw_not_done_plural") : t("pilot.kpi.aw_not_done_singular")) + '</strong>' : '')
            + '</div>';
        if (c.due_date) {
            var sevTxt = c.severity === "red" ? t("pilot.kpi.sev_grace_imminent")
                : c.severity === "amber" ? t("pilot.kpi.sev_grace")
                    : t("pilot.kpi.sev_on_time");
            var sevCol = c.severity === "red" ? "var(--danger,var(--ct-critical))"
                : c.severity === "amber" ? "var(--ct-medium)" : "var(--ct-low)";
            h += '<div class="ct-text-meta ct-muted ct-mb-2">'
                + t("pilot.kpi.initial_due") + ' : <strong>' + esc(c.due_date) + '</strong>'
                + (c.grace_date ? ' · ' + t("pilot.kpi.grace_end") + ' : <strong>' + esc(c.grace_date) + '</strong>' : '')
                + ' · <span style="color:' + sevCol + '">' + esc(sevTxt) + '</span></div>';
        }
        var late = c.late_users || [];
        var ov = c.overdue_users || [];
        if (!late.length && !ov.length) {
            h += '<div class="ct-text-low ct-text-data">' + t("pilot.kpi.all_on_time") + '</div>';
        }
        else {
            h += '<table class="ct-journal-body ct-collapse ct-text-data"><thead><tr class="ct-ta-l ct-muted">';
            h += '<th class="ct-py-1 ct-px-2 ct-border-bottom">' + t("pilot.kpi.col_user") + '</th>';
            h += '<th class="ct-py-1 ct-px-2 ct-border-bottom">' + t("pilot.kpi.col_status") + '</th></tr></thead><tbody>';
            late.forEach(function (em) {
                h += '<tr><td class="ct-py-1 ct-px-2 ct-border-bottom-alt">' + esc(em) + '</td>'
                    + '<td class="ct-py-1 ct-px-2 ct-border-bottom-alt ct-text-medium">' + t("pilot.kpi.completed_late") + '</td></tr>';
            });
            ov.forEach(function (em) {
                h += '<tr><td class="ct-py-1 ct-px-2 ct-border-bottom-alt">' + esc(em) + '</td>'
                    + '<td style="padding:var(--ct-s1) var(--ct-s2);border-bottom:1px solid var(--ct-surface-2);color:var(--danger,var(--ct-critical))">' + t("pilot.kpi.not_completed") + '</td></tr>';
            });
            h += '</tbody></table>';
        }
        h += '</div>';
        return h;
    }
    function _renderDetailBody(k, health, snaps, awarenessHtml, aiProvider) {
        var h = '';
        // Header pills row
        h += '<div class="kpi-detail-pills">';
        h += '<span class="kpi-card-src kpi-card-src--' + (k.source_type === 'auto' ? 'auto' : 'ext') + '">' + (k.source_type === 'auto' ? 'AUTO' : 'EXT') + '</span>';
        h += '<span class="kpi-card-pill kpi-card-pill--' + (k.active ? 'active' : 'inactive') + '">' + (k.active ? t("pilot.kpi.active_badge") : t("pilot.kpi.inactive_badge")) + '</span>';
        h += '<span class="kpi-card-pill kpi-card-pill--cat">' + esc(_catLabel(k.category_primary)) + '</span>';
        h += '<span class="ct-flex-1"></span>';
        if (_isAdmin()) {
            var toggleLbl = k.active ? t("pilot.kpi.deactivate") : t("pilot.kpi.activate");
            h += '<button class="ct-btn" data-click="_kpiToggleActive" data-args=\'' + _da(k.code, !k.active) + '\'>' + toggleLbl + '</button>';
        }
        h += '</div>';
        if (_kpiDesc(k)) {
            h += '<div class="kpi-detail-desc">' + esc(_kpiDesc(k)) + '</div>';
        }
        // Big value
        h += '<div class="kpi-detail-value-row">';
        h += '<div class="kpi-card-value kpi-card-value--' + health.color + '">' + esc(_fmtValue(k));
        h += ' <span class="kpi-card-status kpi-card-status--' + health.color + '">' + esc(health.label) + '</span>';
        h += '</div>';
        h += '<div class="kpi-detail-thresholds">';
        h += '<span>' + t("pilot.kpi.target") + ': <strong>' + esc(_fmtThreshold(k.target, k.unit)) + '</strong></span>';
        h += '<span class="kpi-card-meta-amber">' + t("pilot.kpi.amber") + ': ' + esc(_fmtThreshold(k.threshold_amber, k.unit)) + '</span>';
        h += '<span class="kpi-card-meta-red">' + t("pilot.kpi.red") + ': ' + esc(_fmtThreshold(k.threshold_red, k.unit)) + '</span>';
        h += '</div>';
        h += '</div>';
        // Sparkline + mini history (last 10)
        if (snaps.length) {
            var chrono = snaps.slice().reverse();
            var points = chrono.map(function (s) { return s.value; });
            h += '<div class="kpi-detail-sparkline">' + window._svgSparkline(points, { width: 520, height: 60, color: 'blue' }) + '</div>';
            var recent = snaps.slice(0, 10);
            h += '<table class="ct-table kpi-history-table"><thead><tr><th>' + t("pilot.kpi.col_date") + '</th><th>' + t("pilot.kpi.col_value") + '</th><th>' + t("pilot.kpi.col_source") + '</th><th>' + t("pilot.kpi.col_note") + '</th></tr></thead><tbody>';
            recent.forEach(function (s) {
                h += '<tr>';
                h += '<td>' + esc((s.captured_at || "").substring(0, 16).replace("T", " ")) + '</td>';
                h += '<td><strong>' + esc(s.value.toString()) + '</strong></td>';
                h += '<td>' + esc(_fmtSource(s.source)) + '</td>';
                h += '<td class="ct-muted">' + esc(s.note || '') + '</td>';
                h += '</tr>';
            });
            h += '</tbody></table>';
            if (snaps.length > 10) {
                h += '<div class="ct-ta-r ct-mt-1"><a href="#" data-click="_kpiOpenHistory" data-args=\'' + _da(k.code) + '\'>' + t("pilot.kpi.view_full_history", { n: snaps.length }) + '</a></div>';
            }
        }
        else {
            h += '<div class="kpi-detail-empty">' + t("pilot.kpi.no_values_indicator") + '</div>';
        }
        // Connector drill-down (e.g. PSAT awareness: overdue / late users) —
        // shown right after the value/history, above the admin config sections.
        if (awarenessHtml)
            h += awarenessHtml;
        // Inline manual entry — only for genuinely-manual external KPIs (NOT
        // connector-fed auto KPIs, which get their value from the connector).
        // Admin only, mirrors require_admin on POST /api/kpis/{code}/manual.
        if (k.source_type === "external" && k.source_module !== "connector" && k.active && _isAdmin()) {
            h += '<div class="kpi-detail-section">';
            h += '<div class="kpi-detail-section-title">' + t("pilot.kpi.enter_value") + '</div>';
            h += '<div class="kpi-detail-manual">';
            h += '<input type="number" step="any" id="kpi-detail-value" class="ct-input ct-w-140" placeholder="' + esc(t("pilot.kpi.value_placeholder", { unit: k.unit })) + '">';
            h += '<input type="datetime-local" id="kpi-detail-ts" class="ct-input" style="width:200px">';
            h += '<input type="text" id="kpi-detail-note" class="ct-input ct-flex-1 ct-minw-120" placeholder="' + esc(t("pilot.kpi.note_optional")) + '">';
            h += '<button class="ct-btn" data-variant="primary" data-click="_kpiDetailSubmitManual" data-args=\'' + _da(k.code) + '\'>' + t("pilot.action.save") + '</button>';
            h += '</div>';
            h += '</div>';
        }
        // Framework anchors (with admin add/remove)
        h += '<div class="kpi-detail-section">';
        h += '<div class="kpi-detail-section-title">' + t("pilot.kpi.associated_frameworks") + '</div>';
        h += '<div class="kpi-detail-frameworks" id="kpi-detail-frameworks">';
        if (!(k.mappings || []).length) {
            h += '<span class="ct-muted ct-text-meta">' + t("pilot.kpi.no_associated_fw") + '</span>';
        }
        else {
            k.mappings.forEach(function (m, idx) {
                var lbl = FW_LABELS[m.framework] || m.framework;
                h += '<span class="ct-badge kpi-fw-badge kpi-fw-badge--with-action" data-tone="' + _fwTone(m.framework) + '" title="' + esc((m.label_fr || m.label_en || '')) + '">';
                h += esc(lbl) + ' · ' + esc(m.ref);
                if (_isAdmin()) {
                    h += ' <button class="kpi-fw-remove" data-click="_kpiRemoveMapping" data-args=\'' + _da(k.code, idx) + '\' title="' + esc(t("pilot.kpi.dissociate")) + '">×</button>';
                }
                h += '</span>';
            });
        }
        h += '</div>';
        if (_isAdmin()) {
            h += '<div class="kpi-detail-add-fw">';
            h += '<select id="kpi-detail-add-fw" class="ct-select ct-w-auto">';
            FW_ORDER.forEach(function (fw) {
                h += '<option value="' + fw + '">' + esc(FW_LABELS[fw]) + '</option>';
            });
            h += '</select>';
            h += '<input type="text" id="kpi-detail-add-ref" class="ct-input ct-w-160" placeholder="' + esc(t("pilot.kpi.ref_placeholder")) + '">';
            h += '<input type="text" id="kpi-detail-add-label" class="ct-input ct-flex-1 ct-minw-120" placeholder="' + esc(t("pilot.kpi.label_optional")) + '">';
            h += '<button class="ct-btn" data-size="xs" data-click="_kpiAddMapping" data-args=\'' + _da(k.code) + '\'>' + t("pilot.kpi.associate") + '</button>';
            h += '</div>';
            if (aiProvider) {
                h += '<div class="kpi-detail-ai-fw ct-mt-2">';
                h += '<button class="ct-btn btn-ai" data-click="_kpiSuggestFrameworks" data-args=\'' + _da(k.code, aiProvider) + '\'>' + t("pilot.kpi.ai_suggest_fw") + '</button>';
                h += '<div id="kpi-detail-ai-suggestions" class="ct-mt-2"></div>';
                h += '</div>';
            }
            h += '<div class="ct-text-label ct-muted ct-mt-1">' + t("pilot.kpi.fw_reaffirm_note") + '</div>';
        }
        h += '</div>';
        // Admin tuning
        if (_isAdmin()) {
            h += '<div class="kpi-detail-section">';
            h += '<div class="kpi-detail-section-title">' + t("pilot.kpi.settings_admin") + '</div>';
            h += '<div class="kpi-detail-tune">';
            h += '<label class="pilot-label">' + t("pilot.kpi.target") + '<input type="number" step="any" id="kpi-detail-target" class="ct-input" value="' + (k.target != null ? k.target : '') + '"></label>';
            h += '<label class="pilot-label">' + t("pilot.kpi.threshold_amber") + '<input type="number" step="any" id="kpi-detail-amber" class="ct-input" value="' + (k.threshold_amber != null ? k.threshold_amber : '') + '"></label>';
            h += '<label class="pilot-label">' + t("pilot.kpi.threshold_red") + '<input type="number" step="any" id="kpi-detail-red" class="ct-input" value="' + (k.threshold_red != null ? k.threshold_red : '') + '"></label>';
            h += '<div class="kpi-detail-tune-actions" style="display:flex;justify-content:flex-start;margin-top:var(--ct-s3)">';
            h += '<button class="ct-btn" data-variant="danger" data-click="_kpiDetailDelete" data-args=\'' + _da(k.code) + '\'>' + t("pilot.kpi.delete_indicator") + '</button>';
            h += '</div>';
            h += '</div>';
            h += '</div>';
        }
        return h;
    }
    // ─────────────────────────────────────────────────────────────────
    // ACTIONS (called from inside the detail modal)
    // ─────────────────────────────────────────────────────────────────
    window._kpiToggleActive = function (code, newValue) {
        if (!_isAdmin())
            return;
        _fetch("/kpis/" + encodeURIComponent(code), {
            method: "PATCH",
            body: { active: !!newValue }
        }).then(function () {
            showStatus(newValue ? t("pilot.kpi.msg_activated") : t("pilot.kpi.msg_deactivated"));
            // Close any open detail modal so the toggled card refreshes.
            if (window.ct_modal && ct_modal.close)
                ct_modal.close();
            return _reloadAndRerender();
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
        });
    };
    window._kpiDetailSubmitManual = function (code) {
        var v = document.getElementById("kpi-detail-value").value;
        if (v === "" || isNaN(parseFloat(v))) {
            ct_modal.alert({ title: t("pilot.kpi.invalid_value"), message: t("pilot.kpi.enter_number") });
            return;
        }
        var ts = document.getElementById("kpi-detail-ts").value;
        var note = document.getElementById("kpi-detail-note").value;
        var payload = { value: parseFloat(v) };
        if (ts)
            payload.captured_at = new Date(ts).toISOString();
        if (note)
            payload.note = note;
        _fetch("/kpis/" + encodeURIComponent(code) + "/manual", {
            method: "POST",
            body: payload
        }).then(function (r) {
            if (r && r.idempotent)
                showStatus(t("pilot.kpi.value_already_saved"));
            else
                showStatus(t("pilot.kpi.value_saved"));
            return _loadKpis().then(function () {
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                window._renderKpis(document.getElementById("content"));
                window._kpiOpenDetail(code); // re-open to reflect the new value
            });
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
        });
    };
    // Returns the save promise so the modal footer action closes on success
    // (resolve → ct_modal closes) and stays open on error (returns false).
    window._kpiDetailSaveTune = function (code) {
        var payload = {
            target: _numOrNull("kpi-detail-target"),
            threshold_amber: _numOrNull("kpi-detail-amber"),
            threshold_red: _numOrNull("kpi-detail-red")
        };
        return _fetch("/kpis/" + encodeURIComponent(code), {
            method: "PATCH", body: payload
        }).then(function () {
            showStatus(t("pilot.kpi.settings_saved"));
            return _loadKpis().then(function () {
                window._renderKpis(document.getElementById("content"));
            });
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
            return false;
        });
    };
    window._kpiDetailDelete = function (code) {
        ct_modal.confirm({
            title: t("pilot.kpi.delete_confirm_title"),
            message: t("pilot.kpi.delete_confirm_msg"),
            danger: true
        }).then(function (ok) {
            if (!ok)
                return;
            return _fetch("/kpis/" + encodeURIComponent(code), { method: "DELETE" }).then(function () {
                showStatus(t("pilot.kpi.msg_deleted"));
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                return _reloadAndRerender();
            });
        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); });
    };
    window._kpiRemoveMapping = function (code, idx) {
        if (!_isAdmin())
            return;
        var k = _kpiByCode(code);
        if (!k)
            return;
        var newMappings = (k.mappings || []).slice();
        newMappings.splice(idx, 1);
        // Send as MappingPayload[] — backend replaces the full set.
        _fetch("/kpis/" + encodeURIComponent(code), {
            method: "PATCH",
            body: { mappings: newMappings.map(_mappingToPayload) }
        }).then(function () {
            showStatus(t("pilot.kpi.msg_fw_dissociated"));
            return _loadKpis().then(function () {
                window._renderKpis(document.getElementById("content"));
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                window._kpiOpenDetail(code);
            });
        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); });
    };
    window._kpiAddMapping = function (code) {
        if (!_isAdmin())
            return;
        var k = _kpiByCode(code);
        if (!k)
            return;
        var fw = document.getElementById("kpi-detail-add-fw").value;
        var ref = (document.getElementById("kpi-detail-add-ref").value || "").trim();
        var label = (document.getElementById("kpi-detail-add-label").value || "").trim();
        if (!ref) {
            ct_modal.alert({ title: t("pilot.kpi.ref_missing_title"), message: t("pilot.kpi.ref_missing_msg") });
            return;
        }
        var newMappings = (k.mappings || []).map(_mappingToPayload);
        newMappings.push({
            framework: fw,
            ref: ref,
            label_fr: label || null,
            label_en: null
        });
        _fetch("/kpis/" + encodeURIComponent(code), {
            method: "PATCH",
            body: { mappings: newMappings }
        }).then(function () {
            showStatus(t("pilot.kpi.msg_fw_associated"));
            return _loadKpis().then(function () {
                window._renderKpis(document.getElementById("content"));
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                window._kpiOpenDetail(code);
            });
        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); });
    };
    function _mappingToPayload(m) {
        return {
            framework: m.framework,
            ref: m.ref,
            label_fr: m.label_fr || null,
            label_en: m.label_en || null
        };
    }
    // B4: ask the (backend-proxied) AI to propose framework mappings for a KPI.
    window._kpiSuggestFrameworks = function (code, provider) {
        if (!_isAdmin())
            return;
        var k = _kpiByCode(code);
        if (!k)
            return;
        var out = document.getElementById("kpi-detail-ai-suggestions");
        if (out)
            out.innerHTML = '<span class="ct-muted ct-text-data">' + esc(t("pilot.kpi.ai_analyzing")) + '</span>';
        var fwList = FW_ORDER.map(function (f) { return f + " (" + (FW_LABELS[f] || f) + ")"; }).join(", ");
        var system = "Tu es expert GRC (gouvernance, risque, conformité). On te donne un indicateur de sécurité (KPI). "
            + "Propose les exigences de référentiels les plus pertinentes à lui associer. "
            + "Réponds UNIQUEMENT par un tableau JSON d'objets "
            + '{"framework":"<code>","ref":"<référence exacte>","label":"<intitulé court>"}, sans aucun texte autour. '
            + "framework doit être l'un de : " + fwList + ". "
            + "Donne au plus 6 propositions, les plus précises possibles (ex: ISO A.5.31, NIST PR.AT-01).";
        var existing = (k.mappings || []).map(function (m) { return m.framework + " " + m.ref; }).join("; ");
        var user = "KPI : " + (k.name_fr || k.code)
            + "\nCatégorie : " + (k.category_primary || "")
            + "\nUnité : " + (k.unit || "")
            + "\nDescription : " + (k.description_fr || "")
            + "\nDéjà associés (ne pas répéter) : " + (existing || "aucun");
        _fetch("/ai/complete", { method: "POST", body: { system: system, user: user, provider: provider } })
            .then(function (res) {
            var arr = _parseJsonArray((res && res.text) || "");
            var seen = {};
            (k.mappings || []).forEach(function (m) { seen[m.framework + "|" + m.ref] = true; });
            var h = '';
            var n = 0;
            arr.forEach(function (s) {
                if (!s || !s.framework || !s.ref)
                    return;
                if (FW_ORDER.indexOf(s.framework) < 0)
                    return;
                if (seen[s.framework + "|" + s.ref])
                    return;
                n++;
                h += '<label style="display:flex;align-items:center;gap:var(--ct-s2);margin:var(--ct-s1) 0;font-size:var(--ct-text-data);cursor:pointer">';
                h += '<input type="checkbox" class="kpi-ai-sugg" checked data-ai-fw="' + esc(s.framework) + '" data-ai-ref="' + esc(s.ref) + '" data-ai-label="' + esc(String(s.label || "")) + '">';
                h += '<span class="ct-badge kpi-fw-badge" data-tone="' + _fwTone(s.framework) + '">' + esc(FW_LABELS[s.framework] || s.framework) + ' · ' + esc(s.ref) + '</span>';
                if (s.label)
                    h += '<span class="ct-muted">' + esc(String(s.label)) + '</span>';
                h += '</label>';
            });
            if (n) {
                h += '<button class="ct-btn ct-mt-2" data-variant="primary" data-size="xs" data-click="_kpiAddSelectedMappings" data-args=\'' + _da(code) + '\'>' + t("pilot.kpi.associate_selection") + '</button>';
            }
            if (out)
                out.innerHTML = h || '<span class="ct-muted ct-text-data">' + esc(t("pilot.kpi.ai_no_new_suggestions")) + '</span>';
        })
            .catch(function (e) {
            if (out)
                out.innerHTML = '<span style="color:var(--danger,var(--ct-critical));font-size:var(--ct-text-data)">' + esc(t("pilot.kpi.ai_error")) + ' : ' + esc(String(e && e.message || e)) + '</span>';
        });
    };
    // Add ALL checked AI-suggested mappings at once (single KPI PATCH).
    window._kpiAddSelectedMappings = function (code) {
        if (!_isAdmin())
            return;
        var k = _kpiByCode(code);
        if (!k)
            return;
        var boxes = document.querySelectorAll("input.kpi-ai-sugg:checked");
        if (!boxes.length) {
            ct_modal.alert({ title: t("pilot.kpi.no_selection_title"), message: t("pilot.kpi.no_selection_msg") });
            return;
        }
        var newMappings = (k.mappings || []).map(_mappingToPayload);
        var seen = {};
        newMappings.forEach(function (m) { seen[m.framework + "|" + m.ref] = true; });
        var added = 0;
        Array.prototype.forEach.call(boxes, function (b) {
            var fw = b.getAttribute("data-ai-fw");
            var ref = b.getAttribute("data-ai-ref");
            var lbl = b.getAttribute("data-ai-label") || "";
            if (!fw || !ref || seen[fw + "|" + ref])
                return;
            seen[fw + "|" + ref] = true;
            added++;
            newMappings.push({ framework: fw, ref: ref, label_fr: lbl || null, label_en: null });
        });
        _fetch("/kpis/" + encodeURIComponent(code), { method: "PATCH", body: { mappings: newMappings } })
            .then(function () {
            showStatus(t("pilot.kpi.msg_n_fw_associated", { n: added }));
            return _loadKpis().then(function () {
                window._renderKpis(document.getElementById("content"));
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                window._kpiOpenDetail(code);
            });
        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); });
    };
    // ─────────────────────────────────────────────────────────────────
    // Legacy entry points (kept for the "Voir l'historique complet" link
    // and the create modal).
    // ─────────────────────────────────────────────────────────────────
    window._kpiOpenHistory = function (code) {
        var k = _kpiByCode(code);
        if (!k)
            return;
        _fetch("/kpis/" + encodeURIComponent(code) + "/snapshots?limit=500").then(function (snaps) {
            snaps = snaps || [];
            var body = '<div class="ct-text-meta ct-muted ct-mb-3">' + esc(_kpiName(k)) + '</div>';
            if (!snaps.length) {
                body += '<div class="ct-p-5 ct-ta-c ct-muted">' + t("pilot.kpi.no_values") + '</div>';
            }
            else {
                var chrono = snaps.slice().reverse();
                var points = chrono.map(function (s) { return s.value; });
                body += '<div class="ct-mb-3">' + window._svgSparkline(points, { width: 600, height: 80, color: 'blue' }) + '</div>';
                body += '<table class="ct-table kpi-history-table"><thead><tr><th>' + t("pilot.kpi.col_date") + '</th><th>' + t("pilot.kpi.col_value") + '</th><th>' + t("pilot.kpi.col_source") + '</th><th>' + t("pilot.kpi.col_note") + '</th></tr></thead><tbody>';
                snaps.forEach(function (s) {
                    body += '<tr>';
                    body += '<td>' + esc((s.captured_at || "").substring(0, 16).replace("T", " ")) + '</td>';
                    body += '<td><strong>' + esc(s.value.toString()) + '</strong></td>';
                    body += '<td>' + esc(_fmtSource(s.source)) + '</td>';
                    body += '<td class="ct-muted">' + esc(s.note || '') + '</td>';
                    body += '</tr>';
                });
                body += '</tbody></table>';
            }
            ct_modal.open({
                title: t("pilot.kpi.history") + " · " + (_kpiName(k) || code),
                body: body,
                // Same: "large" unknown to ct_modal — original bug kept.
                size: "large",
                buttons: [{ id: "close", label: t("pilot.action.close"), primary: true }]
            });
        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); });
    };
    // ─────────────────────────────────────────────────────────────────
    // AUTO PICKER (admin) — activate one of the catalogue's inactive auto KPIs
    // ─────────────────────────────────────────────────────────────────
    window._kpiOpenAutoPicker = function () {
        if (!_isAdmin())
            return;
        var pool = _kpiData.filter(function (k) { return !k.active && k.source_type === "auto"; });
        // Group by category for readability.
        var byCat = {};
        CAT_ORDER.forEach(function (c) { byCat[c] = []; });
        pool.forEach(function (k) { (byCat[k.category_primary] || (byCat[k.category_primary] = [])).push(k); });
        var body = '';
        body += '<div class="ct-muted ct-text-meta ct-mb-3">';
        body += t("pilot.kpi.picker_intro");
        body += '</div>';
        if (!pool.length) {
            body += '<div class="ct-p-6 ct-ta-c ct-muted">';
            body += t("pilot.kpi.picker_all_active");
            body += '</div>';
        }
        else {
            CAT_ORDER.forEach(function (cat) {
                var arr = byCat[cat] || [];
                if (!arr.length)
                    return;
                body += '<div class="kpi-picker-cat">';
                body += '<div class="kpi-picker-cat-title">' + esc(_catLabel(cat)) + '</div>';
                arr.forEach(function (k) {
                    body += '<div class="kpi-picker-row">';
                    body += '<div class="kpi-picker-row-main">';
                    body += '<div class="kpi-picker-row-title">' + esc(_kpiName(k)) + '</div>';
                    if (_kpiDesc(k)) {
                        body += '<div class="kpi-picker-row-desc">' + esc(_kpiDesc(k)) + '</div>';
                    }
                    if ((k.mappings || []).length) {
                        body += '<div class="kpi-picker-row-fw">';
                        k.mappings.forEach(function (m) {
                            var lbl = FW_LABELS[m.framework] || m.framework;
                            body += '<span class="ct-badge kpi-fw-badge" data-tone="' + _fwTone(m.framework) + '">' + esc(lbl) + ' · ' + esc(m.ref) + '</span>';
                        });
                        body += '</div>';
                    }
                    body += '</div>';
                    body += '<button class="ct-btn" data-variant="primary" data-click="_kpiPickerActivate" data-args=\'' + _da(k.code) + '\'>' + t("pilot.kpi.activate") + '</button>';
                    body += '</div>';
                });
                body += '</div>';
            });
        }
        ct_modal.open({
            title: t("pilot.kpi.picker_title"),
            body: body,
            // Same: "large" unknown to ct_modal — original bug kept.
            size: "large",
            buttons: [{ id: "close", label: t("pilot.action.close"), primary: true }]
        });
    };
    window._kpiPickerActivate = function (code) {
        if (!_isAdmin())
            return;
        _fetch("/kpis/" + encodeURIComponent(code), {
            method: "PATCH",
            body: { active: true }
        }).then(function () {
            showStatus(t("pilot.kpi.msg_activated"));
            return _loadKpis().then(function () {
                window._renderKpis(document.getElementById("content"));
                // Re-open the picker so the admin can activate several in one go.
                if (window.ct_modal && ct_modal.close)
                    ct_modal.close();
                window._kpiOpenAutoPicker();
            });
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
        });
    };
    // ─────────────────────────────────────────────────────────────────
    // CREATE custom KPI (admin)
    // ─────────────────────────────────────────────────────────────────
    window._kpiOpenCreate = function () {
        if (!_isAdmin())
            return;
        var body = '';
        body += '<div class="ct-grid ct-grid-2 ct-gap-2">';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_code") + '</label><input type="text" id="kpi-new-code" class="ct-input ct-w-full" placeholder="' + esc(t("pilot.kpi.code_placeholder")) + '"></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_category") + '</label><select id="kpi-new-cat" class="ct-select ct-w-full">' +
            CAT_ORDER.map(function (c) { return '<option value="' + c + '">' + esc(_catLabel(c)) + '</option>'; }).join('') + '</select></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_name_fr") + '</label><input type="text" id="kpi-new-name-fr" class="ct-input ct-w-full"></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_name_en") + '</label><input type="text" id="kpi-new-name-en" class="ct-input ct-w-full"></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_unit") + '</label><select id="kpi-new-unit" class="ct-select ct-w-full">' +
            ['%', 'count', 'days', 'score', 'currency', 'ratio'].map(function (u) { return '<option value="' + u + '">' + u + '</option>'; }).join('') + '</select></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_direction") + '</label><select id="kpi-new-dir" class="ct-select ct-w-full"><option value="higher_better">' + t("pilot.kpi.dir_higher") + '</option><option value="lower_better">' + t("pilot.kpi.dir_lower") + '</option></select></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.field_source") + '</label><select id="kpi-new-src" class="ct-select ct-w-full"><option value="external">' + t("pilot.kpi.src_manual_plugin") + '</option><option value="auto">' + t("pilot.kpi.src_auto_stats") + '</option></select></div>';
        body += '<div><label class="pilot-label">' + t("pilot.kpi.target") + '</label><input type="number" step="any" id="kpi-new-target" class="ct-input ct-w-full"></div>';
        body += '</div>';
        ct_modal.open({
            title: t("pilot.kpi.create_title"),
            body: body,
            buttons: [
                { id: "cancel", label: t("pilot.action.cancel") },
                {
                    id: "save", label: t("pilot.kpi.create"), primary: true,
                    result: function () {
                        var code = (document.getElementById("kpi-new-code").value || "").trim();
                        var nameFr = (document.getElementById("kpi-new-name-fr").value || "").trim();
                        var nameEn = (document.getElementById("kpi-new-name-en").value || "").trim() || nameFr;
                        if (!code || !nameFr) {
                            ct_modal.alert({ title: t("pilot.kpi.required_fields_title"), message: t("pilot.kpi.required_fields_msg") });
                            return false;
                        }
                        var payload = {
                            code: code, name_fr: nameFr, name_en: nameEn,
                            category_primary: document.getElementById("kpi-new-cat").value,
                            unit: document.getElementById("kpi-new-unit").value,
                            direction: document.getElementById("kpi-new-dir").value,
                            source_type: document.getElementById("kpi-new-src").value,
                            target: _numOrNull("kpi-new-target"),
                            mappings: []
                        };
                        return _fetch("/kpis", { method: "POST", body: payload }).then(function () {
                            showStatus(t("pilot.kpi.msg_created"));
                            return _reloadAndRerender();
                        }).catch(function (e) { ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) }); return false; });
                    }
                }
            ]
        });
    };
    // ─────────────────────────────────────────────────────────────────
    // AUTO-COMPUTE
    // ─────────────────────────────────────────────────────────────────
    window._kpiAutoCompute = function () {
        if (!_isAdmin())
            return;
        showStatus(t("pilot.kpi.recompute_running"));
        _fetch("/kpis/auto-compute", { method: "POST" }).then(function (r) {
            showStatus(t("pilot.kpi.recompute_done", { computed: (r.computed || 0), skipped: (r.skipped || 0) }));
            return _reloadAndRerender();
        }).catch(function (e) {
            ct_modal.alert({ title: t("pilot.kpi.error"), message: String(e) });
        });
    };
    window._kpiResetCache = function () { _kpiData = null; };
})();
