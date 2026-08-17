/**
 * Pilot Connectors panel — centralised view of every third-party connector
 * declared by suite modules. See docs/CHANTIER_CONNECTEURS.md.
 *
 * Backend contract (Pilot aggregator at /api/admin/connectors/*):
 *   GET    /api/admin/connectors                 — aggregate by type
 *   GET    /api/admin/connectors/{id}            — single type detail
 *   PUT    /api/admin/connectors/{id}            — write + fan-out to consumers
 *   POST   /api/admin/connectors/{id}/test       — probe first consumer
 *   POST   /api/admin/connectors/{id}/run        — fan-out run
 *
 * The PUT body is the same shape every connector accepts: a partial map
 * of field-id → string. Secret fields with the placeholder "configured"
 * are preserved (the actual value is never returned to the browser).
 *
 * UX
 * --
 * Top of panel: title + recap of how many connector types are configured.
 * Below: a grid of cards, one per connector TYPE. Each card shows the
 * connector name (FR/EN from the schema), the list of consumer module
 * ids ("Utilisé par : Pilot, Access, AppSec"), the configured/not
 * configured status, and three actions: Configurer (schema-driven modal),
 * Tester, Recalculer.
 */
(function() {
"use strict";

// Lightweight HTML escape (the page already loads cisotoolbox.js which
// defines a global `esc`; we still define a fallback so this file works
// in isolation during dev).
function _e(s: any) { if (typeof esc === "function") return esc(s); return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"} as Record<string, string>)[c]; }); }

function _isAdmin() {
    return !!(window._currentUser && window._currentUser.role === "admin");
}

function _t(obj: CtConnLabel | null | undefined) {
    // Re-use the shared connectors_common helper if loaded
    if (typeof window._connT === "function") return window._connT(obj);
    if (!obj) return "";
    if (typeof obj === "string") return obj;
    var l = window._locale || "fr";
    return obj[l] || obj.fr || obj.en || "";
}

// Cached aggregator response so multiple actions don't re-fetch
var _aggCache: PilotConnAggregate | null = null;
// Active module filter for the connectors list ("all" or a module id)
var _connFilter = "all";
// Preferred display order for module sections
var MODULE_ORDER = ["pilot", "access", "asset", "surface", "appsec", "watch", "risk", "vendor", "compliance"];

// Functional label for the connector category (what the connector feeds),
// not the raw module id.
var MODULE_LABELS: Record<string, string> = {
    pilot: "pilot.connectors.module.pilot",
    access: "pilot.connectors.module.access",
    asset: "pilot.connectors.module.asset",
    surface: "pilot.connectors.module.surface",
    appsec: "pilot.connectors.module.appsec",
    watch: "pilot.connectors.module.watch",
    risk: "pilot.connectors.module.risk",
    vendor: "pilot.connectors.module.vendor",
    compliance: "pilot.connectors.module.compliance"
};
function _moduleLabel(m: string) {
    if (!m) return "—";
    return MODULE_LABELS[m] ? t(MODULE_LABELS[m]) : (m.charAt(0).toUpperCase() + m.slice(1));
}

// Group connectors by the modules that consume them (a multi-consumer
// connector lands in every matching module section).
function _groupByModule(list: PilotConnEntry[]) {
    var byMod: Record<string, PilotConnEntry[]> = {}, mods: string[] = [];
    list.forEach(function(conn) {
        var cs = (conn.consumers && conn.consumers.length) ? conn.consumers : ["—"];
        cs.forEach(function(m) {
            if (!byMod[m]) { byMod[m] = []; mods.push(m); }
            byMod[m].push(conn);
        });
    });
    mods.sort(function(a, b) {
        var ia = MODULE_ORDER.indexOf(a), ib = MODULE_ORDER.indexOf(b);
        if (ia < 0) ia = 99;
        if (ib < 0) ib = 99;
        return ia - ib || a.localeCompare(b);
    });
    return { byMod: byMod, mods: mods };
}

function _connGrid(conns: PilotConnEntry[]) {
    var h = '<div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(360px, 1fr));gap:var(--ct-s3)">';
    conns.forEach(function(conn) { h += _renderCard(conn); });
    return h + '</div>';
}

function _renderFilterBar(g: { byMod: Record<string, PilotConnEntry[]>; mods: string[] }, total: number) {
    function chip(key: string, label: string, count: number, active: boolean) {
        var bg = active ? "var(--ct-ink)" : "var(--ct-surface)";
        var col = active ? "var(--ct-surface)" : "var(--ct-ink)";
        return '<button data-click="_connSetFilter" data-args=\'["' + _e(key) + '"]\' '
            + 'style="border:1px solid var(--ct-line);background:' + bg + ';color:' + col
            + ';border-radius:999px;padding:5px 14px;font-size:var(--ct-text-data);font-weight:600;cursor:pointer">'
            + _e(label) + ' <span style="opacity:.65">' + count + '</span></button>';
    }
    var h = '<div class="ct-flex ct-gap-2 ct-row-wrap ct-mb-4">';
    h += chip("all", t("pilot.connectors.filter.all"), total, _connFilter === "all");
    g.mods.forEach(function(m) { h += chip(m, _moduleLabel(m), g.byMod[m].length, _connFilter === m); });
    h += '</div>';
    return h;
}

window._connSetFilter = function(mod: string) {
    _connFilter = mod || "all";
    var c = document.getElementById("content");
    if (c) window._renderConnectors!(c);
};

async function _loadAggregate() {
    var r = await fetch("api/admin/connectors", { credentials: "same-origin" });
    if (r.status === 401) { window.location.href = "/login.html"; return null; }
    if (!r.ok) throw new Error("HTTP " + r.status);
    _aggCache = await r.json();
    return _aggCache;
}

function _consumerLabel(ids: string[] | undefined) {
    if (!ids || !ids.length) return "—";
    return ids.map(function(s) { return s.charAt(0).toUpperCase() + s.slice(1); }).join(", ");
}

function _renderCard(conn: PilotConnEntry) {
    var schema = conn.schema || {};
    var name = _t(schema.name) || conn.id;
    var desc = _t(schema.description);
    var cardinality = conn.cardinality || schema.cardinality || "one";
    var isMulti = cardinality === "many";

    // Status: configured = at least one instance configured for multi, or
    // the singleton is configured.
    var statusLabel, statusColor;
    if (isMulti) {
        var nInstances = (conn.instances || []).length;
        var nConfigured = (conn.instances || []).filter(function(i) { return i.configured; }).length;
        statusLabel = nInstances === 0 ? t("pilot.connectors.status.no_instance")
            : t(nConfigured > 1 ? "pilot.connectors.status.configured_count_plural" : "pilot.connectors.status.configured_count", { n: nConfigured, total: nInstances });
        statusColor = nConfigured > 0 ? "var(--ct-low)" : "var(--ct-ink-2)";
    } else {
        statusLabel = conn.configured ? t("pilot.connectors.status.configured") : t("pilot.connectors.status.not_configured");
        statusColor = conn.configured ? "var(--ct-low)" : "var(--ct-ink-2)";
    }

    var h = '';
    h += '<div class="conn-card">';
    h += '  <div style="display:flex;align-items:start;justify-content:space-between;gap:var(--ct-s2)">';
    h += '    <div>';
    h += '      <div class="ct-text-section ct-bold ct-ink">' + _e(name) + '</div>';
    h += '      <div class="ct-text-meta ct-muted ct-mt-1">' + _e(t("pilot.connectors.used_by")) + ' ' + _e(_consumerLabel(conn.consumers)) + '</div>';
    h += '    </div>';
    h += '    <div style="font-size:var(--ct-text-label);font-weight:700;color:' + statusColor + ';padding:4px 10px;border:1px solid ' + statusColor + ';border-radius:999px;white-space:nowrap">' + _e(statusLabel) + '</div>';
    h += '  </div>';
    if (desc) {
        h += '  <div style="font-size:var(--ct-text-data);color:var(--ct-ink-2);line-height:1.4">' + _e(desc) + '</div>';
    }

    if (isMulti) {
        h += _renderInstanceList(conn);
    } else {
        h += '  <div style="display:flex;gap:var(--ct-s2);flex-wrap:wrap;margin-top:auto;padding-top:8px">';
        h += '    <button class="ct-btn" data-variant="primary" data-click="_connOpenConfig" data-args=\'["' + _e(conn.id) + '"]\'>' + _e(t("pilot.connectors.configure")) + '</button>';
        if ((schema.capabilities || []).indexOf("test") >= 0) {
            h += '    <button class="ct-btn" data-click="_connRunTest" data-args=\'["' + _e(conn.id) + '"]\'>' + _e(t("pilot.connectors.test")) + '</button>';
        }
        if ((schema.capabilities || []).indexOf("run") >= 0) {
            h += '    <button class="ct-btn" data-click="_connRunNow" data-args=\'["' + _e(conn.id) + '"]\'>' + _e(t("pilot.connectors.recompute")) + '</button>';
        }
        if (conn.configured) {
            h += '    <button class="ct-btn" data-variant="ghost" data-click="_connDeleteConfig" data-args=\'["' + _e(conn.id) + '"]\' style="color:var(--danger,var(--ct-critical))">' + _e(t("pilot.connectors.delete_config")) + '</button>';
        }
        h += '    <span class="conn-result" data-conn-result="' + _e(conn.id) + '"></span>';
        h += '  </div>';
    }
    h += '</div>';
    return h;
}

function _renderInstanceList(conn: PilotConnEntry) {
    var instances = conn.instances || [];
    var h = '<div style="border-top:1px solid var(--ct-line);margin-top:var(--ct-s1);padding-top:10px;display:flex;flex-direction:column;gap:var(--ct-s1)">';
    if (!instances.length) {
        h += '<div class="ct-text-meta ct-journal-sep ct-italic">';
        h += _e(t("pilot.connectors.no_instance_configured"));
        h += '</div>';
    } else {
        instances.forEach(function(inst) {
            var iid = inst.id || "";
            var owner = inst._owner || "";
            var label = inst.label || iid;
            var projLabel = inst.project_id ? ' · ' + t("pilot.connectors.project") + ' ' + inst.project_id.substr(0, 8) : '';
            var enabled = inst.enabled ? '' : t("pilot.connectors.disabled_suffix");
            var statusColor = inst.configured ? "var(--ct-low)" : "var(--ct-ink-2)";
            // encodeURIComponent on instance_id since it contains a colon
            var encId = encodeURIComponent(iid);
            h += '<div class="ct-flex ct-items-center ct-gap-2 ct-text-data ct-py-1 ct-px-2 ct-bg-alt ct-r-md">';
            h += '  <div style="flex:1;min-width:0">';
            h += '    <div class="ct-strong ct-ink">' + _e(label) + '<span class="ct-muted">' + _e(enabled) + '</span></div>';
            h += '    <div class="ct-text-label ct-muted">' + _e(owner) + _e(projLabel) + '</div>';
            h += '  </div>';
            h += '  <div style="font-size:var(--ct-text-label);color:' + statusColor + ';font-weight:700;white-space:nowrap">' + (inst.configured ? '●' : '○') + '</div>';
            h += '  <button class="ct-btn ct-text-label ct-py-1 ct-px-2" data-variant="ghost" data-click="_connOpenInstance" data-args=\'["' + _e(conn.id) + '","' + _e(owner) + '","' + _e(iid) + '"]\'>' + _e(t("pilot.connectors.configure")) + '</button>';
            h += '  <button class="ct-btn ct-text-label ct-py-1 ct-px-2" data-variant="ghost" data-click="_connTestInstance" data-args=\'["' + _e(conn.id) + '","' + _e(owner) + '","' + _e(iid) + '"]\'>' + _e(t("pilot.connectors.test_short")) + '</button>';
            h += '  <span data-conn-result="' + _e(conn.id) + '__' + _e(iid) + '" class="ct-text-label ct-muted"></span>';
            h += '</div>';
        });
    }
    h += '<div class="ct-mt-1">';
    h += '  <button class="ct-btn ct-text-meta ct-py-1 ct-px-3" data-click="_connNewInstance" data-args=\'["' + _e(conn.id) + '"]\'>' + _e(t("pilot.connectors.new_instance_btn")) + '</button>';
    h += '</div>';
    h += '</div>';
    return h;
}

window._renderConnectors = function(c: HTMLElement) {
    if (!_isAdmin()) {
        c.innerHTML = '<div class="ct-p-5 ct-muted">' + _e(t("pilot.connectors.admin_only")) + '</div>';
        return;
    }
    c.innerHTML = '<div class="ct-p-5 ct-muted">' + _e(t("pilot.connectors.loading")) + '</div>';
    _loadAggregate().then(function(data) {
        var list = (data && data.connectors) || [];
        var h = '';
        h += '<div style="padding:var(--ct-s5);max-width:1280px;margin:0 auto">';
        h += '  <div style="display:flex;align-items:end;justify-content:space-between;margin-bottom:var(--ct-s4)">';
        h += '    <div>';
        h += '      <h1 class="ct-m-0 ct-text-page ct-ink">' + _e(t("pilot.connectors.title")) + '</h1>';
        h += '      <div class="ct-text-data ct-muted ct-mt-1">';
        h += _e(t("pilot.connectors.subtitle"));
        h += '      </div>';
        h += '    </div>';
        h += '    <div class="ct-text-meta ct-muted">' + _e(t("pilot.connectors.types_declared", { n: list.length })) + '</div>';
        h += '  </div>';
        if (!list.length) {
            h += '<div class="ct-bg-surface ct-bordered ct-r-xl ct-p-8 ct-ta-c ct-muted">';
            h += _e(t("pilot.connectors.none_declared"));
            h += '</div>';
        } else {
            var g = _groupByModule(list);
            // Reset a stale filter that points to a module no longer present.
            if (_connFilter !== "all" && g.mods.indexOf(_connFilter) < 0) _connFilter = "all";
            h += _renderFilterBar(g, list.length);
            if (_connFilter === "all") {
                g.mods.forEach(function(m) {
                    h += '<h2 style="font-size:var(--ct-text-body);color:var(--ct-ink);margin:var(--ct-s4) 0 var(--ct-s2);font-weight:700">'
                       + _e(_moduleLabel(m))
                       + ' <span style="color:var(--ct-ink-2);font-weight:500">· ' + g.byMod[m].length + '</span></h2>';
                    h += _connGrid(g.byMod[m]);
                });
            } else {
                h += _connGrid(g.byMod[_connFilter] || []);
            }
        }
        h += '</div>';
        c.innerHTML = h;
    }).catch(function(e) {
        c.innerHTML = '<div style="padding:var(--ct-s5);color:var(--danger,var(--ct-critical))">' + _e(t("pilot.connectors.load_error")) + ' ' + _e(String(e && e.message || e)) + '</div>';
    });
};

window._connOpenConfig = function(id: string) {
    var entry = (_aggCache && _aggCache.connectors || []).find(function(x) { return x.id === id; });
    if (!entry) { return; }
    var schema = entry.schema || {};
    var currentLabel = _t(schema.name) || id;

    var prereqHtml = '';
    // prereqs.graph_permissions n'est pas dans le type partagé CtConnSchema — cast localisé.
    var pre: any = schema.prereqs || {};
    if (pre.graph_permissions && pre.graph_permissions.length) {
        prereqHtml += '<div class="ct-bg-alt ct-bordered ct-r-lg ct-py-2 ct-px-3 ct-mb-3 ct-text-meta ct-muted">';
        prereqHtml += '<div class="ct-strong ct-ink ct-mb-1">' + _e(t("pilot.connectors.perms_required")) + '</div>';
        prereqHtml += pre.graph_permissions.map(function(p: any) {
            var purpose = _t(p.purpose);
            return '<div><code style="font-family:ui-monospace,monospace">' + _e(p.id) + '</code>' + (purpose ? ' — ' + _e(purpose) : '') + '</div>';
        }).join('');
        prereqHtml += '</div>';
    }

    var body = (typeof window._connHelpPanelHtml === "function" ? window._connHelpPanelHtml(schema) : "") + prereqHtml;
    // Schema-driven form via the shared helper (or inline if not loaded)
    if (typeof window._connRenderForm === "function") {
        body += window._connRenderForm(schema, entry);
    } else {
        // fallback: minimal inline
        (schema.fields || []).forEach(function(f) {
            body += '<div class="ct-mt-3 ct-mb-3"><label class="ct-block ct-strong ct-mb-1">' + _e(_t(f.label) || f.id) + '</label>';
            body += '<input data-conn-field="' + _e(f.id) + '" type="' + (f.secret ? 'password' : 'text') + '" value="' + _e(entry![f.id] || "") + '" class="ct-input"></div>';
        });
    }

    ct_modal.open({
        title: t("pilot.connectors.modal_title") + " — " + currentLabel,
        body: body,
        // FIX portage TS : la source historique passait `actions:` que ct_modal ignore
        // (seul `buttons:` est lu) — les modales s'ouvraient sans bouton Enregistrer/Annuler.
        buttons: [
            { id: "cancel", label: t("pilot.action.cancel") },
            {
                id: "save", label: t("pilot.action.save"), primary: true,
                result: function() {
                    var root = document.querySelector(".ct-modal-box")!;
                    var payload: Record<string, string>;
                    if (typeof window._connReadForm === "function") {
                        payload = window._connReadForm(schema, root);
                    } else {
                        payload = {};
                        (schema.fields || []).forEach(function(f) {
                            var el = root.querySelector('[data-conn-field="' + f.id + '"]');
                            if (el) payload[f.id] = (el as HTMLInputElement).value;
                        });
                    }
                    // Strip "configured" placeholder for secret fields — sending it back
                    // tells the backend to preserve the stored value, but sending the
                    // empty string would clear it. We just omit the field entirely.
                    (schema.fields || []).forEach(function(f) {
                        if (f.secret && payload[f.id] === "configured") delete payload[f.id];
                    });
                    return _putAggregator(id, payload).then(function(report) {
                        if (report.ok) {
                            showStatus(t("pilot.connectors.credentials_saved", { report: JSON.stringify(report.report) }));
                        } else {
                            ct_modal.alert({ title: t("pilot.connectors.partial_push"), message: t("pilot.connectors.modules_failed") + "\n" + JSON.stringify(report.report, null, 2) });
                        }
                        _aggCache = null;
                        var c = document.getElementById("content");
                        if (c) window._renderConnectors(c);
                    }).catch(function(e) {
                        ct_modal.alert({ title: t("pilot.connectors.error"), message: String(e && e.message || e) });
                        return false;
                    });
                }
            }
        ]
    });
};

async function _putAggregator(id: string, payload: Record<string, string>) {
    var r = await fetch("api/admin/connectors/" + encodeURIComponent(id), {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    if (!r.ok) {
        var detail = "";
        try { detail = (await r.json()).detail || ""; } catch(e) {}
        throw new Error("HTTP " + r.status + (detail ? ": " + detail : ""));
    }
    return r.json();
}

window._connRunTest = function(id: string) {
    var out = document.querySelector<HTMLElement>('[data-conn-result="' + id + '"]');
    if (out) { out.style.color = "var(--ct-ink-2)"; out.textContent = t("pilot.connectors.testing"); }
    fetch("api/admin/connectors/" + encodeURIComponent(id) + "/test", {
        method: "POST", credentials: "same-origin"
    }).then(function(r) { return r.json().then(function(j) { return { status: r.status, body: j }; }); })
    .then(function(res) {
        if (!out) return;
        var body = res.body || {};
        var ok = res.status === 200 && body.ok;
        out.style.color = ok ? "var(--ct-low)" : "var(--danger,var(--ct-critical))";
        var prefix = ok ? t("pilot.connectors.ok") : t("pilot.connectors.failed");
        var msg = body.message || ("HTTP " + res.status);
        var on = body.tested_on ? t("pilot.connectors.tested_on", { target: body.tested_on }) : "";
        out.textContent = prefix + " — " + msg + on;
    }).catch(function(e) {
        if (out) { out.style.color = "var(--danger,var(--ct-critical))"; out.textContent = t("pilot.connectors.network_error"); }
    });
};

window._connRunNow = function(id: string) {
    var out = document.querySelector<HTMLElement>('[data-conn-result="' + id + '"]');
    if (out) { out.style.color = "var(--ct-ink-2)"; out.textContent = t("pilot.connectors.computing"); }
    fetch("api/admin/connectors/" + encodeURIComponent(id) + "/run", {
        method: "POST", credentials: "same-origin"
    }).then(function(r) { return r.json(); }).then(function(res) {
        if (!out) return;
        // Pilot's run returns {results: {pilot: {...}, ...}}. Shapes vary per
        // connector: {computed, skipped, errors} (KPI runners) or the PSAT
        // {ok, mode, kpis_synced, measures_raised} / {ok:false, error|skipped}.
        var hasError = false;
        var summary = "";
        if (res.results) {
            summary = Object.keys(res.results).map(function(k) {
                var r = res.results[k] || {};
                if (r.error) { hasError = true; return k + ": " + r.error; }
                if (r.ok === false) { hasError = true; return k + ": " + (r.skipped || t("pilot.connectors.not_configured_lc")); }
                if (typeof r.computed !== "undefined") return k + ": " + r.computed + " calc., " + (r.skipped || 0) + " skip., " + (r.errors || 0) + " err.";
                if (typeof r.kpis_synced !== "undefined") return k + ": " + r.kpis_synced + " KPI, " + (r.measures_raised || 0) + " " + t("pilot.connectors.measures_unit") + (r.completed_late ? ", " + r.completed_late + " " + t("pilot.connectors.late") : "") + (r.mode ? " [" + r.mode + "]" : "");
                return k + ": ok";
            }).join(" | ");
        }
        out.style.color = hasError ? "var(--danger,var(--ct-critical))" : "var(--ct-low)";
        out.textContent = summary || t("pilot.connectors.done");
    }).catch(function(e) {
        if (out) { out.style.color = "var(--danger,var(--ct-critical))"; out.textContent = t("pilot.connectors.network_error"); }
    });
};

window._connDeleteConfig = function(id: string) {
    var entry = (_aggCache && _aggCache.connectors || []).find(function(x) { return x.id === id; });
    var label = (entry && _t((entry.schema || {}).name)) || id;
    ct_modal.confirm({
        title: t("pilot.connectors.delete_config_title"),
        message: t("pilot.connectors.delete_config_confirm", { label: label }),
        danger: true,
        confirmLabel: t("pilot.action.delete")
    }).then(function(ok: boolean) {
        if (!ok) return;
        fetch("api/admin/connectors/" + encodeURIComponent(id), {
            method: "DELETE", credentials: "same-origin"
        }).then(function(r) { return r.json().then(function(j) { return { status: r.status, body: j }; }); })
        .then(function(res) {
            if (res.status !== 200 || !res.body.ok) {
                ct_modal.alert({ title: t("pilot.connectors.failed"), message: t("pilot.connectors.partial_delete") + "\n" + JSON.stringify((res.body || {}).report || res.body, null, 2) });
            } else {
                showStatus(t("pilot.connectors.config_deleted"));
            }
            _aggCache = null;
            var c = document.getElementById("content");
            if (c) window._renderConnectors(c);
        }).catch(function(e) {
            ct_modal.alert({ title: t("pilot.connectors.error"), message: String(e && e.message || e) });
        });
    });
};

// ── Multi-instance helpers ────────────────────────────────────────

window._connOpenInstance = function(typeId: string, ownerModule: string, instanceId: string) {
    var entry = (_aggCache && _aggCache.connectors || []).find(function(x) { return x.id === typeId; });
    if (!entry) return;
    var schema = entry.schema || {};
    var instance = (entry.instances || []).find(function(i) {
        return i.id === instanceId && i._owner === ownerModule;
    });
    if (!instance) {
        ct_modal.alert({ title: t("pilot.connectors.not_found"), message: t("pilot.connectors.instance_unknown") });
        return;
    }
    var currentLabel = (instance.label || instanceId) + " — " + (_t(schema.name) || typeId);

    var body = (typeof window._connHelpPanelHtml === "function" ? window._connHelpPanelHtml(schema) : "");
    body += '<div class="ct-bg-alt ct-bordered ct-r-lg ct-py-2 ct-px-3 ct-mb-3 ct-text-meta ct-muted">';
    body += _e(t("pilot.connectors.managed_by")) + ' <b>' + _e(ownerModule) + '</b>';
    if (instance.project_id) body += ' · ' + _e(t("pilot.connectors.project")) + ' <code>' + _e(instance.project_id) + '</code>';
    body += '</div>';

    if (typeof window._connRenderForm === "function") {
        body += window._connRenderForm(schema, instance);
    } else {
        (schema.fields || []).forEach(function(f) {
            body += '<div class="ct-mt-3 ct-mb-3"><label class="ct-block ct-strong ct-mb-1">' + _e(_t(f.label) || f.id) + '</label>';
            body += '<input data-conn-field="' + _e(f.id) + '" type="' + (f.secret ? 'password' : 'text') + '" value="' + _e(instance![f.id] || "") + '" class="ct-input"></div>';
        });
    }

    ct_modal.open({
        title: t("pilot.connectors.configure") + " — " + currentLabel,
        body: body,
        // FIX portage TS : la source historique passait `actions:` que ct_modal ignore
        // (seul `buttons:` est lu) — les modales s'ouvraient sans bouton Enregistrer/Annuler.
        buttons: [
            { id: "cancel", label: t("pilot.action.cancel") },
            {
                id: "save", label: t("pilot.action.save"), primary: true,
                result: function() {
                    var root = document.querySelector(".ct-modal-box")!;
                    var payload: Record<string, string>;
                    if (typeof window._connReadForm === "function") {
                        payload = window._connReadForm(schema, root);
                    } else {
                        payload = {};
                        (schema.fields || []).forEach(function(f) {
                            var el = root.querySelector('[data-conn-field="' + f.id + '"]');
                            if (el) payload[f.id] = (el as HTMLInputElement).value;
                        });
                    }
                    (schema.fields || []).forEach(function(f) {
                        if (f.secret && payload[f.id] === "configured") delete payload[f.id];
                    });
                    return _putInstance(typeId, ownerModule, instanceId, payload).then(function() {
                        showStatus(t("pilot.connectors.instance_saved"));
                        _aggCache = null;
                        var c = document.getElementById("content");
                        if (c) window._renderConnectors(c);
                    }).catch(function(e) {
                        ct_modal.alert({ title: t("pilot.connectors.error"), message: String(e && e.message || e) });
                        return false;
                    });
                }
            }
        ]
    });
};

async function _putInstance(typeId: string, ownerModule: string, instanceId: string, payload: Record<string, string>) {
    var url = "api/admin/connectors/" + encodeURIComponent(typeId)
            + "/instances/" + encodeURIComponent(ownerModule)
            + "/" + encodeURIComponent(instanceId);
    var r = await fetch(url, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    if (!r.ok) {
        var detail = "";
        try { detail = (await r.json()).detail || ""; } catch(e) {}
        throw new Error("HTTP " + r.status + (detail ? ": " + detail : ""));
    }
    return r.json();
}

window._connNewInstance = function(typeId: string) {
    var entry = (_aggCache && _aggCache.connectors || []).find(function(x) { return x.id === typeId; });
    if (!entry) return;
    var schema = entry.schema || {};
    var typeName = _t(schema.name) || typeId;
    var consumers = entry.consumers || [];
    // Target module: single consumer → implicit; several → let the admin pick.
    var modulePicker = "";
    if (consumers.length > 1) {
        modulePicker = '<div class="ct-mt-3 ct-mb-3"><label class="ct-block ct-strong ct-mb-1">' + _e(t("pilot.connectors.module_label")) + '</label>';
        modulePicker += '<select data-conn-new-module class="ct-select">';
        consumers.forEach(function(m) { modulePicker += '<option value="' + _e(m) + '">' + _e(_consumerLabel([m])) + '</option>'; });
        modulePicker += '</select></div>';
    }

    var body = (typeof window._connHelpPanelHtml === "function" ? window._connHelpPanelHtml(schema) : "");
    body += '<div class="ct-bg-alt ct-bordered ct-r-lg ct-py-2 ct-px-3 ct-mb-3 ct-text-meta ct-muted">';
    body += _e(t("pilot.connectors.new_instance_of")) + ' <b>' + _e(typeName) + '</b>';
    if (consumers.length === 1) body += ' ' + _e(t("pilot.connectors.on")) + ' <b>' + _e(_consumerLabel(consumers)) + '</b>';
    body += '</div>';
    body += modulePicker;
    body += '<div class="ct-mt-3 ct-mb-3"><label class="ct-block ct-strong ct-mb-1">' + _e(t("pilot.connectors.label_field")) + '</label>';
    body += '<input data-conn-new-label type="text" placeholder="' + _e(t("pilot.connectors.label_placeholder")) + '" class="ct-input"></div>';
    if (typeof window._connRenderForm === "function") {
        body += window._connRenderForm(schema, {});
    } else {
        (schema.fields || []).forEach(function(f) {
            body += '<div class="ct-mt-3 ct-mb-3"><label class="ct-block ct-strong ct-mb-1">' + _e(_t(f.label) || f.id) + '</label>';
            body += '<input data-conn-field="' + _e(f.id) + '" type="' + (f.secret ? 'password' : 'text') + '" class="ct-input"></div>';
        });
    }

    ct_modal.open({
        title: t("pilot.connectors.new_instance_title") + " — " + typeName,
        body: body,
        // FIX portage TS : la source historique passait `actions:` que ct_modal ignore
        // (seul `buttons:` est lu) — les modales s'ouvraient sans bouton Enregistrer/Annuler.
        buttons: [
            { id: "cancel", label: t("pilot.action.cancel") },
            {
                id: "create", label: t("pilot.connectors.create"), primary: true,
                result: function() {
                    var root = document.querySelector(".ct-modal-box")!;
                    var payload: Record<string, string>;
                    if (typeof window._connReadForm === "function") {
                        payload = window._connReadForm(schema, root);
                    } else {
                        payload = {};
                        (schema.fields || []).forEach(function(f) {
                            var el = root.querySelector('[data-conn-field="' + f.id + '"]');
                            if (el) payload[f.id] = (el as HTMLInputElement).value;
                        });
                    }
                    // Drop unfilled secret placeholders (nothing stored yet on create)
                    (schema.fields || []).forEach(function(f) {
                        if (f.secret && payload[f.id] === "configured") delete payload[f.id];
                    });
                    var labelEl = root.querySelector<HTMLInputElement>('[data-conn-new-label]');
                    payload.label = labelEl ? labelEl.value : "";
                    var modEl = root.querySelector<HTMLSelectElement>('[data-conn-new-module]');
                    payload.module = modEl ? modEl.value : (consumers[0] || "");
                    if (!payload.module) {
                        ct_modal.alert({ title: t("pilot.connectors.module_unknown"), message: t("pilot.connectors.module_undetermined") });
                        return false;
                    }
                    return _postCreateInstance(typeId, payload).then(function() {
                        showStatus(t("pilot.connectors.instance_created"));
                        _aggCache = null;
                        var c = document.getElementById("content");
                        if (c) window._renderConnectors(c);
                    }).catch(function(e) {
                        ct_modal.alert({ title: t("pilot.connectors.error"), message: String(e && e.message || e) });
                        return false;
                    });
                }
            }
        ]
    });
};

async function _postCreateInstance(typeId: string, body: Record<string, string>) {
    var r = await fetch("api/admin/connectors/" + encodeURIComponent(typeId) + "/instances", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
    if (!r.ok) {
        var detail = "";
        try { detail = (await r.json()).detail || ""; } catch(e) {}
        throw new Error("HTTP " + r.status + (detail ? ": " + detail : ""));
    }
    return r.json();
}

window._connTestInstance = function(typeId: string, ownerModule: string, instanceId: string) {
    var out = document.querySelector<HTMLElement>('[data-conn-result="' + typeId + '__' + instanceId + '"]');
    if (out) { out.style.color = "var(--ct-ink-2)"; out.textContent = t("pilot.connectors.test_ellipsis"); }
    var url = "api/admin/connectors/" + encodeURIComponent(typeId)
            + "/instances/" + encodeURIComponent(ownerModule)
            + "/" + encodeURIComponent(instanceId) + "/test";
    fetch(url, { method: "POST", credentials: "same-origin" })
        .then(function(r) { return r.json().then(function(j) { return { status: r.status, body: j }; }); })
        .then(function(res) {
            if (!out) return;
            var body = res.body || {};
            var ok = res.status === 200 && body.ok;
            out.style.color = ok ? "var(--ct-low)" : "var(--danger,var(--ct-critical))";
            out.textContent = body.message || (ok ? t("pilot.connectors.ok") : t("pilot.connectors.failed"));
        }).catch(function(e) {
            if (out) { out.style.color = "var(--danger,var(--ct-critical))"; out.textContent = t("pilot.connectors.network_error"); }
        });
};

})();
