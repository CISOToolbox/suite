/**
 * Audit — REST API Client Layer (suite/backend mode)
 *
 * Multi-audit persistence: every past audit is stored server-side as a
 * Project blob. This layer owns the boot (loads the active audit),
 * overrides _autoSave with a debounced blob PUT, wraps the file-open
 * path so a frontend-version file becomes a new stored audit, and adds
 * the "Mes audits" picker (list / open / import / duplicate / delete).
 * Load BEFORE ISO_Audit_app.js.
 */
(function () {
    "use strict";
    var BASE = "api";
    var LS_ACTIVE = "audit_active_project";
    var _activeId = null;
    var _saveTimer = null;
    async function _fetch(url, opts) {
        opts = opts || {};
        opts.headers = opts.headers || {};
        opts.credentials = "same-origin";
        if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
            opts.headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(opts.body);
        }
        var resp = await fetch(BASE + url, opts);
        if (resp.status === 401) {
            var _rp = window.location.pathname.replace(/[^/]*$/, "");
            window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp);
            throw new Error("Not authenticated");
        }
        if (resp.status === 403) {
            var errBody = "";
            try {
                errBody = await resp.text();
            }
            catch (e) { }
            if (errBody.indexOf("pending") >= 0) {
                window.location.href = "/login.html?error=pending";
                throw new Error("Account pending");
            }
            throw new Error("API 403: " + errBody.substring(0, 200));
        }
        if (resp.status === 204)
            return null;
        if (!resp.ok) {
            var errText = "";
            try {
                errText = await resp.text();
            }
            catch (e) { }
            throw new Error("API " + resp.status + ": " + errText.substring(0, 200));
        }
        return resp.json();
    }
    window.AuditAPI = {
        list: function () { return _fetch("/projects"); },
        get: function (id) { return _fetch("/projects/" + id); },
        create: function (body) { return _fetch("/projects", { method: "POST", body: body || { name: "", data: {} } }); },
        update: function (id, body) { return _fetch("/projects/" + id, { method: "PUT", body: body }); },
        del: function (id) { return _fetch("/projects/" + id, { method: "DELETE" }); },
        duplicate: function (id) { return _fetch("/projects/" + id + "/duplicate", { method: "POST" }); },
        importFile: function (file) {
            var fd = new FormData();
            fd.append("file", file);
            return _fetch("/projects/import", { method: "POST", body: fd, headers: {} });
        },
        listMeasures: function (pid) { return _fetch("/projects/" + pid + "/measures"); },
        createMeasure: function (pid, body) { return _fetch("/projects/" + pid + "/measures", { method: "POST", body: body }); },
        patchMeasure: function (pid, id, body) { return _fetch("/projects/" + pid + "/measures/" + id, { method: "PATCH", body: body }); },
        deleteMeasure: function (pid, id) { return _fetch("/projects/" + pid + "/measures/" + id, { method: "DELETE" }); },
        aiComplete: function (systemPrompt, userPrompt, provider, model) {
            return _fetch("/ai/complete", {
                method: "POST",
                body: { system: systemPrompt, user: userPrompt, provider: provider || (window._aiRuntime && window._aiRuntime.provider) || "anthropic", model: model || (window._aiRuntime && window._aiRuntime.model) || "claude-sonnet-4-6" }
            });
        },
        aiConfig: function () { return _fetch("/ai/config"); },
        aiGetKeys: function () { return _fetch("/ai/keys"); },
        aiSetKeys: function (data) { return _fetch("/ai/keys", { method: "PUT", body: data }); },
        authMe: function () { return fetch("auth/me", { credentials: "same-origin" }).then(function (r) { return r.ok ? r.json() : null; }); },
        authLogout: function () { return fetch("auth/logout", { method: "POST", credentials: "same-origin" }).then(function () { var _rp = window.location.pathname.replace(/[^/]*$/, ""); window.location.href = "/login.html?redirect=" + encodeURIComponent(_rp); }); },
        listUsers: function () { return _fetch("/users"); },
        updateUser: function (id, data) { return _fetch("/users/" + id, { method: "PUT", body: data }); }
    };
    window.getActiveProjectId = function () { return _activeId; };
    // ═══════════════════════════════════════════════════════════════
    // AUTOSAVE — debounced blob PUT
    // ═══════════════════════════════════════════════════════════════
    var _dataReady = false;
    window._setDataReady = function () { _dataReady = true; };
    // FEAT-33 — server_rev seen at load; sent with the blob PUT (409 = a
    // server-initiated write happened since: reload instead of overwrite).
    var _serverRev = 0;
    // FEAT-33 — a stale blob PUT was refused: warn (blocking) then reload the
    // authoritative server state. The stale bulk change is lost by design.
    function _staleConflict() {
        alert(t("chrome.stale_conflict"));
        window.location.reload();
    }
    window._autoSave = function () {
        if (!_dataReady)
            return;
        if (_saveTimer)
            clearTimeout(_saveTimer);
        var saveId = _activeId;
        _saveTimer = setTimeout(function () {
            _saveTimer = null; // FEAT-33: a fired timer must not keep blocking the focus refresh
            if (!saveId || String(saveId) !== String(_activeId))
                return;
            AuditAPI.update(saveId, { data: JSON.parse(JSON.stringify(D)),
                expected_server_rev: _serverRev })
                .catch(function (err) {
                if (err && String(err.message || "").indexOf("API 409") === 0) {
                    _staleConflict();
                    return;
                }
                console.error("Autosave failed:", err);
            });
        }, 800);
    };
    // Force the current D to the server NOW (cancels the pending debounce), so a
    // snapshot taken right after captures exactly what the user sees.
    function _flushAutosave() {
        if (!_dataReady || !_activeId)
            return Promise.resolve();
        if (_saveTimer) {
            clearTimeout(_saveTimer);
            _saveTimer = null;
        }
        return AuditAPI.update(_activeId, { data: JSON.parse(JSON.stringify(D)) }).then(function () { });
    }
    // ═══════════════════════════════════════════════════════════════
    // DATA SWAP + BOOT
    // ═══════════════════════════════════════════════════════════════
    function _swapData(pdata) {
        Object.keys(D).forEach(function (k) { delete D[k]; });
        Object.assign(D, pdata || {});
        _dataReady = true;
        if (typeof _initDataAndRender === "function")
            _initDataAndRender();
        if (_auditorHandle)
            _auditorHandle.setValue((D.meta && D.meta.auditor) || "");
    }
    // ── Champ Auditeur → ct_userpicker branché sur l'annuaire ──────
    // Remplace l'input libre #meta-auditor (la boucle de remplissage de
    // l'app garde son null-guard). Repli automatique du composant : input
    // simple si aucun annuaire inscriptible derrière le proxy.
    var _auditorHandle = null;
    function _mountAuditorPicker() {
        var input = document.getElementById("meta-auditor");
        if (!input || !window.ct_userpicker)
            return;
        var slot = document.createElement("div");
        slot.id = "auditor-picker-slot";
        input.parentNode.replaceChild(slot, input);
        ct_userpicker.mount({
            slotId: "auditor-picker-slot",
            pickerId: "audit-meta-auditor",
            value: (D.meta && D.meta.auditor) || "",
            placeholder: t("audit.meta.auditor"),
            directoryUrl: "api/directory",
            onChange: function (val) {
                if (typeof onMetaChange === "function")
                    onMetaChange("auditor", val);
            }
        }).then(function (h) {
            _auditorHandle = h;
            if (h && D.meta && D.meta.auditor)
                h.setValue(D.meta.auditor);
        }).catch(function () { });
    }
    function _openStored(id) {
        return AuditAPI.get(id).then(function (project) {
            _activeId = project.id;
            _serverRev = project.server_rev || 0;
            try {
                localStorage.setItem(LS_ACTIVE, project.id);
            }
            catch (e) { }
            var pdata = typeof project.data === "string" ? JSON.parse(project.data) : (project.data || {});
            return _reloadMeasures().then(function () {
                _swapData(pdata);
                _closePicker();
            });
        });
    }
    function _createStored() {
        var initData = typeof window.ISO_AUDIT_INIT_DATA !== "undefined"
            ? JSON.parse(JSON.stringify(window.ISO_AUDIT_INIT_DATA)) : {};
        return AuditAPI.create({ name: "", data: initData }).then(function (project) {
            _activeId = project.id;
            _serverRev = project.server_rev || 0;
            try {
                localStorage.setItem(LS_ACTIVE, project.id);
            }
            catch (e) { }
            _measures = [];
            _swapData(initData);
            _closePicker();
        });
    }
    // FEAT-13 — deep-linked measure (?measure=<M-xxx@project>): the audit
    // source_id is namespaced on "@" (project part consumed at boot via
    // ?entity). Opens the native edit modal once measures are loaded.
    function _handleMeasureDeepLink() {
        if (typeof window.ct_handleMeasureDeepLink !== "function")
            return;
        window.ct_handleMeasureDeepLink({ open: function (mid) {
                // FEAT-32 composite "<audit8>:MES-NNN" (new) or "<id>@<uuid>" (legacy).
                var local = mid.indexOf(":") >= 0 ? (mid.split(":").pop() || mid)
                    : (mid.indexOf("@") >= 0 ? mid.split("@")[0] : mid);
                if (!_measures.some(function (m) { return m.id === local; }))
                    return false;
                if (typeof window._editAuditMeasure === "function")
                    window._editAuditMeasure(local);
                return true;
            } });
    }
    window._appInitCallback = function () {
        AuditAPI.list().then(function (items) {
            var last = null;
            try {
                last = localStorage.getItem(LS_ACTIVE);
            }
            catch (e) { }
            // FEAT-13 — a Pilot deep link (?entity=<audit project id>) targets a
            // precise stored audit: it wins over the saved choice.
            try {
                var _dlEntity = new URLSearchParams(window.location.search).get("entity");
                if (_dlEntity && items.some(function (p) { return String(p.id) === _dlEntity; }))
                    last = _dlEntity;
            }
            catch (e) { /* ignore */ }
            var found = last && items.some(function (p) { return String(p.id) === String(last); });
            if (found) {
                _openStored(last).catch(function () { _bootFallback(items); });
            }
            else {
                _bootFallback(items);
            }
        }).catch(function () { _swapData(typeof window.ISO_AUDIT_INIT_DATA !== "undefined" ? JSON.parse(JSON.stringify(window.ISO_AUDIT_INIT_DATA)) : {}); });
        _handleMeasureDeepLink();
    };
    function _bootFallback(items) {
        if (items.length > 0) {
            _openStored(items[0].id).catch(function () { });
        }
        else {
            _createStored().catch(function () { });
        }
    }
    // ═══════════════════════════════════════════════════════════════
    // FILE-OPEN HOOK — a frontend file becomes a NEW stored audit
    // ═══════════════════════════════════════════════════════════════
    var _origLoadBuffer = window._loadBuffer;
    if (_origLoadBuffer) {
        window._loadBuffer = function (buffer, filename) {
            var p = _origLoadBuffer(buffer, filename);
            Promise.resolve(p).then(function (ok) {
                if (ok === null)
                    return; // decryption cancelled
                AuditAPI.create({ data: JSON.parse(JSON.stringify(D)) }).then(function (project) {
                    _activeId = project.id;
                    _serverRev = project.server_rev || 0;
                    try {
                        localStorage.setItem(LS_ACTIVE, project.id);
                    }
                    catch (e) { }
                    _dataReady = true;
                    showStatus(t("auditapi.imported"));
                }).catch(function (err) { showStatus("Import : " + err.message, true); });
            });
            return p;
        };
    }
    // ═══════════════════════════════════════════════════════════════
    // "MES AUDITS" PICKER
    // ═══════════════════════════════════════════════════════════════
    function _pickerEl() { return document.getElementById("audit-picker-overlay"); }
    function _closePicker() {
        var el = _pickerEl();
        if (el)
            el.remove();
    }
    window._closeAuditPicker = _closePicker;
    window._openAuditPicker = function () {
        _closePicker();
        var overlay = document.createElement("div");
        overlay.id = "audit-picker-overlay";
        overlay.style.cssText = "position:fixed;inset:0;background:var(--ct-scrim);z-index:1000;display:flex;align-items:center;justify-content:center";
        overlay.innerHTML = '<div id="audit-picker" style="background:var(--ct-surface);border:1px solid var(--ct-line);border-radius:10px;max-width:760px;width:92%;max-height:80vh;display:flex;flex-direction:column;padding:var(--ct-s4)"></div>';
        overlay.addEventListener("mousedown", function (e) { if (e.target === overlay)
            _closePicker(); });
        document.body.appendChild(overlay);
        _renderPicker();
    };
    function _renderPicker() {
        var box = document.getElementById("audit-picker");
        if (!box)
            return;
        var boxEl = box;
        boxEl.innerHTML = '<p class="text-muted">' + esc(t("auditapi.loading")) + '</p>';
        AuditAPI.list().then(function (items) {
            var h = '<div class="ct-row" style="align-items:center;margin-bottom:var(--ct-s3)">';
            h += '<h2 class="ct-m-0">' + esc(t("auditapi.title")) + '</h2><span style="flex:1"></span>';
            h += '<input type="file" id="audit-import-file" accept=".json" style="display:none">';
            h += '<button class="ct-btn" data-write data-click="_auditPickerImport">' + _icon("upload", 14) + ' ' + esc(t("auditapi.import")) + '</button> ';
            h += '<button class="ct-btn" data-write data-variant="primary" data-click="_auditPickerNew">' + _icon("plus", 14) + ' ' + esc(t("auditapi.new")) + '</button> ';
            h += '<button class="appsec-modal-close" data-click="_closeAuditPicker" style="background:none;border:none;font-size:1.4em;cursor:pointer;color:var(--ct-ink-2)">&#10005;</button>';
            h += '</div>';
            if (!items.length) {
                h += '<p class="text-muted">' + esc(t("auditapi.empty")) + '</p>';
            }
            else {
                h += '<div style="overflow:auto"><table class="ct-table"><thead><tr>';
                h += '<th>' + esc(t("auditapi.col_name")) + '</th><th>' + esc(t("auditapi.col_date")) + '</th><th>' + esc(t("auditapi.col_updated")) + '</th><th></th>';
                h += '</tr></thead><tbody>';
                items.forEach(function (p) {
                    var active = String(p.id) === String(_activeId);
                    h += '<tr' + (active ? ' style="background:var(--ct-accent-tint)"' : '') + '>';
                    h += '<td>' + esc(p.name || "(sans nom)") + (active ? ' <span class="ct-badge" data-tone="info">' + esc(t("auditapi.active")) + '</span>' : '') + '</td>';
                    h += '<td>' + esc(p.audit_date || "") + '</td>';
                    h += '<td class="fs-sm text-muted">' + esc((p.updated_at || "").substring(0, 10)) + '</td>';
                    h += '<td class="ct-ta-r ct-nowrap">';
                    h += '<button class="ct-btn" data-size="xs" data-click="_auditPickerOpen" data-args=\'' + _da(p.id) + '\'>' + esc(t("auditapi.open")) + '</button> ';
                    h += '<button class="ct-btn" data-size="xs" data-write data-click="_auditPickerDup" data-args=\'' + _da(p.id) + '\' data-icon title="' + esc(t("auditapi.duplicate")) + '">' + _icon("copy", 14) + '</button> ';
                    h += '<button class="ct-btn ct-admin-only" data-size="xs" data-variant="danger" data-click="_auditPickerDel" data-args=\'' + _da(p.id) + '\' data-icon title="' + esc(t("auditapi.delete")) + '">' + _icon("trash", 14) + '</button>';
                    h += '</td></tr>';
                });
                h += '</tbody></table></div>';
            }
            boxEl.innerHTML = h;
            var input = document.getElementById("audit-import-file");
            if (input)
                input.addEventListener("change", function () {
                    if (!input.files || !input.files[0])
                        return;
                    AuditAPI.importFile(input.files[0]).then(function (project) {
                        showStatus(t("auditapi.imported"));
                        _openStored(project.id).catch(function () { _renderPicker(); });
                    }).catch(function (err) { showStatus("Import : " + err.message, true); });
                });
        }).catch(function (err) {
            boxEl.innerHTML = '<p class="ct-text-critical">' + esc(err.message) + '</p>';
        });
    }
    window._auditPickerOpen = function (id) {
        _openStored(String(id)).catch(function (err) { showStatus(err.message, true); });
    };
    window._auditPickerNew = function () {
        _createStored().catch(function (err) { showStatus(err.message, true); });
    };
    window._auditPickerDup = function (id) {
        AuditAPI.duplicate(String(id)).then(function () { _renderPicker(); }).catch(function (err) { showStatus(err.message, true); });
    };
    window._auditPickerDel = function (id) {
        if (!window.confirm(t("auditapi.delete_confirm")))
            return;
        AuditAPI.del(String(id)).then(function () {
            if (String(id) === String(_activeId)) {
                _activeId = null;
                try {
                    localStorage.removeItem(LS_ACTIVE);
                }
                catch (e) { }
                AuditAPI.list().then(function (items) { _bootFallback(items); });
            }
            _renderPicker();
        }).catch(function (err) { showStatus(err.message, true); });
    };
    window._auditPickerImport = function () {
        var input = document.getElementById("audit-import-file");
        if (input)
            input.click();
    };
    // ═══════════════════════════════════════════════════════════════
    // ACTIONS CORRECTIVES (mesures) — par NC + panneau de suivi
    // ═══════════════════════════════════════════════════════════════
    var _measures = [];
    function _reloadMeasures() {
        if (!_activeId) {
            _measures = [];
            return Promise.resolve();
        }
        return AuditAPI.listMeasures(_activeId).then(function (items) { _measures = items || []; })
            .catch(function () { _measures = []; });
    }
    var _MEASURE_STATUS = [
        { value: "a_faire", label: function () { return t("auditapi.m.a_faire"); } },
        { value: "en_cours", label: function () { return t("auditapi.m.en_cours"); } },
        { value: "termine", label: function () { return t("auditapi.m.termine"); } }
    ];
    function _statusOpts() {
        return _MEASURE_STATUS.map(function (s) { return { value: s.value, label: s.label() }; });
    }
    function _measureStatusLabel(s) {
        for (var i = 0; i < _MEASURE_STATUS.length; i++)
            if (_MEASURE_STATUS[i].value === s)
                return _MEASURE_STATUS[i].label();
        return s;
    }
    // Bloc inline sous les champs d'écart d'un contrôle (appelé par le fork
    // suite d'ISO_Audit_app.renderControl via un hook typeof-guardé).
    window._auditControlMeasuresHTML = function (controlId) {
        var linked = _measures.filter(function (m) { return m.control_id === controlId; });
        var h = '<div class="ctrl-field audit-measures-inline">';
        h += '<label>' + esc(t("auditapi.m.linked")) + '</label><div>';
        linked.forEach(function (m) {
            h += '<button class="ct-btn" data-size="xs" data-click="_editAuditMeasure" data-args=\'' + _da(m.id) + '\' style="margin:0 4px 4px 0">'
                + esc(m.id) + ' · ' + esc(m.title.substring(0, 40)) + (m.responsable ? ' — ' + esc(m.responsable) : '')
                + ' <span class="ct-badge" data-size="sm">' + esc(_measureStatusLabel(m.statut)) + '</span></button>';
        });
        h += '<button class="ct-btn" data-size="xs" data-write data-variant="primary" data-click="_auditNewMeasure" data-args=\'' + _da(controlId) + '\'>'
            + _icon("plus", 12) + ' ' + esc(t("auditapi.m.create")) + '</button>';
        h += '</div></div>';
        return h;
    };
    window._auditNewMeasure = function (controlId) {
        if (!_activeId || !window.ct_measure_modal)
            return;
        var f = (D.findings && D.findings[controlId]) || {};
        ct_measure_modal.open({
            title: (f.ecart_action || "").substring(0, 200) || (t("auditapi.m.default_title") + " " + controlId),
            description: f.ecart_constat || "",
            statut: "a_faire"
        }, {
            title: t("auditapi.m.new_title") + " — " + controlId,
            hideFields: ["type"],
            statusOptions: _statusOpts(),
            defaultStatus: "a_faire",
            ownerPicker: { pickerId: "audit-measure-owner", directoryUrl: "api/directory" }
        }).then(function (result) {
            if (!result)
                return;
            result.control_id = controlId;
            AuditAPI.createMeasure(_activeId, result).then(function () {
                showStatus(t("auditapi.m.created"));
                _reloadMeasures().then(function () {
                    if (typeof _initDataAndRender === "function")
                        _initDataAndRender();
                });
            }).catch(function (err) { showStatus(err.message, true); });
        });
    };
    window._editAuditMeasure = function (measureId) {
        if (!_activeId || !window.ct_measure_modal)
            return;
        var m = _measures.find(function (x) { return x.id === measureId; });
        if (!m)
            return;
        var isAdmin = document.body.classList.contains("ct-role-admin");
        ct_measure_modal.open(m, {
            title: m.id + (m.control_id ? " — " + m.control_id : ""),
            hideFields: ["type"],
            statusOptions: _statusOpts(),
            defaultStatus: "a_faire",
            ownerPicker: { pickerId: "audit-measure-owner", directoryUrl: "api/directory" },
            onAddNote: function (_entry, fullLog) {
                m.progress_log = fullLog;
                return AuditAPI.patchMeasure(_activeId, m.id, { progress_log: fullLog });
            },
            onDelete: !isAdmin ? undefined : function () {
                ct_modal.confirm({
                    title: t("auditapi.m.delete"),
                    message: t("auditapi.m.delete_confirm"),
                    danger: true
                }).then(function (ok) {
                    if (!ok)
                        return;
                    AuditAPI.deleteMeasure(_activeId, m.id).then(function () {
                        showStatus(t("auditapi.m.deleted"));
                        _reloadMeasures().then(_refreshAfterMeasureChange);
                    }).catch(function (err) { showStatus(err.message, true); });
                });
            }
        }).then(function (result) {
            if (!result || result.__deleted)
                return;
            AuditAPI.patchMeasure(_activeId, m.id, result).then(function () {
                showStatus(t("auditapi.m.updated"));
                _reloadMeasures().then(_refreshAfterMeasureChange);
            }).catch(function (err) { showStatus(err.message, true); });
        });
    };
    function _refreshAfterMeasureChange() {
        var panel = document.getElementById("panel-measures");
        if (panel && panel.classList.contains("active")) {
            window._renderAuditMeasures();
        }
        else if (typeof _initDataAndRender === "function") {
            _initDataAndRender();
        }
    }
    window._renderAuditMeasures = function () {
        var c = document.getElementById("measures-content");
        if (!c)
            return;
        var el = c;
        el.innerHTML = '<p class="text-muted">' + esc(t("auditapi.loading")) + '</p>';
        _reloadMeasures().then(function () {
            var h = '<div class="ct-row" style="align-items:center;margin-bottom:var(--ct-s3)">';
            h += '<span style="flex:1"></span>';
            h += '<button class="ct-btn" data-write data-variant="primary" data-click="_auditNewMeasure" data-args=\'' + _da("") + '\'>' + _icon("plus", 14) + ' ' + esc(t("auditapi.m.new_title")) + '</button>';
            h += '</div>';
            if (!_measures.length) {
                h += '<p class="text-muted">' + esc(t("auditapi.m.empty")) + '</p>';
            }
            else {
                h += '<div style="overflow:auto"><table class="ct-table"><thead><tr>';
                h += '<th>ID</th><th>' + esc(t("auditapi.m.col_title")) + '</th><th>' + esc(t("auditapi.m.col_control")) + '</th>';
                h += '<th>' + esc(t("auditapi.m.col_status")) + '</th><th>' + esc(t("auditapi.m.col_owner")) + '</th><th>' + esc(t("auditapi.m.col_due")) + '</th>';
                h += '</tr></thead><tbody>';
                _measures.forEach(function (m) {
                    h += '<tr class="ct-clickable" data-click="_editAuditMeasure" data-args=\'' + _da(m.id) + '\'>';
                    h += '<td class="ct-nowrap">' + esc(m.id) + '</td>';
                    h += '<td>' + esc(m.title) + '</td>';
                    h += '<td class="ct-nowrap">' + esc(m.control_id || "—") + '</td>';
                    h += '<td><span class="ct-badge" data-tone="' + (m.statut === "termine" ? "low" : (m.statut === "en_cours" ? "info" : "medium")) + '">' + esc(_measureStatusLabel(m.statut)) + '</span></td>';
                    h += '<td>' + esc(m.responsable || "") + '</td>';
                    h += '<td class="ct-nowrap">' + esc(m.echeance || "") + '</td>';
                    h += '</tr>';
                });
                h += '</tbody></table></div>';
            }
            el.innerHTML = h;
        });
    };
    // ═══════════════════════════════════════════════════════════════
    // AUTH + TOOLBAR (user pill — "Mes audits" vit dans le menu Fichier)
    // ═══════════════════════════════════════════════════════════════
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
                var right2 = document.getElementById("toolbar-right");
                if (!right2)
                    return;
                var h = '<span style="color:var(--ct-ink-1);font-size:var(--ct-text-label);margin:0 var(--ct-s1)">' + esc(user.name || user.email) + '</span>';
                h += '<button class="ct-text-label ct-muted ct-bg-none ct-no-border ct-clickable ct-py-1 ct-px-2" data-click="_logout" title="Sign out">&#x23FB;</button>';
                var container = document.createElement("span");
                container.className = "ct-toolbar-right";
                container.style.cssText = "display:flex;align-items:center;gap:4px;margin-left:auto";
                container.innerHTML = h;
                right2.parentNode.insertBefore(container, right2);
                fetch("auth/role", { credentials: "same-origin" }).then(function (rr) {
                    return rr.ok ? rr.json() : {};
                }).then(function (roleInfo) {
                    var role = roleInfo.role || "";
                    window._moduleRole = role;
                    if (role)
                        document.body.classList.add("ct-role-" + role);
                    if (user.role === "admin")
                        document.body.classList.add("ct-role-admin");
                }).catch(function () { });
            });
        }).catch(function () { });
    }
    window._logout = function () {
        fetch("auth/logout", { method: "POST", credentials: "same-origin" })
            .finally(function () { window.location.href = "/auth/logout"; });
    };
    // ═══════════════════════════════════════════════════════════════
    // I18N
    // ═══════════════════════════════════════════════════════════════
    _registerTranslations("fr", {
        "auditapi.title": "Mes audits",
        "auditapi.loading": "Chargement…",
        "auditapi.empty": "Aucun audit stocké. Créez-en un ou importez un fichier de la version en ligne.",
        "auditapi.new": "Nouvel audit",
        "auditapi.import": "Importer un fichier",
        "auditapi.imported": "Audit importé",
        "auditapi.open": "Ouvrir",
        "auditapi.duplicate": "Dupliquer",
        "auditapi.delete": "Supprimer",
        "auditapi.delete_confirm": "Supprimer définitivement cet audit ?",
        "auditapi.active": "actif",
        "auditapi.col_name": "Audit",
        "auditapi.col_date": "Date d'audit",
        "auditapi.col_updated": "Modifié",
        "auditapi.m.linked": "Actions correctives",
        "auditapi.m.create": "Créer une action corrective",
        "auditapi.m.new_title": "Nouvelle action corrective",
        "auditapi.m.default_title": "Action corrective",
        "auditapi.m.created": "Action corrective créée",
        "auditapi.m.updated": "Action corrective mise à jour",
        "auditapi.m.deleted": "Action corrective supprimée",
        "auditapi.m.delete": "Supprimer l'action corrective",
        "auditapi.m.delete_confirm": "Supprimer définitivement cette action corrective ?",
        "auditapi.m.empty": "Aucune action corrective. Créez-en depuis une non-conformité ou avec le bouton ci-dessus.",
        "auditapi.m.col_title": "Titre",
        "auditapi.m.col_control": "Contrôle",
        "auditapi.m.col_status": "Statut",
        "auditapi.m.col_owner": "Responsable",
        "auditapi.m.col_due": "Échéance",
        "auditapi.m.a_faire": "À faire",
        "auditapi.m.en_cours": "En cours",
        "auditapi.m.termine": "Terminé"
    });
    _registerTranslations("en", {
        "auditapi.title": "My audits",
        "auditapi.loading": "Loading…",
        "auditapi.empty": "No stored audit. Create one or import a file from the online version.",
        "auditapi.new": "New audit",
        "auditapi.import": "Import a file",
        "auditapi.imported": "Audit imported",
        "auditapi.open": "Open",
        "auditapi.duplicate": "Duplicate",
        "auditapi.delete": "Delete",
        "auditapi.delete_confirm": "Permanently delete this audit?",
        "auditapi.active": "active",
        "auditapi.col_name": "Audit",
        "auditapi.col_date": "Audit date",
        "auditapi.col_updated": "Updated",
        "auditapi.m.linked": "Corrective actions",
        "auditapi.m.create": "Create a corrective action",
        "auditapi.m.new_title": "New corrective action",
        "auditapi.m.default_title": "Corrective action",
        "auditapi.m.created": "Corrective action created",
        "auditapi.m.updated": "Corrective action updated",
        "auditapi.m.deleted": "Corrective action deleted",
        "auditapi.m.delete": "Delete corrective action",
        "auditapi.m.delete_confirm": "Permanently delete this corrective action?",
        "auditapi.m.empty": "No corrective action yet. Create one from a non-conformity or with the button above.",
        "auditapi.m.col_title": "Title",
        "auditapi.m.col_control": "Control",
        "auditapi.m.col_status": "Status",
        "auditapi.m.col_owner": "Owner",
        "auditapi.m.col_due": "Due date",
        "auditapi.m.a_faire": "To do",
        "auditapi.m.en_cours": "In progress",
        "auditapi.m.termine": "Done"
    });
    function _apiBoot() { _initAuth(); _mountAuditorPicker(); }
    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", _apiBoot);
    else
        _apiBoot();
    // FEAT-33 — refresh on tab focus when a server-initiated write happened
    // while the tab was hidden. Skipped while local edits are in flight.
    document.addEventListener("visibilitychange", function () {
        if (document.visibilityState !== "visible" || !_activeId || _saveTimer)
            return;
        AuditAPI.get(_activeId).then(function (project) {
            if (!project || (project.server_rev || 0) === _serverRev)
                return;
            _serverRev = project.server_rev || 0;
            var pdata = typeof project.data === "string" ? JSON.parse(project.data) : (project.data || {});
            Object.keys(D).forEach(function (k) { delete D[k]; });
            Object.assign(D, pdata);
            if (typeof renderAll === "function")
                renderAll();
            showStatus(t("chrome.stale_refreshed"));
        }).catch(function () { });
    });
})();
