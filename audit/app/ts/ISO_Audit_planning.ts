// ═══════════════════════════════════════════════════════════════════════
// ISO Audit — PLANNING
// ═══════════════════════════════════════════════════════════════════════

var PLANNING_DOMAINS: AuditDomain[] = window.ISO_AUDIT_DOMAINS || [];

// ── HELPERS ──

function _pad2(n: number): string { return n < 10 ? "0" + n : "" + n; }

function _addMinutes(timeStr: string, minutes: number): string {
    var parts = timeStr.split(":");
    var h = parseInt(parts[0], 10);
    var m = parseInt(parts[1], 10) + minutes;
    while (m >= 60) { h++; m -= 60; }
    while (m < 0) { h--; m += 60; }
    return _pad2(h) + ":" + _pad2(m);
}

function _timeToMin(timeStr: string): number {
    var parts = timeStr.split(":");
    return parseInt(parts[0], 10) * 60 + parseInt(parts[1], 10);
}

// ── RENDER HELPERS ──

function _formatDayHeader(dateStr: string, dayNum: number): string {
    // dateStr = "2026-03-15" → "Day 1 — Monday, March 15, 2026", in the UI's
    // language. Without a start date the slots carry no real date: the header
    // is the day number alone, never "undefined NaN".
    var head = t("audit.planning.day") + " " + dayNum;
    var parts = String(dateStr || "").split("-");
    var d = new Date(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, parseInt(parts[2], 10));
    if (parts.length !== 3 || isNaN(d.getTime())) return head;
    return head + " — " + d.toLocaleDateString(_locale, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
}

function _domainGroup(domainId: string): string {
    for (var i = 0; i < PLANNING_DOMAINS.length; i++) {
        if (PLANNING_DOMAINS[i].id === domainId) return PLANNING_DOMAINS[i].group;
    }
    return "";
}

function _domainLabel(domainId: string): string {
    for (var i = 0; i < PLANNING_DOMAINS.length; i++) {
        if (PLANNING_DOMAINS[i].id === domainId) return _rt(PLANNING_DOMAINS[i] as unknown as Record<string, any>, "label");
    }
    return domainId;
}

// ── RENDER ──

function renderPlanning(): void {
    var el = document.getElementById("planning-content");
    if (!el) return;

    var p = D.planning.params;
    var h = '';

    // ── Parameters section ── a socle form: two columns, one on a phone.
    var champ = function(key: string, input: string): string {
        return '<div class="ct-form-row"><label>' + t("audit.planning." + key) + '</label>' + input + '</div>';
    };
    var saisie = function(type: string, key: string, value: string, extra?: string): string {
        return '<input type="' + type + '"' + (extra || "") + ' value="' + esc(value) + '" data-change="onPlanningParam" data-args=\'' + _da(key) + '\' data-pass-value>';
    };
    h += '<div class="ct-tprm-form ct-mb-5"><div class="ct-form-grid">';
    h += champ("start_date", saisie("date", "start_date", p.start_date || ""));
    h += champ("days", saisie("number", "days", String(p.days || 3), ' min="1" max="10"'));
    h += champ("start_time", saisie("time", "start_time", p.start_time || "09:00"));
    h += champ("slot_duration", saisie("number", "slot_duration", String(p.slot_duration || 60), ' min="15" max="240" step="15"'));
    h += champ("lunch_start", saisie("time", "lunch_start", p.lunch_start || "12:30"));
    h += champ("lunch_duration", saisie("number", "lunch_duration", String(p.lunch_duration || 60), ' min="0" max="120" step="15"'));
    h += '</div></div>';

    // ── Generate button ──
    h += '<div class="ct-ta-c ct-mb-5">';
    h += '<button class="ct-btn" data-variant="primary" data-click="generatePlanning">' + t("audit.planning.generate") + '</button>';
    h += '</div>';

    // ── Planning timeline ──
    if (D.planning.slots && D.planning.slots.length > 0) {
        var currentDay = "";
        var dayNum = 0;

        D.planning.slots.forEach(function(slot, idx) {
            // Day header
            if (slot.date && slot.date !== currentDay) {
                if (currentDay !== "") h += '</div>'; // close previous day container
                currentDay = slot.date;
                dayNum++;
                h += '<div class="planning-day">';
                h += '<div class="planning-day-head">' + esc(_formatDayHeader(slot.date, dayNum)) + '</div>';
            }

            if (slot.type === "lunch") {
                // ── Lunch separator ──
                h += '<div class="planning-lunch">';
                h += '<span class="slot-time">' + esc(slot.start) + ' - ' + esc(slot.end) + '</span>';
                h += '<span class="ct-italic">' + t("audit.planning.lunch") + '</span>';
                h += '</div>';
            } else {
                // ── Audit slot card ── ISO clauses vs Annex A, on theme tokens
                var grp = _domainGroup(slot.domain);
                var kind = grp === "Clauses ISO 27001" ? "clause" : "annex";

                h += '<div class="planning-slot" data-kind="' + kind + '">';
                h += '<span class="slot-time">' + esc(slot.start) + ' - ' + esc(slot.end) + '</span>';

                // Domain select
                h += '<select class="slot-domain ct-select" data-size="sm" data-change="onSlotDomain" data-args=\'' + _da(idx) + '\' data-pass-value>';
                h += '<option value="">' + t("audit.planning.select_domain") + '</option>';
                PLANNING_DOMAINS.forEach(function(dom) {
                    h += '<option value="' + esc(dom.id) + '"' + (slot.domain === dom.id ? ' selected' : '') + '>' + esc(_rt(dom as unknown as Record<string, any>, "label")) + '</option>';
                });
                h += '</select>';

                // Delete button
                h += '<button class="ct-btn" data-variant="danger" data-size="sm" data-icon data-click="deleteSlot" data-args=\'' + _da(idx) + '\' title="' + esc(t("btn_delete")) + '" aria-label="' + esc(t("btn_delete")) + '">&times;</button>';

                h += '</div>';
            }
        });

        if (currentDay !== "") h += '</div>'; // close last day container

        // ── Export buttons ──
        h += '<div class="planning-exports">';
        h += '<button class="btn-report" data-click="exportPlanningCSV">' + t("audit.planning.export_csv") + '</button>';
        h += '<button class="btn-report" data-click="exportPlanningWord">' + t("audit.planning.export_word") + '</button>';
        h += '</div>';
    }

    el.innerHTML = h;
}
window.renderPlanning = renderPlanning;

// ── EXPORT FUNCTIONS ──

function exportPlanningCSV(): void {
    if (!D.planning.slots || D.planning.slots.length === 0) return;
    var rows = [[t("audit.planning.col_date"), t("audit.planning.col_start"), t("audit.planning.col_end"), t("audit.planning.col_type"), t("audit.planning.col_domain")]];
    D.planning.slots.forEach(function(s) {
        rows.push([s.date, s.start, s.end, s.type === "lunch" ? "Pause" : "Audit", _domainLabel(s.domain)]);
    });
    var csv = rows.map(function(r) { return r.map(function(c) { return '"' + String(c).replace(/"/g,'""') + '"'; }).join(";"); }).join("\n");
    var blob = new Blob(["\uFEFF" + csv], {type:"text/csv;charset=utf-8;"});
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "planning_audit_" + (D.meta.ref || "export") + ".csv";
    a.click();
}
window.exportPlanningCSV = exportPlanningCSV;

function exportPlanningWord(): void {
    if (!D.planning.slots || D.planning.slots.length === 0) return;
    var html = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word"><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:Calibri,sans-serif;font-size:10pt}th{background:#2c3e50;color:white;padding:6px 10px;text-align:left}td{padding:5px 10px;border:1px solid #bdc3c7}.day-header{background:#ecf0f1;font-weight:bold;font-size:11pt}.lunch{background:#f9f9f9;color:#95a5a6;font-style:italic}</style></head><body>';
    html += '<h1 style="font-family:Calibri;color:#2c3e50">' + esc(t("audit.planning.doc_title")) + ' — ' + esc(D.meta.name || "") + '</h1>';
    html += '<p style="font-family:Calibri;color:#7f8c8d">Ref: ' + esc(D.meta.ref || "") + ' | Date: ' + esc(D.meta.date || "") + '</p>';
    html += '<table><tr><th>' + t("audit.planning.col_time") + '</th><th>' + t("audit.planning.col_domain") + '</th></tr>';
    var curDay = "";
    D.planning.slots.forEach(function(s) {
        if (s.date !== curDay) {
            curDay = s.date;
            html += '<tr><td colspan="2" class="day-header">' + esc(s.date) + '</td></tr>';
        }
        if (s.type === "lunch") {
            html += '<tr class="lunch"><td>' + esc(s.start) + ' - ' + esc(s.end) + '</td><td>' + esc(t("audit.planning.lunch")) + '</td></tr>';
        } else {
            html += '<tr><td>' + esc(s.start) + ' - ' + esc(s.end) + '</td><td>' + esc(_domainLabel(s.domain)) + '</td></tr>';
        }
    });
    html += '</table></body></html>';
    var blob = new Blob([html], {type:"application/msword"});
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "planning_audit_" + (D.meta.ref || "export") + ".doc";
    a.click();
}
window.exportPlanningWord = exportPlanningWord;

// ── HANDLERS ──

function onPlanningParam(field: string, val: string): void {
    _saveState();
    if (field === "days" || field === "slot_duration" || field === "lunch_duration") {
        D.planning.params[field] = parseInt(val, 10) || 0;
    } else {
        (D.planning.params as Record<string, string | number | undefined>)[field] = val;
    }
    _autoSave();
}
window.onPlanningParam = onPlanningParam;

function onSlotDomain(idx: number | string, val: string): void {
    _saveState();
    idx = parseInt(String(idx), 10);
    if (D.planning.slots[idx]) {
        D.planning.slots[idx].domain = val;
        _autoSave();
    }
}
window.onSlotDomain = onSlotDomain;

function generatePlanning(): void {
    _saveState();
    var p = D.planning.params;
    var days = p.days || 3;
    var startTime = p.start_time || "09:00";
    var duration = p.slot_duration || 60;
    var lunchStart = p.lunch_start || "12:30";
    var lunchDur = p.lunch_duration || 60;
    var startDate = p.start_date || "";

    // Collect available domains
    var domainIds = PLANNING_DOMAINS.map(function(d) { return d.id; });
    var domIdx = 0;

    var slots: AuditSlot[] = [];

    for (var day = 0; day < days; day++) {
        var dateStr = "";
        if (startDate) {
            // "YYYY-MM-DD" parses as UTC midnight: step the day in UTC too.
            // Stepping in local time lands on the previous UTC day once the
            // clocks go forward: two days came out with one date and every
            // later day one day early.
            var d = new Date(startDate);
            d.setUTCDate(d.getUTCDate() + day);
            dateStr = d.toISOString().slice(0, 10);
        } else {
            dateStr = t("audit.planning.day") + " " + (day + 1);
        }

        var cursor = startTime;
        var endOfDay = "18:00";
        var lunchStartMin = _timeToMin(lunchStart);
        var lunchEndMin = lunchStartMin + lunchDur;

        while (_timeToMin(cursor) + duration <= _timeToMin(endOfDay)) {
            var cursorMin = _timeToMin(cursor);
            var slotEnd = _addMinutes(cursor, duration);

            // Check if slot overlaps lunch
            if (cursorMin < lunchEndMin && _timeToMin(slotEnd) > lunchStartMin && lunchDur > 0) {
                // Insert lunch slot if we're at lunch start
                if (cursorMin <= lunchStartMin) {
                    slots.push({ date: dateStr, start: lunchStart, end: _addMinutes(lunchStart, lunchDur), type: "lunch", domain: "" });
                    cursor = _addMinutes(lunchStart, lunchDur);
                    continue;
                }
                cursor = _addMinutes(lunchStart, lunchDur);
                continue;
            }

            // Assign domain round-robin
            var domain = domainIds.length > 0 ? domainIds[domIdx % domainIds.length] : "";
            domIdx++;

            slots.push({ date: dateStr, start: cursor, end: slotEnd, type: "audit", domain: domain });
            cursor = slotEnd;
        }
    }

    D.planning.slots = slots;
    _autoSave();
    renderPlanning();
}
window.generatePlanning = generatePlanning;

function deleteSlot(idx: number | string): void {
    _saveState();
    idx = parseInt(String(idx), 10);
    if (D.planning.slots[idx] !== undefined) {
        D.planning.slots.splice(idx, 1);
        _autoSave();
        renderPlanning();
    }
}
window.deleteSlot = deleteSlot;
