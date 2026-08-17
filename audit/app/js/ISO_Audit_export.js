// ═══════════════════════════════════════════════════════════════════════
// ISO Audit — EXPORT (CSV, Word, Doc Review CSV)
// ═══════════════════════════════════════════════════════════════════════
// ── CSV EXPORT ──────────────────────────────────────────────────────────
function exportCSV() {
    var CONTROLS = window.ISO_AUDIT_CONTROLS || [];
    var DOMAINS = window.ISO_AUDIT_DOMAINS || [];
    if (!D || !D.meta)
        return;
    var domainMap = {};
    DOMAINS.forEach(function (d) { domainMap[d.id] = _rt(d, "label"); });
    var rows = [["ID", "Domaine", "Contrôle", "Statut", "Preuves", "Constats", "Critère", "Constat factuel", "Cause", "Action corrective"]];
    CONTROLS.forEach(function (c) {
        var f = readFinding(c.id);
        var lbl = statusLabel(f.status) || t("audit.status.na_export") || "Non audité";
        rows.push([
            c.id,
            domainMap[c.d] || c.d,
            _rt(c, "t"),
            lbl,
            f.preuve,
            f.constats,
            f.ecart_critere,
            f.ecart_constat,
            f.ecart_cause,
            f.ecart_action
        ]);
    });
    var csv = rows.map(function (r) {
        return r.map(function (v) {
            return '"' + (v || "").replace(/"/g, '""') + '"';
        }).join(";");
    }).join("\n");
    var blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    var fname = (D.meta.ref || "audit") + "_" + (D.meta.name || "export").replace(/\s/g, "_") + ".csv";
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
    URL.revokeObjectURL(a.href);
    showStatus(t("audit.export.csv_ok") || "CSV exporté");
}
window.exportCSV = exportCSV;
// ── WORD EXPORT ─────────────────────────────────────────────────────────
function exportWord() {
    var CONTROLS = window.ISO_AUDIT_CONTROLS || [];
    var DOMAINS = window.ISO_AUDIT_DOMAINS || [];
    if (!D || !D.meta)
        return;
    showStatus(t("audit.export.word_loading") || "Preparing export...");
    // JSZip 3.10.1, vendored under js/vendor/ — same-origin, so the app CSP
    // keeps script-src 'self' with no CDN entry and the export works offline.
    _loadAsset("js/vendor/jszip.min.js", function () {
        // Preload all images from IndexedDB before building the doc
        _preloadAllImages(CONTROLS, function (imageMap) {
            _buildWordDoc(CONTROLS, DOMAINS, imageMap);
        });
    });
}
window.exportWord = exportWord;
// Preload images from IndexedDB for all controls
function _preloadAllImages(CONTROLS, cb) {
    var imageMap = {}; // ctrlId -> [{id, data, name}]
    var ctrlsWithImages = CONTROLS.filter(function (c) {
        var f = readFinding(c.id);
        return f.images && f.images.length > 0;
    });
    if (ctrlsWithImages.length === 0) {
        cb(imageMap);
        return;
    }
    var pending = ctrlsWithImages.length;
    ctrlsWithImages.forEach(function (c) {
        _imgGetAll(c.id, function (imgs) {
            imageMap[c.id] = imgs; // [{id, data, name, ctrlId}]
            if (--pending === 0)
                cb(imageMap);
        });
    });
}
function _buildWordDoc(CONTROLS, DOMAINS, imageMap) {
    var m = D.meta;
    var findings = D.findings || {};
    var now = new Date().toLocaleDateString("fr-FR");
    // ── Counts ──
    var cCnt = 0, ncmajCnt = 0, ncminCnt = 0, psCnt = 0, ppCnt = 0, naCnt = 0, todoCnt = 0;
    CONTROLS.forEach(function (ctrl) {
        var f = readFinding(ctrl.id);
        var s = f.status;
        if (s === "c")
            cCnt++;
        else if (s === "ncmaj")
            ncmajCnt++;
        else if (s === "ncmin")
            ncminCnt++;
        else if (s === "ps")
            psCnt++;
        else if (s === "pp")
            ppCnt++;
        else if (s === "na")
            naCnt++;
        else
            todoCnt++;
    });
    var audited = cCnt + ncmajCnt + ncminCnt + psCnt + ppCnt + naCnt;
    var scored = cCnt + ncmajCnt + ncminCnt + psCnt + ppCnt;
    var scorePct = scored > 0 ? Math.round(((cCnt * 1 + ppCnt * 0.75 + psCnt * 0.5 + ncminCnt * 0.25) / scored) * 100) : 0;
    var grade = scorePct >= 80 ? "A" : scorePct >= 65 ? "B" : scorePct >= 50 ? "C" : scorePct >= 35 ? "D" : "E";
    // ── OOXML helpers ──
    function xmlEsc(s) { return (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
    function p(text, style, opts) {
        opts = opts || {};
        var sz = opts.sz || "20";
        var bold = opts.bold ? "<w:b/>" : "";
        var italic = opts.italic ? "<w:i/>" : "";
        var color = opts.color ? '<w:color w:val="' + opts.color + '"/>' : "";
        var align = opts.align ? '<w:jc w:val="' + opts.align + '"/>' : "";
        var spacing = opts.spacing ? '<w:spacing w:before="' + (opts.spacing.before || 0) + '" w:after="' + (opts.spacing.after || 120) + '"/>' : '<w:spacing w:after="80"/>';
        var indent = opts.indent ? '<w:ind w:left="' + opts.indent + '"/>' : "";
        return '<w:p><w:pPr>' + align + spacing + indent + '</w:pPr><w:r><w:rPr>' + bold + italic + '<w:sz w:val="' + sz + '"/><w:szCs w:val="' + sz + '"/>' + color + '</w:rPr><w:t xml:space="preserve">' + xmlEsc(text) + '</w:t></w:r></w:p>';
    }
    function pEmpty(after) { return '<w:p><w:pPr><w:spacing w:after="' + (after || 120) + '"/></w:pPr></w:p>'; }
    function heading(text, level) {
        var configs = {
            1: { sz: "32", color: "2C3E50", bold: true, spacing: { before: 360, after: 120 } },
            2: { sz: "26", color: "1A1916", bold: true, spacing: { before: 240, after: 80 } },
            3: { sz: "22", color: "3A3A3A", bold: true, spacing: { before: 160, after: 60 } }
        };
        var cfg = configs[level] || configs[2];
        return p(text, null, cfg);
    }
    function hrLine() {
        return '<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="2C3E50"/></w:pBdr><w:spacing w:after="80"/></w:pPr></w:p>';
    }
    function pageBreak() {
        return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>';
    }
    function table(rows, colWidths) {
        var totalW = colWidths.reduce(function (a, b) { return a + b; }, 0);
        var gridCols = colWidths.map(function (w) { return '<w:gridCol w:w="' + w + '"/>'; }).join("");
        var bdr = "<w:tblBorders>"
            + '<w:top w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + '<w:left w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + '<w:bottom w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + '<w:right w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + '<w:insideH w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + '<w:insideV w:val="single" w:sz="4" w:color="DDDDDD"/>'
            + "</w:tblBorders>";
        var tblXml = '<w:tbl><w:tblPr><w:tblW w:w="' + totalW + '" w:type="dxa"/>' + bdr
            + '<w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar>'
            + '</w:tblPr><w:tblGrid>' + gridCols + '</w:tblGrid>'
            + rows.map(function (row) {
                return "<w:tr>" + row.cells.map(function (cell, ci) {
                    var bg = cell.bg ? '<w:shd w:val="clear" w:color="auto" w:fill="' + cell.bg + '"/>' : "";
                    var w = colWidths[ci] || 1000;
                    var cellAlign = cell.align ? '<w:jc w:val="' + cell.align + '"/>' : "";
                    var b = cell.bold ? "<w:b/>" : "";
                    var col = cell.color ? '<w:color w:val="' + cell.color + '"/>' : "";
                    var sz = '<w:sz w:val="' + (cell.sz || "18") + '"/><w:szCs w:val="' + (cell.sz || "18") + '"/>';
                    return '<w:tc><w:tcPr><w:tcW w:w="' + w + '" w:type="dxa"/>' + bg + '</w:tcPr>'
                        + '<w:p><w:pPr>' + cellAlign + '<w:spacing w:after="60"/></w:pPr>'
                        + '<w:r><w:rPr>' + b + sz + col + '</w:rPr><w:t xml:space="preserve">' + xmlEsc(cell.text || "") + '</w:t></w:r></w:p></w:tc>';
                }).join("") + "</w:tr>";
            }).join("") + "</w:tbl>";
        return tblXml;
    }
    function _sColor(s) {
        return s === "c" ? "27AE60" : s === "ncmaj" ? "C0203A" : s === "ncmin" ? "C06000" : s === "ps" ? "6030C0" : s === "pp" ? "3498DB" : "888888";
    }
    function _sLabel(s) {
        return statusLabel(s) || t("audit.status.na_export") || "N/A";
    }
    // ── Image tracking for OOXML ──
    var _imgRels = []; // { rId, filename, base64 }
    var _imgIdx = 0;
    function addImage(dataUrl, widthCm) {
        if (!dataUrl)
            return "";
        _imgIdx++;
        var rId = "rImg" + _imgIdx;
        var ext = dataUrl.indexOf("image/png") >= 0 ? "png" : "jpeg";
        var fname = "image" + _imgIdx + "." + ext;
        var b64 = dataUrl.split(",")[1] || "";
        if (!b64)
            return "";
        _imgRels.push({ rId: rId, filename: fname, base64: b64 });
        var wEmu = Math.round((widthCm || 12) * 360000);
        var hEmu = Math.round(wEmu * 0.75); // assume 4:3 aspect
        return '<w:p><w:pPr><w:spacing w:after="80"/></w:pPr><w:r><w:drawing>'
            + '<wp:inline distT="0" distB="0" distL="0" distR="0">'
            + '<wp:extent cx="' + wEmu + '" cy="' + hEmu + '"/>'
            + '<wp:docPr id="' + _imgIdx + '" name="' + xmlEsc(fname) + '"/>'
            + '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            + '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            + '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            + '<pic:nvPicPr><pic:cNvPr id="' + _imgIdx + '" name="' + xmlEsc(fname) + '"/><pic:cNvPicPr/></pic:nvPicPr>'
            + '<pic:blipFill><a:blip r:embed="' + rId + '"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            + '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="' + wEmu + '" cy="' + hEmu + '"/></a:xfrm>'
            + '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            + '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>';
    }
    // ── START BUILDING BODY ──
    var body = "";
    // ═══ PAGE DE GARDE ═══
    body += pEmpty(600);
    body += p("Rapport d'audit ISO 27001", null, { sz: "48", bold: true, color: "2C3E50", align: "center", spacing: { before: 0, after: 40 } });
    body += p("Système de management de la sécurité de l'information", null, { sz: "24", color: "555555", align: "center", spacing: { before: 0, after: 400 } });
    body += hrLine();
    body += pEmpty(200);
    body += p(m.name || "[Client]", null, { sz: "40", bold: true, align: "center", spacing: { before: 0, after: 60 } });
    body += p("Audit ISO 27001:2022" + (m.hds && m.hds !== "non" ? " + HDS" : ""), null, { sz: "26", color: "2C3E50", align: "center", spacing: { before: 0, after: 400 } });
    body += pEmpty(200);
    body += table([
        { cells: [{ text: "Référence", bold: true, bg: "F0F0F0", sz: "18" }, { text: m.ref || "", sz: "18" }] },
        { cells: [{ text: "Date", bold: true, bg: "F0F0F0", sz: "18" }, { text: m.date || now, sz: "18" }] },
        { cells: [{ text: "Auditeur(s)", bold: true, bg: "F0F0F0", sz: "18" }, { text: m.auditor || "", sz: "18" }] },
        { cells: [{ text: "Périmètre", bold: true, bg: "F0F0F0", sz: "18" }, { text: m.scope || "À définir", sz: "18" }] }
    ], [2200, 6800]);
    body += pEmpty(400);
    body += p("Confidentiel — usage interne", null, { sz: "16", color: "999999", align: "center", italic: true });
    body += pageBreak();
    // ═══ SYNTHÈSE EXECUTIVE ═══
    body += heading("Synthèse exécutive", 1);
    body += hrLine();
    body += pEmpty();
    body += table([
        { cells: [
                { text: "Indicateur", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "20" },
                { text: "Valeur", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "20", align: "center" }
            ] },
        { cells: [
                { text: "Mesures totales", bg: "F7F7F7", sz: "20" },
                { text: String(CONTROLS.length), align: "center", sz: "20", bg: "F7F7F7" }
            ] },
        { cells: [
                { text: "Mesures auditées", sz: "20" },
                { text: String(audited), align: "center", bold: true, sz: "20", color: "2C3E50" }
            ] },
        { cells: [
                { text: "Conformes", bg: "F7F7F7", sz: "20" },
                { text: String(cCnt), align: "center", bold: true, sz: "20", color: "2C3E50", bg: "F7F7F7" }
            ] },
        { cells: [
                { text: "NC majeures", sz: "20" },
                { text: String(ncmajCnt), align: "center", bold: true, sz: "20", color: ncmajCnt > 0 ? "C0203A" : "2C3E50" }
            ] },
        { cells: [
                { text: "NC mineures", bg: "F7F7F7", sz: "20" },
                { text: String(ncminCnt), align: "center", bold: true, sz: "20", color: ncminCnt > 0 ? "C06000" : "2C3E50", bg: "F7F7F7" }
            ] },
        { cells: [
                { text: "Score de maturité", sz: "20" },
                { text: scorePct + "% — Niveau " + grade, align: "center", bold: true, sz: "20", color: scorePct >= 80 ? "2C3E50" : scorePct >= 50 ? "C06000" : "C0203A" }
            ] }
    ], [4500, 4500]);
    body += pEmpty();
    body += pageBreak();
    // ═══ DÉTAIL PAR DOMAINE ═══
    DOMAINS.forEach(function (dom) {
        var ctrls = CONTROLS.filter(function (c) { return c.d === dom.id; });
        if (ctrls.length === 0)
            return;
        body += heading(_rt(dom, "label"), 1);
        body += hrLine();
        body += pEmpty();
        var domRows = [{ cells: [
                    { text: "Réf.", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "18" },
                    { text: "Contrôle", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "18" },
                    { text: "Statut", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "18", align: "center" },
                    { text: "Constats / Preuves", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "18" }
                ] }];
        ctrls.forEach(function (ctrl, i) {
            var f = readFinding(ctrl.id);
            var bg = i % 2 === 0 ? "F7F7F7" : "FFFFFF";
            var notes = (f.constats || "") + (f.preuve ? (f.constats ? " | " : "") + f.preuve : "");
            domRows.push({ cells: [
                    { text: ctrl.id, bold: true, color: _sColor(f.status), bg: bg, sz: "18" },
                    { text: ctrl.t, bg: bg, sz: "18" },
                    { text: _sLabel(f.status), align: "center", bold: true, color: _sColor(f.status), bg: bg, sz: "16" },
                    { text: notes || "", bg: bg, sz: "16" }
                ] });
            // Track which controls have images
            ctrl._ctrlImages = imageMap[ctrl.id] || [];
        });
        body += table(domRows, [1000, 3200, 1800, 3000]);
        body += pEmpty();
        // Add images for controls that have them
        ctrls.forEach(function (ctrl) {
            if (!ctrl._ctrlImages || ctrl._ctrlImages.length === 0)
                return;
            body += heading(ctrl.id + " — Images preuves", 3);
            ctrl._ctrlImages.forEach(function (img) {
                if (img.data) {
                    if (img.name)
                        body += p(img.name, null, { sz: "16", italic: true, color: "666666" });
                    body += addImage(img.data, 14);
                }
            });
            body += pEmpty();
        });
        body += pageBreak();
    });
    // ═══ NON-CONFORMITÉS ═══
    var ncSeverityOrder = { ncmaj: 0, ncmin: 1, ps: 2, pp: 3 };
    var ncs = CONTROLS.filter(function (c) {
        var s = readFinding(c.id).status;
        return s === "ncmaj" || s === "ncmin" || s === "ps" || s === "pp";
    }).sort(function (a, b) {
        // BUG FIX (portage TS) : l'original utilisait `|| 99` — ncmaj (0, falsy)
        // était trié en dernier au lieu de premier. `??` préserve le 0.
        var sa = ncSeverityOrder[readFinding(a.id).status] ?? 99;
        var sb = ncSeverityOrder[readFinding(b.id).status] ?? 99;
        return sa - sb;
    });
    if (ncs.length > 0) {
        body += heading("Non-conformités et écarts", 1);
        body += hrLine();
        body += pEmpty();
        var ncRows = [{ cells: [
                    { text: "#", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16", align: "center" },
                    { text: "Réf.", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16" },
                    { text: "Type", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16", align: "center" },
                    { text: "Contrôle", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16" },
                    { text: "Constat", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16" },
                    { text: "Action corrective", bold: true, bg: "2C3E50", color: "FFFFFF", sz: "16" }
                ] }];
        ncs.forEach(function (ctrl, i) {
            var f = readFinding(ctrl.id);
            var bg = i % 2 === 0 ? "F7F7F7" : "FFFFFF";
            ncRows.push({ cells: [
                    { text: String(i + 1), align: "center", bg: bg, sz: "16" },
                    { text: ctrl.id, bold: true, color: _sColor(f.status), bg: bg, sz: "16" },
                    { text: _sLabel(f.status), align: "center", bold: true, color: _sColor(f.status), bg: bg, sz: "15" },
                    { text: ctrl.t, bg: bg, sz: "16" },
                    { text: f.ecart_constat || f.constats || "", bg: bg, sz: "16" },
                    { text: f.ecart_action || "", bg: bg, sz: "16" }
                ] });
        });
        body += table(ncRows, [400, 900, 1200, 2200, 2200, 2100]);
        body += pEmpty();
    }
    // ── Assemble OOXML document ──
    var ooxml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        + '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mo="http://schemas.microsoft.com/office/mac/office/2008/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:mv="urn:schemas-microsoft-com:mac:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="mv mo w14 wp14">'
        + "<w:body>"
        + '<w:sectPr>'
        + '<w:pgSz w:w="11906" w:h="16838"/>'
        + '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="709" w:footer="709" w:gutter="0"/>'
        + '</w:sectPr>'
        + body
        + "</w:body></w:document>";
    // ── Build DOCX via JSZip ──
    // Build content types with image extensions
    var ctExtras = "";
    var hasJpeg = _imgRels.some(function (r) { return r.filename.endsWith(".jpeg"); });
    var hasPng = _imgRels.some(function (r) { return r.filename.endsWith(".png"); });
    if (hasJpeg)
        ctExtras += '<Default Extension="jpeg" ContentType="image/jpeg"/>';
    if (hasPng)
        ctExtras += '<Default Extension="png" ContentType="image/png"/>';
    var contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' + ctExtras + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
    var rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
    // Build word rels with image references
    var imgRelsXml = _imgRels.map(function (r) {
        return '<Relationship Id="' + r.rId + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/' + r.filename + '"/>';
    }).join("");
    var wordRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + imgRelsXml + '</Relationships>';
    var fname = (m.ref || "audit").replace(/[^a-zA-Z0-9\-_]/g, "_") + "_" + (m.name || "export").replace(/\s/g, "_") + ".docx";
    if (typeof JSZip !== "undefined") {
        var zip = new JSZip();
        zip.file("[Content_Types].xml", contentTypes);
        zip.folder("_rels").file(".rels", rels);
        zip.folder("word").file("document.xml", ooxml);
        zip.folder("word/_rels").file("document.xml.rels", wordRels);
        // Add images to word/media/
        _imgRels.forEach(function (r) {
            zip.folder("word/media").file(r.filename, r.base64, { base64: true });
        });
        zip.generateAsync({ type: "blob", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }).then(function (blob) {
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = fname;
            a.click();
            URL.revokeObjectURL(a.href);
            showStatus(t("audit.export.word_ok") || "Word exporté");
        });
    }
    else {
        var blob = new Blob([ooxml], { type: "application/xml" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = fname.replace(".docx", ".xml");
        a.click();
        URL.revokeObjectURL(a.href);
        showStatus("JSZip non disponible — fichier XML téléchargé");
    }
}
// ── DOC REVIEW CSV EXPORT ───────────────────────────────────────────────
function exportDocReviewCSV() {
    var DOC_REVIEW = window.ISO_AUDIT_DOC_REVIEW || [];
    if (!D || !D.doc_review)
        return;
    var statusMap = { recu: "Reçu", incomplet: "Incomplet", manquant: "Manquant", na: "N/A" };
    var rows = [["Ref", "Document", "Statut", "Observations"]];
    DOC_REVIEW.forEach(function (d) {
        var entry = D.doc_review[d.ref] || {};
        rows.push([
            d.ref,
            _rt(d, "label"),
            statusMap[entry.status || ""] || "",
            entry.observations || ""
        ]);
    });
    var csv = rows.map(function (r) {
        return r.map(function (v) {
            return '"' + (v || "").replace(/"/g, '""') + '"';
        }).join(";");
    }).join("\n");
    var blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    var fname = (D.meta.ref || "audit") + "_" + (D.meta.name || "revue_doc").replace(/\s/g, "_") + "_revue_doc.csv";
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
    URL.revokeObjectURL(a.href);
    showStatus(t("audit.export.docreview_ok") || "Revue documentaire exportée");
}
window.exportDocReviewCSV = exportDocReviewCSV;
