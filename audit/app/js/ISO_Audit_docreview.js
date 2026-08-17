// ═══════════════════════════════════════════════════════════════════════
// ISO Audit — DOCUMENT REVIEW
// ═══════════════════════════════════════════════════════════════════════
window.ISO_AUDIT_DOC_REVIEW = [
    { ref: "D-01", cat: "Gouvernance", cat_en: "Governance", label: "Politique de securite de l'information", label_en: "Information security policy", desc: "Document cadre approuve par la direction, diffuse et revise periodiquement.", desc_en: "Framework document approved by top management, published and reviewed periodically.", critical: true, hds: true, linkedControls: ["5.2", "A.5.1"], ecartAuto: "Absence de politique SSI formalisee - NC majeure probable sur §5.2 et A.5.1", ecartAuto_en: "No formalized information security policy - probable major NC on §5.2 and A.5.1" },
    { ref: "D-02", cat: "Gouvernance", cat_en: "Governance", label: "Declaration d'Applicabilite (SoA)", label_en: "Statement of Applicability (SoA)", desc: "Liste des mesures de l'Annexe A avec justification d'inclusion/exclusion et statut de mise en oeuvre.", desc_en: "List of Annex A controls with inclusion/exclusion justification and implementation status.", critical: true, hds: true, linkedControls: ["6.1.3"], ecartAuto: "SoA absente - NC majeure sur §6.1.3", ecartAuto_en: "SoA missing - major NC on §6.1.3" },
    { ref: "D-03", cat: "Gouvernance", cat_en: "Governance", label: "Registre des risques SSI", label_en: "Information security risk register", desc: "Resultats de l'appreciation des risques avec mesures de traitement associees.", desc_en: "Risk assessment results with associated treatment measures.", critical: true, hds: true, linkedControls: ["6.1.2", "8.2"], ecartAuto: "Registre absent - NC majeure sur §6.1.2", ecartAuto_en: "Register missing - major NC on §6.1.2" },
    { ref: "D-04", cat: "Gouvernance", cat_en: "Governance", label: "Plan de traitement des risques", label_en: "Risk treatment plan", desc: "Plan d'action pour traiter les risques identifies avec responsables et echeances.", desc_en: "Action plan to treat identified risks with owners and deadlines.", critical: true, hds: false, linkedControls: ["6.1.3", "8.3"], ecartAuto: "Plan de traitement absent - NC sur §6.1.3 et §8.3", ecartAuto_en: "Treatment plan missing - NC on §6.1.3 and §8.3" },
    { ref: "D-05", cat: "Gouvernance", cat_en: "Governance", label: "Compte-rendu de revue de direction", label_en: "Management review minutes", desc: "PV de la derniere revue annuelle du SMSI par la direction.", desc_en: "Minutes of the last annual management review of the ISMS.", critical: true, hds: false, linkedControls: ["9.3"], ecartAuto: "Absence de revue de direction documentee - NC sur §9.3", ecartAuto_en: "No documented management review - NC on §9.3" },
    { ref: "D-06", cat: "Gouvernance", cat_en: "Governance", label: "Rapport du dernier audit interne", label_en: "Latest internal audit report", desc: "Resultats et plan d'actions du dernier audit interne SMSI.", desc_en: "Results and action plan of the latest ISMS internal audit.", critical: false, hds: false, linkedControls: ["9.2"], ecartAuto: "Absence d'audit interne documente - NC sur §9.2", ecartAuto_en: "No documented internal audit - NC on §9.2" },
    { ref: "D-07", cat: "Gouvernance", cat_en: "Governance", label: "Tableau de bord des indicateurs SSI", label_en: "Information security indicators dashboard", desc: "Indicateurs de performance et d'efficacite du SMSI.", desc_en: "ISMS performance and effectiveness indicators.", critical: false, hds: false, linkedControls: ["9.1"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-08", cat: "Organisation", cat_en: "Organization", label: "Organigramme SSI et fiches de poste RSSI", label_en: "Information security org chart and CISO job descriptions", desc: "Structure organisationnelle SSI avec roles et responsabilites documentes.", desc_en: "Information security organizational structure with documented roles and responsibilities.", critical: true, hds: false, linkedControls: ["5.3", "A.5.2"], ecartAuto: "Roles SSI non documentes - Ecart potentiel sur §5.3", ecartAuto_en: "Information security roles not documented - potential finding on §5.3" },
    { ref: "D-09", cat: "Organisation", cat_en: "Organization", label: "Plan de sensibilisation et formation SSI", label_en: "Information security awareness and training plan", desc: "Programme annuel de sensibilisation et formation du personnel.", desc_en: "Annual personnel awareness and training programme.", critical: false, hds: true, linkedControls: ["7.2", "7.3", "A.6.3"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-10", cat: "Organisation", cat_en: "Organization", label: "Accords de confidentialite (NDA)", label_en: "Confidentiality agreements (NDA)", desc: "Modele NDA et liste des signatures du personnel et prestataires.", desc_en: "NDA template and list of signatures from personnel and contractors.", critical: false, hds: true, linkedControls: ["A.6.6"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-11", cat: "Organisation", cat_en: "Organization", label: "Registre des exigences legales et reglementaires", label_en: "Register of legal and regulatory requirements", desc: "Inventaire des obligations legales applicables (HDS, RGPD, NIS2, Code sante).", desc_en: "Inventory of applicable legal obligations (HDS, GDPR, NIS2, health regulations).", critical: true, hds: true, linkedControls: ["A.5.31"], ecartAuto: "Registre absent - Ecart sur A.5.31", ecartAuto_en: "Register missing - finding on A.5.31" },
    { ref: "D-12", cat: "Organisation", cat_en: "Organization", label: "Procedure de gestion des incidents SSI", label_en: "Information security incident management procedure", desc: "Processus de detection, signalement, classification et traitement des incidents.", desc_en: "Process for detecting, reporting, classifying and handling incidents.", critical: true, hds: true, linkedControls: ["A.5.24", "A.5.26"], ecartAuto: "Absence de procedure incidents - NC sur A.5.24", ecartAuto_en: "No incident procedure - NC on A.5.24" },
    { ref: "D-13", cat: "Organisation", cat_en: "Organization", label: "Procedure de gestion des non-conformites", label_en: "Nonconformity management procedure", desc: "Processus de traitement des NC et actions correctives.", desc_en: "Process for handling NCs and corrective actions.", critical: false, hds: false, linkedControls: ["10.1"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-14", cat: "Actifs et acces", cat_en: "Assets and access", label: "Inventaire des actifs informationnels", label_en: "Inventory of information assets", desc: "Inventaire complet des actifs avec proprietaire, classification et localisation.", desc_en: "Complete asset inventory with owner, classification and location.", critical: true, hds: true, linkedControls: ["A.5.9", "A.5.10"], ecartAuto: "Inventaire absent - NC sur A.5.9", ecartAuto_en: "Inventory missing - NC on A.5.9" },
    { ref: "D-15", cat: "Actifs et acces", cat_en: "Assets and access", label: "Politique de classification de l'information", label_en: "Information classification policy", desc: "Niveaux de classification, criteres d'attribution et regles de traitement.", desc_en: "Classification levels, assignment criteria and handling rules.", critical: true, hds: true, linkedControls: ["A.5.12"], ecartAuto: "Politique de classification absente - Ecart sur A.5.12", ecartAuto_en: "Classification policy missing - finding on A.5.12" },
    { ref: "D-16", cat: "Actifs et acces", cat_en: "Assets and access", label: "Politique de controle d'acces", label_en: "Access control policy", desc: "Regles d'acces logique aux systemes et donnees, principe du moindre privilege.", desc_en: "Logical access rules for systems and data, least privilege principle.", critical: true, hds: true, linkedControls: ["A.5.15", "A.5.16", "A.5.18"], ecartAuto: "Politique d'acces absente - NC potentielle sur A.5.15", ecartAuto_en: "Access policy missing - potential NC on A.5.15" },
    { ref: "D-17", cat: "Actifs et acces", cat_en: "Assets and access", label: "Resultats de la derniere revue des droits d'acces", label_en: "Results of the latest access rights review", desc: "Rapport de revue periodique des droits utilisateurs et acces privilegies.", desc_en: "Report of the periodic review of user rights and privileged access.", critical: true, hds: true, linkedControls: ["A.5.18", "A.8.2"], ecartAuto: "Absence de revue des droits - NC sur A.5.18", ecartAuto_en: "No access rights review - NC on A.5.18" },
    { ref: "D-18", cat: "Actifs et acces", cat_en: "Assets and access", label: "Politique de gestion des mots de passe", label_en: "Password management policy", desc: "Exigences de complexite, duree de vie, stockage et renouvellement.", desc_en: "Complexity, lifetime, storage and renewal requirements.", critical: false, hds: false, linkedControls: ["A.5.17"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-19", cat: "Securite physique", cat_en: "Physical security", label: "Plan des zones de securite physique", label_en: "Physical security zone map", desc: "Cartographie des perimetres physiques, zones d'acces controle, salle serveurs.", desc_en: "Map of physical perimeters, controlled access zones, server room.", critical: true, hds: true, linkedControls: ["A.7.1", "A.7.2"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-20", cat: "Securite physique", cat_en: "Physical security", label: "Procedure de mise au rebut des equipements", label_en: "Equipment disposal procedure", desc: "Processus d'effacement securise des donnees avant cession ou destruction.", desc_en: "Secure data erasure process before transfer or destruction.", critical: false, hds: true, linkedControls: ["A.7.14", "A.8.10"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-21", cat: "Securite technique", cat_en: "Technical security", label: "Schema d'architecture reseau", label_en: "Network architecture diagram", desc: "Topologie reseau, segmentation VLAN, flux autorises, DMZ.", desc_en: "Network topology, VLAN segmentation, authorized flows, DMZ.", critical: true, hds: true, linkedControls: ["A.8.20", "A.8.22"], ecartAuto: "Schema reseau absent - Verification architecture impossible", ecartAuto_en: "Network diagram missing - architecture verification impossible" },
    { ref: "D-22", cat: "Securite technique", cat_en: "Technical security", label: "Politique de sauvegarde", label_en: "Backup policy", desc: "Frequence, retention, tests de restauration et stockage hors-site.", desc_en: "Frequency, retention, restoration tests and off-site storage.", critical: true, hds: true, linkedControls: ["A.8.13"], ecartAuto: "Politique sauvegarde absente - NC probable sur A.8.13", ecartAuto_en: "Backup policy missing - probable NC on A.8.13" },
    { ref: "D-23", cat: "Securite technique", cat_en: "Technical security", label: "Dernier rapport de scan de vulnerabilites", label_en: "Latest vulnerability scan report", desc: "Resultats du dernier scan avec criticites et plan de remediation.", desc_en: "Latest scan results with severity levels and remediation plan.", critical: true, hds: true, linkedControls: ["A.8.8"], ecartAuto: "Absence de scan de vulnerabilites - NC sur A.8.8", ecartAuto_en: "No vulnerability scan - NC on A.8.8" },
    { ref: "D-24", cat: "Securite technique", cat_en: "Technical security", label: "Politique de gestion des correctifs (patch management)", label_en: "Patch management policy", desc: "Frequence de mise a jour, delais selon criticite, procedure d'urgence.", desc_en: "Update frequency, timelines by criticality, emergency procedure.", critical: true, hds: true, linkedControls: ["A.8.8"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-25", cat: "Securite technique", cat_en: "Technical security", label: "Politique cryptographique", label_en: "Cryptographic policy", desc: "Algorithmes autorises, longueurs de cle, gestion du cycle de vie des cles.", desc_en: "Authorized algorithms, key lengths, key life cycle management.", critical: false, hds: true, linkedControls: ["A.8.24"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-26", cat: "Securite technique", cat_en: "Technical security", label: "Politique de journalisation et surveillance", label_en: "Logging and monitoring policy", desc: "Evenements journalises, durees de conservation, procedure d'analyse.", desc_en: "Logged events, retention periods, analysis procedure.", critical: true, hds: true, linkedControls: ["A.8.15", "A.8.16"], ecartAuto: "Politique journalisation absente - Ecart sur A.8.15", ecartAuto_en: "Logging policy missing - finding on A.8.15" },
    { ref: "D-27", cat: "Continuite", cat_en: "Continuity", label: "Plan de Continuite d'Activite (PCA/DRP)", label_en: "Business Continuity Plan (BCP/DRP)", desc: "Procedures de continuite et reprise incluant les objectifs RTO/RPO.", desc_en: "Continuity and recovery procedures including RTO/RPO objectives.", critical: true, hds: true, linkedControls: ["A.5.29", "A.5.30"], ecartAuto: "PCA absent - NC majeure sur A.5.30", ecartAuto_en: "BCP missing - major NC on A.5.30" },
    { ref: "D-28", cat: "Continuite", cat_en: "Continuity", label: "Rapport du dernier test du PCA/DRP", label_en: "Report of the latest BCP/DRP test", desc: "Compte-rendu du dernier exercice de continuite avec resultats et actions.", desc_en: "Minutes of the latest continuity exercise with results and actions.", critical: false, hds: true, linkedControls: ["A.5.30"], ecartAuto: "PCA non teste - Ecart sur A.5.30", ecartAuto_en: "BCP not tested - finding on A.5.30" },
    { ref: "D-29", cat: "Fournisseurs", cat_en: "Suppliers", label: "Politique de securite des fournisseurs", label_en: "Supplier security policy", desc: "Exigences SSI applicables aux tiers, processus d'evaluation et de suivi.", desc_en: "Information security requirements for third parties, assessment and monitoring process.", critical: false, hds: true, linkedControls: ["A.5.19", "A.5.22"], ecartAuto: "", ecartAuto_en: "" },
    { ref: "D-30", cat: "Fournisseurs", cat_en: "Suppliers", label: "Contrats fournisseurs avec clauses SSI", label_en: "Supplier contracts with information security clauses", desc: "Echantillon de contrats incluant les clauses de confidentialite et securite.", desc_en: "Sample of contracts including confidentiality and security clauses.", critical: true, hds: true, linkedControls: ["A.5.19", "A.5.20"], ecartAuto: "Absence de clauses SSI dans les contrats - NC sur A.5.20", ecartAuto_en: "No information security clauses in contracts - NC on A.5.20" },
    { ref: "D-31", cat: "HDS", cat_en: "HDS", label: "Certificat ou attestation HDS en cours de validite", label_en: "Valid HDS certificate or attestation", desc: "Document prouvant l'habilitation HDS de l'hebergeur ou de l'organisme.", desc_en: "Document proving the HDS certification of the hosting provider or the organization.", critical: true, hds: true, linkedControls: ["A.5.31"], ecartAuto: "Certification HDS absente ou expiree - NC critique", ecartAuto_en: "HDS certification missing or expired - critical NC" },
    { ref: "D-32", cat: "HDS", cat_en: "HDS", label: "Contrats d'hebergement HDS", label_en: "HDS hosting contracts", desc: "Contrat avec l'hebergeur certifie HDS avec responsabilites definies.", desc_en: "Contract with the HDS-certified hosting provider with defined responsibilities.", critical: true, hds: true, linkedControls: ["A.5.19", "A.5.20"], ecartAuto: "Contrat HDS absent - NC majeure", ecartAuto_en: "HDS contract missing - major NC" },
    { ref: "D-33", cat: "HDS", cat_en: "HDS", label: "Registre des traitements de donnees de sante (RGPD)", label_en: "Register of health data processing activities (GDPR)", desc: "Inventaire des traitements de donnees de sante avec bases legales.", desc_en: "Inventory of health data processing activities with legal bases.", critical: true, hds: true, linkedControls: ["A.5.34"], ecartAuto: "Registre traitements absent - NC sur A.5.34", ecartAuto_en: "Processing register missing - NC on A.5.34" },
    { ref: "D-34", cat: "HDS", cat_en: "HDS", label: "Analyse d'Impact (PIA/DPIA) pour les traitements a risque", label_en: "Impact Assessment (PIA/DPIA) for high-risk processing", desc: "Etudes d'impact sur la protection des donnees pour les traitements sensibles.", desc_en: "Data protection impact assessments for sensitive processing activities.", critical: false, hds: true, linkedControls: ["A.5.34"], ecartAuto: "", ecartAuto_en: "" }
];
// ── DOC REVIEW HELPERS ──
var DOC_REVIEW = window.ISO_AUDIT_DOC_REVIEW;
function _getDocEntry(ref) {
    if (!D.doc_review[ref])
        D.doc_review[ref] = { status: "", observations: "" };
    return D.doc_review[ref];
}
// ── RENDER ──
function renderDocReview() {
    var el = document.getElementById("docreview-content");
    if (!el)
        return;
    var cats = [];
    DOC_REVIEW.forEach(function (d) { if (cats.indexOf(d.cat) === -1)
        cats.push(d.cat); });
    // Summary counters
    var counts = { recu: 0, incomplet: 0, manquant: 0, na: 0, total: DOC_REVIEW.length, done: 0 };
    DOC_REVIEW.forEach(function (d) {
        var s = (D.doc_review[d.ref] && D.doc_review[d.ref].status) || "";
        if (s) {
            counts.done++;
            // Équivalent typé de l'ancien `counts[s] !== undefined`
            if (s === "recu" || s === "incomplet" || s === "manquant" || s === "na")
                counts[s]++;
        }
    });
    // KPI row
    var h = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">';
    function dkpi(val, label, tone) {
        return '<div class="ct-kpi"' + (tone ? ' data-tone="' + tone + '" data-emphasis="value"' : '')
            + '><div class="ct-kpi-tone"></div><div class="ct-kpi-body"><div class="ct-kpi-label">' + label
            + '</div><div class="ct-kpi-value">' + val + '</div></div></div>';
    }
    h += dkpi(counts.done + '/' + counts.total, t("audit.dash.progress"));
    h += dkpi(counts.recu, t("audit.doc.recu"), counts.recu > 0 ? "low" : undefined);
    h += dkpi(counts.incomplet, t("audit.doc.incomplet"), counts.incomplet > 0 ? "high" : undefined);
    h += dkpi(counts.manquant, t("audit.doc.manquant"), counts.manquant > 0 ? "critical" : undefined);
    h += dkpi(counts.na, t("audit.doc.na"));
    h += '</div>';
    // Table per category
    cats.forEach(function (cat) {
        var docs = DOC_REVIEW.filter(function (d) { return d.cat === cat; });
        var catDone = docs.filter(function (d) { return D.doc_review[d.ref] && D.doc_review[d.ref].status; }).length;
        h += '<div style="margin-bottom:20px">';
        h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid var(--ct-accent)">';
        h += '<h3 style="font-size:0.95em;color:var(--ct-ink);margin:0">' + esc(docs.length ? _rt(docs[0], "cat") : cat) + '</h3>';
        h += '<span style="font-size:0.75em;color:var(--ct-ink-2)">' + catDone + '/' + docs.length + '</span>';
        h += '</div>';
        h += '<table class="ct-table"><thead><tr>';
        h += '<th style="width:60px">' + t("audit.doc.col_ref") + '</th>';
        h += '<th>' + t("audit.doc.col_doc") + '</th>';
        h += '<th style="width:70px">' + t("audit.doc.col_status") + '</th>';
        h += '<th>' + t("audit.doc.observations") + '</th>';
        h += '</tr></thead><tbody>';
        docs.forEach(function (d) {
            var entry = _getDocEntry(d.ref);
            var st = entry.status || "";
            var obs = entry.observations || "";
            var stTone = st === "recu" ? "low" : st === "incomplet" ? "high" : st === "manquant" ? "critical" : "neutral";
            var stLabel = st ? t("audit.doc." + st) : "—";
            var showAlert = st === "manquant" && d.ecartAuto;
            h += '<tr>';
            // Ref + badges
            h += '<td><strong>' + esc(d.ref) + '</strong>';
            if (d.critical)
                h += ' <span style="color:var(--ct-critical);font-size:0.7em;font-weight:700">★</span>';
            if (d.hds)
                h += ' <span class="ctrl-hds">HDS</span>';
            h += '</td>';
            // Document name + description
            h += '<td><div style="font-weight:600;font-size:0.85em">' + esc(_rt(d, "label")) + '</div>';
            h += '<div style="font-size:0.78em;color:var(--ct-ink-2)">' + esc(_rt(d, "desc")) + '</div>';
            if (d.linkedControls && d.linkedControls.length)
                h += '<div style="font-size:0.72em;color:var(--ct-accent);margin-top:2px">§ ' + d.linkedControls.join(', ') + '</div>';
            if (showAlert)
                h += '<div style="font-size:0.75em;color:var(--ct-critical);margin-top:2px">⚠ ' + esc(_rt(d, "ecartAuto")) + '</div>';
            h += '</td>';
            // Status (clickable badge cycling through states)
            h += '<td style="text-align:center">';
            h += '<div class="doc-status-cycle" data-click="cycleDocStatus" data-args=\'' + _da(d.ref) + '\' style="cursor:pointer;user-select:none">';
            if (st) {
                h += '<span class="ct-badge" data-tone="' + stTone + '">' + esc(stLabel) + '</span>';
            }
            else {
                h += '<span style="display:inline-block;padding:3px 8px;border-radius:4px;font-size:0.75em;border:1px dashed var(--ct-line);color:var(--ct-ink-2);cursor:pointer">—</span>';
            }
            h += '</div></td>';
            // Observations
            h += '<td><textarea rows="1" style="width:100%;font-size:0.8em;min-height:28px;resize:vertical" data-change="setDocObs" data-args=\'' + _da(d.ref) + '\' data-pass-value placeholder="' + esc(t("audit.doc.observations")) + '">' + esc(obs) + '</textarea></td>';
            h += '</tr>';
        });
        h += '</tbody></table></div>';
    });
    el.innerHTML = h;
}
window.renderDocReview = renderDocReview;
// ── HANDLERS ──
var DOC_STATUS_CYCLE = ["", "recu", "incomplet", "manquant", "na"];
function cycleDocStatus(ref) {
    _saveState();
    var entry = _getDocEntry(ref);
    var idx = DOC_STATUS_CYCLE.indexOf(entry.status || "");
    entry.status = DOC_STATUS_CYCLE[(idx + 1) % DOC_STATUS_CYCLE.length];
    _autoSave();
    renderDocReview();
}
window.cycleDocStatus = cycleDocStatus;
function setDocObs(ref, val) {
    var entry = _getDocEntry(ref);
    entry.observations = val;
    _autoSave();
}
window.setDocObs = setDocObs;
