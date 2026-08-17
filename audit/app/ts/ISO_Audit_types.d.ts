/**
 * ISO Audit — modèle de données D + globals app (fichier de types pur).
 * Déduit de ISO_AUDIT_INIT_DATA (ISO_Audit_data.ts), des fichiers de
 * référentiel (controls/docreview) et des usages dans l'app.
 */

interface AuditControl {
    id: string;
    d: string;
    t: string;
    t_en?: string;
    desc: string;
    desc_en?: string;
    hds: boolean;
    /** Posé temporairement par l'export Word (ISO_Audit_export.ts). */
    _ctrlImages?: AuditImageEntry[];
}

interface AuditDomain {
    id: string;
    label: string;
    label_en?: string;
    group: string;
    group_en?: string;
}

interface AuditFinding {
    status: string;
    preuve: string;
    constats: string;
    ecart_critere: string;
    ecart_constat: string;
    ecart_cause: string;
    ecart_action: string;
    images?: string[];
}

interface AuditDocItem {
    ref: string;
    cat: string;
    cat_en?: string;
    label: string;
    label_en?: string;
    desc: string;
    desc_en?: string;
    critical: boolean;
    hds: boolean;
    linkedControls: string[];
    ecartAuto: string;
    ecartAuto_en?: string;
}

interface AuditDocEntry {
    status: string;
    observations: string;
}

interface AuditPlanningParams {
    start_date?: string;
    days?: number;
    start_time?: string;
    slot_duration?: number;
    lunch_start?: string;
    lunch_duration?: number;
}

interface AuditSlot {
    date: string;
    start: string;
    end: string;
    type: string;
    domain: string;
}

interface AuditJournalEntry {
    ts: string;
    type: string;
    author: string;
    data?: { ctrl?: string; status?: string; field?: string };
}

interface AuditMeta {
    name: string;
    ref: string;
    date: string;
    auditor: string;
    scope: string;
    hds: string;
}

/** Entrée image stockée dans IndexedDB (et embarquée dans D._images à l'export JSON). */
interface AuditImageEntry {
    id: string;
    ctrlId: string;
    data: string;
    name: string;
    ts: string;
}

interface AuditData {
    meta: AuditMeta;
    findings: Record<string, AuditFinding>;
    doc_review: Record<string, AuditDocEntry>;
    planning: { params: AuditPlanningParams; slots: AuditSlot[] };
    journal: AuditJournalEntry[];
    timers: Record<string, unknown>;
    /** Transitoire : images embarquées lors de la sérialisation/du chargement JSON. */
    _images?: AuditImageEntry[];
}

/* ── Statistiques ─────────────────────────────────────────────── */

/** Clés de statut comptées dans les stats (cf. STATUS_MAP). */
type AuditStatusKey = "c" | "ncmaj" | "ncmin" | "ps" | "pp" | "na";

interface AuditStatusCounts {
    total: number;
    audited: number;
    c: number;
    ncmaj: number;
    ncmin: number;
    ps: number;
    pp: number;
    na: number;
}

interface AuditDomainStats extends AuditStatusCounts {
    score: number;
}

interface AuditStats extends AuditStatusCounts {
    score: number;
    grade: string;
    gradeColor: string;
    gradeTone?: string;
    domains: Record<string, AuditDomainStats>;
}

interface AuditHDSCount {
    total: number;
    c: number;
    nc: number;
    other: number;
}

/* ── Export Word (OOXML) ──────────────────────────────────────── */

interface AuditWordPOpts {
    sz?: string;
    bold?: boolean;
    italic?: boolean;
    color?: string;
    align?: string;
    /** Variante app (rapport IA) : espacement à plat. */
    after?: number;
    before?: number;
    /** Variante export : espacement imbriqué. */
    spacing?: { before?: number; after?: number };
    indent?: number;
}

interface AuditWordCell {
    text?: string;
    bold?: boolean;
    bg?: string;
    color?: string;
    sz?: string;
    align?: string;
}

interface AuditWordRow {
    cells: AuditWordCell[];
}

interface AuditWordImgRel {
    rId: string;
    filename: string;
    base64: string;
}

/* ── Globals ai_common exposés via window (assignés par ai_common.js,
 *    donc accessibles en appel nu dans le scope global du navigateur).
 *    Mêmes signatures que dans gen-ai_common.d.ts ; _aiOpenPanel accepte
 *    un titre optionnel (ignoré par l'implémentation partagée — l'app
 *    l'a toujours passé). ─────────────────────────────────────── */

declare function _aiIsEnabled(): boolean;
declare function _aiGetApiKey(): string;
declare function _aiCallAPI(systemPrompt: string, userPrompt: string): Promise<string>;
declare function _aiEnsurePanel(): { title: HTMLElement; body: HTMLElement; footer: HTMLElement };
declare function _aiOpenPanel(title?: string): void;
declare function _aiShowLoading(title: string): void;
declare function _aiShowError(title: string, errMsg: string): void;

/* ── Globals window (référentiels + dispatch data-click) ──────── */

interface Window {
    ISO_AUDIT_INIT_DATA?: AuditData;
    ISO_AUDIT_CONTROLS?: AuditControl[];
    ISO_AUDIT_DOMAINS?: AuditDomain[];
    ISO_AUDIT_QUESTIONS?: Record<string, string[]>;
    ISO_AUDIT_QUESTIONS_EN?: Record<string, string[]>;
    ISO_AUDIT_DOC_REVIEW?: AuditDocItem[];
    _lastAIReport?: string;
    /** Hooks surchargés par ISO_Audit_images.ts (sérialisation avec images). */
    _serializeForSave?: typeof _serializeForSave;
    _initDataAndRender?: (afterFn?: () => void) => void;

    selectPanel?: typeof selectPanel;
    onMetaChange?: typeof onMetaChange;
    setStatus?: typeof setStatus;
    setField?: typeof setField;
    onFilterStatus?: typeof onFilterStatus;
    onFilterHDS?: typeof onFilterHDS;
    onFilterText?: typeof onFilterText;
    toggleQuestions?: typeof toggleQuestions;
    copyQuestion?: typeof copyQuestion;
    openSearch?: typeof openSearch;
    closeSearch?: typeof closeSearch;
    onSearchScope?: typeof onSearchScope;
    onSearchInput?: typeof onSearchInput;
    goToSearchResult?: typeof goToSearchResult;
    generateReport?: typeof generateReport;
    renderDocReview?: typeof renderDocReview;
    cycleDocStatus?: typeof cycleDocStatus;
    setDocObs?: typeof setDocObs;
    renderPlanning?: typeof renderPlanning;
    exportPlanningCSV?: typeof exportPlanningCSV;
    exportPlanningWord?: typeof exportPlanningWord;
    onPlanningParam?: typeof onPlanningParam;
    onSlotDomain?: typeof onSlotDomain;
    generatePlanning?: typeof generatePlanning;
    deleteSlot?: typeof deleteSlot;
    exportCSV?: typeof exportCSV;
    exportWord?: typeof exportWord;
    exportDocReviewCSV?: typeof exportDocReviewCSV;
    _imgSave?: (ctrlId: string, dataUrl: string, name: string, cb?: (id: string | null) => void) => void;
    _imgGet?: (imgId: string, cb: (entry: AuditImageEntry | null) => void) => void;
    _imgGetAll?: (ctrlId: string, cb: (imgs: AuditImageEntry[]) => void) => void;
    _imgDelete?: (imgId: string, ctrlId: string, cb?: () => void) => void;
    addImage?: (ctrlId: string) => void;
    deleteImage?: (ctrlId: string, imgId: string) => void;
    viewImage?: (imgId: string) => void;
    renderImages?: (ctrlId: string) => void;
}

/* Fonctions exposées par ISO_Audit_images.ts (IIFE) — utilisées en appel nu
 * par ISO_Audit_app.ts / ISO_Audit_export.ts via le scope global window. */
declare function renderImages(ctrlId: string): void;
declare function _imgGetAll(ctrlId: string, cb: (imgs: AuditImageEntry[]) => void): void;
