/**
 * ISO Audit — data model D + app globals (pure types file).
 * Derived from ISO_AUDIT_INIT_DATA (ISO_Audit_data.ts), the referential
 * files (controls/docreview) and the usages in the app.
 */

interface AuditControl {
    id: string;
    d: string;
    t: string;
    t_en?: string;
    desc: string;
    desc_en?: string;
    hds: boolean;
    /** Set temporarily by the Word export (ISO_Audit_export.ts). */
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

/** Image entry stored in IndexedDB (and embedded in D._images on JSON export). */
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
    /** Transient: images embedded during JSON serialization/loading. */
    _images?: AuditImageEntry[];
}

/* ── Statistics ───────────────────────────────────────────────── */

/** Status keys counted in the stats (cf. STATUS_MAP). */
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

/* ── Word export (OOXML) ──────────────────────────────────────── */

interface AuditWordPOpts {
    sz?: string;
    bold?: boolean;
    italic?: boolean;
    color?: string;
    align?: string;
    /** App variant (AI report): flat spacing. */
    after?: number;
    before?: number;
    /** Export variant: nested spacing. */
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

/* ── ai_common globals exposed via window (assigned by ai_common.js,
 *    hence callable bare in the browser's global scope).
 *    Same signatures as in gen-ai_common.d.ts; _aiOpenPanel accepts an
 *    optional title (ignored by the shared implementation — the app
 *    has always passed it). ─────────────────────────────────────── */

declare function _aiIsEnabled(): boolean;
declare function _aiGetApiKey(): string;
declare function _aiCallAPI(systemPrompt: string, userPrompt: string): Promise<string>;
declare function _aiEnsurePanel(): { title: HTMLElement; body: HTMLElement; footer: HTMLElement };
declare function _aiOpenPanel(title?: string): void;
declare function _aiShowLoading(title: string): void;
declare function _aiShowError(title: string, errMsg: string): void;

/* ── Window globals (referentials + data-click dispatch) ──────── */

interface Window {
    ISO_AUDIT_INIT_DATA?: AuditData;
    ISO_AUDIT_CONTROLS?: AuditControl[];
    ISO_AUDIT_DOMAINS?: AuditDomain[];
    ISO_AUDIT_QUESTIONS?: Record<string, string[]>;
    ISO_AUDIT_QUESTIONS_EN?: Record<string, string[]>;
    ISO_AUDIT_DOC_REVIEW?: AuditDocItem[];
    _lastAIReport?: string;
    /** Hooks overridden by ISO_Audit_images.ts (serialization with images). */
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

/* Functions exposed by ISO_Audit_images.ts (IIFE) — called bare by
 * ISO_Audit_app.ts / ISO_Audit_export.ts via the global window scope. */
declare function renderImages(ctrlId: string): void;
declare function _imgGetAll(ctrlId: string, cb: (imgs: AuditImageEntry[]) => void): void;
