/**
 * AppSec — Application Security Scanner (demo-docker front).
 * Types du modèle de données (objets servis par l'API FastAPI) + globals
 * posés par appsec_api.ts / AppSec_app.ts. Fichier de types pur (aucun emit).
 *
 * Les modèles sont des alias de type (pas des interfaces) pour bénéficier
 * de la signature d'index implicite (passage à ct_table.render dont les
 * rows sont des Record<string, any>).
 */

/* ── Modèle de données (API) ───────────────────────────────────── */

type AppSecApp = {
    id: number | string;
    name: string;
    description?: string;
    enabled?: boolean;
    criticality?: string;
    repo_url?: string;
    repo_branch?: string;
    has_token?: boolean;
    has_image_token?: boolean;
    scan_paths?: string[];
    docker_images?: string[];
    enabled_scanners?: string[];
    scan_frequency_hours?: number;
    last_scan_at?: string | null;
    findings_critical?: number;
    findings_high?: number;
    findings_medium?: number;
    findings_low?: number;
    notification_emails?: string[];
    notification_lang?: string;
};

/** Blob evidence libre (compatible CtFvEvidence de ct_finding_view). */
type AppSecEvidence = {
    fixed_version?: string;
    installed_version?: string;
    package?: string;
    rule_id?: string;
    rule?: string;
    png_b64?: string;
    [key: string]: unknown;
};

type AppSecFinding = {
    id: string;
    application_id?: number | string;
    application_name?: string;
    scanner?: string;
    type?: string;
    severity?: string;
    status?: string;
    title?: string;
    description?: string;
    target?: string;
    cve_id?: string;
    evidence?: AppSecEvidence | null;
    measure_id?: string | null;
    created_at?: string;
    last_seen_at?: string;
    triaged_at?: string;
    triaged_by?: string;
    triage_notes?: string;
};

type AppSecScan = {
    id?: number | string;
    application_id: number | string;
    application_name?: string;
    scanner?: string;
    status?: string;
    findings_count?: number;
    error?: string | null;
    triggered_by?: string;
    created_at?: string;
};

type AppSecStats = {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    cve_total?: number;
    cve_with_patch?: number;
    by_app?: Record<string, number>;
    by_app_severity?: Record<string, Record<string, number>>;
};

type AppSecMeasure = {
    id: string;
    title?: string;
    description?: string;
    statut?: string;
    responsable?: string;
    echeance?: string;
    finding_id?: string | null;
    finding_ids?: string[];
};

type AppSecSbomEntry = {
    package_name?: string;
    version?: string;
    ecosystem?: string;
    license?: string;
    direct?: boolean;
    parent_packages?: string[];
    application_name?: string;
    application_names?: string[];
    cve_ids?: string[];
    cve_details?: { id: string; status?: string }[];
};

type AppSecIgnoreCriterion = { type: string; value: string };

type AppSecIgnoreRule = {
    id: string;
    criteria?: AppSecIgnoreCriterion[];
    application_ids?: string[];
    application_names?: string[];
    reason?: string;
    created_by?: string;
    enabled?: boolean;
};

type AppSecUser = { name?: string; email?: string; role?: string };

/* ── Filtres / payloads ────────────────────────────────────────── */

type AppSecFindingsFilter = {
    app_id: string;
    severity: string;
    scanner: string;
    status: string;
    q: string;
    patch: string;
};

type AppSecSbomFilter = {
    app_id: string;
    ecosystem: string;
    q: string;
    vulnerable_only: boolean;
};

/** Paramètres de query-string génériques (sérialisés par les list*). */
type AppSecQueryParams = Record<string, string | number | boolean | null | undefined>;

type AppSecAppPayload = {
    name: string;
    description: string;
    repo_url: string;
    repo_branch: string;
    scan_paths: string[];
    docker_images: string[];
    scan_frequency_hours: number;
    criticality: string;
    enabled_scanners: string[];
    repo_token?: string;
    image_token?: string;
    notification_emails?: string[];
    notification_lang?: string;
};

type AppSecBulkTriagePayload = {
    ids: string[];
    status: string;
    measure_title?: string;
    measure_description?: string;
    responsable?: string;
    echeance?: string;
    triage_notes?: string;
};

/* Réponse IA serveur-autoritative (POST /api/ai/appsec/analyze-finding).
   Champs typés librement : JSON produit par le LLM côté serveur. */
type AppSecAiAnalysis = {
    is_probable_false_positive?: boolean;
    confidence?: string;
    severity_recommendation?: string;
    summary?: string;
    remediation?: string;
    references?: string[];
    deep_used?: boolean;
    deep_note?: string;
};

type AppSecAnalyzeOpts = {
    lang?: string;
    context?: string;
    deep?: boolean;
};

/* ── Couche API (appsec_api.ts) ────────────────────────────────── */

type AppSecFetchOpts = {
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
    credentials?: RequestCredentials;
};

interface AppSecApiType {
    _fetch(path: string, opts?: AppSecFetchOpts): Promise<any>;
    listApps(): Promise<AppSecApp[]>;
    getApp(id: string | number | null): Promise<AppSecApp>;
    createApp(data: AppSecAppPayload): Promise<any>;
    updateApp(id: string | number, data: AppSecAppPayload): Promise<any>;
    deleteApp(id: string | number): Promise<any>;
    triggerScan(id: string | number): Promise<any>;
    getFinding(id: string | null): Promise<AppSecFinding>;
    listFindings(params?: AppSecQueryParams): Promise<{ items?: AppSecFinding[]; total?: number }>;
    findingsStats(appId?: string | number): Promise<AppSecStats>;
    triageFinding(id: string, data: Record<string, unknown>): Promise<any>;
    bulkTriageFindings(data: AppSecBulkTriagePayload): Promise<{ updated?: number; measures_created?: number }>;
    analyzeFinding(id: string, opts?: AppSecAnalyzeOpts): Promise<AppSecAiAnalysis>;
    listScans(appId?: string | number): Promise<AppSecScan[]>;
    resetStuckScans(appId: string | number): Promise<{ reset_count?: number }>;
    listMeasures(): Promise<AppSecMeasure[]>;
    updateMeasure(id: string, data: Record<string, unknown>): Promise<any>;
    deleteMeasure(id: string): Promise<any>;
    listSBOM(params?: AppSecQueryParams): Promise<{ items?: AppSecSbomEntry[]; total?: number; ecosystems?: string[] }>;
}

/* ── Globals runtime posés par les libs shared via window.* ─────── */
/* (accédés en identifiant nu dans le code app, comme dans le source) */

declare var ct_table: CtTableApi;
declare var ct_bulkbar: CtBulkbarApi;
declare var ct_modal: CtModalApi;
declare var ct_measure_modal: CtMeasureModalApi;
declare var ct_finding_view: CtFindingViewApi;
/** Posés par ai_common.js sur window (appels nus dans _aiTriageFinding). */
declare function _aiCallAPI(systemPrompt: string, userPrompt: string): Promise<string>;
declare function _aiParseJSON(raw: string): any;

/** Posés via window.* par AppSec_app.ts mais appelés en identifiant nu. */
declare function selectPanel(id: string): void;
declare function _backToFindings(): void;

/* ── Window — propriétés posées par appsec_api.ts / AppSec_app.ts ── */

interface Window {
    ct_notifprefs?: { open: (opts: Record<string, unknown>) => void };
    _openNotifPrefs?: () => void;
    /* Applications page: tile/table toggle + text filter */
    _appsSetView?: (view: string) => void;
    _appsSearch?: (value: string) => void;
    /* appsec_api.ts */
    _currentUser?: AppSecUser;
    _moduleRole?: string;
    _logout: () => void;

    /* AppSec_app.ts — routing + dashboard */
    selectPanel: typeof selectPanel;
    _backToApps: () => void;
    _dashNav: (panel: string) => void;
    _dashNavSev: (sev: string) => void;
    _dashNavPatch: () => void;

    /* app detail filters */
    _adSetSev: (v: string) => void;
    _adSetScanner: (v: string) => void;
    _adSetStatus: (v: string) => void;
    _adSetSearch: (v: string) => void;

    /* app modal */
    showAddApp: () => void;
    _editAppDialog: (id: string | number) => void;
    _closeAppModal: () => void;
    _toggleImageSection: () => void;
    _saveApp: (appId: string | number) => Promise<void>;
    _deleteAppFromDetail: (id: string | number) => Promise<void>;
    _deleteApp: (id: string | number) => Promise<void>;
    _triggerScan: (id: string | number) => Promise<void>;
    _scanAllApps: () => Promise<void>;

    /* findings */
    _openFindingRow: (row: any) => void;
    _bulkAppsecFindingsToFix: (scope: string) => void;
    _bulkAppsecFindingsFixed: (scope: string) => void;
    _bulkAppsecFindingsFP: (scope: string) => void;
    _setFSev: (v: string) => void;
    _setFScanner: (v: string) => void;
    _setFStatus: (v: string) => void;
    _setFApp: (v: string) => void;
    _setFSearch: (v: string) => void;
    _setFPatch: (v: string) => void;
    _openFinding: (id: string) => void;
    _backToFindings: typeof _backToFindings;
    _appsecTriageDetail: (status: string) => void;
    _deleteAppsecFinding: () => void;
    _aiTriageFinding: () => void;
    _aiTriageRun: () => Promise<void>;

    /* SBOM */
    _setSApp: (v: string) => void;
    _setSEco: (v: string) => void;
    _setSSearch: (v: string) => void;
    _setSVuln: (el: HTMLInputElement) => void;
    _sbomFilterByPkg: (pkg: string) => void;

    /* scans */
    _resetStuckScans: (appId: string | number, appName: string) => Promise<void>;

    /* ignore rules */
    _irToggleAllApps: () => void;
    _addIgnoreRule: () => void;
    _irAddCrit: () => void;
    _irRemoveCrit: (idx: number) => void;
    _irFilterApps: (q: string) => void;
    _editIgnoreRule: (ruleId: string) => void;
    _toggleIgnoreRule: (ruleId: string, enable: boolean) => void;
    _deleteIgnoreRule: (ruleId: string) => void;

    /* audit */
    _saveAuditRetention: () => Promise<void>;

    /* measures */
    _bulkAppsecMeasuresDone: (scope: string) => void;
    _editAppsecMeasureRow: (row: any) => void;
    _bulkAppsecMeasuresDelete: (scope: string) => void;

    /* init / toolbar */
    importApps: () => void;
    exportReport: () => void;
}
