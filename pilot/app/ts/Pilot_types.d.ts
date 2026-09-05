/**
 * Pilot_types.d.ts — data model of the Pilot front end (demo-docker).
 *
 * The stats v2 envelope (PilotStatsEnvelope) follows the authoritative
 * contract shared/docs/pilot-dashboard-contract.md: every backend module
 * exposes GET /api/internal/stats with { entity_count, entity_label,
 * measures{}, posture{score, score_label, trend_30d}, breakdown{type, data},
 * top_items[], alerts[] }. Fields are optional on the front end because
 * Pilot applies the fallbacks documented in the contract.
 *
 * Pure type file — no emit.
 */

/* ── Stats v2 (dashboard contract) ─────────────────────────────── */

interface PilotMeasuresSummary {
    total?: number;
    completed?: number;
    in_progress?: number;
    planned?: number;
    overdue?: number;
    progress_pct?: number;
}

interface PilotPosture {
    score?: number | null;
    score_label?: string;
    trend_30d?: number[];
}

interface PilotTopItem {
    id?: string;
    label?: string;
    severity?: string;
    url?: string;
}

interface PilotAlert {
    level?: string;   // info | warning | critical
    text?: string;
    url?: string;
}

/** Stats v2 envelope returned by each module (dashboard contract). */
interface PilotStatsEnvelope {
    entity_count?: number;
    entity_label?: string;
    measures?: PilotMeasuresSummary;
    posture?: PilotPosture | null;
    /** breakdown.type ∈ donut | bar | gauge | heatmap_5x5 | timeline — rendered via _svgBreakdown. */
    breakdown?: CtBreakdown | null;
    top_items?: PilotTopItem[];
    alerts?: PilotAlert[];
}

interface PilotModuleEntry {
    id: string;
    name: string;
    status?: string;        // active | external | unreachable | unknown
    url?: string;
    external_url?: string;
    stats?: PilotStatsEnvelope | null;
}

/* ── Consolidated dashboard (GET /api/dashboard) ───────────────── */

interface PilotDashKpis {
    posture_global?: number | null;
    posture_label?: string;
    measures_total?: number;
    measures_overdue?: number;
    measures_done_last_30d?: number;
    critical_count?: number;
    critical_breakdown?: Record<string, number>;
    proofs_expired_10d?: number;
}

interface PilotUpcoming {
    label?: string;
    date?: string;
    days_left?: number | null;
}

interface PilotActivityEvent {
    module?: string;
    label?: string;
    date?: string;
}

interface PilotDashboard {
    kpis?: PilotDashKpis;
    modules?: PilotModuleEntry[];
    upcoming?: PilotUpcoming[];
    activity?: PilotActivityEvent[];
}

/* ── Measures / projects ───────────────────────────────────────── */

interface PilotMeasure {
    id: string;
    module: string;
    source_id: string;
    entity_id?: string;
    title?: string;
    description?: string;
    status: string;          // backlog | planned | in_progress | completed
    assignee?: string;
    due_date?: string | null;
    entity_name?: string;
    vendor_name?: string;
    /** Front-only stash: current project at edit time (diff). */
    __project_id?: string;
}

interface PilotMeasureGroupMember {
    id: string;
    module: string;
    source_id: string;
    entity_id?: string;
    entity_name?: string;
    title?: string;
    status: string;
    assignee?: string;
    due_date?: string;
}

interface PilotMeasureGroup {
    ref?: string;
    id: string;
    title: string;
    status: string;
    due_date?: string;
    responsible?: string;
    members: PilotMeasureGroupMember[];
}

interface PilotProject {
    id?: string;             // absent for a project still being created
    name: string;
    description?: string;
    status?: string;         // planned | in_progress | completed | on_hold
    priority?: string;       // low | medium | high | critical
    responsible?: string;
    start_date?: string | null;
    due_date?: string | null;
    progress?: number;
    measures_total?: number;
    measures_completed?: number;
    measures?: PilotMeasure[];
}

/* ── Annuaire / utilisateurs ───────────────────────────────────── */

interface PilotPerson {
    id?: string;
    nom?: string;
    prenom?: string;
    email?: string;
    fonction?: string;
    departement?: string;
    statut?: string;         // actif | inactif | externe
    telephone?: string;
    site?: string;
    manager_email?: string;
    sync_source?: string;    // "" = Pilot-managed (editable) | "access" = fed from Access (read-only)
}

interface PilotUser {
    id: string;
    name?: string;
    email: string;
    role?: string;           // admin | user | viewer | pending
    picture?: string;
    permissions?: Record<string, string>;
    ai_enabled?: string;     // "true" | "false" (stored as a string on the backend side)
    last_login?: string;
}

interface PilotCurrentUser {
    id?: string;
    name?: string;
    email?: string;
    role?: string;
}

/* ── KPIs (Pilot_kpis.js) ──────────────────────────────────────── */

interface PilotKpiMapping {
    framework: string;
    ref: string;
    label_fr?: string | null;
    label_en?: string | null;
}

interface PilotKpiSnapshot {
    value: number;
    captured_at?: string;
    source?: string;
    note?: string;
}

interface PilotKpi {
    code: string;
    name_fr: string;
    name_en?: string;
    description_fr?: string;
    description_en?: string;
    category_primary: string;   // govern | identify | protect | detect | respond | recover
    unit: string;               // % | count | days | score | currency | ratio
    direction?: string;         // higher_better | lower_better
    source_type?: string;       // auto | external
    source_module?: string;
    connector_config?: { detail?: string; campaign?: string; slug?: string } | null;
    active?: boolean;
    target?: number | null;
    threshold_amber?: number | null;
    threshold_red?: number | null;
    latest?: PilotKpiSnapshot | null;
    last_synced_at?: string | null;
    mappings?: PilotKpiMapping[];
}

type PilotKpiColor = "green" | "amber" | "red" | "grey";

interface PilotKpiHealth {
    color: PilotKpiColor;
    label: string;
}

/* ── Backups / settings ────────────────────────────────────────── */

interface PilotBackupModuleConfig {
    module?: string;
    enabled: boolean;
    frequency_hours: number;
    retention_daily: number;
    retention_weekly: number;
    retention_monthly: number;
}

type PilotBackupConfig = Record<string, PilotBackupModuleConfig>;

interface PilotBackupEntry {
    key: string;
    module: string;
    timestamp?: string;
    items_count?: number;
    size_kb?: number;
}

interface PilotSettings {
    demo_mode?: string;
    ai_provider?: string;
    ai_model?: string;
    ai_key_anthropic?: string;     // "configured" or absent (never the key itself)
    ai_key_openai?: string;
    ai_key_gemini?: string;
    ai_custom_label?: string;
    ai_custom_model?: string;
    ai_custom_endpoint?: string;
    ai_custom_key?: string;
    http_proxy?: string;
    https_proxy?: string;
    no_proxy?: string;
    smtp_host?: string;
    smtp_port?: string;
    smtp_user?: string;
    smtp_password?: string;
    smtp_from?: string;
    smtp_tls?: string;
    [k: string]: string | undefined;
}

/* ── Connectors (Pilot_connectors.js, /api/admin/connectors aggregator) ── */

interface PilotConnInstance {
    id?: string;
    _owner?: string;
    label?: string;
    project_id?: string;
    enabled?: boolean;
    configured?: boolean;
    [k: string]: any;
}

interface PilotConnEntry extends CtConnector {
    consumers?: string[];
    cardinality?: string;        // one | many
    instances?: PilotConnInstance[];
}

interface PilotConnAggregate {
    connectors?: PilotConnEntry[];
}

/* ── Fetch wrapper ─────────────────────────────────────────────── */

interface PilotFetchInit {
    method?: string;
    headers?: Record<string, string>;
    /** Object → JSON-serialized by _fetch; string/FormData passed through. */
    body?: any;
    credentials?: RequestCredentials;
}

/* ── Pilot AI panel (pilot_ai_panel.js — local variant, NOT ai_common) ────── */

interface PilotAiPanelParts {
    panel: HTMLElement;
    title: HTMLElement;
    body: HTMLElement;
    footer: HTMLElement;
}

/* ── Cross-file globals (assigned on window, called bare) ──────── */

declare var ct_modal: CtModalApi;
declare var ct_table: CtTableApi;
declare var ct_bulkbar: CtBulkbarApi;
declare var ct_measure_modal: CtMeasureModalApi;
declare var ct_userpicker: {
    mount?: (opts: { slotId: string; pickerId?: string; value?: string; placeholder?: string; directoryUrl?: string; sourceUrl?: string | null; onCreate?: ((query: string) => Promise<unknown>) | null }) => Promise<{ getValue(): string }>;
    getValue?: (id: string) => string;
} | undefined;

declare var _fetch: (url: string, opts?: PilotFetchInit) => Promise<any>;
declare var _renderKpis: (c: HTMLElement) => void;
declare var _renderConnectors: (c: HTMLElement) => void;

declare var _aiEnsurePanel: () => PilotAiPanelParts;
declare var _aiOpenPanel: (title?: string) => void;
declare var _aiClosePanel: () => void;
declare var _aiShowLoading: (title?: string, msg?: string) => void;
declare var _aiShowError: (title?: string, errMsg?: string) => void;

interface Window {
    _openGroupRow?: (gid: string) => void;
    _openGroupMemberModule?: (gid: string, mid: string) => void;
    _linkSelectedMeasures?: (scope: string) => void;
    _detachGroupMember?: (gid: string, mid: string) => void;
    _resyncGroup?: (gid: string) => void;
    _filterEvidences?: () => void;
    _aiSuggestGroups?: () => void;
    _aiCreateSuggestedGroups?: () => void;
    /** cisotoolbox_backend variant flag: Pilot does not unwrap its own backups. */
    _CT_IMPORT_NO_UNWRAP?: boolean;
    _currentUser?: PilotCurrentUser;
    _locale?: string;
    _fetch?: (url: string, opts?: PilotFetchInit) => Promise<any>;
    _logout?: () => void;
    _openNotifPrefs?: () => void;
    ct_notifprefs?: { open: (opts: Record<string, unknown>) => void };
    selectPanel?: (id: string) => void;

    /* pilot_ai_panel.js */
    _aiEnsurePanel?: () => PilotAiPanelParts;
    _aiOpenPanel?: (title?: string) => void;
    _aiClosePanel?: () => void;
    _aiShowLoading?: (title?: string, msg?: string) => void;
    _aiShowError?: (title?: string, errMsg?: string) => void;

    /* Pilot_kpis.js */
    _renderKpis?: (c: HTMLElement) => void;
    _kpiSetFilter?: (field: string, value: string) => void;
    _kpiOpenDetail?: (code: string) => void;
    _kpiToggleActive?: (code: string, newValue: boolean) => void;
    _kpiDetailSubmitManual?: (code: string) => void;
    _kpiDetailSaveTune?: (code: string) => Promise<unknown>;
    _kpiDetailDelete?: (code: string) => void;
    _kpiRemoveMapping?: (code: string, idx: number) => void;
    _kpiAddMapping?: (code: string) => void;
    _kpiSuggestFrameworks?: (code: string, provider: string) => void;
    _kpiAddSelectedMappings?: (code: string) => void;
    _kpiOpenHistory?: (code: string) => void;
    _kpiOpenAutoPicker?: () => void;
    _kpiPickerActivate?: (code: string) => void;
    _kpiOpenCreate?: () => void;
    _kpiAutoCompute?: () => void;
    _kpiResetCache?: () => void;

    /* Pilot_connectors.js */
    _connSetFilter?: (mod: string) => void;
    _renderConnectors?: (c: HTMLElement) => void;
    _connOpenConfig?: (id: string) => void;
    _connRunTest?: (id: string) => void;
    _connRunNow?: (id: string) => void;
    _connDeleteConfig?: (id: string) => void;
    _connOpenInstance?: (typeId: string, ownerModule: string, instanceId: string) => void;
    _connNewInstance?: (typeId: string) => void;
    _connTestInstance?: (typeId: string, ownerModule: string, instanceId: string) => void;

    /* Pilot_app.js */
    _healthCheck?: () => void;
    _setMeasureView?: (view: string) => void;
    _openMeasureRow?: (row: PilotMeasure) => void;
    _bulkPilotMeasuresDelete?: (scope: string) => void;
    _filterMeasures?: () => void;
    _syncMeasuresNow?: () => void;
    _syncEvidencesNow?: () => void;
    _editEvidence?: (module: string, sourceId: string) => void;
    _openMeasure?: (modId: string, sourceId: string) => void;
    _showNewMeasureForm?: () => void;
    _openModule?: (url: string) => void;
    _newProject?: () => void;
    _editProject?: (id: string) => void;
    _backToProjects?: () => void;
    _saveProject?: () => void;
    _deleteProject?: (id: string) => void;
    _removeMeasure?: (projectId: string, measureId: string) => void;
    _searchMeasuresToAdd?: (val: string) => void;
    _addSelectedMeasures?: () => void;
    _aiSuggestMeasures?: (projectId: string) => void;
    _aiToggleAllMeasures?: () => void;
    _aiAddSuggestedMeasures?: () => void;
    _aiSuggestProjects?: () => void;
    _aiApplySuggestedPlan?: () => void;
    _dirAddPerson?: () => void;
    _dirEditPerson?: (idx: any) => void;
    _dirImportCsv?: () => void;
    _dirImportFromAccess?: () => void;
    _dirExportForAccess?: () => void;
    _changeRole?: (uid: string, role: string) => void;
    _changeModPerm?: (uid: string, mod: string, role: string) => void;
    _deleteUser?: (uid: string, email: string) => void;
    _resyncModules?: () => void;
    _toggleAI?: (uid: string, el: HTMLInputElement) => void;
    _saveBackupConfig?: () => void;
    _runBackup?: (mod: string) => void;
    _bkToggleOne?: (key: string, el: HTMLInputElement) => void;
    _bkToggleAll?: (el: HTMLInputElement) => void;
    _bkClearSelection?: () => void;
    _deleteSelectedBackups?: () => void;
    _runAllBackups?: () => void;
    _downloadBackup?: (key: string) => void;
    _restoreBackup?: (key: string, mod: string) => void;
    _deleteBackup?: (key: string) => void;
    _saveSettings?: () => void;
}
