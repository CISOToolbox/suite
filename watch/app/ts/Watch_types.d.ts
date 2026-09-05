/**
 * Watch (demo-docker) — server data model + app globals.
 * Watch has no local D model (app 100% driven by the REST API):
 * the interfaces describe the payloads returned by watch_api.ts.
 * Pure types file (no emit).
 */

interface WatchRecipient {
    email: string;
    name?: string;
}

interface WatchScope {
    id: string;
    name: string;
    description?: string;
    is_owner?: boolean;
    owner_email?: string;
    updated_at?: string;
    recipients?: WatchRecipient[];
    /* vulnerability digest */
    digest_enabled?: boolean;
    digest_hour?: number;
    digest_minute?: number;
    digest_timezone?: string;
    digest_severity_min?: string;
    digest_include_kev?: boolean;
    digest_cvss_min?: number | null;
    digest_epss_min?: number | null;
    /* digest menaces */
    threat_digest_enabled?: boolean;
    threat_digest_frequency?: string;
    threat_digest_weekday?: number;
    threat_digest_hour?: number;
    threat_digest_minute?: number;
    threat_digest_timezone?: string;
    threat_prompt?: string;
    threat_search_window_days?: number;
}

interface WatchTarget {
    id: string;
    kind: string;
    value: string;
    label?: string;
    version_constraint?: string;
    enabled?: boolean;
}

interface WatchAlertMatch {
    scope_name: string;
    match_kind?: string;
    match_value?: string;
    target_label?: string;
}

interface WatchAlert {
    id: string;
    external_id: string;
    source: string;
    title?: string;
    summary?: string;
    severity?: string;
    cvss_score?: number | null;
    epss_score?: number | null;
    kev_listed?: boolean;
    published_at?: string;
    ingested_at?: string;
    status?: string;
    note?: string;
    matches?: WatchAlertMatch[];
    references_json?: string[];
}

/** AI analysis of an alert (backend cache). */
interface WatchAnalysis {
    sections?: Record<string, string>;
    provider?: string;
    model?: string;
    generated_at?: string;
}

/** Client-side filters of the alerts panel. */
interface WatchAlertFilters {
    severity: string;
    status: string;
    source: string;
    scope_id: string;
    kev_only: boolean;
    q: string;
}

/** Utilisateur de l'annuaire Pilot (picker destinataires). */
interface WatchDirectoryUser {
    email?: string;
    prenom?: string;
    nom?: string;
    name?: string;
}

/* ── Couche API (watch_api.ts) ─────────────────────────────────── */

type WatchFetchOpts = {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    credentials?: RequestCredentials;
};

interface WatchApiType {
    _fetch(path: string, opts?: WatchFetchOpts): Promise<any>;
    listScopes(): Promise<any>;
    createScope(data: Record<string, unknown>): Promise<any>;
    getScope(id: string): Promise<any>;
    updateScope(id: string, data: Record<string, unknown>): Promise<any>;
    deleteScope(id: string): Promise<any>;
    addRecipient(id: string, data: { email: string; name?: string }): Promise<any>;
    removeRecipient(id: string, email: string): Promise<any>;
    listTargets(scopeId: string): Promise<any>;
    createTarget(scopeId: string, data: Record<string, unknown>): Promise<any>;
    updateTarget(scopeId: string, tid: string, data: Record<string, unknown>): Promise<any>;
    deleteTarget(scopeId: string, tid: string): Promise<any>;
    listAlerts(params?: Record<string, string | number | boolean | null | undefined>): Promise<any>;
    getAlert(id: string): Promise<any>;
    setAlertStatus(id: string, data: { status: string; note?: string }): Promise<any>;
    bulkSetAlertStatus(data: { ids: string[]; status: string }): Promise<any>;
    getAlertAnalysis(id: string): Promise<any>;
    analyzeAlert(id: string): Promise<any>;
    getAlertSbomImpact(id: string): Promise<any>;
    listFeeds(): Promise<any>;
    runFeedNow(source: string): Promise<any>;
    previewDigest(scopeId?: string): Promise<string>;
    listDigestRuns(): Promise<any>;
    getDigestBody(runId: string): Promise<string>;
    sendDigestNow(scopeId: string, kind: string): Promise<any>;
    getDashboard(): Promise<any>;
    getDirectory(): Promise<any>;
}

/* ── Shared globals declared Window-only in the generated .d.ts ────
 * ct_modal / ct_bulkbar expose their APIs only on Window
 * (optional properties). Watch_app.ts calls them as bare globals
 * (guarded by window.X / typeof checks like the source) —
 * local ambient declarations, no impact on the emitted js. */
declare var ct_modal: CtModalApi;
declare var ct_bulkbar: CtBulkbarApi;

/** Read by _renderAudit via `typeof renderAuditLog === "function"` — NEVER
 *  defined: ct_audit.js (watch source AND master) only defines
 *  `_renderAuditLog(c)`. Dead guard → audit panel = placeholder
 *  (pre-existing bug of the source, reproduced identically). */
declare var renderAuditLog: ((c: HTMLElement, opts?: { api?: unknown }) => void) | undefined;

/* Globals exposed on window (data-click dispatch + shared state). */
interface Window {
    /* set by watch_api.ts */
    _currentUser?: { name?: string; email?: string; role?: string } | null;
    _moduleRole?: string;
    _logout?: () => void;
    /* alert detail state (Watch_app.ts) */
    _currentAlertId?: string | null;
    _currentAnalysis?: WatchAnalysis | null;
    _watchAlertsBulkToggle?: (alertId: string) => void;
    _watchAlertsBulkToggleAll?: () => void;
    _watchAlertsBulkSetStatus?: (scope: string, status: string) => void;
}
