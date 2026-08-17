/**
 * Watch (demo-docker) — modèle de données serveur + globals app.
 * Watch n'a pas de modèle D local (app 100 % pilotée par l'API REST) :
 * les interfaces décrivent les payloads renvoyés par watch_api.ts.
 * Fichier de types pur (aucun emit).
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
    /* digest vulnérabilités */
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

/** Analyse IA d'une alerte (cache backend). */
interface WatchAnalysis {
    sections?: Record<string, string>;
    provider?: string;
    model?: string;
    generated_at?: string;
}

/** Filtres client du panneau alertes. */
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

/* ── Globals shared déclarés Window-only dans les .d.ts générés ────
 * ct_modal / ct_bulkbar n'exposent leurs APIs que sur Window
 * (propriétés optionnelles). Watch_app.ts les appelle en globals nus
 * (gardés par des checks window.X / typeof comme le source) —
 * déclarations ambiantes locales, aucun impact sur le js émis. */
declare var ct_modal: CtModalApi;
declare var ct_bulkbar: CtBulkbarApi;

/** Lu par _renderAudit via `typeof renderAuditLog === "function"` — JAMAIS
 *  défini : ct_audit.js (source watch ET master) ne définit que
 *  `_renderAuditLog(c)`. Garde morte → panneau audit = placeholder
 *  (bug pré-existant de la source, reproduit à l'identique). */
declare var renderAuditLog: ((c: HTMLElement, opts?: { api?: unknown }) => void) | undefined;

/* Globals exposés sur window (dispatch data-click + état partagé). */
interface Window {
    /* posés par watch_api.ts */
    _currentUser?: { name?: string; email?: string; role?: string } | null;
    _moduleRole?: string;
    _logout?: () => void;
    /* état du détail d'alerte (Watch_app.ts) */
    _currentAlertId?: string | null;
    _currentAnalysis?: WatchAnalysis | null;
    _watchAlertsBulkToggle?: (alertId: string) => void;
    _watchAlertsBulkToggleAll?: () => void;
    _watchAlertsBulkSetStatus?: (scope: string, status: string) => void;
}
