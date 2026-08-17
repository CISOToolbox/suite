/**
 * Access Rights Review (demo-docker) — modèle de données D + globals app.
 * Types déduits de Access_app.ts / access_api.ts (création dans addUser /
 * addApp / startReview / addServiceAccount / addMeasure), de demo-fr.json
 * et des routes du backend Access. Fichier de types pur (aucun emit).
 */

/* ── Modèle D ───────────────────────────────────────────────────── */

type AccessDecision = "pending" | "conforme" | "non_conforme";

type AccessSiUser = {
    id: string;
    nom: string;
    prenom: string;
    email: string;
    /** "actif" | "ancien" | "recrutement" (legacy: "employe"). */
    statut: string;
    /** "salarie" | "prestataire" | "stagiaire" | "alternant". */
    type_compte?: string;
    fonction: string;
    /** Team / department (free text). */
    equipe?: string;
    /** Planned contract end date (ISO). Required for non-salarie. */
    date_fin_contrat?: string;
    /** Email of the user's manager (hierarchy). */
    manager_email?: string;
    politique_validee: boolean;
    politique_date?: string;
    politique_justification?: string;
    mfa_active: boolean;
    mfa_date?: string;
    mfa_justification?: string;
    sensibilisation: boolean;
    sensibilisation_date?: string;
    sensibilisation_justification?: string;
    sensibilisation_history?: Record<string, {
        completed?: boolean; due_date?: string; completion_date?: string;
        statut?: string; first_seen?: string; last_seen?: string;
    }>;
    background_check?: boolean;
    background_check_date?: string;
    background_check_justification?: string;
    background_check_url?: string;
    nda_signed?: boolean;
    nda_date?: string;
    nda_justification?: string;
    /** ISO datetime — alimenté par les connecteurs / Pilot. */
    last_login_at?: string;
    /** État du compte IdP (actif/désactivé) ; null/absent = inconnu. */
    account_enabled?: boolean | null;
    /** "pilot" → identité gérée par l'annuaire Pilot (champs verrouillés). */
    sync_source?: string;
};

type AccessApplication = {
    id: string;
    nom: string;
    url?: string;
    /** Ids de SiUser (ou emails annuaire Pilot). */
    reviewers?: string[];
    /** "trimestrielle" | "semestrielle" | "annuelle". */
    frequence_revue: string;
    /** "application" | "infrastructure" | "physique" (UI: "périmètre"). */
    type?: string;
    /** Free-text role names defined for this perimeter. */
    roles?: string[];
};

type AccessEntitlement = {
    id: string;
    si_user_id: string;
    perimetre_id: string;
    role: string;
    status: string;
    created_by: string;
    created_at: string;
    updated_by: string;
    updated_at: string;
};

type AccessEntitlementAudit = {
    id: string;
    si_user_id: string;
    entitlement_id: string;
    action: string;
    field: string;
    old_value: string;
    new_value: string;
    actor: string;
    at: string;
};

type AccessReviewEntry = {
    id: string;
    type_compte: string;
    email_or_login: string;
    nom?: string;
    prenom?: string;
    si_user_id?: string | null;
    roles?: string;
    groups?: string;
    decision: AccessDecision;
    decided_at?: string;
    decided_by?: string;
    notes?: string;
    last_login_at?: string;
    account_enabled?: boolean | null;
};

type AccessReview = {
    id: string;
    application_id: string;
    /** "en_cours" | "cloturee". */
    status: string;
    started_at: string;
    closed_at: string;
    closed_by: string;
    entries: AccessReviewEntry[];
};

type AccessMeasure = {
    id: string;
    review_entry_id: string;
    title: string;
    description?: string;
    /** "a_faire" | "en_cours" | "termine" | "annule". */
    statut: string;
    responsable?: string;
    echeance?: string;
};

type AccessServiceAccount = {
    id: string;
    name: string;
    identifier: string;
    /** "" | "azure" | "aws" | "gcp" | "on-prem" | "saas" | "other". */
    platform: string;
    application_id: string;
    purpose?: string;
    /** "vault" | "env_var" | "key_management" | "hardcoded" | "unknown". */
    secret_storage: string;
    /** "30d" | "60d" | "90d" | "180d" | "365d" | "never" | "unknown". */
    rotation_policy: string;
    last_rotation: string;
    owners?: string[];
    /** "critical" | "high" | "medium" | "low". */
    risk_level: string;
    notes?: string;
};

type AccessMetadata = {
    organization: string;
    created: string;
};

type AccessData = {
    si_users: AccessSiUser[];
    applications: AccessApplication[];
    reviews: AccessReview[];
    measures: AccessMeasure[];
    service_accounts: AccessServiceAccount[];
    metadata: AccessMetadata;
};

/* ── Plugins (connecteurs) — hors D, chargés via l'API ──────────── */

type AccessPluginConfigField = {
    key: string;
    label?: string;
    type?: string;
    required?: boolean;
    placeholder?: string;
    rows?: number;
    /** Objets {value,label} ou primitives nues — formats mixtes côté backend. */
    options?: any[];
};

type AccessAvailablePlugin = {
    type: string;
    label: string;
    config_schema?: AccessPluginConfigField[];
    setup_guide?: string;
    setup_guide_en?: string;
    accepts_file?: boolean;
};

type AccessPlugin = {
    id: string;
    plugin_type: string;
    label?: string;
    enabled?: boolean;
    schedule?: string;
    config?: Record<string, unknown>;
    group_filters?: string[];
    application_id?: string;
    last_sync_at?: string;
    last_sync_status?: string;
    accepts_file?: boolean;
};

type AccessSyncJob = {
    started_at?: string;
    status?: string;
    users_found?: number | null;
    users_created?: number | null;
    users_updated?: number | null;
    error_message?: string;
};

/* ── Réponses API ───────────────────────────────────────────────── */

type AccessProject = {
    id: string;
    name?: string;
    data?: AccessData | string;
};

interface AccessPilotSyncResult {
    created: number;
    updated: number;
    skipped: number;
    total_pilot: number;
}

interface AccessCsvImportResult {
    imported: number;
    matched?: number;
    unmatched?: number;
}

interface AccessAssetSyncResult {
    imported: number;
    total_assets_found?: number;
}

interface AccessConnectorImportResult {
    imported: number;
    matched: number;
    unmatched: number;
    skipped_duplicates: number;
    removed_disabled?: number;
    connector_errors_count?: number;
}

interface AccessPluginTestResult {
    ok: boolean;
    error?: string;
}

interface AccessAuthUser {
    email: string;
    name?: string;
    role?: string;
}

interface AccessApi {
    list(): Promise<AccessProject[]>;
    get(id: string): Promise<AccessProject>;
    create(data?: { name: string; data: unknown }): Promise<AccessProject>;
    update(id: string, data: { name: string; data: unknown }): Promise<AccessProject>;
    del(id: string): Promise<unknown>;
    saveFull(pid: string, data: AccessData): Promise<AccessProject>;
    importFile(file: File): Promise<any>;
    exportUrl(id: string): string;

    listSiUsers(pid: string): Promise<AccessSiUser[]>;
    createSiUser(pid: string, data: Partial<AccessSiUser>): Promise<AccessSiUser>;
    patchSiUser(pid: string, uid: string, fields: Partial<AccessSiUser>): Promise<AccessSiUser>;
    deleteSiUser(pid: string, uid: string): Promise<unknown>;
    syncSiUsersFromPilot(pid: string): Promise<AccessPilotSyncResult>;
    importSiUsersCsv(pid: string, file: File): Promise<{ created: number; updated: number; skipped: number }>;
    syncSiUsersFromHr(pid: string): Promise<{ instances: number; created: number; updated: number; skipped: number; errors: string[] }>;
    listEntitlements(pid: string, uid: string): Promise<AccessEntitlement[]>;
    listEntitlementAudit(pid: string, uid: string): Promise<AccessEntitlementAudit[]>;
    createEntitlement(pid: string, uid: string, data: { perimetre_id: string; role: string }): Promise<AccessEntitlement>;
    deleteEntitlement(pid: string, uid: string, eid: string): Promise<unknown>;

    listApps(pid: string): Promise<AccessApplication[]>;
    createApp(pid: string, data: Partial<AccessApplication>): Promise<AccessApplication>;
    patchApp(pid: string, aid: string, fields: Partial<AccessApplication>): Promise<AccessApplication>;
    deleteApp(pid: string, aid: string): Promise<unknown>;
    importAppsCsv(pid: string, file: File): Promise<AccessCsvImportResult>;
    syncAppsFromAsset(pid: string): Promise<AccessAssetSyncResult>;

    listReviews(pid: string, status?: string): Promise<AccessReview[]>;
    getReview(pid: string, rid: string): Promise<AccessReview>;
    createReview(pid: string, data: { application_id: string }): Promise<AccessReview>;
    importCsv(pid: string, rid: string, file: File): Promise<AccessCsvImportResult>;
    patchEntry(pid: string, rid: string, eid: string, fields: Partial<AccessReviewEntry>): Promise<AccessReviewEntry>;
    closeReview(pid: string, rid: string): Promise<unknown>;
    exportReview(pid: string | null, rid: string): string;
    deleteReview(pid: string, rid: string): Promise<unknown>;

    listMeasures(pid: string): Promise<AccessMeasure[]>;
    createMeasure(pid: string, data: Partial<AccessMeasure>): Promise<AccessMeasure>;
    patchMeasure(pid: string, mid: string, fields: Partial<AccessMeasure>): Promise<AccessMeasure>;
    deleteMeasure(pid: string, mid: string): Promise<unknown>;

    listServiceAccounts(pid: string): Promise<AccessServiceAccount[]>;
    createServiceAccount(pid: string, d: Partial<AccessServiceAccount>): Promise<AccessServiceAccount>;
    patchServiceAccount(pid: string, id: string, f: Partial<AccessServiceAccount>): Promise<AccessServiceAccount>;
    deleteServiceAccount(pid: string, id: string): Promise<unknown>;

    listAvailablePlugins(): Promise<AccessAvailablePlugin[]>;
    listPlugins(pid: string): Promise<AccessPlugin[]>;
    createPlugin(pid: string, d: Record<string, unknown>): Promise<AccessPlugin>;
    patchPlugin(pid: string, id: string, f: Record<string, unknown>): Promise<AccessPlugin>;
    deletePlugin(pid: string, id: string): Promise<unknown>;
    testPlugin(pid: string, id: string): Promise<AccessPluginTestResult>;
    testPluginConfig(pid: string, body: { plugin_type: string; config: Record<string, unknown> }): Promise<AccessPluginTestResult>;
    importReviewFromConnector(pid: string, rid: string, body?: Record<string, unknown>): Promise<AccessConnectorImportResult>;
    importReviewFromConnectorFile(pid: string, rid: string, file: File, pluginId?: string): Promise<AccessConnectorImportResult>;
    pluginHistory(pid: string, id: string): Promise<AccessSyncJob[]>;

    aiComplete(sys: string, usr: string, prov?: string, model?: string): Promise<any>;
    aiConfig(): Promise<any>;

    authMe(): Promise<AccessAuthUser | null>;
    authProviders(): Promise<any>;
    authLogout(): Promise<void>;
    listUsers(): Promise<any[]>;
    updateUser(id: string, data: Record<string, unknown>): Promise<any>;
}

/* ── Globals shared déclarés Window-only dans les .d.ts générés ───
 * ct_table / ct_bulkbar / ct_modal / ct_measure_modal n'exposent leurs
 * APIs que sur l'interface Window (propriétés optionnelles) ;
 * Access_app.js les appelle en globals nus → déclarations ambiantes
 * locales (aucun impact sur le js émis). Idem pour les helpers de
 * directory_picker.js et la couche access_api.js (toujours chargés
 * avant Access_app.js dans index.html). */
declare var ct_table: CtTableApi;
declare var ct_bulkbar: CtBulkbarApi;
declare var ct_modal: CtModalApi;
declare var ct_measure_modal: CtMeasureModalApi;
declare function _dirGetSource(): string;
declare function _dirMultiPicker(currentIds: string[] | null | undefined, addHandler: string, removeHandler: string): string;
/** Truth-testé nu dans renderAppDetail → déclaré possiblement undefined. */
declare var _dirResolve: ((email: string | null | undefined) => string) | undefined;
declare var AccessAPI: AccessApi;
declare function getActiveProjectId(): string | null;
declare var _setDataReady: (() => void) | undefined;

/* ── Window : propriétés posées par access_api.js / Access_app.js ── */

interface Window {
    /* access_api.js */
    AccessAPI?: AccessApi;
    getActiveProjectId?: () => string | null;
    _setDataReady?: () => void;
    _autoSave?: () => void;
    _loadBuffer?: (buffer: ArrayBuffer, filename: string) => unknown;
    _appInitCallback?: () => void;
    _currentUser?: AccessAuthUser;
    _moduleRole?: string;
    _logout?: () => void;
    openUserAdmin?: () => void;
    /** Hook de sauvegarde debouncée (couches backend alternatives). */
    _debouncedSave?: () => void;

    /* directory_picker.js (decl générée vide — globals window-only) */
    _dirGetSource?: () => string;
    _dirMultiPicker?: (currentIds: string[] | null | undefined, addHandler: string, removeHandler: string) => string;
    _dirResolve?: (email: string | null | undefined) => string;

    /* Access_app.js — fonctions data-click/data-change/data-input */
    _filterUsers?: (val: string) => void;
    syncUsersFromPilot?: () => void;
    syncUsersFromHr?: () => void;
    addEntitlement?: () => void;
    removeEntitlement?: (eid: string) => void;
    _entPerimOpen?: () => void;
    _entPerimSearch?: (query: string) => void;
    _entPickPerim?: (perimId: string) => void;
    importUsersCsv?: () => void;
    downloadUsersCsvTemplate?: () => void;
    _openUserRow?: (row: { id: string }) => void;
    _bulkDeleteUsers?: (scope: string) => void;
    openUser?: typeof openUser;
    addUser?: typeof addUser;
    backToUsers?: typeof backToUsers;
    deleteUser?: typeof deleteUser;
    saveUserField?: typeof saveUserField;
    saveUserCheck?: typeof saveUserCheck;
    _filterApps?: (val: string) => void;
    _openAppRow?: (row: { id: string }) => void;
    _bulkDeleteApps?: (scope: string) => void;
    openApp?: typeof openApp;
    addApp?: typeof addApp;
    backToApps?: typeof backToApps;
    deleteApp?: typeof deleteApp;
    deleteReviewFromApp?: (reviewId: string) => void;
    saveAppField?: typeof saveAppField;
    saveAppRoles?: typeof saveAppRoles;
    addAppReviewer?: typeof addAppReviewer;
    removeAppReviewer?: typeof removeAppReviewer;
    importAppsCsv?: typeof importAppsCsv;
    syncAppsFromAsset?: typeof syncAppsFromAsset;
    openReview?: typeof openReview;
    backToReviews?: typeof backToReviews;
    startReview?: typeof startReview;
    _toggleReviewFilter?: (key: string) => void;
    _clearReviewFilters?: () => void;
    setDecision?: typeof setDecision;
    importReviewCsv?: typeof importReviewCsv;
    downloadCsvTemplate?: typeof downloadCsvTemplate;
    importReviewFromConnector?: () => void;
    closeReview?: typeof closeReview;
    openSA?: typeof openSA;
    backToSA?: typeof backToSA;
    addServiceAccount?: typeof addServiceAccount;
    deleteServiceAccount?: typeof deleteServiceAccount;
    saveSAField?: typeof saveSAField;
    _refreshMeasures?: () => void;
    _editAccessMeasureRow?: (row: { id: string }) => void;
    _bulkAccessMeasuresDone?: (scope: string) => void;
    _bulkAccessMeasuresDelete?: (scope: string) => void;
    addMeasure?: typeof addMeasure;
    showPluginModal?: typeof showPluginModal;
    _plgSearchFilter?: (query: string) => void;
    _plgSelectType?: (type: string) => void;
    _plgCancel?: () => void;
    _plgTypeChanged?: () => void;
    _toggleReviewListFilter?: (key: string) => void;
    _plgTestInline?: (pluginId: string) => void;
    _plgSave?: (existingId: string) => void;
    testPlugin?: typeof testPlugin;
    deletePlugin?: typeof deletePlugin;
    showPluginHistory?: typeof showPluginHistory;
}
