/**
 * Asset Management (demo-docker variant) — data model D + app globals.
 * Base: opensource port (frontend-ts/opensource/asset/app/ts/Asset_types.d.ts),
 * extended with the backend fields: licence, connectors (sources/manual locks,
 * ip_address, last_login_at), custom types, renewal deadlines, plugins,
 * API layer (asset_api.ts). Pure type file (no emit).
 */

interface AssetRaciCells {
    r: string;
    a: string;
    c: string;
    i: string;
}

interface AssetRaciRow extends AssetRaciCells {
    activite: string;
}

/** Legacy RACI object format { installation: {r,a,c,i}, mco: …, mcs: … } —
 *  migrated to AssetRaciRow[] by _ensureRaciArray(). */
type AssetRaciLegacy = Record<string, Partial<AssetRaciCells>>;

interface AssetPolSauvegarde {
    frequence?: string;
    retention?: string;
    type?: string;
    site_distant?: boolean;
    teste?: boolean;
    dernier_test?: string;
    notes?: string;
}

interface AssetPolSupervision {
    outil?: string;
    perimetre?: string;
    alerting?: boolean;
    h24?: boolean;
    notes?: string;
}

interface AssetPolMaj {
    frequence?: string;
    fenetre?: string;
    validation?: string;
    critique_delai?: string;
    notes?: string;
}

/** License / support contract cycle (backend variant). */
interface AssetLicence {
    date_renouvellement?: string;
    /** Notice period in days — number at creation, may be a string after form edits. */
    preavis_jours?: number | string;
    cout?: string;
    devise?: string;
    reference?: string;
    contact?: string;
}

/** Field provenance (connectors) — sources.fields[field] = "manual" | <plugin>. */
interface AssetSources {
    fields?: Record<string, string>;
    [k: string]: any;
}

interface AssetItem {
    id: string;
    nom: string;
    type: string;
    description?: string;
    criticite: number;
    proprietaire?: string;
    localisation?: string;
    quantite?: number;
    os?: string;
    version?: string;
    fournisseur?: string;
    fin_support?: string;
    fin_vie?: string;
    statut?: string;
    notes?: string;
    groupe_ids?: string[];
    depends_on?: string[];
    /* ── backend-variant fields ── */
    ip_address?: string;
    last_login_at?: string;
    licence?: AssetLicence;
    sources?: AssetSources;
}

interface AssetGroupe {
    id: string;
    nom: string;
    principe?: string;
    criticite?: number;
    raci?: AssetRaciRow[] | AssetRaciLegacy;
    politique_sauvegarde?: AssetPolSauvegarde;
    politique_supervision?: AssetPolSupervision;
    politique_maj?: AssetPolMaj;
    asset_ids?: string[];
    depends_on_groups?: string[];
    notes?: string;
}

interface AssetMetadata {
    organization?: string;
    created?: string;
}

/** Custom asset type (D.custom_asset_types). */
interface AssetCustomType {
    id: string;
    label: string;
    label_en?: string;
    color?: string;
}

interface AssetData {
    assets: AssetItem[];
    groupes: AssetGroupe[];
    metadata: AssetMetadata;
    custom_asset_types?: AssetCustomType[];
}

/** Dependency view (asset or group) resolved for display. */
interface AssetDepView {
    id: string;
    nom: string;
    badge: string;
    kind: string;
}

/* ── Renewal deadlines (licence / end of support / end of life) ── */

type AssetEcheanceKind = "licence" | "support" | "vie";
type AssetEcheanceBucket = "expired" | "due" | "upcoming";

interface AssetEcheance {
    asset: AssetItem;
    kind: AssetEcheanceKind;
    date: string;
    days: number;
    bucket: AssetEcheanceBucket;
}

/** Client-side sort state of the asset list. */
interface AssetSortState {
    key: string;
    direction: "asc" | "desc";
}

/* ── Connectors (AD / Intune / EDR… plugins) ───────────────────── */

interface AssetPluginConfigField {
    key: string;
    label?: string;
    type?: string;
    required?: boolean;
    placeholder?: string;
    default?: boolean;
}

/** Definition of an available connector type (GET /plugins/available). */
interface AssetPluginTypeDef {
    type: string;
    label: string;
    setup_guide?: string;
    config_schema?: AssetPluginConfigField[];
}

/** Connector configured on the project. */
interface AssetPlugin {
    id: string;
    plugin_type: string;
    label?: string;
    enabled?: boolean;
    priority?: number;
    schedule?: string;
    config?: Record<string, any>;
    filters?: Record<string, any>;
    last_sync_status?: string;
    last_sync_at?: string;
}

/** Payload of the connector add/edit form (_collectPluginForm). */
interface AssetPluginForm {
    plugin_type: string;
    label: string;
    enabled: boolean;
    priority: number;
    schedule: string;
    config: Record<string, any>;
    filters: Record<string, any>;
    /** Id of the connector being edited (empty at creation) — set by
     *  _collectPluginForm from the hidden aplg-id field, read by _testCurrentForm
     *  to reopen the modal on the same connector. */
    plugin_id?: string;
}

/** Result of one connector sync. */
interface AssetSyncResult {
    assets_found?: number;
    assets_created?: number;
    assets_updated?: number;
    assets_unchanged?: number;
    assets_retired?: number;
    assets_reactivated?: number;
    assets_merged_hosts?: number;
    connector_errors_count?: number;
}

/** Sync history entry. */
interface AssetPluginJob {
    status?: string;
    started_at?: string;
    assets_found?: number | null;
    assets_created?: number | null;
    assets_updated?: number | null;
    assets_unchanged?: number | null;
    error_message?: string;
}

/* ── API layer (asset_api.ts) ──────────────────────────────────── */

interface AssetFetchOpts {
    method?: string;
    body?: any;
    headers?: Record<string, string>;
    credentials?: RequestCredentials;
}

interface CtAuthUser {
    id: string;
    name?: string;
    email?: string;
    role?: string;
    picture?: string;
    ai_enabled?: string;
    last_login?: string;
}

interface AssetMeasure {
    id: string;
    title: string;
    description?: string;
    statut: string;
    responsable?: string;
    echeance?: string;
    progress_log?: Array<{ at?: string; by?: string; text?: string }>;
    origine?: string;
    asset_id?: string;
}

interface AssetApiClient {
    list(): Promise<any>;
    get(id: string): Promise<any>;
    create(data?: { name?: string; data?: any }): Promise<any>;
    update(id: string, data: { name?: string; data?: any }): Promise<any>;
    del(id: string): Promise<any>;
    duplicate(id: string): Promise<any>;
    importFile(file: File): Promise<any>;
    exportUrl(id: string): string;
    importCsv(projectId: string, file: File): Promise<any>;
    saveFull(projectId: string, data: AssetData): Promise<any>;
    listAvailablePlugins(): Promise<AssetPluginTypeDef[]>;
    listPlugins(pid: string): Promise<AssetPlugin[]>;
    createPlugin(pid: string, body: AssetPluginForm): Promise<any>;
    patchPlugin(pid: string, id: string, body: AssetPluginForm): Promise<any>;
    deletePlugin(pid: string, id: string): Promise<any>;
    testPlugin(pid: string, id: string): Promise<any>;
    testPluginConfig(pid: string, body: AssetPluginForm): Promise<any>;
    syncPlugin(pid: string, id: string): Promise<AssetSyncResult>;
    pluginHistory(pid: string, id: string): Promise<AssetPluginJob[]>;
    listMeasures(pid: string): Promise<AssetMeasure[]>;
    createMeasure(pid: string, body: any): Promise<AssetMeasure>;
    patchMeasure(pid: string, id: string, body: any): Promise<AssetMeasure>;
    deleteMeasure(pid: string, id: string): Promise<any>;
    aiComplete(systemPrompt: string, userPrompt: string, provider?: string, model?: string): Promise<any>;
    aiConfig(): Promise<any>;
    aiGetKeys(): Promise<any>;
    aiSetKeys(data: any): Promise<any>;
    authMe(): Promise<any>;
    authProviders(): Promise<any>;
    authLogout(): Promise<any>;
    listUsers(): Promise<CtAuthUser[]>;
    updateUser(id: string, data: Record<string, string>): Promise<any>;
}

/* ── Shared globals declared Window-only in the generated .d.ts ────
 * ai_common / ct_table / ct_bulkbar / ct_modal / directory_picker
 * expose their APIs only on the Window interface (optional
 * properties). Asset_app.ts calls them as bare globals (guarded by
 * window.X checks like the source) — local ambient declarations,
 * no impact on the emitted js (vendor-port pattern). */
declare function _aiIsEnabled(): boolean;
declare function _aiGetContext(): string;
declare function _aiCallAPI(systemPrompt: string, userPrompt: string): Promise<string>;
declare function _aiParseJSON(raw: string): any;
declare function _aiEnsurePanel(): { title: HTMLElement; body: HTMLElement; footer: HTMLElement };
declare function _aiOpenPanel(): void;
declare function _aiClosePanel(): void;
declare function _aiShowLoading(title: string): void;
declare function _aiShowError(title: string, errMsg: string): void;
declare var ct_table: CtTableApi;
declare var ct_bulkbar: CtBulkbarApi;
declare var ct_modal: CtModalApi;
/** Set by directory_picker.js (window._dirPicker) — generated decl is empty (IIFE). */
declare var _dirPicker: (currentValue: string | null | undefined, handler: string, argsJson: string) => string;
/** Per-entity PATCH layer — does NOT exist in asset (blob autosave only); guarded by typeof. */
declare var _persist: ((entityType: string, id: string, patch: Record<string, any>) => void) | undefined;
/** Set by asset_api.ts on window; called as bare globals after a guard. */
declare var AssetAPI: AssetApiClient;
declare function getActiveProjectId(): string | null;
declare var _setDataReady: (() => void) | undefined;

/* Globals exposed on window (data-click dispatch + persistence hooks). */
interface Window {
    /* persistence hooks redefined by asset_api.ts */
    _autoSave?: () => void;
    _cancelAutosave?: () => void;
    _debouncedSave?: () => void;
    _loadBuffer?: (buffer: ArrayBuffer, filename: string) => Promise<true | null> | void;
    _setDataReady?: () => void;
    _appInitCallback?: () => void;
    AssetAPI?: AssetApiClient;
    getActiveProjectId?: () => string | null;
    /* auth / toolbar (asset_api.ts) */
    _currentUser?: CtAuthUser | null;
    _moduleRole?: string;
    _logout?: () => void;
    openUserAdmin?: () => void;
    _toggleAiAccess?: (userId: string, el: HTMLInputElement) => void;
    _changeUserRole?: (userId: string, role: string) => void;
    /* Asset_app.ts — data-click/data-change globals */
    openEcheanceAsset?: (id: string) => void;
    exportEcheancesIcs?: typeof exportEcheancesIcs;
    _sortAssets?: (key: string) => void;
    _toggleAssetColsPopup?: () => void;
    _toggleAssetCol?: (key: string, el: HTMLInputElement) => void;
    filterAssets?: typeof filterAssets;
    filterAssetType?: typeof filterAssetType;
    filterAssetCrit?: typeof filterAssetCrit;
    filterAssetStatut?: typeof filterAssetStatut;
    _openAssetRow?: (row: Record<string, any>) => void;
    _bulkAssetsRetire?: (scope: string) => void;
    _bulkAssetsEdit?: (scope: string) => void;
    _bulkAssetsDelete?: (scope: string) => void;
    _bulkAssetsAddToGroup?: (scope: string) => void;
    openAsset?: typeof openAsset;
    addAsset?: typeof addAsset;
    openAssetTypesModal?: () => void;
    _deleteCustomType?: (idx: number) => void;
    deleteAsset?: typeof deleteAsset;
    _clearManualLocks?: () => void;
    saveAssetField?: typeof saveAssetField;
    saveLicenceField?: typeof saveLicenceField;
    backToAssets?: typeof backToAssets;
    addAssetDep?: typeof addAssetDep;
    removeAssetDep?: typeof removeAssetDep;
    addAssetGroupe?: typeof addAssetGroupe;
    removeAssetGroupe?: typeof removeAssetGroupe;
    openGroupe?: typeof openGroupe;
    addGroupe?: typeof addGroupe;
    deleteGroupe?: typeof deleteGroupe;
    switchGroupeTab?: typeof switchGroupeTab;
    backToGroupes?: typeof backToGroupes;
    saveRaciCell?: typeof saveRaciCell;
    saveRaciActivite?: typeof saveRaciActivite;
    addRaciRow?: typeof addRaciRow;
    removeRaciRow?: typeof removeRaciRow;
    addGroupeAsset?: typeof addGroupeAsset;
    _openGroupeAssetPicker?: () => void;
    _groupePickerFilter?: (val: string) => void;
    removeGroupeAsset?: typeof removeGroupeAsset;
    addGroupeDep?: typeof addGroupeDep;
    removeGroupeDep?: typeof removeGroupeDep;
    saveGroupeField?: typeof saveGroupeField;
    saveGroupePol?: typeof saveGroupePol;
    saveGroupePolCheck?: typeof saveGroupePolCheck;
    importCsvDialog?: typeof importCsvDialog;
    aiSuggestDescription?: typeof aiSuggestDescription;
    aiSuggestPrincipe?: typeof aiSuggestPrincipe;
    aiSuggestRaci?: typeof aiSuggestRaci;
    aiSuggestPolitiques?: typeof aiSuggestPolitiques;
    /* connectors */
    showPluginModal?: (pluginId?: string) => void;
    _aplgTypeChanged?: (val: string) => void;
    testAssetPlugin?: (pluginId: string) => void;
    syncAssetPlugin?: (pluginId: string) => void;
    refreshConnectors?: () => void;
    deleteAssetPlugin?: (pluginId: string) => void;
    showAssetPluginHistory?: (pluginId: string) => void;
}
