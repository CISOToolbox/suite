/**
 * Types du couche API backend (audit_api.ts) — variante suite uniquement.
 */

interface CtAuthUser {
    id: string;
    name?: string;
    email?: string;
    role?: string;
    picture?: string;
    ai_enabled?: string;
    last_login?: string;
}

interface AuditStoredProject {
    id: string;
    name: string;
    organization?: string | null;
    audit_date?: string | null;
    owner_id?: string | null;
    created_at?: string;
    updated_at?: string;
    data?: AuditData | string;
}

interface AuditMeasure {
    id: string;
    title: string;
    description?: string;
    statut: string;
    responsable?: string;
    echeance?: string;
    control_id?: string;
    progress_log?: Array<{ at?: string; by?: string; text?: string }>;
}

interface AuditAPIType {
    listMeasures(pid: string): Promise<AuditMeasure[]>;
    createMeasure(pid: string, body: any): Promise<AuditMeasure>;
    patchMeasure(pid: string, id: string, body: any): Promise<AuditMeasure>;
    deleteMeasure(pid: string, id: string): Promise<null>;
    list(): Promise<AuditStoredProject[]>;
    get(id: string): Promise<AuditStoredProject>;
    create(body?: { name?: string; data?: any }): Promise<AuditStoredProject>;
    update(id: string, body: { name?: string; data?: any }): Promise<AuditStoredProject>;
    del(id: string): Promise<null>;
    duplicate(id: string): Promise<AuditStoredProject>;
    importFile(file: File): Promise<AuditStoredProject>;
    aiComplete(systemPrompt: string, userPrompt: string, provider?: string, model?: string): Promise<{ text: string }>;
    aiConfig(): Promise<any>;
    aiGetKeys(): Promise<any>;
    aiSetKeys(data: any): Promise<any>;
    authMe(): Promise<CtAuthUser | null>;
    authLogout(): Promise<void>;
    listUsers(): Promise<CtAuthUser[]>;
    updateUser(id: string, data: Record<string, string>): Promise<CtAuthUser>;
}

declare var AuditAPI: AuditAPIType;
declare var _setDataReady: (() => void) | undefined;
declare var ct_modal: CtModalApi;
declare var ct_measure_modal: CtMeasureModalApi;
declare var ct_userpicker: CtUserpickerApi;
declare function onMetaChange(field: string, value: string): void;

/* Fournis par cisotoolbox_local.js en frontend ; absents (ou stubs) dans
   cisotoolbox_backend.js — l'app garde des appels guardés par typeof. */
declare var _renderSnapshotsPanel: ((opts: any) => Promise<void>) | undefined;
declare var _demoSettingsHTML: (() => string) | undefined;
declare var _wireDemoSettings: (() => void) | undefined;

interface Window {
    AuditAPI: AuditAPIType;
    _appInitCallback?: () => void;
    _setDataReady?: () => void;
    getActiveProjectId?: () => string | null;
    _loadBuffer?: (buffer: ArrayBuffer, filename: string) => any;
    _autoSave?: () => void;
    _currentUser?: CtAuthUser | null;
    _moduleRole?: string;
    _logout?: () => void;
    _openAuditPicker?: () => void;
    _closeAuditPicker?: () => void;
    _auditPickerOpen?: (id: string) => void;
    _auditPickerNew?: () => void;
    _auditPickerDup?: (id: string) => void;
    _auditPickerDel?: (id: string) => void;
    _auditPickerImport?: () => void;
    _auditControlMeasuresHTML?: (controlId: string) => string;
    _auditNewMeasure?: (controlId: string) => void;
    _editAuditMeasure?: (measureId: string) => void;
    _renderAuditMeasures?: () => void;
    ct_measure_modal?: typeof ct_measure_modal;
}
