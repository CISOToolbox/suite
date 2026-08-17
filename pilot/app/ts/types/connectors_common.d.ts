// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/types/gen/connectors_common.d.ts).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/** Libellé bilingue { fr, en } ou chaîne brute. */
type CtConnLabel = string | {
    fr?: string;
    en?: string;
    [lang: string]: string | undefined;
};
interface CtConnField {
    id: string;
    label?: CtConnLabel;
    help?: CtConnLabel;
    secret?: boolean;
    required?: boolean;
    pattern?: string;
    placeholder?: string;
}
interface CtConnSchema {
    fields?: CtConnField[];
    prereqs?: {
        setup_guide?: CtConnLabel;
    };
    setup_guide?: CtConnLabel;
    [k: string]: any;
}
interface CtConnector {
    id: string;
    schema?: CtConnSchema;
    configured?: boolean;
    config?: Record<string, any>;
    [k: string]: any;
}
interface CtConnRuntime {
    managed: boolean;
    connectors: CtConnector[];
    [k: string]: any;
}
interface CtConnHttpError extends Error {
    status?: number;
    body?: any;
}
interface Window {
    _connRuntime?: () => Promise<CtConnRuntime>;
    _connInvalidateCache?: () => void;
    _connIsManaged?: () => Promise<boolean>;
    _connList?: () => Promise<CtConnector[]>;
    _connGet?: (id: string) => Promise<any>;
    _connSave?: (id: string, body: Record<string, any>) => Promise<any>;
    _connTest?: (id: string) => Promise<any>;
    _connRun?: (id: string) => Promise<any>;
    _connT?: (obj: CtConnLabel | null | undefined, lang?: string) => string;
    _connRenderForm?: (schema: CtConnSchema | null | undefined, current: Record<string, any> | null | undefined, lang?: string) => string;
    _connReadForm?: (schema: CtConnSchema | null | undefined, root: ParentNode) => Record<string, string>;
    _connSetupGuide?: (schema: CtConnSchema | null | undefined, lang?: string) => string;
    _connHelpPanelHtml?: (schema: CtConnSchema | null | undefined, lang?: string) => string;
    _connToggleHelp?: (el: Element | null) => void;
}
