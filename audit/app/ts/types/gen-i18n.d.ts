// ─────────────────────────────────────────────────────────────
// REPLICATED from the private shared repository — do not edit here.
// GENERATED from shared/ts/ (or shared/types/) by shared/ts-build.sh.
// Edit the shared source instead: any change made in this repository is
// overwritten by the next sync, and pull requests touching this file
// cannot be merged. See CONTRIBUTING.md § Replicated files.
// ─────────────────────────────────────────────────────────────
/**
 * CISO Toolbox — Système i18n (FR/EN)
 *
 * Charger AVANT cisotoolbox.js et les fichiers app.
 * Chaque app ajoute ses traductions via _registerTranslations().
 */
declare var _locale: string;
declare var _translations: Record<string, CtI18nDict>;
declare function _registerTranslations(lang: string, dict: CtI18nDict): void;
declare function t(key: string, params?: Record<string, string | number>): string;
declare function _initLocale(): void;
declare var _i18nLoaded: Record<string, boolean>;
declare function _loadI18nFile(lang: string, cb?: () => void): void;
declare function switchLang(lang?: string, cb?: () => void): void;
declare function _applyStaticTranslations(): void;
declare function _getSettingsButtonHTML(): string;
declare function _getGithubLinkHTML(repoUrl: string): string;
declare function _rt(obj: Record<string, any>, field: string): string;
