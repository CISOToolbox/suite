// ─────────────────────────────────────────────────────────────
// REPLICATED from the private shared repository — do not edit here.
// GENERATED from shared/ts/ (or shared/types/) by shared/ts-build.sh.
// Edit the shared source instead: any change made in this repository is
// overwritten by the next sync, and pull requests touching this file
// cannot be merged. See CONTRIBUTING.md § Replicated files.
// ─────────────────────────────────────────────────────────────
/**
 * CISO Toolbox — Settings drawer
 *
 * The settings drawer (window.openSettings): Language section, AI section,
 * and per-module extra settings. Extracted from ai_common.js so the AI
 * file stays a pure AI engine.
 *
 * Load AFTER i18n.js, cisotoolbox.js and ai_common.js:
 *   <script src="js/ai_common.js"></script>
 *   <script src="js/ct_settings.js"></script>
 *
 * Depends on ai_common.js (via window): _AI_PROVIDERS, _aiK,
 * _aiValidateKey, the _aiGet/_aiSet storage accessors, _aiIsEnabled,
 * _aiEnsurePanel, _aiOpenPanel, _aiClosePanel.
 *
 * Per-module hooks via window.AI_APP_CONFIG:
 *   hideAI, settingsExtraHTML(), onSettingsRendered(), onSettingsSaved()
 */
interface Window {
    openSettings?: () => void;
    /** Allowlist de fournisseurs — posée par ai_backend.js (déploiements backend). */
    _AI_PROVIDER_ALLOWLIST?: string[];
    /** Flush provider/model/creds côté serveur — posé par ai_backend.js. */
    _aiPersistConfig?: () => void;
}
