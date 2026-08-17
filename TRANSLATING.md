# Adding a language to CISO Toolbox

The product ships **English (base language) + French**. The i18n engine is
language-agnostic — adding a language is a matter of providing dictionaries
that follow the file-name convention, then declaring the language to the
packaging. This guide walks a translator through it end to end.

## How i18n works (2 minutes)

- Every user-visible string goes through `t("key")` in JS or a
  `data-i18n="key"` attribute in HTML. Keys are namespaced per app
  (`pilot.measures.title`, `watch.digest.subject`…).
- Each app loads **two dictionary layers**:
  - `js/i18n_core_<lang>.js` — the **core dictionary** shared by all apps
    (common buttons, table chrome, settings panel, AI panel…);
  - `js/<App>_i18n_<lang>.js` — the **app dictionary** (e.g.
    `Pilot_i18n_fr.js`, `EBIOS_RM_i18n_en.js`).
- The **base language (English)** is loaded statically; other languages are
  **lazy-loaded on first switch** by file-name convention
  (`_loadI18nFile("de")` fetches `js/i18n_core_de.js` +
  `js/<App>_i18n_de.js`). Missing keys fall back to the base language, so a
  partial translation degrades gracefully instead of breaking.
- The language switcher (globe icon) offers the languages listed in
  `window._CT_LANGS`, injected at packaging time — or, in a raw dev tree,
  the languages whose dictionaries are actually loaded.

## What to translate for a new language `xx`

App dictionaries are **authored in TypeScript** (`app/ts/…`) and compiled to
`app/js/` by the build. For each module you want to cover:

1. Copy the English app dictionary and translate the values (never the
   keys):
   ```bash
   cp <module>/app/ts/<App>_i18n_en.ts <module>/app/ts/<App>_i18n_xx.ts
   # then edit: keep every key, translate every value
   ```
2. Translate the **core dictionary** once (same shape as
   `app/js/i18n_core_en.js`): it is maintained as a shared master upstream,
   so contribute it as `i18n_core_xx` alongside your PR — maintainers wire
   it into the shared tree and the build distributes it to every app.

### Translation rules

- **Never translate keys**, only values.
- **Preserve placeholders** exactly: `{n}`, `{msg}`, `{name}`, `{days}`…
  They are substituted at runtime.
- Some values contain **HTML markup** (the in-app help pages under
  `*.help.methodo` / `*.help.usage`, tooltips with `<strong>`…): translate
  the text, keep the tags and their nesting intact.
- Keep encoded entities/escapes as they are (`&laquo;`, `&mdash;`,
  `→`…) unless your language calls for different typography.
- Dynamic keys (ending with `.` or `_`, e.g. `t("comp.statut." + value)`)
  are completed at runtime — make sure every possible suffix key exists.

## Declaring the language

1. **Language name in the switcher**: `de`, `es`, `it`, `pt`, `nl` are
   already known to the engine (`_LANG_NAMES` in the shared `i18n.ts`). For
   another language, add its native name there (one line).
2. **Packaging**: add the language to `shared/i18n.conf`:
   ```bash
   BASE=en
   LANGS="en fr xx"
   ```
   The packaging step (`i18n-apply.sh`, run by the image builds) injects
   `window._CT_LANGS` into each `index.html` and keeps only the retained
   languages' files — a deployment that doesn't want `xx` simply builds with
   `--langs "en fr"`.
3. **Dev tree preview** (no packaging): add the two static tags to the
   app's `index.html` next to the existing ones:
   ```html
   <script src="js/i18n_core_xx.js"></script>
   <script src="js/<App>_i18n_xx.js"></script>
   ```

## Checking your work

- **Key parity**: every key of the English file must exist in yours and
  vice-versa. The repo gate (`check-i18n.py`) currently enforces parity for
  the FR/EN pair; for another language, diff the key sets:
  ```bash
  python3 - <<'EOF'
  import re
  keys = lambda p: set(re.findall(r'"([a-z0-9_.]+)"\s*:', open(p).read()))
  en = keys("pilot/app/ts/Pilot_i18n_en.ts")
  xx = keys("pilot/app/ts/Pilot_i18n_xx.ts")
  print("missing:", sorted(en - xx)); print("extra:", sorted(xx - en))
  EOF
  ```
- **In the browser**: build (`docker compose up -d --build <module>-app`),
  switch to your language with the globe icon, and walk every page — the
  fallback makes untranslated strings show up in English, which is exactly
  what to hunt for.

## Known limits

- **Reference data** (compliance frameworks, control catalogues, DORA
  codelists…) is bilingual FR/EN in the data model (`_rt()` helper, `_en`
  suffixed fields). A third UI language falls back to English for that
  content — translating it is a separate, heavier effort on the data files.
- **Demo data** (`demo-fr.json` / `demo-en.json`) is optional: a language
  without demo files simply offers the existing ones.
- **Emails** (Watch digests, Pilot deadline digests) currently render in
  FR/EN only; extending them means adding your language to the small `_L`
  string tables in the modules' digest code.

## Contributing the translation

Open a PR with: the per-app `*_i18n_xx.ts` files, the `i18n_core_xx`
dictionary, the `_LANG_NAMES` addition if needed, and the `i18n.conf`
update. Partial coverage is acceptable (fallback covers the rest) — state
in the PR which apps are fully translated.
