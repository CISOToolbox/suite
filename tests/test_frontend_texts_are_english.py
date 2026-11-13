"""A text the frontend holds in one language is English.

A text shown to a user goes through `t("key")` or carries a `data-i18n*`
key, and its two languages live in the dictionaries. What is left outside
them exists once, and that once is English: the text a page shows before its
scripts ran, a file name, the content of a sample file, an `aria-label`.

The sweep reads, for every module:
- its scripts — the TypeScript of `app/ts/` and the shared scripts it is
  served with (`app/js/`, those that have no source in `app/ts/`) — for a
  string that reads as French (`_looks_french`), and for a text given after a
  translation (`t("key") || "text"`, `tEsc("key") ?? "text"`): `t()` returns
  the key when a text is missing, never an empty value, so the second text is
  never shown and only hides that a key is missing;
- its pages, `app/*.html`: a page declares English, every key it
  carries (`data-i18n`, `data-i18n-html`, `data-i18n-title`,
  `data-i18n-placeholder`, `data-i18n-aria-label`) has an English text, the
  text or the attribute written in the page is that English text, an element
  that carries `data-i18n` holds that text and nothing else (the translation
  replaces its content), and what carries no key does not read as French.

French that stays, because it is not a text of the interface:
- the French dictionaries (`*_i18n_fr`, `_registerTranslations("fr", …)`) and
  the reference data (frameworks, questionnaires, catalogs), published in the
  language of their source;
- the French of a declared pair: the value of a `fr:` key, or the branch
  chosen by `=== "fr" ?`;
- the values a model stores and reads back, the names an import looks for,
  the name a language gives itself (`_FRENCH_DATA`, `_FRENCH_BY_CONTEXT`).

Not covered:
- French written without an accent and without any of the words listed (a
  single unaccented word, a listed word written in lower case, a sentence made
  of words the list does not know), and a text built from pieces too short to
  be read;
- an English text that carries no key: it stays English in a French
  interface, and nothing here tells it from a name;
- a French value in an English dictionary, and a `fr:` text that has no
  `en:` beside it;
- a value of `_FRENCH_DATA` shown as a text: the list cannot tell
  `showStatus("En cours")` from the stored value it compares;
- a string the reading of the script loses: a template inside a template, a
  regular expression that holds a quote;
- a text given after a translation whose call holds a call of its own
  (`t("k", { n: f(x) }) || "text"`) or stands in parentheses;
- a copy of a shared script that differs from the first one read: each name
  is read once;
- the pages kept below `app/` in a directory of their own and their scripts,
  and the content a `data-i18n-html` key puts in its container.
"""
import html
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# What makes a string read as French: a letter English does not write, a word
# the interface used to show, or two of the small words no English sentence
# strings together.
_ACCENT = re.compile(r"[éèêëàâùûçôîïœÉÈÊËÀÂÙÛÇÔÎÏŒ]")
_WORD = re.compile(
    r"\b(Erreur|Supprimer|Aucune?|Annuler|Enregistrer|Ajouter|Modifier|Rechercher|"
    r"Fermer|Valider|Nouveau|Nouvelle|Statut|Fichier|Oui|Cette|Veuillez|Chargement|"
    r"Echec|Impossible de|Voulez|sans nom|Niveau|Rafra|Retour|Suivant|Mot de passe|"
    r"Utilisateurs?|Langue|Aide|Tous|Toutes|Projet|Importer|Exporter|Copier|"
    r"Confirmer|Ouvrir|Mesure corrective|Rapport|Informations|Retirer|Monter|Descendre|"
    r"EXTERNE|Lecteur)\b")
# Words that are also the names of fields and of keys: read in a sentence only.
_WORD_IN_A_SENTENCE = re.compile(
    r"\b(manquant|couverts?|connus|donnees|controles|profil|connecteur|detecte)\b")
_SMALL_WORD = re.compile(r"\b(les|des|une|est|pour|avec|sur|dans|par|aux|du|ou|et|de|la|le|un)\b")
_ELISION = re.compile(r"\b(?:[ldjnscm]|qu)\\?['’][a-zéèêàh]")

# French that is data. A value here is taken out of a string before the
# string is read, so a text that holds nothing else passes.
_FRENCH_DATA = sorted((
    # values the Risk and Compliance models store, and their older spellings
    "Terminé", "En cours", "À étudier", "A étudier", "À lancer", "A lancer",
    "Planifié", "Élevé", "Elevé", "Écosystème", "Complémentaire",
    "Prévention", "Détection", "Réaction", "Réduire", "Transférer", "Éviter",
    # sheets of the Risk workbook: the names an import looks for
    "Synthèse", "0-Échelle Gravité", "1a-Valeurs Métier", "3a-Événements Redoutés",
    "3b-Scénarios Stratégiques", "3c-Mesures Écosystème",
    "4a-Scénarios Opérationnels", "4b-Synthèse SOP", "5b-Risques Résiduels",
    # words an import recognises in French data
    "hébergeur", "éditeur",
    # the name a language gives itself, and the name of a publication
    "Français", "Português", "ANSSI — Guide d'hygiène",
    # the example given in the field that asks for a French label
    "Équipement réseau",
), key=len, reverse=True)

# French kept for where it stands: what precedes the string on its line.
_FRENCH_BY_CONTEXT = re.compile(
    # the French of a declared pair
    r"""(\bfr["']?\s*:\s*$|===?\s*["']fr["']\s*\?\s*$"""
    # the names a French spreadsheet gives its columns
    r"""|\bcol\([^)]*$"""
    # the frameworks, described in the language they are published in
    r"""|_REFERENTIELS_CATALOG\s*=)""")

# The sample of a bilingual import carries a row in both languages.
_BILINGUAL_SAMPLE = re.compile(r"^CUSTOM-\d+;")

# A dictionary: `Access_i18n_en.ts`, `i18n_core_fr.js`. `i18n.js` is code.
_DICTIONARY = re.compile(r"i18n_|_i18n\.")

_REFERENCE_DATA = re.compile(
    r"(_ref_|_reference_controls|_controls\.|_data\.|_descriptions|_questions|"
    r"_docreview|_mesures_types|referentiels_catalog|dora_codelists)")

_STRING = re.compile(
    r'''"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`''', re.S)
_FRENCH_DICTIONARY = re.compile(r"""_registerTranslations\(\s*["']fr["']\s*,\s*\{""")
_DEAD_FALLBACK = re.compile(
    r"""\b(?:t|tEsc)\(\s*["'`][\w.\-]+["'`][^()]*\)\s*(?:\|\||\?\?)\s*(["'`])(?!\1)""")

_TAG = re.compile(r"<[a-zA-Z][^<>]*>")
_CLOSING_TAG = re.compile(r"</[a-zA-Z][^<>]*>")
_KEYED_ATTRIBUTES = {
    "data-i18n-title": "title",
    "data-i18n-placeholder": "placeholder",
    "data-i18n-aria-label": "aria-label",
}
_PAIR_LINE = re.compile(r'^\s*"(?:[^"\\]|\\.)*"\s*:\s*"')
_PAIR = re.compile(r'("(?:[^"\\]|\\.)*")\s*:\s*("(?:[^"\\]|\\.)*")')
_KEY_LINE = re.compile(r'^\s*("(?:[^"\\]|\\.)*")\s*:')


def _looks_french(text: str) -> bool:
    for value in _FRENCH_DATA:
        text = text.replace(value, " ")
    if _ACCENT.search(text) or _WORD.search(text) or _ELISION.search(text):
        return True
    return " " in text.strip() and bool(
        _WORD_IN_A_SENTENCE.search(text) or len(_SMALL_WORD.findall(text)) >= 2)


def _blank(text: str) -> str:
    """The same text with nothing left to read, its line breaks kept."""
    return re.sub(r"[^\n]", " ", text)


def _without_comments(source: str) -> str:
    """The source with its comments blanked, every offset kept."""
    out, i, quote = [], 0, None
    while i < len(source):
        char = source[i]
        if quote:
            out.append(char)
            if char == "\\" and i + 1 < len(source):
                out.append(source[i + 1])
                i += 2
                continue
            if char == quote or (char == "\n" and quote != "`"):
                quote = None
            i += 1
        elif char in "\"'`":
            quote = char
            out.append(char)
            i += 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            end = len(source) if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i)
            end = len(source) if end < 0 else end + 2
            out.append(_blank(source[i:end]))
            i = end
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _without_french_dictionaries(source: str) -> str:
    """The source with every `_registerTranslations("fr", {…})` blanked."""
    while True:
        start = _FRENCH_DICTIONARY.search(source)
        if not start:
            return source
        depth, i, quote = 1, start.end(), None
        while i < len(source) and depth:
            char = source[i]
            if quote:
                if char == "\\":
                    i += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "\"'`":
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            i += 1
        source = source[:start.start()] + _blank(source[start.start():i]) + source[i:]


def _code(source: str) -> str:
    return _without_french_dictionaries(_without_comments(source))


def _french_strings(source: str):
    """Every string of a script that reads as French: (line, string)."""
    code = _code(source)
    for found in _STRING.finditer(code):
        text = next((group for group in found.groups() if group), "")
        if not _looks_french(text) or _BILINGUAL_SAMPLE.match(text):
            continue
        before = code[code.rfind("\n", 0, found.start()) + 1:found.start()]
        if not _FRENCH_BY_CONTEXT.search(before):
            yield code.count("\n", 0, found.start()) + 1, text


def _dead_fallbacks(source: str):
    """Every text given after a translation: (line, the code)."""
    code = _code(source)
    for found in _DEAD_FALLBACK.finditer(code):
        yield code.count("\n", 0, found.start()) + 1, found.group(0)


def _modules():
    return sorted(page.parent.parent for page in REPO_ROOT.glob("*/app/index.html"))


def _pages():
    for module in _modules():
        for page in sorted((module / "app").glob("*.html")):
            yield module, page


def _scripts():
    """The scripts a module is written in, then the shared ones, each once."""
    shared = {}
    for module in _modules():
        sources = set()
        for path in sorted((module / "app/ts").glob("*.ts")):
            sources.add(path.stem)
            if not path.name.endswith(".d.ts"):
                yield path
        for path in sorted((module / "app/js").glob("*.js")):
            if path.stem not in sources:
                shared.setdefault(path.name, path)
    yield from shared.values()


def _read(path: Path):
    """The scripts that hold texts of the interface, not a dictionary or data."""
    return not _DICTIONARY.search(path.name) and not _REFERENCE_DATA.search(path.name)


def _english(module: Path) -> dict:
    """key → English text, from every dictionary the module is served with."""
    texts = {}
    for path in sorted((module / "app/js").glob("*.js")):
        source = path.read_text(encoding="utf-8")
        for block in source.split("_registerTranslations(")[1:]:
            if not re.match(r"""\s*["']en["']""", block):
                continue
            end = block.find("\n});")
            for line in (block if end < 0 else block[:end]).splitlines():
                if _PAIR_LINE.match(line):
                    for key, text in _PAIR.findall(line):
                        texts.setdefault(json.loads(key), json.loads(text))
                elif _KEY_LINE.match(line):
                    # a text written in pieces, over several lines: known, not read
                    texts.setdefault(json.loads(_KEY_LINE.match(line).group(1)), "")
    return texts


def _attribute(tag: str, name: str):
    found = re.search(r"(?<![\w-])" + re.escape(name) + r"""=(?:"([^"]*)"|'([^']*)')""", tag)
    return html.unescape(found.group(1) or found.group(2) or "") if found else None


def _page_defects(page: str, english: dict):
    """Every static text of a page that is not the English it should be: (line, what)."""
    page = re.sub(r"<!--.*?-->", lambda comment: _blank(comment.group(0)), page, flags=re.S)
    opening = re.search(r"<html\b[^>]*>", page)
    if not opening or _attribute(opening.group(0), "lang") != "en":
        yield 1, 'the page does not declare `lang="en"`'
    for found in _TAG.finditer(page):
        tag = found.group(0)
        line = page.count("\n", 0, found.start()) + 1
        text = html.unescape(page[found.end():page.find("<", found.end())])
        key = _attribute(tag, "data-i18n")
        if key is None:
            if _looks_french(text):
                yield line, f"{text.strip()!r} carries no key"
        elif key not in english:
            yield line, f'`data-i18n="{key}"` has no English text'
        elif text.strip() != english[key].strip():
            yield line, f"{text.strip()!r} is not the English of `{key}`: {english[key]!r}"
        elif not page.startswith("</", page.find("<", found.end())):
            yield line, f'`data-i18n="{key}"` sits on an element that holds more than its text'
        key = _attribute(tag, "data-i18n-html")
        if key is not None and key not in english:
            yield line, f'`data-i18n-html="{key}"` has no English text'
        for keyed, name in _KEYED_ATTRIBUTES.items():
            key, value = _attribute(tag, keyed), _attribute(tag, name)
            if key is None:
                if value is not None and _looks_french(value):
                    yield line, f'`{name}="{value}"` carries no key'
            elif key not in english:
                yield line, f'`{keyed}="{key}"` has no English text'
            elif value != english[key]:
                yield line, f'`{name}="{value}"` is not the English of `{key}`: {english[key]!r}'
        for name in ("alt", "content", "value", "label"):
            value = _attribute(tag, name)
            if value is not None and _looks_french(value):
                yield line, f'`{name}="{value}"` reads as French'
    for found in _CLOSING_TAG.finditer(page):
        text = html.unescape(page[found.end():page.find("<", found.end())])
        if _looks_french(text):
            yield page.count("\n", 0, found.start()) + 1, f"{text.strip()!r} carries no key"


def _where(path: Path, line: int) -> str:
    return f"{path.relative_to(REPO_ROOT)}:{line}"


@pytest.mark.parametrize("code", [
    'showStatus("Enregistré");',
    "h += '<button class=\"ct-btn\">Supprimer</button>';",
    'var title = "Mesure corrective (" + ids.length + " findings)";',
    """h += '<a title="Ouvrir l\\'application">';""",
    'alert("La requete IA n\'a pas retourne de reponse.");',
    'var rows = ["Serveur de base de donnees;MySQL;Production"];',
    'var label = lang === "en" ? "Audit report" : "Rapport d\'audit";',
    'h += `<th>${esc(name)}</th><th>Échéance</th>`;',
    'showStatus("Type de connecteur manquant", true);',
    """h += '<button title="Monter">&#9650;</button>';""",
    'var rows = ["personnel;ada@example.com;Admin,Lecteur;Finance"];',
    'var answer = col("answer", ["réponse"]) || "Œuvre sans réponse";',
])
def test_a_french_string_is_seen(code):
    assert list(_french_strings(code)), code


@pytest.mark.parametrize("code", [
    'showStatus(t("misc.saved"));',
    'if (m.statut === "Terminé") done++;',
    'h += `${sel("measures", i, "statut", m.statut, ["Terminé", "En cours", "À étudier"], _statutLabel)}`;',
    'var ws = wb.getWorksheet("3a-Événements Redoutés");',
    'var titles = { fr: "1. Sensibiliser et former", en: "1. Raise awareness and train" };',
    'var description = lang === "fr" ? "Questionnaire de securite par defaut" : "Default security questionnaire";',
    'var answer = col("answer", ["réponse", "reponse"]);',
    "h += '<option value=\"fr\">Français</option>';",
    '_registerTranslations("fr", {\n    "misc.saved": "Enregistré",\n});',
    '// Enregistre le périmètre\nsave();',
    'var note = "The owner of the measure, and the date it is due on";',
])
def test_english_and_french_data_are_kept(code):
    assert not list(_french_strings(code)), code


@pytest.mark.parametrize("code", [
    'var label = t("misc.error") || "Error";',
    "h += esc(t('dora.entity.name') || 'Nom');",
    'var title = t("measure.count", { n: 3 }) || `${n} measures`;',
    'h += tEsc("misc.error") || "Error";',
    'var label = t("misc.error") ?? "Error";',
    'var label = t(`misc.error`) || "Error";',
])
def test_a_text_given_after_a_translation_is_seen(code):
    assert list(_dead_fallbacks(code)), code


@pytest.mark.parametrize("code", [
    'var label = t("misc.error") + ": " + message;',
    'var label = names[id] || t("misc.unknown");',
    'var label = t(key) || "";',
    'var help = t("kind.help." + kind) || "";',
    '// t("misc.error") || "Error"',
])
def test_a_translation_alone_is_not_a_fallback(code):
    assert not list(_dead_fallbacks(code)), code


_ENGLISH = {"btn.save": "Save", "chrome.lang": "Language", "search": "Search…", "help": "<p>Help</p>"}


@pytest.mark.parametrize("page", [
    '<html lang="fr"><body></body></html>',
    '<html lang="en"><button data-i18n="btn.save">Enregistrer</button></html>',
    '<html lang="en"><button data-i18n="btn.missing">Save</button></html>',
    '<html lang="en"><button aria-label="Langue" data-i18n-aria-label="chrome.lang"></button></html>',
    '<html lang="en"><button data-i18n-aria-label="chrome.lang"></button></html>',
    '<html lang="en"><input placeholder="Search…" data-i18n-placeholder="missing"></html>',
    '<html lang="en"><div data-i18n-html="missing"></div></html>',
    '<html lang="en"><span>Tableau de bord des risques</span></html>',
    '<html lang="en"><button title="Rafraîchir"></button></html>',
    '<html lang="en"><meta name="description" content="Outil d\'audit de conformité"></html>',
    '<html lang="en"><p><b>CISO Toolbox</b> Tableau de bord des risques</p></html>',
    """<html lang="en"><button title='Rafraîchir'></button></html>""",
    '<html lang="en"><option label="Tous les périmètres"></option></html>',
    '<html lang="en"><button data-i18n="btn.save">Save<span class="kbd">S</span></button></html>',
])
def test_a_page_that_is_not_english_is_seen(page):
    assert list(_page_defects(page, _ENGLISH)), page


@pytest.mark.parametrize("page", [
    '<html lang="en"><button data-i18n="btn.save">Save</button></html>',
    '<html lang="en"><button aria-label="Language" data-i18n-aria-label="chrome.lang"></button></html>',
    '<html lang="en"><input placeholder="Search…" data-i18n-placeholder="search"></html>',
    '<html lang="en"><div data-i18n-html="help"></div></html>',
    '<html lang="en"><!-- Enregistrer --><span>CISO Toolbox</span></html>',
    '<html lang="en"><p><b>CISO Toolbox</b> risk dashboard</p><option value="fr">FR</option></html>',
])
def test_an_english_page_passes(page):
    assert not list(_page_defects(page, _ENGLISH)), page


def test_the_sweep_reads_every_module():
    names = {path.name for path in _scripts()}
    assert len(_modules()) >= 10, "modules are missing: the sweep reads too little"
    assert len(list(_pages())) >= 2 * len(_modules()), "a module misses its page or its sign-in page"
    assert {"cisotoolbox.js", "ct_settings.js", "i18n.js"} <= names, "the shared scripts are not read"
    for module in _modules():
        assert len(_english(module)) > 100, f"{module.name}: the English dictionaries were not read"


def test_scripts_hold_no_french_text():
    found = [f"{_where(path, line)}  {text[:110]!r}"
             for path in _scripts() if _read(path)
             for line, text in _french_strings(path.read_text(encoding="utf-8"))]
    assert not found, "a text held in one language is not English:\n" + "\n".join(found)


def test_no_text_is_given_after_a_translation():
    found = [f"{_where(path, line)}  {code}"
             for path in _scripts() if _read(path)
             for line, code in _dead_fallbacks(path.read_text(encoding="utf-8"))]
    assert not found, "`t()` never returns an empty value, this text is never shown:\n" + "\n".join(found)


def test_pages_are_written_in_english():
    found = [f"{_where(page, line)}  {what}"
             for module, page in _pages()
             for line, what in _page_defects(page.read_text(encoding="utf-8"), _english(module))]
    assert not found, "the static text of a page is not English:\n" + "\n".join(found)
