"""English is the language nobody chose.

Where a language can be chosen — the language of a notification, of a mail,
of what a model answers — the one used when none was given is English, in the
backend and in the frontend alike. Where a text exists in two languages, the
French one is named as such and the English one is what any other value gets.

The sweep reads the source of every module:
- a language given as the default of a parameter, of a request field
  (`lang: str = "fr"`, `Field("fr")`, `default=lambda: "fr"`) or of a
  column, as the value kept when a setting is empty (`x or "fr"`,
  `prefs.get("lang", "fr")`, `getattr(prefs, "lang", "fr")`,
  `os.getenv("…", "fr")`), as the other branch of a choice (`… else "fr"`),
  under a `lang` key, or in a constant named after a language or a locale
  (`MAIL_LANG`, `_DIGEST_LANGUAGE`, `DEFAULT_LOCALE`);
- the texts picked the same way: `_L.get(lang) or _L["fr"]`,
  `… else PROMPT_FR`;
- in the frontend, `|| "fr"`, `?? "fr"`, `: "fr"`, `|| T.fr`, and a
  language set to French (`lang = "fr"`, as a statement or as the default of
  a parameter).

French is `fr`, any of its regional spellings (`FR`, `fr-FR`, `fr_FR`) and
its name (`French`, `Français`).

A language that is read is read whatever its spelling: the backend neither
compares it to `"fr"` exactly (`language == "fr"`, `"fr" == language`) nor
tests its prefix without removing the surrounding spaces and the case first
(`.strip()` and `.lower()` on the same line).
A value checked against a closed list (`lang in ("fr", "en")`) is a stored
choice, not a reading, and stays.

A prompt given to a model is written in English and names the language of
the answer. A French prompt is kept only beside its English one, in a constant
named `*_FR`, under a `"fr"` key, or in a `*_fr.md` file that has its
`*_en.md`. The sweep knows a French prompt by the way it addresses the model
(`_PROMPT_FRENCH`): French words that are data — the values of an enum, the
keys of the JSON asked for — are not prose and stay. The frontend holds its
French dictionaries and reference texts in the same files as its code, so it
is read for the second person only (`_ADDRESSES_A_MODEL`).

Not covered: a French prompt that addresses the model in none of the ways
listed, a language chosen by a comparison the sweep does not read
(`if is_en: … else: …` sends any other language to the second branch), a
language passed by position to a function (`render(body, "fr")`), and the
migrations, which keep the default they created a column with: a later
migration changes it. A narrow reading is seen in the two forms above only.
Not seen: a lookup in a table (`NAMES.get(lang.lower())`), a membership (`lang
in ("fr",)`, `"fr" in lang`), a regular expression, a `match`, a `find`, a
prefix given as a tuple or longer than the language (`startswith(("fr",
"FR"))`, `startswith("fr-")`), a comparison to another spelling, to the name
of the language or to a constant (`.upper() == "FR"`, `== "French"`, `== FR`),
`is "fr"`, a prefix given a start position or read by `str.startswith`
(`startswith("fr", 0)`, `str.startswith(lang, "fr")`), the English branch
tested in place of the French one by an `if` statement (`if lang == "en": …
else: …`) or by a conditional expression whose other branch names French
otherwise than by a literal, a `["fr"]` subscript, a bare name ending in `_FR`
or a call whose only argument is `"fr"` (`m.PROMPT_FR`, `prompt_fr()`,
`build("fr", x)`), a comparison whose `"fr"` is not on the line of its
operator, a `.startswith("fr")` split over two lines, a `.strip()` or a
`.lower()` that belongs to something else on the line, and a language that may
be absent read without a fallback (`language.strip()` on `None`).
What a prompt says for each spelling, and that each route hands the language
of its request to its prompt, is read by the unit tests of the modules
(`test_prompt_language.py`, `test_analysis_language.py`).
"""
import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# What stands for French where a language is expected.
_FRENCH_VALUE = re.compile(r"'?(fr([-_][a-z]{2})?|french|fran[çc]ais)'?", re.IGNORECASE)

# The ways a French prompt addresses a model, with or without accents.
_PROMPT_FRENCH = re.compile(
    r"\b(tu es|tu dois|tu r[ée]diges|on te donne|r[ée]ponds|r[ée]dige|g[ée]n[èe]re|"
    r"produis|propose (?:une?|des|les?|la)\b|trouve les|s[ée]lectionne les|"
    r"ne retourne|ne dis pas|ne fabrique|ne propose|ne groupe|"
    r"base-toi|ta t[âa]che|r[èe]gles? (?:strictes?|absolue)|"
    r"contexte m[ée]thodologique|fournisseur ?:|d[ée]j[àa] associ[ée]s)",
    re.IGNORECASE,
)

# The second person, which no dictionary entry or reference text uses.
_ADDRESSES_A_MODEL = re.compile(
    r"\b(tu es|tu dois|on te donne|base-toi|ta t[âa]che)\b", re.IGNORECASE)


def _is_french_value(node: ast.AST) -> bool:
    return (isinstance(node, ast.Constant) and isinstance(node.value, str)
            and bool(_FRENCH_VALUE.fullmatch(node.value.strip())))


def _is_french_pick(node: ast.AST) -> bool:
    """`"fr"`, `_L["fr"]`, `PROMPT_FR`, `text("'fr'")`, `lambda: "fr"`: French, or the French text."""
    if _is_french_value(node):
        return True
    if isinstance(node, ast.Lambda):
        return _is_french_pick(node.body)
    if isinstance(node, ast.Subscript):
        return _is_french_value(node.slice)
    if isinstance(node, ast.Name):
        return node.id.upper().endswith("_FR")
    if isinstance(node, ast.Call) and len(node.args) == 1:
        return _is_french_value(node.args[0])
    return False


def _names_a_language(name: str) -> bool:
    return bool(re.search(r"(lang(uage)?|locale)(_|$)", name.lower()))


def _target_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _french_defaults(tree: ast.AST):
    """Every place where French is what is used when nothing was chosen."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for default in node.args.defaults + [d for d in node.args.kw_defaults if d]:
                if _is_french_pick(default):
                    yield default.lineno, "the default of a parameter"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if (node.value is not None and _names_a_language(_target_name(target))
                    and _is_french_pick(node.value)):
                yield node.lineno, "the value of a language constant or field"
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            if _is_french_pick(node.values[-1]):
                yield node.lineno, "the value kept when the first is empty"
        elif isinstance(node, ast.IfExp):
            if _is_french_pick(node.orelse):
                yield node.lineno, "the other branch of a choice"
        elif isinstance(node, ast.Call):
            callee = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if callee in ("get", "getenv", "getattr", "next", "pop", "setdefault"):
                for arg in node.args[1:]:
                    if _is_french_pick(arg):
                        yield arg.lineno, "the value used when a setting is missing"
            for kw in node.keywords:
                if (kw.arg in ("default", "default_factory", "server_default")
                        or (kw.arg and _names_a_language(kw.arg))):
                    if _is_french_pick(kw.value):
                        yield kw.value.lineno, f"`{kw.arg}=`"
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and _names_a_language(key.value) and _is_french_value(value)):
                    yield value.lineno, f'the value of "{key.value}"'


def _declared_french(node: ast.AST, parents: dict) -> bool:
    """Whether a text sits where the French of a pair is kept."""
    child = node
    while child in parents:
        parent = parents[child]
        if isinstance(parent, ast.Dict):
            for key, value in zip(parent.keys, parent.values):
                if value is child and isinstance(key, ast.Constant) and key.value == "fr":
                    return True
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            target = parent.targets[0] if isinstance(parent, ast.Assign) else parent.target
            if _target_name(target).upper().endswith("_FR"):
                return True
        child = parent
    return False


def _french_prompts(tree: ast.AST):
    """Every text that addresses a model in French, a declared French one aside."""
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        found = _PROMPT_FRENCH.search(node.value)
        if found and not _declared_french(node, parents):
            yield node.lineno, found.group(0)


def _sources():
    for src in sorted(REPO_ROOT.glob("*/src")):
        module = src.parent
        for top in (src, module / "addons"):
            for path in sorted(top.rglob("*.py")):
                if path.name.startswith("test_") or "tests" in path.parts:
                    continue
                yield module.name, path


def _frontend_sources():
    """The TypeScript a module is written in, its dictionaries aside."""
    for path in sorted(REPO_ROOT.glob("*/app/ts/*.ts")):
        if "i18n" not in path.name:
            yield path


def _where(path: Path, line: int) -> str:
    return f"{path.relative_to(REPO_ROOT)}:{line}"


# French where the frontend had no language: kept when the first value is
# empty, or set on a language (`lang = "fr"`, the default of a parameter too).
# French after English (`label.en || label.fr`) is the last resort of a text
# that has no English, not a default.
_FRONTEND_FRENCH_DEFAULT = re.compile(
    r"""(\|\||\?\?|:)\s*["']fr(?:[-_]FR)?["']"""
    r"""|(?<!\.en )(\|\||\?\?)\s*\w+\.fr\b"""
    r"""|\b\w*(?:lang|locale)\w*\s*(?::\s*string\s*)?(?<![=!<>])=\s*["']fr(?:[-_]FR)?["']""",
    re.IGNORECASE)


@pytest.mark.parametrize("code", [
    'var lang = window._locale || "fr";',
    'var lang = prefs.lang ?? "fr";',
    'var lang = known ? prefs.lang : "fr";',
    'var date = d.toLocaleDateString(_locale || "fr-FR");',
    'var texts = T[lang] || T.fr;',
    'function render(lang = "fr") {}',
    'function render(lang: string = "fr") {}',
    'if (!lang) lang = "fr";',
    'let _locale = "fr";',
])
def test_a_french_default_of_the_frontend_is_seen(code):
    assert _FRONTEND_FRENCH_DEFAULT.search(code), code


@pytest.mark.parametrize("code", [
    'var lang = _locale === "fr" ? "fr" : "en";',
    'if (_locale === "fr") title = french;',
    'var date = d.toLocaleDateString(_locale === "fr" ? "fr-FR" : "en-GB");',
    'var names = { en: "English", fr: "Français" };',
    'var lang = window._locale || "en";',
    'return label[lang] || label.en || label.fr || "";',
])
def test_naming_french_in_the_frontend_is_not_defaulting_to_it(code):
    assert not _FRONTEND_FRENCH_DEFAULT.search(code), code


@pytest.mark.parametrize("code", [
    'def render(lang="fr"): ...',
    'def render(*, language: str = "fr"): ...',
    'class Prefs(BaseModel):\n    lang: str = "fr"',
    'MAIL_LANG = os.getenv("ACCESS_MAIL_LANG", "fr")',
    '_DIGEST_LANGUAGE = "fr"',
    'lang = Column(String(5), default="fr")',
    'lang = Column(String(5), server_default=text("\'fr\'"))',
    'lang = body.get("lang", "fr")',
    'lang = language or "fr"',
    'L = _L.get(lang) or _L["fr"]',
    'lang = prefs.lang if prefs.lang in ("fr", "en") else "fr"',
    'name = "English" if language == "en" else "French"',
    'name = _LANG_NAMES.get(lang, "French")',
    'prompt = PROMPT_EN if lang == "en" else PROMPT_FR',
    'answer = {"enabled": False, "lang": "fr"}',
    'html = render(items, language="fr")',
    'class Prefs(BaseModel):\n    lang: str = Field("fr", max_length=5)',
    'class Prefs(BaseModel):\n    lang: str = Field(default_factory=lambda: "fr")',
    'lang = Column(String(5), default=lambda: "fr")',
    'lang = getattr(prefs, "lang", "fr")',
    'lang = next((l for l in langs if l in known), "fr")',
    'DEFAULT_LOCALE = "fr"',
    'MAIL_LANG = os.getenv("ACCESS_MAIL_LANG", "FR")',
    'lang = language or "fr-FR"',
    'locale = prefs.locale or "fr_FR"',
    'name = _LANG_NAMES.get(lang, "Français")',
])
def test_a_french_default_is_seen(code):
    assert list(_french_defaults(ast.parse(code))), code


@pytest.mark.parametrize("code", [
    'def render(lang="en"): ...',
    'lang = "fr" if lang.startswith("fr") else "en"',
    'name = "French" if language == "fr" else "English"',
    'L = _L.get(lang) or _L["en"]',
    'if lang not in ("fr", "en"): raise ValueError("lang must be fr|en")',
    '_L = {"fr": {"hello": "Bonjour"}, "en": {"hello": "Hello"}}',
    'tlds = ["com", "fr", "io"]',
    'prompt = PROMPT_FR if lang == "fr" else PROMPT_EN',
    'origin = body.get("from", "front")',
    'lang = "fr" if (os.getenv("WATCH_DIGEST_LANG") or "").lower().startswith("fr") else "en"',
])
def test_naming_french_is_not_defaulting_to_it(code):
    assert not list(_french_defaults(ast.parse(code))), code


@pytest.mark.parametrize("code", [
    'SYSTEM = "Tu es un expert en gestion d\'actifs. Reponds en francais."',
    'prompt = f"Redige une description concise pour {name}"',
    'prompt = "Génère un rapport d\'audit à partir de ces données :"',
    'system = "Propose une matrice RACI au format JSON strict"',
    'user = "Fournisseur: " + name',
    'RULE = "Ne dis pas \\"je vais chercher\\"."',
])
def test_a_french_prompt_is_seen(code):
    assert list(_french_prompts(ast.parse(code))), code


@pytest.mark.parametrize("code", [
    '_SYSTEM = {"fr": "Tu es un auditeur principal.", "en": "You are a lead auditor."}',
    '_SYSTEM_PROMPT_FR = "Tu es analyste. " "Réponds en JSON."',
    'schema = \'{"mesure":"…","type":"Prévention|Détection|Réaction"}\'',
    'system = "You are an expert. Propose measures. Respond in French."',
])
def test_a_declared_french_prompt_and_french_data_are_kept(code):
    assert not list(_french_prompts(ast.parse(code))), code


# `fr-FR` is what a browser sends, ` fr ` what a setting file may hold: both
# are French. Read on the line, comments aside.
_EXACT_FRENCH = re.compile(r"""(?:==|!=)\s*["']fr["']|["']fr["']\s*(?:==|!=)""")
_PREFIX_FRENCH = re.compile(r"""\.startswith\(\s*["']fr["']\s*\)""")


def _narrow_readings(text: str):
    for number, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        tolerant = ".strip()" in code and ".lower()" in code
        if _EXACT_FRENCH.search(code) or (_PREFIX_FRENCH.search(code) and not tolerant):
            yield number, line.strip()


@pytest.mark.parametrize("code", [
    'lang = "French" if language == "fr" else "English"',
    'if language != "fr":',
    "if language == 'fr':",
    'return "French" if (language or "").lower().startswith("fr") else "English"',
    'lang = "fr" if lang.startswith("fr") else "en"',
    'lang = "fr" if lang.strip().startswith("fr") else "en"',
    'if "fr" == language:',
])
def test_a_narrow_reading_of_the_language_is_seen(code):
    assert list(_narrow_readings(code)), code


@pytest.mark.parametrize("code", [
    'return "French" if (language or "").strip().lower().startswith("fr") else "English"',
    'if lang not in ("fr", "en"):',
    'texts = {"fr": FRENCH, "en": ENGLISH}',
    'x = 1  # language == "fr" was read exactly',
])
def test_a_tolerant_reading_or_a_closed_list_is_kept(code):
    assert not list(_narrow_readings(code)), code


def test_a_language_is_read_whatever_its_spelling():
    found = [f"{_where(path, line)}  {what[:120]}"
             for _module, path in _sources()
             for line, what in _narrow_readings(path.read_text(encoding="utf-8"))]
    assert not found, "a language read in one spelling only:\n" + "\n".join(found)


def test_no_language_defaults_to_french():
    found = [f"{_where(path, line)}  {what}"
             for _module, path in _sources()
             for line, what in _french_defaults(ast.parse(path.read_text(encoding="utf-8")))]
    assert not found, "French used where no language was chosen:\n" + "\n".join(found)


def test_the_frontend_does_not_default_to_french():
    found = [f"{_where(path, number)}  {line.strip()[:120]}"
             for path in _frontend_sources()
             for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
             if _FRONTEND_FRENCH_DEFAULT.search(line) and not line.lstrip().startswith("//")]
    assert not found, "French used where no language was chosen:\n" + "\n".join(found)


def test_prompts_are_written_in_english():
    found = [f"{_where(path, line)}  {text!r}"
             for _module, path in _sources()
             for line, text in _french_prompts(ast.parse(path.read_text(encoding="utf-8")))]
    for path in _frontend_sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = _ADDRESSES_A_MODEL.search(line)
            if match and not line.lstrip().startswith("//"):
                found.append(f"{_where(path, number)}  {match.group(0)!r}")
    assert not found, "a prompt addresses the model in French:\n" + "\n".join(found)


def test_a_prompt_file_has_its_english():
    prompts = sorted(REPO_ROOT.glob("*/src/prompts/*.md"))
    assert prompts, "no prompt file found: the sweep reads nothing"
    for path in prompts:
        if path.stem.endswith("_fr"):
            english = path.with_name(path.stem[:-3] + "_en.md")
            assert english.exists(), f"{path.relative_to(REPO_ROOT)} has no English counterpart"
        else:
            assert path.stem.endswith("_en"), f"{path.relative_to(REPO_ROOT)} names no language"
            match = _PROMPT_FRENCH.search(path.read_text(encoding="utf-8"))
            assert not match, f"{path.relative_to(REPO_ROOT)}: {match.group(0)!r}"
