"""What the backend writes for a screen is written in English.

English is the product default and the backend has no translation layer: an
error detail, a refused target, a dashboard alert or the title of a generated
measure written in another language reaches every user as is, whatever the
language of their interface.

The sweep reads the source of every module, so a new text is covered the day
it is written:
- the `detail` of an HTTP error, as a keyword or as a key of a JSON body;
- the message of a raised exception (the validators' messages end up in a
  `detail`);
- an `error` value, and the message of a `(result, message)` pair;
- a message built in a variable named after what it holds (`TEXT_VARS`);
- a text handed over under one of `DISPLAY_KEYS`, as a key of a dict, as a
  keyword, as an attribute or an item being set (`report["error"] = …`): the
  labels and alerts of the dashboard contract, the title and description of a
  generated finding or measure, the lines of a validation report;
- a text stored to be read later (`STORED_KEYS`, a `*_justification`);
- what a function named `*_label` returns.

A text built from several pieces — a concatenation, a choice between two
strings — is read piece by piece. A key (`row["plage"]`, `cfg.get("serveur")`)
is not a text.

A text that exists in two languages keeps both: the dict carries the other
one in a sibling key. `<key>_en` beside `<key>` declares `<key>` as the French
one (the connectors' field labels); `<key>_fr` holds the French beside an
English `<key>` (the dashboard contract).

Not covered: the e-mails, which choose their language themselves, the
findings of the SMB share scanner, written by its worker, and a text that
reaches the screen by a path the sweep does not follow: a variable or a
constant it does not know by name, an annotated or chained assignment, an
item appended to a list, a result of more than two elements. A French text
without an accent and without a word of `_FRENCH` goes unseen too, and so
does the value beside an `_en` sibling, declared French. Only the alerts are
checked for their `_fr` sibling.
"""
import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Keys and keywords under which a text is handed over to be displayed.
DISPLAY_KEYS = ("label", "text", "message", "title", "description", "details",
                "entity_label", "center_sublabel", "name", "placeholder")

# Fields a text is stored in, to be read on a screen later.
STORED_KEYS = ("notes", "triage_notes")

# Variables a text is built in before it is handed over or stored.
TEXT_VARS = ("msg", "note", "summary", "motif", "_motif")

# The day counts of the two digest e-mails that have no language of their own.
MAIL_LABELS = {("asset", "_days_label"), ("compliance", "_days_label")}

# An accented letter, a French quotation mark, or a word no English text
# contains.
_FRENCH = re.compile(
    r"[àâçéèêëîïôùûœ«»]|\b(le|les|une|du|pour|est|pas|dans|sur|avec|ou(?!=)|et|sont|"
    r"cle|cible|aucune?|invalides?|requise?s?|bloquee?|erreur|echec|trouve|"
    r"obligatoire|vide|manquants?|plage|partage|inconnu|adresse|destinataire|"
    r"trop|deja|interdite?s?|injoignable|introuvables?|impossible de|serveur|"
    r"fournisseurs?|modele|verifiez|reessaye[rz]|nouveau|nouvelle|actifs?|"
    r"faible|bon|moyen|conforme|revue|en cours|en retard|sans|risques?|"
    r"projets?|ouverte?s?|echeance|preuves?|utilisateurs?|decouverte?s?|apres|lors|detectee?s?|copie|autres?|incomplets?|"
    r"enregistrements?|depuis|terminee?s?)\b",
    re.IGNORECASE,
)


def _text(node: ast.AST) -> str | None:
    """The literal part of a string or f-string, None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return " ".join(v.value for v in node.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _strings(node: ast.AST):
    """Every string an expression is built from, an f-string counted once."""
    if _text(node) is not None:
        yield node
    if isinstance(node, ast.JoinedStr):
        children = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
    elif isinstance(node, ast.Subscript):
        children = [node.value]
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
          and node.func.attr == "get"):
        children = [node.func.value, *node.args[1:]]
    else:
        children = ast.iter_child_nodes(node)
    for child in children:
        yield from _strings(child)


def _is_result(node: ast.AST) -> bool:
    """`return result, message`: `True, "…"`, `[], "…"`."""
    value = getattr(node, "value", None)
    return (isinstance(node, ast.Return) and isinstance(value, ast.Tuple)
            and len(value.elts) == 2)


def _is_text_field(name: str) -> bool:
    return (name in DISPLAY_KEYS or name in STORED_KEYS
            or name.endswith("_justification"))


def _is_text_target(target: ast.AST) -> bool:
    """`msg = …`, `finding.description = …`, `report["error"] = …`: where a
    text is built or stored."""
    if isinstance(target, ast.Name):
        return target.id in TEXT_VARS
    if isinstance(target, ast.Subscript):
        key = _text(target.slice)
        return key is not None and (key in ("detail", "error") or _is_text_field(key))
    return isinstance(target, ast.Attribute) and _is_text_field(target.attr)


def _messages(tree: ast.AST, module: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and (node.arg == "detail" or _is_text_field(node.arg or "")):
            yield from _strings(node.value)
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            for arg in node.exc.args:
                yield from _strings(arg)
        elif isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            for key, value in zip(node.keys, node.values):
                if not isinstance(key, ast.Constant):
                    continue
                if key.value in ("detail", "error"):
                    yield from _strings(value)
                elif key.value in DISPLAY_KEYS and f"{key.value}_en" not in keys:
                    yield from _strings(value)
        elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name.endswith("_label")
              and (module, node.name) not in MAIL_LABELS):
            for ret in ast.walk(node):
                if isinstance(ret, ast.Return) and ret.value is not None:
                    yield from _strings(ret.value)
        elif _is_result(node):
            yield from _strings(node.value.elts[1])
        elif isinstance(node, ast.Assign) and _is_text_target(node.targets[0]):
            yield from _strings(node.value)
        elif isinstance(node, ast.AugAssign) and _is_text_target(node.target):
            yield from _strings(node.value)


def _sources():
    for src in sorted(REPO_ROOT.glob("*/src")):
        module = src.parent
        for top in (src, module / "addons"):
            for path in sorted(top.rglob("*.py")):
                if path.name.startswith("test_") or "tests" in path.parts:
                    continue
                yield module.name, path


def test_the_sweep_recognises_french():
    assert _FRENCH.search("Cible requise")
    assert _FRENCH.search("un import est déjà en cours")
    assert _FRENCH.search("Habilitation introuvable")
    assert not _FRENCH.search("Non-conformity not found")
    assert not _FRENCH.search("No finding found for the given ids")
    assert _FRENCH.search("3 mesure(s) en retard")
    assert _FRENCH.search("Port 443/tcp ouvert sur h.medsecure.example")
    assert not _FRENCH.search("3 overdue measure(s)")
    assert not _FRENCH.search("EBIOS RM analyses")
    assert not _FRENCH.search("CN=svc,OU=Service Accounts,DC=example,DC=com")
    assert _FRENCH.search("Decouvert via medsecure.example")
    assert _FRENCH.search("Scan timeout apres 600s")
    assert not _FRENCH.search("Scan timed out after 600s")
    assert _FRENCH.search("Audit interne (copie)")
    assert _FRENCH.search("import incomplet")
    assert not _FRENCH.search("incomplete import: 3 file(s) copied to another host")


def test_a_text_in_two_languages_keeps_both():
    """`label_en` declares `label` as the French one; `text_fr` is not read."""
    def french(source):
        return [_text(n) for n in _messages(ast.parse(source), "m")
                if _text(n) and _FRENCH.search(_text(n))]
    assert french('{"label": "Clé API"}') == ["Clé API"]
    assert french('{"label": "Clé API", "label_en": "API key"}') == []
    assert french('{"text": "3 overdue measure(s)", "text_fr": "3 mesure(s) en retard"}') == []
    assert french('Measure(title=f"Échéance : {nom}")') == ["Échéance : "]


def test_a_text_is_read_wherever_it_is_built():
    def french(source):
        return [_text(n) for n in _messages(ast.parse(source), "m")
                if _text(n) and _FRENCH.search(_text(n))]
    # Built from pieces.
    assert french('f.description = d + "[Reouvert : detecte a nouveau]"') == ["[Reouvert : detecte a nouveau]"]
    assert french('raise HTTPException(400, detail="Cible requise" if a else "Target required")') == ["Cible requise"]
    assert french('{"error": "Echec : " + reason}') == ["Echec : "]
    assert french('raise ValueError("Echec : " + reason)') == ["Echec : "]
    assert french('raise ValueError("Cible requise" if a else "Target required")') == ["Cible requise"]
    # Built in a variable, then extended.
    assert french('summary = f"{n} formation(s) terminée(s)"') == [" formation(s) terminée(s)"]
    assert french('summary += " (en retard)"') == [" (en retard)"]
    # Stored for later.
    assert french('Asset(notes=f"Auto-decouvert lors du scan de {v}")') == ["Auto-decouvert lors du scan de "]
    assert french('f.triage_notes = "[Fermé automatiquement]"') == ["[Fermé automatiquement]"]
    # A result that is not True or False.
    assert french('def f():\n    return [], "aucune formation en cours"') == ["aucune formation en cours"]
    assert french('async def kind_label(k):\n    return "Échéance"') == ["Échéance"]
    # Set as an item.
    assert french('report["error"] = result.get("error") or "import incomplet"') == ["import incomplet"]
    assert french('row["notes"] = "Fermé automatiquement"') == ["Fermé automatiquement"]
    # A key is not a text.
    assert french('raise ValueError(f"bad value {row[\'plage\']}")') == []
    assert french('raise ValueError("unknown host " + cfg.get("serveur", "?"))') == []


def test_dashboard_alerts_carry_both_languages():
    """An alert a module hands to the dashboard is shown in the language of
    the interface: its English `text` goes with a `text_fr`."""
    missing = []
    seen = 0
    for path in sorted(REPO_ROOT.glob("*/src/routes/internal.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if {"level", "text"} <= keys:
                seen += 1
                if "text_fr" not in keys:
                    missing.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert seen > 20, "the sweep found almost no alert: it reads the wrong tree"
    assert not missing, "alerts without a French text:\n" + "\n".join(missing)


def test_api_messages_are_english():
    french = []
    seen = 0
    for module, path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _messages(tree, module):
            text = _text(node)
            if text is None:
                continue
            seen += 1
            if _FRENCH.search(text):
                french.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {text!r}")
    assert seen > 1000, "the sweep found almost no message: it reads the wrong tree"
    if french:
        pytest.fail(f"{len(french)} messages not written in English:\n" + "\n".join(french))
