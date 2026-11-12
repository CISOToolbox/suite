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
- an `error` value, the items of a list of `errors` or `warnings` — given as
  a keyword or under a key, assigned, appended, inserted or extended, the
  list being a variable, an attribute or an item — and the message of a
  `(result, message)` pair;
- a message built in a variable named after what it holds (`TEXT_VARS`), and
  a constant named `*_NAME`, `*_LABEL` or `*_TITLE`;
- a text handed over under one of `DISPLAY_KEYS`, as a key of a dict, as a
  keyword, as an attribute or an item being set (`report["error"] = …`): the
  labels and alerts of the dashboard contract, the title and description of a
  generated finding or measure, the lines of a validation report;
- a text stored to be read later (`STORED_KEYS`, a `*_justification`);
- what a function named `*_label` returns;
- an e-mail or a page: its subject, every text of a function named `*_html`,
  which builds its body, and a text written into a variable named `body` or
  `html` (`PAGE_VARS`; a `body` that is a dict is the payload of a request,
  not a page). A mail written in two languages keeps them in a dict the
  function reads, not in its own text.

A migration writes into the data too, and is read apart: a sentence it
holds, and a value of several words quoted in its SQL. The name of the project
every module is seeded with is one of them: the application creates it on a
new database, a migration on a database that predates it, and both write the
same.

A text built from several pieces — a concatenation, a choice between two
strings — is read piece by piece. A key (`row["plage"]`, `cfg.get("serveur")`)
is not a text.

A text that exists in two languages keeps both: the dict carries the other
one in a sibling key. `<key>_en` beside `<key>` declares `<key>` as the French
one (the connectors' field labels); `<key>_fr` holds the French beside an
English `<key>` (the dashboard contract).

Not covered: the digest of Watch, written in French until its language
becomes a setting (`FRENCH_MAILS`), the findings of the SMB share scanner,
written by its worker, the prompts given to a model, and a text that reaches
the screen by a path the sweep does not follow: a variable or a constant it
does not know by name, a chained or unpacked assignment (`a = b = …`,
`subject, body = …`), an item appended to a list other than `errors` or
`warnings`, a result of more than two elements, a single word a migration
writes, the text of a tag's attribute (`title=`, `alt=`), a piece of a page
built in a function of another name, a page built by a call
(`"…".format(…)`, `"".join(…)`). A French text without an accent and
without a word of `_FRENCH` goes unseen too, and so does the value beside an
`_en` sibling, declared French. Only the alerts are checked for their `_fr`
sibling.

The other way round, an English text may be taken for French: a word of
`_FRENCH` that is also English or an abbreviation ("pour", "EST"), a style
sheet inside a mail body. The sweep then fails on a text to reword, or on a
word to take out of the list.
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
TEXT_VARS = ("msg", "note", "summary", "motif", "_motif", "subject")

# Variables a page or a mail body is written into, when what they receive is
# a text: a `body` given a dict is the payload of a request.
PAGE_VARS = ("body", "html")

# Lists a failure is reported in, one sentence per item.
ERROR_LISTS = ("errors", "warnings")

# The mail bodies still written in French only: Watch's digest. Only these
# functions need naming: the rest of that digest — its subjects, the cards its
# body is made of — is French too, held in a variable or built in a function
# the sweep does not read. A text written into a `body` or an `html` of that
# digest is read like any other.
FRENCH_MAILS = {("watch", "_wrap_html"), ("watch", "render_vuln_digest_html"),
                ("watch", "render_threat_digest_html"), ("watch", "render_html")}

# A tag and its attributes are markup, not text: `font-family:…,sans-serif`.
_TAG = re.compile(r"<[a-zA-Z][^<>]*=[^<>]*>")

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
    r"enregistrements?|depuis|terminee?s?|hebdomadaires?|aujourd'hui|logiciels?|"
    r"fin de|jours?)\b",
    re.IGNORECASE,
)


def _french(text: str):
    """The first French word of a text, its markup aside."""
    return _FRENCH.search(_TAG.sub(" ", text))


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


def _docstring(node: ast.AST):
    """The statement that holds the docstring of a function, None without."""
    first = node.body[0]
    if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)):
        return first
    return None


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
        return target.id in TEXT_VARS or target.id.endswith(("_NAME", "_LABEL", "_TITLE"))
    if isinstance(target, ast.Subscript):
        key = _text(target.slice)
        return key is not None and (key in ("detail", "error", "Subject") or _is_text_field(key))
    return isinstance(target, ast.Attribute) and _is_text_field(target.attr)


_PROSE = (ast.Constant, ast.JoinedStr, ast.BinOp, ast.BoolOp, ast.IfExp)


def _is_written(target: ast.AST, value: ast.AST) -> bool:
    """An assignment that holds a text, a list of failures, or a page written
    as a text."""
    if isinstance(target, ast.Name) and target.id in PAGE_VARS:
        return isinstance(value, _PROSE)
    return _is_text_target(target) or _is_error_list(target)


def _is_error_list(node: ast.AST) -> bool:
    """`errors`, `self.errors`, `report["errors"]`: where failures are listed."""
    if isinstance(node, ast.Name):
        return node.id in ERROR_LISTS
    if isinstance(node, ast.Attribute):
        return node.attr in ERROR_LISTS
    return isinstance(node, ast.Subscript) and _text(node.slice) in ERROR_LISTS


def _messages(tree: ast.AST, module: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and (node.arg in ("detail", "subject", *ERROR_LISTS)
                                              or _is_text_field(node.arg or "")):
            yield from _strings(node.value)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("append", "extend", "insert")
              and _is_error_list(node.func.value)):
            for arg in node.args:
                yield from _strings(arg)
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            for arg in node.exc.args:
                yield from _strings(arg)
        elif isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            for key, value in zip(node.keys, node.values):
                if not isinstance(key, ast.Constant):
                    continue
                if key.value in ("detail", "error", *ERROR_LISTS):
                    yield from _strings(value)
                elif key.value in DISPLAY_KEYS and f"{key.value}_en" not in keys:
                    yield from _strings(value)
        elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name.endswith("_label")):
            for ret in ast.walk(node):
                if isinstance(ret, ast.Return) and ret.value is not None:
                    yield from _strings(ret.value)
        elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name.endswith("_html")
              and (module, node.name) not in FRENCH_MAILS):
            docstring = _docstring(node)
            for statement in node.body:
                if statement is not docstring:
                    yield from _strings(statement)
        elif _is_result(node):
            yield from _strings(node.value.elts[1])
        elif isinstance(node, ast.Assign) and _is_written(node.targets[0], node.value):
            yield from _strings(node.value)
        elif (isinstance(node, (ast.AugAssign, ast.AnnAssign)) and node.value is not None
              and _is_written(node.target, node.value)):
            yield from _strings(node.value)


# A statement of a migration is SQL: its quoted values are read, not its words.
_SQL = re.compile(r"\s*(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|SELECT|WITH)\b")
_SQL_VALUE = re.compile(r"'((?:[^']|'')*)'")


def _migration_texts(tree: ast.AST):
    """The texts a migration writes into the data, with their line: a sentence
    it holds, and a value of several words quoted in its SQL. A single word is
    an identifier or a status, in the vocabulary of the data model."""
    documented = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    docstrings = {id(_docstring(node).value) for node in ast.walk(tree)
                  if isinstance(node, documented) and node.body and _docstring(node)}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or id(node) in docstrings:
            continue
        values = _SQL_VALUE.findall(node.value) if _SQL.match(node.value) else [node.value]
        for value in values:
            if " " in value.strip():
                yield node.lineno, value


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
    assert _FRENCH.search("Projet principal")
    assert not _FRENCH.search("Main project")
    assert _FRENCH.search("aujourd'hui")
    assert _FRENCH.search("Licence logiciel")
    assert _FRENCH.search("Fin de vie")
    assert _FRENCH.search("12 jour(s)")
    assert _FRENCH.search("3 jours")
    assert not _FRENCH.search("Software license")
    assert not _FRENCH.search("End of life")
    # Markup is not text.
    assert not _french("<body style='font-family:Arial,sans-serif'><p>Deadlines to renew</p>")
    assert _french("<td style='padding:6px'>Preuve</td><td>sans date</td>")
    assert _french("<cible> requise")


def test_a_text_in_two_languages_keeps_both():
    """`label_en` declares `label` as the French one; `text_fr` is not read."""
    def french(source):
        return [_text(n) for n in _messages(ast.parse(source), "m")
                if _text(n) and _french(_text(n))]
    assert french('{"label": "Clé API"}') == ["Clé API"]
    assert french('{"label": "Clé API", "label_en": "API key"}') == []
    assert french('{"text": "3 overdue measure(s)", "text_fr": "3 mesure(s) en retard"}') == []
    assert french('Measure(title=f"Échéance : {nom}")') == ["Échéance : "]


def test_a_text_is_read_wherever_it_is_built():
    def french(source):
        return [_text(n) for n in _messages(ast.parse(source), "m")
                if _text(n) and _french(_text(n))]
    # Built from pieces.
    assert french('f.description = d + "[Reouvert : detecte a nouveau]"') == ["[Reouvert : detecte a nouveau]"]
    assert french('raise HTTPException(400, detail="Cible requise" if a else "Target required")') == ["Cible requise"]
    assert french('{"error": "Echec : " + reason}') == ["Echec : "]
    assert french('raise ValueError("Echec : " + reason)') == ["Echec : "]
    assert french('raise ValueError("Cible requise" if a else "Target required")') == ["Cible requise"]
    # Built in a variable, then extended.
    assert french('summary = f"{n} formation(s) terminée(s)"') == [" formation(s) terminée(s)"]
    assert french('summary += " (en retard)"') == [" (en retard)"]
    assert french('msg = "Cible requise"') == ["Cible requise"]
    assert french('note = "Fermé automatiquement"') == ["Fermé automatiquement"]
    assert french('motif = "aucune formation en cours"') == ["aucune formation en cours"]
    assert french('_motif = "aucune formation en cours"') == ["aucune formation en cours"]
    # Stored for later.
    assert french('row.awareness_justification = "Formation terminée"') == ["Formation terminée"]
    assert french('Asset(notes=f"Auto-decouvert lors du scan de {v}")') == ["Auto-decouvert lors du scan de "]
    assert french('f.triage_notes = "[Fermé automatiquement]"') == ["[Fermé automatiquement]"]
    # A result that is not True or False.
    assert french('def f():\n    return [], "aucune formation en cours"') == ["aucune formation en cours"]
    assert french('async def kind_label(k):\n    return "Échéance"') == ["Échéance"]
    # Set as an item.
    assert french('report["error"] = result.get("error") or "import incomplet"') == ["import incomplet"]
    assert french('row["notes"] = "Fermé automatiquement"') == ["Fermé automatiquement"]
    # Reported in a list of errors.
    assert french('SyncResult(assets=[], errors=["Identifiants AWS non configurés."])') == ["Identifiants AWS non configurés."]
    assert french('errors.append("Dernière connexion indisponible")') == ["Dernière connexion indisponible"]
    assert french('errors = ["Compte inconnu"]') == ["Compte inconnu"]
    assert french('warnings: list[str] = ["Compte inconnu"]') == ["Compte inconnu"]
    assert french('errors += ["Compte inconnu"]') == ["Compte inconnu"]
    assert french('errors.extend(["Compte inconnu"])') == ["Compte inconnu"]
    assert french('errors.insert(0, "Compte inconnu")') == ["Compte inconnu"]
    assert french('self.errors.append("Compte inconnu")') == ["Compte inconnu"]
    assert french('report["errors"].append("Compte inconnu")') == ["Compte inconnu"]
    assert french('{"ok": False, "errors": ["Compte inconnu"]}') == ["Compte inconnu"]
    assert french('{"errors": errors[:20]}') == []
    # An annotated constant.
    assert french('DEFAULT_PROJECT_NAME: str = "Projet principal"') == ["Projet principal"]
    # A constant named after the text it holds.
    assert french('DEFAULT_PROJECT_NAME = "Projet principal"') == ["Projet principal"]
    assert french('_KIND_LABEL = {"support": "Support matériel"}') == ["Support matériel"]
    assert french('MAIL_TITLE = "Preuves à renouveler"') == ["Preuves à renouveler"]
    # A key is not a text.
    assert french('raise ValueError(f"bad value {row[\'plage\']}")') == []
    assert french('raise ValueError("unknown host " + cfg.get("serveur", "?"))') == []


def test_an_email_is_read_subject_and_body():
    def french(source, module="m"):
        return [_text(n) for n in _messages(ast.parse(source), module)
                if _text(n) and _french(_text(n))]
    assert french('subject = f"[CISO Toolbox] {n} preuve(s) à renouveler"') == ["[CISO Toolbox]   preuve(s) à renouveler"]
    assert french('msg["Subject"] = "Surface — digest hebdomadaire"') == ["Surface — digest hebdomadaire"]
    assert french('send_mail(to, subject="Preuves à renouveler")') == ["Preuves à renouveler"]
    body = ('def build_digest_html(due):\n'
            '    """Corps du mail."""\n'
            '    rows = ""\n'
            '    for e in due:\n'
            '        rows += f"<td style=\'padding:6px\'>{e[\'label\']} expirée</td>"\n'
            '    return f"<div style=\'font-family:Arial,sans-serif\'><h2>Preuves à renouveler</h2>{rows}</div>"\n')
    assert french(body) == ["<td style='padding:6px'>  expirée</td>",
                            "<div style='font-family:Arial,sans-serif'><h2>Preuves à renouveler</h2> </div>"]
    # A page served in place of a mail body.
    assert french('body = "<p style=\'padding:24px\'>Aucun contenu archivé</p>"') == ["<p style='padding:24px'>Aucun contenu archivé</p>"]
    assert french('html = f"<h1>Synthèse</h1>{rows}"') == ["<h1>Synthèse</h1>"]
    assert french('html += "<p>Aucun résultat</p>"') == ["<p>Aucun résultat</p>"]
    assert french('body = "<p>" + "Aucun contenu archivé" + "</p>"') == ["Aucun contenu archivé"]
    assert french('body = row.body_html or "<p>Aucun contenu archivé</p>"') == ["<p>Aucun contenu archivé</p>"]
    assert french('body = "<p>Aucun contenu archivé</p>" if empty else row.body_html') == ["<p>Aucun contenu archivé</p>"]
    # The payload of a request is not a page.
    assert french('body = {"system": "Tu es un analyste sécurité"}') == []
    # The one mail declared French is not read; the same function elsewhere is.
    digest = 'def render_html(inner):\n    return f"<p>Périmètre</p>{inner}"\n'
    assert french(digest, "watch") == []
    assert french(digest, "surface") == ["<p>Périmètre</p>"]


def test_a_migration_is_read_sentence_and_sql_value():
    def texts(source):
        return [text for _, text in _migration_texts(ast.parse(source))]
    assert texts('"""Renomme les référentiels."""\ndef _libelle(fw):\n    return "Contrôles internes"\n') == ["Contrôles internes"]
    assert texts("""op.execute("INSERT INTO projects (id, name) VALUES (:c, 'Projet principal')")""") == ["Projet principal"]
    # A status and a column are words of the data model, not texts.
    assert texts("""op.execute("UPDATE si_users SET statut = 'actif' WHERE statut = 'employe'")""") == []
    assert texts('op.add_column("mesures", sa.Column("echeance", sa.String()))') == []


def test_migrations_write_english():
    french = []
    seen = 0
    for path in sorted(REPO_ROOT.glob("*/alembic/versions/*.py")):
        for lineno, text in _migration_texts(ast.parse(path.read_text(encoding="utf-8"))):
            seen += 1
            if _french(text):
                french.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {text!r}")
    assert seen > 50, "the sweep found almost no text: it reads the wrong tree"
    if french:
        pytest.fail(f"{len(french)} texts of a migration not written in English:\n" + "\n".join(french))


def test_the_default_project_has_one_english_name():
    """The application creates the project on a new database, a migration
    seeds it on a database that predates it: both write the same name."""
    seed = re.compile(r"INSERT INTO projects \(id, name\) VALUES \(:c, '([^']*)'\)")
    names = {}
    for path in sorted(REPO_ROOT.glob("*/src/default_project.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "DEFAULT_PROJECT_NAME"):
                names[path.parent.parent] = _text(node.value)
    assert len(names) >= 4, "the sweep found almost no default project: it reads the wrong tree"
    for module, name in names.items():
        assert name and not _french(name), f"{module.name}: the default project is named {name!r}"
        seeded = {found for path in sorted((module / "alembic" / "versions").glob("*.py"))
                  for found in seed.findall(path.read_text(encoding="utf-8"))}
        assert seeded == {name}, f"{module.name}: the migrations seed {sorted(seeded)}, the application {name!r}"


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
        # A text may be reached by two rules: it is counted once.
        for node in {id(n): n for n in _messages(tree, module)}.values():
            text = _text(node)
            if text is None:
                continue
            seen += 1
            if _french(text):
                french.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {text!r}")
    assert seen > 1000, "the sweep found almost no message: it reads the wrong tree"
    if french:
        pytest.fail(f"{len(french)} messages not written in English:\n" + "\n".join(french))
