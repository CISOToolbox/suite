"""« Abandonné » (cancelled) — le statut que le backend refusait.

Le kanban proposait la colonne, le Literal du backend ne la connaissait pas :
tout drop répondait 422 + rollback. Et une mesure abandonnée comptait dans le
% de complétion des projets (dénominateur) et dans les échéances à venir.

Vérifications par le code source (AST/texte) + calcul pur, sans base.
"""
import ast
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

ROUTES = os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes")


def _source(name: str) -> str:
    with open(os.path.join(ROUTES, name), encoding="utf-8") as f:
        return f.read()


def test_the_backend_accepts_every_status_the_kanban_offers():
    # La consigne écrite dans Pilot_app.ts : garder _MEASURE_STATUSES en phase
    # avec le Literal de MeasureUpdate. Le commit 39bf28f l'avait violée dans
    # la ligne même qui la portait.
    tree = ast.parse(_source("measures.py"))
    literals: list[set] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and getattr(node.value, "id", "") == "Literal":
            elts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            vals = {e.value for e in elts if isinstance(e, ast.Constant)}
            if "planned" in vals:
                literals.append(vals)
    assert literals, "no measure-status Literal found in measures.py"
    for vals in literals:
        assert "cancelled" in vals, f"Literal {vals} misses 'cancelled' — the kanban offers it"


def test_project_completion_ignores_cancelled_measures():
    from src.routes.projects import _project_to_dict
    p = SimpleNamespace(id="00000000-0000-0000-0000-000000000001", name="P",
                        description="", status="active", owner_id=None,
                        priority="normal", responsible="", start_date=None,
                        end_date=None, due_date=None, completed_date=None,
                        tags=None, created_at=None, updated_at=None)
    measures = [{"status": "completed"}, {"status": "planned"},
                {"status": "cancelled"}, {"status": "annule"}]
    d = _project_to_dict(p, measures)
    # 1 faite sur 2 actives — les 2 abandonnées ne plombent pas le %.
    assert d["measures_total"] == 2
    assert d["measures_completed"] == 1


def test_upcoming_deadlines_exclude_cancelled():
    src = _source("dashboard.py")
    assert "cancelled" in src and "annule" in src, (
        "the upcoming-deadlines filter must exclude cancelled/annule — an "
        "abandoned measure has no deadline left to meet")
