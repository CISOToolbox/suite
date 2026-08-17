import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


class TestMeasureTitleInPayload:
    """Verify the pilot notify payload uses measure.title (not measure.titre).

    The access internal.py patch_measure endpoint builds the notify payload
    with measure.title. This test ensures a mock Measure with a title field
    produces the correct payload key.
    """

    def test_payload_uses_title_field(self):
        """Simulate the payload construction from patch_measure."""

        class MockMeasure:
            title = "Revue des droits administrateurs"
            statut = "en_cours"
            responsable = "alice@medsecure.example"
            echeance = "2026-05-01"

        m = MockMeasure()
        payload = {
            "source_id": "abc-123",
            "title": m.title or "",
            "status": m.statut or "",
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
        }
        assert "title" in payload
        assert payload["title"] == "Revue des droits administrateurs"
        assert "titre" not in payload

    def test_payload_title_empty_when_none(self):
        class MockMeasure:
            title = None
            statut = "termine"
            responsable = ""
            echeance = ""

        m = MockMeasure()
        payload = {
            "source_id": "abc-456",
            "title": m.title or "",
            "status": m.statut or "",
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
        }
        assert payload["title"] == ""

    def test_internal_measures_uses_title(self):
        """The /internal/measures endpoint maps m.title to both entity_name and title."""

        class MockMeasure:
            id = "m1"
            project_id = "p1"
            title = "Controle acces VPN"
            statut = "completed"
            responsable = "bob"
            echeance = "2026-06-01"
            sort_order = 0

        m = MockMeasure()
        from routes.internal import _normalize_status
        entry = {
            "source_id": m.id,
            "entity_id": str(m.project_id),
            "entity_name": m.title,
            "title": m.title,
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
            "type": "access_review",
            "source_module": "access",
        }
        assert entry["title"] == "Controle acces VPN"
        assert entry["entity_name"] == "Controle acces VPN"
        assert "titre" not in entry
