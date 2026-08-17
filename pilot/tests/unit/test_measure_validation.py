"""Test Pydantic models MeasureUpdate and MeasureCreate from routes/measures.py."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest
from pydantic import ValidationError

from src.routes.measures import MeasureCreate, MeasureUpdate


class TestMeasureCreate:
    """MeasureCreate requires title, status defaults to 'planned'."""

    def test_valid_minimal(self):
        m = MeasureCreate(title="Patch servers")
        assert m.title == "Patch servers"
        assert m.status == "planned"
        assert m.assignee == ""
        assert m.due_date == ""

    def test_valid_all_fields(self):
        m = MeasureCreate(
            title="Deploy WAF",
            status="in_progress",
            assignee="alice@example.com",
            due_date="2026-06-01",
        )
        assert m.status == "in_progress"
        assert m.assignee == "alice@example.com"

    def test_valid_status_planned(self):
        m = MeasureCreate(title="x", status="planned")
        assert m.status == "planned"

    def test_valid_status_in_progress(self):
        m = MeasureCreate(title="x", status="in_progress")
        assert m.status == "in_progress"

    def test_valid_status_completed(self):
        m = MeasureCreate(title="x", status="completed")
        assert m.status == "completed"

    def test_valid_status_backlog(self):
        m = MeasureCreate(title="x", status="backlog")
        assert m.status == "backlog"

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            MeasureCreate(title="x", status="done")
        assert "status" in str(exc_info.value)

    def test_invalid_status_french_rejected(self):
        with pytest.raises(ValidationError):
            MeasureCreate(title="x", status="termine")

    def test_invalid_status_en_cours_rejected(self):
        with pytest.raises(ValidationError):
            MeasureCreate(title="x", status="en_cours")

    def test_missing_title_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            MeasureCreate(status="planned")  # type: ignore[call-arg]
        assert "title" in str(exc_info.value)

    def test_empty_string_title_accepted(self):
        """Pydantic does not enforce non-empty strings by default.
        The route itself does not reject empty titles (unlike projects)."""
        m = MeasureCreate(title="")
        assert m.title == ""


class TestMeasureUpdate:
    """MeasureUpdate: all fields optional, status Literal validated."""

    def test_empty_update(self):
        m = MeasureUpdate()
        assert m.status is None
        assert m.assignee is None
        assert m.due_date is None
        assert m.title is None

    def test_status_only(self):
        m = MeasureUpdate(status="completed")
        assert m.status == "completed"
        assert m.assignee is None

    def test_assignee_only(self):
        m = MeasureUpdate(assignee="bob@example.com")
        assert m.assignee == "bob@example.com"
        assert m.status is None

    def test_due_date_only(self):
        m = MeasureUpdate(due_date="2026-12-31")
        assert m.due_date == "2026-12-31"

    def test_title_only(self):
        m = MeasureUpdate(title="Updated title")
        assert m.title == "Updated title"

    def test_all_fields(self):
        m = MeasureUpdate(
            status="backlog",
            assignee="carol@example.com",
            due_date="2026-09-15",
            title="New title",
        )
        assert m.status == "backlog"
        assert m.assignee == "carol@example.com"
        assert m.due_date == "2026-09-15"
        assert m.title == "New title"

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            MeasureUpdate(status="invalid")
        assert "status" in str(exc_info.value)

    def test_invalid_status_uppercase_rejected(self):
        with pytest.raises(ValidationError):
            MeasureUpdate(status="COMPLETED")

    def test_invalid_status_french_rejected(self):
        with pytest.raises(ValidationError):
            MeasureUpdate(status="termine")

    def test_none_status_is_valid(self):
        """Explicitly passing None keeps the field unset."""
        m = MeasureUpdate(status=None)
        assert m.status is None
