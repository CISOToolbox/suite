"""Regression: Access uses a single shared project, so duplicating or
importing a project is refused like creating one when a project exists.

Only `create` used to check; duplicate and import created a second project.
"""
import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import projects  # noqa: E402


class _Count:
    def scalar(self):
        return 1

    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return SimpleNamespace(all=lambda: [])


class _FakeDB:
    def __init__(self):
        self.added = []

    async def execute(self, _stmt):
        return _Count()

    async def get(self, _model, _id):
        return SimpleNamespace(id=uuid.uuid4(), name="MedSecure", organization="MedSecure",
                               owner_id=None, shared_with=[], updated_at=None)

    def add(self, obj):
        self.added.append(obj)


class _Upload:
    filename = "a.json"
    content_type = "application/json"

    def __init__(self):
        self._chunks = [b"{}"]

    async def read(self, *_a):
        return self._chunks.pop() if self._chunks else b""


@pytest.mark.parametrize("call", [
    lambda db: projects.create_project(SimpleNamespace(name="x", organization="", data=None), None, db),
    lambda db: projects.duplicate_project(uuid.uuid4(), None, db),
    lambda db: projects.import_project(_Upload(), None, db),
], ids=["create", "duplicate", "import"])
def test_second_project_is_refused(call):
    db = _FakeDB()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(call(db))
    assert exc.value.status_code == 409
    assert db.added == []
