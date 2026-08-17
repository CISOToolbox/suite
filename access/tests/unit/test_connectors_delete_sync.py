"""Regression (H3): the singleton-connector DELETE feature must exist in every
module's connectors_common.py, not just Pilot's.

Pilot's `connectors_admin` fans a `DELETE /api/internal/connectors/{id}` out to
each consumer module when an admin deletes a connector. That receiver route was
added to Pilot's copy of connectors_common.py only; access/asset (and the
shared master) kept the older 718-line copy without it, so the fan-out hit 405
and the module silently kept the connector's stored credentials. The fix
re-syncs one canonical connectors_common.py across all copies.
"""
import hashlib
import os
import sys
from pathlib import Path

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.connectors_common import ConnectorBinding, make_router  # noqa: E402

REPO = Path(__file__).resolve().parents[3]  # demo-docker root


def test_connectors_common_identical_across_modules():
    digests = {}
    for module in ("pilot", "access", "asset"):
        path = REPO / module / "src" / "connectors_common.py"
        digests[module] = hashlib.md5(path.read_bytes()).hexdigest()
    assert len(set(digests.values())) == 1, f"connectors_common.py drifted: {digests}"


def test_singleton_exposes_internal_delete_receiver():
    async def _test(db):
        return True, ""

    async def _run(db):
        return {}

    binding = ConnectorBinding(
        schema_dict={
            "id": "demo",
            "cardinality": "one",
            "fields": [{"id": "token", "secret": True}],
        },
        test=_test,
        run=_run,
    )
    router = make_router({"demo": binding})
    routes = {(r.path, frozenset(r.methods)) for r in router.routes}
    # The service-token receiver Pilot fans out to (was missing -> 405).
    assert ("/api/internal/connectors/{connector_id}", frozenset({"DELETE"})) in routes
    # The admin-facing singleton delete.
    assert ("/api/connectors/{connector_id}", frozenset({"DELETE"})) in routes
