"""Regression guard for the reference cleanup performed on deletion.

Nothing cascades in the database: ``application_id``, ``review_entry_id`` and
``reviewers`` are plain strings with no foreign key — the model's cascades only
hang off ``project_id``. The cleanup therefore lives in the frontend, and this
test exercises it.

It runs the **compiled** ``app/js/Access_app.js`` — the file the image actually
serves — rather than a Python transcription of it. A transcription would keep
passing after the shipped code broke, which is the failure mode this test
exists to prevent.

Skipped when ``node`` is unavailable; the assertions need a JS runtime and
there is no useful degraded mode.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parents[2] / "app" / "js" / "Access_app.js"

# The functions under test. They read and write the module-global D, so the
# harness injects one instead of relying on any browser state.
HELPERS = ("_detachMeasures", "_entryIdsOf", "_purgeUserRefs", "_purgeAppRefs")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="needs node to run the shipped frontend code"
)


def _extract(source: str, name: str) -> str:
    """Return the full body of ``function name(...) {...}`` by brace matching."""
    start = source.find("function " + name + "(")
    assert start >= 0, f"{name} is gone from Access_app.js — was it renamed?"
    i = source.index("{", start)
    depth = 0
    while True:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
        if depth == 0:
            return source[start:i]


def _run(data: dict, op: str, ids: list[str]) -> dict:
    source = APP_JS.read_text(encoding="utf-8")
    helpers = "\n".join(_extract(source, n) for n in HELPERS)
    script = (
        helpers
        # Under `node -e`, argv is [execPath, ...args] — there is no script slot.
        + "\nvar D = JSON.parse(process.argv[1]);"
        + "\nvar op = process.argv[2], ids = JSON.parse(process.argv[3]);"
        + "\nvar stripped = op === 'user' ? _purgeUserRefs(ids) : (_purgeAppRefs(ids), 0);"
        + "\nprocess.stdout.write(JSON.stringify({D: D, stripped: stripped}));"
    )
    out = subprocess.run(
        ["node", "-e", script, "--", json.dumps(data), op, json.dumps(ids)],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return json.loads(out.stdout)


def _dataset() -> dict:
    return {
        "si_users": [{"id": "U-001"}, {"id": "U-002"}],
        "applications": [
            {"id": "APP-001", "reviewers": ["U-001", "U-002"]},
            {"id": "APP-002", "reviewers": ["U-002"]},
        ],
        "reviews": [
            {"id": "REV-001", "application_id": "APP-001",
             "entries": [{"id": "E-1"}, {"id": "E-2"}]},
            {"id": "REV-002", "application_id": "APP-002",
             "entries": [{"id": "E-3"}]},
        ],
        "measures": [
            {"id": "MES-001", "review_entry_id": "E-1"},
            {"id": "MES-002", "review_entry_id": "E-3"},
            {"id": "MES-003", "review_entry_id": ""},
        ],
    }


def test_deleted_user_is_removed_from_every_reviewer_list():
    r = _run(_dataset(), "user", ["U-002"])
    assert r["stripped"] == 2
    assert r["D"]["applications"][0]["reviewers"] == ["U-001"]
    assert r["D"]["applications"][1]["reviewers"] == []


def test_deleting_an_application_removes_its_reviews_only():
    r = _run(_dataset(), "app", ["APP-001"])
    assert [x["id"] for x in r["D"]["reviews"]] == ["REV-002"]


def test_measures_survive_the_review_that_created_them():
    """A measure is assigned work — it is detached, never deleted."""
    r = _run(_dataset(), "app", ["APP-001"])
    measures = r["D"]["measures"]
    assert len(measures) == 3, "a measure was destroyed with its review"
    assert measures[0]["review_entry_id"] == ""      # detached
    assert measures[1]["review_entry_id"] == "E-3"   # other review, untouched


def test_bulk_deletion_leaves_no_dangling_reference():
    r = _run(_dataset(), "app", ["APP-001", "APP-002"])
    assert r["D"]["reviews"] == []
    assert all(m["review_entry_id"] == "" for m in r["D"]["measures"])
    assert len(r["D"]["measures"]) == 3


def test_empty_dataset_is_tolerated():
    empty = {"si_users": [], "applications": [], "reviews": [], "measures": []}
    assert _run(empty, "app", ["APP-999"])["D"]["reviews"] == []
