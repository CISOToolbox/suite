"""Regression (H5): OAuth callbacks must verify the `state` parameter.

Each login set an `oauth_state` cookie but the callback rebuilt the
AsyncOAuth2Client without `state=`, so authlib never checked it and the cookie
was only deleted, never compared. That is login CSRF: an attacker feeds a
victim their own authorization code and the victim is silently logged into the
attacker's account. The fix adds `_verify_oauth_state()` at the top of every
callback (pilot + the standalone surface/appsec/watch trio).
"""
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from fastapi import HTTPException  # noqa: E402

from src.routes.auth import _verify_oauth_state  # noqa: E402

REPO = Path(__file__).resolve().parents[3]


def _req(cookie, returned):
    return SimpleNamespace(
        cookies={"oauth_state": cookie} if cookie is not None else {},
        query_params={"state": returned} if returned is not None else {},
    )


def test_matching_state_passes():
    _verify_oauth_state(_req("s0m3-st4te", "s0m3-st4te"))  # must not raise


def test_mismatched_state_is_rejected():
    with pytest.raises(HTTPException) as exc:
        _verify_oauth_state(_req("expected", "attacker-value"))
    assert exc.value.status_code == 400


def test_missing_cookie_is_rejected():
    with pytest.raises(HTTPException):
        _verify_oauth_state(_req(None, "anything"))


def test_missing_returned_state_is_rejected():
    with pytest.raises(HTTPException):
        _verify_oauth_state(_req("expected", None))


def test_all_modules_guard_every_callback():
    for m in ("pilot", "surface", "appsec", "watch"):
        src = (REPO / m / "src" / "routes" / "auth.py").read_text()
        assert src.count("_verify_oauth_state(request)") >= 3, f"{m}/auth.py under-guarded"
