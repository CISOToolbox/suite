"""Regression: Microsoft Graph $select must not contain @odata.type.

Graph rejects `$select=@odata.type` with HTTP 400 ("Could not find a property
named '@odata.type'") because it is an instance annotation, not a selectable
property. The memberOf calls in the Entra ID / M365 connectors used
`$select=displayName,@odata.type`, which broke the connectors with 400 errors.
The @odata.type annotation is still returned automatically for polymorphic
directoryObject collections, so type filtering keeps working without selecting
it. This test locks the fix.
"""
import os
import re

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "..", "..", "src", "plugins")
PLUGINS = ["entra_id.py", "m365.py"]


def _source(name: str) -> str:
    with open(os.path.join(SRC, name)) as f:
        return f.read()


def test_no_odata_type_in_graph_select():
    """No $select clause may include @odata.type (causes Graph 400)."""
    bad = re.compile(r"\$select=[^\"'\s]*@odata")
    for name in PLUGINS:
        src = _source(name)
        offenders = bad.findall(src)
        assert not offenders, f"{name}: @odata.type in $select -> Graph 400: {offenders}"


def test_memberof_still_queried():
    """The connectors still fetch group/role membership via memberOf."""
    for name in PLUGINS:
        assert "/memberOf" in _source(name), f"{name}: memberOf query missing"


def test_entra_fetches_last_signin():
    """Entra connector requests signInActivity, populates last_login_at, and
    falls back gracefully when it's unavailable (no Entra ID P1 / AuditLog perm)."""
    src = _source("entra_id.py")
    assert "signInActivity" in src, "signInActivity not requested"
    assert "last_login_at=last_login_at" in src, "last_login_at not set on the record"
    assert "lastSignInDateTime" in src, "lastSignInDateTime not parsed"
    # graceful fallback path so a non-premium tenant still syncs
    assert "except httpx.HTTPStatusError" in src, "no fallback when signInActivity unavailable"
