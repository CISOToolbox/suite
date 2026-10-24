"""Lock the rule that a stored token never follows an application to a new
destination: repointing repo_url or docker_images elsewhere would otherwise
hand the token to whoever answers the auth challenge there.

Also locks the single host parser behind it: an authority that URL parsers
read differently ("github.com?@evil.example") is refused everywhere, since
vetting one host while git contacts another is the same leak."""
import os
import sys
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import scanners, schemas  # noqa: E402
from src.models import Application  # noqa: E402
from src.routes import applications  # noqa: E402
from src.schemas import ApplicationUpdate, repo_host, tokens_to_clear  # noqa: E402

REPO = "https://github.com/acme/app.git"
IMAGES = ["ghcr.io/acme/app:1", "nginx:alpine"]
AMBIGUOUS = [
    "https://github.com?@evil.example/x.git",
    "https://github.com#@evil.example/x.git",
    "https://github.com?x@evil.example/x.git",
    "https://github.com\\@evil.example/x.git",
    "https://a@github.com@evil.example/x.git",
    "git@github.com?@evil.example:x/y.git",
    # git percent-decodes ssh:// URLs before splitting the host.
    "ssh://github.com:%40evil.example/x",
    "ssh://169.254.169.254%2f@github.com/x",
    "https://github.com:443x/x.git",
    # curl decodes a percent-encoded host name too.
    "https://github.com%2eevil.example/x.git",
    "https://[;evil&]@github.com/x.git",
]


@pytest.fixture(autouse=True)
def _offline_resolver(monkeypatch):
    """Any host resolves to a public address: these tests are about parsing."""
    monkeypatch.setattr(schemas, "resolve_safe_target", lambda host, **kw: "203.0.113.10")


class TestRepoHost:
    @pytest.mark.parametrize("url", AMBIGUOUS)
    def test_ambiguous_authority_has_no_host(self, url):
        assert repo_host(url) == ""

    @pytest.mark.parametrize("url", AMBIGUOUS)
    def test_ambiguous_authority_is_refused_on_input(self, url):
        with pytest.raises(ValueError):
            ApplicationUpdate(repo_url=url)

    # Only HTTP URLs ever carry the token.
    @pytest.mark.parametrize("url", [u for u in AMBIGUOUS if u.startswith("http")])
    def test_ambiguous_authority_never_gets_the_token(self, url):
        with pytest.raises(RuntimeError):
            scanners._inject_token(url, "SECRETPAT")

    def test_deep_analysis_fetch_refuses_an_ambiguous_host(self):
        r = scanners.fetch_file_window(AMBIGUOUS[0], "main", "", "", "src/x.py", 1)
        assert r == {"ok": False, "note": "repo_host"}

    def test_ssh_url_never_carries_the_pat(self):
        url = "ssh://git@github.com:2222/acme/app.git"
        assert repo_host(url) == "github.com"
        assert scanners._inject_token(url, "SECRETPAT") == url

    @pytest.mark.parametrize("url", [
        "x:y@z", "https://[github.com/x.git", "https://github.com]/x.git",
        "https://[::1]x/x.git", "ssh://git@[github.com:22/x", "https://ex\u2100ample.com/x.git",
    ])
    def test_unparsable_input_fails_closed_without_raising(self, url):
        # Callers only expect "" here, RuntimeError from the re-check, and a
        # note from the deep-analysis fetch (which must never raise).
        assert repo_host(url) == ""
        assert tokens_to_clear(REPO, [], {"repo_url": url}) == ["repo_token"]
        with pytest.raises(RuntimeError):
            scanners._revalidate_repo_host(url)
        if "://" in url:
            assert scanners.fetch_file_window(url, "main", "", "", "src/x.py", 1) == \
                {"ok": False, "note": "repo_host"}

    def test_deep_analysis_fetch_with_a_token_never_raises(self, monkeypatch):
        # A legacy row with a blank after the host: the re-check and the
        # token injection must read the same string.
        monkeypatch.setattr(scanners, "decrypt_token", lambda _c: "SECRETPAT")
        r = scanners.fetch_file_window("https://github.com\t", "main", "", "ENC", "src/x.py", 1)
        assert r == {"ok": False, "note": "repo_host"}

    def test_userinfo_and_scp_forms_still_parse(self):
        assert repo_host("https://acme@dev.azure.com/acme/p/_git/r") == "dev.azure.com"
        assert repo_host("git@github.com:acme/app.git") == "github.com"
        assert repo_host("https://jdoe%40corp.example@git.corp.example/x.git") == "git.corp.example"
        assert scanners._inject_token("https://acme@dev.azure.com/acme/p/_git/r", "T") == \
            "https://x-access-token:T@dev.azure.com/acme/p/_git/r"


class TestRepoToken:
    def test_same_host_keeps_token(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "https://github.com/acme/other.git"}) == []

    def test_explicit_default_port_and_case_are_the_same_destination(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "https://GitHub.com:443/acme/app.git"}) == []

    def test_new_host_clears_token(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "https://evil.example/x.git"}) == ["repo_token"]

    def test_downgrade_to_http_clears_token(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "http://github.com/acme/app.git"}) == ["repo_token"]

    def test_other_port_clears_token(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "https://github.com:8443/acme/app.git"}) == ["repo_token"]

    @pytest.mark.parametrize("url", AMBIGUOUS)
    def test_ambiguous_url_clears_token(self, url):
        assert tokens_to_clear(REPO, [], {"repo_url": url}) == ["repo_token"]

    def test_scp_form_to_new_host_clears_token(self):
        assert tokens_to_clear(REPO, [], {"repo_url": "git@evil.example:x/y.git"}) == ["repo_token"]

    def test_new_token_in_same_update_is_kept(self):
        updates = {"repo_url": "https://gitlab.example/x.git", "repo_token": "glpat-new"}
        assert tokens_to_clear(REPO, [], updates) == []

    def test_url_untouched_keeps_token(self):
        assert tokens_to_clear(REPO, [], {"name": "renamed"}) == []


class TestImageToken:
    def test_same_registries_keep_token(self):
        assert tokens_to_clear(REPO, IMAGES, {"docker_images": ["ghcr.io/acme/app:2"]}) == []

    def test_registry_case_is_not_a_new_registry(self):
        assert tokens_to_clear(REPO, IMAGES, {"docker_images": ["GHCR.IO/acme/app:2"]}) == []

    def test_docker_hub_short_and_namespaced_refs_compare_equal(self):
        assert tokens_to_clear(REPO, IMAGES, {"docker_images": ["grafana/grafana:11"]}) == []

    def test_added_registry_clears_token(self):
        updates = {"docker_images": IMAGES + ["evil.example/x:1"]}
        assert tokens_to_clear(REPO, IMAGES, updates) == ["image_token"]

    def test_other_registry_port_clears_token(self):
        updates = {"docker_images": ["ghcr.io:5000/acme/app:1"]}
        assert tokens_to_clear(REPO, IMAGES, updates) == ["image_token"]

    def test_new_token_in_same_update_is_kept(self):
        updates = {"docker_images": ["evil.example/x:1"], "image_token": "new"}
        assert tokens_to_clear(REPO, IMAGES, updates) == []


class _Result:
    def __init__(self, app):
        self._app = app

    def scalar_one_or_none(self):
        return self._app


class _Session:
    """Just what update_application touches: one SELECT, commit, refresh."""

    def __init__(self, app):
        self.app = app

    async def execute(self, _stmt):
        return _Result(self.app)

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


@pytest.fixture
def stored_app():
    return Application(name="app", repo_url=REPO, repo_branch="main", scan_paths=[],
                       docker_images=list(IMAGES), enabled_scanners=["gitleaks"],
                       notification_emails=[], repo_token_encrypted="ENC-REPO",
                       image_token_encrypted="ENC-IMG")


@pytest.fixture
def audit(monkeypatch):
    calls = []

    async def log_action(db, user, request, action, target=None, details=None):
        calls.append((action, details))

    monkeypatch.setattr(applications, "log_action", log_action)
    monkeypatch.setattr(applications, "require_min_role", lambda *a, **kw: None)
    monkeypatch.setattr(applications, "encrypt_token", lambda t: f"ENC({t})" if t else "")
    return calls


async def _patch(app, body):
    return await applications.update_application(
        app.id, ApplicationUpdate(**body), SimpleNamespace(), None, _Session(app))


@pytest.mark.asyncio
async def test_route_clears_token_on_host_change_and_audits_it(stored_app, audit):
    out = await _patch(stored_app, {"repo_url": "https://evil.example/x.git"})
    assert stored_app.repo_token_encrypted == ""
    assert stored_app.image_token_encrypted == "ENC-IMG"
    assert out["has_token"] is False
    assert audit == [("app.update", {"fields": ["repo_url"], "tokens_cleared": ["repo_token"]})]


@pytest.mark.asyncio
async def test_route_stores_token_supplied_with_the_new_host(stored_app, audit):
    await _patch(stored_app, {"repo_url": "https://gitlab.example/x.git", "repo_token": "glpat-new"})
    assert stored_app.repo_token_encrypted == "ENC(glpat-new)"
    assert "tokens_cleared" not in audit[0][1]


@pytest.mark.asyncio
async def test_route_keeps_token_on_same_host(stored_app, audit):
    await _patch(stored_app, {"repo_url": "https://github.com/acme/other.git",
                              "docker_images": ["ghcr.io/acme/app:2"]})
    assert stored_app.repo_token_encrypted == "ENC-REPO"
    assert stored_app.image_token_encrypted == "ENC-IMG"
    assert "tokens_cleared" not in audit[0][1]
