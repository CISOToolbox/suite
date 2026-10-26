"""Lock what each container of docker-compose.yml is handed.

No container loads the whole .env: each lists the variables it reads, so a
compromised one holds only its own secrets. These checks keep it that way,
and catch the silent failure on the other side — a setting the code reads
that the compose file no longer passes.

The files are loaded with a YAML parser, so anchors and aliases are resolved
as docker compose resolves them, and every check runs on the base file merged
with each override: an override can hand a secret out too.
"""
import json
import pathlib
import re

import yaml

SUITE = pathlib.Path(__file__).resolve().parents[1]
MODULES = ["pilot", "risk", "vendor", "compliance", "asset", "audit", "access", "surface", "appsec", "watch"]
OVERRIDES = [[], ["docker-compose.s3.yml"], ["docker-compose.s3.yml", "docker-compose.s3-ca.yml"]]


def _load(name: str) -> dict:
    return yaml.safe_load((SUITE / name).read_text()) or {}


def _env(svc: dict) -> dict[str, str]:
    """A service's environment as {name: raw value} (list or mapping form)."""
    env = svc.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            name, _, value = str(item).partition("=")
            out[name] = value
        return out
    return {k: "" if v is None else str(v) for k, v in env.items()}


def stacks():
    """(label, {service: (env, raw)}) for the base file and each override set.

    `env` is the merged environment; `raw` the whole service definition as
    text, so an interpolation anywhere (command, labels…) is seen too."""
    base = _load("docker-compose.yml")
    for extra in OVERRIDES:
        merged = {name: (dict(_env(svc)), yaml.safe_dump(svc)) for name, svc in base["services"].items()}
        for f in extra:
            for name, svc in (_load(f).get("services") or {}).items():
                env, raw = merged.get(name, ({}, ""))
                env.update(_env(svc))
                merged[name] = (env, raw + yaml.safe_dump(svc))
        yield "+".join(["base"] + extra), merged


def holders(services: dict, var: str) -> set[str]:
    """Services handed `var`: by name, or interpolated anywhere ($VAR, ${VAR…})."""
    ref = re.compile(r"\$\{?" + re.escape(var) + r"(?![A-Za-z0-9_])")
    return {s for s, (env, raw) in services.items() if var in env or ref.search(raw)}


def test_no_service_loads_the_whole_env_file():
    for f in ["docker-compose.yml"] + sorted({f for o in OVERRIDES for f in o}):
        for name, svc in (_load(f).get("services") or {}).items():
            assert "env_file" not in svc, f"{f}: {name}"


def test_backup_secrets_stay_with_their_users():
    for label, env in stacks():
        assert holders(env, "BACKUP_AGENT_TOKEN") == {"pilot-app", "backup-agent"}, label
        assert holders(env, "BACKUP_CIPHER_PASS") == {f"{m}-db" for m in MODULES} | {"backup-agent"}, label


def test_off_site_credentials_stay_with_the_backup_side():
    for label, env in list(stacks())[1:]:
        assert holders(env, "BACKUP_S3_KEY_SECRET") <= {f"{m}-db" for m in MODULES} | {"backup-agent"}, label


def test_identity_provider_secrets_reach_pilot_only():
    # Modules run AUTH_MODE=pilot: sign-in happens in Pilot alone.
    for label, env in stacks():
        for var in ("ENTRA_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET", "OIDC_CLIENT_SECRET"):
            assert holders(env, var) == {"pilot-app"}, (label, var)


def test_smb_service_account_reaches_surface_only():
    for label, env in stacks():
        assert holders(env, "SURFACE_SMB_PASSWORD") == {"surface-app"}, label


def test_each_pair_has_its_own_database_password():
    for label, env in stacks():
        for m in MODULES:
            var = f"DB_PASSWORD_{m.upper()}"
            assert holders(env, var) == {f"{m}-app", f"{m}-db"}, (label, var)


def test_pilot_connector_env_fallbacks_are_passed():
    # connectors_common falls back to CONNECTOR_<ID>_<FIELD>; the names are
    # built at run time, so only the schemas say which ones exist.
    expected = set()
    for schema in sorted((SUITE / "pilot" / "src" / "connector_schemas").glob("*.json")):
        d = json.loads(schema.read_text())
        expected |= {f"CONNECTOR_{d['id'].upper()}_{f['id'].upper()}" for f in d["fields"]}
    # Legacy M365 names, still read by pilot/src/connectors/graph.py.
    expected |= {"M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"}
    for label, env in stacks():
        missing = expected - set(env["pilot-app"][0])
        assert not missing, (label, sorted(missing))


def _networks(svc: dict) -> set[str]:
    nets = svc.get("networks") or []
    return set(nets if isinstance(nets, list) else nets.keys())


def test_each_database_is_off_the_shared_network():
    # Base file merged with each override: compose unions the network lists.
    base = _load("docker-compose.yml")["services"]
    for extra in OVERRIDES:
        nets = {name: _networks(svc) for name, svc in base.items()}
        for f in extra:
            for name, svc in (_load(f).get("services") or {}).items():
                nets.setdefault(name, set()).update(_networks(svc))
        for m in MODULES:
            assert nets[f"{m}-db"] <= {f"{m}-data", f"{m}-egress"}, (extra, m, nets[f"{m}-db"])
            assert f"{m}-data" in nets[f"{m}-db"] and f"{m}-data" in nets[f"{m}-app"], (extra, m)
        assert nets["backup-agent"] <= {"ciso-recovery", "agent-egress"}, (extra, nets["backup-agent"])
        # And the other way round: who else joins a private network.
        members: dict[str, set[str]] = {}
        for svc, svc_nets in nets.items():
            for n in svc_nets:
                members.setdefault(n, set()).add(svc)
        for m in MODULES:
            assert members.get(f"{m}-data", set()) == {f"{m}-app", f"{m}-db"}, (extra, m, members.get(f"{m}-data"))
            assert members.get(f"{m}-egress", {f"{m}-db"}) == {f"{m}-db"}, (extra, m, members.get(f"{m}-egress"))
        assert members.get("agent-egress", {"backup-agent"}) == {"backup-agent"}, (extra, members.get("agent-egress"))


def test_private_networks_have_no_way_out():
    declared = _load("docker-compose.yml")["networks"]
    for name in [f"{m}-data" for m in MODULES] + ["ciso-recovery"]:
        assert (declared.get(name) or {}).get("internal") is True, name


def test_s3_override_gives_each_container_its_own_way_out():
    # A shared egress bridge would let the databases reach each other.
    s3 = _load("docker-compose.s3.yml")["services"]
    egress = {name: [n for n in svc.get("networks", []) if n.endswith("-egress")]
              for name, svc in s3.items() if svc.get("networks")}
    flat = [n for nets in egress.values() for n in nets]
    assert len(flat) == len(set(flat)) == len(egress) == len(MODULES) + 1, egress
