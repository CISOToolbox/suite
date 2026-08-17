from src.plugins.base import AccessPlugin

# The registry is populated ONLY by the add-on loader below. All concrete
# connectors now live as add-ons under addons/generic/<name>/ (shareable) or
# addons/custom/<client>/ (client-specific), baked into an image at build time
# via shared/build-client-image.sh. The core image ships ZERO connectors so a
# client deploys only what it selects. base.py and _graph_auth.py stay here
# (shared framework, imported by the connectors).
PLUGIN_REGISTRY: dict[str, type[AccessPlugin]] = {}


# ── Client add-on connectors ──────────────────────────────────
# Beyond the built-in connectors above, a deployment can drop bespoke
# connectors (e.g. a client-specific file-import connector) into an
# add-on directory without forking this module. Each *.py found is
# imported and every AccessPlugin subclass it defines is registered by
# its `plugin_type`. This keeps `__init__.py` and `requirements.txt`
# untouched, so core updates propagate to client repos without conflict.
#
# Add-on directories are taken from the ACCESS_ADDON_PATHS env var
# (os.pathsep-separated) plus the conventional in-image path /app/addons.
# Each directory is scanned RECURSIVELY, so the convention
# /app/addons/{generic,custom/<client>}/ works out of the box.
# A file whose dependency is missing is skipped (logged), exactly like
# the built-ins above. Optionally, ACCESS_ADDONS_ENABLED (comma-separated
# plugin_types) restricts which discovered connectors are actually
# registered — empty means "all that are present".
def _load_addon_connectors() -> None:
    import importlib.util
    import logging
    import os

    log = logging.getLogger("access-backend")
    paths = [p.strip() for p in os.environ.get("ACCESS_ADDON_PATHS", "").split(os.pathsep) if p.strip()]
    if "/app/addons" not in paths:
        paths.append("/app/addons")
    allow = {p.strip() for p in os.environ.get("ACCESS_ADDONS_ENABLED", "").split(",") if p.strip()}

    seen: set[str] = set()
    for base in paths:
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fname in sorted(files):
                if not fname.endswith(".py") or fname.startswith("_") or fname.startswith("test_") or fname == "conftest.py":
                    continue
                fpath = os.path.join(root, fname)
                if fpath in seen:
                    continue
                seen.add(fpath)
                try:
                    spec = importlib.util.spec_from_file_location(f"access_addon_{fname[:-3]}", fpath)
                    if spec is None or spec.loader is None:
                        continue
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for obj in vars(mod).values():
                        if (
                            isinstance(obj, type)
                            and issubclass(obj, AccessPlugin)
                            and obj is not AccessPlugin
                            and getattr(obj, "plugin_type", "")
                        ):
                            if allow and obj.plugin_type not in allow:
                                log.info("Add-on connector '%s' present but disabled (ACCESS_ADDONS_ENABLED)", obj.plugin_type)
                                continue
                            PLUGIN_REGISTRY[obj.plugin_type] = obj
                            log.info("Loaded add-on connector '%s' from %s", obj.plugin_type, fpath)
                except Exception as e:  # noqa: BLE001 — a broken add-on must not crash boot
                    log.warning("Skipped add-on connector %s: %s: %s", fpath, type(e).__name__, e)


_load_addon_connectors()
