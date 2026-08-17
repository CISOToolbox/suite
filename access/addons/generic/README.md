# Generic add-on connectors

**Shareable** Access connectors, reusable across clients. Drop an
`AccessPlugin` subclass `.py` here (with a unique `plugin_type`) and an
optional `requirements.txt`.

These are the catalogue/showcase connectors. They are included in a client
image when selected at build time (see `shared/build-client-image.sh`), e.g.
`--addons generic`.

Client-**specific** connectors go under `../custom/<client>/` instead (never
shipped to other clients — selected per build).

The core loader (`src/plugins/__init__.py`) auto-discovers every connector
under the directories in `ACCESS_ADDON_PATHS` (recursively). It skips
`test_*`, `_*`, `conftest.py`, and any connector whose dependency is missing.
