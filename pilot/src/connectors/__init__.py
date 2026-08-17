"""Pilot KPI connectors — pull metrics from third-party platforms.

Each connector module exposes async resolver functions that return a
single ``float`` (or ``None`` on no-data / soft failure). The registry
(``resolve_connector_metric``) maps the ``source_metric`` string used
in ``kpi_catalog.json`` to the right resolver.

Currently shipped:
  * ``graph`` — Microsoft Graph (M365 Secure Score, Defender exposure,
    Intune compliance, Entra MFA coverage, Entra risky users).

Adding a new platform: drop a new module here, expose resolver
coroutines with the same ``async def fn(client, ctx) -> float | None``
signature, and register them in ``registry.RESOLVERS``.
"""
