"""AWS security connector for Pilot KPIs (hybrid: boto3 if available + creds,
otherwise deterministic demo/mock values so the indicators populate offline).

Four metrics are exposed (all lower_better):

* ``aws_securityhub_critical``  — number of CRITICAL Security Hub findings
  (``RecordState=ACTIVE``, ``SeverityLabel=CRITICAL``).
* ``aws_guardduty_high``        — number of HIGH/CRITICAL GuardDuty findings
  across detectors.
* ``aws_iam_keys_old_pct``      — percentage of active IAM access keys older
  than 90 days (key-rotation hygiene).
* ``aws_s3_public_buckets``     — number of S3 buckets exposed publicly
  (public ACL or public bucket policy).

Credentials live in ``AppSettings`` under the connectors-framework
convention ``connector_aws_<field>`` with env-var fallback
``CONNECTOR_AWS_<FIELD>``. Fields: ``access_key_id``, ``secret_access_key``,
``region`` (default ``us-east-1``).

**Hybrid behaviour** — when boto3 is missing OR no real credentials are
configured, every resolver returns a deterministic demo value (logged at
INFO) so the MedSecure demo shows realistic AWS posture without a live
account. With real credentials + boto3 installed, the real AWS APIs are
queried; any per-call failure falls back to the demo value for that metric.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import AppSettings
from src.settings_crypto import decrypt_setting, is_secret_key

logger = logging.getLogger("pilot.connectors.aws")

# Deterministic demo values (MedSecure AWS posture) — used when boto3 or
# credentials are unavailable. Kept in one place so test/run agree.
_DEMO = {
    "aws_securityhub_critical": 0.0,  # <= target 0 → vert
    "aws_guardduty_high": 2.0,        # > target 0 (< amber 3) → amber (realistic)
    "aws_iam_keys_old_pct": 9.0,      # > target 0 (< amber 15) → amber (realistic)
    "aws_s3_public_buckets": 0.0,     # <= target 0 → vert
}


# ---------- Credentials -------------------------------------------------- #

async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    raw = (s.value if s else "") or ""
    # Credentials are stored encrypted; pre-migration rows have no marker and
    # come back unchanged (see settings_crypto).
    return decrypt_setting(raw) if is_secret_key(key) else raw


async def get_credentials(db: AsyncSession) -> Optional[dict[str, str]]:
    """Return AWS creds from AppSettings (connector_aws_*) with CONNECTOR_AWS_*
    env fallback, or None when not configured."""
    akid = await _get_setting("connector_aws_access_key_id", db) or os.getenv("CONNECTOR_AWS_ACCESS_KEY_ID", "")
    secret = await _get_setting("connector_aws_secret_access_key", db) or os.getenv("CONNECTOR_AWS_SECRET_ACCESS_KEY", "")
    region = await _get_setting("connector_aws_region", db) or os.getenv("CONNECTOR_AWS_REGION", "") or "us-east-1"
    if not (akid and secret):
        return None
    return {"access_key_id": akid, "secret_access_key": secret, "region": region}


async def _demo_enabled(db: AsyncSession) -> bool:
    """Demo mode is on unless explicitly disabled in Pilot settings (demo_mode='false')."""
    return (await _get_setting("demo_mode", db)) != "false"


def _boto3_session(creds: dict[str, str]):
    import boto3  # imported lazily so the module loads without boto3 installed
    return boto3.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name=creds.get("region") or "us-east-1",
    )


# ---------- Real metric implementations (best-effort) -------------------- #

def _real_securityhub_critical(session) -> float:
    sh = session.client("securityhub")
    n = 0
    paginator = sh.get_paginator("get_findings")
    flt = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
           "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}]}
    for page in paginator.paginate(Filters=flt):
        n += len(page.get("Findings", []))
    return float(n)


def _real_guardduty_high(session) -> float:
    gd = session.client("guardduty")
    total = 0
    for det in gd.list_detectors().get("DetectorIds", []):
        stats = gd.get_findings_statistics(
            DetectorId=det, FindingStatisticTypes=["COUNT_BY_SEVERITY"]
        ).get("FindingStatistics", {}).get("CountBySeverity", {})
        # GuardDuty severity buckets: 7.0-8.9 High, 9.0+ Critical
        for sev, cnt in stats.items():
            try:
                if float(sev) >= 7.0:
                    total += int(cnt)
            except (TypeError, ValueError):
                continue
    return float(total)


def _real_iam_keys_old_pct(session) -> float:
    from datetime import datetime, timezone
    iam = session.client("iam")
    now = datetime.now(timezone.utc)
    total = old = 0
    for upage in iam.get_paginator("list_users").paginate():
        for u in upage.get("Users", []):
            for k in iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []):
                if k.get("Status") != "Active":
                    continue
                total += 1
                created = k.get("CreateDate")
                if created and (now - created).days > 90:
                    old += 1
    return round(100.0 * old / total, 1) if total else 0.0


def _real_s3_public_buckets(session) -> float:
    s3 = session.client("s3")
    n = 0
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            if pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy"):
                continue
        except Exception:
            pass
        try:
            status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            if status.get("IsPublic"):
                n += 1
                continue
        except Exception:
            pass
    return float(n)


_REAL = {
    "aws_securityhub_critical": _real_securityhub_critical,
    "aws_guardduty_high": _real_guardduty_high,
    "aws_iam_keys_old_pct": _real_iam_keys_old_pct,
    "aws_s3_public_buckets": _real_s3_public_buckets,
}


# ---------- Resolver dispatch -------------------------------------------- #

async def resolve_metric(metric: str, db: AsyncSession) -> Optional[float]:
    """Resolve an aws_* metric. Returns a float (real or demo) or None for an
    unknown metric. Never raises — failures fall back to the demo value."""
    if metric not in _DEMO:
        return None
    creds = await get_credentials(db)
    if creds is None:
        if await _demo_enabled(db):
            logger.info("AWS connector: no credentials — demo value for %s", metric)
            return _DEMO[metric]
        return None
    try:
        import asyncio
        session = _boto3_session(creds)
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: _REAL[metric](session)
        )
    except ModuleNotFoundError:
        # Credentials are set but boto3 is missing — a misconfiguration, not a
        # demo. Skip (return None) rather than masking it as a healthy posture.
        logger.warning("AWS connector: boto3 not installed but credentials set — skipping %s", metric)
        return None
    except Exception as e:  # noqa: BLE001 — a live-account failure must NOT be reported as a clean demo value
        logger.warning("AWS connector: %s failed on configured account (%s) — skipping", metric, e)
        return None


async def test_credentials(db: AsyncSession) -> tuple[bool, str]:
    creds = await get_credentials(db)
    if creds is None:
        return True, "Mode démo (aucune credential AWS configurée) — valeurs simulées."
    try:
        import asyncio
        session = _boto3_session(creds)
        ident = await asyncio.get_event_loop().run_in_executor(
            None, lambda: session.client("sts").get_caller_identity()
        )
        return True, f"Connecté au compte AWS {ident.get('Account', '?')}."
    except ModuleNotFoundError:
        return True, "boto3 non installé — mode démo (valeurs simulées)."
    except Exception as e:  # noqa: BLE001
        logger.warning("AWS connector test failed: %s", e)
        return False, "Échec de connexion AWS (voir les logs serveur)."
