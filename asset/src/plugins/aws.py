"""AWS infrastructure inventory plugin for the Asset module (hybrid).

Imports EC2 instances and RDS databases as assets by querying the EC2/RDS
APIs. Requires read-only AWS credentials and boto3; without them the plugin
reports the missing configuration rather than returning anything.

Read-only IAM permissions for the real path:
  ec2:DescribeInstances, rds:DescribeDBInstances, sts:GetCallerIdentity.
"""
from __future__ import annotations

import logging

from src.plugins.base import AssetPlugin, AssetRecord, SyncResult

logger = logging.getLogger("asset-backend")


class AwsAssetPlugin(AssetPlugin):
    plugin_type = "aws_ec2"
    label = "AWS (EC2 / RDS)"
    label_en = "AWS (EC2 / RDS)"
    config_schema = [
        {"key": "access_key_id", "label": "Access Key ID", "label_en": "Access Key ID", "type": "text", "required": True, "placeholder": "AKIA…"},
        {"key": "secret_access_key", "label": "Secret Access Key", "label_en": "Secret Access Key", "type": "password", "required": True},
        {"key": "region", "label": "Région", "label_en": "Region", "type": "text", "required": False, "placeholder": "eu-west-3"},
    ]
    setup_guide = (
        "Compte AWS en lecture seule :\n"
        "1. AWS Console > IAM > Utilisateurs > créer « ciso-asset-reader » (accès programmatique).\n"
        "2. Attacher une politique avec : ec2:DescribeInstances, rds:DescribeDBInstances, "
        "sts:GetCallerIdentity (aucune écriture).\n"
        "3. Renseigner Access Key ID + Secret + région, puis Tester."
    )
    setup_guide_en = (
        "Read-only AWS account:\n"
        "1. AWS Console > IAM > Users > create \"ciso-asset-reader\" (programmatic access).\n"
        "2. Attach a policy with: ec2:DescribeInstances, rds:DescribeDBInstances, "
        "sts:GetCallerIdentity (no write).\n"
        "3. Fill Access Key ID + Secret + region, then Test."
    )

    def _session(self, config: dict):
        import boto3
        return boto3.Session(
            aws_access_key_id=config["access_key_id"],
            aws_secret_access_key=config["secret_access_key"],
            region_name=config.get("region") or "us-east-1",
        )

    def _has_creds(self, config: dict) -> bool:
        return bool(config.get("access_key_id") and config.get("secret_access_key"))

    async def test_connection(self, config: dict) -> dict:
        if not self._has_creds(config):
            return {"ok": False, "error": "Renseignez Access Key ID et Secret Access Key.", "details": ""}
        import asyncio
        try:
            def _probe():
                return self._session(config).client("sts").get_caller_identity().get("Account", "")
            account = await asyncio.get_event_loop().run_in_executor(None, _probe)
            return {"ok": True, "error": "", "details": f"Connecté au compte AWS {account}."}
        except ModuleNotFoundError:
            return {"ok": False, "error": "boto3 n'est pas installé sur le serveur.", "details": ""}
        except Exception as e:  # noqa: BLE001
            logger.warning("AWS asset plugin test failed: %s", e)
            return {"ok": False, "error": "Échec de connexion AWS (voir les logs serveur).", "details": ""}

    async def sync(self, config: dict, filters: dict) -> SyncResult:
        region = config.get("region") or "eu-west-3"
        if not self._has_creds(config):
            logger.info("AWS asset plugin: no credentials configured")
            return SyncResult(assets=[], errors=["Identifiants AWS non configurés."])

        import asyncio
        try:
            records = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._sync_real(config)
            )
            return SyncResult(assets=records)
        except ModuleNotFoundError:
            # Surface the misconfiguration instead of failing silently.
            logger.warning("AWS asset plugin: boto3 missing but credentials set")
            return SyncResult(assets=[], errors=["boto3 non installé sur le serveur."])
        except Exception as e:  # noqa: BLE001 — report the failure, never mask it
            logger.warning("AWS asset plugin: live sync failed (%s)", e)
            return SyncResult(assets=[], errors=[str(e)])

    def _sync_real(self, config: dict) -> list[AssetRecord]:
        session = self._session(config)
        region = config.get("region") or "us-east-1"
        loc = f"AWS {region}"
        out: list[AssetRecord] = []

        ec2 = session.client("ec2")
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    name = tags.get("Name") or inst["InstanceId"]
                    state = inst.get("State", {}).get("Name", "")
                    out.append(AssetRecord(
                        external_key=inst["InstanceId"], nom=name, type="serveur_virtuel",
                        description=f"EC2 {inst.get('InstanceType', '')}",
                        os=inst.get("PlatformDetails", ""), fournisseur="Amazon Web Services",
                        localisation=loc, ip_address=inst.get("PrivateIpAddress", ""),
                        statut="actif" if state == "running" else "inactif",
                        raw_data={"source": "aws", "state": state, "tags": tags},
                    ))

        rds = session.client("rds")
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                out.append(AssetRecord(
                    external_key=db.get("DBInstanceArn") or db["DBInstanceIdentifier"],
                    nom=db["DBInstanceIdentifier"], type="donnees",
                    description=f"RDS {db.get('DBInstanceClass', '')}",
                    os=f"{db.get('Engine', '')} {db.get('EngineVersion', '')}".strip(),
                    fournisseur="Amazon Web Services", localisation=loc,
                    statut="actif" if db.get("DBInstanceStatus") == "available" else "inactif",
                    raw_data={"source": "aws", "engine": db.get("Engine")},
                ))
        return out
