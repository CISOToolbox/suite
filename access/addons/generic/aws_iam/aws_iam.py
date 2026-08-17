from __future__ import annotations

import logging

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")


class AwsIamPlugin(AccessPlugin):
    plugin_type = "aws_iam"
    label = "AWS IAM"
    label_en = "AWS IAM"
    config_schema = [
        {"key": "access_key_id", "label": "Access Key ID", "label_en": "Access Key ID", "type": "text", "required": True},
        {"key": "secret_access_key", "label": "Secret Access Key", "label_en": "Secret Access Key", "type": "password", "required": True},
        {"key": "region", "label": "Région", "label_en": "Region", "type": "text", "required": False, "placeholder": "us-east-1"},
    ]
    setup_guide = (
        "1. Aller dans AWS Console > IAM > Utilisateurs\n"
        "2. Créer un utilisateur \"ciso-access-reader\" (accès programmatique uniquement)\n"
        "3. Attacher la politique gérée suivante :\n"
        "   - IAMReadOnlyAccess (arn:aws:iam::aws:policy/IAMReadOnlyAccess)\n"
        "4. Ou créer une politique personnalisée avec les permissions minimales :\n"
        "   {\n"
        "     \"Version\": \"2012-10-17\",\n"
        "     \"Statement\": [{\n"
        "       \"Effect\": \"Allow\",\n"
        "       \"Action\": [\n"
        "         \"iam:ListUsers\", \"iam:GetUser\", \"iam:ListGroupsForUser\",\n"
        "         \"iam:ListAttachedUserPolicies\", \"iam:ListUserTags\",\n"
        "         \"iam:ListRoles\", \"iam:ListAccessKeys\",\n"
        "         \"sts:GetCallerIdentity\"\n"
        "       ],\n"
        "       \"Resource\": \"*\"\n"
        "     }]\n"
        "   }\n"
        "5. Créer une clé d'accès (Access Key) et noter l'Access Key ID et le Secret\n"
        "6. Aucune permission d'écriture (pas de iam:Create*, iam:Delete*, iam:Update*)\n\n"
        "Permissions minimales : IAMReadOnlyAccess ou la politique personnalisée ci-dessus"
    )
    setup_guide_en = (
        "1. Go to AWS Console > IAM > Users\n"
        "2. Create a user \"ciso-access-reader\" (programmatic access only)\n"
        "3. Attach the following managed policy:\n"
        "   - IAMReadOnlyAccess (arn:aws:iam::aws:policy/IAMReadOnlyAccess)\n"
        "4. Or create a custom policy with minimum permissions:\n"
        "   {\n"
        "     \"Version\": \"2012-10-17\",\n"
        "     \"Statement\": [{\n"
        "       \"Effect\": \"Allow\",\n"
        "       \"Action\": [\n"
        "         \"iam:ListUsers\", \"iam:GetUser\", \"iam:ListGroupsForUser\",\n"
        "         \"iam:ListAttachedUserPolicies\", \"iam:ListUserTags\",\n"
        "         \"iam:ListRoles\", \"iam:ListAccessKeys\",\n"
        "         \"sts:GetCallerIdentity\"\n"
        "       ],\n"
        "       \"Resource\": \"*\"\n"
        "     }]\n"
        "   }\n"
        "5. Create an Access Key and note the Access Key ID and Secret\n"
        "6. No write permissions (no iam:Create*, iam:Delete*, iam:Update*)\n\n"
        "Minimum permissions: IAMReadOnlyAccess or the custom policy above"
    )

    def _get_session(self, config: dict):
        import boto3
        region = config.get("region") or "us-east-1"
        return boto3.Session(
            aws_access_key_id=config["access_key_id"],
            aws_secret_access_key=config["secret_access_key"],
            region_name=region,
        )

    def _has_creds(self, config: dict) -> bool:
        return bool(config.get("access_key_id") and config.get("secret_access_key"))

    def _demo_sync(self) -> SyncResult:
        """Deterministic MedSecure AWS IAM directory for demo mode."""
        demo = [
            ("breakglass-admin", "Break-glass Admin", "personnel", ["AdministratorAccess"], ["admins"]),
            ("svc-terraform-ci", "Terraform CI", "service", ["PowerUserAccess"], ["ci"]),
            ("svc-s3-backup", "S3 Backup", "service", ["S3BackupReadWrite"], ["backup"]),
            ("svc-iomt-ingest", "IoMT Ingest", "service", ["IoTDataPlanePolicy"], ["iomt"]),
            ("dev-readonly", "Dev Read-Only", "personnel", ["ReadOnlyAccess"], ["developers"]),
            ("monitoring-datadog", "Datadog Monitoring", "service", ["CloudWatchReadOnlyAccess"], ["monitoring"]),
        ]
        records = [
            UserRecord(
                email=f"{u}@medsecure.example", display_name=name, type_compte=kind,
                roles=roles, groups=groups,
                raw_data={"source": "aws_iam", "demo": True, "UserName": u, "groups": groups, "policies": roles},
            )
            for u, name, kind, roles, groups in demo
        ]
        logger.info("AWS IAM demo sync: %d users", len(records))
        return SyncResult(users=records, errors=[])

    async def test_connection(self, config: dict) -> dict:
        if not self._has_creds(config):
            return {"ok": True, "error": "", "details": "Mode démo (aucune credential AWS) — utilisateurs IAM simulés."}
        import asyncio
        try:
            def _test():
                import boto3
                session = self._get_session(config)
                sts = session.client("sts")
                identity = sts.get_caller_identity()
                return identity.get("Account", "")

            account = await asyncio.get_event_loop().run_in_executor(None, _test)
            return {"ok": True, "error": "", "details": f"Connected to AWS account: {account}"}
        except Exception as e:
            logger.warning("AWS IAM test failed: %s", e)
            return {"ok": False, "error": "Échec de connexion AWS (voir les logs serveur).", "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        if not self._has_creds(config):
            logger.info("AWS IAM sync: no credentials — demo directory")
            return self._demo_sync()
        import asyncio

        errors: list[str] = []

        def _sync_all():
            session = self._get_session(config)
            iam = session.client("iam")

            # List all IAM users (paginated)
            raw_users: list[dict] = []
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                raw_users.extend(page.get("Users", []))

            logger.info("AWS IAM sync: fetched %d users", len(raw_users))

            # Per-user details
            user_groups: dict[str, list[str]] = {}
            user_policies: dict[str, list[str]] = {}
            user_tags: dict[str, dict[str, str]] = {}
            user_access_keys: dict[str, list[dict]] = {}

            for user in raw_users:
                username = user["UserName"]

                # Groups
                try:
                    resp = iam.list_groups_for_user(UserName=username)
                    user_groups[username] = [g["GroupName"] for g in resp.get("Groups", [])]
                except Exception as e:
                    errors.append(f"groups for {username}: {e}")

                # Attached policies
                try:
                    policies = []
                    paginator_pol = iam.get_paginator("list_attached_user_policies")
                    for page in paginator_pol.paginate(UserName=username):
                        policies.extend([p["PolicyName"] for p in page.get("AttachedPolicies", [])])
                    user_policies[username] = policies
                except Exception as e:
                    errors.append(f"policies for {username}: {e}")

                # Tags
                try:
                    resp = iam.list_user_tags(UserName=username)
                    user_tags[username] = {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
                except Exception as e:
                    errors.append(f"tags for {username}: {e}")

                # Access keys
                try:
                    resp = iam.list_access_keys(UserName=username)
                    user_access_keys[username] = [
                        {"AccessKeyId": k["AccessKeyId"], "Status": k["Status"],
                         "CreateDate": k["CreateDate"].isoformat()}
                        for k in resp.get("AccessKeyMetadata", [])
                    ]
                except Exception as e:
                    errors.append(f"access_keys for {username}: {e}")

            return raw_users, user_groups, user_policies, user_tags, user_access_keys

        raw_users, user_groups, user_policies, user_tags, user_access_keys = (
            await asyncio.get_event_loop().run_in_executor(None, _sync_all)
        )

        # Build filter set
        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            username = user["UserName"]
            groups = user_groups.get(username, [])

            if filter_set:
                if not any(g.lower() in filter_set for g in groups):
                    continue

            tags = user_tags.get(username, {})
            email = tags.get("email", tags.get("Email", username))
            display_name = tags.get("Name", tags.get("name", username))

            password_last_used = user.get("PasswordLastUsed")
            type_compte = "service" if password_last_used is None else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=user_policies.get(username, []),
                groups=groups,
                raw_data={
                    "UserName": username,
                    "UserId": user.get("UserId"),
                    "Arn": user.get("Arn"),
                    "CreateDate": user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate", ""), "isoformat") else str(user.get("CreateDate", "")),
                    "PasswordLastUsed": password_last_used.isoformat() if password_last_used and hasattr(password_last_used, "isoformat") else str(password_last_used or ""),
                    "groups": groups,
                    "policies": user_policies.get(username, []),
                    "tags": tags,
                    "access_keys": user_access_keys.get(username, []),
                },
            ))

        logger.info("AWS IAM sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
