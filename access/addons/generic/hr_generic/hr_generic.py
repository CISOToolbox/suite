from __future__ import annotations

import logging
from typing import Any

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")

# Source header/key → canonical identity field. Keys are normalised
# (lowercased, spaces/hyphens → underscore) before lookup, so a column
# "First Name" matches "first_name".
_HR_FIELD_ALIASES: dict[str, str] = {
    "email": "email", "mail": "email", "e_mail": "email", "work_email": "email",
    "courriel": "email", "emailaddress": "email", "email_address": "email",
    "prenom": "prenom", "prénom": "prenom", "first_name": "prenom", "firstname": "prenom",
    "given_name": "prenom", "givenname": "prenom",
    "nom": "nom", "last_name": "nom", "lastname": "nom", "family_name": "nom",
    "familyname": "nom", "surname": "nom",
    "fonction": "fonction", "function": "fonction", "title": "fonction",
    "job_title": "fonction", "jobtitle": "fonction", "role": "fonction",
    "poste": "fonction", "position": "fonction",
    "equipe": "equipe", "équipe": "equipe", "team": "equipe", "department": "equipe",
    "departement": "equipe", "division": "equipe", "service": "equipe", "org_unit": "equipe",
    "manager_email": "manager_email", "manageremail": "manager_email", "manager": "manager_email",
    "responsable": "manager_email", "supervisor_email": "manager_email",
    "date_fin_contrat": "date_fin_contrat", "fin_contrat": "date_fin_contrat",
    "contract_end": "date_fin_contrat", "contractend": "date_fin_contrat",
    "end_date": "date_fin_contrat", "enddate": "date_fin_contrat", "termination_date": "date_fin_contrat",
    "statut": "statut", "status": "statut", "state": "statut", "employment_status": "statut",
    "type_compte": "type_compte", "type": "type_compte", "employee_type": "type_compte",
    "employment_type": "type_compte", "worker_type": "type_compte", "contract_type": "type_compte",
}

_LIST_KEYS = ("results", "data", "employees", "users", "items", "records", "value")


def _map_employee(rec: dict) -> dict:
    """Map one source HR record to canonical identity fields (raw strings).

    Type/statut normalisation is done later by the sync route so it stays
    consistent with the CSV import. Returns a dict that always carries an
    'email' key (possibly empty)."""
    out: dict[str, str] = {}
    for k, v in (rec or {}).items():
        if v is None or isinstance(v, (dict, list)):
            continue
        key = str(k).strip().lower().replace(" ", "_").replace("-", "_")
        field = _HR_FIELD_ALIASES.get(key)
        if field and field not in out:
            out[field] = str(v).strip()
    out.setdefault("email", "")
    return out


def _extract_list(payload: Any, users_key: str = "") -> list[dict]:
    """Pull the employee array out of an HR API response (list, or an
    object wrapping the list under a configured/known key)."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        if users_key and isinstance(payload.get(users_key), list):
            return [r for r in payload[users_key] if isinstance(r, dict)]
        for k in _LIST_KEYS:
            if isinstance(payload.get(k), list):
                return [r for r in payload[k] if isinstance(r, dict)]
    return []


class HrGenericPlugin(AccessPlugin):
    plugin_type = "hr_generic"
    label = "SIRH (API générique)"
    label_en = "HRIS (generic API)"
    config_schema = [
        {"key": "api_url", "label": "URL de l'API (liste des employés, JSON)",
         "label_en": "API URL (employee list, JSON)", "type": "text", "required": True,
         "placeholder": "https://sirh.example.com/api/employees"},
        {"key": "api_token", "label": "Jeton Bearer (optionnel)",
         "label_en": "Bearer token (optional)", "type": "password", "required": False},
        {"key": "users_key", "label": "Clé JSON de la liste (optionnel, ex : results)",
         "label_en": "JSON list key (optional, e.g. results)", "type": "text", "required": False,
         "placeholder": "results"},
    ]
    setup_guide = (
        "Connecteur RH générique : pointe vers une API qui renvoie la liste des\n"
        "employés en JSON (tableau, ou objet contenant le tableau sous une clé).\n"
        "1. Renseigner l'URL de l'API (lecture seule).\n"
        "2. Si l'API exige une authentification, fournir un jeton Bearer.\n"
        "3. Champs reconnus (alias FR/EN) : email, prenom, nom, fonction, equipe,\n"
        "   manager (email), date_fin_contrat, type_compte, statut.\n"
        "Aucune écriture côté SIRH. La synchronisation alimente le référentiel\n"
        "des utilisateurs (Utilisateurs > Sync RH)."
    )
    setup_guide_en = (
        "Generic HRIS connector: points to an API returning the employee list as\n"
        "JSON (an array, or an object wrapping the array under a key).\n"
        "1. Set the read-only API URL.\n"
        "2. If the API requires auth, provide a Bearer token.\n"
        "3. Recognised fields (FR/EN aliases): email, prenom/first_name, nom/last_name,\n"
        "   fonction/title, equipe/department, manager (email), date_fin_contrat,\n"
        "   type_compte, statut.\n"
        "Read-only. The sync feeds the user referential (Users > HR Sync)."
    )

    def _headers(self, config: dict) -> dict:
        h = {"Accept": "application/json"}
        token = (config.get("api_token") or "").strip()
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    async def test_connection(self, config: dict) -> dict:
        # api_url is operator-supplied and the API token rides along with
        # every request, so the host is vetted before we reach out.
        try:
            url = validate_connector_base_url(config.get("api_url", ""))
        except ValueError as e:
            return {"ok": False, "error": str(e), "details": ""}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers(config))
                resp.raise_for_status()
                rows = _extract_list(resp.json(), (config.get("users_key") or "").strip())
            return {"ok": True, "error": "", "details": f"{len(rows)} enregistrement(s) lus"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        try:
            url = validate_connector_base_url(config.get("api_url", ""))
        except ValueError as e:
            return SyncResult(users=[], errors=[str(e)])
        errors: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(url, headers=self._headers(config))
                resp.raise_for_status()
                rows = _extract_list(resp.json(), (config.get("users_key") or "").strip())
        except Exception as e:
            return SyncResult(users=[], errors=[f"HR API: {e}"])

        filter_set = {g.lower() for g in group_filters} if group_filters else set()
        records: list[UserRecord] = []
        for rec in rows:
            ident = _map_employee(rec)
            email = ident.get("email", "")
            if not email:
                continue
            if filter_set and ident.get("equipe", "").lower() not in filter_set:
                continue
            display_name = (ident.get("prenom", "") + " " + ident.get("nom", "")).strip() or email
            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte="personnel",
                groups=[ident["equipe"]] if ident.get("equipe") else [],
                raw_data=ident,
            ))
        logger.info("HR generic sync: %d user(s), %d error(s)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
