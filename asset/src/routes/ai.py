"""Asset AI endpoints.

The shared /api/ai proxy (provider registry, key/settings management,
/complete, /runtime, /config, /keys, /validate-key, the LLM dispatch) lives in
src/ai_proxy_common.py. Only the asset-inventory métier prompt and its four
suggestion endpoints are here — the methodology stays server-side.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.ai_proxy_common import (
    _check_ai_access,
    _check_rate_limit,
    _parse_json_lax,
    _provider_complete,
    _runtime_provider_model,
    make_ai_router,
)
from src.auth import get_current_user
from src.database import get_db
from src.models import User

# Common /api/ai endpoints; the domain endpoints below are appended to it.
router = make_ai_router()


ASSET_SYSTEM_PROMPT = (
    "Tu es un expert en gestion d'actifs informatiques et en securite des SI. "
    "Tu aides a documenter un inventaire d'actifs pour une organisation. "
    "Reponds en francais, de maniere structuree et concise. "
    "Utilise un vocabulaire professionnel adapte a un RSSI ou un DSI."
)


def _asset_system(methodology_context: str = "", organization: str = "") -> str:
    """Build the system prompt: base methodology + optional user-supplied
    methodological context + optional organization name."""
    sys = ASSET_SYSTEM_PROMPT
    if methodology_context:
        sys += "\n\nContexte methodologique fourni:\n" + methodology_context
    if organization:
        sys += "\n\nOrganisation: " + organization
    return sys


class AssetDescriptionRequest(BaseModel):
    nom: str = ""
    type_label: str = ""
    proprietaire: str = ""
    fournisseur: str = ""
    os: str = ""
    criticite_label: str = ""
    methodology_context: str = ""
    organization: str = ""


class AssetTextResponse(BaseModel):
    text: str = ""


@router.post("/asset/suggest-description", response_model=AssetTextResponse)
async def asset_suggest_description(body: AssetDescriptionRequest,
                                   user: User = Depends(get_current_user),
                                   db: AsyncSession = Depends(get_db)):
    """Draft a concise description for one IT asset. The frontend posts the
    asset attributes; the methodology prompt is owned here, server-side."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)
    user_prompt = (
        "Redige une description concise (2-3 phrases) pour cet actif informatique:\n"
        f"- Nom: {body.nom or 'non defini'}\n"
        f"- Type: {body.type_label or 'non defini'}\n"
        f"- Proprietaire: {body.proprietaire or 'non defini'}\n"
        f"- Fournisseur: {body.fournisseur or 'non defini'}\n"
        f"- OS: {body.os or 'non defini'}\n"
        f"- Criticite: {body.criticite_label or 'non defini'}\n"
        "Reponds uniquement avec la description, sans introduction."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization),
        user_prompt, provider, model)
    return AssetTextResponse(text=(raw or "").strip())


class AssetPrincipeRequest(BaseModel):
    nom: str = ""
    criticite_label: str = ""
    members: list[str] = []
    methodology_context: str = ""
    organization: str = ""


@router.post("/asset/suggest-principe", response_model=AssetTextResponse)
async def asset_suggest_principe(body: AssetPrincipeRequest,
                                 user: User = Depends(get_current_user),
                                 db: AsyncSession = Depends(get_db)):
    """Draft the principle/function statement of an asset group. The frontend
    posts the group attributes and member labels; the prompt is built here."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)
    member_desc = "\n".join("- " + m for m in body.members) or "  (aucun actif assigne)"
    user_prompt = (
        "Redige le principe/fonction de ce groupe d'actifs (3-5 phrases):\n"
        f"- Nom du groupe: {body.nom or 'non defini'}\n"
        f"- Criticite: {body.criticite_label or 'non defini'}\n"
        f"- Actifs membres:\n{member_desc}\n"
        "Decris a quoi sert ce groupe, son role dans le SI, et pourquoi il est important. "
        "Reponds uniquement avec le texte du principe."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization),
        user_prompt, provider, model)
    return AssetTextResponse(text=(raw or "").strip())


class AssetRaciRequest(BaseModel):
    nom: str = ""
    principe: str = ""
    criticite_label: str = ""
    existing_activities: list[str] = []
    methodology_context: str = ""
    organization: str = ""


class RaciRow(BaseModel):
    activite: str = ""
    r: str = ""
    a: str = ""
    c: str = ""
    i: str = ""


class AssetRaciResponse(BaseModel):
    raci: list[RaciRow] = []


@router.post("/asset/suggest-raci", response_model=AssetRaciResponse)
async def asset_suggest_raci(body: AssetRaciRequest,
                             user: User = Depends(get_current_user),
                             db: AsyncSession = Depends(get_db)):
    """Propose a RACI matrix for an asset group. Returns a structured array of
    activity rows; the methodology prompt is owned server-side."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)
    user_prompt = (
        "Propose une matrice RACI pour ce groupe d'actifs:\n"
        f"- Nom: {body.nom or 'non defini'}\n"
        f"- Principe: {body.principe or 'non defini'}\n"
        f"- Criticite: {body.criticite_label or 'non defini'}\n\n"
        f"Activites existantes: {', '.join(body.existing_activities)}\n"
        "Roles: R (Responsable), A (Approbateur), C (Consulte), I (Informe)\n\n"
        "Reponds au format JSON strict — un tableau d'objets:\n"
        '[{"activite":"installation","r":"...","a":"...","c":"...","i":"..."},'
        '{"activite":"mco","r":"...","a":"...","c":"...","i":"..."},'
        '{"activite":"mcs","r":"...","a":"...","c":"...","i":"..."}]\n'
        "Tu peux proposer des activites supplementaires pertinentes au-dela des 3 par defaut.\n"
        "Utilise des noms de roles/services (DSI, RSSI, Metier, DG, Admin Sys, etc.), "
        "pas des noms de personnes."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization),
        user_prompt, provider, model)
    parsed = _parse_json_lax(raw)
    if not isinstance(parsed, list):
        raise HTTPException(status_code=502, detail="AI did not return a RACI array")
    rows = [
        RaciRow(
            activite=str(r.get("activite") or ""),
            r=str(r.get("r") or ""),
            a=str(r.get("a") or ""),
            c=str(r.get("c") or ""),
            i=str(r.get("i") or ""),
        )
        for r in parsed if isinstance(r, dict) and r.get("activite")
    ]
    return AssetRaciResponse(raci=rows)


class AssetPoliciesRequest(BaseModel):
    nom: str = ""
    principe: str = ""
    criticite_label: str = ""
    members: list[str] = []
    methodology_context: str = ""
    organization: str = ""


class AssetPoliciesResponse(BaseModel):
    politique_sauvegarde: dict = {}
    politique_supervision: dict = {}
    politique_maj: dict = {}


@router.post("/asset/suggest-policies", response_model=AssetPoliciesResponse)
async def asset_suggest_policies(body: AssetPoliciesRequest,
                                 user: User = Depends(get_current_user),
                                 db: AsyncSession = Depends(get_db)):
    """Propose backup / supervision / update policies for an asset group.
    Returns a structured object; the methodology prompt is owned here."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)
    member_desc = "\n".join("- " + m for m in body.members) or "  (aucun)"
    user_prompt = (
        "Propose des politiques de sauvegarde, supervision et mise a jour pour ce groupe d'actifs:\n"
        f"- Nom: {body.nom or 'non defini'}\n"
        f"- Principe: {body.principe or 'non defini'}\n"
        f"- Criticite: {body.criticite_label or 'non defini'}\n"
        f"- Actifs:\n{member_desc}\n\n"
        "Reponds au format JSON strict:\n"
        '{"politique_sauvegarde":{"frequence":"...","retention":"...","type":"...",'
        '"site_distant":true/false,"teste":true/false},'
        '"politique_supervision":{"outil":"...","perimetre":"...","alerting":true/false,'
        '"h24":true/false},'
        '"politique_maj":{"frequence":"...","fenetre":"...","validation":"...",'
        '"critique_delai":"..."}}\n'
        "Sois realiste et adapte a la criticite du groupe."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization),
        user_prompt, provider, model)
    parsed = _parse_json_lax(raw)
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=502, detail="AI did not return a policies object")
    return AssetPoliciesResponse(
        politique_sauvegarde=parsed.get("politique_sauvegarde") or {},
        politique_supervision=parsed.get("politique_supervision") or {},
        politique_maj=parsed.get("politique_maj") or {},
    )
