"""Asset AI endpoints.

The shared /api/ai proxy (provider registry, key/settings management,
/complete, /runtime, /config, /keys, /validate-key, the LLM dispatch) lives in
src/ai_proxy_common.py. Only the asset-inventory domain prompt and its four
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
    "You are an expert in IT asset management and information-system security. "
    "You help document the asset inventory of an organisation. "
    "Respond in {lang}, in a structured and concise way. "
    "Use the professional vocabulary of a CISO or a CIO."
)


def _lang_name(language: str) -> str:
    return "French" if (language or "").strip().lower().startswith("fr") else "English"


def _asset_system(methodology_context: str = "", organization: str = "",
                  language: str = "en") -> str:
    """Build the system prompt: base methodology + optional user-supplied
    methodological context + optional organization name."""
    sys = ASSET_SYSTEM_PROMPT.format(lang=_lang_name(language))
    if methodology_context:
        sys += "\n\nMethodological context provided:\n" + methodology_context
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
    language: str = "en"


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
        "Write a concise description (2-3 sentences) of this IT asset:\n"
        f"- Name: {body.nom or 'not set'}\n"
        f"- Type: {body.type_label or 'not set'}\n"
        f"- Owner: {body.proprietaire or 'not set'}\n"
        f"- Vendor: {body.fournisseur or 'not set'}\n"
        f"- OS: {body.os or 'not set'}\n"
        f"- Criticality: {body.criticite_label or 'not set'}\n"
        "Respond with the description only, without an introduction."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization, body.language),
        user_prompt, provider, model)
    return AssetTextResponse(text=(raw or "").strip())


class AssetPrincipeRequest(BaseModel):
    nom: str = ""
    criticite_label: str = ""
    members: list[str] = []
    methodology_context: str = ""
    organization: str = ""
    language: str = "en"


@router.post("/asset/suggest-principe", response_model=AssetTextResponse)
async def asset_suggest_principe(body: AssetPrincipeRequest,
                                 user: User = Depends(get_current_user),
                                 db: AsyncSession = Depends(get_db)):
    """Draft the principle/function statement of an asset group. The frontend
    posts the group attributes and member labels; the prompt is built here."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)
    member_desc = "\n".join("- " + m for m in body.members) or "  (no asset assigned)"
    user_prompt = (
        "Write the principle/function of this asset group (3-5 sentences):\n"
        f"- Group name: {body.nom or 'not set'}\n"
        f"- Criticality: {body.criticite_label or 'not set'}\n"
        f"- Member assets:\n{member_desc}\n"
        "Describe what this group is for, its role in the information system, and why "
        "it matters. Respond with the text of the principle only."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization, body.language),
        user_prompt, provider, model)
    return AssetTextResponse(text=(raw or "").strip())


class AssetRaciRequest(BaseModel):
    nom: str = ""
    principe: str = ""
    criticite_label: str = ""
    existing_activities: list[str] = []
    methodology_context: str = ""
    organization: str = ""
    language: str = "en"


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
        "Suggest a RACI matrix for this asset group:\n"
        f"- Name: {body.nom or 'not set'}\n"
        f"- Principle: {body.principe or 'not set'}\n"
        f"- Criticality: {body.criticite_label or 'not set'}\n\n"
        f"Existing activities: {', '.join(body.existing_activities)}\n"
        "Roles: R (Responsible), A (Accountable), C (Consulted), I (Informed)\n\n"
        "Respond in strict JSON — an array of objects, with these keys as written:\n"
        '[{"activite":"installation","r":"...","a":"...","c":"...","i":"..."},'
        '{"activite":"mco","r":"...","a":"...","c":"...","i":"..."},'
        '{"activite":"mcs","r":"...","a":"...","c":"...","i":"..."}]\n'
        "You may add relevant activities beyond the 3 default ones.\n"
        "Use names of roles or departments (CIO, CISO, business owner, executive "
        "management, system administrators, etc.), not names of people."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization, body.language),
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
    language: str = "en"


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
    member_desc = "\n".join("- " + m for m in body.members) or "  (none)"
    user_prompt = (
        "Suggest backup, monitoring and update policies for this asset group:\n"
        f"- Name: {body.nom or 'not set'}\n"
        f"- Principle: {body.principe or 'not set'}\n"
        f"- Criticality: {body.criticite_label or 'not set'}\n"
        f"- Assets:\n{member_desc}\n\n"
        "Respond in strict JSON, with these keys as written:\n"
        '{"politique_sauvegarde":{"frequence":"...","retention":"...","type":"...",'
        '"site_distant":true/false,"teste":true/false},'
        '"politique_supervision":{"outil":"...","perimetre":"...","alerting":true/false,'
        '"h24":true/false},'
        '"politique_maj":{"frequence":"...","fenetre":"...","validation":"...",'
        '"critique_delai":"..."}}\n'
        "Be realistic and fit the criticality of the group."
    )
    raw = await _provider_complete(
        db, _asset_system(body.methodology_context, body.organization, body.language),
        user_prompt, provider, model)
    parsed = _parse_json_lax(raw)
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=502, detail="AI did not return a policies object")
    return AssetPoliciesResponse(
        politique_sauvegarde=parsed.get("politique_sauvegarde") or {},
        politique_supervision=parsed.get("politique_supervision") or {},
        politique_maj=parsed.get("politique_maj") or {},
    )
