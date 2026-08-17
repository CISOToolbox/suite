from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger("access-backend")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 3
MAX_CONCURRENT = 20


async def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        })
        if resp.status_code != 200:
            detail = resp.text[:500]
            raise Exception(f"Token request failed ({resp.status_code}): {detail}")
        return resp.json()["access_token"]


async def graph_get(token: str, url: str, client: httpx.AsyncClient) -> dict:
    for attempt in range(MAX_RETRIES):
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
            logger.warning("Graph API 429 — retry in %ds (attempt %d/%d)", retry_after, attempt + 1, MAX_RETRIES)
            await asyncio.sleep(retry_after)
            continue
        resp.raise_for_status()
        return resp.json()
    raise Exception(f"Graph API rate limited after {MAX_RETRIES} retries: {url}")


async def graph_get_all(token: str, url: str, client: httpx.AsyncClient) -> list:
    items: list = []
    while url:
        data = await graph_get(token, url, client)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return items
