from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: float = 300.0):
        self.base_url = base_url
        self.model = model
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def generate(
        self, prompt: str, params: Optional[Dict[str, Any]] = None
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if params:
            payload.update(params)
        response = await self._client.post("/api/generate", json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "OllamaClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
