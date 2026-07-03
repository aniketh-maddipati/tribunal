"""LM client: the only network-touching code in Tribunal.

Speaks the OpenAI-compatible /chat/completions dialect so any local server
(LM Studio, llama.cpp, vLLM, ollama's compat endpoint) can sit behind it.
"""

from __future__ import annotations

import httpx


class LMClient:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._http = httpx.Client(timeout=120.0)

    def chat(self, messages: list[dict[str, str]]) -> str:
        try:
            resp = self._http.post(
                f"{self.base_url}/chat/completions",
                json={"model": self.model, "messages": messages, "temperature": 0},
            )
        except httpx.TransportError as exc:
            raise RuntimeError(f"could not reach LLM server at {self.base_url}: {exc}") from exc
        resp.raise_for_status()
        payload = resp.json()
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"malformed chat completion from {self.base_url}: {exc}") from exc
        if not isinstance(content, str):
            raise RuntimeError(f"non-string message content from {self.base_url}: {content!r}")
        return content

    def close(self) -> None:
        self._http.close()
