# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""Pluggable AI verdict backends.

Supported providers (set AI_PROVIDER in .env):
  claude        — Anthropic Claude API (ANTHROPIC_API_KEY required)
  ollama        — Ollama local LLM  (OLLAMA_URL, OLLAMA_MODEL)
  openai_compat — Any OpenAI-compatible API: LM Studio, vLLM, Groq, Together…
  none          — AI verdicts disabled (default)
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are an expert SOC analyst. You will be given a structured alert "
    "investigation report. Read every section carefully, then produce the "
    "JUDGEMENT RESPONSE as instructed at the bottom of the report. "
    "Be specific, cite exact timestamps and data lines. "
    "Do not invent information not present in the report."
)


@runtime_checkable
class AIProvider(Protocol):
    async def get_verdict(self, prompt: str) -> str: ...


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------

class _NoProvider:
    async def get_verdict(self, prompt: str) -> str:
        return ""


class _ClaudeProvider:
    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model

    async def get_verdict(self, prompt: str) -> str:
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
            msg = await client.messages.create(
                model=self._model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as exc:
            logger.warning("Claude verdict failed: %s", exc)
            return f"[Verdict unavailable: {exc}]"


class _OllamaProvider:
    def __init__(self, url: str, model: str) -> None:
        self._url = url.rstrip("/")
        self._model = model

    async def get_verdict(self, prompt: str) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    f"{self._url}/api/chat",
                    json={
                        "model": self._model,
                        "stream": False,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                    },
                )
                r.raise_for_status()
                return r.json()["message"]["content"]
        except Exception as exc:
            logger.warning("Ollama verdict failed: %s", exc)
            return f"[Verdict unavailable: {exc}]"


class _OpenAICompatProvider:
    def __init__(self, url: str, api_key: str, model: str) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._model = model

    async def get_verdict(self, prompt: str) -> str:
        try:
            import httpx
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    f"{self._url}/chat/completions",
                    headers=headers,
                    json={
                        "model": self._model,
                        "max_tokens": 1500,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                    },
                )
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("OpenAI-compat verdict failed: %s", exc)
            return f"[Verdict unavailable: {exc}]"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_provider(config: object) -> AIProvider:
    """Construct the correct provider from a config object."""
    provider = getattr(config, "ai_provider", "none").lower().strip()

    if provider == "claude":
        key = getattr(config, "anthropic_api_key", "")
        model = getattr(config, "claude_model", "claude-haiku-4-5-20251001")
        if not key:
            logger.warning("AI_PROVIDER=claude but ANTHROPIC_API_KEY is not set — verdicts disabled")
            return _NoProvider()
        logger.info("AI provider: Claude (%s)", model)
        return _ClaudeProvider(key, model)

    if provider == "ollama":
        url   = getattr(config, "ollama_url",   "http://localhost:11434")
        model = getattr(config, "ollama_model", "llama3.2")
        logger.info("AI provider: Ollama (%s @ %s)", model, url)
        return _OllamaProvider(url, model)

    if provider == "openai_compat":
        url   = getattr(config, "openai_compat_url",   "")
        key   = getattr(config, "openai_compat_key",   "")
        model = getattr(config, "openai_compat_model", "mistral")
        if not url:
            logger.warning("AI_PROVIDER=openai_compat but OPENAI_COMPAT_URL not set — verdicts disabled")
            return _NoProvider()
        logger.info("AI provider: OpenAI-compat (%s @ %s)", model, url)
        return _OpenAICompatProvider(url, key, model)

    if provider != "none":
        logger.warning("Unknown AI_PROVIDER=%r — verdicts disabled", provider)
    return _NoProvider()
