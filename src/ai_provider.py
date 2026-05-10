# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""Pluggable AI verdict backends.

Supported providers (set AI_PROVIDER in .env):
  claude        — Anthropic Claude API (ANTHROPIC_API_KEY required)
  ollama        — Ollama local LLM  (OLLAMA_URL, OLLAMA_MODEL)
  openai_compat — Any OpenAI-compatible API: LM Studio, vLLM, Groq, Together…
  none          — AI verdicts disabled (default)

All providers expose an async `get_verdict(prompt)` and `health_check()` that
returns `(ok, message)` so the server can surface actionable startup errors.
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
    name: str
    async def get_verdict(self, prompt: str) -> str: ...
    async def health_check(self) -> tuple[bool, str]: ...


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------

class _NoProvider:
    name = "none"

    async def get_verdict(self, prompt: str) -> str:
        return ""

    async def health_check(self) -> tuple[bool, str]:
        return True, "AI verdicts disabled"


class _ClaudeProvider:
    def __init__(self, api_key: str, model: str, timeout: int = 180) -> None:
        self.name = f"claude/{model}"
        self._model = model
        self._api_key = api_key
        self._timeout = timeout
        self._client = None
        try:
            import anthropic
            self._client = anthropic.AsyncAnthropic(
                api_key=api_key, timeout=timeout
            )
        except ImportError:
            logger.error(
                "anthropic package not installed — run: pip install 'anthropic>=0.40.0'"
            )

    async def get_verdict(self, prompt: str) -> str:
        if self._client is None:
            return (
                "[Verdict unavailable: anthropic SDK not installed. "
                "Activate the venv and run:  pip install 'anthropic>=0.40.0']"
            )
        try:
            msg = await self._client.messages.create(
                model=self._model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as exc:
            logger.warning("Claude verdict failed: %s", exc)
            return f"[Verdict unavailable: Claude API error — {exc}]"

    async def health_check(self) -> tuple[bool, str]:
        if self._client is None:
            return False, "anthropic SDK not installed (pip install anthropic)"
        if not self._api_key:
            return False, "ANTHROPIC_API_KEY is not set"
        # Minimal ping — costs ~5 tokens and validates key + model.
        try:
            await self._client.messages.create(
                model=self._model,
                max_tokens=5,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True, f"Claude API reachable (model={self._model})"
        except Exception as exc:
            return False, f"Claude API unreachable: {exc}"


class _OllamaProvider:
    def __init__(self, url: str, model: str, timeout: int = 180) -> None:
        self._url = url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self.name = f"ollama/{model}"

    def _hint(self) -> str:
        return (
            f"Is Ollama running?  Start it with:  ollama serve\n"
            f"            Pull the model:  ollama pull {self._model}\n"
            f"            Configured URL:  {self._url}"
        )

    async def get_verdict(self, prompt: str) -> str:
        try:
            import httpx
        except ImportError:
            return "[Verdict unavailable: httpx not installed]"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
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
        except httpx.ConnectError as exc:
            logger.warning("Ollama unreachable at %s: %s", self._url, exc)
            return (
                f"[Verdict unavailable: cannot reach Ollama at {self._url}.\n"
                f" {self._hint()}]"
            )
        except httpx.ReadTimeout:
            logger.warning("Ollama timed out after %ss on model %s", self._timeout, self._model)
            return (
                f"[Verdict unavailable: Ollama timed out after {self._timeout}s.\n"
                f" The model `{self._model}` may be too large for this hardware,\n"
                f" or it is loading for the first time. Try a smaller model or\n"
                f" raise AI_TIMEOUT in .env.]"
            )
        except Exception as exc:
            logger.warning("Ollama verdict failed: %s", exc)
            return f"[Verdict unavailable: Ollama error — {exc}]"

        if r.status_code == 404:
            # Ollama returns 404 when the model isn't pulled.
            try:
                detail = r.json().get("error", "")
            except Exception:
                detail = r.text
            return (
                f"[Verdict unavailable: model `{self._model}` not found on Ollama.\n"
                f" Pull it with:  ollama pull {self._model}\n"
                f" Server said: {detail}]"
            )
        try:
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            return f"[Verdict unavailable: bad Ollama response — {exc}]"

        msg = data.get("message") or {}
        content = msg.get("content")
        if not content:
            return f"[Verdict unavailable: Ollama returned no content — {data}]"
        return content

    async def health_check(self) -> tuple[bool, str]:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self._url}/api/tags")
        except Exception as exc:
            return False, (
                f"Ollama not reachable at {self._url} ({exc.__class__.__name__}). "
                f"Start it with:  ollama serve"
            )
        if r.status_code != 200:
            return False, f"Ollama returned HTTP {r.status_code} on /api/tags"
        try:
            tags = [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            tags = []
        # Match the model with or without an explicit ":tag" suffix.
        wanted = self._model
        wanted_base = wanted.split(":")[0]
        have = any(t == wanted or t.split(":")[0] == wanted_base for t in tags)
        if not have:
            return False, (
                f"Ollama is up but model `{wanted}` is not pulled. "
                f"Run:  ollama pull {wanted}    "
                f"(installed: {', '.join(tags) or 'none'})"
            )
        return True, f"Ollama OK (model `{wanted}` available at {self._url})"


class _OpenAICompatProvider:
    def __init__(self, url: str, api_key: str, model: str, timeout: int = 180) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self.name = f"openai_compat/{model}"

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    async def get_verdict(self, prompt: str) -> str:
        try:
            import httpx
        except ImportError:
            return "[Verdict unavailable: httpx not installed]"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.post(
                    f"{self._url}/chat/completions",
                    headers=self._headers(),
                    json={
                        "model": self._model,
                        "max_tokens": 1500,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                    },
                )
        except httpx.ConnectError as exc:
            logger.warning("OpenAI-compat unreachable at %s: %s", self._url, exc)
            return (
                f"[Verdict unavailable: cannot reach API at {self._url}.\n"
                f" Check OPENAI_COMPAT_URL and that the backend is running.]"
            )
        except httpx.ReadTimeout:
            return (
                f"[Verdict unavailable: API timed out after {self._timeout}s.\n"
                f" Raise AI_TIMEOUT in .env or pick a faster model.]"
            )
        except Exception as exc:
            logger.warning("OpenAI-compat verdict failed: %s", exc)
            return f"[Verdict unavailable: API error — {exc}]"

        if r.status_code == 401:
            return "[Verdict unavailable: 401 Unauthorized — check OPENAI_COMPAT_KEY]"
        if r.status_code == 404:
            return (
                f"[Verdict unavailable: 404 from {self._url}/chat/completions — "
                f"check OPENAI_COMPAT_URL (it must be the OpenAI base URL, e.g. "
                f"http://localhost:1234/v1)]"
            )
        try:
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            body = r.text[:200] if hasattr(r, "text") else ""
            return f"[Verdict unavailable: bad API response — {exc}  body={body}]"

    async def health_check(self) -> tuple[bool, str]:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                # /models is the standard OpenAI discovery endpoint; most
                # compat servers (LM Studio, vLLM, Groq, Together) implement it.
                r = await client.get(f"{self._url}/models", headers=self._headers())
        except Exception as exc:
            return False, (
                f"OpenAI-compat API not reachable at {self._url} "
                f"({exc.__class__.__name__})"
            )
        if r.status_code in (401, 403):
            return False, f"OpenAI-compat auth failed (HTTP {r.status_code}) — check OPENAI_COMPAT_KEY"
        if r.status_code >= 400:
            return False, f"OpenAI-compat API returned HTTP {r.status_code} on /models"
        return True, f"OpenAI-compat API reachable at {self._url} (model={self._model})"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_provider(config: object) -> AIProvider:
    """Construct the correct provider from a config object."""
    provider = getattr(config, "ai_provider", "none").lower().strip()
    timeout = int(getattr(config, "ai_timeout", 180))

    if provider == "claude":
        key = getattr(config, "anthropic_api_key", "")
        model = getattr(config, "claude_model", "claude-haiku-4-5-20251001")
        if not key:
            logger.warning("AI_PROVIDER=claude but ANTHROPIC_API_KEY is not set — verdicts disabled")
            return _NoProvider()
        logger.info("AI provider: Claude (%s)", model)
        return _ClaudeProvider(key, model, timeout=timeout)

    if provider == "ollama":
        url   = getattr(config, "ollama_url",   "http://localhost:11434")
        model = getattr(config, "ollama_model", "llama3.2")
        logger.info("AI provider: Ollama (%s @ %s)", model, url)
        return _OllamaProvider(url, model, timeout=timeout)

    if provider == "openai_compat":
        url   = getattr(config, "openai_compat_url",   "")
        key   = getattr(config, "openai_compat_key",   "")
        model = getattr(config, "openai_compat_model", "mistral")
        if not url:
            logger.warning("AI_PROVIDER=openai_compat but OPENAI_COMPAT_URL not set — verdicts disabled")
            return _NoProvider()
        logger.info("AI provider: OpenAI-compat (%s @ %s)", model, url)
        return _OpenAICompatProvider(url, key, model, timeout=timeout)

    if provider != "none":
        logger.warning("Unknown AI_PROVIDER=%r — verdicts disabled", provider)
    return _NoProvider()
