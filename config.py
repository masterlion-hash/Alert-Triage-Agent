# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""Central configuration. All tunables loaded from .env."""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # Elasticsearch
    elastic_url: str = os.getenv("ELASTIC_URL", "")
    elastic_username: str = os.getenv("ELASTIC_USERNAME", "")
    elastic_password: str = os.getenv("ELASTIC_PASSWORD", "")
    elastic_verify_ssl: bool = os.getenv("ELASTIC_VERIFY_SSL", "false").lower() == "true"
    elastic_index: str = os.getenv("ELASTIC_INDEX", ".alerts-security.alerts-default")
    elastic_event_indices: str = os.getenv("ELASTIC_EVENT_INDICES", "logs-*,filebeat-*,winlogbeat-*,auditbeat-*")
    elastic_timeout: int = int(os.getenv("ELASTIC_TIMEOUT", "30"))

    # Investigation
    related_events_window_min: int = int(os.getenv("RELATED_EVENTS_WINDOW_MIN", "15"))
    related_events_max: int = int(os.getenv("RELATED_EVENTS_MAX", "50"))

    # Threat intel
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    threat_intel_timeout: int = int(os.getenv("THREAT_INTEL_TIMEOUT", "10"))

    # Asset inventory
    asset_inventory_path: str = os.getenv("ASSET_INVENTORY_PATH", "assets.yml")

    # AI verdict backend — set AI_PROVIDER to: claude | ollama | openai_compat | none
    ai_provider: str = os.getenv("AI_PROVIDER", "none")

    # Claude (AI_PROVIDER=claude)
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    claude_model: str = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")

    # Ollama (AI_PROVIDER=ollama)
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2")

    # OpenAI-compatible API (AI_PROVIDER=openai_compat)
    openai_compat_url: str = os.getenv("OPENAI_COMPAT_URL", "")
    openai_compat_key: str = os.getenv("OPENAI_COMPAT_KEY", "")
    openai_compat_model: str = os.getenv("OPENAI_COMPAT_MODEL", "mistral")

    # HTTP server
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Public URL (ngrok or reverse proxy) — used for MCP endpoint display in the UI
    public_url: str = os.getenv("PUBLIC_URL", "")


config = Config()
