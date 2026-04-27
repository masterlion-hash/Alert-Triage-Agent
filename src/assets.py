"""Asset inventory.

Loads a YAML or JSON file describing the hosts in your environment and
returns context (criticality, owner, environment, tags, OS, role) for a
given hostname. The file is loaded once at startup and cached in memory.

Why a flat file: most small-to-mid environments don't have a real CMDB,
and the ones that do usually expose it via a custom API. A YAML file
gives you a working starting point that you can replace with an API
adapter when you need to.

File format (YAML example, see assets.example.yml):
    hosts:
      WIN-DC01:
        criticality: critical
        environment: production
        role: domain_controller
        os: Windows Server 2022
        owner: infra-team@example.com
        tags: [tier-0, domain-controller]
      ubuntu-edge-03:
        criticality: medium
        environment: production
        role: edge_proxy
        os: Ubuntu 22.04
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AssetInventory:
    """In-memory asset lookup loaded from a YAML or JSON file."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._hosts: dict[str, dict[str, Any]] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            logger.warning(
                "Asset inventory not found at %s — host context disabled",
                self._path,
            )
            return

        try:
            text = self._path.read_text(encoding="utf-8")
            if self._path.suffix in (".yml", ".yaml"):
                try:
                    import yaml  # type: ignore[import-not-found]
                except ImportError as exc:
                    logger.error(
                        "PyYAML required for %s. Run: pip install pyyaml",
                        self._path,
                    )
                    raise RuntimeError("pyyaml not installed") from exc
                data = yaml.safe_load(text) or {}
            else:
                data = json.loads(text)

            raw_hosts = data.get("hosts", {})
            # Normalise hostname keys to lowercase for case-insensitive lookup
            self._hosts = {
                str(name).lower(): info for name, info in raw_hosts.items()
            }
            self._loaded = True
            logger.info(
                "Loaded asset inventory: %d host(s) from %s",
                len(self._hosts),
                self._path,
            )
        except Exception as exc:
            logger.error("Failed to load asset inventory: %s", exc)

    def lookup(self, hostname: str | None) -> dict[str, Any]:
        """Return asset context for a hostname.

        Always returns a dict — `known: False` when nothing is found, so
        the LLM can still see "this host is not in the inventory" as a
        signal in itself.
        """
        if not hostname:
            return {"known": False, "reason": "no hostname provided"}

        info = self._hosts.get(hostname.lower())
        if not info:
            return {
                "known": False,
                "hostname": hostname,
                "reason": "not in inventory",
            }

        return {
            "known": True,
            "hostname": hostname,
            "criticality": info.get("criticality", "unknown"),
            "environment": info.get("environment"),
            "role": info.get("role"),
            "os": info.get("os"),
            "owner": info.get("owner"),
            "tags": info.get("tags", []),
            "notes": info.get("notes"),
        }
