"""Threat intelligence enrichment.

Wraps two free-tier APIs that cover the majority of L1 triage needs:
  - AbuseIPDB: IP reputation, abuse confidence score (0-100)
  - VirusTotal: file hashes, domains, IPs (consensus malicious count)

Both clients degrade gracefully: if no API key is set, lookups return
a structured "skipped" result rather than raising, so investigations
still work without intel configured.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Skip RFC1918, loopback, link-local — no point sending internal IPs to
# external reputation APIs (privacy + wasted quota).
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.", "255.")
_PRIVATE_172_RE = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")


def is_internal_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local addresses."""
    if not ip or ":" in ip:  # crude IPv6 short-circuit
        return False
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if _PRIVATE_172_RE.match(ip):
        return True
    return False


class ThreatIntelClient:
    """Combined AbuseIPDB + VirusTotal client. Async, no shared state."""

    def __init__(
        self,
        abuseipdb_key: str = "",
        virustotal_key: str = "",
        timeout: int = 10,
    ) -> None:
        self._abuseipdb_key = abuseipdb_key
        self._virustotal_key = virustotal_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> "ThreatIntelClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # IP reputation
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Return reputation summary for an IP.

        Output shape is normalised so the LLM sees a consistent structure:
            {
              "ip": "1.2.3.4",
              "internal": False,
              "abuseipdb": {...} | None,
              "virustotal": {...} | None,
              "verdict": "malicious" | "suspicious" | "clean" | "unknown"
            }
        """
        result: dict[str, Any] = {
            "ip": ip,
            "internal": is_internal_ip(ip),
            "abuseipdb": None,
            "virustotal": None,
            "verdict": "unknown",
        }

        if result["internal"]:
            result["verdict"] = "internal"
            return result

        # Run both lookups; tolerate per-source failures
        if self._abuseipdb_key:
            result["abuseipdb"] = await self._abuseipdb_ip(ip)
        if self._virustotal_key:
            result["virustotal"] = await self._virustotal_ip(ip)

        result["verdict"] = self._verdict_from_ip_intel(result)
        return result

    async def _abuseipdb_ip(self, ip: str) -> dict[str, Any] | None:
        try:
            r = await self._client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self._abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType"),
            }
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return {"error": str(exc)}

    async def _virustotal_ip(self, ip: str) -> dict[str, Any] | None:
        try:
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self._virustotal_key},
            )
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation", 0),
            }
        except Exception as exc:
            logger.warning("VirusTotal IP lookup failed for %s: %s", ip, exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # File hash reputation
    # ------------------------------------------------------------------

    async def lookup_hash(self, sha256: str) -> dict[str, Any]:
        """Return VirusTotal verdict for a SHA-256 file hash."""
        result: dict[str, Any] = {
            "hash": sha256,
            "virustotal": None,
            "verdict": "unknown",
        }
        if not self._virustotal_key:
            return result

        try:
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self._virustotal_key},
            )
            if r.status_code == 404:
                result["virustotal"] = {"found": False}
                result["verdict"] = "unknown"
                return result
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["virustotal"] = {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "names": attrs.get("names", [])[:5],
                "type_description": attrs.get("type_description"),
                "first_seen": attrs.get("first_submission_date"),
                "reputation": attrs.get("reputation", 0),
            }
            result["verdict"] = self._verdict_from_vt_stats(stats)
        except Exception as exc:
            logger.warning("VirusTotal hash lookup failed for %s: %s", sha256, exc)
            result["virustotal"] = {"error": str(exc)}
        return result

    # ------------------------------------------------------------------
    # Domain reputation
    # ------------------------------------------------------------------

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Return VirusTotal verdict for a domain."""
        result: dict[str, Any] = {
            "domain": domain,
            "virustotal": None,
            "verdict": "unknown",
        }
        if not self._virustotal_key:
            return result

        try:
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self._virustotal_key},
            )
            if r.status_code == 404:
                result["verdict"] = "unknown"
                return result
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
                "reputation": attrs.get("reputation", 0),
            }
            result["verdict"] = self._verdict_from_vt_stats(stats)
        except Exception as exc:
            logger.warning("VirusTotal domain lookup failed for %s: %s", domain, exc)
            result["virustotal"] = {"error": str(exc)}
        return result

    # ------------------------------------------------------------------
    # Verdict derivation (kept simple — model does the real reasoning)
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_from_vt_stats(stats: dict) -> str:
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        if mal >= 5:
            return "malicious"
        if mal >= 1 or sus >= 3:
            return "suspicious"
        if stats.get("harmless", 0) + stats.get("undetected", 0) > 0:
            return "clean"
        return "unknown"

    @staticmethod
    def _verdict_from_ip_intel(intel: dict) -> str:
        abuse = intel.get("abuseipdb") or {}
        vt = intel.get("virustotal") or {}
        score = abuse.get("abuse_confidence_score", 0)
        vt_mal = vt.get("malicious", 0)
        if score >= 75 or vt_mal >= 5:
            return "malicious"
        if score >= 25 or vt_mal >= 1 or abuse.get("is_tor"):
            return "suspicious"
        if score == 0 and vt_mal == 0 and abuse:
            return "clean"
        return "unknown"
