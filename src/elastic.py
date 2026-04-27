"""Async Elasticsearch client — basic auth, supports v2 investigation ops."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ElasticClient:
    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        verify_ssl: bool = False,
        index: str = ".alerts-security.alerts-default",
        event_indices: str = "logs-*,filebeat-*,winlogbeat-*,auditbeat-*",
        timeout: int = 30,
    ) -> None:
        if not url:
            raise ValueError("ELASTIC_URL is required")
        if not username or not password:
            raise ValueError("ELASTIC_USERNAME and ELASTIC_PASSWORD are required")

        self._url = url.rstrip("/")
        self._index = index
        self._event_indices = event_indices
        self._client = httpx.AsyncClient(
            base_url=self._url,
            auth=(username, password),
            headers={"Content-Type": "application/json"},
            verify=verify_ssl,
            timeout=timeout,
        )

    async def __aenter__(self) -> "ElasticClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.aclose()

    async def fetch_open_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [
                {"term": {"kibana.alert.workflow_status": "open"}}
            ]}},
            "_source": [
                "@timestamp",
                "kibana.alert.rule.name",
                "kibana.alert.severity",
                "kibana.alert.risk_score",
                "kibana.alert.reason",
                "kibana.alert.workflow_status",
                "host.name", "host.hostname",
                "user.name", "source.ip", "destination.ip",
            ],
        }
        resp = await self._post(f"/{self._index}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        results = []
        for h in hits:
            doc = h.get("_source", {})
            doc["_alert_id"] = h.get("_id")
            results.append(doc)
        return results

    async def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        # Use term on _id inside bool/filter — the ids query triggers the
        # multi-index alias restriction on .alerts-security.alerts-default
        # even with _search.  A regular term query does not.
        body = {"size": 1, "query": {"bool": {"filter": [{"term": {"_id": alert_id}}]}}}
        resp = await self._post(f"/{self._index}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return None
        doc = hits[0].get("_source", {})
        doc["_alert_id"] = hits[0].get("_id")
        return doc

    async def get_related_events(
        self,
        host: str | None,
        user: str | None,
        center_ts: str,
        window_minutes: int = 15,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not host and not user:
            return []
        try:
            center = datetime.fromisoformat(center_ts.replace("Z", "+00:00"))
        except ValueError:
            logger.warning("Could not parse timestamp: %s", center_ts)
            return []

        start = (center - timedelta(minutes=window_minutes)).isoformat()
        end   = (center + timedelta(minutes=window_minutes)).isoformat()

        should: list[dict[str, Any]] = []
        if host:
            should.append({"term": {"host.name": host}})
            should.append({"term": {"host.hostname": host}})
        if user:
            should.append({"term": {"user.name": user}})

        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {
                "filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}],
                "should": should,
                "minimum_should_match": 1,
            }},
            "_source": [
                "@timestamp", "event.action", "event.category", "event.type",
                "event.outcome", "host.name", "host.hostname", "user.name",
                "process.name", "process.command_line", "process.executable",
                "process.parent.name", "source.ip", "destination.ip",
                "destination.port", "destination.domain",
                "file.path", "file.hash.sha256", "message",
            ],
        }
        resp = await self._post(f"/{self._event_indices}/_search", body)
        return [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]

    async def _post(self, path: str, body: dict) -> dict:
        logger.debug("POST %s", path)
        resp = await self._client.post(path, json=body)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Elasticsearch returned {resp.status_code}: {resp.text[:500]}"
            )
        return resp.json()
