"""Format raw Elastic alert documents into LLM-readable summaries."""

from __future__ import annotations

from typing import Any


def _get(doc: dict[str, Any], dotted_path: str, default: str = "unknown") -> str:
    """Read a dotted key out of an Elastic _source dict.

    Elastic returns nested objects, but `_source` filtering can flatten
    them into dotted-key strings depending on the index mapping. This
    handles both shapes.
    """
    if dotted_path in doc:
        value = doc[dotted_path]
        return str(value) if value not in (None, "") else default

    parts = dotted_path.split(".")
    cursor: Any = doc
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            return default
        cursor = cursor[part]

    if cursor in (None, ""):
        return default
    if isinstance(cursor, list):
        return ", ".join(str(v) for v in cursor) or default
    return str(cursor)


def format_alert_summary(alerts: list[dict[str, Any]]) -> str:
    """Render a list of alert _source docs as a single human-readable string.

    Output is structured so the model can scan it quickly: one block per
    alert, with clear labels, separated by a divider line.
    """
    blocks: list[str] = [f"Found {len(alerts)} open alert(s):", ""]

    for idx, alert in enumerate(alerts, start=1):
        rule = _get(alert, "kibana.alert.rule.name", "Unnamed rule")
        severity = _get(alert, "kibana.alert.severity")
        risk_score = _get(alert, "kibana.alert.risk_score")
        timestamp = _get(alert, "@timestamp")
        host = _get(alert, "host.name")
        if host == "unknown":
            host = _get(alert, "host.hostname")
        user = _get(alert, "user.name")
        src_ip = _get(alert, "source.ip")
        dst_ip = _get(alert, "destination.ip")
        reason = _get(alert, "kibana.alert.reason", "")

        block = [
            f"[{idx}] {rule}",
            f"    Severity:  {severity} (risk_score={risk_score})",
            f"    Time:      {timestamp}",
            f"    Host:      {host}",
            f"    User:      {user}",
            f"    Source IP: {src_ip}",
            f"    Dest IP:   {dst_ip}",
        ]
        if reason and reason != "unknown":
            # Trim very long reason fields — they can include full event JSON
            trimmed = reason if len(reason) <= 400 else reason[:400] + "..."
            block.append(f"    Reason:    {trimmed}")

        blocks.append("\n".join(block))
        blocks.append("-" * 60)

    return "\n".join(blocks)
