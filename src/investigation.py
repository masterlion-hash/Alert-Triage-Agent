# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""Investigation orchestrator.

Pulls together everything Claude needs to judge an alert as TP or FP:
  - the alert itself
  - asset context for the host
  - threat-intel verdicts on every IP, hash, and domain in the alert
  - related events on the same host/user in a +/-window
  - timeline of those events

Returns a structured text blob with explicit sections and a fixed
template at the end that prompts Claude to produce a consistent verdict.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.ai_provider import AIProvider, _NoProvider
from src.assets import AssetInventory
from src.elastic import ElasticClient
from src.threat_intel import ThreatIntelClient, is_internal_ip
from src.triage import _get  # reuse the dotted-key helper

logger = logging.getLogger(__name__)

# Indicators we extract from an alert and try to enrich
HASH_FIELDS = (
    "process.hash.sha256",
    "file.hash.sha256",
    "kibana.alert.process.hash.sha256",
    "kibana.alert.file.hash.sha256",
)
IP_FIELDS = ("source.ip", "destination.ip")
DOMAIN_FIELDS = ("destination.domain", "url.domain", "dns.question.name")


async def investigate(
    alert_id: str,
    elastic: ElasticClient,
    intel: ThreatIntelClient,
    assets: AssetInventory,
    related_window_min: int,
    related_max: int,
    ai_provider: AIProvider | None = None,
) -> str:
    """Run a full investigation and return a markdown-style text blob."""

    # 1. Fetch the alert itself
    alert = await elastic.get_alert_by_id(alert_id)
    if not alert:
        return f"ERROR: alert with _id `{alert_id}` not found."

    timestamp = _get(alert, "@timestamp")
    rule = _get(alert, "kibana.alert.rule.name", "Unnamed rule")
    severity = _get(alert, "kibana.alert.severity")
    risk_score = _get(alert, "kibana.alert.risk_score")
    reason = _get(alert, "kibana.alert.reason", "")
    host = _get(alert, "host.name")
    if host == "unknown":
        host = _get(alert, "host.hostname")
    user = _get(alert, "user.name")

    # 2. Extract indicators from the alert
    ips_to_check: list[str] = []
    hashes_to_check: list[str] = []
    domains_to_check: list[str] = []

    for f in IP_FIELDS:
        v = _get(alert, f)
        if v != "unknown" and v not in ips_to_check:
            ips_to_check.append(v)
    for f in HASH_FIELDS:
        v = _get(alert, f)
        if v != "unknown" and len(v) == 64 and v not in hashes_to_check:
            hashes_to_check.append(v)
    for f in DOMAIN_FIELDS:
        v = _get(alert, f)
        if v != "unknown" and "." in v and v not in domains_to_check:
            domains_to_check.append(v)

    # 3. Run all enrichments in parallel
    asset_ctx = assets.lookup(host if host != "unknown" else None)

    intel_tasks: list[asyncio.Task] = []
    intel_keys: list[tuple[str, str]] = []  # (kind, value) parallel to tasks
    for ip in ips_to_check:
        intel_tasks.append(asyncio.create_task(intel.lookup_ip(ip)))
        intel_keys.append(("ip", ip))
    for h in hashes_to_check:
        intel_tasks.append(asyncio.create_task(intel.lookup_hash(h)))
        intel_keys.append(("hash", h))
    for d in domains_to_check:
        intel_tasks.append(asyncio.create_task(intel.lookup_domain(d)))
        intel_keys.append(("domain", d))

    related_task = asyncio.create_task(
        elastic.get_related_events(
            host=host if host != "unknown" else None,
            user=user if user != "unknown" else None,
            center_ts=timestamp,
            window_minutes=related_window_min,
            limit=related_max,
        )
    )

    intel_results = await asyncio.gather(*intel_tasks, return_exceptions=True)
    related_events = await related_task

    # 4. Render the report
    report = _render_report(
        alert=alert,
        rule=rule,
        severity=severity,
        risk_score=risk_score,
        timestamp=timestamp,
        host=host,
        user=user,
        reason=reason,
        asset_ctx=asset_ctx,
        intel_keys=intel_keys,
        intel_results=intel_results,
        related_events=related_events,
        related_window_min=related_window_min,
    )

    # 5. Get AI verdict if a provider is configured
    if ai_provider and not isinstance(ai_provider, _NoProvider):
        verdict = await ai_provider.get_verdict(report + _JUDGEMENT_PROMPT)
        if verdict:
            report = report + "\n\n" + verdict

    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_report(
    alert: dict[str, Any],
    rule: str,
    severity: str,
    risk_score: str,
    timestamp: str,
    host: str,
    user: str,
    reason: str,
    asset_ctx: dict[str, Any],
    intel_keys: list[tuple[str, str]],
    intel_results: list[Any],
    related_events: list[dict[str, Any]],
    related_window_min: int,
) -> str:
    out: list[str] = []

    # ---- Section 1: alert summary ----
    out.append("=" * 70)
    out.append("ALERT INVESTIGATION REPORT")
    out.append("=" * 70)
    out.append("")
    out.append("## ALERT")
    out.append(f"Rule:       {rule}")
    out.append(f"Severity:   {severity} (risk_score={risk_score})")
    out.append(f"Timestamp:  {timestamp}")
    out.append(f"Host:       {host}")
    out.append(f"User:       {user}")
    out.append(f"Alert ID:   {alert.get('_alert_id', 'unknown')}")
    if reason and reason != "unknown":
        trimmed = reason if len(reason) <= 600 else reason[:600] + "..."
        out.append(f"Reason:     {trimmed}")
    out.append("")

    # ---- Section 2: asset context ----
    out.append("## HOST CONTEXT")
    if asset_ctx.get("known"):
        out.append(f"Criticality: {asset_ctx.get('criticality')}")
        out.append(f"Environment: {asset_ctx.get('environment')}")
        out.append(f"Role:        {asset_ctx.get('role')}")
        out.append(f"OS:          {asset_ctx.get('os')}")
        out.append(f"Owner:       {asset_ctx.get('owner')}")
        if asset_ctx.get("tags"):
            out.append(f"Tags:        {', '.join(asset_ctx['tags'])}")
        if asset_ctx.get("notes"):
            out.append(f"Notes:       {asset_ctx['notes'].strip()}")
    else:
        out.append(
            f"Host not in asset inventory ({asset_ctx.get('reason', 'unknown')})."
        )
        out.append("Treat as unknown criticality — request asset owner to confirm.")
    out.append("")

    # ---- Section 3: threat intel ----
    out.append("## THREAT INTELLIGENCE")
    if not intel_keys:
        out.append("No external indicators (IPs, hashes, domains) in alert.")
    else:
        for (kind, value), result in zip(intel_keys, intel_results):
            if isinstance(result, Exception):
                out.append(f"[{kind}] {value}: lookup failed ({result})")
                continue
            out.append(_render_intel_line(kind, value, result))
    out.append("")

    # ---- Section 4: related events timeline ----
    out.append(
        f"## RELATED EVENTS (+/- {related_window_min} min, "
        f"same host or user)"
    )
    if not related_events:
        out.append(
            "No related events found. Either the host/user was quiet around "
            "the alert, or event indices aren't being shipped from this host."
        )
    else:
        out.append(f"Found {len(related_events)} event(s):")
        out.append("")
        for ev in related_events:
            out.append(_render_event_line(ev))
    out.append("")

    return "\n".join(out)


_JUDGEMENT_PROMPT = """\

======================================================================
JUDGEMENT REQUEST
======================================================================
Using the alert, host context, threat intel, and related events \
above, produce an investigative writeup with these sections, in order:

1. VERDICT — one of: TRUE_POSITIVE, FALSE_POSITIVE, INCONCLUSIVE
2. CONFIDENCE — HIGH, MEDIUM, or LOW
3. KEY INDICATORS — bullet list of the specific signals from the data \
above that drove the verdict
4. TIMELINE — chronological narrative of what happened, weaving in \
the related events. Include exact timestamps.
5. PIVOTS — what to investigate next, named explicitly \
("check whether <user> logged into other hosts in the last 24h", \
not "do more analysis")
6. RECOMMENDED ACTION — one of: ESCALATE, CONTAIN_HOST, \
RESET_CREDENTIALS, MONITOR, CLOSE_AS_FP, with one sentence of justification

Be specific. If asset context is missing, say so and adjust confidence. \
If intel returned `unknown` for everything, do not invent verdicts. \
Anchor every claim to a line of data above."""


def _render_intel_line(kind: str, value: str, result: dict) -> str:
    verdict = result.get("verdict", "unknown")
    if kind == "ip":
        if result.get("internal"):
            return f"[ip] {value}: internal (RFC1918) — skipped"
        abuse = result.get("abuseipdb") or {}
        vt = result.get("virustotal") or {}
        bits = [f"verdict={verdict}"]
        if abuse:
            score = abuse.get("abuse_confidence_score", "n/a")
            reports = abuse.get("total_reports", 0)
            country = abuse.get("country_code") or "?"
            isp = abuse.get("isp") or "?"
            bits.append(f"abuseipdb_score={score}")
            bits.append(f"reports={reports}")
            bits.append(f"country={country}")
            bits.append(f"isp={isp}")
            if abuse.get("is_tor"):
                bits.append("tor=yes")
        if vt and "malicious" in vt:
            bits.append(f"vt_malicious={vt['malicious']}")
            if vt.get("as_owner"):
                bits.append(f"asn={vt.get('as_owner')}")
        if not abuse and not vt:
            bits.append("no intel sources configured")
        return f"[ip] {value}: " + ", ".join(bits)

    if kind == "hash":
        vt = result.get("virustotal") or {}
        if not vt:
            return f"[hash] {value}: no intel sources configured"
        if vt.get("found") is False:
            return f"[hash] {value}: not seen on VirusTotal (verdict={verdict})"
        if "error" in vt:
            return f"[hash] {value}: VT error — {vt['error']}"
        bits = [
            f"verdict={verdict}",
            f"malicious={vt.get('malicious', 0)}",
            f"suspicious={vt.get('suspicious', 0)}",
        ]
        if vt.get("type_description"):
            bits.append(f"type={vt['type_description']}")
        if vt.get("names"):
            bits.append(f"names={','.join(vt['names'][:3])}")
        return f"[hash] {value[:16]}...: " + ", ".join(bits)

    if kind == "domain":
        vt = result.get("virustotal") or {}
        if not vt:
            return f"[domain] {value}: no intel sources configured"
        if "error" in vt:
            return f"[domain] {value}: VT error — {vt['error']}"
        bits = [
            f"verdict={verdict}",
            f"malicious={vt.get('malicious', 0)}",
            f"suspicious={vt.get('suspicious', 0)}",
        ]
        cats = vt.get("categories", {})
        if cats:
            sample = list(cats.values())[:2]
            bits.append(f"categories={','.join(sample)}")
        return f"[domain] {value}: " + ", ".join(bits)

    return f"[{kind}] {value}: {result}"


def _render_event_line(ev: dict[str, Any]) -> str:
    ts = _get(ev, "@timestamp")
    action = _get(ev, "event.action")
    category = _get(ev, "event.category")
    proc = _get(ev, "process.name")
    cmd = _get(ev, "process.command_line")
    parent = _get(ev, "process.parent.name")
    src_ip = _get(ev, "source.ip")
    dst_ip = _get(ev, "destination.ip")
    dst_port = _get(ev, "destination.port")

    parts: list[str] = [f"{ts}"]
    if category != "unknown":
        parts.append(f"[{category}]")
    if action != "unknown":
        parts.append(action)
    if proc != "unknown":
        proc_str = proc
        if parent != "unknown":
            proc_str = f"{parent} -> {proc}"
        parts.append(proc_str)
    if cmd != "unknown" and cmd:
        cmd_short = cmd if len(cmd) <= 200 else cmd[:200] + "..."
        parts.append(f"cmd={cmd_short}")
    if src_ip != "unknown" or dst_ip != "unknown":
        net_bits = []
        if src_ip != "unknown" and not is_internal_ip(src_ip):
            net_bits.append(f"src={src_ip}(ext)")
        elif src_ip != "unknown":
            net_bits.append(f"src={src_ip}")
        if dst_ip != "unknown" and not is_internal_ip(dst_ip):
            net_bits.append(f"dst={dst_ip}(ext)")
        elif dst_ip != "unknown":
            net_bits.append(f"dst={dst_ip}")
        if dst_port != "unknown":
            net_bits.append(f"port={dst_port}")
        if net_bits:
            parts.append(" ".join(net_bits))

    return "  - " + " | ".join(parts)
