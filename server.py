# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
#
# Elastic Security Alert Triage & Investigation MCP Server
#
# MCP tools:
#   triage_recent_alerts   list open alerts with alert_id
#   investigate_alert      full investigation: asset + intel + events + verdict
#   get_host_context       asset inventory lookup
#   lookup_indicator       threat-intel (AbuseIPDB / VirusTotal)
#   get_related_events     events around a timestamp for host/user
#
# REST helpers (used by the UI):
#   GET /api/triage?limit=N
#   GET /api/investigate/{alert_id}
#   GET /health

import contextlib
import logging
import sys

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from config import config
from src.ai_provider import build_provider
from src.assets import AssetInventory
from src.elastic import ElasticClient
from src.investigation import investigate
from src.threat_intel import ThreatIntelClient
from src.triage import format_alert_summary

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("elastic-mcp")

# ---------------------------------------------------------------------------
# Shared resources
# ---------------------------------------------------------------------------

asset_inventory = AssetInventory(config.asset_inventory_path)
ai_provider = build_provider(config)


def _elastic() -> ElasticClient:
    return ElasticClient(
        url=config.elastic_url,
        username=config.elastic_username,
        password=config.elastic_password,
        verify_ssl=config.elastic_verify_ssl,
        index=config.elastic_index,
        event_indices=config.elastic_event_indices,
        timeout=config.elastic_timeout,
    )


def _intel() -> ThreatIntelClient:
    return ThreatIntelClient(
        abuseipdb_key=config.abuseipdb_api_key,
        virustotal_key=config.virustotal_api_key,
        timeout=config.threat_intel_timeout,
    )


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="elastic-alert-triage",
    instructions=(
        "Investigation toolkit for Elastic Security alerts.\n"
        "1. Call triage_recent_alerts to see open alerts.\n"
        "2. Call investigate_alert(alert_id) for a full report ending with a "
        "JUDGEMENT REQUEST — fill it in to produce a TP/FP/INCONCLUSIVE verdict.\n"
        "3. Use get_host_context, lookup_indicator, get_related_events for pivots."
    ),
    stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
async def triage_recent_alerts(limit: int = 10) -> str:
    """Fetch the most recent open Elastic Security alerts.

    Returns a compact list with rule, severity, host, user, IPs, and alert_id.
    Use alert_id with investigate_alert to dig deeper.
    """
    limit = max(1, min(int(limit), 50))
    logger.info("triage_recent_alerts(limit=%s)", limit)
    try:
        async with _elastic() as es:
            alerts = await es.fetch_open_alerts(limit=limit)
    except Exception as exc:
        logger.error("Elastic query failed: %s", exc, exc_info=True)
        return f"ERROR: {exc}"

    if not alerts:
        return "No open alerts found."

    summary = format_alert_summary(alerts)
    ids = ["", "Alert IDs (use with investigate_alert):"]
    for i, a in enumerate(alerts, 1):
        ids.append(f"  [{i}] {a.get('_alert_id', 'unknown')}")
    return summary + "\n" + "\n".join(ids)


@mcp.tool()
async def investigate_alert(alert_id: str) -> str:
    """Full investigation on a single alert.

    Pulls the alert, asset context, threat-intel on all IPs/hashes/domains,
    and related events. Returns a structured report ending with a JUDGEMENT
    REQUEST template for TP/FP/INCONCLUSIVE verdict.
    """
    if not alert_id:
        return "ERROR: alert_id is required."
    logger.info("investigate_alert(alert_id=%s)", alert_id)
    try:
        async with _elastic() as es, _intel() as intel:
            return await investigate(
                alert_id=alert_id,
                elastic=es,
                intel=intel,
                assets=asset_inventory,
                related_window_min=config.related_events_window_min,
                related_max=config.related_events_max,
                ai_provider=ai_provider,
            )
    except Exception as exc:
        logger.error("Investigation failed: %s", exc, exc_info=True)
        return f"ERROR: investigation failed: {exc}"


@mcp.tool()
async def get_host_context(hostname: str) -> str:
    """Look up asset-inventory context for a single host."""
    info = asset_inventory.lookup(hostname)
    if not info.get("known"):
        return f"Host `{hostname}` is not in the asset inventory."
    lines = [
        f"Host:        {info.get('hostname')}",
        f"Criticality: {info.get('criticality')}",
        f"Environment: {info.get('environment')}",
        f"Role:        {info.get('role')}",
        f"OS:          {info.get('os')}",
        f"Owner:       {info.get('owner')}",
    ]
    if info.get("tags"):
        lines.append(f"Tags:        {', '.join(info['tags'])}")
    if info.get("notes"):
        lines.append(f"Notes:       {info['notes'].strip()}")
    return "\n".join(lines)


@mcp.tool()
async def lookup_indicator(kind: str, value: str) -> str:
    """Threat-intelligence lookup for an IP, SHA-256 hash, or domain.

    Args:
        kind:  One of "ip", "hash", or "domain".
        value: The indicator value.
    """
    kind = (kind or "").lower().strip()
    if kind not in ("ip", "hash", "domain"):
        return "ERROR: kind must be 'ip', 'hash', or 'domain'."
    if not value:
        return "ERROR: value is required."
    async with _intel() as intel:
        if kind == "ip":
            res = await intel.lookup_ip(value)
        elif kind == "hash":
            res = await intel.lookup_hash(value)
        else:
            res = await intel.lookup_domain(value)
    return f"{kind}={value} -> {res}"


@mcp.tool()
async def get_related_events(
    host: str = "",
    user: str = "",
    timestamp: str = "",
    window_minutes: int = 15,
    limit: int = 50,
) -> str:
    """Pull events on the same host or user within a time window.

    Args:
        host:           Hostname to filter by (optional if user given).
        user:           Username to filter by (optional if host given).
        timestamp:      ISO 8601 centre time (defaults to now-1m).
        window_minutes: +/- window (1-120, default 15).
        limit:          Max events (1-200, default 50).
    """
    if not host and not user:
        return "ERROR: provide host, user, or both."
    window_minutes = max(1, min(int(window_minutes), 120))
    limit = max(1, min(int(limit), 200))
    if not timestamp:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()
    async with _elastic() as es:
        events = await es.get_related_events(
            host=host or None,
            user=user or None,
            center_ts=timestamp,
            window_minutes=window_minutes,
            limit=limit,
        )
    if not events:
        return f"No events found for host={host} user={user} window=+/-{window_minutes}min."
    from src.investigation import _render_event_line
    out = [f"Found {len(events)} event(s):", ""]
    out.extend(_render_event_line(ev) for ev in events)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Toggle UI
# ---------------------------------------------------------------------------

_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alert Triage &amp; Investigation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #0b0f1a;
  --surface:  #111827;
  --surface2: #1a2235;
  --border:   #1f2d45;
  --border2:  #2a3f5f;
  --text:     #e2e8f0;
  --muted:    #64748b;
  --dim:      #94a3b8;
  --accent:   #3b82f6;
  --accent-d: #1d4ed8;
  --c-crit:   #ef4444;
  --c-high:   #f97316;
  --c-med:    #eab308;
  --c-low:    #22c55e;
  --c-tp:     #f87171;
  --c-fp:     #4ade80;
  --c-inc:    #fbbf24;
  --font:     'Inter', system-ui, sans-serif;
  --mono:     'JetBrains Mono', 'Cascadia Code', 'Fira Mono', monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 14px; }
body { font-family: var(--font); background: var(--bg); color: var(--text);
       display: flex; flex-direction: column; min-height: 100vh; }

/* ── Top nav ── */
nav {
  display: flex; align-items: center; justify-content: space-between;
  padding: .75rem 1.5rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 100;
  box-shadow: 0 2px 12px rgba(0,0,0,.5);
}
.brand { display: flex; align-items: center; gap: .6rem; }
.brand-icon { font-size: 1.3rem; }
.brand-name { font-size: 1rem; font-weight: 700; color: var(--text);
              letter-spacing: -.01em; }
.brand-name span { color: var(--accent); }
.brand-version { font-size: .65rem; background: var(--border2);
                 color: var(--dim); padding: .15rem .45rem;
                 border-radius: 1rem; font-weight: 600; }
.nav-right { display: flex; align-items: center; gap: 1rem; }
.health-pill { display: flex; align-items: center; gap: .4rem;
               font-size: .72rem; color: var(--muted); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted);
       transition: background .3s, box-shadow .3s; flex-shrink: 0; }
.dot.ok  { background: var(--c-low);  box-shadow: 0 0 6px color-mix(in srgb, var(--c-low) 60%, transparent); }
.dot.err { background: var(--c-crit); box-shadow: 0 0 6px color-mix(in srgb, var(--c-crit) 60%, transparent); }
.nav-meta { display: flex; gap: .5rem; flex-wrap: wrap; }
.chip { font-size: .65rem; padding: .2rem .55rem; border-radius: 1rem;
        border: 1px solid var(--border2); color: var(--dim); background: var(--surface2);
        display: flex; align-items: center; gap: .3rem; }
.chip .dot-sm { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.chip.on .dot-sm  { background: var(--c-low); }
.chip.off .dot-sm { background: var(--muted); }

/* ── Layout ── */
.layout { display: flex; flex: 1; overflow: hidden; height: calc(100vh - 53px); }

/* ── Sidebar ── */
.sidebar {
  width: 240px; flex-shrink: 0;
  background: var(--surface); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; overflow-y: auto;
  padding: 1rem .85rem; gap: 1rem;
}
.sidebar-section { display: flex; flex-direction: column; gap: .4rem; }
.sidebar-label { font-size: .65rem; font-weight: 700; color: var(--muted);
                 text-transform: uppercase; letter-spacing: .06em;
                 padding-bottom: .25rem; border-bottom: 1px solid var(--border); }
.fg { display: flex; flex-direction: column; gap: .2rem; }
.fg label { font-size: .7rem; color: var(--dim); }
select, input[type=number], input[type=datetime-local] {
  width: 100%; padding: .35rem .5rem;
  background: var(--surface2); border: 1px solid var(--border2);
  border-radius: .35rem; color: var(--text); font-size: .78rem;
  font-family: var(--font); transition: border-color .2s;
}
select:focus, input:focus { outline: none; border-color: var(--accent); }
select option { background: var(--surface2); }
input[type=datetime-local] { font-size: .7rem; color-scheme: dark; }
.stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .4rem; }
.stat-card { background: var(--surface2); border: 1px solid var(--border);
             border-radius: .4rem; padding: .45rem .6rem;
             display: flex; flex-direction: column; gap: .1rem; }
.stat-card .stat-n { font-size: 1.1rem; font-weight: 700; line-height: 1; }
.stat-card .stat-l { font-size: .62rem; color: var(--muted); text-transform: uppercase;
                     letter-spacing: .05em; }
.stat-crit .stat-n { color: var(--c-crit); }
.stat-high .stat-n { color: var(--c-high); }
.stat-med  .stat-n { color: var(--c-med);  }
.stat-low  .stat-n { color: var(--c-low);  }
.sidebar-foot { margin-top: auto; padding-top: .75rem;
                border-top: 1px solid var(--border); }
.sidebar-foot p { font-size: .62rem; color: var(--muted); line-height: 1.6; }
.sidebar-foot a { color: var(--dim); text-decoration: none; }
.sidebar-foot a:hover { color: var(--accent); }

/* ── Main area ── */
main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.toolbar {
  display: flex; align-items: center; gap: .75rem; flex-wrap: wrap;
  padding: .75rem 1.25rem;
  background: var(--surface); border-bottom: 1px solid var(--border);
}
.btn { padding: .42rem 1rem; border: none; border-radius: .4rem;
       font-size: .8rem; font-weight: 600; font-family: var(--font);
       cursor: pointer; white-space: nowrap; transition: background .15s, transform .1s; }
.btn:active { transform: scale(.97); }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-d); }
.btn-primary:disabled { background: var(--border2); color: var(--muted); cursor: not-allowed; transform: none; }
.btn-ghost { background: transparent; color: var(--dim);
             border: 1px solid var(--border2); }
.btn-ghost:hover { background: var(--surface2); color: var(--text); }
.status-bar { font-size: .72rem; color: var(--muted); margin-left: auto; }
.filter-badge { font-size: .7rem; background: var(--accent); color: #fff;
                padding: .1rem .45rem; border-radius: 1rem; font-weight: 600; }

/* ── Alert list ── */
.alerts-wrap { flex: 1; overflow-y: auto; padding: 1rem 1.25rem;
               display: flex; flex-direction: column; gap: .6rem; }
.empty-state { display: flex; flex-direction: column; align-items: center;
               justify-content: center; height: 100%; gap: .75rem;
               color: var(--muted); }
.empty-state .empty-icon { font-size: 2.5rem; opacity: .4; }
.empty-state p { font-size: .82rem; }

/* ── Alert card ── */
.alert-card {
  background: var(--surface); border: 1px solid var(--border);
  border-left: 4px solid var(--border2);
  border-radius: .5rem; padding: .85rem 1rem;
  transition: border-color .2s, box-shadow .2s;
}
.alert-card:hover { border-color: var(--border2); box-shadow: 0 2px 12px rgba(0,0,0,.3); }
.alert-card.critical { border-left-color: var(--c-crit); }
.alert-card.high     { border-left-color: var(--c-high); }
.alert-card.medium   { border-left-color: var(--c-med);  }
.alert-card.low      { border-left-color: var(--c-low);  }

.card-top { display: flex; align-items: flex-start;
            justify-content: space-between; gap: 1rem; }
.card-left { flex: 1; min-width: 0; }
.card-rule { font-size: .9rem; font-weight: 600; color: var(--text);
             margin-bottom: .3rem; }
.card-chips { display: flex; flex-wrap: wrap; gap: .3rem; margin-bottom: .3rem; }
.c-chip { font-size: .65rem; padding: .15rem .45rem; border-radius: .25rem;
          border: 1px solid var(--border2); color: var(--dim);
          background: var(--surface2); }
.card-reason { font-size: .7rem; color: var(--muted); font-style: italic;
               border-left: 2px solid var(--border2); padding-left: .5rem;
               margin-top: .3rem; line-height: 1.5; }
.card-right { display: flex; flex-direction: column; align-items: flex-end;
              gap: .45rem; flex-shrink: 0; }
.sev-badge { font-size: .62rem; font-weight: 800; padding: .2rem .55rem;
             border-radius: .3rem; letter-spacing: .04em; }
.sev-critical { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
.sev-high     { background: #431407; color: #fdba74; border: 1px solid #7c2d12; }
.sev-medium   { background: #422006; color: #fcd34d; border: 1px solid #78350f; }
.sev-low      { background: #052e16; color: #86efac; border: 1px solid #14532d; }
.sev-unknown  { background: var(--surface2); color: var(--muted); border: 1px solid var(--border2); }
.risk-text { font-size: .65rem; color: var(--muted); }
.btn-inv {
  display: flex; align-items: center; gap: .35rem;
  background: var(--surface2); color: var(--dim);
  border: 1px solid var(--border2); border-radius: .4rem;
  padding: .38rem .8rem; font-size: .75rem; font-weight: 600;
  font-family: var(--font); cursor: pointer; white-space: nowrap;
  transition: background .15s, color .15s, border-color .15s;
}
.btn-inv:hover { background: #0f766e22; color: #2dd4bf; border-color: #0d9488; }
.btn-inv:active { transform: scale(.97); }
.btn-inv:disabled { opacity: .4; cursor: not-allowed; transform: none; }
.btn-inv.done { border-color: #1d4ed8; color: #93c5fd; }

/* ── Report panel ── */
.report {
  margin-top: .75rem;
  background: #060d1b;
  border: 1px solid var(--border2);
  border-radius: .45rem;
  font-family: var(--mono);
  font-size: .72rem; line-height: 1.75;
  color: #94a3b8;
  padding: 1rem 1.1rem;
  white-space: pre-wrap; word-break: break-word;
  max-height: 60vh; overflow-y: auto;
  display: none;
  scroll-behavior: smooth;
}
.report.visible { display: block; }
.report.error { border-color: #7f1d1d; color: #fca5a5; background: #1a0505; }
/* Report syntax */
.report .r-sep  { color: #1e293b; }
.report .r-sec  { color: #38bdf8; font-weight: 700; font-size: .78rem; }
.report .r-key  { color: #7dd3fc; }
.report .r-val  { color: #cbd5e1; }
.report .r-tp   { color: var(--c-tp);  font-weight: 700; }
.report .r-fp   { color: var(--c-fp);  font-weight: 700; }
.report .r-inc  { color: var(--c-inc); font-weight: 700; }
.report .r-act  { color: #c084fc; font-weight: 600; }
.report .r-ts   { color: #94a3b8; }
.report .r-ip   { color: #fbbf24; }
.report .r-num  { color: #f97316; }
.report .r-ev   { color: #cbd5e1; }
.report .r-hi   { color: var(--c-low);  }
.report .r-med  { color: var(--c-med);  }
.report .r-lo   { color: var(--c-high); }
.report::-webkit-scrollbar { width: 6px; }
.report::-webkit-scrollbar-track { background: transparent; }
.report::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

/* ── Footer ── */
footer {
  padding: .6rem 1.5rem;
  background: var(--surface); border-top: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: .5rem;
}
footer p { font-size: .65rem; color: var(--muted); }
footer a { color: var(--dim); text-decoration: none; }
footer a:hover { color: var(--accent); }
.footer-right { display: flex; gap: 1rem; }

/* ── Skeleton loader ── */
@keyframes shimmer {
  0%   { background-position: -600px 0; }
  100% { background-position:  600px 0; }
}
.skeleton { background: linear-gradient(90deg,#1a2235 25%,#1e293b 50%,#1a2235 75%);
            background-size: 600px 100%; animation: shimmer 1.4s infinite;
            border-radius: .3rem; }

/* ── Date toggle ── */
.date-toggle {
  display: flex; align-items: center; gap: .4rem;
  padding: .35rem .5rem; border-radius: .35rem;
  background: var(--surface2); border: 1px solid var(--border2);
  cursor: pointer; user-select: none;
  transition: border-color .2s;
}
.date-toggle:hover { border-color: var(--accent); }
.date-toggle-label { font-size: .7rem; color: var(--dim); flex-shrink: 0; }
.date-toggle-summary { font-size: .65rem; color: var(--accent); flex: 1;
                       white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.date-caret { font-size: .75rem; color: var(--muted); margin-left: auto;
              flex-shrink: 0; line-height: 1; transition: transform .2s; }
.date-caret.open { transform: rotate(45deg); }
.date-range-body { display: flex; flex-direction: column; gap: .4rem;
                   padding: .4rem 0 0; }
.btn-clear-dates { background: none; border: none; color: var(--muted);
                   font-size: .65rem; cursor: pointer; text-align: left;
                   padding: .1rem 0; text-decoration: underline; }
.btn-clear-dates:hover { color: var(--c-crit); }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
</style>
</head>
<body>

<!-- ── Navigation ── -->
<nav>
  <div class="brand">
    <span class="brand-name"><span>Elastic</span> Alert Triage</span>
    <span class="brand-version">v2.0</span>
  </div>
  <div class="nav-right">
    <div class="nav-meta">
      <span class="chip" title="Elasticsearch">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10"/></svg>
        <span id="elasticUrl">ELASTIC_DISPLAY</span>
      </span>
      <span class="chip ABUSE_CLASS" title="AbuseIPDB threat intel">
        <span class="dot-sm"></span>AbuseIPDB
      </span>
      <span class="chip VT_CLASS" title="VirusTotal threat intel">
        <span class="dot-sm"></span>VirusTotal
      </span>
    </div>
    <div class="health-pill">
      <span class="dot" id="dot"></span>
      <span id="connLabel">checking…</span>
    </div>
  </div>
</nav>

<!-- ── Body ── -->
<div class="layout">

  <!-- ── Sidebar ── -->
  <aside class="sidebar">

    <div class="sidebar-section">
      <div class="sidebar-label">Filters</div>
      <div class="fg"><label>Severity</label>
        <select id="fSev">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      <div class="fg"><label>Host</label>
        <select id="fHost"><option value="">All hosts</option></select>
      </div>
      <div class="fg"><label>Rule</label>
        <select id="fRule"><option value="">All rules</option></select>
      </div>
      <div class="fg"><label>User</label>
        <select id="fUser"><option value="">All users</option></select>
      </div>
      <div class="date-toggle" id="dateToggle" onclick="toggleDateRange()">
        <span class="date-toggle-label">Date range</span>
        <span class="date-toggle-summary" id="dateSummary"></span>
        <span class="date-caret" id="dateCaret">+</span>
      </div>
      <div class="date-range-body" id="dateRangeBody" style="display:none">
        <div class="fg"><label>From</label>
          <input type="datetime-local" id="fFrom">
        </div>
        <div class="fg"><label>To</label>
          <input type="datetime-local" id="fTo">
        </div>
        <button class="btn-clear-dates" onclick="clearDates(event)">Clear dates</button>
      </div>
      <div class="fg"><label>Fetch limit</label>
        <input type="number" id="limit" value="50" min="1" max="200">
      </div>
    </div>

    <div class="sidebar-section">
      <div class="sidebar-label">Summary</div>
      <div class="stats-grid">
        <div class="stat-card stat-crit">
          <span class="stat-n" id="sCrit">—</span>
          <span class="stat-l">Critical</span>
        </div>
        <div class="stat-card stat-high">
          <span class="stat-n" id="sHigh">—</span>
          <span class="stat-l">High</span>
        </div>
        <div class="stat-card stat-med">
          <span class="stat-n" id="sMed">—</span>
          <span class="stat-l">Medium</span>
        </div>
        <div class="stat-card stat-low">
          <span class="stat-n" id="sLow">—</span>
          <span class="stat-l">Low</span>
        </div>
      </div>
    </div>

    <div class="sidebar-foot">
      <p>
        MIT License &mdash; open source<br>
        elastic-mcp-triage<br>
        MCP: <code style="font-size:.6rem;color:var(--dim)">BASE_URL/mcp/mcp</code>
      </p>
    </div>

  </aside>

  <!-- ── Main ── -->
  <main>
    <div class="toolbar">
      <button class="btn btn-primary" id="fetchBtn" onclick="fetchAlerts()">
        Fetch Alerts
      </button>
      <button class="btn btn-ghost" onclick="clearFilters()">Clear Filters</button>
      <button class="btn btn-ghost" onclick="clearAll()">Reset</button>
      <span class="filter-badge" id="filterBadge" style="display:none"></span>
      <span class="status-bar" id="status"></span>
    </div>

    <div class="alerts-wrap" id="alertsWrap">
      <div class="empty-state" id="emptyState">
        <p>Click <strong>Fetch Alerts</strong> to load open Elastic Security alerts.</p>
      </div>
      <div id="alerts"></div>
    </div>
  </main>

</div>

<!-- ── Footer ── -->
<footer>
  <p>
    Released under the
    <a href="https://opensource.org/licenses/MIT" target="_blank" rel="noopener">MIT License</a>
    &mdash; elastic-mcp-triage &mdash; contributions welcome
  </p>
  <div class="footer-right">
    <p><a href="/health" target="_blank">Health</a></p>
    <p><a href="BASE_URL/mcp/mcp" target="_blank">MCP endpoint</a></p>
  </div>
</footer>

<script>
let allAlerts = [];

// ── Health check ──
async function health() {
  const dot = document.getElementById('dot');
  const lbl = document.getElementById('connLabel');
  try {
    const d = await (await fetch('/health')).json();
    if (d.status === 'ok') {
      dot.className = 'dot ok'; lbl.textContent = 'connected';
    } else { throw new Error(); }
  } catch {
    dot.className = 'dot err'; lbl.textContent = 'unreachable';
  }
}
health();

// ── Fetch ──
async function fetchAlerts() {
  const limit = Math.max(1, Math.min(200, parseInt(document.getElementById('limit').value)||50));
  const btn = document.getElementById('fetchBtn');
  btn.disabled = true; btn.innerHTML = '<span style="opacity:.6">Fetching…</span>';
  setStatus('');
  document.getElementById('alerts').innerHTML = '';
  document.getElementById('emptyState').style.display = 'none';
  try {
    const d = await (await fetch('/api/triage?limit=' + limit)).json();
    if (d.error) { setStatus('Error: ' + d.error); showEmpty('Error: ' + d.error); return; }
    allAlerts = (d.alerts || []).sort((a,b) => {
      const o = {critical:4,high:3,medium:2,low:1};
      return (o[b.severity]||0)-(o[a.severity]||0) || +b.risk_score - +a.risk_score;
    });
    populateDropdowns(allAlerts);
    updateStats(allAlerts);
    applyFilters();
    setStatus('Fetched ' + allAlerts.length + ' alert(s) — ' + new Date().toLocaleTimeString());
  } catch(e) { setStatus('Request failed: ' + e); showEmpty('Request failed: ' + e); }
  finally { btn.disabled = false; btn.textContent = 'Fetch Alerts'; }
}

function showEmpty(msg) {
  const es = document.getElementById('emptyState');
  es.innerHTML = '<p>' + esc(msg) + '</p>';
  es.style.display = 'flex';
}

// ── Dropdowns ──
function populateDropdowns(alerts) {
  const uniq = (fn) => [...new Set(alerts.map(fn).filter(v=>v&&v!=='unknown'))].sort();
  fill('fHost', uniq(a=>a.host),  'All hosts');
  fill('fRule', uniq(a=>a.rule),  'All rules');
  fill('fUser', uniq(a=>a.user),  'All users');
}
function fill(id, vals, label) {
  const sel = document.getElementById(id), cur = sel.value;
  sel.innerHTML = '<option value="">' + label + '</option>' +
    vals.map(v => '<option value="'+eA(v)+'"'+(v===cur?' selected':'')+'>'+eA(v)+'</option>').join('');
}

// ── Stats ──
function updateStats(alerts) {
  const cnt = {critical:0,high:0,medium:0,low:0};
  alerts.forEach(a => { if(cnt[a.severity]!==undefined) cnt[a.severity]++; });
  document.getElementById('sCrit').textContent = cnt.critical;
  document.getElementById('sHigh').textContent = cnt.high;
  document.getElementById('sMed').textContent  = cnt.medium;
  document.getElementById('sLow').textContent  = cnt.low;
}

// ── Filters ──
function applyFilters() {
  const sev  = document.getElementById('fSev').value.toLowerCase();
  const host = document.getElementById('fHost').value;
  const rule = document.getElementById('fRule').value;
  const user = document.getElementById('fUser').value;
  const from = document.getElementById('fFrom').value ? new Date(document.getElementById('fFrom').value) : null;
  const to   = document.getElementById('fTo').value   ? new Date(document.getElementById('fTo').value)   : null;
  const filtered = allAlerts.filter(a => {
    if (sev  && (a.severity||'').toLowerCase() !== sev) return false;
    if (host && a.host !== host) return false;
    if (rule && a.rule !== rule) return false;
    if (user && a.user !== user) return false;
    if (from || to) {
      const ts = new Date(a.timestamp);
      if (from && ts < from) return false;
      if (to   && ts > to)   return false;
    }
    return true;
  });
  const badge = document.getElementById('filterBadge');
  if (filtered.length < allAlerts.length) {
    badge.textContent = filtered.length + ' / ' + allAlerts.length;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
  renderAlerts(filtered);
}

function clearFilters() {
  ['fSev','fHost','fRule','fUser'].forEach(id => document.getElementById(id).selectedIndex = 0);
  clearDates(null);
  if (allAlerts.length) applyFilters();
}

function toggleDateRange() {
  const body  = document.getElementById('dateRangeBody');
  const caret = document.getElementById('dateCaret');
  const open  = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'flex';
  caret.classList.toggle('open', !open);
}

function clearDates(e) {
  if (e) e.stopPropagation();
  document.getElementById('fFrom').value = '';
  document.getElementById('fTo').value   = '';
  document.getElementById('dateSummary').textContent = '';
  if (allAlerts.length) applyFilters();
}

function updateDateSummary() {
  const from = document.getElementById('fFrom').value;
  const to   = document.getElementById('fTo').value;
  const fmt  = v => v ? new Date(v).toLocaleDateString(undefined,{month:'short',day:'numeric'}) : '';
  const parts = [from && 'from '+fmt(from), to && 'to '+fmt(to)].filter(Boolean);
  document.getElementById('dateSummary').textContent = parts.join(' ');
}

['fSev','fHost','fRule','fUser'].forEach(id =>
  document.getElementById(id)?.addEventListener('change', () => { if (allAlerts.length) applyFilters(); })
);
['fFrom','fTo'].forEach(id =>
  document.getElementById(id)?.addEventListener('change', () => { updateDateSummary(); if (allAlerts.length) applyFilters(); })
);

// ── Render alerts ──
const SEV_CLS = {critical:'sev-critical',high:'sev-high',medium:'sev-medium',low:'sev-low'};

function renderAlerts(alerts) {
  const box = document.getElementById('alerts');
  document.getElementById('emptyState').style.display = alerts.length ? 'none' : 'flex';
  if (!alerts.length) {
    box.innerHTML = '';
    if (allAlerts.length) document.getElementById('emptyState').innerHTML =
      '<p>No alerts match the current filters.</p>';
    return;
  }
  box.innerHTML = alerts.map((a,i) => {
    const sev = (a.severity||'unknown').toLowerCase();
    const badgeCls = SEV_CLS[sev] || 'sev-unknown';
    const risk = parseFloat(a.risk_score||0);
    const riskFmt = risk > 1 ? Math.round(risk) : (risk*100).toFixed(0);
    const chips = [
      a.timestamp && a.timestamp!=='unknown' ? chip(fmtTs(a.timestamp)) : '',
      a.host && a.host!=='unknown'   ? chip('host: '+eA(a.host)) : '',
      a.user && a.user!=='unknown'   ? chip('user: '+eA(a.user)) : '',
      a.src_ip && a.src_ip!=='unknown' ? chip('src: '+eA(a.src_ip)) : '',
      a.dst_ip && a.dst_ip!=='unknown' ? chip('dst: '+eA(a.dst_ip)) : '',
    ].filter(Boolean).join('');
    return `<div class="alert-card ${sev}" id="card-${i}">
      <div class="card-top">
        <div class="card-left">
          <div class="card-rule">${esc(a.rule)}</div>
          <div class="card-chips">${chips}</div>
          ${a.reason&&a.reason!=='unknown'
            ? '<div class="card-reason">'+esc(a.reason.slice(0,240))+(a.reason.length>240?'…':'')+'</div>'
            : ''}
        </div>
        <div class="card-right">
          <span class="sev-badge ${badgeCls}">${sev.toUpperCase()}</span>
          <span class="risk-text">risk ${riskFmt}</span>
          <button class="btn-inv" id="ibtn-${i}" data-id="${eA(a.alert_id)}"
            onclick="investigate(this,${i})">Investigate</button>
        </div>
      </div>
      <div class="report" id="report-${i}"></div>
    </div>`;
  }).join('');
}

function chip(html) {
  return '<span class="c-chip">'+html+'</span>';
}
function fmtTs(ts) {
  try { return new Date(ts).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}); }
  catch { return ts; }
}

// ── Investigate ──
async function investigate(btn, idx) {
  const alertId = btn.dataset.id;
  const box = document.getElementById('report-' + idx);
  btn.disabled = true; btn.textContent = 'Working...';
  box.className = 'report visible';
  box.innerHTML = '<span style="color:var(--muted)">Pulling alert data, host context, threat intel, related events…</span>';
  try {
    const d = await (await fetch('/api/investigate/' + encodeURIComponent(alertId))).json();
    const text = d.result || d.error || 'No result.';
    const isErr = !!(d.error || text.startsWith('ERROR'));
    box.classList.toggle('error', isErr);
    box.innerHTML = colorize(text);
    box.scrollTop = 0;
  } catch(e) {
    box.textContent = 'Request failed: ' + e;
    box.classList.add('error');
  }
  btn.disabled = false;
  btn.className = 'btn-inv done';
  btn.textContent = 'Re-investigate';
}

// ── Colorize report ──
function colorize(raw) {
  let s = raw
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // separators
  s = s.replace(/(={10,})/g, '<span class="r-sep">$1</span>');
  // section headers
  s = s.replace(/(^|\n)(##\s+[A-Z][A-Z /+\-]+)/g, '$1<span class="r-sec">$2</span>');
  // numbered verdict headings
  s = s.replace(/(^|\n)(\d+\.\s+[A-Z][A-Z &mdash;\/]+(?:\s*&mdash;\s*[^<\n]+)?)/g,
                '$1<strong style="color:#7dd3fc">$2</strong>');
  // key: value lines (Rule:   xxx)
  s = s.replace(/(^|\n)([A-Z][A-Za-z ]{1,20}:\s{1,10})([^\n<]+)/g,
                '$1<span class="r-key">$2</span><span class="r-val">$3</span>');
  // verdict values
  s = s.replace(/\b(TRUE_POSITIVE)\b/g,  '<span class="r-tp">$1</span>');
  s = s.replace(/\b(FALSE_POSITIVE)\b/g, '<span class="r-fp">$1</span>');
  s = s.replace(/\b(INCONCLUSIVE)\b/g,   '<span class="r-inc">$1</span>');
  // recommended actions
  s = s.replace(/\b(ESCALATE|CONTAIN_HOST|RESET_CREDENTIALS|MONITOR|CLOSE_AS_FP)\b/g,
                '<span class="r-act">$1</span>');
  // confidence levels (standalone)
  s = s.replace(/\b(HIGH)\b(?!\s*:)/g,  '<span class="r-hi">$1</span>');
  s = s.replace(/\b(MEDIUM)\b(?!\s*:)/g,'<span class="r-med">$1</span>');
  s = s.replace(/\b(LOW)\b(?!\s*:)/g,   '<span class="r-lo">$1</span>');
  // timestamps
  s = s.replace(/(\d{4}-\d{2}-\d{2}T[\d:+.\-Z]+)/g, '<span class="r-ts">$1</span>');
  // IPs
  s = s.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="r-ip">$1</span>');
  // numeric values after = in intel lines
  s = s.replace(/((?:score|reports|malicious|suspicious|risk_score)=)(\d[\d.]*)/gi,
                '$1<span class="r-num">$2</span>');
  // bullet event lines
  s = s.replace(/(^|\n)(\s{2,}- )([^\n]+)/g, '$1$2<span class="r-ev">$3</span>');

  return s;
}

// ── Utilities ──
function clearAll() {
  allAlerts = [];
  document.getElementById('alerts').innerHTML = '';
  document.getElementById('filterBadge').style.display = 'none';
  ['sCrit','sHigh','sMed','sLow'].forEach(id => { document.getElementById(id).textContent = '—'; });
  setStatus('');
  clearFilters();
  document.getElementById('emptyState').innerHTML =
    '<span class="empty-icon">&#128270;</span>' +
    '<p>Click <strong>Fetch Alerts</strong> to load open Elastic Security alerts.</p>'
  document.getElementById('emptyState').style.display = 'flex';
  document.getElementById('emptyState').style.display = 'flex';
}

function setStatus(msg) { document.getElementById('status').textContent = msg; }

function esc(s) {
  if (!s || s === 'unknown') return '<span style="color:var(--muted)">—</span>';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function eA(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        logger.info(
            "MCP ready — /mcp | elastic=%s | abuseipdb=%s | virustotal=%s",
            config.elastic_url,
            "set" if config.abuseipdb_api_key else "NOT SET",
            "set" if config.virustotal_api_key else "NOT SET",
        )
        yield


app = FastAPI(title="Elastic Alert Triage", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def allow_framing(request: Request, call_next):
    response = await call_next(request)
    if "x-frame-options" in response.headers:
        del response.headers["x-frame-options"]
    response.headers["content-security-policy"] = "frame-ancestors *"
    return response


@app.get("/", response_class=HTMLResponse)
async def ui():
    # Use public (ngrok) URL if set, otherwise fall back to internal address
    base = config.public_url.rstrip("/") if config.public_url else f"http://{config.host}:{config.port}"
    display_url = config.elastic_url.replace("https://", "").replace("http://", "")
    html = (
        _UI
        .replace("ELASTIC_DISPLAY", display_url)
        .replace("BASE_URL", base)
        .replace("ABUSE_CLASS", "on" if config.abuseipdb_api_key else "off")
        .replace("VT_CLASS", "on" if config.virustotal_api_key else "off")
    )
    return html


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "elastic-alert-triage",
        "intel": {
            "abuseipdb": bool(config.abuseipdb_api_key),
            "virustotal": bool(config.virustotal_api_key),
        },
    }


@app.get("/api/triage")
async def api_triage(limit: int = 10) -> JSONResponse:
    limit = max(1, min(int(limit), 50))
    try:
        async with _elastic() as es:
            raw = await es.fetch_open_alerts(limit=limit)
    except Exception as exc:
        logger.error("Triage failed: %s", exc, exc_info=True)
        return JSONResponse({"error": str(exc)}, status_code=500)

    from src.triage import _get
    alerts = []
    for a in raw:
        host = _get(a, "host.name")
        if host == "unknown":
            host = _get(a, "host.hostname")
        alerts.append({
            "alert_id":  a.get("_alert_id", ""),
            "rule":      _get(a, "kibana.alert.rule.name", "Unnamed rule"),
            "severity":  _get(a, "kibana.alert.severity"),
            "risk_score": _get(a, "kibana.alert.risk_score"),
            "timestamp": _get(a, "@timestamp"),
            "host":      host,
            "user":      _get(a, "user.name"),
            "src_ip":    _get(a, "source.ip"),
            "dst_ip":    _get(a, "destination.ip"),
            "reason":    _get(a, "kibana.alert.reason", ""),
        })
    return JSONResponse({"alerts": alerts})


@app.get("/api/investigate/{alert_id}")
async def api_investigate(alert_id: str) -> JSONResponse:
    logger.info("UI investigate request: %s", alert_id)
    try:
        async with _elastic() as es, _intel() as intel:
            result = await investigate(
                alert_id=alert_id,
                elastic=es,
                intel=intel,
                assets=asset_inventory,
                related_window_min=config.related_events_window_min,
                related_max=config.related_events_max,
                ai_provider=ai_provider,
            )
        return JSONResponse({"result": result})
    except Exception as exc:
        logger.error("Investigation failed: %s", exc, exc_info=True)
        return JSONResponse({"error": str(exc)}, status_code=500)


app.mount("/mcp", mcp.streamable_http_app())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not config.elastic_url or not config.elastic_username or not config.elastic_password:
        logger.error("ELASTIC_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD must be set in .env")
        sys.exit(1)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
    )
