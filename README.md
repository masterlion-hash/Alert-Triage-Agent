# elastic-mcp-triage

AI-assisted alert triage and investigation for Elastic Security.
Exposes a web UI, a REST API, and an MCP server so any MCP-compatible AI client can investigate alerts directly.

## Features

- Live alert feed with filters: severity, host, rule, user, date range
- One-click investigation: host context, threat intel (AbuseIPDB / VirusTotal), related events, AI verdict
- Pluggable AI verdict backend — bring your own:
  - **Anthropic Claude** (cloud API)
  - **Ollama** — fully local/offline (llama3, mistral, phi3, …)
  - **Any OpenAI-compatible API** — LM Studio, vLLM, Groq, Together AI, Mistral API, …
  - Disabled — raw investigation report only
- MCP server at `/mcp/mcp` for Claude.ai, Claude Code, or any MCP client
- Asset inventory (YAML) for host criticality / owner context
- MIT licensed, no telemetry

## Quick start

```bash
git clone https://github.com/your-org/elastic-mcp-triage.git
cd elastic-mcp-triage
pip install -r requirements.txt
python install.py        # interactive setup — asks you everything
python server.py
```

Open `http://localhost:8000` (or the port you chose).

## Requirements

- Python 3.11+
- Elasticsearch 8.x with Kibana Security enabled
- Read access to the `.alerts-security.alerts-default` index (or your custom index)

## Configuration

Run `python install.py` for a guided wizard, or copy `.env.example` to `.env` and edit manually.

### Elasticsearch

| Variable | Description | Default |
|---|---|---|
| `ELASTIC_URL` | Full URL with scheme and port | `https://localhost:9200` |
| `ELASTIC_USERNAME` | Basic auth username | `elastic` |
| `ELASTIC_PASSWORD` | Basic auth password | — |
| `ELASTIC_VERIFY_SSL` | Verify TLS certificate | `false` |
| `ELASTIC_INDEX` | Alerts index/alias | `.alerts-security.alerts-default` |

### AI backend

Set `AI_PROVIDER` to one of: `claude` · `ollama` · `openai_compat` · `none`

**Anthropic Claude**
```env
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-haiku-4-5-20251001
```

**Ollama** (local — `ollama serve` must be running)
```env
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```
Pull a model first: `ollama pull llama3.2`

**OpenAI-compatible** (LM Studio, vLLM, Groq, Together AI, …)
```env
AI_PROVIDER=openai_compat
OPENAI_COMPAT_URL=http://localhost:1234/v1
OPENAI_COMPAT_KEY=            # blank if not required
OPENAI_COMPAT_MODEL=mistral
```

### Threat intelligence (optional)

```env
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

Leave blank to disable. Investigations still run — IP/hash/domain enrichment is skipped.

### Asset inventory

Copy `assets.example.yml` to `assets.yml` and describe your hosts:

```yaml
hosts:
  WIN-DC01:
    criticality: critical
    environment: production
    role: domain_controller
    owner: infra@example.com
    notes: >
      Tier-0 asset. PowerShell with -enc is almost always malicious here.
```

The AI uses this to calibrate confidence and suggest better pivots.

## MCP server

The MCP endpoint is `/mcp/mcp`. Add it to your client:

**Claude Code** (`~/.claude.json`):
```json
{
  "mcpServers": {
    "elastic-triage": {
      "type": "http",
      "url": "http://localhost:8000/mcp/mcp"
    }
  }
}
```

**Claude.ai** — Settings → Connectors → Add custom connector → paste the URL.

For external access, tunnel with ngrok:
```bash
ngrok http 8000
```
Then set `PUBLIC_URL=https://your-tunnel.ngrok-free.app` in `.env`.

### MCP tools

| Tool | Description |
|---|---|
| `triage_recent_alerts` | List open alerts with IDs |
| `investigate_alert` | Full investigation + AI verdict |
| `get_host_context` | Asset inventory lookup |
| `lookup_indicator` | Threat-intel check (IP / hash / domain) |
| `get_related_events` | Events on the same host/user around a timestamp |

## Project structure

```
elastic-mcp-triage/
  install.py           Interactive setup wizard
  server.py            FastAPI app + MCP tools + UI
  config.py            Configuration loaded from .env
  requirements.txt
  .env.example         Configuration template
  assets.example.yml   Sample asset inventory
  src/
    ai_provider.py     Pluggable AI backend (Claude / Ollama / OpenAI-compat)
    elastic.py         Async Elasticsearch client
    investigation.py   Investigation orchestrator
    threat_intel.py    AbuseIPDB + VirusTotal lookups
    assets.py          Asset inventory loader
    triage.py          Alert formatting helpers
  deploy/
    elastic-triage.service   systemd unit file
```

## Deploying as a service (Linux)

```bash
sudo cp deploy/elastic-triage.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now elastic-triage
```

Edit the service file to match your install path and user.

## Troubleshooting

**401 from Elasticsearch** — check username/password and that the user has read access to the alerts index.

**No alerts returned** — confirm the index name with `GET _cat/indices/.alerts-security*` in Kibana Dev Tools. Set `ELASTIC_INDEX` if yours differs.

**SSL errors** — for self-signed certs keep `ELASTIC_VERIFY_SSL=false`. For production, install the CA and set it to `true`.

**MCP connector fails** — open `<your-url>/health` in a browser. If that works, make sure you registered `<url>/mcp/mcp` (not just `/mcp`).

**Ollama timeout** — increase `THREAT_INTEL_TIMEOUT` or check that `ollama serve` is running and the model is pulled.

## Contributing

Pull requests are welcome. Open an issue first for large changes.

## License

[MIT](LICENSE) — Copyright (c) 2024 elastic-mcp-triage contributors
