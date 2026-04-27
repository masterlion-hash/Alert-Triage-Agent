# Alert Triage Agent

AI-assisted alert triage and investigation for Elastic Security.
Exposes a web UI, a REST API, and an MCP server so any MCP-compatible AI client can investigate alerts directly.

## Install — one command, no git required

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -o /tmp/ata.py && python3 /tmp/ata.py
```

**Windows PowerShell**
```powershell
Invoke-WebRequest https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -OutFile "$env:TEMP\ata.py"; python "$env:TEMP\ata.py"
```

The installer will:
1. Check your system (RAM, CPU, disk, GPU)
2. Download the project if needed — no git required
3. Create a Python virtual environment and install all dependencies
4. Ask for your Elasticsearch URL and credentials (and test the connection)
5. Help you choose and set up an AI backend — Ollama (local) or Anthropic Claude (cloud)
6. Pull your chosen Ollama model, or validate your Claude API key
7. Write `.env`, create `start.sh` / `start.bat`, and optionally install as a service

Then start the server:

```bash
bash start.sh          # Linux / macOS
start.bat              # Windows
```

Open `http://localhost:8000`.

---

Already have the repo cloned? Just run:

```bash
python3 install.py     # Linux / macOS
python  install.py     # Windows
```

## Features

- Live alert feed with filters: severity, host, rule, user, date range
- One-click investigation: host context, threat intel (AbuseIPDB / VirusTotal), related events, AI verdict
- Pluggable AI verdict backend:
  - **Anthropic Claude** (cloud API — Haiku, Sonnet, or Opus)
  - **Ollama** — fully local/offline (Llama 3, Mistral, Phi-3, …) — auto-installed
  - **Any OpenAI-compatible API** — LM Studio, vLLM, Groq, Together AI, …
  - Disabled — raw investigation report only
- MCP server at `/mcp/mcp` for Claude.ai, Claude Code, or any MCP client
- Asset inventory (YAML) for host criticality / owner context
- MIT licensed, no telemetry

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

[MIT](LICENSE) — Copyright (c) 2024 Alert Triage Agent contributors
