#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""
elastic-mcp-triage — interactive setup wizard.

Run:  python install.py
It will ask questions and write a .env configuration file.
"""

from __future__ import annotations

import getpass
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).parent

# ---------------------------------------------------------------------------
# Terminal colours (no external deps)
# ---------------------------------------------------------------------------

_NO_COLOUR = not sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return text if _NO_COLOUR else f"\033[{code}m{text}\033[0m"

def bold(t: str)   -> str: return _c("1",  t)
def dim(t: str)    -> str: return _c("2",  t)
def green(t: str)  -> str: return _c("92", t)
def yellow(t: str) -> str: return _c("93", t)
def red(t: str)    -> str: return _c("91", t)
def cyan(t: str)   -> str: return _c("96", t)


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def ask(label: str, default: str = "", secret: bool = False, required: bool = True) -> str:
    dflt = f" {dim('[' + default + ']')}" if default else ""
    prompt = f"  {bold(label)}{dflt}: "
    while True:
        try:
            val = getpass.getpass(prompt) if secret else input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise
        if val:
            return val
        if default:
            return default
        if not required:
            return ""
        print(f"  {red('Required — please enter a value.')}")


def ask_yn(label: str, default: bool = True) -> bool:
    hint = dim("Y/n") if default else dim("y/N")
    raw = input(f"  {bold(label)} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "1", "true")


def section(title: str) -> None:
    print(f"\n{bold(cyan('-- ' + title + ' --'))}")


def ok(msg: str)   -> None: print(f"  {green('ok')}  {msg}")
def warn(msg: str) -> None: print(f"  {yellow('warn')} {msg}")
def err(msg: str)  -> None: print(f"  {red('err')} {msg}")


def ask_choice(label: str, options: list[tuple[str, str]], default: str | None = None) -> str:
    """Print a numbered menu and return the chosen key."""
    for i, (key, desc) in enumerate(options, 1):
        marker = green("*") if key == default else " "
        print(f"  {marker} {bold(str(i))}. {bold(key):<16} {dim(desc)}")
    dflt_n = next((str(i) for i, (k, _) in enumerate(options, 1) if k == default), "")
    hint = f" {dim('[' + dflt_n + ']')}" if dflt_n else ""
    while True:
        raw = input(f"  {bold(label)}{hint}: ").strip()
        if not raw and dflt_n:
            return options[int(dflt_n) - 1][0]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(f"  {red('Enter a number 1–' + str(len(options)))}")


# ---------------------------------------------------------------------------
# Connection tests
# ---------------------------------------------------------------------------

def _test_elastic(url: str, username: str, password: str, verify_ssl: bool) -> tuple[bool, str]:
    try:
        import httpx
        r = httpx.get(
            f"{url.rstrip('/')}/_cluster/health",
            auth=(username, password),
            verify=verify_ssl,
            timeout=8,
        )
        if r.status_code == 200:
            return True, r.json().get("status", "green")
        return False, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, str(exc)


def _test_ollama(url: str) -> tuple[bool, str]:
    try:
        import httpx
        r = httpx.get(f"{url.rstrip('/')}/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return True, ", ".join(models[:5]) or "no models pulled yet"
        return False, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Main wizard
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"\n  {bold('elastic-mcp-triage')}  {dim('setup wizard')}")
    print(f"  {dim('Writes a .env file — edit it any time to change settings.')}\n")

    env: dict[str, str] = {}

    # ── Elasticsearch ──────────────────────────────────────────────────────
    section("Elasticsearch")
    env["ELASTIC_URL"]      = ask("URL", "https://localhost:9200")
    env["ELASTIC_USERNAME"] = ask("Username", "elastic")
    env["ELASTIC_PASSWORD"] = ask("Password", secret=True)
    verify_ssl = ask_yn("Verify SSL certificate?", default=False)
    env["ELASTIC_VERIFY_SSL"] = "true" if verify_ssl else "false"
    env["ELASTIC_INDEX"]    = ask("Alerts index", ".alerts-security.alerts-default")
    env["ELASTIC_TIMEOUT"]  = ask("Timeout (seconds)", "30")

    print(f"\n  Testing {env['ELASTIC_URL']} …", end=" ", flush=True)
    connected, status = _test_elastic(
        env["ELASTIC_URL"], env["ELASTIC_USERNAME"],
        env["ELASTIC_PASSWORD"], verify_ssl,
    )
    if connected:
        ok(f"cluster status: {bold(status)}")
    else:
        warn(f"could not connect: {status}")
        if not ask_yn("Continue anyway?", default=True):
            sys.exit(1)

    # ── Threat intel ───────────────────────────────────────────────────────
    section("Threat Intelligence  (optional — press Enter to skip)")
    env["ABUSEIPDB_API_KEY"]  = ask("AbuseIPDB API key",  required=False)
    env["VIRUSTOTAL_API_KEY"] = ask("VirusTotal API key", required=False)
    env["THREAT_INTEL_TIMEOUT"] = "10"

    # ── AI backend ─────────────────────────────────────────────────────────
    section("AI Verdict Backend")
    ai_opts: list[tuple[str, str]] = [
        ("claude",        "Anthropic Claude — cloud API (fastest, best quality)"),
        ("ollama",        "Ollama — local LLM, fully offline (llama3, mistral…)"),
        ("openai_compat", "OpenAI-compatible — LM Studio, vLLM, Groq, Together AI…"),
        ("none",          "Disabled — skip AI verdicts"),
    ]
    ai = ask_choice("Choose backend", ai_opts, default="none")
    env["AI_PROVIDER"] = ai

    if ai == "claude":
        env["ANTHROPIC_API_KEY"] = ask("Anthropic API key", secret=True)
        env["CLAUDE_MODEL"]      = ask("Model", "claude-haiku-4-5-20251001")

    elif ai == "ollama":
        env["OLLAMA_URL"]   = ask("Ollama base URL", "http://localhost:11434")
        env["OLLAMA_MODEL"] = ask("Model name", "llama3.2")
        print(f"\n  Testing Ollama at {env['OLLAMA_URL']} …", end=" ", flush=True)
        up, detail = _test_ollama(env["OLLAMA_URL"])
        if up:
            ok(f"available models: {detail}")
        else:
            warn(f"not reachable: {detail}")
            warn("Make sure Ollama is running: ollama serve")

    elif ai == "openai_compat":
        env["OPENAI_COMPAT_URL"]   = ask("API base URL", "http://localhost:1234/v1")
        env["OPENAI_COMPAT_KEY"]   = ask("API key (blank if not required)", required=False)
        env["OPENAI_COMPAT_MODEL"] = ask("Model name", "mistral")

    # ── Server ─────────────────────────────────────────────────────────────
    section("HTTP Server")
    env["HOST"]      = "0.0.0.0"
    env["PORT"]      = ask("Port", "8000")
    env["LOG_LEVEL"] = "INFO"
    public = ask("Public URL (ngrok / reverse proxy, blank to skip)", required=False)
    if public:
        env["PUBLIC_URL"] = public.rstrip("/")

    # ── Asset inventory ────────────────────────────────────────────────────
    section("Asset Inventory  (optional)")
    print(f"  {dim('A YAML file that maps hostnames to criticality, owner, and role.')}")
    print(f"  {dim('The AI uses this to judge whether an alert is suspicious.')}\n")
    asset_path = ask("Path to assets.yml", "assets.yml", required=False) or "assets.yml"
    env["ASSET_INVENTORY_PATH"] = asset_path
    if not pathlib.Path(asset_path).exists():
        example = ROOT / "assets.example.yml"
        if example.exists():
            if ask_yn(f"Copy assets.example.yml to {asset_path} as a starting point?", default=True):
                shutil.copy(example, asset_path)
                ok(f"Copied. Edit {bold(asset_path)} to describe your hosts.")

    # ── Write .env ─────────────────────────────────────────────────────────
    section("Writing .env")
    env_path = ROOT / ".env"
    if env_path.exists():
        if not ask_yn(f"{env_path} already exists. Overwrite?", default=False):
            env_path = ROOT / ".env.new"
            print(f"  Writing to {bold(str(env_path))} instead.")

    lines: list[str] = [
        "# elastic-mcp-triage — generated by install.py",
        "",
        "# Elasticsearch",
        f"ELASTIC_URL={env['ELASTIC_URL']}",
        f"ELASTIC_USERNAME={env['ELASTIC_USERNAME']}",
        f"ELASTIC_PASSWORD={env['ELASTIC_PASSWORD']}",
        f"ELASTIC_VERIFY_SSL={env['ELASTIC_VERIFY_SSL']}",
        f"ELASTIC_INDEX={env['ELASTIC_INDEX']}",
        f"ELASTIC_TIMEOUT={env['ELASTIC_TIMEOUT']}",
        "",
        "# Threat intelligence (leave blank to disable)",
        f"ABUSEIPDB_API_KEY={env.get('ABUSEIPDB_API_KEY', '')}",
        f"VIRUSTOTAL_API_KEY={env.get('VIRUSTOTAL_API_KEY', '')}",
        f"THREAT_INTEL_TIMEOUT={env['THREAT_INTEL_TIMEOUT']}",
        "",
        "# AI verdict backend: claude | ollama | openai_compat | none",
        f"AI_PROVIDER={ai}",
    ]

    if ai == "claude":
        lines += [
            f"ANTHROPIC_API_KEY={env.get('ANTHROPIC_API_KEY', '')}",
            f"CLAUDE_MODEL={env.get('CLAUDE_MODEL', 'claude-haiku-4-5-20251001')}",
        ]
    elif ai == "ollama":
        lines += [
            f"OLLAMA_URL={env.get('OLLAMA_URL', 'http://localhost:11434')}",
            f"OLLAMA_MODEL={env.get('OLLAMA_MODEL', 'llama3.2')}",
        ]
    elif ai == "openai_compat":
        lines += [
            f"OPENAI_COMPAT_URL={env.get('OPENAI_COMPAT_URL', '')}",
            f"OPENAI_COMPAT_KEY={env.get('OPENAI_COMPAT_KEY', '')}",
            f"OPENAI_COMPAT_MODEL={env.get('OPENAI_COMPAT_MODEL', 'mistral')}",
        ]

    lines += [
        "",
        "# HTTP server",
        f"HOST={env['HOST']}",
        f"PORT={env['PORT']}",
        f"LOG_LEVEL={env['LOG_LEVEL']}",
    ]
    if env.get("PUBLIC_URL"):
        lines.append(f"PUBLIC_URL={env['PUBLIC_URL']}")

    lines += [
        "",
        "# Asset inventory",
        f"ASSET_INVENTORY_PATH={env['ASSET_INVENTORY_PATH']}",
        "",
        "# Related events window around an alert",
        "RELATED_EVENTS_WINDOW_MIN=15",
        "RELATED_EVENTS_MAX=50",
    ]

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok(f"Written: {bold(str(env_path))}")

    # ── Done ───────────────────────────────────────────────────────────────
    port = env["PORT"]
    print(f"\n  {bold(green('Setup complete.'))}\n")
    print(f"  Install dependencies:  {cyan('pip install -r requirements.txt')}")
    print(f"  Start the server:      {cyan('python server.py')}")
    print(f"  Open the UI:           {cyan('http://localhost:' + port)}")
    if env.get("PUBLIC_URL"):
        print(f"  Public URL:            {cyan(env['PUBLIC_URL'])}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Cancelled.')}\n")
        sys.exit(0)
