#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""
Alert Triage Agent — one-command installer.

Works on Ubuntu / Debian / RHEL / Windows 10+

    python3 install.py        # Linux / macOS
    python  install.py        # Windows
"""

from __future__ import annotations

import getpass
import os
import pathlib
import platform
import shutil
import subprocess
import sys

# ── Python version guard ──────────────────────────────────────────────────────
if sys.version_info < (3, 11):
    sys.exit(f"Python 3.11+ required (you have {platform.python_version()}). "
             "Download from https://python.org")

ROOT    = pathlib.Path(__file__).parent.resolve()
IS_WIN  = platform.system() == "Windows"
VENV    = ROOT / (".venv" if not IS_WIN else ".venv")
VENV_PY = VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
VENV_PIP= VENV / ("Scripts/pip.exe"    if IS_WIN else "bin/pip")

# ── Colour helpers (no deps) ──────────────────────────────────────────────────
_TTY = sys.stdout.isatty()

def _c(code: str, t: str) -> str:
    return f"\033[{code}m{t}\033[0m" if _TTY else t

def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)
def green(t):  return _c("92", t)
def yellow(t): return _c("93", t)
def red(t):    return _c("91", t)
def cyan(t):   return _c("96", t)
def blue(t):   return _c("94", t)

def ok(m):   print(f"  {green('✔')}  {m}")
def warn(m): print(f"  {yellow('!')}  {m}")
def err(m):  print(f"  {red('✘')}  {m}"); sys.exit(1)
def hdr(t):  print(f"\n{bold(blue('──'))} {bold(t)}")

# ── Prompt helpers ────────────────────────────────────────────────────────────

def ask(label: str, default: str = "", secret: bool = False,
        required: bool = True) -> str:
    hint = f" {dim('[' + default + ']')}" if default else ""
    prompt = f"   {bold(label)}{hint}: "
    while True:
        try:
            val = getpass.getpass(prompt) if secret else input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(); raise
        if val:
            return val
        if default:
            return default
        if not required:
            return ""
        print(f"   {red('Required — please enter a value.')}")


def ask_yn(label: str, default: bool = True) -> bool:
    hint = dim("Y/n") if default else dim("y/N")
    try:
        raw = input(f"   {bold(label)} [{hint}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(); raise
    return default if not raw else raw in ("y", "yes", "1")


def ask_menu(label: str, options: list[tuple[str, str]],
             default: str | None = None) -> str:
    for i, (key, desc) in enumerate(options, 1):
        marker = green("*") if key == default else " "
        print(f"   {marker} {bold(str(i))}. {bold(key):<16}  {dim(desc)}")
    dflt_n = next((str(i) for i, (k, _) in enumerate(options, 1)
                   if k == default), "")
    hint = f" {dim('[' + dflt_n + ']')}" if dflt_n else ""
    while True:
        try:
            raw = input(f"   {bold(label)}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); raise
        if not raw and dflt_n:
            return options[int(dflt_n) - 1][0]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(f"   {red('Enter a number 1–' + str(len(options)))}")


# ── System helpers ────────────────────────────────────────────────────────────

def run(cmd: list[str], check: bool = True, capture: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=capture,
                       text=True, check=False)
    if check and r.returncode != 0:
        err(f"Command failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return (r.stdout or "").strip()


def pip(*args: str) -> None:
    run([str(VENV_PIP), "install", "-q", *args])


def test_elastic(url: str, user: str, pwd: str,
                 verify: bool) -> tuple[bool, str]:
    try:
        import urllib.request, urllib.error, ssl, base64, json
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req   = urllib.request.Request(
            url.rstrip("/") + "/_cluster/health",
            headers={"Authorization": f"Basic {creds}"})
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            return True, json.loads(r.read()).get("status", "green")
    except Exception as exc:
        return False, str(exc)


def test_ollama(url: str) -> tuple[bool, str]:
    try:
        import urllib.request, json
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags",
                                    timeout=5) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models", [])]
            return True, ", ".join(models[:4]) or "no models pulled yet"
    except Exception as exc:
        return False, str(exc)


# ── Step 1 — virtual environment ──────────────────────────────────────────────

def setup_venv() -> None:
    hdr("Setting up Python environment")
    if VENV.exists():
        ok(f"Virtual environment already exists at {dim(str(VENV))}")
    else:
        print(f"   Creating virtual environment …", end=" ", flush=True)
        run([sys.executable, "-m", "venv", str(VENV)])
        print(green("done"))

    print(f"   Installing dependencies …", end=" ", flush=True)
    pip("--upgrade", "pip")
    pip("-r", str(ROOT / "requirements.txt"))
    print(green("done"))
    ok("Dependencies installed")


# ── Step 2 — interactive config wizard ───────────────────────────────────────

def run_wizard() -> dict[str, str]:
    env: dict[str, str] = {}

    # ── Elasticsearch ─────────────────────────────────────────────────────
    hdr("Elasticsearch connection")
    env["ELASTIC_URL"]      = ask("URL", "https://localhost:9200")
    env["ELASTIC_USERNAME"] = ask("Username", "elastic")
    env["ELASTIC_PASSWORD"] = ask("Password", secret=True)
    verify = ask_yn("Verify SSL certificate?", default=False)
    env["ELASTIC_VERIFY_SSL"] = "true" if verify else "false"
    env["ELASTIC_INDEX"]    = ask("Alerts index",
                                  ".alerts-security.alerts-default")
    env["ELASTIC_TIMEOUT"]  = "30"

    print(f"\n   Testing connection …", end=" ", flush=True)
    ok_conn, status = test_elastic(
        env["ELASTIC_URL"], env["ELASTIC_USERNAME"],
        env["ELASTIC_PASSWORD"], verify)
    if ok_conn:
        print(green(f"connected  ({status})"))
    else:
        print(yellow(f"unreachable — {status}"))
        if not ask_yn("Continue anyway?", default=True):
            sys.exit(0)

    # ── Threat intel ──────────────────────────────────────────────────────
    hdr("Threat intelligence  (press Enter to skip)")
    env["ABUSEIPDB_API_KEY"]  = ask("AbuseIPDB API key",  required=False)
    env["VIRUSTOTAL_API_KEY"] = ask("VirusTotal API key", required=False)
    env["THREAT_INTEL_TIMEOUT"] = "10"

    # ── AI backend ────────────────────────────────────────────────────────
    hdr("AI verdict backend")
    ai = ask_menu("Choose", [
        ("claude",        "Anthropic Claude API — cloud, best quality"),
        ("ollama",        "Ollama — local/offline LLM (llama3, mistral …)"),
        ("openai_compat", "OpenAI-compatible — LM Studio, Groq, vLLM …"),
        ("none",          "Disabled — no AI verdict"),
    ], default="none")
    env["AI_PROVIDER"] = ai

    if ai == "claude":
        env["ANTHROPIC_API_KEY"] = ask("Anthropic API key", secret=True)
        env["CLAUDE_MODEL"]      = ask("Model",
                                        "claude-haiku-4-5-20251001")

    elif ai == "ollama":
        env["OLLAMA_URL"]   = ask("Ollama URL", "http://localhost:11434")
        env["OLLAMA_MODEL"] = ask("Model name", "llama3.2")
        print(f"\n   Testing Ollama …", end=" ", flush=True)
        up, detail = test_ollama(env["OLLAMA_URL"])
        if up:
            print(green(f"online  ({detail})"))
        else:
            print(yellow(f"not reachable — {detail}"))
            warn("Make sure Ollama is running:  ollama serve")

    elif ai == "openai_compat":
        env["OPENAI_COMPAT_URL"]   = ask("API base URL",
                                          "http://localhost:1234/v1")
        env["OPENAI_COMPAT_KEY"]   = ask("API key (blank if none)",
                                          required=False)
        env["OPENAI_COMPAT_MODEL"] = ask("Model name", "mistral")

    # ── Server ────────────────────────────────────────────────────────────
    hdr("HTTP server")
    env["HOST"]      = "0.0.0.0"
    env["PORT"]      = ask("Port", "8000")
    env["LOG_LEVEL"] = "INFO"
    pub = ask("Public URL — ngrok / reverse proxy (blank to skip)",
              required=False)
    if pub:
        env["PUBLIC_URL"] = pub.rstrip("/")

    # ── Asset inventory ───────────────────────────────────────────────────
    hdr("Asset inventory  (optional)")
    print(f"   {dim('YAML file mapping hostnames → criticality, owner, role.')}")
    print(f"   {dim('The AI uses this to give better verdicts.')}\n")
    asset = ask("Path to assets.yml", "assets.yml", required=False) \
            or "assets.yml"
    env["ASSET_INVENTORY_PATH"] = asset
    if not (ROOT / asset).exists():
        ex = ROOT / "assets.example.yml"
        if ex.exists() and ask_yn(
                f"Copy assets.example.yml → {asset}?", default=True):
            shutil.copy(ex, ROOT / asset)
            ok(f"Copied. Edit {bold(asset)} to describe your hosts.")

    env["RELATED_EVENTS_WINDOW_MIN"] = "15"
    env["RELATED_EVENTS_MAX"]        = "50"
    return env


# ── Step 3 — write .env ───────────────────────────────────────────────────────

def write_env(env: dict[str, str]) -> pathlib.Path:
    hdr("Writing configuration")
    env_path = ROOT / ".env"
    if env_path.exists() and not ask_yn(
            ".env already exists. Overwrite?", default=False):
        env_path = ROOT / ".env.new"
        warn(f"Writing to {env_path} instead.")

    ai = env["AI_PROVIDER"]
    blocks: list[str] = [
        "# Alert Triage Agent — generated by install.py\n",
        "# Elasticsearch",
        f"ELASTIC_URL={env['ELASTIC_URL']}",
        f"ELASTIC_USERNAME={env['ELASTIC_USERNAME']}",
        f"ELASTIC_PASSWORD={env['ELASTIC_PASSWORD']}",
        f"ELASTIC_VERIFY_SSL={env['ELASTIC_VERIFY_SSL']}",
        f"ELASTIC_INDEX={env['ELASTIC_INDEX']}",
        f"ELASTIC_TIMEOUT={env['ELASTIC_TIMEOUT']}",
        "",
        "# Threat intelligence",
        f"ABUSEIPDB_API_KEY={env.get('ABUSEIPDB_API_KEY','')}",
        f"VIRUSTOTAL_API_KEY={env.get('VIRUSTOTAL_API_KEY','')}",
        f"THREAT_INTEL_TIMEOUT={env['THREAT_INTEL_TIMEOUT']}",
        "",
        "# AI backend",
        f"AI_PROVIDER={ai}",
    ]
    if ai == "claude":
        blocks += [f"ANTHROPIC_API_KEY={env.get('ANTHROPIC_API_KEY','')}",
                   f"CLAUDE_MODEL={env.get('CLAUDE_MODEL','')}"]
    elif ai == "ollama":
        blocks += [f"OLLAMA_URL={env.get('OLLAMA_URL','')}",
                   f"OLLAMA_MODEL={env.get('OLLAMA_MODEL','')}"]
    elif ai == "openai_compat":
        blocks += [f"OPENAI_COMPAT_URL={env.get('OPENAI_COMPAT_URL','')}",
                   f"OPENAI_COMPAT_KEY={env.get('OPENAI_COMPAT_KEY','')}",
                   f"OPENAI_COMPAT_MODEL={env.get('OPENAI_COMPAT_MODEL','')}"]
    blocks += [
        "",
        "# Server",
        f"HOST={env['HOST']}",
        f"PORT={env['PORT']}",
        f"LOG_LEVEL={env['LOG_LEVEL']}",
    ]
    if env.get("PUBLIC_URL"):
        blocks.append(f"PUBLIC_URL={env['PUBLIC_URL']}")
    blocks += [
        "",
        "# Asset inventory",
        f"ASSET_INVENTORY_PATH={env['ASSET_INVENTORY_PATH']}",
        "",
        "# Related events window",
        f"RELATED_EVENTS_WINDOW_MIN={env['RELATED_EVENTS_WINDOW_MIN']}",
        f"RELATED_EVENTS_MAX={env['RELATED_EVENTS_MAX']}",
    ]
    env_path.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    ok(f"Written: {bold(str(env_path))}")
    return env_path


# ── Step 4 — start scripts ────────────────────────────────────────────────────

def write_start_scripts(port: str) -> None:
    hdr("Creating start scripts")

    if not IS_WIN:
        sh = ROOT / "start.sh"
        sh.write_text(
            f'#!/usr/bin/env bash\ncd "$(dirname "$0")"\n'
            f'.venv/bin/python server.py\n', encoding="utf-8")
        sh.chmod(0o755)
        ok(f"Created {bold('start.sh')}")
    else:
        bat = ROOT / "start.bat"
        bat.write_text(
            f'@echo off\ncd /d "%~dp0"\n'
            f'.venv\\Scripts\\python server.py\npause\n',
            encoding="utf-8")
        ok(f"Created {bold('start.bat')}")


# ── Step 5 — optional service ─────────────────────────────────────────────────

def install_service(port: str) -> None:
    if not ask_yn("Install as a background service (auto-start on boot)?",
                  default=False):
        return

    if IS_WIN:
        _install_windows_service(port)
    else:
        _install_systemd_service(port)


def _install_systemd_service(port: str) -> None:
    svc_path = pathlib.Path("/etc/systemd/system/alert-triage.service")
    content  = f"""\
[Unit]
Description=Alert Triage Agent
After=network.target

[Service]
Type=simple
WorkingDirectory={ROOT}
EnvironmentFile={ROOT}/.env
ExecStart={VENV_PY} server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    try:
        svc_path.write_text(content, encoding="utf-8")
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "alert-triage"])
        ok("systemd service installed and started")
        ok(f"Control:  {cyan('sudo systemctl start|stop|status alert-triage')}")
    except PermissionError:
        # write to /tmp and give instructions
        tmp = pathlib.Path("/tmp/alert-triage.service")
        tmp.write_text(content, encoding="utf-8")
        warn("Need sudo to install the service. Run:")
        print(f"\n   {cyan('sudo cp /tmp/alert-triage.service /etc/systemd/system/')}")
        print(f"   {cyan('sudo systemctl daemon-reload')}")
        print(f"   {cyan('sudo systemctl enable --now alert-triage')}\n")
    except FileNotFoundError:
        warn("systemctl not found — skipping service install.")


def _install_windows_service(port: str) -> None:
    # Register via Task Scheduler (no admin required for current user)
    task  = "AlertTriageAgent"
    cmd   = str(VENV_PY)
    args  = f'"{ROOT / "server.py"}"'
    try:
        # Remove old task if it exists
        subprocess.run(
            ["schtasks", "/Delete", "/TN", task, "/F"],
            capture_output=True)
        run(["schtasks", "/Create", "/TN", task,
             "/TR", f'"{cmd}" {args}',
             "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
        ok(f"Windows scheduled task '{task}' created (runs at logon)")
        ok(f"Start now: {cyan('schtasks /Run /TN AlertTriageAgent')}")
    except Exception as exc:
        warn(f"Could not create scheduled task: {exc}")
        warn(f"Start manually: {cyan('start.bat')}")


# ── Main ──────────────────────────────────────────────────────────────────────

def banner() -> None:
    print()
    print(bold(cyan("  ╔══════════════════════════════════════╗")))
    print(bold(cyan("  ║   Alert Triage Agent — Installer      ║")))
    print(bold(cyan("  ╚══════════════════════════════════════╝")))
    print(f"  Platform : {platform.system()} {platform.release()}")
    print(f"  Python   : {platform.python_version()}")
    print(f"  Directory: {ROOT}")
    print()


def main() -> None:
    banner()

    try:
        setup_venv()
        env = run_wizard()
        write_env(env)
        write_start_scripts(env["PORT"])
        install_service(env["PORT"])
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Cancelled.')}")
        sys.exit(0)

    # ── Done ──────────────────────────────────────────────────────────────
    port    = env["PORT"]
    pub_url = env.get("PUBLIC_URL", "")

    print()
    print(bold(green("  ✔  Setup complete!")))
    print()
    if IS_WIN:
        print(f"  Start server :  {cyan('start.bat')}")
    else:
        print(f"  Start server :  {cyan('bash start.sh')}")
        print(f"                  {dim('or')}  {cyan('.venv/bin/python server.py')}")
    print()
    print(f"  Open UI      :  {cyan('http://localhost:' + port)}")
    if pub_url:
        print(f"  Public URL   :  {cyan(pub_url)}")
    print(f"  MCP endpoint :  {cyan('http://localhost:' + port + '/mcp/mcp')}")
    print()


if __name__ == "__main__":
    main()
