#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 elastic-mcp-triage contributors
"""
Alert Triage Agent — one-command installer.

Works on Ubuntu / Debian / RHEL / Windows 10+
No git required — downloads and installs everything automatically.

── Linux / macOS ──────────────────────────────────────────────────────────────
  curl -fsSL https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -o /tmp/ata.py && python3 /tmp/ata.py

── Windows PowerShell ─────────────────────────────────────────────────────────
  Invoke-WebRequest https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -OutFile "$env:TEMP\ata.py"; python "$env:TEMP\ata.py"

── Already cloned ─────────────────────────────────────────────────────────────
  python3 install.py   (Linux)
  python  install.py   (Windows)
"""

from __future__ import annotations

import getpass
import io
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

# ── Python version guard ──────────────────────────────────────────────────────
if sys.version_info < (3, 11):
    sys.exit(
        f"Python 3.11+ required (you have {platform.python_version()}).\n"
        "Download from https://www.python.org/downloads/"
    )

REPO_URL  = "https://github.com/masterlion-hash/Alert-Triage-Agent"
REPO_ZIP  = f"{REPO_URL}/archive/refs/heads/main.zip"

ROOT     = pathlib.Path(__file__).resolve().parent
IS_WIN   = platform.system() == "Windows"
VENV     = ROOT / ".venv"
VENV_PY  = VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
VENV_PIP = VENV / ("Scripts/pip.exe"    if IS_WIN else "bin/pip")

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

def ok(m):   print(f"  {green('ok')}  {m}")
def warn(m): print(f"  {yellow('!!')}  {m}")
def err(m):  print(f"  {red('ERR')}  {m}"); sys.exit(1)
def hdr(t):  print(f"\n{bold(blue('──'))} {bold(t)}")


# ── Prompt helpers ────────────────────────────────────────────────────────────

def ask(label: str, default: str = "", secret: bool = False,
        required: bool = True) -> str:
    hint   = f" {dim('[' + default + ']')}" if default else ""
    prompt = f"   {bold(label)}{hint}: "
    while True:
        try:
            val = getpass.getpass(prompt) if secret else input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(); raise
        if val:         return val
        if default:     return default
        if not required:return ""
        print(f"   {red('Required.')}")


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
        print(f"   {red('Enter 1–' + str(len(options)))} ")


# ── System helpers ────────────────────────────────────────────────────────────

def run(cmd: list[str], check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        err(f"Command failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return (r.stdout or "").strip()


def pip_install(*args: str) -> None:
    run([str(VENV_PIP), "install", "-q", *args])


def test_elastic(url: str, user: str, pwd: str,
                 verify: bool) -> tuple[bool, str]:
    try:
        import base64, json, ssl
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req   = urllib.request.Request(
            url.rstrip("/") + "/_cluster/health",
            headers={"Authorization": f"Basic {creds}"})
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            return True, __import__("json").loads(r.read()).get("status","?")
    except Exception as exc:
        return False, str(exc)


def test_ollama(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(
                url.rstrip("/") + "/api/tags", timeout=5) as r:
            models = [m["name"] for m in
                      __import__("json").loads(r.read()).get("models", [])]
            return True, ", ".join(models[:4]) or "no models pulled yet"
    except Exception as exc:
        return False, str(exc)


# ── Bootstrap: download repo when running outside the project ─────────────────

def _download_zip(target: pathlib.Path) -> None:
    print(f"   Downloading from GitHub …", end=" ", flush=True)
    try:
        with urllib.request.urlopen(REPO_ZIP, timeout=60) as r:
            data = r.read()
    except Exception as exc:
        err(f"Download failed: {exc}")
    print(green("done"))

    print(f"   Extracting …", end=" ", flush=True)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        top = zf.namelist()[0].split("/")[0]
        with tempfile.TemporaryDirectory() as tmp:
            zf.extractall(tmp)
            extracted = pathlib.Path(tmp) / top
            for item in extracted.iterdir():
                dst = target / item.name
                if dst.exists():
                    shutil.rmtree(dst) if dst.is_dir() else dst.unlink()
                shutil.move(str(item), str(dst))
    print(green("done"))


def bootstrap() -> None:
    """Download the repo and re-exec install.py from it."""
    hdr("Downloading Alert Triage Agent")

    default_dir = (
        pathlib.Path(os.environ.get("USERPROFILE", "C:/"))
        if IS_WIN else pathlib.Path.home()
    ) / "alert-triage-agent"

    target = pathlib.Path(ask("Install directory", str(default_dir)))

    if (target / "server.py").exists():
        ok(f"Repository already present at {target}")
    else:
        target.mkdir(parents=True, exist_ok=True)

        # Try git clone first, fall back to zip
        if shutil.which("git"):
            print(f"   Cloning repository …", end=" ", flush=True)
            r = subprocess.run(
                ["git", "clone", "--depth=1", f"{REPO_URL}.git", str(target)],
                capture_output=True, text=True)
            if r.returncode == 0:
                print(green("done"))
            else:
                print(yellow("git clone failed, using zip download"))
                _download_zip(target)
        else:
            warn("git not found — downloading zip")
            _download_zip(target)

    new_script = target / "install.py"
    if not new_script.exists():
        err(f"install.py not found in {target} — download may have failed.")

    print(f"\n   Continuing setup in {bold(str(target))} …\n")
    # Re-exec from the actual project directory
    os.execv(sys.executable, [sys.executable, str(new_script)])


# ── Step 1: virtual environment ───────────────────────────────────────────────

def setup_venv() -> None:
    hdr("Python environment")
    if VENV.exists():
        ok(f"Virtual environment: {dim(str(VENV))}")
    else:
        print(f"   Creating virtual environment …", end=" ", flush=True)
        run([sys.executable, "-m", "venv", str(VENV)])
        print(green("done"))

    print(f"   Installing dependencies …", end=" ", flush=True)
    pip_install("--upgrade", "pip")
    pip_install("-r", str(ROOT / "requirements.txt"))
    print(green("done"))
    ok("Dependencies ready")


# ── Step 2: config wizard ─────────────────────────────────────────────────────

def run_wizard() -> dict[str, str]:
    env: dict[str, str] = {}

    hdr("Elasticsearch")
    env["ELASTIC_URL"]      = ask("URL", "https://localhost:9200")
    env["ELASTIC_USERNAME"] = ask("Username", "elastic")
    env["ELASTIC_PASSWORD"] = ask("Password", secret=True)
    verify = ask_yn("Verify SSL certificate?", default=False)
    env["ELASTIC_VERIFY_SSL"] = "true" if verify else "false"
    env["ELASTIC_INDEX"]    = ask("Alerts index",
                                  ".alerts-security.alerts-default")
    env["ELASTIC_TIMEOUT"]  = "30"

    print(f"\n   Testing connection …", end=" ", flush=True)
    connected, status = test_elastic(
        env["ELASTIC_URL"], env["ELASTIC_USERNAME"],
        env["ELASTIC_PASSWORD"], verify)
    if connected:
        print(green(f"connected ({status})"))
    else:
        print(yellow(f"unreachable — {status}"))
        if not ask_yn("Continue anyway?", default=True):
            sys.exit(0)

    hdr("Threat intelligence  (press Enter to skip)")
    env["ABUSEIPDB_API_KEY"]  = ask("AbuseIPDB API key",  required=False)
    env["VIRUSTOTAL_API_KEY"] = ask("VirusTotal API key", required=False)
    env["THREAT_INTEL_TIMEOUT"] = "10"

    hdr("AI verdict backend")
    ai = ask_menu("Choose backend", [
        ("claude",        "Anthropic Claude — cloud API"),
        ("ollama",        "Ollama — local LLM, fully offline"),
        ("openai_compat", "OpenAI-compatible — LM Studio, Groq, vLLM …"),
        ("none",          "Disabled"),
    ], default="none")
    env["AI_PROVIDER"] = ai

    if ai == "claude":
        env["ANTHROPIC_API_KEY"] = ask("Anthropic API key", secret=True)
        env["CLAUDE_MODEL"]      = ask("Model", "claude-haiku-4-5-20251001")
    elif ai == "ollama":
        env["OLLAMA_URL"]   = ask("Ollama URL", "http://localhost:11434")
        env["OLLAMA_MODEL"] = ask("Model name", "llama3.2")
        print(f"\n   Testing Ollama …", end=" ", flush=True)
        up, detail = test_ollama(env["OLLAMA_URL"])
        print(green(f"online ({detail})") if up else yellow(f"unreachable — {detail}"))
        if not up:
            warn("Run  ollama serve  before starting the triage server.")
    elif ai == "openai_compat":
        env["OPENAI_COMPAT_URL"]   = ask("API base URL",
                                          "http://localhost:1234/v1")
        env["OPENAI_COMPAT_KEY"]   = ask("API key (blank if none)",
                                          required=False)
        env["OPENAI_COMPAT_MODEL"] = ask("Model name", "mistral")

    hdr("HTTP server")
    env["HOST"]      = "0.0.0.0"
    env["PORT"]      = ask("Port", "8000")
    env["LOG_LEVEL"] = "INFO"
    pub = ask("Public URL — ngrok / reverse proxy (blank to skip)",
              required=False)
    if pub:
        env["PUBLIC_URL"] = pub.rstrip("/")

    hdr("Asset inventory  (optional)")
    print(f"   {dim('YAML file: hostnames mapped to criticality, owner, role.')}")
    print(f"   {dim('Helps the AI give better verdicts.')}\n")
    asset = ask("Path to assets.yml", "assets.yml", required=False) or "assets.yml"
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


# ── Step 3: write .env ────────────────────────────────────────────────────────

def write_env(env: dict[str, str]) -> None:
    hdr("Writing .env")
    env_path = ROOT / ".env"
    if env_path.exists() and not ask_yn(".env already exists. Overwrite?",
                                        default=False):
        env_path = ROOT / ".env.new"
        warn(f"Writing to {env_path} instead.")

    ai = env["AI_PROVIDER"]
    lines: list[str] = [
        "# Alert Triage Agent — generated by install.py",
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
        f"ABUSEIPDB_API_KEY={env.get('ABUSEIPDB_API_KEY','')}",
        f"VIRUSTOTAL_API_KEY={env.get('VIRUSTOTAL_API_KEY','')}",
        f"THREAT_INTEL_TIMEOUT={env['THREAT_INTEL_TIMEOUT']}",
        "",
        "# AI backend: claude | ollama | openai_compat | none",
        f"AI_PROVIDER={ai}",
    ]
    if ai == "claude":
        lines += [f"ANTHROPIC_API_KEY={env.get('ANTHROPIC_API_KEY','')}",
                  f"CLAUDE_MODEL={env.get('CLAUDE_MODEL','')}"]
    elif ai == "ollama":
        lines += [f"OLLAMA_URL={env.get('OLLAMA_URL','')}",
                  f"OLLAMA_MODEL={env.get('OLLAMA_MODEL','')}"]
    elif ai == "openai_compat":
        lines += [f"OPENAI_COMPAT_URL={env.get('OPENAI_COMPAT_URL','')}",
                  f"OPENAI_COMPAT_KEY={env.get('OPENAI_COMPAT_KEY','')}",
                  f"OPENAI_COMPAT_MODEL={env.get('OPENAI_COMPAT_MODEL','')}"]
    lines += [
        "",
        "# Server",
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
        "# Related events window",
        f"RELATED_EVENTS_WINDOW_MIN={env['RELATED_EVENTS_WINDOW_MIN']}",
        f"RELATED_EVENTS_MAX={env['RELATED_EVENTS_MAX']}",
    ]
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok(f"Written: {bold(str(env_path))}")


# ── Step 4: start scripts ─────────────────────────────────────────────────────

def write_start_scripts() -> None:
    hdr("Start scripts")
    if IS_WIN:
        bat = ROOT / "start.bat"
        bat.write_text(
            '@echo off\ncd /d "%~dp0"\n'
            '.venv\\Scripts\\python server.py\npause\n',
            encoding="utf-8")
        ok(f"Created {bold('start.bat')}")
    else:
        sh = ROOT / "start.sh"
        sh.write_text(
            '#!/usr/bin/env bash\nset -e\ncd "$(dirname "$0")"\n'
            'exec .venv/bin/python server.py\n',
            encoding="utf-8")
        sh.chmod(0o755)
        ok(f"Created {bold('start.sh')}")


# ── Step 5: optional service ──────────────────────────────────────────────────

def install_service(port: str) -> None:
    if not ask_yn("Install as a background service (auto-start on boot)?",
                  default=False):
        return
    if IS_WIN:
        _task_scheduler(port)
    else:
        _systemd(port)


def _systemd(port: str) -> None:
    svc = pathlib.Path("/etc/systemd/system/alert-triage.service")
    content = (
        "[Unit]\nDescription=Alert Triage Agent\nAfter=network.target\n\n"
        "[Service]\nType=simple\n"
        f"WorkingDirectory={ROOT}\nEnvironmentFile={ROOT}/.env\n"
        f"ExecStart={VENV_PY} server.py\nRestart=on-failure\nRestartSec=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    try:
        svc.write_text(content, encoding="utf-8")
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "alert-triage"])
        ok("systemd service installed and started")
    except PermissionError:
        tmp = pathlib.Path(tempfile.gettempdir()) / "alert-triage.service"
        tmp.write_text(content, encoding="utf-8")
        warn("Need sudo to install the service. Run:")
        print(f"\n   {cyan(f'sudo cp {tmp} /etc/systemd/system/')}")
        print(f"   {cyan('sudo systemctl daemon-reload')}")
        print(f"   {cyan('sudo systemctl enable --now alert-triage')}\n")


def _task_scheduler(port: str) -> None:
    task = "AlertTriageAgent"
    try:
        subprocess.run(["schtasks", "/Delete", "/TN", task, "/F"],
                       capture_output=True)
        run(["schtasks", "/Create", "/TN", task,
             "/TR", f'"{VENV_PY}" "{ROOT / "server.py"}"',
             "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
        ok(f"Windows Task Scheduler entry '{task}' created (runs at logon)")
    except Exception as exc:
        warn(f"Could not create scheduled task: {exc}")
        warn(f"Start manually: {cyan('start.bat')}")


# ── Banner ────────────────────────────────────────────────────────────────────

def banner() -> None:
    print()
    print(bold(cyan("  ╔═══════════════════════════════════════╗")))
    print(bold(cyan("  ║    Alert Triage Agent  —  Installer    ║")))
    print(bold(cyan("  ╚═══════════════════════════════════════╝")))
    print(f"  {dim('Platform:')}  {platform.system()} {platform.release()}")
    print(f"  {dim('Python:')}    {platform.python_version()}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    banner()

    # If server.py is missing we're running standalone — download the repo first
    if not (ROOT / "server.py").exists():
        bootstrap()
        # bootstrap() calls os.execv so execution never continues past this line
        sys.exit(1)

    try:
        setup_venv()
        env = run_wizard()
        write_env(env)
        write_start_scripts()
        install_service(env["PORT"])
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Cancelled.')}\n")
        sys.exit(0)

    port    = env["PORT"]
    pub_url = env.get("PUBLIC_URL", "")

    print()
    print(bold(green("  Setup complete!")))
    print()
    if IS_WIN:
        print(f"  Start server  :  {cyan('start.bat')}")
    else:
        print(f"  Start server  :  {cyan('bash start.sh')}")
    print()
    print(f"  Open UI       :  {cyan('http://localhost:' + port)}")
    if pub_url:
        print(f"  Public URL    :  {cyan(pub_url)}")
    print(f"  MCP endpoint  :  {cyan('http://localhost:' + port + '/mcp/mcp')}")
    print()


if __name__ == "__main__":
    main()
