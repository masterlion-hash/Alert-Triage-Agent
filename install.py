#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Alert Triage Agent — one-command installer.

Works on Ubuntu / Debian / RHEL / Windows 10+
No git required — downloads and installs everything automatically.

── Linux / macOS ──────────────────────────────────────────────────────────────
  curl -fsSL https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -o /tmp/ata.py && python3 /tmp/ata.py

── Windows PowerShell ─────────────────────────────────────────────────────────
  Invoke-WebRequest https://raw.githubusercontent.com/masterlion-hash/Alert-Triage-Agent/main/install.py -OutFile "$env:TEMP\ata.py"; python "$env:TEMP\ata.py"

── Already cloned ─────────────────────────────────────────────────────────────
  python3 install.py   (Linux / macOS)
  python  install.py   (Windows)
"""

from __future__ import annotations

import base64
import ctypes
import getpass
import io
import json
import os
import pathlib
import platform
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
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

def bold(t):    return _c("1",  t)
def dim(t):     return _c("2",  t)
def green(t):   return _c("92", t)
def yellow(t):  return _c("93", t)
def red(t):     return _c("91", t)
def cyan(t):    return _c("96", t)
def blue(t):    return _c("94", t)
def magenta(t): return _c("95", t)

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
        if val:          return val
        if default:      return default
        if not required: return ""
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
        print(f"   {marker} {bold(str(i))}. {bold(key):<20}  {dim(desc)}")
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
        print(f"   {red('Enter 1–' + str(len(options)))}")


# ── System helpers ────────────────────────────────────────────────────────────

def run(cmd: list[str], check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        err(f"Command failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return (r.stdout or "").strip()


def pip_install(*args: str) -> None:
    run([str(VENV_PIP), "install", "-q", *args])


# ── Environment assessment ────────────────────────────────────────────────────

def _get_ram_gb() -> float:
    try:
        if IS_WIN:
            class _MEMSTAT(ctypes.Structure):
                _fields_ = [
                    ("dwLength",                ctypes.c_ulong),
                    ("dwMemoryLoad",             ctypes.c_ulong),
                    ("ullTotalPhys",             ctypes.c_ulonglong),
                    ("ullAvailPhys",             ctypes.c_ulonglong),
                    ("ullTotalPageFile",         ctypes.c_ulonglong),
                    ("ullAvailPageFile",         ctypes.c_ulonglong),
                    ("ullTotalVirtual",          ctypes.c_ulonglong),
                    ("ullAvailVirtual",          ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            s = _MEMSTAT()
            s.dwLength = ctypes.sizeof(s)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))
            return round(s.ullTotalPhys / 1024 ** 3, 1)
        elif platform.system() == "Darwin":
            r = subprocess.run(["sysctl", "-n", "hw.memsize"],
                               capture_output=True, text=True)
            return round(int(r.stdout.strip()) / 1024 ** 3, 1)
        else:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return round(int(line.split()[1]) / 1024 ** 2, 1)
    except Exception:
        pass
    return 0.0


def _detect_gpu() -> tuple[bool, str]:
    r = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
        capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        parts = r.stdout.strip().split(",")
        name  = parts[0].strip()
        vram  = parts[1].strip() if len(parts) > 1 else "?"
        return True, f"NVIDIA {name} ({vram})"
    if not IS_WIN:
        r = subprocess.run(["rocm-smi", "--showproductname"],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return True, "AMD ROCm GPU"
    return False, "none detected"


def assess_environment() -> dict:
    hdr("System check")

    ram_gb   = _get_ram_gb()
    cpu      = os.cpu_count() or 1
    free_gb  = round(shutil.disk_usage(ROOT).free / 1024 ** 3, 1)
    has_gpu, gpu_desc = _detect_gpu()

    ram_col  = green if ram_gb >= 16 else (yellow if ram_gb >= 8 else red)
    disk_col = green if free_gb >= 10 else (yellow if free_gb >= 4 else red)

    print(f"\n   {'OS:':<16} {platform.system()} {platform.release()}")
    print(f"   {'Python:':<16} {platform.python_version()}")
    print(f"   {'RAM:':<16} {ram_col(f'{ram_gb} GB')}")
    print(f"   {'CPU cores:':<16} {cpu}")
    print(f"   {'Free disk:':<16} {disk_col(f'{free_gb} GB')}")
    print(f"   {'GPU:':<16} {(green if has_gpu else dim)(gpu_desc)}")

    return {"ram_gb": ram_gb, "cpu": cpu,
            "free_gb": free_gb, "has_gpu": has_gpu, "gpu_desc": gpu_desc}


# ── Ollama model catalogue ────────────────────────────────────────────────────
#
# (min_ram_gb, ollama_tag, display_label, short_capabilities)
#
MODELS = [
    (
        3, "llama3.2:1b", "Llama 3.2  (1 B)",
        "Extremely lightweight — handles basic alert classification only. "
        "Will miss nuance and complex attack chains. Use only if RAM is very "
        "tight; even then, expect limited reasoning quality.",
        [
            "Basic TRUE/FALSE classification of well-known alert types",
            "Short plain-English summaries",
            "Simple IOC extraction (IP, hash)",
        ],
        [
            "Multi-stage attack chains",
            "Ambiguous or low-signal alerts",
            "Threat hunting suggestions",
        ],
    ),
    (
        4, "phi3:mini", "Phi-3 Mini  (3.8 B)",
        "Compact but surprisingly capable for structured triage tasks. "
        "Handles clear-cut alerts well. Struggles when context is long "
        "or the attack is subtle.",
        [
            "Classifying common alerts with good accuracy",
            "Explaining what triggered the rule in plain English",
            "Flagging obvious IOCs (known-bad IPs, hashes, domains)",
            "Basic lateral movement and credential-abuse patterns",
        ],
        [
            "Complex multi-stage APT campaigns",
            "Highly ambiguous signals requiring deep reasoning",
            "Long correlation across many events",
        ],
    ),
    (
        4, "llama3.2:3b", "Llama 3.2  (3 B)",
        "Solid compact model with good instruction-following. "
        "A good daily driver for most SOC triage on lower-end hardware.",
        [
            "Reliable verdict on common alert types",
            "Summarising host context and alert details",
            "Identifying attack phase (recon, execution, exfil …)",
            "Actionable next-step suggestions",
        ],
        [
            "Sophisticated low-and-slow attacks",
            "Very long event timelines",
        ],
    ),
    (
        8, "mistral:7b", "Mistral 7B",
        "A well-rounded workhorse. Strong reasoning, good contextual "
        "awareness, and reliable verdicts. The recommended minimum for "
        "production SOC use.",
        [
            "All common alert types with high accuracy",
            "Multi-step attack chain analysis",
            "Connecting host context, threat intel and alert details",
            "Structured verdicts with confidence levels",
            "Actionable remediation steps",
        ],
        [
            "Very sophisticated nation-state TTPs (rare edge cases)",
        ],
    ),
    (
        8, "llama3.1:8b", "Llama 3.1  (8 B)",
        "Excellent reasoning and contextual understanding — one of the best "
        "open-source models for security analysis. Highly recommended if "
        "your hardware supports it.",
        [
            "Deep analysis of complex, multi-stage attacks",
            "Campaign pattern identification across alerts",
            "Nuanced verdict with full reasoning trace",
            "Threat hunting query suggestions",
            "MITRE ATT&CK tactic/technique mapping",
        ],
        [],
    ),
    (
        16, "phi3:medium", "Phi-3 Medium  (14 B)",
        "High-quality model with strong instruction-following. "
        "Handles nuanced and ambiguous alerts very well.",
        [
            "All capabilities of 7–8 B models, with greater reliability",
            "Better performance on long, context-heavy alerts",
            "More precise MITRE mapping and hunt recommendations",
        ],
        [],
    ),
]


def _recommend_tag(ram_gb: float, has_gpu: bool) -> str:
    effective = ram_gb * 1.4 if has_gpu else ram_gb
    best = MODELS[0][1]
    for min_ram, tag, *_ in MODELS:
        if effective >= min_ram:
            best = tag
    return best


def _visible_models(ram_gb: float) -> list:
    return [(min_ram, tag, label, desc, can, cant)
            for min_ram, tag, label, desc, can, cant in MODELS
            if ram_gb >= min_ram * 0.75]


# ── RAM advisory ──────────────────────────────────────────────────────────────

def _print_ram_advisory(ram_gb: float, has_gpu: bool) -> None:
    print()
    if ram_gb == 0:
        warn("Could not detect RAM — proceeding with defaults.")
        return
    if ram_gb >= 32 or (has_gpu and ram_gb >= 16):
        print(f"  {green('Great hardware!')} You can run high-quality local models with strong")
        print(f"  reasoning. Expect detailed, reliable verdicts on complex attacks.")
    elif ram_gb >= 16:
        print(f"  {green('Good system.')} Solid mid-size models run comfortably here — you'll")
        print(f"  get reliable verdicts including on multi-stage attack analysis.")
    elif ram_gb >= 8:
        print(f"  {yellow('Decent system.')} Capable 7–8 B models run fine and handle the vast")
        print(f"  majority of SOC alert types. Minor gaps on very complex scenarios.")
    elif ram_gb >= 4:
        print(f"  {yellow('Limited RAM.')} Compact models will work for clear-cut alerts but")
        print(f"  may miss subtlety. For best results consider the {bold('Anthropic Claude API')}")
        print(f"  — it's cloud-based so local RAM doesn't matter.")
    else:
        print(f"  {red('Low RAM')} ({ram_gb} GB). Local AI will be severely constrained.")
        print(f"  The {bold('Anthropic Claude API')} is strongly recommended — it runs in the")
        print(f"  cloud, so your hardware is not a bottleneck at all.")


# ── Model capability display ──────────────────────────────────────────────────

def _print_model_capabilities(tag: str, ram_gb: float, has_gpu: bool) -> None:
    entry = next((e for e in MODELS if e[1] == tag), None)
    if not entry:
        return

    min_ram, _, label, prose, can_do, cant_do = entry
    fits = ram_gb >= min_ram or (has_gpu and ram_gb * 1.4 >= min_ram)

    print()
    print(f"  {bold(cyan('About  ') + bold(label))}")
    print()

    # Prose wrap at 68 chars
    words, line = prose.split(), ""
    for w in words:
        if len(line) + len(w) + 1 > 68:
            print(f"  {dim(line)}")
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        print(f"  {dim(line)}")

    print()
    print(f"  {green('What it handles well:')}")
    for item in can_do:
        print(f"    {green('+')}  {item}")

    if cant_do:
        print()
        print(f"  {yellow('Where it may fall short:')}")
        for item in cant_do:
            print(f"    {yellow('-')}  {item}")

    print()
    ram_note = (f"{green('fits comfortably')}" if fits
                else yellow(f"tight — may be slow; recommended {min_ram} GB"))
    print(f"  {dim('RAM requirement:')}  ~{min_ram} GB  ({ram_note})")

    if has_gpu and fits:
        print(f"  {green('GPU detected')} — inference will be noticeably faster.")
    elif not fits and not has_gpu:
        print()
        warn(f"Your RAM ({ram_gb} GB) is below the recommended {min_ram} GB.")
        warn("The model will still run but may be slow or use swap memory.")
        warn("Consider a smaller model, or add a GPU to help offload layers.")


# ── Ollama helpers ────────────────────────────────────────────────────────────

def _ollama_installed() -> bool:
    if shutil.which("ollama"):
        return True
    if IS_WIN:
        local = pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / \
                "Programs" / "Ollama" / "ollama.exe"
        return local.exists()
    return False


def _install_ollama_linux() -> bool:
    print(f"\n   Fetching Ollama install script …", end=" ", flush=True)
    try:
        with urllib.request.urlopen("https://ollama.com/install.sh",
                                    timeout=30) as r:
            script = r.read().decode()
    except Exception as exc:
        print(red("failed"))
        warn(f"Download error: {exc}")
        return False
    print(green("done"))

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(script)
        tmp = f.name
    os.chmod(tmp, 0o755)
    print(f"   Running installer (may prompt for sudo) …")
    r = subprocess.run(["bash", tmp], check=False)
    pathlib.Path(tmp).unlink(missing_ok=True)
    return r.returncode == 0


def _install_ollama_windows() -> bool:
    url       = "https://ollama.com/download/OllamaSetup.exe"
    installer = pathlib.Path(tempfile.gettempdir()) / "OllamaSetup.exe"
    print(f"\n   Downloading Ollama for Windows …", end=" ", flush=True)
    try:
        urllib.request.urlretrieve(url, str(installer))
    except Exception as exc:
        print(red("failed"))
        warn(f"Download error: {exc}")
        return False
    print(green("done"))
    print(f"   Running installer — follow the on-screen prompts …")
    r = subprocess.run([str(installer)], check=False)
    installer.unlink(missing_ok=True)
    return r.returncode == 0


def ensure_ollama(sysinfo: dict) -> bool:
    hdr("Ollama  (local AI engine)")

    if _ollama_installed():
        ver = run(["ollama", "--version"], check=False)
        ok(f"Ollama is already installed  ({ver or 'version unknown'})")
        return True

    print(f"\n   Ollama is not installed on this system.")
    print(f"   {dim('Ollama runs AI models locally — your data never leaves this machine.')}\n")

    if not ask_yn("Install Ollama now?", default=True):
        warn("Skipping Ollama — AI backend will not be available for local inference.")
        return False

    ok_flag = _install_ollama_windows() if IS_WIN else _install_ollama_linux()

    if ok_flag and _ollama_installed():
        ok("Ollama installed successfully")
        return True

    warn("Ollama installation may not have completed.")
    print(f"   Install manually from: {cyan('https://ollama.com/download')}")
    return False


def _ensure_ollama_running() -> None:
    r = subprocess.run(["ollama", "list"], capture_output=True, text=True,
                       timeout=5)
    if r.returncode == 0:
        return
    print(f"   Starting Ollama server …", end=" ", flush=True)
    if IS_WIN:
        subprocess.Popen(["ollama", "serve"],
                         creationflags=subprocess.CREATE_NEW_CONSOLE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(["ollama", "serve"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    print(green("started"))


def _pull_model(tag: str) -> bool:
    print(f"\n   Pulling {bold(tag)} from Ollama library …")
    print(f"   {dim('Depending on model size and connection speed, this may take')}")
    print(f"   {dim('several minutes. Grab a coffee — it only downloads once.')}\n")
    r = subprocess.run(["ollama", "pull", tag], check=False)
    if r.returncode == 0:
        print()
        ok(f"Model {bold(tag)} is ready")
        return True
    warn(f"Pull returned non-zero. Pull manually later: {cyan('ollama pull ' + tag)}")
    return False


def _model_already_local(tag: str) -> bool:
    out = run(["ollama", "list"], check=False)
    return tag.split(":")[0] in out


# ── Elasticsearch ─────────────────────────────────────────────────────────────

def _test_elastic(url: str, user: str, pwd: str, verify: bool) -> tuple[bool, str]:
    try:
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req   = urllib.request.Request(
            url.rstrip("/") + "/_cluster/health",
            headers={"Authorization": f"Basic {creds}"})
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            data = json.loads(r.read())
            return True, data.get("status", "?")
    except Exception as exc:
        return False, str(exc)


def setup_elastic() -> dict[str, str]:
    hdr("Elasticsearch")
    print(f"   {dim('Enter the details of your Elastic Security / SIEM cluster.')}\n")

    env: dict[str, str] = {}
    env["ELASTIC_URL"]      = ask("Elasticsearch URL", "https://localhost:9200")
    env["ELASTIC_USERNAME"] = ask("Username", "elastic")
    env["ELASTIC_PASSWORD"] = ask("Password", secret=True)
    verify = ask_yn("Verify SSL certificate?", default=False)
    env["ELASTIC_VERIFY_SSL"] = "true" if verify else "false"
    env["ELASTIC_INDEX"]    = ask("Alerts index", ".alerts-security.alerts-default")
    env["ELASTIC_TIMEOUT"]  = "30"

    print(f"\n   Testing connection …", end=" ", flush=True)
    connected, status = _test_elastic(
        env["ELASTIC_URL"], env["ELASTIC_USERNAME"],
        env["ELASTIC_PASSWORD"], verify)
    if connected:
        print(green(f"connected  (cluster health: {status})"))
    else:
        print(yellow(f"unreachable — {status}"))
        if not ask_yn("Continue anyway?", default=True):
            sys.exit(0)

    return env


# ── AI backend ────────────────────────────────────────────────────────────────

def setup_ai(sysinfo: dict, env: dict[str, str]) -> None:
    hdr("AI verdict engine")
    _print_ram_advisory(sysinfo["ram_gb"], sysinfo["has_gpu"])
    print()

    default_ai = "ollama" if sysinfo["ram_gb"] >= 3 else "claude"

    ai = ask_menu("Choose AI backend", [
        ("ollama",        "Ollama — local LLM, fully offline, free"),
        ("claude",        "Anthropic Claude — cloud API, best quality"),
        ("openai_compat", "OpenAI-compatible — LM Studio, Groq, vLLM …"),
        ("none",          "Disabled — no AI verdicts"),
    ], default=default_ai)
    env["AI_PROVIDER"] = ai

    if ai == "ollama":
        _configure_ollama(sysinfo, env)
    elif ai == "claude":
        env["ANTHROPIC_API_KEY"] = ask("Anthropic API key", secret=True)
        env["CLAUDE_MODEL"]      = ask("Model", "claude-haiku-4-5-20251001")
    elif ai == "openai_compat":
        env["OPENAI_COMPAT_URL"]   = ask("API base URL", "http://localhost:1234/v1")
        env["OPENAI_COMPAT_KEY"]   = ask("API key (blank if none)", required=False)
        env["OPENAI_COMPAT_MODEL"] = ask("Model name", "mistral")


def _configure_ollama(sysinfo: dict, env: dict[str, str]) -> None:
    ram_gb  = sysinfo["ram_gb"]
    has_gpu = sysinfo["has_gpu"]

    ollama_ok = ensure_ollama(sysinfo)
    if not ollama_ok:
        print(f"\n   {yellow('Ollama unavailable. Pick a different backend:')}\n")
        fallback = ask_menu("Fallback AI backend", [
            ("claude",        "Anthropic Claude — cloud API"),
            ("openai_compat", "OpenAI-compatible — LM Studio, Groq, vLLM …"),
            ("none",          "Disabled"),
        ], default="none")
        env["AI_PROVIDER"] = fallback
        if fallback == "claude":
            env["ANTHROPIC_API_KEY"] = ask("Anthropic API key", secret=True)
            env["CLAUDE_MODEL"]      = ask("Model", "claude-haiku-4-5-20251001")
        elif fallback == "openai_compat":
            env["OPENAI_COMPAT_URL"]   = ask("API base URL", "http://localhost:1234/v1")
            env["OPENAI_COMPAT_KEY"]   = ask("API key (blank if none)", required=False)
            env["OPENAI_COMPAT_MODEL"] = ask("Model name", "mistral")
        return

    hdr("Choose your AI model")
    print(f"   {dim('The model shapes the quality of every alert verdict.')}")
    print(f"   {dim('Models marked * fit within your available RAM.')}\n")

    visible = _visible_models(ram_gb)
    if not visible:
        visible = [MODELS[0]]

    rec = _recommend_tag(ram_gb, has_gpu)
    options = [
        (tag, f"{'* ' if ram_gb >= mr else '  '}{label}  (~{mr} GB RAM)")
        for mr, tag, label, *_ in visible
    ]
    chosen = ask_menu("Model", options, default=rec)
    env["OLLAMA_MODEL"] = chosen
    env["OLLAMA_URL"]   = ask("Ollama API URL", "http://localhost:11434")

    _print_model_capabilities(chosen, ram_gb, has_gpu)
    print()

    _ensure_ollama_running()
    if _model_already_local(chosen):
        ok(f"Model {bold(chosen)} already downloaded — nothing to pull")
    else:
        if ask_yn(f"Download {bold(chosen)} now?", default=True):
            _pull_model(chosen)
        else:
            warn(f"Not downloaded. Pull later:  {cyan('ollama pull ' + chosen)}")
            warn(f"The server won't give AI verdicts until the model is available.")


# ── Threat intel, server, assets ──────────────────────────────────────────────

def setup_threat_intel(env: dict[str, str]) -> None:
    hdr("Threat intelligence  (press Enter to skip any)")
    print(f"   {dim('Free API keys enrich alerts with IP/domain reputation data.')}\n")
    env["ABUSEIPDB_API_KEY"]    = ask("AbuseIPDB API key",  required=False)
    env["VIRUSTOTAL_API_KEY"]   = ask("VirusTotal API key", required=False)
    env["THREAT_INTEL_TIMEOUT"] = "10"


def setup_server(env: dict[str, str]) -> None:
    hdr("HTTP server")
    env["HOST"]      = "0.0.0.0"
    env["PORT"]      = ask("Port", "8000")
    env["LOG_LEVEL"] = "INFO"
    pub = ask("Public URL — ngrok / reverse proxy (blank to skip)", required=False)
    if pub:
        env["PUBLIC_URL"] = pub.rstrip("/")

    hdr("Asset inventory  (optional)")
    print(f"   {dim('YAML file mapping hostnames to criticality, owner, and role.')}")
    print(f"   {dim('Gives the AI context to make better, more targeted verdicts.')}\n")
    asset = ask("Path to assets.yml", "assets.yml", required=False) or "assets.yml"
    env["ASSET_INVENTORY_PATH"] = asset
    if not (ROOT / asset).exists():
        ex = ROOT / "assets.example.yml"
        if ex.exists() and ask_yn(f"Copy assets.example.yml → {asset}?", default=True):
            shutil.copy(ex, ROOT / asset)
            ok(f"Copied. Edit {bold(asset)} to describe your hosts.")

    env["RELATED_EVENTS_WINDOW_MIN"] = "15"
    env["RELATED_EVENTS_MAX"]        = "50"


# ── Write .env ────────────────────────────────────────────────────────────────

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
        f"ABUSEIPDB_API_KEY={env.get('ABUSEIPDB_API_KEY', '')}",
        f"VIRUSTOTAL_API_KEY={env.get('VIRUSTOTAL_API_KEY', '')}",
        f"THREAT_INTEL_TIMEOUT={env['THREAT_INTEL_TIMEOUT']}",
        "",
        "# AI backend: claude | ollama | openai_compat | none",
        f"AI_PROVIDER={ai}",
    ]
    if ai == "claude":
        lines += [f"ANTHROPIC_API_KEY={env.get('ANTHROPIC_API_KEY', '')}",
                  f"CLAUDE_MODEL={env.get('CLAUDE_MODEL', '')}"]
    elif ai == "ollama":
        lines += [f"OLLAMA_URL={env.get('OLLAMA_URL', '')}",
                  f"OLLAMA_MODEL={env.get('OLLAMA_MODEL', '')}"]
    elif ai == "openai_compat":
        lines += [f"OPENAI_COMPAT_URL={env.get('OPENAI_COMPAT_URL', '')}",
                  f"OPENAI_COMPAT_KEY={env.get('OPENAI_COMPAT_KEY', '')}",
                  f"OPENAI_COMPAT_MODEL={env.get('OPENAI_COMPAT_MODEL', '')}"]
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


# ── Start scripts & service ───────────────────────────────────────────────────

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


def install_service(port: str) -> None:
    if not ask_yn("Install as a background service (auto-start on boot)?",
                  default=False):
        return
    if IS_WIN:
        _task_scheduler()
    else:
        _systemd()


def _systemd() -> None:
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


def _task_scheduler() -> None:
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


# ── Bootstrap: download repo when running as a standalone script ──────────────

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
        if shutil.which("git"):
            print(f"   Cloning repository …", end=" ", flush=True)
            r = subprocess.run(
                ["git", "clone", "--depth=1", f"{REPO_URL}.git", str(target)],
                capture_output=True, text=True)
            if r.returncode == 0:
                print(green("done"))
            else:
                print(yellow("git clone failed — falling back to zip download"))
                _download_zip(target)
        else:
            warn("git not found — downloading zip archive")
            _download_zip(target)

    new_script = target / "install.py"
    if not new_script.exists():
        err(f"install.py not found in {target} — download may have failed.")

    print(f"\n   Continuing setup in {bold(str(target))} …\n")
    os.execv(sys.executable, [sys.executable, str(new_script)])


# ── Virtual environment ───────────────────────────────────────────────────────

def setup_venv() -> None:
    hdr("Python environment")
    if VENV.exists():
        ok(f"Virtual environment exists: {dim(str(VENV))}")
    else:
        print(f"   Creating virtual environment …", end=" ", flush=True)
        run([sys.executable, "-m", "venv", str(VENV)])
        print(green("done"))

    print(f"   Installing dependencies …", end=" ", flush=True)
    pip_install("--upgrade", "pip")
    pip_install("-r", str(ROOT / "requirements.txt"))
    print(green("done"))
    ok("Dependencies ready")


# ── Banner ────────────────────────────────────────────────────────────────────

def banner() -> None:
    print()
    print(bold(cyan("  ╔══════════════════════════════════════════╗")))
    print(bold(cyan("  ║    Alert Triage Agent  —  Installer       ║")))
    print(bold(cyan("  ╚══════════════════════════════════════════╝")))
    print(f"  {dim('Automated SOC alert triage powered by local or cloud AI.')}")
    print(f"  {dim('Takes about 5 minutes to set up. Ctrl+C to cancel at any time.')}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    banner()

    if not (ROOT / "server.py").exists():
        bootstrap()
        sys.exit(1)

    try:
        sysinfo = assess_environment()
        setup_venv()
        env: dict[str, str] = {}
        env.update(setup_elastic())
        setup_ai(sysinfo, env)
        setup_threat_intel(env)
        setup_server(env)
        write_env(env)
        write_start_scripts()
        install_service(env["PORT"])
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('Cancelled.')}\n")
        sys.exit(0)

    port    = env["PORT"]
    pub_url = env.get("PUBLIC_URL", "")
    model   = env.get("OLLAMA_MODEL") or env.get("CLAUDE_MODEL") or \
              env.get("OPENAI_COMPAT_MODEL") or ""
    ai      = env.get("AI_PROVIDER", "none")

    print()
    print(bold(green("  All done! Here's what was set up:")))
    print()
    print(f"  {'Elasticsearch:':<18} {dim(env['ELASTIC_URL'])}")
    if ai != "none":
        label = (f"Ollama / {model}" if ai == "ollama"
                 else f"Anthropic Claude ({model})" if ai == "claude"
                 else f"OpenAI-compat ({model})")
        print(f"  {'AI backend:':<18} {dim(label)}")
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
    if ai == "ollama" and model:
        print(f"  {dim('Tip: keep Ollama running before starting the triage server.')}")
        print(f"  {dim('     ollama serve   (or it auto-starts on most installs)')}")
        print()


if __name__ == "__main__":
    main()
