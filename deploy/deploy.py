"""
Deploy the Alert Triage server to a remote host over SSH.

Reads target host and credentials from environment variables or prompts.
Run from the project root:
    python deploy/deploy.py
"""

import getpass
import os
import pathlib
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("ERROR: paramiko is required — pip install paramiko")

PROJECT_ROOT = pathlib.Path(__file__).parent.parent

INSTALL_DIR  = os.environ.get("DEPLOY_DIR",  "/opt/elastic-triage")
SERVICE_PORT = int(os.environ.get("PORT",    "8000"))

UPLOAD_FILES = [
    "server.py",
    "config.py",
    "install.py",
    "requirements.txt",
    "assets.example.yml",
    "src/__init__.py",
    "src/ai_provider.py",
    "src/assets.py",
    "src/elastic.py",
    "src/investigation.py",
    "src/threat_intel.py",
    "src/triage.py",
]

SERVICE_TEMPLATE = """\
[Unit]
Description=Alert Triage MCP Server
After=network.target

[Service]
Type=simple
WorkingDirectory={install_dir}
EnvironmentFile={install_dir}/.env
ExecStart={python} server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def _run(ssh, cmd, check=True):
    _, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc  = stdout.channel.recv_exit_status()
    if check and rc != 0:
        print(f"  [!] Command failed (rc={rc}): {cmd}")
        if err:
            print(f"      {err}")
        sys.exit(1)
    return out


def _upload(sftp, local, remote):
    sftp.put(str(local), remote)
    print(f"  uploaded {pathlib.Path(local).name}")


def main():
    siem_host = os.environ.get("DEPLOY_HOST") or input("SIEM host (IP or hostname): ").strip()
    siem_port = int(os.environ.get("DEPLOY_SSH_PORT", "22"))
    ssh_user  = os.environ.get("DEPLOY_USER") or input(f"SSH username for {siem_host}: ").strip()
    ssh_pass  = os.environ.get("DEPLOY_PASS") or getpass.getpass(f"SSH password for {ssh_user}@{siem_host}: ")

    print(f"\nConnecting to {siem_host}:{siem_port} …")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(siem_host, port=siem_port, username=ssh_user, password=ssh_pass, timeout=10)
    except Exception as exc:
        sys.exit(f"[ERROR] SSH failed: {exc}")
    print("  Connected.")

    sftp = ssh.open_sftp()

    print(f"\nSetting up {INSTALL_DIR} …")
    _run(ssh, f"mkdir -p {INSTALL_DIR}/src")

    print("\nUploading files …")
    for rel in UPLOAD_FILES:
        local = PROJECT_ROOT / rel
        if local.exists():
            _upload(sftp, local, f"{INSTALL_DIR}/{rel}")
        else:
            print(f"  skipped (not found): {rel}")

    # Copy .env if it exists locally, otherwise remind the user
    local_env = PROJECT_ROOT / ".env"
    if local_env.exists():
        _upload(sftp, local_env, f"{INSTALL_DIR}/.env")
        print("  NOTE: .env deployed — verify credentials on the remote host.")
    else:
        print("\n  No .env found locally.")
        print(f"  Run  python install.py  on the remote host, or copy .env.example to")
        print(f"  {INSTALL_DIR}/.env and fill in the values.")

    print("\nInstalling Python dependencies …")
    python = _run(ssh, "which python3 || which python", check=False) or "python3"
    venv   = f"{INSTALL_DIR}/venv"
    _run(ssh, f"{python} -m venv {venv} 2>/dev/null || true", check=False)
    pip    = f"{venv}/bin/pip"
    _run(ssh, f"{pip} install -q -r {INSTALL_DIR}/requirements.txt")
    print("  Done.")

    print("\nInstalling systemd service …")
    svc_content = SERVICE_TEMPLATE.format(install_dir=INSTALL_DIR, python=f"{venv}/bin/python")
    with sftp.open("/etc/systemd/system/elastic-triage.service", "w") as f:
        f.write(svc_content)
    _run(ssh, "systemctl daemon-reload")
    _run(ssh, "systemctl enable elastic-triage")
    _run(ssh, "systemctl restart elastic-triage")

    time.sleep(3)
    status = _run(ssh, "systemctl is-active elastic-triage", check=False)
    health = _run(ssh, f"curl -sf http://localhost:{SERVICE_PORT}/health 2>/dev/null || echo 'not yet up'", check=False)
    print(f"  service : {status}")
    print(f"  health  : {health}")

    sftp.close()
    ssh.close()

    print(f"\n{'='*50}")
    print(f"  Triage UI  : http://{siem_host}:{SERVICE_PORT}")
    print(f"  MCP server : http://{siem_host}:{SERVICE_PORT}/mcp/mcp")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
