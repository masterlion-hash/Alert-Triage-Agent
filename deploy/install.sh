#!/usr/bin/env bash
# Deploy the Alert Triage server to a remote host over SSH/rsync.
#
# Usage:
#   SIEM_HOST=192.168.1.10 SIEM_USER=ubuntu bash deploy/install.sh
#
# Required env vars:
#   SIEM_HOST   — target IP or hostname
#   SIEM_USER   — SSH username (default: ubuntu)
set -euo pipefail

SIEM_HOST="${SIEM_HOST:?Set SIEM_HOST to your target host IP or hostname}"
SIEM_USER="${SIEM_USER:-ubuntu}"
INSTALL_DIR="${INSTALL_DIR:-/opt/elastic-triage}"

echo "==> Deploying to ${SIEM_USER}@${SIEM_HOST}:${INSTALL_DIR}"

# Copy project files (exclude secrets and caches)
rsync -av \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.git' \
  --exclude='venv' \
  --exclude='.venv' \
  ./ "${SIEM_USER}@${SIEM_HOST}:${INSTALL_DIR}/"

# Install Python deps inside a virtualenv
ssh "${SIEM_USER}@${SIEM_HOST}" "
  set -e
  cd ${INSTALL_DIR}
  python3 -m venv venv 2>/dev/null || true
  venv/bin/pip install -q -r requirements.txt
"

# Remind the operator to configure .env
echo ""
echo "==> Files uploaded."
echo "==> Now run the setup wizard on the remote host:"
echo "      ssh ${SIEM_USER}@${SIEM_HOST}"
echo "      cd ${INSTALL_DIR} && python install.py"
echo ""
echo "    Or copy .env.example to .env and fill in your values manually."

# Install + enable systemd service (if it exists)
if [ -f "deploy/elastic-triage.service" ]; then
  scp deploy/elastic-triage.service "${SIEM_USER}@${SIEM_HOST}:/tmp/elastic-triage.service"
  ssh "${SIEM_USER}@${SIEM_HOST}" "
    sudo mv /tmp/elastic-triage.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable elastic-triage
    echo 'Service installed. Start it after configuring .env:'
    echo '  sudo systemctl start elastic-triage'
  "
fi
