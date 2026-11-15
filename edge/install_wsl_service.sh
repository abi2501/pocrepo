#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT=/opt/edge-sync
SERVICE_USER=edge-sync

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found. Enable systemd in WSL first; see IMPLEMENTATION_GUIDE.md"
  exit 1
fi

sudo useradd --system --home /var/lib/edge-sync --create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
sudo mkdir -p "$INSTALL_ROOT" /etc/edge-sync /var/lib/edge-sync
sudo rsync -a --delete --exclude ".env" --exclude ".venv" --exclude "data" "$PROJECT_DIR/" "$INSTALL_ROOT/edge/"
sudo python3 -m venv "$INSTALL_ROOT/venv"
sudo "$INSTALL_ROOT/venv/bin/pip" install --upgrade pip
sudo "$INSTALL_ROOT/venv/bin/pip" install -r "$INSTALL_ROOT/edge/requirements.txt"

if [[ ! -f /etc/edge-sync/edge-sync.env ]]; then
  echo "Creating /etc/edge-sync/edge-sync.env from example. EDIT IT BEFORE STARTING THE SERVICE."
  sudo cp "$INSTALL_ROOT/edge/.env.example" /etc/edge-sync/edge-sync.env
fi

sudo chown -R root:root "$INSTALL_ROOT"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/edge-sync
sudo chmod 600 /etc/edge-sync/edge-sync.env
sudo cp "$INSTALL_ROOT/edge/systemd/edge-sync.service" /etc/systemd/system/edge-sync.service
sudo systemctl daemon-reload
sudo systemctl enable edge-sync.service

echo "Installed. Edit /etc/edge-sync/edge-sync.env, then run: sudo systemctl start edge-sync"
