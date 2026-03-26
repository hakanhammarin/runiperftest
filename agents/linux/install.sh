#!/usr/bin/env bash
# Install NetMon Linux agents as systemd services.
# Run as root: sudo bash install.sh

set -euo pipefail

INSTALL_DIR=/opt/netmon
AGENT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MQTT_HOST="${MQTT_HOST:-localhost}"
MQTT_PORT="${MQTT_PORT:-1883}"
MQTT_USER="${MQTT_USER:-}"
MQTT_PASS="${MQTT_PASS:-}"

echo "==> Installing NetMon agents to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cp -r "${AGENT_DIR}"/* "${INSTALL_DIR}/"
pip3 install -r "${INSTALL_DIR}/agents/linux/requirements.txt" -q

# --- session collector service ---
cat > /etc/systemd/system/netmon-collector.service <<EOF
[Unit]
Description=NetMon Session Collector
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agents/linux/session_collector.py
Environment=MQTT_HOST=${MQTT_HOST}
Environment=MQTT_PORT=${MQTT_PORT}
Environment=MQTT_USER=${MQTT_USER}
Environment=MQTT_PASS=${MQTT_PASS}
Environment=POLL_INTERVAL=30
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- firewall deployer service ---
cat > /etc/systemd/system/netmon-deployer.service <<EOF
[Unit]
Description=NetMon Firewall Deployer
After=network.target firewalld.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agents/linux/firewall_deployer.py
Environment=MQTT_HOST=${MQTT_HOST}
Environment=MQTT_PORT=${MQTT_PORT}
Environment=MQTT_USER=${MQTT_USER}
Environment=MQTT_PASS=${MQTT_PASS}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now netmon-collector netmon-deployer
echo "==> Done. Services started."
