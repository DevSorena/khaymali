#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/khaymali-manager"
if [[ "${EUID}" -ne 0 ]]; then echo "Error: run as root"; exit 1; fi
systemctl stop khaymali-light 2>/dev/null || true
systemctl disable khaymali-light 2>/dev/null || true
systemctl stop ltm-restore 2>/dev/null || true
systemctl disable ltm-restore 2>/dev/null || true
rm -f /etc/systemd/system/khaymali-light.service /etc/systemd/system/ltm-restore.service
rm -rf /etc/khaymali-light
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/khaymali-manager /usr/local/bin/khaymali-light /usr/local/bin/tunnel
rm -rf "${INSTALL_DIR}"
echo "Done."
