#!/bin/bash
# arrancar_manager.sh — (re)arranca el manager de Wazuh en wazuh-server (higiene del laboratorio).
# Contrasena de sudo por STDIN (opcional). No escribe secretos.
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
sudo -n systemctl restart wazuh-manager
sleep 30
echo "manager=$(systemctl is-active wazuh-manager)"
sudo -n /var/ossec/bin/agent_control -l 2>/dev/null | head -8
sudo -n tail -n 6 /var/ossec/logs/ossec.log 2>/dev/null
