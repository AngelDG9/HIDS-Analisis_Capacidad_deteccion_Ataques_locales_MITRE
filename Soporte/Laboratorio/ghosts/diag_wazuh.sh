#!/bin/bash
# diag_wazuh.sh — diagnostico rapido del laboratorio Wazuh (L0). Se ejecuta en cualquier VM.
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi

echo "== host: $(hostname) =="
echo "-- fecha UTC --"; date -u
echo "-- servicios --"
for s in wazuh-agent wazuh-manager wazuh-indexer wazuh-dashboard auditd; do
    printf '  %-16s %s\n' "$s" "$(systemctl is-active $s 2>/dev/null)"
done
echo "-- agent_control -l --"; sudo /var/ossec/bin/agent_control -l 2>/dev/null | head -10
echo "-- tail ossec.log --"; sudo tail -n 12 /var/ossec/logs/ossec.log 2>/dev/null
echo "-- dir alertas --"
sudo ls -l /var/ossec/logs/alerts/ 2>/dev/null | head
echo "-- alertas de hoy (diario) --"
D=$(date -u +%Y); M=$(date -u +%b)
sudo ls -l "/var/ossec/logs/alerts/$D/$M/" 2>/dev/null | tail -4
echo "== FIN =="
