#!/bin/bash
# ============================================================================
# estado_manager.sh — (MANAGER) estado de solo lectura para la VIGILANCIA de L1.
# Imprime: manager activo, agente 001, tamaño del fichero diario de alertas y de
# archives.json (denominador). No cambia nada.
#
# Usa `sudo -S` por comando (el ticket cacheado con `sudo -n` es intermitente en SSH
# sin TTY). Contraseña por STDIN; nunca en fichero.
#
# Uso:  echo "<pw>" | ssh manager "bash /tmp/estado_manager.sh"
# ============================================================================
set -u
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
s() { printf '%s\n' "$SUDOPW" | sudo -S -p "" "$@" 2>/dev/null; }

echo "utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "manager=$(systemctl is-active wazuh-manager 2>/dev/null)"
echo "agente001=$(s /var/ossec/bin/agent_control -i 001 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"
D=$(date -u +%Y); M=$(date -u +%b)
echo "diario_hoy=$(s ls -l /var/ossec/logs/alerts/$D/$M/ossec-alerts-$(date -u +%d).json 2>/dev/null | awk '{print $5" "$6" "$7" "$8}')"
echo "archives_json=$(s ls -l /var/ossec/logs/archives/archives.json 2>/dev/null | awk '{print $5" "$6" "$7" "$8}')"
echo "logall_json=$(s grep -o '<logall_json>[^<]*</logall_json>' /var/ossec/etc/ossec.conf 2>/dev/null | tail -1)"
echo "disco=$(df -h / | awk 'NR==2{print $4" libre ("$5" usado)"}')"
