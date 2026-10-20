#!/bin/bash
# ============================================================================
# verificar_rastro.sh — (MANAGER) comprueba que la actividad de GHOSTS deja
# rastro en las alertas de Wazuh. Bloque `legitimo-72h` (L1).
#
# Diferencia con `ghosts/check_wazuh_host_trace.sh` (L0): aquí se pasa la contraseña
# a CADA `sudo -S` (el ticket cacheado con `sudo -n` es intermitente en SSH sin TTY).
# No modifica nada; solo lee `/var/ossec/logs/alerts/alerts.json`.
#
# Uso:  echo "<pw>" | ssh manager "bash /tmp/verificar_rastro.sh"
# ============================================================================
set -u
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
AL=/var/ossec/logs/alerts/alerts.json
c() { printf '%s\n' "$SUDOPW" | sudo -S -p "" grep -F "$1" "$AL" 2>/dev/null | wc -l; }

echo "== fichero =="; printf '%s\n' "$SUDOPW" | sudo -S -p "" ls -l "$AL" 2>/dev/null
echo "== alertas totales por marcador (acumulado del dia) =="
for m in /usr/bin/md5sum /usr/bin/gzip /usr/bin/tar /usr/bin/curl \
         'intranet.local' 'nube.local' 'copia_noche' 'actas/acta_reunion.txt' \
         'plantilla_informe.csv' 'manual_empleado.pdf'; do
  printf '  %-30s -> %s\n' "$m" "$(c "$m")"
done
echo "80792 (audit_command) -> $(c 80792)"
echo "agente 001            -> $(c '"id":"001"')"
echo "== FIN =="
