#!/bin/bash
# contar_wazuh2.sh — cuenta marcadores en las alertas del manager en UNA sola invocacion sudo.
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
sudo -n bash -c '
AL=/var/ossec/logs/alerts/alerts.json
echo "fichero:"; ls -l "$AL"
echo "lineas: $(wc -l < "$AL")"
for m in "intranet.local" "informes.tar.gz" "md5sum" "gzip"; do
  echo "  $m -> $(grep -F -c -- "$m" "$AL")"
done
echo "  80792 (audit_command) -> $(grep -F -c 80792 "$AL")"
echo "  agente 001 -> $(grep -F -c "\"id\":\"001\"" "$AL")"
echo "ultima alerta:"; tail -n 1 "$AL" | cut -c1-240
'
