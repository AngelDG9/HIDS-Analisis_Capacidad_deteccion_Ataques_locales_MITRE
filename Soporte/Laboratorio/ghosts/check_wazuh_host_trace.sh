#!/bin/bash
# check_wazuh_host_trace.sh — comprueba que las acciones GHOSTS dejan rastro visible por Wazuh (G3).
#
# Se ejecuta EN el manager (wazuh-server). Lee las alertas del día y busca:
#   - la regla 80792 (audit_command: execve);
#   - marcadores concretos de la actividad legitima (rutas/nombres de los comandos).
# Contrasena de sudo por STDIN (opcional); nunca se escribe en ficheros.
#
# Uso:  echo "<pw>" | ssh ... "bash /tmp/check_wazuh_host_trace.sh <marcador1> <marcador2> ..."

SUDOPW=""
if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
if ! sudo -n true 2>/dev/null; then echo "SIN SUDO: no se pueden leer los logs del manager"; exit 3; fi

AL=/var/ossec/logs/alerts/alerts.json
echo "== fichero de alertas =="; sudo ls -l "$AL" 2>/dev/null

echo "== alertas del dia (varias) =="
sudo test -s "$AL" && echo "alerts.json existe y no vacio" || echo "alerts.json ausente/vacio"

echo "== conteo regla 80792 (audit_command) =="
sudo grep -c '"id":"80792"' "$AL" 2>/dev/null || echo 0

echo "== ultimos 5 execve auditados =="
sudo grep -o '"audit":[^}]*' "$AL" 2>/dev/null | grep execve | tail -5

echo "== marcadores de la actividad legitima =="
for m in "$@"; do
    n=$(sudo grep -c "$m" "$AL" 2>/dev/null || echo 0)
    echo "  '$m' -> $n coincidencias"
done

echo "== ejemplo de alerta con marcador =="
if [ "$#" -gt 0 ]; then
    sudo grep -m1 "$1" "$AL" 2>/dev/null | cut -c1-400
fi
echo "== FIN =="
