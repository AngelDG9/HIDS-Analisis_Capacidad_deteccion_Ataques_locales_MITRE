#!/bin/bash
# ============================================================================
# tfg_keepalive.sh — mantiene VIVO el cliente GHOSTS durante la captura de 72 h
# (bloque `legitimo-72h`, L1). Es el cuerpo de la "tarea del invitado"
# `TFG-Ghosts-Legit` (systemd: tfg-ghosts-legit.service/.timer).
#
# Arranca el cliente si no está en marcha y lo RELANZA si muere. Corre ~74 h y sale
# (va sobrado respecto a [t0,t1]=72 h; la parada de la VM en t1+5min lo mata igualmente).
# Su telemetría se DECLARA (es actividad del propio invitado, no acceso del operador).
# Sin secretos.
# ============================================================================
set -u
DIR=/home/angel/ghosts-client
DUR_H="${1:-74}"
END=$(( $(date -u +%s) + DUR_H * 3600 ))
cd "$DIR" 2>/dev/null || { echo "keepalive: no existe $DIR"; exit 1; }
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') keepalive: inicio (dur_h=$DUR_H)" >> "$DIR/keepalive.log"
while [ "$(date -u +%s)" -lt "$END" ]; do
  if ! pgrep -f ghosts.client.linux >/dev/null 2>&1; then
    nohup ./ghosts.client.linux > ghasts.out 2>&1 &
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') keepalive: cliente arrancado (pid=$!)" >> "$DIR/keepalive.log"
    sleep 3
  fi
  sleep 30
done
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') keepalive: fin" >> "$DIR/keepalive.log"
exit 0
