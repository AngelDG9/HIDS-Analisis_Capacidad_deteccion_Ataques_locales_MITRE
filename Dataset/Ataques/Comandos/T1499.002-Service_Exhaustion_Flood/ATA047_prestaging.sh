#!/usr/bin/env bash
# ============================================================================
# ATA047 · T1499.002 — PRE-STAGING: levanta el SERVICIO local desechable
# ----------------------------------------------------------------------------
# Se ejecuta ANTES de t0: deja un servicio HTTP escuchando en 127.0.0.1:9094 para
# que la ventana mida SOLO el flood de peticiones. El servicio es el receptor
# `sink_http.py` del laboratorio (propio), ligado a LOOPBACK: nunca el manager.
# ============================================================================
set -u
BASE="${HOME}/lab-attack/ATA047"
PORT=9094
cd "$BASE" || { echo "ERROR: no existe $BASE" >&2; exit 1; }

if [ ! -f sink_http.py ]; then echo "ERROR: falta sink_http.py en $BASE" >&2; exit 1; fi
if [ -f svc.pid ]; then kill "$(cat svc.pid)" 2>/dev/null || true; rm -f svc.pid; fi
pkill -f "sink_http.py.*9094" 2>/dev/null || true
sleep 1
: > service.log
nohup python3 sink_http.py --bind 127.0.0.1 --port "$PORT" --log "$BASE/service.log" >svc.err 2>&1 &
echo $! > svc.pid
for i in $(seq 1 50); do
  if curl --silent --max-time 1 --output /dev/null "http://127.0.0.1:$PORT/health"; then break; fi
  sleep 0.1
done
SVC_PID=$(cat svc.pid)
if ! kill -0 "$SVC_PID" 2>/dev/null; then
  echo "ERROR: el servicio no arranco; salida:" >&2
  cat svc.err >&2 2>/dev/null || true
  exit 1
fi
echo "SVC_PID=$SVC_PID"
echo "svc_url=http://127.0.0.1:$PORT/ping"
echo "PRE_STAGING=OK"
