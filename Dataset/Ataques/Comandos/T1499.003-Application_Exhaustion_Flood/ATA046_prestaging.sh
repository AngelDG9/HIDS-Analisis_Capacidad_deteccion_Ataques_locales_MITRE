#!/usr/bin/env bash
# ============================================================================
# ATA046 · T1499.003 — PRE-STAGING: levanta la APP local desechable
# ----------------------------------------------------------------------------
# Se ejecuta ANTES de t0: deja la app escuchando en 127.0.0.1:9093 para que la
# ventana mida SOLO el flood de peticiones caras (no el arranque de la app).
# La app es mono-hilo y su endpoint /compute hace un calculo acotado pero caro.
# ============================================================================
set -u
BASE="${HOME}/lab-attack/ATA046"
PORT=9093
cd "$BASE" || { echo "ERROR: no existe $BASE" >&2; exit 1; }

# Parar cualquier instancia previa (idempotente).
if [ -f app.pid ]; then kill "$(cat app.pid)" 2>/dev/null || true; rm -f app.pid; fi
pkill -f "ATA046_app.py" 2>/dev/null || true
sleep 1
: > app.log
nohup python3 ATA046_app.py "$PORT" "$BASE/app.log" >app.err 2>&1 &
echo $! > app.pid
# esperar a que escuche (hasta 5 s)
for i in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then break; fi
  sleep 0.1
done
APP_PID=$(cat app.pid)
if ! kill -0 "$APP_PID" 2>/dev/null; then
  echo "ERROR: la app no arranco; salida:" >&2
  cat app.err >&2 2>/dev/null || true
  exit 1
fi
echo "APP_PID=$APP_PID"
echo "app_compute_url=http://127.0.0.1:$PORT/compute"
echo "PRE_STAGING=OK"
