#!/usr/bin/env bash
# ============================================================================
# ATA047 · T1499.002 Service Exhaustion Flood — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1499.002 Endpoint DoS: Service Exhaustion Flood (tactica Impact)
# Fuente  : custom (escrito por el TFG). ART no trae prueba de T1499 -> propio.
# Objetivo: AGOTAR por VOLUMEN un SERVICIO local DESECHABLE (loopback 127.0.0.1:9094)
#           con una RAFAGA ACOTADA de peticiones concurrentes. El "medio" es un
#           servicio local simulado del laboratorio: NUNCA el manager ni la red real.
# Destino : http://127.0.0.1:9094/ping (servicio desechable propio, loopback).
# Ejecuta : desde /home/angel/lab-attack/ATA047 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# ⚠️ GUARDARRAIL DE RECURSOS (aborta): TOTAL <= 800 peticiones, CONC <= 32, MAX_TIME <= 15 s.
#    Solo loopback; jamas el manager.
#
# Telemetria esperada (ver README §5):
#   - execve de curl (volumen de peticiones) -> 80792 (deteccion; T1499.002-S1).
#   - execve de xargs/seq (lanzadores)       -> 80792 (deteccion; S2,S3).
#   - execve de timeout (cota)               -> 80792 (deteccion; S4).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA047/*` (S5).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el `service.log` registra el
#   VOLUMEN de peticiones recibidas durante la rafaga (delta == TOTAL) y la CPU
#   del servicio sube (delta de /proc/<pid>/stat) -> el servicio fue "agotado".
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA047"
PORT=9094
URL="http://127.0.0.1:${PORT}/ping"
TOTAL=400
CONC=20
MAX_TIME=15
MAX_TOTAL=800
MAX_CONC=32

echo "ATA047 · T1499.002 Service Exhaustion Flood (rafaga acotada a servicio local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in curl timeout xargs seq awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DE RECURSOS ---
if [ "$TOTAL" -gt "$MAX_TOTAL" ] || [ "$CONC" -gt "$MAX_CONC" ] || [ "$MAX_TIME" -gt 15 ]; then
  echo "ERROR: topes de recursos fuera de rango (abortado por seguridad)" >&2
  exit 1
fi
case "$URL" in
  "http://127.0.0.1:${PORT}/"*) : ;;
  *) echo "ERROR: destino '$URL' no es el servicio local; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

SVC_PID=$(cat svc.pid 2>/dev/null || true)
if [ -z "$SVC_PID" ] || ! kill -0 "$SVC_PID" 2>/dev/null; then
  echo "ERROR: el servicio desechable no esta vivo (¿pre-staging?). ABORTADO" >&2
  exit 1
fi
log_before=$(wc -l < service.log 2>/dev/null || echo 0)
CLK=$(getconf CLK_TCK)
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
cpu0=$(cpu_ticks "$SVC_PID")

# 1) RAFAGA ACOTADA por VOLUMEN: `seq | xargs -P CONC curl` (execve por curl).
echo "--- rafaga: TOTAL=$TOTAL CONC=$CONC ---"
seq 1 "$TOTAL" | timeout --signal=TERM "${MAX_TIME}s" xargs -P "$CONC" -I{} \
  curl --silent --output /dev/null --max-time "$MAX_TIME" "$URL" 2>/dev/null
rc=$?
echo "xargs_rc=$rc"

# 2) MEDIDAS del efecto.
log_after=$(wc -l < service.log 2>/dev/null || echo 0)
log_delta=$((log_after - log_before))
cpu1=$(cpu_ticks "$SVC_PID")
cpu_s=$(awk -v a="$cpu0" -v b="$cpu1" -v c="$CLK" 'BEGIN{printf "%.2f",(b-a)/c}')
echo "peticiones_recibidas=$log_delta"
echo "svc_cpu_usada_s=$cpu_s"

viva=0; kill -0 "$SVC_PID" 2>/dev/null && viva=1
echo "svc_vivo_final=$viva"

echo "--- estado final ---"
if [ "$log_delta" -ge "$TOTAL" ] && [ "$viva" -eq 1 ] && awk -v c="$cpu_s" 'BEGIN{exit !(c>0.05)}'; then
  echo "SERVICE_EXHAUST=OK (servicio absorbio la rafaga; CPU subio ${cpu_s}s)"
else
  echo "SERVICE_EXHAUST=FALLO (recibidas=$log_delta cpu=$cpu_s vivo=$viva)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
