#!/usr/bin/env bash
# ============================================================================
# ATA046 · T1499.003 Application Exhaustion Flood — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1499.003 Endpoint DoS: Application Exhaustion Flood (tactica Impact)
# Fuente  : custom (escrito por el TFG). ART no trae prueba de T1499 -> propio.
# Objetivo: saturar una APP local DESECHABLE (mono-hilo, 127.0.0.1:9093) con una
#           RAFAGA ACOTADA de peticiones CARAS (`/compute`). El "medio" es un
#           servicio local simulado del laboratorio: NUNCA el manager ni la red real.
# Destino : http://127.0.0.1:9093/compute (app desechable, loopback de la victima).
# Ejecuta : desde /home/angel/lab-attack/ATA046 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# ⚠️ GUARDARRAIL DE RECURSOS (aborta): TOTAL <= 64 peticiones, CONC <= 8, MAX_TIME <= 15 s.
#    Todo bajo `timeout`. Solo loopback; jamas el manager.
#
# Telemetria esperada (ver README §5):
#   - execve de curl (peticiones caras) -> 80792 (deteccion; T1499.003-S1).
#   - execve de xargs/seq (lanzadores)  -> 80792 (deteccion; S2,S3).
#   - execve de timeout (cota)          -> 80792 (deteccion; S4).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA046/*` (S5).
#
# Prueba de exito (INDEPENDIENTE de la alerta): la app registra en su log las
#   peticiones `compute_s`; se demuestra que absorbio la rafaga y que su CPU
#   subio (delta de /proc/<pid>/stat) -> la app fue "agotada".
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA046"
PORT=9093
URL="http://127.0.0.1:${PORT}/compute"
TOTAL=16
CONC=4
MAX_TIME=15
MAX_TOTAL=64
MAX_CONC=8

echo "ATA046 · T1499.003 Application Exhaustion Flood (rafaga acotada a app local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in curl timeout xargs seq awk sort; do
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
  *) echo "ERROR: destino '$URL' no es la app local; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

APP_PID=$(cat app.pid 2>/dev/null || true)
if [ -z "$APP_PID" ] || ! kill -0 "$APP_PID" 2>/dev/null; then
  echo "ERROR: la app desechable no esta viva (¿pre-staging?). ABORTADO" >&2
  exit 1
fi
log_before=$(wc -l < app.log 2>/dev/null || echo 0)
# CPU de la app antes (utime+stime, en ticks); CLK_TCK via getconf.
CLK=$(getconf CLK_TCK)
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
cpu0=$(cpu_ticks "$APP_PID")

# 1) RAFAGA ACOTADA de peticiones CARAS: `seq | xargs -P CONC curl` (execve por curl).
echo "--- rafaga: TOTAL=$TOTAL CONC=$CONC ---"
seq 1 "$TOTAL" | timeout --signal=TERM "${MAX_TIME}s" xargs -P "$CONC" -I{} \
  curl --silent --output /dev/null --max-time "$MAX_TIME" \
       --write-out '%{time_total}\n' "$URL" > times.txt 2>/dev/null
rc=$?
echo "xargs_rc=$rc"

# 2) MEDIDAS del efecto.
servidas=$(wc -l < times.txt 2>/dev/null || echo 0)
log_after=$(wc -l < app.log 2>/dev/null || echo 0)
log_delta=$((log_after - log_before))
cpu1=$(cpu_ticks "$APP_PID")
cpu_s=$(awk -v a="$cpu0" -v b="$cpu1" -v c="$CLK" 'BEGIN{printf "%.2f",(b-a)/c}')
t_max=$(sort -n times.txt | tail -1)
t_min=$(sort -n times.txt | head -1)
echo "peticiones_servidas=$servidas"
echo "app_log_delta=$log_delta"
echo "app_cpu_usada_s=$cpu_s"
echo "latencia_min_s=$t_min"
echo "latencia_max_s=$t_max"

# 3) La app sigue viva y responde tras la rafaga (servicio desechable, no destruido).
viva=0; kill -0 "$APP_PID" 2>/dev/null && viva=1
echo "app_viva_final=$viva"

echo "--- estado final ---"
if [ "$servidas" -eq "$TOTAL" ] && [ "$viva" -eq 1 ] && [ "$log_delta" -ge "$TOTAL" ] \
   && awk -v c="$cpu_s" 'BEGIN{exit !(c>0.1)}'; then
  echo "APP_EXHAUST=OK (rafaga absorbida por la app mono-hilo; CPU subio ${cpu_s}s)"
else
  echo "APP_EXHAUST=FALLO (servidas=$servidas log_delta=$log_delta cpu=$cpu_s viva=$viva)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
