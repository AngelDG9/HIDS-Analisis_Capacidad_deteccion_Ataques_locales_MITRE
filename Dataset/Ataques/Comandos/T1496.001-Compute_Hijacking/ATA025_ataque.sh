#!/usr/bin/env bash
# ============================================================================
# ATA025 · T1496.001 Compute Hijacking — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1496.001 Resource Hijacking: Compute (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: SIMULAR mineria/robo de computo: saturar la CPU con cargas de trabajo
#           "utiles" (proceso `yes` a pleno rendimiento) de forma ACOTADA. El
#           interes cientifico es comprobar si un HIDS de HOST ve el consumo de
#           recursos (Wazuh no tiene reglas de CPU/recursos -> probable deteccion
#           solo por el execve, o NINGUNA si el consumo fuese con builtins).
# Destino : CPU de la victima (sin ficheros); evidencia en la carpeta del ataque.
# Ejecuta : desde /home/angel/lab-attack/ATA025 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ GUARDARRAIL DE RECURSOS (aborta): WORKERS <= 4 y DURATION <= 15 s. Cada
#    trabajador va bajo `timeout` (nunca queda colgado); un `trap` mata a los
#    hijos remanentes al salir. No se toca ningun servicio ni la red.
#
# Telemetria esperada (ver README §5):
#   - execve de `timeout` (lanzador) -> 80792 (deteccion; T1496.001-S2).
#   - execve de `yes` (carga)        -> 80792 (deteccion; T1496.001-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA025/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): la CPU de la victima pasa de
#   `busy` bajo a `busy` alto sostenido durante la ventana (calculado de
#   /proc/stat) y `loadavg` sube; al terminar NO queda ningun `yes` vivo.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA025"
WORKERS=2
DURATION=10                       # segundos (tope duro por trabajador)
MAX_WORKERS=4
MAX_DURATION=15

echo "ATA025 · T1496.001 Compute Hijacking (carga de CPU acotada) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in timeout yes awk cat sleep nproc; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DE RECURSOS ---
if [ "$WORKERS" -gt "$MAX_WORKERS" ] || [ "$DURATION" -gt "$MAX_DURATION" ]; then
  echo "ERROR: topes de recursos fuera de rango (abortado por seguridad)" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

pids=""
killpids() { [ -n "$pids" ] && kill $pids 2>/dev/null || true; }
trap killpids EXIT

# --- muestreo de CPU (/proc/stat: total y idle+iowait) ---
sample_cpu() { awk '/^cpu /{total=0; for(i=2;i<=NF;i++) total+=$i; printf "%s %s\n", total, $5+$6}' /proc/stat; }

echo "nproc=$(nproc)"
echo "loadavg_antes=$(cat /proc/loadavg)"
set -- $(sample_cpu); T_a="$1"; I_a="$2"

# 1) LANZAR la carga ACOTADA: WORKERS procesos `yes` bajo `timeout`.
i=1
while [ "$i" -le "$WORKERS" ]; do
  timeout --signal=TERM "${DURATION}s" yes >/dev/null 2>&1 &
  pids="$pids $!"
  i=$((i + 1))
done
echo "workers_lanzados=$WORKERS duracion_s=$DURATION"

# 2) MEDIR la carga mientras corre (2 s de ventana de muestreo).
sleep 2
set -- $(sample_cpu); T_b="$1"; I_b="$2"
echo "loadavg_durante=$(cat /proc/loadavg)"

# 3) Esperar a que terminen (timeout) y comprobar que NO queda ninguno vivo.
wait
sleep 1
set -- $(sample_cpu); T_c="$1"; I_c="$2"
vivos=$(pgrep -x yes | wc -l)

busy=$(awk -v t0="$T_a" -v i0="$I_a" -v t1="$T_b" -v i1="$I_b" \
  'BEGIN{d=t1-t0; di=i1-i0; if(d<=0){print "0.0"}else{printf "%.1f",(1-di/d)*100}}')
busy_post=$(awk -v t0="$T_b" -v i0="$I_b" -v t1="$T_c" -v i1="$I_c" \
  'BEGIN{d=t1-t0; di=i1-i0; if(d<=0){print "0.0"}else{printf "%.1f",(1-di/d)*100}}')

echo "--- estado final ---"
echo "cpu_busy_pct_durante=${busy}"
echo "cpu_busy_pct_despues_de_parar=${busy_post}"
echo "loadavg_despues=$(cat /proc/loadavg)"
echo "procesos_yes_vivos=$vivos"

if [ "$vivos" -eq 0 ] \
   && awk -v b="$busy" 'BEGIN{exit !(b>=30)}' \
   && awk -v b="$busy" -v p="$busy_post" 'BEGIN{exit !(p<b)}'; then
  echo "HIJACK_COMPUTE=OK (carga acotada sostenida: busy=${busy}% ; 0 procesos residuales)"
  pids=""
  trap - EXIT
else
  echo "HIJACK_COMPUTE=FALLO (vivos=${vivos} busy=${busy}% busy_post=${busy_post}%)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
