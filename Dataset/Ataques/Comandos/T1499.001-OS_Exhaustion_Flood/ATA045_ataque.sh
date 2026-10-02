#!/usr/bin/env bash
# ============================================================================
# ATA045 · T1499.001 OS Exhaustion Flood — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1499.001 Endpoint DoS: OS Exhaustion Flood (tactica Impact)
# Fuente  : custom (escrito por el TFG). ART no trae prueba de T1499 -> propio.
# Objetivo: AGOTAR de forma ACOTADA un recurso del SISTEMA OPERATIVO: la MEMORIA.
#           Se LLENA un tmpfs RAM-backed (/dev/shm) con `dd` hasta un TOPE FIJO y
#           se libera al terminar. El HIDS de host no tiene reglas de recursos:
#           se espera deteccion SOLO por el execve (R9).
# Destino : memoria RAM de la victima via /dev/shm/ATA045_fill (no toca disco real,
#           no toca swap de forma persistente, no toca red).
# Ejecuta : desde /home/angel/lab-attack/ATA045 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ GUARDARRAIL DE RECURSOS (aborta): MAX_MB <= 768 (tope duro) y DURATION <= 15 s.
#    El relleno va bajo `timeout`; un `trap` borra el fichero temporal al salir.
#    Nunca se apunta a disco real (/dev/shm es tmpfs) ni al manager.
#
# Telemetria esperada (ver README §5):
#   - execve de dd (relleno de memoria)   -> 80792 (deteccion; T1499.001-S1).
#   - execve de timeout (lanzador acotado) -> 80792 (deteccion; T1499.001-S2).
#   - execve de free/rm (medida/limpieza)  -> 80792 (deteccion; S3,S4).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA045/*` (S5).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `MemAvailable` cae durante el
#   relleno en ~MAX_MB y se RECUPERA tras borrarlo; 0 residuos del ataque.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA045"
FILL="/dev/shm/ATA045_fill"
MAX_MB=512          # relleno acotado (tope duro inferior)
MAX_MB_HARD=768     # tope duro de seguridad
HOLD=4              # segundos que se mantiene el relleno (con `sleep`)
MAX_TIME=15

echo "ATA045 · T1499.001 OS Exhaustion Flood (memoria /dev/shm acotada) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in dd timeout free rm sleep awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DE RECURSOS ---
if [ "$MAX_MB" -gt "$MAX_MB_HARD" ] || [ "$HOLD" -gt "$MAX_TIME" ]; then
  echo "ERROR: topes de recursos fuera de rango (abortado por seguridad)" >&2
  exit 1
fi
case "$FILL" in
  /dev/shm/*) : ;;
  *) echo "ERROR: el relleno '$FILL' no esta bajo /dev/shm; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

cleanup() { rm -f "$FILL"; }
trap cleanup EXIT

# --- ayuda: MemAvailable en MB (columna 7 de `free -m`) ---
avail_mb() { free -m | awk '/^Mem:/{print $7}'; }

a0=$(avail_mb)
echo "mem_available_antes_mb=$a0"

# 1) RELLENO ACOTADO de memoria: `timeout` + `dd` escriben MAX_MB en tmpfs RAM.
timeout --signal=TERM "${MAX_TIME}s" dd if=/dev/zero of="$FILL" bs=1M count="$MAX_MB" status=none
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: el relleno fallo (rc=$rc); ABORTADO" >&2
  exit 1
fi
echo "relleno_mb=$MAX_MB"
ls -l "$FILL"

# 2) MEDIR con el relleno ACTIVO (execve free).
a1=$(avail_mb)
echo "mem_available_durante_mb=$a1"
sleep "$HOLD"

# 3) LIBERAR y comprobar recuperacion (execve rm).
rm -f "$FILL"
sleep 1
a2=$(avail_mb)
echo "mem_available_despues_mb=$a2"

# 4) PRUEBA DEL EFECTO: caida durante el relleno y recuperacion tras liberar.
caida=$((a0 - a1))
recuperado=$((a2 - a1))
echo "--- estado final ---"
echo "caida_available_mb=$caida (objetivo ~$MAX_MB)"
echo "recuperado_mb=$recuperado"
echo "fichero_residual=$([ -e "$FILL" ] && echo SI || echo no)"
if [ "$caida" -ge $((MAX_MB / 2)) ] && [ "$recuperado" -gt 0 ] && [ ! -e "$FILL" ]; then
  echo "OS_EXHAUST=OK (memoria agotada de forma acotada y liberada; 0 residuo)"
  trap - EXIT
else
  echo "OS_EXHAUST=FALLO (caida=${caida} recuperado=${recuperado})" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
