#!/usr/bin/env bash
# ============================================================================
# ATA036 · T1565.003 Runtime Data Manipulation — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1565.003 Runtime Data Manipulation (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: MANIPULAR un dato EN EJECUCION (memoria) de un proceso DE
#           LABORATORIO: `memedit` se adjunta (ptrace) al proceso `target` y le
#           sobrescribe su dato en memoria (`SALDO=1000` -> `SALDO=9999`).
#           Distinto de T1565.001 (reposo, ATA032) y T1565.002 (transito, ATA026).
# Destino : SOLO el proceso de laboratorio `target` (bajo lab-attack/ATA036).
# Ejecuta : desde /home/angel/lab-attack/ATA036 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES DUROS (abortan si no se cumplen):
#   - el PID objetivo DEBE ser un proceso cuyo `/proc/<pid>/exe` sea EXACTAMENTE
#     $BASE/target (binario de laboratorio). JAMAS se toca un proceso del sistema.
#   - `memedit` y `target` DEBEN estar bajo $HOME/lab-attack/ATA036/.
#
# NOTA DE ENTORNO (paso 0, 2026-09-29): la VICTIMA **no tiene compilador** ni `gdb`
#   (gcc/cc/make/gdb ausentes). El payload se COMPILA APARTE (maquina con toolchain)
#   y se transporta como `.b64` (texto): aqui se DECODIFICA. Fallback previsto (R1).
#
# Telemetria esperada (ver README §5):
#   - execve de memedit -> 80792 (deteccion; S1) anclado por S2.
#   - el PTRACE en si NO genera telemetria (audit no audita ptrace en este ruleset):
#     punto ciego declarado (el HIDS ve la herramienta, no la manipulacion).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `target_state.log` muestra el dato
#   ANTES (`SALDO=1000`) y DESPUES (`SALDO=9999`) del proceso EN EJECUCION.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA036"
TB64="${BASE}/ATA036_target.b64"
MB64="${BASE}/ATA036_memedit.b64"
TGT="${BASE}/target"
MED="${BASE}/memedit"
STATE="${BASE}/target_state.log"
PIDF="${BASE}/target_pid.txt"
OLD="SALDO=1000"
NEW="SALDO=9999"

echo "ATA036 · T1565.003 Runtime Data Manipulation (ptrace/memoria) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in base64 chmod sha256sum readlink kill sleep grep cat; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: payloads bajo la carpeta del ataque.
for p in "$TGT" "$MED"; do
  case "$p" in
    "$HOME/lab-attack/ATA036/"*) : ;;
    *) echo "ERROR: ruta '$p' fuera de lab-attack/ATA036 (abortado por seguridad)" >&2; exit 1 ;;
  esac
done
case "$BASE" in
  "$HOME/lab-attack/ATA036"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA036; ABORTADO" >&2; exit 1 ;;
esac

# --- limpieza de seguridad: matar el target si quedo vivo ---
cleanup() {
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# 0) MATERIALIZAR el payload PRE-COMPILADO (decodificacion base64).
base64 -d "$TB64" > "$TGT"
base64 -d "$MB64" > "$MED"
chmod 700 "$TGT" "$MED"
echo "--- payload ---"
ls -l "$TGT" "$MED"
sha256sum "$TGT" "$MED"

# 1) Lanzar el PROCESO DE LABORATORIO (dato en uso en memoria).
: > "$STATE"
: > "$PIDF"
"$TGT" "$STATE" "$PIDF" &
PID=$!
for _ in 1 2 3 4 5; do [ -s "$PIDF" ] && break; sleep 1; done
PID=$(head -n 1 "$PIDF" | tr -d '[:space:]')
echo "target_pid=${PID:-?}"

# GUARDARRAIL DURO: el PID debe ser EXACTAMENTE el binario de laboratorio.
EXE="$(readlink -f "/proc/${PID}/exe" 2>/dev/null || true)"
echo "target_exe=${EXE}"
if [ "$EXE" != "$TGT" ]; then
  echo "ERROR: el PID ${PID} no es el binario de laboratorio $TGT; ABORTADO por seguridad" >&2
  exit 1
fi
sleep 3
echo "--- ANTES (dato en memoria) ---"
tail -n 2 "$STATE"

# 2) MANIPULACION EN MEMORIA del proceso en ejecucion (ptrace).
"$MED" "$PID" "$OLD" "$NEW"
med_rc=$?
echo "memedit_rc=${med_rc}"
sleep 3

# 3) PRUEBA DEL EFECTO (independiente de la alerta): el dato cambio EN EJECUCION.
echo "--- DESPUES (dato en memoria) ---"
tail -n 2 "$STATE"
cleanup
PID=""

v_old=$(grep -c "^${OLD}$" "$STATE" || true)
v_new=$(grep -c "^${NEW}$" "$STATE" || true)
echo "ocurrencias_antes=${v_old}"
echo "ocurrencias_despues=${v_new}"

if [ "$med_rc" -eq 0 ] && [ "${v_old:-0}" -ge 1 ] && [ "${v_new:-0}" -ge 1 ]; then
  echo "RUNTIME_DATA_MANIPULATION=OK (dato del proceso EN EJECUCION cambiado en memoria)"
  trap - EXIT
else
  echo "RUNTIME_DATA_MANIPULATION=FALLO (revisar la manipulacion)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
