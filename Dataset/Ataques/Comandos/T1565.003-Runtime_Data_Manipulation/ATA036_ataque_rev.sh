#!/usr/bin/env bash
# ============================================================================
# ATA036_rev · T1565.003 Runtime Data Manipulation — repetición auditada (motivo: pre-staging)
# ----------------------------------------------------------------------------
# Corrección metodológica (§C): los payloads precompilados (`memedit`, `target`) y el proceso
#   de laboratorio `target` se MATERIALIZAN/LANZAN ANTES de t0 (modo prestage). La ventana
#   ejecuta SOLO la acción de la técnica: el `ptrace` (`memedit <pid> SALDO=1000 SALDO=9999`).
# Fuente: custom (sin cambio de mecanismo).
#
# Uso:  bash ATA036_ataque_rev.sh prestage   # ANTES de t0 (materializa + lanza el `target`)
#       bash ATA036_ataque_rev.sh attack     # ventana [t0,t1] (solo el ptrace de memedit)
# Elevación: NO (usuario angel). yama resuelto con PR_SET_PTRACER_ANY en `target`.
#
# GUARDARRAILES DUROS: el PID objetivo DEBE tener `/proc/<pid>/exe` == $BASE/target;
#   `memedit`/`target` DEBEN estar bajo $HOME/lab-attack/ATA036/.
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
MODE="${1:-attack}"

echo "ATA036_rev · T1565.003 Runtime Data Manipulation (ptrace/memoria) — repeticion (pre-staging)"
echo "MODE=${MODE}"

for t in base64 chmod sha256sum readlink kill sleep grep cat setsid; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done

if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

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

if [ "$MODE" = "prestage" ]; then
  # 0) MATERIALIZAR los payloads PRE-COMPILADOS (decodificacion base64) ANTES de t0.
  base64 -d "$TB64" > "$TGT"
  base64 -d "$MB64" > "$MED"
  chmod 700 "$TGT" "$MED"
  : > "$STATE"
  : > "$PIDF"
  echo "--- payload (pre-staging, antes de t0) ---"
  ls -l "$TGT" "$MED"
  sha256sum "$TGT" "$MED"

  # 1) LANZAR el PROCESO DE LABORATORIO (dato en uso en memoria) ANTES de t0.
  #    `setsid` lo desliga de la sesion para que sobreviva a este shell (el ataque lo manipula).
  setsid "$TGT" "$STATE" "$PIDF" </dev/null >/dev/null 2>&1 &
  for _ in $(seq 1 10); do [ -s "$PIDF" ] && break; sleep 1; done
  PID=$(head -n 1 "$PIDF" | tr -d '[:space:]')
  echo "target_pid=${PID:-?}"
  EXE="$(readlink -f "/proc/${PID}/exe" 2>/dev/null || true)"
  echo "target_exe=${EXE}"
  if [ "$EXE" != "$TGT" ]; then
    echo "ERROR: el PID ${PID} no es el binario de laboratorio $TGT; ABORTADO por seguridad" >&2
    exit 1
  fi
  echo "PRESTAGE=OK (memedit + target materializados; target lanzado ANTES de t0, pid=${PID})"
  exit 0
fi

# ---- modo attack (ventana): SOLO el ptrace de la tecnica ----
[ -f "$MED" ] && [ -x "$TGT" ] || { echo "ERROR: falta el payload (¿prestage ANTES de t0?)" >&2; exit 1; }
PID=$(head -n 1 "$PIDF" 2>/dev/null | tr -d '[:space:]' || true)
echo "target_pid=${PID:-?}"
EXE="$(readlink -f "/proc/${PID}/exe" 2>/dev/null || true)"
echo "target_exe=${EXE}"
if [ -z "${PID:-}" ] || [ "$EXE" != "$TGT" ]; then
  echo "ERROR: el proceso de laboratorio no esta vivo o no es $TGT; ABORTADO por seguridad" >&2
  exit 1
fi

cleanup() { if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then kill -TERM "$PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
