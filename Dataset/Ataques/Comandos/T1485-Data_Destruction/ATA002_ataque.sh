#!/usr/bin/env bash
# ============================================================================
# ATA002 · T1485 Data Destruction — atómica "Overwrite file with DD"
# GUID   : 38deee99-fd65-4031-bec8-bfa4f9f26146
# Fuente : atomic-red-team (commit 388942adbd9641f4dfdcf079d7efe9a75ec0ac43)
# Path   : atomics/T1485/T1485.yaml
# ----------------------------------------------------------------------------
# Ejecuta el cuerpo de la atómica PARAMETRIZADO y SIN elevación (usuario angel).
# Solo para una ventana del piloto (fase-03-piloto). NO ejecuta nada más.
#
# ⚠️ Desviación D1 (ver README.md): el destino NO es /etc (no escribible sin
#    sudo) sino el directorio vigilado por auditd /home/angel/lab-legit/.
#    Se pierde la señal FIM; la detección es por execve/watch de dd.
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). El t1 OFICIAL se sella tras
#         el scan FIM forzado (runbook §3/§4); estos marcadores quedan en
#         ejecucion.out como evidencia.
# ============================================================================
set -u

TARGET="${HOME}/lab-legit/ATA002_scratch_dd.txt"
SOURCE="/dev/zero"

echo "ATA002 · T1485 Data Destruction (dd) — GUID 38deee99-fd65-4031-bec8-bfa4f9f26146"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Precondición: el directorio vigilado por auditd debe existir (está en lab-listo).
if [ ! -d "$(dirname "$TARGET")" ]; then
  echo "ERROR: no existe $(dirname "$TARGET") (¿la víctima no revirtió a lab-listo?)" >&2
  exit 1
fi
if ! command -v dd >/dev/null 2>&1; then
  echo "ERROR: dd no disponible" >&2
  exit 1
fi

# 1) Crear el fichero objetivo (no elevado). La atómica original exige que exista.
dd if="$SOURCE" of="$TARGET" bs=1M count=1

# 2) Cuerpo de la atómica T1485 (parametrizado y fiel al YAML):
#    dd of=<target> if=<source> count=$(tamaño) iflag=count_bytes
dd of="$TARGET" if="$SOURCE" count=$(ls -l "$TARGET" | awk '{print $5}') iflag=count_bytes

echo "--- estado final del objetivo ---"
ls -l "$TARGET"
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
