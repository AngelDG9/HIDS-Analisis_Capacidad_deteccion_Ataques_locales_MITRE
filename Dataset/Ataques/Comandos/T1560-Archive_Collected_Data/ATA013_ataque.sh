#!/usr/bin/env bash
# ============================================================================
# ATA013 · T1560.002 Archive Collected Data (via Library) — gzip en Python
# GUID   : 391f5298-b12d-4636-8482-35d9c17d53a8
# Fuente : atomic-red-team (commit 388942adbd9641f4dfdcf079d7efe9a75ec0ac43)
# Path   : atomics/T1560.002/T1560.002.yaml
# ----------------------------------------------------------------------------
# Comprime /etc/passwd con la stdlib (gzip) SIN elevación (usuario angel).
# Parametrización: python3 fijo (la atómica usa `which python || which python3`).
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). t1 OFICIAL tras el scan FIM.
# ============================================================================
set -u

INPUT="/etc/passwd"
OUTPUT="${HOME}/lab-attack/ATA013/passwd.gz"

echo "ATA013 · T1560.002 Archive Collected Data (gzip/python) — GUID 391f5298-b12d-4636-8482-35d9c17d53a8"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -d "$(dirname "$OUTPUT")" ]; then
  echo "ERROR: no existe $(dirname "$OUTPUT") (¿scp del directorio de la técnica?)" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 no disponible" >&2
  exit 1
fi

# Cuerpo de la atómica parametrizado (stdlib gzip, compresslevel=6):
python3 -c "import gzip; input_file=open('$INPUT','rb'); content=input_file.read(); input_file.close(); output_file=gzip.GzipFile('$OUTPUT','wb',compresslevel=6); output_file.write(content); output_file.close();"

echo "--- estado final del archivo ---"
ls -l "$OUTPUT"
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
