#!/usr/bin/env bash
# ============================================================================
# ATA030_rev · T1560.001 Archive via Utility — repetición auditada (motivo: ART)
# ----------------------------------------------------------------------------
# Método corregido = PRUEBA DE ART:
#   atomic  : "Data Compressed - nix - tar Folder or File"
#   guid    : 7af2b51e-ad1c-498c-aca8-d3290c19535a
#   path    : atomics/T1560.001/T1560.001.yaml
#   commit  : 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
#   comando : tar -cvzf #{output_file} #{input_file_folder}   (sin cambios)
# Parametrización de laboratorio (permitida por el criterio §A.1, entrada/salida):
#   input_file_folder = $BASE/staging   ·   output_file = $BASE/collected_ATA030.tar.gz
# El material (staging/ con 3 ficheros de juguete) se prepara ANTES de t0 (modo prestage).
#
# Uso:  bash ATA030_ataque_rev.sh prestage   # ANTES de t0
#       bash ATA030_ataque_rev.sh attack     # ventana [t0,t1]
# Elevación: NO (usuario angel).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA030"
STAGE="${BASE}/staging"
ARCH="${BASE}/collected_ATA030.tar.gz"
MODE="${1:-attack}"

echo "ATA030_rev · T1560.001 Archive via Utility (atómica ART tar) — repeticion"

# GUARDARRAIL: todo bajo la carpeta del ataque.
case "$BASE" in
  "$HOME/lab-attack/ATA030") : ;;
  *) echo "ERROR: BASE '$BASE' fuera de lab-attack/ATA030 (abortado)" >&2; exit 1 ;;
esac

case "$MODE" in
  prestage)
    mkdir -p "$STAGE"
    cat > "$STAGE/informe_interno.txt" <<'TXT'
Informe interno simulado: resumen de negocio Q3 (datos de juguete).
TXT
    cat > "$STAGE/clientes.csv" <<'CSV'
id,cliente,facturacion_eur
1001,Acme Iberica SL,18450
1002,Comercial Delta SA,9230
CSV
    cat > "$STAGE/credenciales_servicio.txt" <<'TXT'
usuario=svc_backup
token_simulado=ZZZZ-9999
TXT
    echo "PRESTAGE=OK ($(ls -1 "$STAGE" | wc -l) ficheros en staging/)"
    ;;
  attack)
    if [ ! -d "$BASE" ]; then echo "ERROR: no existe $BASE" >&2; exit 1; fi
    for t in tar gzip; do
      command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
    done
    if [ ! -d "$STAGE" ]; then
      echo "ERROR: falta staging/ (¿se ejecutó el prestage ANTES de t0?)" >&2; exit 1
    fi
    cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
    echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "--- comando atómico: tar -cvzf $ARCH $STAGE ---"
    rm -f "$ARCH"
    tar -cvzf "$ARCH" "$STAGE"
    echo "--- prueba de efecto: tar -tzf ---"
    tar -tzf "$ARCH"
    n=$(tar -tzf "$ARCH" | grep -c 'staging/.*\.' || true)
    echo "miembros_de_datos=${n}"
    sha256sum "$ARCH"
    if [ -s "$ARCH" ] && [ "${n:-0}" -ge 3 ]; then
      echo "ARCHIVADO=OK (tar.gz creado y con los 3 ficheros del material)"
    else
      echo "ARCHIVADO=FALLO" >&2
    fi
    sleep 1
    echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ;;
  *)
    echo "uso: $0 {prestage|attack}" >&2; exit 2 ;;
esac
