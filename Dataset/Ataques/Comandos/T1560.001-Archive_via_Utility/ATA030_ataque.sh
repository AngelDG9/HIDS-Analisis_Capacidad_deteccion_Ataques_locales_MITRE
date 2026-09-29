#!/usr/bin/env bash
# ============================================================================
# ATA030 · T1560.001 Archive via Utility — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1560.001 Archive via Utility (tactica Collection)
# Fuente  : custom (ART tiene 5 pruebas Linux para T1560.001; se escribe guion
#           propio KISS con tar/gzip, sin depender del clon de ART)
# Objetivo: ARCHIVAR el material recolectado con una UTILIDAD de linea de ordenes
#           (tar + gzip). Es el CONTRASTE CIENTIFICO con ATA013/T1560.002
#           (archivo por LIBRERIA con python3 -> NO detectado por el punto ciego
#           de fabrica 92600): el MISMO objetivo ("archivar") hecho con utilidad
#           SI deja execve.
# Destino : /home/angel/lab-attack/ATA030/collected_ATA030.tar.gz (bajo el ataque)
# Ejecuta : desde /home/angel/lab-attack/ATA030 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el material y el archivo DEBEN quedar bajo $HOME/lab-attack/ATA030/;
#   - JAMAS se archiva /etc, el home real ni datos reales.
#
# Telemetria esperada (ver README §5):
#   - execve de tar -> 80792 (deteccion; senal T1560.001-S1) anclado por S3.
#   - gzip invocado por tar (tar -z) -> execve de gzip -> 80792 (senal S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el .tar.gz existe, NO esta vacio
#   y contiene los 3 ficheros del material (verificado con `tar -tzf`).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA030"
STAGE="${BASE}/staging"
ARCH="${BASE}/collected_ATA030.tar.gz"

echo "ATA030 · T1560.001 Archive via Utility (tar + gzip) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in tar gzip mkdir sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: material y archivo bajo la carpeta del ataque.
case "$STAGE" in
  "$HOME/lab-attack/ATA030"*) : ;;
  *) echo "ERROR: staging '$STAGE' fuera de lab-attack/ATA030 (abortado)" >&2; exit 1 ;;
esac
case "$ARCH" in
  "$HOME/lab-attack/ATA030"*) : ;;
  *) echo "ERROR: archivo '$ARCH' fuera de lab-attack/ATA030 (abortado)" >&2; exit 1 ;;
esac

# 0) MATERIAL recolectado (datos de juguete) que el atacante va a archivar.
mkdir -p "$STAGE"
[ -f "$STAGE/informe_interno.txt" ] || cat > "$STAGE/informe_interno.txt" <<'TXT'
Informe interno simulado: resumen de negocio Q3 (datos de juguete).
TXT
[ -f "$STAGE/clientes.csv" ] || cat > "$STAGE/clientes.csv" <<'CSV'
id,cliente,facturacion_eur
1001,Acme Iberica SL,18450
1002,Comercial Delta SA,9230
CSV
[ -f "$STAGE/credenciales_servicio.txt" ] || cat > "$STAGE/credenciales_servicio.txt" <<'TXT'
usuario=svc_backup
token_simulado=ZZZZ-9999
TXT

# 1) ARCHIVADO CON UTILIDAD: tar + gzip (execve de tar; gzip invocado por tar).
rm -f "$ARCH"
tar -czf "$ARCH" -C "$BASE" staging

# 2) PRUEBA DEL EFECTO (independiente de la alerta): contenido del archivo.
echo "--- contenido del archivo (tar -tzf) ---"
tar -tzf "$ARCH"
n_miembros=$(tar -tzf "$ARCH" | grep -c 'staging/.*\.')
echo "miembros_de_datos=${n_miembros}"
echo "--- sha256 del archivo ---"
sha256sum "$ARCH"

if [ -s "$ARCH" ] && [ "${n_miembros:-0}" -ge 3 ]; then
  echo "ARCHIVADO=OK (tar.gz creado y con los 3 ficheros del material)"
else
  echo "ARCHIVADO=FALLO (revisar el archivo)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
