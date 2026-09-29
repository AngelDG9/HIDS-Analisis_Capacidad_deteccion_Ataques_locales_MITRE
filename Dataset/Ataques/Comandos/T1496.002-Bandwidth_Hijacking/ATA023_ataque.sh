#!/usr/bin/env bash
# ============================================================================
# ATA023 · T1496.002 Bandwidth Hijacking — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1496.002 Resource Hijacking: Bandwidth (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: CONSUMIR ANCHO DE BANDA de forma ACOTADA volcando un flujo grande
#           (32 MiB de ceros) hacia el receptor del HOST. Demuestra el mecanismo
#           (transferencia masiva), no una exfiltracion de datos concretos.
#           ⚠️ ACOTADO: volumen FIJO (32 MiB) y `--max-time` (aborta si tardara).
# Destino : http://192.168.65.1:9090/api/bw/hog (receptor del HOST, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA023 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ GUARDARRAIL DE RECURSOS (aborta): MAX_BYTES = 32 MiB, MAX_TIME = 15 s. El
#    receptor es local (VMnet1); NO hay NAT ni internet. No se satura nada.
#
# Telemetria esperada (ver README §5):
#   - execve de head (genera el flujo)  -> 80792 (deteccion; T1496.002-S2).
#   - execve de curl (transferencia)    -> 80792 (deteccion; T1496.002-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA023/*` (T1496.002-S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con
#   `POST /api/bw/hog ... len=33554432 sha256=<H>` (32 MiB recibidos de la victima).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA023"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/api/bw/hog"
MAX_BYTES=$((32 * 1024 * 1024))   # 32 MiB (tope duro de la ventana)
MAX_TIME=15                        # segundos (tope duro de la ventana)

echo "ATA023 · T1496.002 Bandwidth Hijacking (flujo acotado de 32 MiB) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in head curl sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# GUARDARRAIL DE RECURSOS: topes duros (aborta si se cambian a mas).
if [ "$MAX_BYTES" -gt $((64 * 1024 * 1024)) ] || [ "$MAX_TIME" -gt 30 ]; then
  echo "ERROR: topes de recursos fuera de rango (abortado por seguridad)" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# 1) TRANSFERENCIA MASIVA ACOTADA: `head` genera 32 MiB de ceros; `curl` los sube.
#    (execve de head + execve de curl). Salida acotada por MAX_BYTES y --max-time.
#    Se CAPTURA la salida de `curl` (write-out) para COMPROBAR el resultado: `HOG=OK`
#    solo si `curl` termino bien, el HTTP es 2xx y se subieron los MAX_BYTES completos.
curl_out=$(head -c "$MAX_BYTES" /dev/zero | curl --silent --show-error --max-time "$MAX_TIME" \
  --request POST \
  --header 'Content-Type: application/octet-stream' \
  --data-binary @- \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} enviado=%{size_upload}B tiempo=%{time_total}s\n' \
  "$ENDPOINT")
curl_rc=$?
echo "$curl_out"

http_code=$(printf '%s\n' "$curl_out" | sed -n 's/.*HTTP=\([0-9][0-9][0-9]\).*/\1/p')
enviado=$(printf '%s\n' "$curl_out" | sed -n 's/.*enviado=\([0-9][0-9]*\)B.*/\1/p')

echo "--- estado final ---"
echo "bytes_objetivo=${MAX_BYTES}"
if [ "$curl_rc" -eq 0 ] && [ -n "$http_code" ] && [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ] \
   && [ -n "$enviado" ] && [ "$enviado" -eq "$MAX_BYTES" ]; then
  echo "HOG=OK (transferencia acotada de ${enviado} B confirmada; HTTP=${http_code})"
else
  echo "HOG=FALLO (curl_rc=${curl_rc} HTTP=${http_code:-?} enviado=${enviado:-?}B): la transferencia NO se confirmo" >&2
  echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  exit 1
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
