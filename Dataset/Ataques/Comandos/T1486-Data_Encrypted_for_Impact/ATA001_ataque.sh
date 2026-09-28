#!/usr/bin/env bash
# ============================================================================
# ATA001 · T1486 Data Encrypted for Impact — atomica ART (openssl, Linux)
# GUID   : 142752dc-ca71-443b-9359-cf6f497315f1
# Fuente : atomic-red-team (commit 388942adbd9641f4dfdcf079d7efe9a75ec0ac43)
# Path   : atomics/T1486/T1486.yaml  ("Encrypt files using openssl")
# ----------------------------------------------------------------------------
# Tecnica : T1486 Data Encrypted for Impact (tactica Impact)
# Fuente  : ART trae 4 pruebas Linux (gpg/7z/ccrypt/openssl); se usa openssl.
# Objetivo: CIFRAR un fichero de datos FALSO del laboratorio (escena de empresa:
#           export de clientes) para simular el "impacto" de un ransomware.
#           NUNCA se toca nada fuera de lab-attack.
# Destino : /home/angel/lab-attack/ATA001/   (NO vigilado -> deteccion por execve)
# Elevacion: NO (usuario angel).
#
# Desviacion declarada (ver README §4): la atomica original genera una clave RSA
#   (`genrsa`) y cifra con `rsautl -encrypt`, que (a) solo admite entradas cortas
#   (<= ~245 B con RSA-2048) y (b) esta DEPRECADO en OpenSSL 3.x. El plan §4 fija
#   el cifrado simetrico `openssl enc -aes-256-cbc -pbkdf2 -salt` (mismo impacto,
#   reproducible y sin esa limitacion). La passphrase es SIMBOLICA del laboratorio
#   (no es un secreto real; se declara en el propio script y en el README).
#
# Telemetria esperada (ver README §7):
#   - execve de openssl -> 80792 (deteccion; senales T1486-S1/S2)
#
# Prueba de exito (INDEPENDIENTE de la alerta): el DESCIFRADO con la misma clave
#   reconstruye el original (mismo sha256) => el ciphertext es valido.
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). El t1 OFICIAL se sella tras
#         el scan FIM forzado (runbook §2 paso 7); estos quedan en ejecucion.out.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA001"
PLAIN="${BASE}/datos_clientes_2026.csv"
ENC="${BASE}/datos_clientes_2026.csv.enc"
REC="${BASE}/datos_clientes_2026.recovered.csv"
# Passphrase SIMBOLICA del laboratorio (no es una credencial real; por eso SI puede
# estar versionada aqui, junto al guion y al README).
PASS="tfg-lab-ata001"

echo "ATA001 · T1486 Data Encrypted for Impact (openssl enc AES-256-CBC) — GUID 142752dc-ca71-443b-9359-cf6f497315f1"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl no disponible (el preflight debe confirmarlo; sin fallback a gpg)" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# 1) Semilla determinista: export de clientes FALSO (datos de juguete; sin datos reales).
{
  printf 'id,cliente,cif,facturacion_eur,alta\n'
  printf '1001,Acme Iberica SL,B12345678,18450,2024-03-11\n'
  printf '1002,Comercial Delta SA,A87654321,9230,2025-01-22\n'
  printf '1003,Talleres Norte SL,B11223344,4310,2026-02-08\n'
} > "$PLAIN"

# 2) CIFRADO (impacto): AES-256-CBC + PBKDF2 + salt.
openssl enc -aes-256-cbc -pbkdf2 -salt -in "$PLAIN" -out "$ENC" -pass pass:"$PASS"

# 3) PRUEBA DE EXITO: descifrar y comparar sha256 con el original.
openssl enc -d -aes-256-cbc -pbkdf2 -in "$ENC" -out "$REC" -pass pass:"$PASS"
sha_plain=$(sha256sum "$PLAIN" | awk '{print $1}')
sha_rec=$(sha256sum "$REC" | awk '{print $1}')

echo "--- estado final ---"
ls -l "$PLAIN" "$ENC" "$REC"
echo "sha256 plain     = $sha_plain"
echo "sha256 recovered = $sha_rec"
if [ "$sha_plain" = "$sha_rec" ]; then
  echo "ROUNDTRIP=OK (el ciphertext es valido y reversible con la clave)"
else
  echo "ROUNDTRIP=FALLO" >&2
fi
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
