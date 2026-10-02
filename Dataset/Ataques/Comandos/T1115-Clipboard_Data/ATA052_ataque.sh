#!/usr/bin/env bash
# ============================================================================
# ATA052 · T1115 Clipboard Data — ART ADAPTADO (xclip)
# ----------------------------------------------------------------------------
# Tecnica : T1115 Clipboard Data (tactica Collection).
# Fuente  : ART ADAPTADO. Atomica Linux "Add or copy content to clipboard with
#           xClip" guid ee363e53-b083-4230-aff3-f8d955f2d5bb
#           (history | tail -n 30 | xclip -sel clip; xclip -o > history.txt).
#           Se conserva xclip (poner y leer el portapapeles); la fuente pasa de
#           `history` (sin sesion interactiva en headless) a un historial simulado.
# Objetivo: copiar contenido al portapapeles del display :99 y leerlo a un fichero.
# Display : :99 (Xvfb sintetico, pre-steado ANTES de t0).
# Ejecuta : desde /home/angel/lab-attack/ATA052 (cwd del ataque -> ancla H4)
# Elevacion: NO en la ventana.
#
# Telemetria esperada (README §5):
#   - execve de xclip              -> 80792 (deteccion; T1115-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA052/*` (S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): fichero capturado == fuente (sha256).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA052"
export DISPLAY=:99
HIST="$BASE/historial_simulado.txt"
CAP="$BASE/portapapeles_capturado.txt"

echo "ATA052 · T1115 Clipboard Data (xclip sobre Xvfb) — ART adaptado"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! command -v xclip >/dev/null 2>&1; then
  echo "ERROR: falta xclip (pre-staging)" >&2
  exit 1
fi
if [ ! -f "$HIST" ]; then
  echo "ERROR: falta $HIST (pre-staging)" >&2
  exit 1
fi
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

echo "--- poner contenido en el portapapeles (xclip -sel clip) ---"
xclip -selection clipboard < "$HIST"
sleep 1
echo "--- leer el portapapeles (xclip -o) ---"
xclip -selection clipboard -o > "$CAP"
rc=$?
echo "xclip_rc=$rc"

if diff -q "$HIST" "$CAP" >/dev/null 2>&1; then
  echo "CLIPBOARD_ROUNDTRIP=OK (capturado == sembrado)"
else
  echo "CLIPBOARD_ROUNDTRIP=KO" >&2
fi
echo "--- sha256 (fuente y capturado) ---"
sha256sum "$HIST" "$CAP" 2>/dev/null
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
