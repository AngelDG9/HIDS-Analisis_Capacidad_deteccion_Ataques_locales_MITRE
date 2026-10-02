#!/usr/bin/env bash
# ============================================================================
# ATA051 · T1113 Screen Capture — ART ADAPTADO (xwd)
# ----------------------------------------------------------------------------
# Tecnica : T1113 Screen Capture (tactica Collection).
# Fuente  : ART ADAPTADO. Atomica Linux "X Windows Capture"
#           guid 8206dd0c-faf6-4d74-ba13-7fbe13dce6ac (xwd -root -out; xwud -in).
#           Se conserva xwd (captura) y se envolvente xwud en `timeout` defensivo
#           (el visor es interactivo y quedaria abierto en el display virtual).
# Objetivo: capturar la pantalla completa del display virtual :99 en un fichero
#           .xwd. Demuestra la captura (fichero valido + sha256).
# Display : :99 (Xvfb sintetico, pre-steado ANTES de t0).
# Ejecuta : desde /home/angel/lab-attack/ATA051 (cwd del ataque -> ancla H4)
# Elevacion: NO en la ventana (el sudo es solo del pre-staging de paquetes).
#
# Telemetria esperada (README §5):
#   - execve de xwd                -> 80792 (deteccion; T1113-S1).
#   - execve de xwud               -> 80792 (deteccion; T1113-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA051/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): fichero .xwd con cabecera XWD valida.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA051"
export DISPLAY=:99
OUT="$BASE/captura_pantalla.xwd"

echo "ATA051 · T1113 Screen Capture (xwd sobre Xvfb) — ART adaptado"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! command -v xwd >/dev/null 2>&1; then
  echo "ERROR: falta xwd (pre-staging x11-apps)" >&2
  exit 1
fi
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

echo "--- xwd -root -out $OUT ---"
xwd -root -out "$OUT" 2>&1
rc=$?
echo "xwd_rc=$rc"

if [ -f "$OUT" ]; then
  echo "--- revision con xwud (timeout 3; el visor es interactivo) ---"
  timeout 3 xwud -in "$OUT" >/dev/null 2>&1 || true
  echo "captura_bytes=$(stat -c%s "$OUT")"
  echo "cabecera_xwd=$(head -c 8 "$OUT" | od -An -tx1 | tr -d ' \n')"
  sha256sum "$OUT"
  echo "SCREEN_CAPTURE=OK"
else
  echo "SCREEN_CAPTURE=FALLO (no se creo la captura)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
