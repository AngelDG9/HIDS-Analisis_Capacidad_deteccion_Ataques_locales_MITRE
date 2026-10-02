#!/usr/bin/env bash
# ============================================================================
# ATA050 · T1567.003 — PRE-STAGING (antes de t0, fuera de la ventana)
# ----------------------------------------------------------------------------
# Crea el fichero de texto de juguete a exfiltrar (`filtracion/notas_internas.txt`).
# No hay material externo: `curl` es de serie y el "paste" es del laboratorio.
# Elevacion: NO. Sin NAT.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA050"
cd "$BASE" || { echo "ERROR: no existe $BASE" >&2; exit 1; }

mkdir -p "$BASE/filtracion"
{
  printf 'usuario=angel\n'
  printf 'password=Lab2026_NoReal\n'
  printf 'api_key=sk-TFG-DEMO-NO-REAL-0001\n'
  printf 'Nota: credenciales de juguete para la prueba de exfiltracion a "paste".\n'
} > "$BASE/filtracion/notas_internas.txt"

echo "--- sha256 del texto de juguete ---"
sha256sum "$BASE/filtracion/notas_internas.txt"
echo "PRE_STAGING=OK"
