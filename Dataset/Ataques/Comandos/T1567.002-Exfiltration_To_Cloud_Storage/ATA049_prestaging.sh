#!/usr/bin/env bash
# ============================================================================
# ATA049 · T1567.002 — PRE-STAGING (antes de t0, fuera de la ventana)
# ----------------------------------------------------------------------------
# Deja listo el cliente de nube (`rclone`, ya copiado por scp al directorio) y el
# directorio de datos de juguete a exfiltrar (`exfil/`). El binario rclone se
# pre-stea (URL+sha256) porque NO esta en el laboratorio.
# Elevacion: NO. Sin NAT. Sin claves reales.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA049"
cd "$BASE" || { echo "ERROR: no existe $BASE" >&2; exit 1; }

if [ ! -f "$BASE/rclone" ]; then echo "ERROR: falta rclone (scp)" >&2; exit 1; fi
chmod +x "$BASE/rclone"

# Datos de juguete con nombres creibles (escena de empresa).
mkdir -p "$BASE/exfil"
printf 'id,cliente,importe_eur\n1,ACME,12000.00\n2,Globex,8450.50\n3,Initech,3300.00\n' > "$BASE/exfil/clientes_2026.csv"
printf 'empleado,bruto_eur\nA. Gomez,2450.00\nB. Ruiz,2600.00\nC. Soto,2300.00\n' > "$BASE/exfil/nominas.csv"
printf 'Nota interna: rotacion de backups pendiente de revision.\n' > "$BASE/exfil/notas.txt"

echo "--- sha256 de los datos a exfiltrar ---"
sha256sum "$BASE"/exfil/*
echo "PRE_STAGING=OK"
