#!/usr/bin/env bash
# ============================================================================
# ATA005 · T1561 Disk Wipe — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1561 Disk Wipe (tactica Impact)
# Fuente  : custom (Atomic Red Team NO tiene pruebas para T1561 -> sin_pruebas)
# Objetivo: MACHACAR (sobrescribir con bytes aleatorios) un FICHERO DE TRABAJO
#           del laboratorio (escena de empresa: una copia de seguridad simulada)
#           para simular el borrado destructivo de un disco.
#           NUNCA se toca un dispositivo real (/dev/sd*, /dev/nvme*, ...).
# Destino : /home/angel/lab-attack/ATA005/  (NO vigilado -> deteccion por execve)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el destino DEBE estar bajo $HOME/lab-attack/ATA005/;
#   - el destino NO puede ser un fichero de dispositivo (block/char).
#
# Telemetria esperada (ver README §7):
#   - execve de dd / shred -> 80792 (deteccion; senales T1561-S1/S2/S3)
#
# Prueba de exito (INDEPENDIENTE de la alerta): sha256 ANTES != DESPUES con el
#   TAMANO estable => el contenido se sobrescribio (wipe) sin cambiar el tamano.
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA005"
TARGET="${BASE}/backup_completo_2026-09.bin"
SHRED_TARGET="${BASE}/notas_operaciones.txt"

echo "ATA005 · T1561 Disk Wipe (dd/shred) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in dd shred sha256sum stat; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL 1: el destino debe estar bajo la carpeta del ataque (nunca un disco real).
case "$TARGET" in
  "$BASE"/*) : ;;
  *) echo "ERROR: destino '$TARGET' fuera de '$BASE' (abortado por seguridad)" >&2; exit 1 ;;
esac
# GUARDARRAIL 2: nunca un fichero de dispositivo.
if [ -b "$TARGET" ] || [ -c "$TARGET" ]; then
  echo "ERROR: '$TARGET' es un dispositivo; prohibido (abortado por seguridad)" >&2
  exit 1
fi

# 1) Fichero de trabajo de 32 MiB (determinista en tamano; si ya existe, se reutiliza).
if [ ! -f "$TARGET" ]; then
  dd if=/dev/zero of="$TARGET" bs=1M count=32 status=none
fi
sha_antes=$(sha256sum "$TARGET" | awk '{print $1}')
size_antes=$(stat -c %s "$TARGET")

# 2) WIPE: sobrescritura IN-SITU con bytes aleatorios (mismo tamano, conv=notrunc).
dd if=/dev/urandom of="$TARGET" bs=1M count=32 conv=notrunc status=none

sha_despues=$(sha256sum "$TARGET" | awk '{print $1}')
size_despues=$(stat -c %s "$TARGET")

# 3) Segundo vector: `shred` (1 pasada aleatoria + 1 de ceros + borrado) sobre un fichero pequeno.
printf 'TFG-HIDS · notas de operaciones falsas (objetivo de shred para ATA005, T1561).\n' > "$SHRED_TARGET"
shred -n 1 -z -u "$SHRED_TARGET"

echo "--- estado final ---"
ls -l "$TARGET" 2>/dev/null
echo "sha256 antes   = $sha_antes"
echo "sha256 despues = $sha_despues"
echo "size antes=$size_antes despues=$size_despues"
if [ "$sha_antes" != "$sha_despues" ] && [ "$size_antes" = "$size_despues" ]; then
  echo "WIPE=OK (contenido sobrescrito; tamano estable)"
else
  echo "WIPE=FALLO" >&2
fi
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
