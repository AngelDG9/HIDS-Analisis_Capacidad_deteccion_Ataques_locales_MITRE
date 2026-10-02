#!/usr/bin/env bash
# ============================================================================
# ATA044 · T1025 — PRE-STAGING: crea el "medio extraible simulado"
# ----------------------------------------------------------------------------
# Se ejecuta ANTES de t0 (fuera de la ventana): deja el medio listo para que la
# ventana mida SOLO la accion (adjuntar en ro + listar + copiar).
#
# El "medio" es una imagen vfat pequena y fijada con documentos senuelo:
#   removable.img (4 MiB, FAT) con clientes_2026.csv / nominas.csv / notas.txt
#
# Elevacion: SI (sudo) SOLO para `losetup`/`mount`/`umount` (inyectar ficheros).
# Guardarrail DURO: SOLO una imagen de fichero bajo lab-attack/ATA044; jamas un
# dispositivo real.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA044"
IMG="${BASE}/removable.img"
MNT="${BASE}/mnt_stage"

if [ -z "${SUDO_PW:-}" ]; then IFS= read -r SUDO_PW || true; fi
if [ -z "${SUDO_PW:-}" ]; then
  echo "ERROR: falta la contrasena de sudo (variable SUDO_PW o stdin)" >&2
  exit 1
fi
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

if [ ! -d "$BASE" ]; then echo "ERROR: no existe $BASE" >&2; exit 1; fi
for t in dd mkfs.vfat losetup mount umount sha256sum realpath; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done
case "$IMG" in *"/dev/"*) echo "ERROR: /dev/ en ruta; ABORTADO" >&2; exit 1 ;; esac
BASE_REAL="$(realpath "$BASE")"; IMG_REAL="$(realpath -m "$IMG")"
if [ "${IMG_REAL#"$BASE_REAL"/}" = "$IMG_REAL" ]; then
  echo "ERROR: la imagen no cuelga de $BASE_REAL; ABORTADO" >&2; exit 1
fi

cd "$BASE" || exit 1
LOOP=""
cleanup() { sudo_cmd umount "$MNT" >/dev/null 2>&1 || true; [ -n "$LOOP" ] && sudo_cmd losetup -d "$LOOP" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# 1) imagen desechable de 4 MiB (FAT).
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count=4 status=none
mkfs.vfat -n REMOVABLE "$IMG" >/dev/null 2>&1
echo "medio_creado=$IMG ($(stat -c%s "$IMG") bytes)"

# 2) inyectar documentos senuelo (datos de juguete creibles).
mkdir -p "$MNT"
LOOP=$(sudo_cmd losetup --find --show "$IMG")
# uid/gid del usuario angel -> puede escribir en el vfat para inyectar los documentos.
sudo_cmd mount -o "uid=$(id -u),gid=$(id -g)" "$LOOP" "$MNT" \
  || { echo "ERROR: no se pudo montar la imagen; ABORTADO" >&2; exit 1; }
{ printf 'id,cliente,importe_eur\n1,ACME,12000.00\n2,Globex,8450.50\n3,Initech,3300.00\n' > "$MNT/clientes_2026.csv" \
  && printf 'empleado,bruto_eur\nA. Gomez,2450.00\nB. Ruiz,2600.00\nC. Soto,2300.00\n' > "$MNT/nominas.csv" \
  && printf 'Nota interna: rotacion de backups pendiente de revision.\n' > "$MNT/notas.txt"; } \
  || { echo "ERROR: no se pudieron inyectar los documentos; ABORTADO" >&2; exit 1; }
echo "--- documentos inyectados en el medio ---"
ls -l "$MNT"
sudo_cmd umount "$MNT"
sudo_cmd losetup -d "$LOOP"; LOOP=""

echo "--- sha256 del medio (para trazabilidad) ---"
sha256sum "$IMG" | tee "${BASE}/medio_sha256.txt"
echo "PRE_STAGING=OK"
