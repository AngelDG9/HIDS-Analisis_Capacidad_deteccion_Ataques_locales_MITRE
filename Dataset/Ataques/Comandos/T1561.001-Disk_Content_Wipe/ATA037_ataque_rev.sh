#!/usr/bin/env bash
# ============================================================================
# ATA037_rev · T1561.001 Disk Content Wipe — repetición auditada (motivo: pre-staging)
# ----------------------------------------------------------------------------
# Corrección metodológica (§C): la IMAGEN de fichero (`disk.img`) se CREA y FORMATEA (ext4) y se
#   ESCRIBE el dato ANTES de t0 (modo prestage). La ventana ejecuta SOLO la acción de la técnica:
#   el WIPE del contenido (montar + sobrescribir in place + desmontar), dejando la estructura intacta.
# Fuente: custom (sin cambio de mecanismo).
#
# Uso:  PRINT_SHA=<sha> bash ATA037_ataque_rev.sh prestage   # ANTES de t0 (crea la imagen ext4)
#       bash ATA037_ataque_rev.sh attack                     # ventana [t0,t1] (solo el wipe)
# Elevación: SI (sudo -S por stdin), SOLO para `mount`/`umount`/`losetup` (+ chown del mnt).
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El destino DEBE ser una IMAGEN DE FICHERO REGULAR bajo lab-attack/ATA037.
#     Si la ruta contiene `/dev/`, si `stat` NO dice "regular file" o si el `realpath` NO cuelga
#     de la carpeta del ataque -> ABORTA.
#   - PROHIBIDO TERMINANTEMENTE tocar discos/particiones/dispositivos REALES.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW / stdin).
#   - `trap`: detacha cualquier loop residual al salir.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA037"
IMG="${BASE}/disk.img"
MNT="${BASE}/mnt"
DATA="${MNT}/datos_confidenciales.bin"
SHAF="${BASE}/sha_antes.txt"
MODE="${1:-attack}"

echo "ATA037_rev · T1561.001 Disk Content Wipe (SOLO imagen loop) — repeticion (pre-staging)"
echo "MODE=${MODE}"

if [ -z "${SUDO_PW:-}" ]; then
  IFS= read -r SUDO_PW || true
fi
if [ -z "${SUDO_PW:-}" ]; then
  echo "ERROR: falta la contrasena de sudo (variable SUDO_PW o primera linea de stdin)" >&2
  exit 1
fi
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in dd mkfs.ext4 mount umount losetup file blkid sha256sum stat realpath awk; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done

# --- GUARDARRAIL DURO: SOLO imagen de fichero bajo la carpeta del ataque ---
for r in "$IMG" "$MNT" "$DATA"; do
  case "$r" in
    *"/dev/"*) echo "ERROR: ruta con /dev/ ('$r'); ABORTADO por seguridad" >&2; exit 1 ;;
  esac
done
case "$BASE" in
  "$HOME/lab-attack/ATA037"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA037; ABORTADO" >&2; exit 1 ;;
esac
mkdir -p "$BASE"
BASE_REAL="$(realpath "$BASE")"
IMG_REAL="$(realpath -m "$IMG")"
if [ "${IMG_REAL#"$BASE_REAL"/}" = "$IMG_REAL" ]; then
  echo "ERROR: la imagen '$IMG_REAL' NO cuelga de '$BASE_REAL'; ABORTADO" >&2
  exit 1
fi

cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

LOOP=""
detach() { if [ -n "$LOOP" ]; then sudo_cmd losetup -d "$LOOP" >/dev/null 2>&1 || true; fi; }
trap detach EXIT

if [ "$MODE" = "prestage" ]; then
  # 1) CREAR la imagen desechable (16 MiB de ceros) ANTES de t0.
  rm -f "$IMG"
  dd if=/dev/zero of="$IMG" bs=1M count=16 status=none
  echo "imagen_creada=${IMG} ($(stat -c%s "$IMG") bytes)"
  FMT="$(stat -c '%F' "$IMG")"
  echo "tipo_imagen=${FMT}"
  if [ "$FMT" != "regular file" ] || [ -b "$IMG" ]; then
    echo "ERROR: '$IMG' NO es un fichero regular; ABORTADO por seguridad" >&2
    exit 1
  fi
  # 2) DAR ESTRUCTURA: filesystem ext4 (queda ANTES de t0).
  mkfs.ext4 -F -q "$IMG"
  echo "--- estructura (preparada en el pre-staging) ---"
  file -s "$IMG" | tee "${BASE}/estructura_antes.txt"
  # 3) MONTAR (loop), ESCRIBIR el dato y registrar el contenido (todo antes de t0).
  mkdir -p "$MNT"
  LOOP=$(sudo_cmd losetup --find --show "$IMG")
  echo "loop_asignado=${LOOP}"
  if ! sudo_cmd mount "$LOOP" "$MNT"; then
    echo "ERROR: no se pudo montar la imagen intacta; ABORTADO" >&2
    exit 1
  fi
  sudo_cmd chown "$(id -u):$(id -g)" "$MNT" 2>/dev/null || true
  dd if=/dev/zero of="$DATA" bs=1M count=4 status=none
  sha_antes=$(sha256sum "$DATA" | awk '{print $1}')
  echo "sha_dato_antes=${sha_antes}" | tee "$SHAF"
  sudo_cmd umount "$MNT"
  detach; LOOP=""
  echo "PRESTAGE=OK (imagen ext4 creada con dato; sha_dato_antes=${sha_antes})"
  exit 0
fi

# ---- modo attack (ventana): SOLO el wipe del contenido ----
[ -f "$IMG" ] || { echo "ERROR: falta la imagen (¿prestage ANTES de t0?)" >&2; exit 1; }
FMT="$(stat -c '%F' "$IMG")"
if [ "$FMT" != "regular file" ] || [ -b "$IMG" ]; then
  echo "ERROR: '$IMG' NO es un fichero regular; ABORTADO por seguridad" >&2; exit 1
fi
sha_antes=$(sed -n 's/^sha_dato_antes=//p' "$SHAF" 2>/dev/null || true)
[ -n "$sha_antes" ] || { echo "ERROR: falta sha_dato_antes (¿prestage ANTES de t0?)" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$MNT"
LOOP=$(sudo_cmd losetup --find --show "$IMG")
echo "loop_asignado=${LOOP}"
if ! sudo_cmd mount "$LOOP" "$MNT"; then
  echo "ERROR: no se pudo montar la imagen; ABORTADO" >&2; exit 1
fi
sudo_cmd chown "$(id -u):$(id -g)" "$MNT" 2>/dev/null || true
echo "montaje_antes=OK"

# WIPE DEL CONTENIDO: sobrescribe el contenido del dato EN EL DISCO (imagen).
dd if=/dev/urandom of="$DATA" bs=1M count=4 conv=notrunc status=none
sha_despues=$(sha256sum "$DATA" | awk '{print $1}')
echo "sha_dato_despues=${sha_despues}"

sudo_cmd umount "$MNT"
sudo_cmd losetup -d "$LOOP"; LOOP=""
echo "--- estructura (DESPUES del wipe) ---"
file -s "$IMG" | tee "${BASE}/estructura_despues.txt"
if blkid "$IMG" >/dev/null 2>&1; then
  echo "blkid_tras_wipe=reconoce_ext4" | tee -a "${BASE}/estructura_despues.txt"
else
  echo "blkid_tras_wipe=NO_reconoce(ERROR)" | tee -a "${BASE}/estructura_despues.txt"
fi

# PRUEBA DEL EFECTO: el CONTENIDO cambio pero la ESTRUCTURA SIGUE MONTANDO.
LOOP=$(sudo_cmd losetup --find --show "$IMG" 2>/dev/null || true)
monta_despues="NO"
if [ -n "$LOOP" ]; then
  if sudo_cmd mount "$LOOP" "$MNT" 2>/dev/null; then
    monta_despues="SI"
    sudo_cmd umount "$MNT"
  fi
  detach; LOOP=""
fi
echo "montaje_despues=${monta_despues}"

echo "--- estado final ---"
echo "sha_dato_antes  =${sha_antes}"
echo "sha_dato_despues=${sha_despues}"
echo "loop_residual=$(losetup -a 2>/dev/null | grep -c "$IMG" || true)"
if [ "$sha_antes" != "$sha_despues" ] \
   && [ "$monta_despues" = "SI" ] \
   && [ "$(losetup -a 2>/dev/null | grep -c "$IMG" || true)" -eq 0 ]; then
  echo "DISK_CONTENT_WIPE=OK (contenido del disco sobrescrito; estructura intacta y montable)"
  trap - EXIT
else
  echo "DISK_CONTENT_WIPE=FALLO (revisar residuos/estructura)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
