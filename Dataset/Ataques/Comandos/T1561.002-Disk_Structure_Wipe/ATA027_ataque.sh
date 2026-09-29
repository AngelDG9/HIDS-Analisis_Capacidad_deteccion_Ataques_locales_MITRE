#!/usr/bin/env bash
# ============================================================================
# ATA027 · T1561.002 Disk Structure Wipe — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1561.002 Disk Wipe: Disk Structure Wipe (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: DESTRUIR la ESTRUCTURA de un disco: se crea una IMAGEN DE FICHERO
#           desechable (`disk.img`), se le da una TABLA DE PARTICIONES (MBR) y un
#           filesystem (ext4), se MONTA (loop), y luego se DESTRUYE su estructura
#           (`wipefs -a` + `dd` de ceros sobre la cabecera), demostrando que la
#           imagen deja de ser reconocible NI montable.
# Destino : SOLO una IMAGEN DE FICHERO bajo la carpeta del ataque. JAMAS discos
#           ni particiones reales.
# Ejecuta : desde /home/angel/lab-attack/ATA027 (cwd del ataque -> ancla H4)
# Elevacion: SI (sudo -S por stdin), SOLO para `mount`/`umount`/`losetup`.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El destino DEBE ser una IMAGEN DE FICHERO bajo lab-attack/ATA027. Si la ruta
#     contiene `/dev/` o el `realpath` NO cuelga de la carpeta del ataque -> ABORTA.
#   - PROHIBIDO TERMINANTEMENTE tocar discos/particiones/dispositivos REALES
#     (`/dev/sd*`, `lsblk` targets, MBR/GPT de discos reales). El loop se crea con
#     `losetup --find --show <imagen>` (deriva del fichero) y se DETACHA siempre.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW / stdin).
#   - `trap`: detacha cualquier loop residual al salir.
#
# Telemetria esperada (ver README §5):
#   - execve de dd / sfdisk / mkfs.ext4 / wipefs / mount / umount / losetup -> 80792
#     (deteccion; S1..S7), anclados por el cwd del ataque (S8).
#
# Prueba de exito (INDEPENDIENTE de la alerta): ANTES del wipe la imagen es un ext4
#   valido y MONTA; DESPUES `file -s` dice `data`, `blkid` no reconoce nada y el
#   montaje FALLA. Sin loop residual.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA027"
IMG="${BASE}/disk.img"
MNT="${BASE}/mnt"

echo "ATA027 · T1561.002 Disk Structure Wipe (SOLO imagen loop) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- contrasena de sudo: SOLO de memoria (entorno o stdin). Jamas en el repo. ---
if [ -z "${SUDO_PW:-}" ]; then
  IFS= read -r SUDO_PW || true
fi
if [ -z "${SUDO_PW:-}" ]; then
  echo "ERROR: falta la contrasena de sudo (variable SUDO_PW o primera linea de stdin)" >&2
  exit 1
fi
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in dd sfdisk mkfs.ext4 wipefs mount umount losetup file blkid sha256sum realpath; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DURO: SOLO imagen de fichero bajo la carpeta del ataque ---
case "$IMG" in
  *"/dev/"*) echo "ERROR: destino con /dev/ en la ruta; ABORTADO por seguridad" >&2; exit 1 ;;
esac
case "$MNT" in
  *"/dev/"*) echo "ERROR: punto de montaje con /dev/; ABORTADO por seguridad" >&2; exit 1 ;;
esac
BASE_REAL="$(realpath "$BASE")"
IMG_REAL="$(realpath -m "$IMG")"
if [ "${IMG_REAL#"$BASE_REAL"/}" = "$IMG_REAL" ]; then
  echo "ERROR: la imagen '$IMG_REAL' NO cuelga de '$BASE_REAL'; ABORTADO" >&2; exit 1
fi
case "$BASE" in
  "$HOME/lab-attack/ATA027"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA027; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

LOOP=""
detach() { if [ -n "$LOOP" ]; then sudo_cmd losetup -d "$LOOP" >/dev/null 2>&1 || true; fi; }
trap detach EXIT

# 1) CREAR la imagen desechable (32 MiB de ceros).
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count=32 status=none
echo "imagen_creada=${IMG} ($(stat -c%s "$IMG") bytes)"

# 2) DAR ESTRUCTURA: tabla de particiones MBR + filesystem ext4.
printf 'label: dos\n,,83,*\n' | sfdisk "$IMG" >/dev/null 2>&1
mkfs.ext4 -F -q "$IMG"
echo "--- estructura ANTES del wipe ---"
file -s "$IMG" | tee "${BASE}/estructura_antes.txt"
sfdisk -l "$IMG" >> "${BASE}/estructura_antes.txt" 2>&1 || true
sha_antes=$(sha256sum "$IMG" | awk '{print $1}')

# 3) MONTAR (loop explicito sobre la imagen) y comprobar que es accesible.
mkdir -p "$MNT"
LOOP=$(sudo_cmd losetup --find --show "$IMG")
echo "loop_asignado=${LOOP}"
if sudo_cmd mount "$LOOP" "$MNT"; then
  echo "montaje_antes=OK"
  printf 'marcador de estructura\n' | tee "${MNT}/marcador_estructura.txt" >/dev/null 2>&1 || true
  ls -la "$MNT" | sed 's/^/  /'
  sudo_cmd umount "$MNT"
  sudo_cmd losetup -d "$LOOP"; LOOP=""
else
  echo "ERROR: no se pudo montar la imagen intacta; ABORTADO" >&2
  exit 1
fi

# 4) DESTRUIR LA ESTRUCTURA (wipefs de firmas + ceros sobre la cabecera MBR/superbloque).
wipefs -a "$IMG"
dd if=/dev/zero of="$IMG" bs=512 count=2048 conv=notrunc status=none
sha_despues=$(sha256sum "$IMG" | awk '{print $1}')
echo "--- estructura DESPUES del wipe ---"
file -s "$IMG" | tee "${BASE}/estructura_despues.txt"
if blkid "$IMG" >/dev/null 2>&1; then
  echo "blkid_tras_wipe=RECONOCE(ERROR)" | tee -a "${BASE}/estructura_despues.txt"
else
  echo "blkid_tras_wipe=no_reconoce" | tee -a "${BASE}/estructura_despues.txt"
fi

# 5) PRUEBA DEL EFECTO: la imagen YA NO es montable.
LOOP=$(sudo_cmd losetup --find --show "$IMG" 2>/dev/null || true)
if [ -n "$LOOP" ]; then
  if sudo_cmd mount "$LOOP" "$MNT" 2>/dev/null; then
    echo "montaje_despues=MONTA(ERROR)" | tee -a "${BASE}/estructura_despues.txt"
    sudo_cmd umount "$MNT" 2>/dev/null || true
  else
    echo "montaje_despues=falla(estructura destruida)" | tee -a "${BASE}/estructura_despues.txt"
  fi
  detach; LOOP=""
else
  echo "montaje_despues=losetup_falla(estructura destruida)" | tee -a "${BASE}/estructura_despues.txt"
fi

echo "--- estado final ---"
echo "sha256_antes =${sha_antes}"
echo "sha256_despues=${sha_despues}"
echo "loop_residual=$(losetup -a 2>/dev/null | grep -c "$IMG" || true)"
if [ "$sha_antes" != "$sha_despues" ] \
   && [ "$(losetup -a 2>/dev/null | grep -c "$IMG" || true)" -eq 0 ] \
   && ! blkid "$IMG" >/dev/null 2>&1; then
  echo "DISK_STRUCTURE_WIPE=OK (estructura de la imagen destruida; dejo de ser montable)"
  trap - EXIT
else
  echo "DISK_STRUCTURE_WIPE=FALLO (revisar residuos)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
