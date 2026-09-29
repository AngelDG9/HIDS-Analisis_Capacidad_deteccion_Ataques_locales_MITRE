#!/usr/bin/env bash
# ============================================================================
# ATA037 · T1561.001 Disk Content Wipe — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1561.001 Disk Wipe: Disk Content Wipe (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: BORRAR EL CONTENIDO de un disco: se prepara una IMAGEN DE FICHERO
#           desechable (`disk.img`), con filesystem ext4 y un dato dentro; se
#           MONTA (loop) y se SOBRESCRIBE el CONTENIDO del dato en el disco,
#           demostrando que el CONTENIDO cambia SIN danar la ESTRUCTURA (la
#           imagen SIGUE montando / sigue siendo ext4). Contraste con ATA027/
#           T1561.002, que DESTRUYO la estructura (dejo de ser montable).
# Destino : SOLO una IMAGEN DE FICHERO bajo la carpeta del ataque. JAMAS discos
#           ni particiones reales.
# Ejecuta : desde /home/angel/lab-attack/ATA037 (cwd del ataque -> ancla H4)
# Elevacion: SI (sudo -S por stdin), SOLO para `mount`/`umount`/`losetup`.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El destino DEBE ser una IMAGEN DE FICHERO REGULAR bajo lab-attack/ATA037.
#     Si la ruta contiene `/dev/`, si `stat` NO dice "regular file" o si el
#     `realpath` NO cuelga de la carpeta del ataque -> ABORTA.
#   - PROHIBIDO TERMINANTEMENTE tocar discos/particiones/dispositivos REALES
#     (`/dev/sd*`, `/dev/nvme*`, targets de `lsblk`, MBR/GPT reales). El loop se
#     crea con `losetup --find --show <imagen>` (deriva del fichero) y se DETACHA.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW / stdin).
#   - `trap`: detacha cualquier loop residual al salir.
#
# Telemetria esperada (ver README §5):
#   - execve de dd / mkfs.ext4(=mke2fs) / mount / umount / losetup -> 80792
#     (deteccion; S1..S5), anclados por el cwd del ataque (S6).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el CONTENIDO del dato cambia
#   (sha256 antes != despues) y la ESTRUCTURA sigue intacta (la imagen SIGUE
#   siendo ext4 y SIGUE montando tras el wipe). Sin loop residual.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA037"
IMG="${BASE}/disk.img"
MNT="${BASE}/mnt"
DATA="${MNT}/datos_confidenciales.bin"

echo "ATA037 · T1561.001 Disk Content Wipe (SOLO imagen loop) — custom"
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
for t in dd mkfs.ext4 mount umount losetup file blkid sha256sum stat realpath awk; do
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
case "$DATA" in
  *"/dev/"*) echo "ERROR: dato con /dev/ en la ruta; ABORTADO por seguridad" >&2; exit 1 ;;
esac
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

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

LOOP=""
detach() { if [ -n "$LOOP" ]; then sudo_cmd losetup -d "$LOOP" >/dev/null 2>&1 || true; fi; }
trap detach EXIT

# 1) CREAR la imagen desechable (16 MiB de ceros).
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count=16 status=none
echo "imagen_creada=${IMG} ($(stat -c%s "$IMG") bytes)"

# GUARDARRAIL DURO: la imagen DEBE ser un fichero REGULAR (nunca un dispositivo).
FMT="$(stat -c '%F' "$IMG")"
echo "tipo_imagen=${FMT}"
if [ "$FMT" != "regular file" ] || [ -b "$IMG" ]; then
  echo "ERROR: '$IMG' NO es un fichero regular; ABORTADO por seguridad" >&2
  exit 1
fi

# 2) DAR ESTRUCTURA: filesystem ext4.
mkfs.ext4 -F -q "$IMG"
echo "--- estructura (ANTES del wipe) ---"
file -s "$IMG" | tee "${BASE}/estructura_antes.txt"

# 3) MONTAR (loop sobre la imagen), escribir el dato y registrar el contenido.
mkdir -p "$MNT"
LOOP=$(sudo_cmd losetup --find --show "$IMG")
echo "loop_asignado=${LOOP}"
if ! sudo_cmd mount "$LOOP" "$MNT"; then
  echo "ERROR: no se pudo montar la imagen intacta; ABORTADO" >&2
  exit 1
fi
sudo_cmd chown "$(id -u):$(id -g)" "$MNT" 2>/dev/null || true
echo "montaje_antes=OK"
dd if=/dev/zero of="$DATA" bs=1M count=4 status=none           # dato "confidencial" (4 MiB)
sha_antes=$(sha256sum "$DATA" | awk '{print $1}')
echo "sha_dato_antes=${sha_antes}"

# 4) WIPE DEL CONTENIDO: sobrescribe el contenido del dato EN EL DISCO (imagen),
#    dejando INTACTA la estructura del filesystem.
dd if=/dev/urandom of="$DATA" bs=1M count=4 conv=notrunc status=none
sha_despues=$(sha256sum "$DATA" | awk '{print $1}')
echo "sha_dato_despues=${sha_despues}"

# 5) DESMONTAR y comprobar que la ESTRUCTURA sigue intacta (contenido != estructura).
sudo_cmd umount "$MNT"
sudo_cmd losetup -d "$LOOP"; LOOP=""
echo "--- estructura (DESPUES del wipe) ---"
file -s "$IMG" | tee "${BASE}/estructura_despues.txt"
if blkid "$IMG" >/dev/null 2>&1; then
  echo "blkid_tras_wipe=reconoce_ext4" | tee -a "${BASE}/estructura_despues.txt"
else
  echo "blkid_tras_wipe=NO_reconoce(ERROR)" | tee -a "${BASE}/estructura_despues.txt"
fi

# 6) PRUEBA DEL EFECTO: el CONTENIDO cambio pero la ESTRUCTURA SIGUE MONTANDO.
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
