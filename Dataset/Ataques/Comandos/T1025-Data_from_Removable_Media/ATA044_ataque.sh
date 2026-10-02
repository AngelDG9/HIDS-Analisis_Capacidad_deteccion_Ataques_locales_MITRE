#!/usr/bin/env bash
# ============================================================================
# ATA044 · T1025 Data from Removable Media — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1025 Data from Removable Media (tactica Collection)
# Fuente  : custom (escrito por el TFG). ART trae SOLO prueba Windows
#           (PowerShell/Get-Volume); no hay prueba Linux -> propio.
# Objetivo: recopilar documentos de un MEDIO EXTRAIBLE SIMULADO. El "medio" es
#           una IMAGEN DE DISCO vfat (removable.img) creada en el pre-staging
#           (fuera de la ventana) con documentos senuelo. En la ventana se
#           ADJUNTA en SOLO-LECTURA (`losetup --read-only` + `mount -o ro`), se
#           LISTAN y se COPIAN los documentos a la carpeta de recoleccion.
# Destino : SOLO /home/angel/lab-attack/ATA044/removable.img (imagen de fichero).
#           JAMAS discos/particiones/USB reales.
# Ejecuta : desde /home/angel/lab-attack/ATA044 (cwd del ataque -> ancla H4)
# Elevacion: SI (sudo -S por stdin), SOLO para `losetup`/`mount`/`umount`.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El medio DEBE ser una IMAGEN DE FICHERO bajo lab-attack/ATA044. Si la ruta
#     contiene `/dev/` o el `realpath` NO cuelga de la carpeta -> ABORTA.
#   - Montaje SIEMPRE en SOLO-LECTURA (`-o ro`); PROHIBIDO tocar dispositivos
#     REALES (/dev/sd*, /dev/mmcblk*, USB). El loop se deriva de la imagen.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW/stdin).
#   - `trap`: desmonta y detacha cualquier loop residual al salir.
#
# Telemetria esperada (ver README §5):
#   - execve de losetup/mount/find/cp/sha256sum/umount -> 80792 (deteccion; S1..S6),
#     anclados por el cwd del ataque (S7).
#
# Prueba de exito (INDEPENDIENTE de la alerta): cada documento copiado tiene el
#   MISMO sha256 que el original del medio montado; la imagen se monto en ro.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA044"
IMG="${BASE}/removable.img"
MNT="${BASE}/mnt_ro"
COL="${BASE}/collected"

echo "ATA044 · T1025 Data from Removable Media (imagen loop ro) — custom (manual)"
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
for t in losetup mount umount find cp sha256sum realpath stat; do
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
  *"/dev/"*) echo "ERROR: punto de montaje con /dev/; ABORTADO" >&2; exit 1 ;;
esac
BASE_REAL="$(realpath "$BASE")"
IMG_REAL="$(realpath -m "$IMG")"
if [ "${IMG_REAL#"$BASE_REAL"/}" = "$IMG_REAL" ]; then
  echo "ERROR: la imagen '$IMG_REAL' NO cuelga de '$BASE_REAL'; ABORTADO" >&2; exit 1
fi
case "$BASE" in
  "$HOME/lab-attack/ATA044"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA044; ABORTADO" >&2; exit 1 ;;
esac

if [ ! -f "$IMG" ]; then
  echo "ERROR: falta el medio $IMG (¿se ejecuto el pre-staging ATA044_prestaging.sh?)" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

LOOP=""
cleanup() {
  sudo_cmd umount "$MNT" >/dev/null 2>&1 || true
  if [ -n "$LOOP" ]; then sudo_cmd losetup -d "$LOOP" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "--- medio (imagen) ---"
ls -l "$IMG"
sha256sum "$IMG"

# 1) ADJUNTAR el medio SIMULADO en SOLO-LECTURA (execve losetup + mount).
mkdir -p "$MNT" "$COL"
LOOP=$(sudo_cmd losetup --find --show --read-only "$IMG")
echo "loop_asignado=$LOOP (read-only)"
if ! sudo_cmd mount -o ro "$LOOP" "$MNT"; then
  echo "ERROR: no se pudo montar el medio en ro; ABORTADO" >&2
  exit 1
fi
echo "montaje_ro=OK"

# 2) LISTAR los documentos del medio extraible (execve find).
echo "--- documentos en el medio ---"
find "$MNT" -type f | sed 's/^/  /'

# 3) RECOPILAR los documentos (execve cp). Solo .csv/.txt simulados.
for f in "$MNT"/*.csv "$MNT"/*.txt "$MNT"/*.pdf; do
  [ -f "$f" ] || continue
  cp -p "$f" "$COL"/
done
echo "--- recopilado en $COL ---"
ls -l "$COL"

# 4) PRUEBA DEL EFECTO: sha256 origen (medio) == sha256 copia (recoleccion).
echo "--- comparacion sha256 origen vs copia ---"
ok=1
n=0
for src in "$MNT"/*.csv "$MNT"/*.txt "$MNT"/*.pdf; do
  [ -f "$src" ] || continue
  name=$(basename "$src")
  s_src=$(sha256sum "$src" | awk '{print $1}')
  s_dst=$(sha256sum "$COL/$name" | awk '{print $1}')
  n=$((n + 1))
  if [ "$s_src" = "$s_dst" ]; then
    echo "  $name OK ($s_src)"
  else
    echo "  $name MISMATCH src=$s_src dst=$s_dst" >&2
    ok=0
  fi
done

# 5) DESMONTAR y DETACHAR (execve umount + losetup -d).
sudo_cmd umount "$MNT"
sudo_cmd losetup -d "$LOOP"; LOOP=""
echo "montaje_ro=desmontado"

echo "--- estado final ---"
echo "documentos_recopilados=$n"
echo "loop_residual=$(losetup -a 2>/dev/null | grep -c "$IMG" || true)"
if [ "$ok" -eq 1 ] && [ "$n" -gt 0 ] && [ "$(losetup -a 2>/dev/null | grep -c "$IMG" || true)" -eq 0 ]; then
  echo "REMOVABLE_MEDIA=OK (documentos recopilados con sha256 identico; medio desmontado)"
  trap - EXIT
else
  echo "REMOVABLE_MEDIA=FALLO (ok=$ok n=$n)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
