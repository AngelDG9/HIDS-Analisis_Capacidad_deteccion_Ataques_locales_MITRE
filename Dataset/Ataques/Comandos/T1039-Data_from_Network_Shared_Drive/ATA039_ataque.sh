#!/usr/bin/env bash
# ============================================================================
# ATA039 · T1039 Data from Network Shared Drive — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1039 Data from Network Shared Drive (tactica Collection).
#           Recolecta datos desde un RECURSO COMPARTIDO de red LOCAL (el
#           "servidor de ficheros" del laboratorio), no desde el FS local.
# Fuente  : custom (escrito por el TFG)
# Objetivo: montar/leer el recurso compartido del servidor del laboratorio y
#           COPIAR su contenido a la carpeta del ataque (recoleccion remota).
# Recurso : rsync://192.168.65.128:9873/share/  (servidor de ficheros = manager
#           del laboratorio, VMnet1). Modulo `share` en modo solo-lectura.
# Ejecuta : desde /home/angel/lab-attack/ATA039 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ MONTAJE (paso 0): en este laboratorio NO hay cliente NFS/SMB disponible
#    sin NAT (ni `mount.nfs`, ni `mount.cifs`, ni `sshfs`). La opcion local mas
#    simple es un RECURSO COMPARTIDO servido por el manager con el DAEMON de
#    `rsync` (rsync://, puerto 9873, sin autenticacion, solo VMnet1). "Montar"
#    = arrancar el daemon en el manager antes de t0; "desmontar" = pararlo tras
#    t1. Ver README §9 y el cierre de la tanda.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el recurso DEBE ser el del laboratorio (192.168.65.128:9873);
#   - solo se escribe en $HOME/lab-attack/ATA039; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de rsync (cliente que recolecta el recurso) -> 80792 (deteccion; T1039-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA039/*` (T1039-S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el sha256 de los ficheros
#   copiados coincide con el sha256 de los ficheros del recurso en el manager.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA039"
DEST="${BASE}/share_copy"
SRV="192.168.65.128"
PORT="9873"
MOD="share"
URL="rsync://${SRV}:${PORT}/${MOD}/"

echo "ATA039 · T1039 Data from Network Shared Drive (rsync recolecta el recurso) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync no disponible" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el recurso DEBE ser el servidor de ficheros del laboratorio (VMnet1).
if [ "$SRV" != "192.168.65.128" ] || [ "$PORT" != "9873" ]; then
  echo "ERROR: recurso '$SRV:$PORT' fuera del servidor del laboratorio (abortado)" >&2
  exit 1
fi
# GUARDARRAIL: el destino DEBE quedar bajo la carpeta del ataque.
case "$DEST" in
  "$HOME/lab-attack/ATA039"*) : ;;
  *) echo "ERROR: destino '$DEST' no esta bajo lab-attack/ATA039 (abortado)" >&2; exit 1 ;;
esac

# --- recurso compartido accesible? (aborta ruidosamente si el daemon no esta) ---
if ! rsync --list-only "$URL" >/dev/null 2>&1; then
  echo "ERROR: recurso compartido no accesible ($URL); ¿daemon rsync levantado en el manager?" >&2
  exit 1
fi

echo "--- RECURSO COMPARTIDO (listado remoto) ---"
rsync --list-only "$URL"

# --- RECOLECCION: copia recursiva del recurso a la carpeta del ataque (execve de rsync) ---
rm -rf "$DEST"
mkdir -p "$DEST"
rsync -a --stats "$URL" "$DEST/"

# --- prueba de efecto local: huella del material recolectado ---
echo "--- material recolectado (sha256 local) ---"
find "$DEST" -type f -print0 | sort -z | xargs -0 sha256sum

echo "--- estado final ---"
n_files=$(find "$DEST" -type f | wc -l)
echo "ficheros_recolectados=${n_files}"
if [ "$n_files" -ge 1 ]; then
  echo "RECOLECCION=OK ($n_files ficheros copiados del recurso compartido)"
else
  echo "RECOLECCION=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
