#!/usr/bin/env bash
# ============================================================================
# ATA024 · T1531 Account Access Removal — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1531 Account Access Removal (tactica Impact / sabotaje)
# Fuente  : custom (escrito por el TFG)
# Objetivo: SABOTEAR el acceso a una cuenta del laboratorio: crear un usuario
#           DESECHABLE, BLOQUEARLE el acceso (`passwd -l`) y ELIMINARLO
#           (`userdel -r`). Toca las capas auth/PAM/syslog y los FICHEROS DE
#           CUENTAS (/etc/passwd, /etc/shadow, /etc/group) -> capa nueva.
# Destino : /etc/passwd, /etc/shadow, /etc/group (via useradd/passwd/userdel)
#           + /home/tfg-victim01 (home desechable, creado y borrado).
# Ejecuta : desde /home/angel/lab-attack/ATA024 (cwd del ataque -> ancla H4)
# Elevacion: SI (sudo -S por stdin), SOLO para useradd/usermod/passwd/userdel.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - SOLO el usuario DESECHABLE `tfg-victim01`. JAMAS `angel`, `root` ni
#     ninguna cuenta real del sistema.
#   - NO se edita /etc/passwd ni /etc/shadow a mano: se usan las herramientas
#     del sistema (useradd / passwd / userdel).
#   - La contrasena de `sudo` NUNCA esta en este fichero: se lee del entorno
#     SUDO_PW o de la primera linea de stdin (por `sudo -S`).
#   - `trap`: si el guion termina con el usuario creado, lo ELIMINA (no queda
#     residuo: el laboratorio cierra sin usuarios desechables).
#
# Telemetria esperada (ver README §5):
#   - execve de useradd / passwd / userdel -> 80792 (deteccion; S1/S2/S3).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA024/*` (S4).
#   - escritura bajo el watch de /etc (audit-wazuh-w) -> 80790/80781/80782
#     -> AMBIGUA (efecto del ataque, no deteccion declarada).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el usuario NO existe al final,
#   su home no existe, /etc/passwd cambio (sha256 antes != despues) y quedo una
#   entrada creada + estado bloqueado registrados en evidencia.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA024"
DUSER="tfg-victim01"
EXPECTED="tfg-victim01"

echo "ATA024 · T1531 Account Access Removal (usuario desechable ${DUSER}) — custom (manual)"
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
for t in id grep useradd userdel passwd sha256sum ls awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAIL DURO: solo el usuario desechable esperado ---
case "$DUSER" in
  "$EXPECTED") : ;;
  *) echo "ERROR: usuario '$DUSER' != '$EXPECTED' (desechable); ABORTADO por seguridad" >&2; exit 1 ;;
esac
for forbidden in root angel daemon bin sys sync nobody operator; do
  if [ "$DUSER" = "$forbidden" ]; then
    echo "ERROR: '$DUSER' es una cuenta REAL del sistema; ABORTADO por seguridad" >&2
    exit 1
  fi
done
case "$BASE" in
  "$HOME/lab-attack/ATA024"*) : ;;
  *) echo "ERROR: BASE '$BASE' fuera de lab-attack/ATA024; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# --- limpieza de seguridad: sin residuo de usuario desechable ---
cleanup() {
  if id "$DUSER" >/dev/null 2>&1; then
    echo "CLEANUP: eliminando usuario desechable remanente ${DUSER}" >&2
    sudo_cmd userdel -r "$DUSER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# 0) Estado inicial: el usuario desechable NO debe existir.
if id "$DUSER" >/dev/null 2>&1; then
  echo "ERROR: ${DUSER} ya existe (estado no limpio); ABORTADO" >&2
  exit 1
fi
sha_passwd_antes=$(sha256sum /etc/passwd | awk '{print $1}')
echo "passwd_sha_antes=${sha_passwd_antes}"

# 1) CREAR el usuario desechable (execve de useradd).
sudo_cmd useradd -m -s /bin/bash "$DUSER"
echo "--- entrada creada en /etc/passwd ---"
grep "^${DUSER}:" /etc/passwd | tee "${BASE}/usuario_creado.txt"

# 2) BLOQUEAR el acceso (Account Access Removal, accion 1: passwd -l).
echo "--- estado de la cuenta ANTES del bloqueo (P=password set / L=locked) ---"
sudo_cmd passwd -S "$DUSER" | tee "${BASE}/cuenta_estado_previo.txt"
sudo_cmd passwd -l "$DUSER"
echo "--- estado de la cuenta TRAS el bloqueo ---"
sudo_cmd passwd -S "$DUSER" | tee "${BASE}/cuenta_bloqueada.txt"

# 3) ELIMINAR la cuenta (Account Access Removal, accion 2: userdel -r).
sudo_cmd userdel -r "$DUSER"

# 4) PRUEBA DEL EFECTO (independiente de la alerta).
sha_passwd_despues=$(sha256sum /etc/passwd | awk '{print $1}')
echo "--- estado final ---"
echo "passwd_sha_antes =${sha_passwd_antes}"
echo "passwd_sha_despues=${sha_passwd_despues}"
if id "$DUSER" >/dev/null 2>&1; then
  echo "id_tras_borrado=EXISTE(ERROR)"
else
  echo "id_tras_borrado=NO_EXISTE"
fi
echo "cuentas_tfg_restantes=$(grep -c '^tfg-' /etc/passwd || true)"
if [ -d "/home/${DUSER}" ]; then echo "home_restante=EXISTE(ERROR)"; else echo "home_restante=no_existe"; fi
creado=$(grep -c "^${DUSER}:" "${BASE}/usuario_creado.txt" || true)

if [ "${creado:-0}" -ge 1 ] \
   && ! id "$DUSER" >/dev/null 2>&1 \
   && [ ! -d "/home/${DUSER}" ]; then
  echo "ACCOUNT_REMOVAL=OK (usuario desechable creado, bloqueado y eliminado; ya no existe)"
  trap - EXIT
else
  echo "ACCOUNT_REMOVAL=FALLO (revisar: el usuario o su home sobreviven)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
