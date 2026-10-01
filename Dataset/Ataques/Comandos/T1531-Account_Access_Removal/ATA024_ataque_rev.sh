#!/usr/bin/env bash
# ============================================================================
# ATA024_rev · T1531 Account Access Removal — repetición auditada (motivo: ART)
# ----------------------------------------------------------------------------
# Método corregido = PRUEBA DE ART (ADAPTADA):
#   atomic  : "Change User Password via passwd"
#   guid    : 3c717bf3-2ecc-4d79-8ac8-0bfbf08fbce6
#   path    : atomics/T1531/T1531.yaml
#   commit  : 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
#   comando : passwd #{user_account}     (elevation_required: true)
# ADAPTACIÓN (se anota qué se recorta respecto al ataque ORIGINAL):
#   - El original CREABA (`useradd`), BLOQUEABA (`passwd -l`) y ELIMINABA (`userdel -r`).
#   - La atómica Linux de T1531 SOLO CAMBIA LA CONTRASEÑA (`passwd`); NO bloquea ni elimina.
#   - La cuenta desechable (`tfg-victim01`) se CREA en el pre-staging (setup, antes de t0) y
#     se ELIMINA en el cleanup (tras t1): ninguna de esas dos acciones cae en [t0,t1].
#   - La atómica es interactiva: la nueva contraseña se pasa por stdin (por `passwd`).
# Guardarraíl DURO: SOLO el usuario desechable `tfg-victim01`; nunca cuentas reales.
#
# Uso:  bash ATA024_ataque_rev.sh prestage   # ANTES de t0 (crea el usuario)
#       bash ATA024_ataque_rev.sh attack     # ventana [t0,t1] (passwd)
#       bash ATA024_ataque_rev.sh cleanup    # tras t1 (elimina el usuario)
# Elevación: SÍ (sudo -S por stdin / SUDO_PW).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA024"
DUSER="tfg-victim01"
EXPECTED="tfg-victim01"
NEWPW="${NEWPW:-Tfg-Victim-2026!}"
MODE="${1:-attack}"

echo "ATA024_rev · T1531 Account Access Removal (atómica ART passwd, usuario desechable) — repeticion"

# --- guardarraíles duros ---
case "$DUSER" in
  "$EXPECTED") : ;;
  *) echo "ERROR: usuario '$DUSER' != '$EXPECTED'; ABORTADO" >&2; exit 1 ;;
esac
for forbidden in root angel daemon bin sys sync nobody operator; do
  [ "$DUSER" = "$forbidden" ] && { echo "ERROR: '$DUSER' es cuenta real; ABORTADO" >&2; exit 1; }
done
case "$BASE" in
  "$HOME/lab-attack/ATA024") : ;;
  *) echo "ERROR: BASE '$BASE' fuera de lab-attack/ATA024; ABORTADO" >&2; exit 1 ;;
esac

# --- contraseña de sudo solo de memoria ---
if [ -z "${SUDO_PW:-}" ]; then IFS= read -r SUDO_PW || true; fi
if [ -z "${SUDO_PW:-}" ]; then
  echo "ERROR: falta la contrasena de sudo (SUDO_PW o 1a linea de stdin)" >&2; exit 1
fi
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

case "$MODE" in
  prestage)
    id "$DUSER" >/dev/null 2>&1 && { echo "ERROR: ${DUSER} ya existe (estado no limpio); ABORTADO" >&2; exit 1; }
    sudo_cmd useradd -m -s /bin/bash "$DUSER"
    grep "^${DUSER}:" /etc/passwd | tee "${BASE}/usuario_creado.txt"
    sudo_cmd grep "^${DUSER}:" /etc/shadow > "${BASE}/shadow_antes.txt" 2>/dev/null || true
    echo "PRESTAGE=OK (usuario desechable ${DUSER} creado antes de t0)"
    ;;
  attack)
    cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
    id "$DUSER" >/dev/null 2>&1 || { echo "ERROR: ${DUSER} no existe (¿prestage ANTES de t0?)" >&2; exit 1; }
    echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "--- comando atómico: passwd ${DUSER} (nueva contraseña por stdin) ---"
    # sudo -S consume la 1a linea; passwd consume las dos siguientes (nueva + confirmacion).
    printf '%s\n%s\n%s\n' "$SUDO_PW" "$NEWPW" "$NEWPW" | sudo -S -p '' passwd "$DUSER"
    echo "--- estado de la cuenta tras el cambio (passwd -S) ---"
    sudo_cmd passwd -S "$DUSER" | tee "${BASE}/cuenta_estado.txt"
    sudo_cmd grep "^${DUSER}:" /etc/shadow > "${BASE}/shadow_despues.txt" 2>/dev/null || true
    s_antes=$(cat "${BASE}/shadow_antes.txt" 2>/dev/null | sha256sum | awk '{print $1}')
    s_despues=$(cat "${BASE}/shadow_despues.txt" 2>/dev/null | sha256sum | awk '{print $1}')
    echo "shadow_hash_antes  =${s_antes}"
    echo "shadow_hash_despues=${s_despues}"
    if [ -n "$s_antes" ] && [ "$s_antes" != "$s_despues" ]; then
      echo "PASSWORD_CHANGE=OK (la entrada de /etc/shadow cambio: hash antes != despues)"
    else
      echo "PASSWORD_CHANGE=FALLO (shadow sin cambios)" >&2
    fi
    sleep 1
    echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ;;
  cleanup)
    if id "$DUSER" >/dev/null 2>&1; then
      sudo_cmd userdel -r "$DUSER"
      echo "CLEANUP=OK (${DUSER} eliminado)"
    else
      echo "CLEANUP=noop (${DUSER} no existe)"
    fi
    ;;
  *) echo "uso: $0 {prestage|attack|cleanup}" >&2; exit 2 ;;
esac
