#!/usr/bin/env bash
# ============================================================================
# ATA038_rev · T1529 System Shutdown/Reboot — repetición auditada (motivo: art+prestaging)
# ----------------------------------------------------------------------------
# Corrección metodológica:
#   * ART (motivo `art`): se ejecuta la atómica "Restart System via `shutdown`"
#       guid : 6326dbc4-444b-4c04-88f4-27e94d0327cb
#       path : atomics/T1529/T1529.yaml
#       commit: 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
#       comando: shutdown -r #{timeout}  (timeout=+1)  -> `art_tal_cual` (parametrizada)
#   * PRE (motivo `prestaging`): el ESTADO (`pre_reboot.txt`) se ESCRIBE ANTES de t0; la
#     ventana ejecuta SOLO la acción de la técnica (el reinicio programado).
# Fuente: ART (atómica Linux, elevation_required: true).
#
# Uso:  bash ATA038_ataque_rev.sh prestage   # ANTES de t0 (escribe pre_reboot.txt)
#       bash ATA038_ataque_rev.sh attack     # ventana [t0,t1] (atómica: sudo shutdown -r +1)
# Elevación: SI (sudo -S por stdin), SOLO para `shutdown -r`.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - SOLO se reinicia la VM VICTIMA: se EXIGE `hostname == victima-linux` y la IP 192.168.65.129.
#     Si aparece la IP del manager -> ABORTA (nunca el manager ni el anfitrion).
#   - El reinicio se PROGRAMA a +1 min (timeout=+1 de la atómica) para sellar la evidencia antes.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW / stdin).
#
# NOTA (paso 0): `shutdown`/`reboot` son enlaces a `/usr/bin/systemctl` -> el execve registra el REAL.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA038"
VICTIM_HOST="victima-linux"
VICTIM_IP="192.168.65.129"
MANAGER_IP="192.168.65.128"
MODE="${1:-attack}"

echo "ATA038_rev · T1529 System Shutdown/Reboot (atómica ART, reinicio VM victima) — repeticion"
echo "MODE=${MODE}"

# La contrasena solo es necesaria para la atómica (attack); el prestage no usa sudo.
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in hostname ip systemctl sha256sum cat; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done

# --- ⚠️⚠️ GUARDARRAIL DURO: SOLO la VM VICTIMA ---
H="$(hostname)"
IPS="$(hostname -I 2>/dev/null || true)"
echo "hostname=${H}"
echo "ips=${IPS}"
if [ "$H" != "$VICTIM_HOST" ]; then
  echo "ERROR: host '$H' != '$VICTIM_HOST'; ABORTADO (solo se reinicia la VM victima)" >&2
  exit 1
fi
case "$IPS" in
  *"$VICTIM_IP"*) : ;;
  *) echo "ERROR: la IP '$VICTIM_IP' no esta presente; ABORTADO por seguridad" >&2; exit 1 ;;
esac
case "$IPS" in
  *"$MANAGER_IP"*) echo "ERROR: aparece la IP del MANAGER; ABORTADO por seguridad" >&2; exit 1 ;;
esac

cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

if [ "$MODE" = "prestage" ]; then
  # ESTADO (evidencia) escrito ANTES de t0; sobrevive al reinicio.
  {
    echo "ata=ATA038_rev"
    echo "host=$(hostname)"
    echo "uptime_antes=$(uptime -p 2>/dev/null || true)"
    echo "boot_id_antes=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    echo "prestaging_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "${BASE}/pre_reboot.txt"
  cat "${BASE}/pre_reboot.txt"
  echo "PRESTAGE=OK (estado pre_reboot.txt escrito ANTES de t0)"
  exit 0
fi

# ---- modo attack (ventana): SOLO la atómica de reinicio ----
if [ -z "${SUDO_PW:-}" ]; then
  IFS= read -r SUDO_PW || true
fi
if [ -z "${SUDO_PW:-}" ]; then
  echo "ERROR: falta la contrasena de sudo (variable SUDO_PW o primera linea de stdin)" >&2
  exit 1
fi
[ -f "${BASE}/pre_reboot.txt" ] || { echo "ERROR: falta pre_reboot.txt (¿prestage ANTES de t0?)" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Atómica ART "Restart System via `shutdown`" (guid 6326dbc4): shutdown -r #{timeout}, timeout=+1
echo "--- atómica ART: shutdown -r +1 (guid 6326dbc4-444b-4c04-88f4-27e94d0327cb) ---"
sudo_cmd shutdown -r +1 "TFG ATA038_rev: reinicio programado de la VM victima"
rc=$?
echo "shutdown_rc=${rc}"
echo "REBOOT_PROGRAMADO=si (host=victima-linux, +1 min)"
if [ "$rc" -ne 0 ]; then
  echo "ERROR: no se pudo programar el reinicio" >&2
  exit 1
fi
echo "T1_LOCAL=(lo sella el operador tras la reconexion; la VM se reinicia)"
