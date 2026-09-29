#!/usr/bin/env bash
# ============================================================================
# ATA038 · T1529 System Shutdown/Reboot — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1529 System Shutdown/Reboot (tactica Impact)
# Fuente  : custom (escrito por el TFG; ART tiene ~10 pruebas Windows/Linux)
# Objetivo: REINICIAR la VM VICTIMA (`victima-linux`) para medir si el HIDS ve
#           el cierre/arranque: por el `execve` del comando de reinicio y por
#           las reglas de estado del AGENTE (`503` agente iniciado, etc.).
# Destino : LA PROPIA VM VICTIMA. JAMAS el manager ni el PC anfitrion.
# Ejecuta : desde /home/angel/lab-attack/ATA038 (cwd del ataque -> ancla H4)
# Elevacion: SI (sudo -S por stdin), SOLO para `shutdown -r`.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - SOLO se reinicia la VM VICTIMA: se EXIGE `hostname == victima-linux` y la
#     IP `192.168.65.129`. Si el host no es la victima -> ABORTA (nunca el
#     manager `192.168.65.128` ni el anfitrion).
#   - El reinicio se PROGRAMA a +1 min (`shutdown -r +1`) para que la ventana
#     quede sellada y no se corte la evidencia a media escritura.
#   - La contrasena de `sudo` NUNCA esta en este fichero (entorno SUDO_PW / stdin).
#
# NOTA (paso 0, 2026-09-29): `shutdown`/`reboot` son enlaces a `/usr/bin/systemctl`
#   -> el `execve` registra `/usr/bin/systemctl` (declarar el binario REAL).
#
# Telemetria esperada (ver README §5):
#   - execve de systemctl (shutdown -r) -> 80792 (deteccion; S1) anclado por S2.
#   - tras el arranque, el agente vuelve: reglas de estado del agente (`503`) -> S3.
#
# Prueba de exito (INDEPENDIENTE de la alerta): el host se reinicia (uptime nuevo)
#   y el agente Wazuh vuelve a estar `active`/`Active` tras el arranque.
# Salida: marcador T0=... (UTC) en stdout; el `t1` lo sella el operador tras la
#   reconexion (la VM se reinicia, no puede sellarlo ella misma).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA038"
VICTIM_HOST="victima-linux"
VICTIM_IP="192.168.65.129"
MANAGER_IP="192.168.65.128"

echo "ATA038 · T1529 System Shutdown/Reboot (reinicio de la VM victima) — custom"
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
for t in hostname ip systemctl sha256sum cat; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
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

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# --- evidencia previa (se conserva tras el reinicio) ---
{
  echo "ata=ATA038"
  echo "host=$(hostname)"
  echo "uptime_antes=$(uptime -p 2>/dev/null || true)"
  echo "boot_id_antes=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
  echo "t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${BASE}/pre_reboot.txt"
cat "${BASE}/pre_reboot.txt"

# --- REINICIO PROGRAMADO (+1 min) de la VM VICTIMA (execve de systemctl) ---
echo "--- programando el reinicio de la VM victima (+1 min) ---"
sudo_cmd shutdown -r +1 "TFG ATA038: reinicio programado de la VM victima"
rc=$?
echo "shutdown_rc=${rc}"
echo "REBOOT_PROGRAMADO=si (host=victima-linux, +1 min)"

if [ "$rc" -ne 0 ]; then
  echo "ERROR: no se pudo programar el reinicio" >&2
  exit 1
fi
echo "T1_LOCAL=(lo sella el operador tras la reconexion; la VM se reinicia)"
