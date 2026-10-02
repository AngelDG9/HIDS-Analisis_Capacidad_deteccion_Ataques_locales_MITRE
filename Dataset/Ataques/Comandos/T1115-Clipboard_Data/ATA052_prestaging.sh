#!/usr/bin/env bash
# ============================================================================
# ATA052 · T1115 — PRE-STAGING (antes de t0, fuera de la ventana)
# ----------------------------------------------------------------------------
# 1) Instala OFFLINE los paquetes GUI pre-steados (Xvfb + xclip; URL+sha256).
# 2) Arranca el display virtual `Xvfb :99`.
# 3) Siembra el historial simulado que hara de fuente del portapapeles.
# Elevacion: SI (sudo) SOLO para `dpkg -i`. Sin NAT.
# Uso: bash ATA052_prestaging.sh [directorio_de_debs]  (password de sudo por stdin)
# ============================================================================
set -u
DEBS="${1:-$HOME/lab-legit/tandaB_debs}"
IFS= read -r SUDO_PW || true
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

BASE="${HOME}/lab-attack/ATA052"
if [ ! -d "$DEBS" ]; then echo "ERROR: no existe $DEBS" >&2; exit 1; fi
sudo_cmd dpkg -i "$DEBS"/*.deb > /tmp/dpkg_${0##*/}.log 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  sudo_cmd dpkg --configure -a >> /tmp/dpkg_${0##*/}.log 2>&1
  rc=$?
fi
echo "dpkg_rc=$rc"
if [ "$rc" -ne 0 ]; then echo "ERROR: dpkg fallo"; tail -20 /tmp/dpkg_ATA052.log; exit 1; fi
for b in Xvfb xclip; do command -v "$b" >/dev/null 2>&1 || { echo "ERROR: falta $b" >&2; exit 1; }; done

pkill -f "Xvfb :99" 2>/dev/null || true
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp > /tmp/xvfb_ATA052.log 2>&1 &
echo $! > /tmp/xvfb_ATA052.pid
sleep 3

mkdir -p "$BASE"
{
  printf 'usuario=angel\n'
  printf 'password=Lab2026_NoReal\n'
  printf 'token=TFG-DEMO-NO-REAL-0002\n'
  printf 'historial simulado para la prueba de portapapeles (xclip).\n'
} > "$BASE/historial_simulado.txt"
echo "PRE_STAGING=OK (Xvfb :99 pid=$(cat /tmp/xvfb_ATA052.pid))"
