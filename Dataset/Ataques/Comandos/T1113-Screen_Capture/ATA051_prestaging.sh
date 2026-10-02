#!/usr/bin/env bash
# ============================================================================
# ATA051 · T1113 — PRE-STAGING (antes de t0, fuera de la ventana)
# ----------------------------------------------------------------------------
# 1) Instala OFFLINE los paquetes GUI pre-steados (Xvfb + x11-apps; URL+sha256).
# 2) Arranca el display virtual `Xvfb :99` y una app visual (`xeyes`) para que la
#    pantalla tenga contenido. Su `execve` ocurre ANTES de t0 (fuera de la ventana).
# Elevacion: SI (sudo) SOLO para `dpkg -i`. Sin NAT.
# Uso: bash ATA051_prestaging.sh [directorio_de_debs]  (password de sudo por stdin)
# ============================================================================
set -u
DEBS="${1:-$HOME/lab-legit/tandaB_debs}"
IFS= read -r SUDO_PW || true
sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

if [ ! -d "$DEBS" ]; then echo "ERROR: no existe $DEBS" >&2; exit 1; fi
sudo_cmd dpkg -i "$DEBS"/*.deb > /tmp/dpkg_${0##*/}.log 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  # dpkg -i puede dejar dependencias sin configurar por el orden de un glob;
  # se completa la configuracion con los MISMOS .deb pre-steados (offline).
  sudo_cmd dpkg --configure -a >> /tmp/dpkg_${0##*/}.log 2>&1
  rc=$?
fi
echo "dpkg_rc=$rc"
if [ "$rc" -ne 0 ]; then echo "ERROR: dpkg fallo"; tail -20 /tmp/dpkg_ATA051.log; exit 1; fi
for b in Xvfb xwd xwud; do command -v "$b" >/dev/null 2>&1 || { echo "ERROR: falta $b" >&2; exit 1; }; done

pkill -f "Xvfb :99" 2>/dev/null || true
Xvfb :99 -screen 0 1280x800x24 -nolisten tcp > /tmp/xvfb_ATA051.log 2>&1 &
echo $! > /tmp/xvfb_ATA051.pid
sleep 3
DISPLAY=:99 xeyes -geometry 400x300+100+100 > /dev/null 2>&1 &
echo $! > /tmp/xeyes_ATA051.pid
sleep 1
echo "PRE_STAGING=OK (Xvfb :99 pid=$(cat /tmp/xvfb_ATA051.pid))"
