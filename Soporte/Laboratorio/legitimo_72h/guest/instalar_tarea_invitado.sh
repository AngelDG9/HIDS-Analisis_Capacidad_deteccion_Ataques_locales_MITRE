#!/bin/bash
# ============================================================================
# instalar_tarea_invitado.sh — instala la "tarea del invitado" `TFG-Ghosts-Legit`
# (systemd timer + servicio + keepalive) en victima-linux. Bloque `legitimo-72h` (L1).
#
# Se ejecuta EN la víctima, con la contraseña de sudo por STDIN (nunca en fichero).
# Espera en /tmp/ los ficheros: tfg_keepalive.sh, tfg-ghosts-legit.service, tfg-ghosts-legit.timer.
#
# Uso: echo "<pw>" | ssh ... "bash /tmp/instalar_tarea_invitado.sh"
# ============================================================================
set -u
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
if ! sudo -n true 2>/dev/null; then echo "SIN SUDO: no se puede instalar la tarea"; exit 3; fi

DIR=/home/angel/ghosts-client
sudo -n install -m 0755 /tmp/tfg_keepalive.sh            "$DIR/tfg_keepalive.sh"
sudo -n install -m 0644 /tmp/tfg-ghosts-legit.service /etc/systemd/system/tfg-ghosts-legit.service
sudo -n install -m 0644 /tmp/tfg-ghosts-legit.timer   /etc/systemd/system/tfg-ghosts-legit.timer
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now tfg-ghosts-legit.timer >/dev/null 2>&1

echo "== enabled =="; systemctl is-enabled tfg-ghosts-legit.timer
echo "== timers =="; systemctl list-timers tfg-ghosts-legit.timer --all --no-pager
echo "== unit-files =="; systemctl list-unit-files 'tfg-ghosts-legit*' --no-pager
echo "== fecha UTC de la victima =="; date -u; timedatectl 2>/dev/null | sed -n '1,3p'
echo "== FIN =="
