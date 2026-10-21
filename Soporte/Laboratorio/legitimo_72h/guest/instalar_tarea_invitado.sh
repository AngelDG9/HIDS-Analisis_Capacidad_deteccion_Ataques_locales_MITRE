#!/bin/bash
# ============================================================================
# instalar_tarea_invitado.sh — instala la "tarea del invitado" `TFG-Ghosts-Legit`
# (systemd timer + servicio + keepalive v3) en victima-linux. Bloque `legitimo-fix`.
#
# Diferencia con L1: la FECHA se PASA al instalar (no está hardcodeada) y el script
# RECHAZA instalar si T0 no es futuro. `Persistent=false` (no se dispara al arrancar).
#
# Uso (en la víctima, con sudo por STDIN):
#   echo "<pw>" | ssh ... "bash /tmp/instalar_tarea_invitado.sh 2026-10-26T00:00:00Z [d1sha d2sha d3sha]"
#
# Espera en /tmp/: tfg_keepalive.sh, tfg-ghosts-legit.service, tfg-ghosts-legit.timer.
# Idempotente: se puede repetir. Sin secretos en fichero.
# ============================================================================
set -u
T0="${1:-}"
D1SHA="${2:-}"; D2SHA="${3:-}"; D3SHA="${4:-}"
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
if ! sudo -n true 2>/dev/null; then echo "SIN SUDO: no se puede instalar la tarea"; exit 3; fi

DIR=/home/angel/ghosts-client

if [ -z "$T0" ]; then echo "USO: instalar_tarea_invitado.sh <T0 ISO UTC> [d1sha d2sha d3sha]"; exit 2; fi
if ! echo "$T0" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
  echo "ERROR: T0 no tiene el formato ISO UTC (YYYY-MM-DDTHH:MM:SSZ): $T0"; exit 2
fi
T0_EPOCH=$(date -u -d "$T0" +%s 2>/dev/null) || { echo "ERROR: fecha inválida $T0"; exit 2; }
AHORA=$(date -u +%s)
if [ "$T0_EPOCH" -le $(( AHORA + 600 )) ]; then
  echo "ERROR: T0 ($T0) NO es futuro (ahora $(date -u +%FT%TZ)); no se instala"; exit 2
fi

# t0-5min en formato systemd, en UTC explícito
CAL=$(date -u -d "@$(( T0_EPOCH - 300 ))" '+%Y-%m-%d %H:%M:%S UTC')
echo "T0=$T0  ->  OnCalendar=$CAL"

# 1) recetas versionadas (idempotente) + verificación de huellas
for k in 1 2 3; do
  f="$DIR/config/timeline.d${k}.json"
  if [ ! -f "$f" ] && [ -f "/tmp/timeline.d${k}.json" ]; then
    sudo -n install -m 0644 "/tmp/timeline.d${k}.json" "$f"
    echo "instalada $f (desde /tmp)"
  fi
  [ -f "$f" ] && echo "receta d${k}: $(sha256sum "$f" | cut -c1-8) presente" || echo "FALTA $f"
done
if [ -n "$D1SHA" ] && [ "$(sha256sum "$DIR/config/timeline.d1.json" 2>/dev/null | awk '{print $1}')" != "$D1SHA" ]; then
  echo "ERROR: d1 no coincide con la huella esperada del repo"; exit 4
fi
if [ -n "$D3SHA" ] && [ "$(sha256sum "$DIR/config/timeline.d3.json" 2>/dev/null | awk '{print $1}')" != "$D3SHA" ]; then
  echo "ERROR: d3 no coincide con la huella esperada del repo"; exit 4
fi

# 2) keepalive + unidades (con la fecha sustituida)
sudo -n install -m 0755 /tmp/tfg_keepalive.sh "$DIR/tfg_keepalive.sh"
sed -e "s#@T0@#$T0#g" /tmp/tfg-ghosts-legit.service | sudo -n tee /etc/systemd/system/tfg-ghosts-legit.service >/dev/null
sed -e "s#@T0CAL@#$CAL#g" /tmp/tfg-ghosts-legit.timer | sudo -n tee /etc/systemd/system/tfg-ghosts-legit.timer >/dev/null
grep -q '@T0' /etc/systemd/system/tfg-ghosts-legit.service && { echo "ERROR: no se sustituyó @T0@"; exit 5; }
grep -q '@T0CAL' /etc/systemd/system/tfg-ghosts-legit.timer && { echo "ERROR: no se sustituyó @T0CAL@"; exit 5; }

sudo -n systemctl daemon-reload
sudo -n systemctl enable --now tfg-ghosts-legit.timer >/dev/null 2>&1

echo "== enabled =="; systemctl is-enabled tfg-ghosts-legit.timer
echo "== timers =="; systemctl list-timers tfg-ghosts-legit.timer --all --no-pager
echo "== unit-files =="; systemctl list-unit-files 'tfg-ghosts-legit*' --no-pager
echo "== ExecStart =="; grep ExecStart /etc/systemd/system/tfg-ghosts-legit.service
echo "== fecha UTC de la victima =="; date -u; timedatectl 2>/dev/null | sed -n '1,3p'
echo "== FIN =="
