#!/bin/bash
# ============================================================================
# logall_json_ctl.sh v2 — controla <logall_json> del manager de Wazuh. NO cambia el ruleset.
#
# Bloque `legitimo-fix`: el reinicio del manager pasa a ser ROBUSTO (§6.6, hallazgo H-F):
#   stop -> pkill -9 wazuh_apid (huérfanos) -> reset-failed -> start -> VERIFICACIÓN
#   (`is-active` **y** `agent_control -l`), hasta 3 intentos.
# El resto de la semántica (`on`/`off`, `rm -f archives.json`) NO cambia.
#
# Uso: on | off | status | size | conf
# Contraseña de sudo por STDIN (nunca en fichero).
# ============================================================================
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
CONF=/var/ossec/etc/ossec.conf
BKP=/var/ossec/etc/ossec.conf.tfg-bak
ARCH=/var/ossec/logs/archives/archives.json
AC=/var/ossec/bin/agent_control

reiniciar_manager() {
  local i est
  for i in 1 2 3; do
    sudo -n systemctl stop wazuh-manager 2>/dev/null
    sudo -n pkill -9 -f wazuh_apid 2>/dev/null
    sudo -n systemctl reset-failed wazuh-manager 2>/dev/null
    sudo -n systemctl start wazuh-manager 2>/dev/null
    sleep 15
    est=$(systemctl is-active wazuh-manager 2>/dev/null)
    if [ "$est" = "active" ] && sudo -n "$AC" -l >/dev/null 2>&1; then
      echo "manager=active (intento $i) agent_control=OK"
      return 0
    fi
    echo "reintento $i: manager=$est agent_control=$(sudo -n "$AC" -l 2>&1 | head -1)"
  done
  echo "manager=FALLO tras 3 intentos"
  return 1
}

case "$1" in
  conf)
    sudo -n sed -n '/<global>/,/<\/global>/p' "$CONF"
    ;;
  on|off)
    val=no; [ "$1" = on ] && val=yes
    sudo -n cp -n "$CONF" "$BKP"
    if sudo -n grep -q '<logall_json>' "$CONF"; then
        sudo -n sed -i "s#<logall_json>[^<]*</logall_json>#<logall_json>${val}</logall_json>#" "$CONF"
    else
        sudo -n sed -i "s#<global>#<global>\n    <logall_json>${val}</logall_json>#" "$CONF"
    fi
    echo "valor aplicado: $(sudo -n grep '<logall_json>' "$CONF")"
    # ORDEN: se borra el archivo del día ANTES de reiniciar (semántica heredada de L1)
    sudo -n rm -f "$ARCH"
    reiniciar_manager || exit 4
    ;;
  status)
    echo "conf: $(sudo -n grep '<logall_json>' "$CONF")"
    echo "manager=$(systemctl is-active wazuh-manager)"
    echo "daemons_remoted_analysisd=$(pgrep -c -f 'wazuh-remoted|wazuh-analysisd' 2>/dev/null)"
    ;;
  size)
    if sudo -n test -f "$ARCH"; then
        sudo -n ls -l "$ARCH"
        echo "lineas=$(sudo -n wc -l < "$ARCH" 2>/dev/null)"
    else
        echo "sin archives.json"
    fi
    sudo -n date -u '+%Y-%m-%dT%H:%M:%SZ'
    ;;
  *)
    echo "uso: logall_json_ctl.sh on|off|status|size|conf"; exit 2;;
esac
