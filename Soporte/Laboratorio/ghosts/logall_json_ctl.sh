#!/bin/bash
# logall_json_ctl.sh — controla <logall_json> del manager de Wazuh (L0). NO cambia el ruleset.
# Uso: on | off | status | size | conf
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
CONF=/var/ossec/etc/ossec.conf
BKP=/var/ossec/etc/ossec.conf.tfg-bak
ARCH=/var/ossec/logs/archives/archives.json

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
    sudo -n rm -f "$ARCH"
    sudo -n systemctl restart wazuh-manager
    sleep 30
    echo "manager=$(systemctl is-active wazuh-manager)"
    ;;
  status)
    echo "conf: $(sudo -n grep '<logall_json>' "$CONF")"
    echo "manager=$(systemctl is-active wazuh-manager)"
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
esac
