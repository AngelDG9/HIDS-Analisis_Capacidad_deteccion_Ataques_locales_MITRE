#!/bin/bash
# limpiar_cliente.sh — para el cliente GHOSTS y deja la victima "sin datos de medida"
# (conserva binarios + config + alias /etc/hosts) para el snapshot lab-listo-legit.
DIR=/home/angel/ghosts-client
pkill -f ghosts.client.linux && sleep 2
rm -rf "$DIR/logs"/* "$DIR/instance"/* "$DIR/ghasts.out"
mkdir -p "$DIR/logs" "$DIR/instance"
rm -rf /home/angel/Documentos/informes
rm -f /home/angel/Descargas/*
rm -f /tmp/client_ctl.sh /tmp/diag_wazuh.sh /tmp/verificar_internet_local.sh /tmp/x.pdf /tmp/x.zip
echo "cliente parado y limpiado"
pgrep -f ghosts.client.linux >/dev/null && echo "AVISO: sigue vivo" || echo "sin proceso cliente"
echo "-- config (debe seguir) --"
ls -1 "$DIR/config/application.json" "$DIR/config/timeline.json"
cat "$DIR/config/timeline.json"
echo "-- dirs --"
ls -la /home/angel/Documentos /home/angel/Descargas
echo "-- /etc/hosts --"; grep -E "intranet|nube" /etc/hosts
