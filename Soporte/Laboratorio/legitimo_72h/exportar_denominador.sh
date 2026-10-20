#!/bin/bash
# ============================================================================
# exportar_denominador.sh — (MANAGER) prepara la copia del denominador `M`.
# Bloque `legitimo-72h` (L1).
#
# ⚠️ ORDEN CRÍTICO: ejecutar ANTES de `logall_json_ctl.sh off` — el apagado de
#    logall_json ejecuta `sudo rm -f archives.json` y BORRA el denominador.
#
# Modos:
#   info   -> informa de la ROTACIÓN de /var/ossec/logs/archives/ (¿un fichero o diarios?)
#   copiar -> copia archives.json* a /tmp/legit_denominador/ (legible por angel) para
#             bajarlo por scp al host. NO apaga logall_json.
#
# Contraseña de sudo por STDIN (nunca en fichero).
# Uso:  echo "<pw>" | ssh ... "bash /tmp/exportar_denominador.sh copiar"
# ============================================================================
set -u
SUDOPW=""; if [ ! -t 0 ]; then read -r SUDOPW || true; fi
if [ -n "$SUDOPW" ]; then printf '%s\n' "$SUDOPW" | sudo -S -p "" -v 2>/dev/null; fi
if ! sudo -n true 2>/dev/null; then echo "SIN SUDO"; exit 3; fi

ARCHDIR=/var/ossec/logs/archives
OUT=/tmp/legit_denominador

case "${1:-info}" in
  info)
    echo "== ${ARCHDIR} =="
    sudo -n ls -la "$ARCHDIR" 2>/dev/null
    n=$(sudo -n sh -c "ls -1 ${ARCHDIR}/archives.json* 2>/dev/null | wc -l")
    echo "ficheros archives.json*: ${n}"
    echo "== hora UTC =="; date -u
    ;;
  copiar)
    sudo -n mkdir -p "$OUT"
    sudo -n sh -c "cp -f ${ARCHDIR}/archives.json ${OUT}/ 2>/dev/null; for f in ${ARCHDIR}/archives.json-* ${ARCHDIR}/archives.json.*; do [ -f \"\$f\" ] && cp -f \"\$f\" ${OUT}/ ; done; true"
    sudo -n chown -R angel:angel "$OUT"
    echo "== copiado (${OUT}) =="
    ls -l "$OUT"
    echo "== sha256 =="
    sha256sum "$OUT"/* 2>/dev/null
    echo "== hora UTC =="; date -u
    ;;
  *)
    echo "uso: exportar_denominador.sh info|copiar"; exit 2;;
esac
echo "== FIN =="
