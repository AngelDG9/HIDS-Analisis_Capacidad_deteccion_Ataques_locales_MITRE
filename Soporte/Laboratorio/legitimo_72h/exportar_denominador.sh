#!/bin/bash
# ============================================================================
# exportar_denominador.sh v2 — (MANAGER) prepara la copia del denominador `M`.
# Bloque `legitimo-fix`.
#
# ⚠️ ORDEN CRÍTICO: ejecutar ANTES de `logall_json_ctl.sh off` — el apagado de
#    logall_json ejecuta `sudo rm -f archives.json` y BORRA el denominador.
#
# Modos:
#   info                     -> informa de la ROTACIÓN de /var/ossec/logs/archives/
#   copiar                   -> (v1) copia archives.json* a /tmp/legit_denominador/
#   copiar-ventana <t0> <t1> -> (v2) COPIA LA VENTANA COMPLETA:
#        · los `.gz` diarios de los días D..D+2 (y sus `.sum`)
#        · el plano `ossec-archive-<DD>.json` de esos días, si existe
#        · `archives.json` (vivo; cubre el borde de t1)
#        · `MANIFEST.tsv` con tamaño y sha256 de CADA fichero
#        · DEDUPE por sha256 (H-D: `archives.json` es hardlink del día)
#      Deja los ficheros ÚNICOS en /tmp/legit_denominador/ + MANIFEST.tsv.
#
# Contraseña de sudo por STDIN (nunca en fichero).
# Uso:  echo "<pw>" | ssh ... "bash /tmp/exportar_denominador.sh copiar-ventana 2026-10-26T00:00:00Z 2026-10-29T00:00:00Z"
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
    echo "== .gz por dia (ultimos) =="
    sudo -n ls -la --time-style=+%Y-%m-%dT%H:%MZ "$ARCHDIR"/*/*/ossec-archive-*.json.gz 2>/dev/null | tail -5
    echo "ficheros archives.json*: $(sudo -n sh -c "ls -1 ${ARCHDIR}/archives.json* 2>/dev/null | wc -l")"
    echo "== hora UTC =="; date -u
    ;;

  copiar)
    sudo -n mkdir -p "$OUT"
    sudo -n sh -c "cp -f ${ARCHDIR}/archives.json ${OUT}/ 2>/dev/null; for f in ${ARCHDIR}/archives.json-* ${ARCHDIR}/archives.json.*; do [ -f \"\$f\" ] && cp -f \"\$f\" ${OUT}/ ; done; true"
    sudo -n chown -R angel:angel "$OUT"
    echo "== copiado (${OUT}) =="; ls -l "$OUT"
    echo "== sha256 =="; sha256sum "$OUT"/* 2>/dev/null
    echo "== hora UTC =="; date -u
    ;;

  copiar-ventana)
    T0="${2:?falta t0 (YYYY-MM-DDTHH:MM:SSZ)}"
    T1="${3:?falta t1 (YYYY-MM-DDTHH:MM:SSZ)}"
    sudo -n rm -rf "$OUT"; sudo -n mkdir -p "$OUT"
    TMP=/tmp/tfg_den_copia.$$
    sudo -n mkdir -p "$TMP"

    # días D, D+1, D+2 (3 días de calendario exactos)
    d0=$(date -u -d "$T0" +%Y-%m-%d)
    for k in 0 1 2; do
      dia=$(date -u -d "$d0 +$k day" +%Y-%m-%d)
      anio=$(date -u -d "$dia" +%Y); mes=$(date -u -d "$dia" +%b); dd=$(date -u -d "$dia" +%d)
      gz="$ARCHDIR/$anio/$mes/ossec-archive-$dd.json.gz"
      plano="$ARCHDIR/$anio/$mes/ossec-archive-$dd.json"
      if sudo -n test -f "$gz"; then
        sudo -n cp -f "$gz" "$TMP/" && sudo -n cp -f "$gz.sum" "$TMP/" 2>/dev/null
        echo "copiado .gz de $dia"
      else
        echo "AVISO: no existe el .gz de $dia ($gz)"
      fi
      if sudo -n test -f "$plano"; then
        sudo -n cp -f "$plano" "$TMP/"
        echo "copiado plano de $dia"
      fi
    done
    # vivo (día D+3): solo puede aportar eventos con timestamp exactamente t1
    if sudo -n test -f "$ARCHDIR/archives.json"; then
      sudo -n cp -f "$ARCHDIR/archives.json" "$TMP/archives.json"
      echo "copiado archives.json (vivo)"
    else
      echo "AVISO: no hay archives.json (¿logall_json apagado antes de copiar?)"
    fi

    # manifiesto + dedupe por sha256
    sudo -n chown -R angel:angel "$TMP"
    : > "$OUT/MANIFEST.tsv"
    echo -e "fichero\tbytes\tsha256\torigen" >> "$OUT/MANIFEST.tsv"
    declare -A vistos
    for f in "$TMP"/*; do
      [ -f "$f" ] || continue
      b=$(stat -c %s "$f"); h=$(sha256sum "$f" | awk '{print $1}')
      if [ -n "${vistos[$h]:-}" ]; then
        echo -e "$(basename "$f")\t$b\t$h\tDUPLICADO de ${vistos[$h]} (descartado)" >> "$OUT/MANIFEST.tsv"
        continue
      fi
      vistos[$h]="$(basename "$f")"
      cp -f "$f" "$OUT/"
      echo -e "$(basename "$f")\t$b\t$h\tunico" >> "$OUT/MANIFEST.tsv"
    done
    chmod 0644 "$OUT"/* 2>/dev/null
    sudo -n rm -rf "$TMP"
    echo "== ficheros unicos (${OUT}) =="; ls -l "$OUT"
    echo "== MANIFEST =="; cat "$OUT/MANIFEST.tsv"
    echo "== rango pedido =="; echo "t0=$T0 t1=$T1"
    echo "== hora UTC =="; date -u
    ;;

  *)
    echo "uso: exportar_denominador.sh info|copiar|copiar-ventana <t0> <t1>"; exit 2;;
esac
echo "== FIN =="
