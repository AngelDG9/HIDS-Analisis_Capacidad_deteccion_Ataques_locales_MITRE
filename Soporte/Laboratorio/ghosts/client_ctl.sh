#!/bin/bash
# ============================================================================
# client_ctl.sh v3 — control del cliente GHOSTS en victima-linux.
# Bloque `legitimo-fix` (v2) + `legitimo-v3` (v3: cwd realista, mejora 1).
# Sustituye al v1 (que redirigía el stdout SIN TOPE: `ghasts.out` llegó a 4,78 GB
# y llenó el disco el 2026-10-19).
#
# Cambios de la v2:
#   · stdout -> `client.out` en modo APPEND (historial de todos los arranques)
#   · TOPE DURO por construcción: TFG_CLIENT_OUT_MAX_MB (def. 20 MB) con copytruncate
#     a `client.out.1`  => máximo 20 + 20 = 40 MB en disco. `rotate` lo llama el
#     keepalive cada 30 s y también cada `start`.
#   · `start` IDEMPOTENTE (H-A): si ya hay una instancia, NO arranca otra.
#   · `stop` ESCALADO (H-B): TERM -> 5 s -> KILL (poder recuperar un cliente colgado).
#   · `log`: tail de client.out y client.out.1
#
# Cambio de la v3 (plan §5.1 mejora 1 / CA-05):
#   · el cliente arranca con `cwd=$TFG_CWD_BASE` (def. `/home/angel`), NO en el
#     directorio del binario. El ejecutable se lanza por ruta ABSOLUTA y sus rutas
#     de config/instance/log las resuelve `ApplicationDetails.InstalledPath`
#     (directorio del exe). Si E0 demuestra que NLog resolviera `logs/app.log`
#     contra el cwd, se revierte esta línea (plan B: `cd` por acción, ya aplicado
#     en la receta v2).
#
# No contiene secretos.
# Uso:  bash client_ctl.sh start|stop|status|id|log|rotate [DIR]
#   DIR por defecto: /home/angel/ghosts-client
# ============================================================================
set -u

DIR="${2:-/home/angel/ghosts-client}"
CWD="${TFG_CWD_BASE:-/home/angel}"
MAX_MB="${TFG_CLIENT_OUT_MAX_MB:-20}"
OUT="$DIR/client.out"
PATRON='(^|/)ghosts[.]client[.]linux'   # no se autoempareja con el patron literal

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') client_ctl: $*"; }

pids() { pgrep -f "$PATRON" 2>/dev/null | tr '\n' ' '; }

rotar() {
  [ -f "$OUT" ] || return 0
  local bytes mb tope
  bytes=$(stat -c %s "$OUT" 2>/dev/null || echo 0)
  mb=$(( bytes / 1048576 ))
  if [ "$mb" -ge "$MAX_MB" ]; then
    # copytruncate ACOTADO: se conservan los ÚLTIMOS MAX_MB (lo útil para diagnosticar)
    # y se vacía el actual. Tope duro por construcción: MAX_MB + MAX_MB.
    tope=$(( MAX_MB * 1048576 ))
    tail -c "$tope" "$OUT" > "$OUT.1" 2>/dev/null
    : > "$OUT"
    log "rotado client.out (${mb}MB >= ${MAX_MB}MB) -> client.out.1 (ultimos ${MAX_MB}MB)"
  fi
}

case "${1:-}" in
  start)
    if [ ! -d "$DIR" ]; then log "no existe $DIR"; exit 1; fi
    if [ ! -d "$CWD" ]; then log "no existe el cwd $CWD"; exit 1; fi
    rotar
    if pgrep -f "$PATRON" >/dev/null 2>&1; then
      log "ya estaba en marcha (pids=$(pids)); NO se duplica (H-A)"
      exit 0
    fi
    cd "$CWD" || exit 1
    ( nohup "$DIR/ghosts.client.linux" >> "$OUT" 2>&1 & )
    sleep 2
    p=$(pids)
    if [ -n "$p" ]; then log "arrancado pid=$p cwd=$CWD (stdout -> client.out, tope ${MAX_MB}MB x2)"
    else log "NO arranco (revisar client.out)"; exit 2; fi
    ;;
  stop)
    p=$(pids)
    if [ -z "$p" ]; then log "no corria"; exit 0; fi
    log "parando pids=$p (TERM)"
    kill -TERM $p 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      sleep 0.5
      [ -z "$(pids)" ] && break
    done
    if [ -n "$(pids)" ]; then
      log "sigue vivo tras 5s -> KILL (pids=$(pids))"
      kill -KILL $(pids) 2>/dev/null
      sleep 1
    fi
    # Con el navegador DESCARTADO (plan §4.8) no se instala la limpieza de chrome/
    # chromedriver: no hay navegador en la víctima.
    if [ -z "$(pids)" ]; then log "parado"; else log "NO se pudo parar (pids=$(pids))"; exit 3; fi
    ;;
  status)
    p=$(pids)
    if [ -n "$p" ]; then log "vivo pids=$p"; else log "no corre"; fi
    ;;
  rotate)
    rotar
    ;;
  id)
    cat "$DIR/instance/id.json" 2>/dev/null; echo
    ;;
  log)
    tail -n "${3:-25}" "$OUT.1" 2>/dev/null
    echo "--- client.out ---"
    tail -n "${3:-25}" "$OUT" 2>/dev/null
    ;;
  *)
    echo "uso: bash client_ctl.sh start|stop|status|rotate|id|log [DIR] [N]"
    exit 1
    ;;
esac
