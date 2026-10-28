#!/bin/bash
# ============================================================================
# tfg_keepalive.sh v3 — mantiene el cliente GHOSTS HACIENDO (no solo "estando")
# durante la captura de 72 h. Bloque `legitimo-fix`.
#
# Cuerpo de la tarea del invitado (`tfg-ghosts-legit.service`, arrancada por el timer
# a t0-5 min). Corre ~74 h y sale.
#
# Novedades de la v3 (plan §6.3):
#   · HEARTBEAT de verdad: `mtime` de `logs/app.log` (NLog escribe por acción), no `pgrep`.
#   · CALENDARIO (`recetas/bloques.env`): solo se juzga DENTRO de bloque; café/comida y
#     la noche NO se evalúan.
#   · RECUPERACIÓN acotada: 2 por ejecución, 2 confirmaciones separadas ≥5 min,
#     enfriamiento 30 min, nunca con < 1000 MB libres.
#   · ROTACIÓN diaria de la receta (```timeline.d<k>.json``` -> `timeline.json`) a las 07:45Z,
#     con reinicio del cliente (declarado; ≤2 en la ventana).
#   · TOPE del stdout: rota `client.out` a 20 MB (copytruncate) cada 30 s.
#   · RAM post-hoc: lee `/proc/meminfo` con `read` de bash (sin fork) cada 10 min y deja
#     `ram_free_mb=`/`ALARMA_RAM` en `keepalive.log` (§4.10).
#   · `recovery.log`: una línea por acción (rotacion|arranque|recuperacion|alarma_disco|alarma_ram).
#   · **`cwd`** (bloque `legitimo-v3`, CA-05): arranca en `$TFG_CWD_BASE` (def.
#     `/home/angel`), no en `~/ghosts-client`; sus forks heredan ese `cwd`.
#
# Los overrides `TFG_*` SOLO se aceptan con `TFG_TEST_MODE=1` (prueba en seco). En la
# ventana no se exporta esa variable: los valores son los del plan.
#
# Sin secretos. Uso: tfg_keepalive.sh [DUR_H] [T0_ISO]
# ============================================================================
set -u

DIR="${TFG_CLIENT_DIR:-/home/angel/ghosts-client}"
DUR_H="${1:-74}"
T0F="${2:-}"

TEST="${TFG_TEST_MODE:-0}"
STALE_MIN="${TFG_STALE_MIN:-30}"
GRACIA_MIN="${TFG_GRACIA_MIN:-15}"
CONFIRMA_MIN="${TFG_CONFIRMA_MIN:-5}"
MAX_RECUP="${TFG_MAX_RECUP:-2}"
MAX_ARRANQUES="${TFG_MAX_ARRANQUES:-3}"
COOLDOWN_MIN="${TFG_COOLDOWN_MIN:-30}"
MIN_FREE_MB="${TFG_MIN_FREE_MB:-1000}"
CLIENT_OUT_MAX_MB="${TFG_CLIENT_OUT_MAX_MB:-20}"
ROTACION_UTC="${TFG_ROTACION_UTC:-07:45}"
FORZAR_BLOQUE=0
DIA_OVERRIDE=""
if [ "$TEST" = "1" ]; then
  FORZAR_BLOQUE="${TFG_FORZAR_BLOQUE:-0}"
  DIA_OVERRIDE="${TFG_DIA_OVERRIDE:-}"
fi

KA_LOG="$DIR/keepalive.log"
REC_LOG="$DIR/recovery.log"
EST="$DIR/rotacion.estado"
BLOQUES_ENV="$DIR/recetas/bloques.env"
CTL="$DIR/client_ctl.sh"

# v3 (`legitimo-v3`, CA-05): el keepalive NO arranca desde el directorio del binario.
# Todos sus forks (`date`, `curl`, `awk`, `sha256sum`, …) heredan el cwd, y un cwd
# `/home/angel/ghosts-client` en esos `execve` es el mismo artefacto que se corrige en
# el cliente. Las rutas de trabajo son absolutas (`$DIR/...`), así que el `cd` solo
# cambia el `audit_cwd`. Si el `cd` fallara, se cae al directorio del cliente.
CWD="${TFG_CWD_BASE:-/home/angel}"
if ! cd "$CWD" 2>/dev/null; then
  cd "$DIR" 2>/dev/null || { echo "keepalive: no existe $DIR"; exit 1; }
fi
[ -d "$DIR" ] || { echo "keepalive: no existe $DIR"; exit 1; }
ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
klog() { echo "$(ts) keepalive: $*" >> "$KA_LOG"; }
rlog() { echo "$(ts) $*" >> "$REC_LOG"; }

# --- calendario -----------------------------------------------------------
declare -A B_ON B_OFF B_TIPO
if [ -f "$BLOQUES_ENV" ]; then
  while IFS= read -r linea; do
    case "$linea" in \#*|"") continue;; esac
    id="${linea%%=*}"; resto="${linea#*=}"
    rango="${resto%% *}"; tipo="${resto#* }"
    B_ON["$id"]=$(echo "$rango" | cut -d- -f1)
    B_OFF["$id"]=$(echo "$rango" | cut -d- -f2)
    B_TIPO["$id"]="$tipo"
  done < "$BLOQUES_ENV"
fi
hay_calendario=${#B_ON[@]}

hms() { echo $(( 10#${1%%:*} * 3600 + 10#$(echo "$1" | cut -d: -f2) * 60 )); }

# Deja en BLOQUE_ID / BLOQUE_INI el bloque de trabajo en curso (vacío si no hay).
BLOQUE_ID=""; BLOQUE_INI=0
en_bloque() {
  BLOQUE_ID=""; BLOQUE_INI=0
  if [ "$FORZAR_BLOQUE" = "1" ]; then BLOQUE_ID="TEST"; BLOQUE_INI=0; return 0; fi
  [ "$hay_calendario" -gt 0 ] || return 1
  local ahora secs id on off
  ahora=$(date -u '+%H:%M')
  secs=$(hms "$ahora")
  for id in "${!B_ON[@]}"; do
    [ "${B_TIPO[$id]}" = "trabajo" ] || continue
    on=$(hms "${B_ON[$id]}"); off=$(hms "${B_OFF[$id]}")
    if [ "$secs" -ge "$on" ] && [ "$secs" -lt "$off" ]; then
      BLOQUE_ID="$id"; BLOQUE_INI="$on"; return 0
    fi
  done
  return 1
}

# --- señales --------------------------------------------------------------
# HALLAZGO (corrige el plan, S6.3.1): `logs/app.log` NO sirve como heartbeat: el hilo de
# updates escribe "No new configuration found" cada ~20 s aunque el motor de la timeline
# este muerto (el modo de fallo de L1). `clientupdates.log` (TIMELINE) no se crea en este
# cliente. Senal primaria: **la ultima accion REPORTADA** (`lastReportedUtc` de la API de
# GHOSTS, en el host) - es literalmente "ha hecho algo" y la misma que usa la vigilancia.
# Respaldo: mtime de `clientupdates.log` o de `app.log` si la API no responde.
# La consulta a la API se cachea 5 min (1 curl + 1 date cada 5 min => ~290 execve/dia,
# 0,02 % de M) para no convertir el heartbeat en ruido.
EDAD_CACHE_MIN=-1
EDAD_CACHE_TS=0

# Deja el valor en EDAD_CACHE_MIN (se llama SIN subshell para que el cache persista).
actualizar_edad() {
  local ahora ts seg f m
  ahora=$(date -u +%s)
  if [ $(( ahora - EDAD_CACHE_TS )) -lt 300 ] && [ "$EDAD_CACHE_MIN" -ge 0 ]; then
    return
  fi
  ts=$(curl -s --max-time 5 'http://192.168.65.1:5000/api/machines?q=' 2>/dev/null \
        | grep -o '"lastReportedUtc":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -n "$ts" ]; then
    seg=$(date -u -d "${ts%%.*}" +%s 2>/dev/null) || seg=""
    if [ -n "$seg" ]; then
      EDAD_CACHE_MIN=$(( (ahora - seg) / 60 )); EDAD_CACHE_TS=$ahora
      return
    fi
  fi
  f="$DIR/logs/clientupdates.log"
  [ -f "$f" ] || f="$DIR/logs/app.log"
  if [ ! -f "$f" ]; then EDAD_CACHE_MIN=99999; EDAD_CACHE_TS=$ahora; return; fi
  m=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  EDAD_CACHE_MIN=$(( (ahora - m) / 60 )); EDAD_CACHE_TS=$ahora
}
edad_app_min() { echo "$EDAD_CACHE_MIN"; }

free_mb() { df -Pk / 2>/dev/null | awk 'NR==2{printf "%d", $4/1024}'; }

ram_free_mb() {
  local k v u
  while read -r k v u; do
    case "$k" in MemAvailable:) echo $(( v / 1024 )); return;; esac
  done < /proc/meminfo
  echo 0
}

sha8() { sha256sum "$1" 2>/dev/null | cut -c1-8; }

# HALLAZGO: al arrancar, el cliente REESCRIBE `config/timeline.json` (anade Id, CommandArgs,
# DelayBefore, ScheduleType). El CONTENIDO es el mismo, pero el sha256 cambia => comparar
# shas daria una rotacion falsa el dia 1. Se compara la HUELLA DE LOS COMANDOS.
huella_timeline() {
  # v3: la huella debe funcionar con el JSON PRETTY (repo) y con el COMPACTO que
  # reescribe el cliente al arrancar. El patrón viejo (`Command[^:]*:`) se comía
  # parte del comando en cuanto había un `:` (URLs, `%{http_code}`) y daba una
  # huella distinta con el mismo contenido => rotación falsa (hallazgo de T3).
  grep -o '"Command"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null \
    | sed 's/.*"Command"[[:space:]]*:[[:space:]]*"//; s/"$//' | md5sum | cut -d' ' -f1
}

# --- rotación diaria de la receta ----------------------------------------
rotar_diaria() {
  local hoy secs_ahora rot_secs fecha_t0 k objetivo actual estado
  [ -n "$T0F" ] || return 0
  hoy=$(date -u +%F)
  fecha_t0="${T0F%%T*}"
  # antes de t0 no se rota (el día 1 lo coloca prep)
  [ "$hoy" \> "$fecha_t0" ] || [ "$hoy" = "$fecha_t0" ] || return 0
  secs_ahora=$(hms "$(date -u '+%H:%M')")
  rot_secs=$(hms "$ROTACION_UTC")
  [ "$secs_ahora" -ge "$rot_secs" ] || return 0
  estado=$(cat "$EST" 2>/dev/null || echo "")
  [ "$estado" = "$hoy" ] && return 0

  if [ -n "$DIA_OVERRIDE" ]; then
    k="$DIA_OVERRIDE"
  else
    local a b dias
    a=$(date -u -d "$hoy" +%s); b=$(date -u -d "$fecha_t0" +%s)
    dias=$(( (a - b) / 86400 ))
    k=$(( 1 + (dias % 3) ))
  fi
  objetivo="$DIR/config/timeline.d${k}.json"
  if [ ! -f "$objetivo" ]; then
    klog "ROTACION dia=$k FALLO (no existe $objetivo)"; rlog "accion=rotacion dia=$k resultado=fallo motivo=sin_fichero"
    echo "$hoy" > "$EST"; return 1
  fi
  actual=$(huella_timeline "$DIR/config/timeline.json"); objetivo_h=$(huella_timeline "$objetivo")
  if [ -n "$actual" ] && [ "$actual" = "$objetivo_h" ]; then
    klog "ROTACION dia=$k omitida (el contenido ya es el del dia; huella=${actual:0:8})"
    echo "$hoy" > "$EST"; return 0
  fi
  sha_objetivo=$(sha8 "$objetivo")
  cp -f "$objetivo" "$DIR/config/timeline.json"
  bash "$CTL" stop "$DIR" >/dev/null 2>&1
  bash "$CTL" start "$DIR" >/dev/null 2>&1
  local pid; pid=$(pgrep -f "(^|/)ghosts[.]client[.]linux" | tr '\n' ' ')
  klog "ROTACION dia=$k sha=$sha_objetivo pid=$pid"
  rlog "accion=rotacion dia=$k sha_timeline=$sha_objetivo huella=${objetivo_h:0:8} pid_nuevo=$pid resultado=ok"
  echo "$hoy" > "$EST"
  return 0
}

# --- arranque -------------------------------------------------------------
klog "inicio (dur_h=$DUR_H t0=$T0F calendario=$hay_calendario bloques test=$TEST)"
# DUR_H puede ser decimal en la prueba en seco (p. ej. 0.2 h = 12 min)
DUR_S=$(awk -v h="$DUR_H" 'BEGIN{printf "%d", h*3600}')
END=$(( $(date -u +%s) + DUR_S ))
recup=0; arranques=0; stale_desde=0; last_recup=0; last_alarma=0; last_ram=0

while [ "$(date -u +%s)" -lt "$END" ]; do
  # 1) tope del stdout (lo hace client_ctl para no duplicar la lógica)
  bash "$CTL" rotate "$DIR" >/dev/null 2>&1

  # 2) rotación diaria de la receta
  rotar_diaria || true

  libre=$(free_mb)
  en_bloque || true

  # 3) ¿hay proceso?
  if ! pgrep -f "(^|/)ghosts[.]client[.]linux" >/dev/null 2>&1; then
    if [ "$arranques" -lt "$MAX_ARRANQUES" ]; then
      arranques=$(( arranques + 1 ))
      bash "$CTL" start "$DIR" >>"$KA_LOG" 2>&1
      pid=$(pgrep -f "(^|/)ghosts[.]client[.]linux" | tr '\n' ' ')
      klog "ARRANQUE n=$arranques pid=$pid"
      rlog "accion=arranque n=$arranques pid_nuevo=$pid free_mb=$libre"
    else
      klog "ALARMA el cliente no arranca y ya hubo $MAX_ARRANQUES arranques"
    fi
  else
    actualizar_edad; edad="$EDAD_CACHE_MIN"
    # 4) recuperación acotada: vivo pero SIN HACER, dentro de bloque
    if [ -n "$BLOQUE_ID" ] && [ "$edad" -gt "$STALE_MIN" ]; then
      ahora=$(date -u +%s)
      inicio_bloque_ok=1
      if [ "$FORZAR_BLOQUE" = "1" ]; then
        inicio_bloque_ok=1
      else
        # minutos desde el inicio del bloque
        mins_bloque=$(( ( $(hms "$(date -u '+%H:%M')") - BLOQUE_INI ) / 60 ))
        [ "$mins_bloque" -ge "$GRACIA_MIN" ] || inicio_bloque_ok=0
      fi
      if [ "$inicio_bloque_ok" = "1" ] && [ "$libre" -ge "$MIN_FREE_MB" ] \
         && [ "$recup" -lt "$MAX_RECUP" ] \
         && [ $(( ahora - last_recup )) -ge $(( COOLDOWN_MIN * 60 )) ]; then
        if [ "$stale_desde" -eq 0 ]; then
          stale_desde=$ahora
          klog "AVISO bloque=$BLOQUE_ID edad_min=$edad (primera lectura stale; se confirma en ${CONFIRMA_MIN} min)"
        elif [ $(( ahora - stale_desde )) -ge $(( CONFIRMA_MIN * 60 )) ]; then
          pid_viejo=$(pgrep -f "(^|/)ghosts[.]client[.]linux" | tr '\n' ' ')
          bash "$CTL" stop "$DIR" >>"$KA_LOG" 2>&1
          recup=$(( recup + 1 ))
          bash "$CTL" start "$DIR" >>"$KA_LOG" 2>&1
          pid_nuevo=$(pgrep -f "(^|/)ghosts[.]client[.]linux" | tr '\n' ' ')
          last_recup=$ahora; stale_desde=0
          # Tras reiniciar, el heartbeat cacheado es del proceso VIEJO: se invalida para
          # releerlo en el siguiente ciclo. Sin esto, el keepalive puede contar una
          # segunda recuperacion falsa (visto en DT5a ronda 2).
          EDAD_CACHE_TS=0
          klog "RECUPERACION n=$recup motivo=heartbeat edad_min=$edad pid_viejo=$pid_viejo pid_nuevo=$pid_nuevo"
          rlog "accion=recuperacion motivo=heartbeat edad_min=$edad dia=${BLOQUE_ID} pid_viejo=$pid_viejo pid_nuevo=$pid_nuevo recuperaciones=$recup free_mb=$libre sha_timeline=$(sha8 "$DIR/config/timeline.json")"
        fi
      fi
    else
      [ "$stale_desde" -ne 0 ] && klog "heartbeat recuperado (edad_min=$edad) en bloque=$BLOQUE_ID"
      stale_desde=0
    fi

    # 5) disco bajo: NUNCA reinicia por esto; solo alarma (cada 10 min como mucho)
    if [ "$libre" -lt "$MIN_FREE_MB" ]; then
      ahora=$(date -u +%s)
      if [ $(( ahora - last_alarma )) -ge 600 ]; then
        last_alarma=$ahora
        klog "ALARMA_DISCO free_mb=$libre (no se reinicia)"
        rlog "accion=alarma_disco free_mb=$libre recuperaciones=$recup"
      fi
    fi
  fi

  # 6) RAM post-hoc (cada 10 min; lectura sin fork)
  ahora=$(date -u +%s)
  if [ $(( ahora - last_ram )) -ge 600 ]; then
    last_ram=$ahora
    r=$(ram_free_mb)
    klog "ram_free_mb=$r swap_mb=$(( $(awk '/^SwapTotal:/{print $2}' /proc/meminfo) / 1024 )) bloque=${BLOQUE_ID:-fuera} edad_app_min=$EDAD_CACHE_MIN free_mb=$libre"
    if [ "$r" -lt 256 ]; then
      klog "ALARMA_RAM ram_free_mb=$r"
      rlog "accion=alarma_ram ram_free_mb=$r"
    fi
  fi

  sleep 30
done

klog "fin (recuperaciones=$recup arranques=$arranques)"
exit 0
