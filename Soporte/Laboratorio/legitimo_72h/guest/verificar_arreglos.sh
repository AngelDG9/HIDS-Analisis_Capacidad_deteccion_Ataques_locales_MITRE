#!/bin/bash
# ============================================================================
# verificar_arreglos.sh — comprueba DE VERDAD los arreglos del bloque `legitimo-fix`
# en el invitado (`victima-linux`). Lo usan `prep` (guardarraíl G-3), `arm` (checklist)
# y la prueba en seco (DT1/DT12).
#
# Imprime `clave=valor` y termina con `RESULT=PASS|FAIL`. Sale con código 40 si FAIL.
#
# Uso:  bash verificar_arreglos.sh [nlog_sha] [d1_sha] [d2_sha] [d3_sha] [keepalive_sha]
#   Los 5 argumentos son las huellas ESPERADAS del repo (las pasa el host). Sin argumentos
#   solo se comprueban los invariantes locales (útil a mano, no para el guardarraíl).
#
# Sin secretos. Solo lectura: no cambia nada.
# ============================================================================
set -u
DIR="${TFG_CLIENT_DIR:-/home/angel/ghosts-client}"
EXP_NLOG="${1:-}"; EXP_D1="${2:-}"; EXP_D2="${3:-}"; EXP_D3="${4:-}"; EXP_KA="${5:-}"
FAIL=0
say() { echo "$1"; }
bad() { echo "$1"; FAIL=1; }

sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# --- 1) nlog.config: consola a Warn y app.log a 21 MB ---------------------
NLOG="$DIR/nlog.config"
nlog_console=$(grep -o 'minlevel="[A-Za-z]*"[[:space:]]*writeTo="console"' "$NLOG" 2>/dev/null | grep -o 'minlevel="[A-Za-z]*"' | head -1 | cut -d'"' -f2)
nlog_sha=$(sha "$NLOG")
nlog_archive=$(grep -o 'name="logfile".*maxArchiveFiles="[0-9]*"' "$NLOG" 2>/dev/null | grep -o 'maxArchiveFiles="[0-9]*"' | head -1 | cut -d'"' -f2)
say "nlog_console=${nlog_console:-none}"
say "nlog_sha=${nlog_sha:-none}"
say "nlog_applog_archive=${nlog_archive:-none}"
[ "$nlog_console" = "Warn" ] || bad "nlog_console=FALLO (se espera Warn)"
[ "$nlog_archive" = "20" ] || bad "nlog_applog_archive=FALLO (se espera 20)"
if [ -n "$EXP_NLOG" ]; then
  [ "$nlog_sha" = "$EXP_NLOG" ] || bad "nlog_sha=FALLO (no coincide con el repo)"
fi

# --- 2) client_ctl.sh v2: tope de stdout ----------------------------------
CTL="$DIR/client_ctl.sh"
cap=$(grep -o 'TFG_CLIENT_OUT_MAX_MB:-[0-9]*' "$CTL" 2>/dev/null | head -1 | sed 's/.*:-//')
say "client_ctl_cap=${cap:-none}"
[ "${cap:-0}" = "20" ] || bad "client_ctl_cap=FALLO (se espera 20)"
grep -q 'client.out.1' "$CTL" 2>/dev/null || bad "client_ctl_rotacion=FALLO (sin copytruncate)"
grep -q 'KILL' "$CTL" 2>/dev/null || bad "client_ctl_stop_escalado=FALLO (sin KILL)"

# --- 3) keepalive v3: heartbeat + bloques + rotacion + RAM ----------------
KA="$DIR/tfg_keepalive.sh"
if [ -f "$KA" ]; then
  ka=1
  grep -q 'clientupdates.log' "$KA" || ka=0                       # heartbeat
  grep -q 'bloques.env' "$KA" || ka=0                   # calendario
  grep -q 'rotacion' "$KA" || ka=0                      # rotación diaria
  grep -q 'ram_free_mb' "$KA" || ka=0                   # RAM post-hoc
  grep -q 'TFG_CONFIRMA_MIN' "$KA" || ka=0              # doble confirmación
  say "keepalive_v3=$ka"
  [ "$ka" = "1" ] || bad "keepalive_v3=FALLO"
  if [ -n "$EXP_KA" ]; then
    [ "$(sha "$KA")" = "$EXP_KA" ] || bad "keepalive_sha=FALLO (no coincide con el repo)"
  fi
else
  say "keepalive_v3=0"
  bad "keepalive_v3=FALLO (no existe $KA)"
fi

# --- 4) recetas + timeline activa ----------------------------------------
d1=$(sha "$DIR/config/timeline.d1.json"); d2=$(sha "$DIR/config/timeline.d2.json"); d3=$(sha "$DIR/config/timeline.d3.json")
say "recetas=$(echo "${d1:0:8},${d2:0:8},${d3:0:8}")"
say "recetas_sha=${d1:-none},${d2:-none},${d3:-none}"
for par in "1:$d1:$EXP_D1" "2:$d2:$EXP_D2" "3:$d3:$EXP_D3"; do
  num=${par%%:*}; resto=${par#*:}; hay=${resto%%:*}; exp=${resto#*:}
  [ -n "$hay" ] || bad "receta_d${num}=FALLO (falta config/timeline.d${num}.json)"
  if [ -n "$exp" ] && [ "$hay" != "$exp" ]; then bad "receta_d${num}=FALLO (sha distinto del repo)"; fi
done
act=$(sha "$DIR/config/timeline.json")
say "timeline_activa=${act:0:8}"
# El cliente REESCRIBE el fichero al arrancar (mismo contenido, sha distinto): ademas del
# sha se compara la HUELLA DE COMANDOS con d1.
huella() { grep -o 'Command[^:]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null | sed 's/.*:[[:space:]]*"//' | md5sum | cut -d' ' -f1; }
h_act=$(huella "$DIR/config/timeline.json"); h_d1=$(huella "$DIR/config/timeline.d1.json")
say "timeline_huella=${h_act:0:8}"
if [ -n "$h_d1" ] && [ "$h_act" != "$h_d1" ]; then bad "timeline_activa=FALLO (el contenido no es d1)"; fi

# --- 5) sesión web browser-like (en d1) ---------------------------------
WEB=0
if [ -f "$DIR/config/timeline.d1.json" ]; then
  ua=$(grep -c 'TFG-Legit/1.0' "$DIR/config/timeline.d1.json" 2>/dev/null)
  ck=$(grep -c 'cookies.txt' "$DIR/config/timeline.d1.json" 2>/dev/null)
  rf=$(grep -c '\-e http://' "$DIR/config/timeline.d1.json" 2>/dev/null)
  pdf=$(grep -c 'manual_empleado.pdf' "$DIR/config/timeline.d1.json" 2>/dev/null)
  br=$(grep -c '"HandlerType": "Browser' "$DIR/config/timeline.d1.json" 2>/dev/null)
  if [ "$ua" -ge 6 ] && [ "$ck" -ge 3 ] && [ "$rf" -ge 1 ] && [ "$pdf" -ge 1 ] && [ "$br" -eq 0 ]; then WEB=1; fi
fi
say "web_session=$WEB"
[ "$WEB" = "1" ] || bad "web_session=FALLO (UA fija / cookies / referer / 0 Browser*)"

# --- 6) receptor de navegador (decisión §4.8: none) ----------------------
RECEP="none"
if [ -x "$HOME/browser/chrome-linux64/chrome" ] || command -v google-chrome >/dev/null 2>&1 \
   || command -v chromium >/dev/null 2>&1 || command -v chromedriver >/dev/null 2>&1; then
  RECEP="chrome"
fi
say "receptor_navegador=$RECEP"
[ "$RECEP" = "none" ] || bad "receptor_navegador=FALLO (hay navegador instalado)"

# --- 7) RAM y swap (lectura sin fork no hace falta aquí: es una comprobación) --
ram_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)
ram_free_mb=$(( ${ram_avail_kb:-0} / 1024 ))
swap_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo 2>/dev/null)
swap_mb=$(( ${swap_kb:-0} / 1024 ))
say "ram_free_mb=${ram_free_mb}"
say "swap_mb=${swap_mb}"
[ "$ram_free_mb" -ge 1500 ] || bad "ram_free_mb=FALLO (se esperan >= 1500)"
# DESVIACIÓN DECLARADA: el plan (§4.5/G-12) asume swap=0; la VM tiene swap habilitada
# desde el snapshot `lab-listo-legit`. No se toca el invitado por esto (sería cambiar el
# banco antes de medir): se REPORTA como AVISO y no invalida.
if [ "$swap_mb" -ne 0 ]; then say "swap_estado=AVISO (swap_mb=${swap_mb} != 0; desviación declarada)"
else say "swap_estado=OK"; fi

# --- 8) timer del invitado: el snapshot NO lo lleva -----------------------
tl=$(systemctl list-unit-files 'tfg-ghosts-legit*' --no-pager 2>/dev/null | grep -c 'tfg-ghosts-legit')
if [ "$tl" -eq 0 ]; then timer="not-found"; else timer=$(systemctl is-enabled tfg-ghosts-legit.timer 2>/dev/null || echo present); fi
say "timer=$timer"
[ "$timer" = "not-found" ] || bad "timer=FALLO (el snapshot no debe llevar el timer)"

# --- 9) disco e inodos ---------------------------------------------------
df_free_mb=$(df -Pk / | awk 'NR==2{printf "%d", $4/1024}')
df_free_mb_pct=$(df -P / | awk 'NR==2{gsub("%","",$5); print 100-$5}')
df_inodes_libres_pct=$(df -Pi / | awk 'NR==2{gsub("%","",$5); print 100-$5}')
say "df_free_mb=${df_free_mb}"
say "df_libre_pct=${df_free_mb_pct}"
say "df_inodes_libres_pct=${df_inodes_libres_pct}"
[ "$df_free_mb" -ge 4096 ] || say "df_estado=AVISO (menos de 4 GB; G-2 lo comprueba en prep)"

# --- resultado -----------------------------------------------------------
if [ "$FAIL" -eq 0 ]; then echo "RESULT=PASS"; exit 0; else echo "RESULT=FAIL"; exit 40; fi
