#!/usr/bin/env bash
# ============================================================================
# ATA028 · T1056.003 Web Portal Capture — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1056.003 Input Capture: Web Portal Capture (Collection/Cred-Access)
# Fuente  : custom (escrito por el TFG)
# Objetivo: CAPTURAR credenciales por un PORTAL WEB FALSO servido LOCALMENTE:
#           (1) se levanta un portal simulado (listener HTTP en 127.0.0.1) cuyo
#               codigo del atacante REGISTRA el POST, y
#           (2) un "usuario" envia credenciales DE JUGUETE al portal; el POST
#               queda capturado en la carpeta del ataque.
#           Mezcla RED (loopback) + FICHERO (la captura). NO hay portal real.
# Destino : 127.0.0.1:<PORT> (loopback acotado) + captura en la carpeta del ataque.
# Ejecuta : desde /home/angel/lab-attack/ATA028 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️⚠️ GUARDARRAILES DUROS (abortan si no se cumplen):
#   - El portal escucha SOLO en 127.0.0.1 (loopback local); NUNCA en una IP de red.
#   - Puerto en rango alto (1024..65535) y `timeout` en el listener (nunca colgado).
#   - Credenciales DE JUGUETE (`usuario=demo`/`clave=demo-...`), jamas credenciales
#     reales. Todo queda bajo /home/angel/lab-attack/ATA028/.
#
# Telemetria esperada (ver README §5):
#   - execve de `nc` (portal)   -> 80792 (deteccion; T1056.003-S1).
#   - execve de `curl` (cliente)-> 80792 (deteccion; T1056.003-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA028/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el fichero de captura
#   (request.http) CONTIENE el POST con las credenciales de juguete.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA028"
PORT=8081
BIND="127.0.0.1"
CAP="${BASE}/request.http"

echo "ATA028 · T1056.003 Web Portal Capture (portal falso local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in nc curl timeout sleep grep; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# --- GUARDARRAILES DUROS ---
case "$BIND" in
  127.0.0.1) : ;;
  *) echo "ERROR: bind '$BIND' no es loopback; ABORTADO por seguridad" >&2; exit 1 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "ERROR: puerto '$PORT' fuera de rango alto; ABORTADO" >&2; exit 1
fi
case "$CAP" in
  "$HOME/lab-attack/ATA028"*) : ;;
  *) echo "ERROR: captura '$CAP' fuera de lab-attack/ATA028; ABORTADO" >&2; exit 1 ;;
esac

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

ppid=""
killportal() { [ -n "$ppid" ] && kill "$ppid" 2>/dev/null || true; }
trap killportal EXIT

# 1) PORTAL FALSO: listener HTTP local cuyo codigo registra el POST entrante.
#    La pagina de login es parte del portal simulado (datos de juguete).
(
  printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n'
  printf '<!doctype html><html><head><title>Portal corporativo</title></head><body>'
  printf '<h1>Inicio de sesion</h1><form method="post" action="/portal/login">'
  printf 'Usuario <input name="usuario"><br>Clave <input name="clave" type="password">'
  printf '</form></body></html>\r\n'
  sleep 2
) | timeout 10 nc -l "$BIND" "$PORT" > "$CAP" 2>/dev/null &
ppid=$!
sleep 0.7

# 2) El "usuario" entra sus credenciales DE JUGUETE en el portal (POST local).
echo ">>> POST de credenciales de juguete al portal falso"
curl -s -o /dev/null --max-time 4 \
  --data 'usuario=demo&clave=demo-solo-juguete' \
  "http://${BIND}:${PORT}/portal/login" || true
wait "$ppid" 2>/dev/null || true
sleep 1

# 3) PRUEBA DEL EFECTO (independiente de la alerta): las credenciales quedaron capturadas.
echo "--- peticion capturada por el portal (extracto) ---"
grep -a -E '^(POST|Host:)|usuario=' "$CAP" | sed 's/^/  /'
if grep -aq 'usuario=demo' "$CAP" && grep -aq 'clave=demo-solo-juguete' "$CAP"; then
  echo "PORTAL_CAPTURE=OK (el portal registro el POST con las credenciales de juguete)"
  ppid=""
  trap - EXIT
else
  echo "PORTAL_CAPTURE=FALLO (no se capturo el POST)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
