#!/usr/bin/env bash
# ============================================================================
# ATA035 · T1056.004 Credential API Hooking — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1056.004 Credential API Hooking (tactica Collection / Cred-Access)
# Fuente  : custom (escrito por el TFG; las atomicas de ART son Windows)
# Objetivo: HOOK de la API de libc por LD_PRELOAD sobre un binario DE
#           LABORATORIO (`credfetch`) para CAPTURAR credenciales SIMULADAS
#           (token por entorno + contrasena por fichero). Capa del HIDS que
#           ejercita: ejecucion de proceso (module-load NO genera telemetria).
# Destino : /home/angel/lab-attack/ATA035/{hook.so,credfetch,hook_capture.log}
# Ejecuta : desde /home/angel/lab-attack/ATA035 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - hook.so, credfetch y el log DEBEN quedar bajo $HOME/lab-attack/ATA035/;
#   - LD_PRELOAD SOLO apunta a ESE hook.so (nunca a ficheros del sistema);
#   - SOLO se ejecuta el proceso DE LABORATORIO `credfetch` (nunca procesos
#     del sistema: no se toca PAM, sshd, login ni ninguna cuenta real).
#
# NOTA DE ENTORNO (paso 0, 2026-09-29): la VICTIMA **no tiene compilador**
#   (gcc/cc/make/as/ld ausentes). El payload se COMPILA APARTE (en la maquina
#   con toolchain) y se transporta como `.b64` (texto): aqui se DECODIFICA.
#   Es el "fallback (.so precompilado)" previsto en el plan (R1).
#
# Telemetria esperada (ver README §5):
#   - execve de credfetch -> 80792 (deteccion; S1) anclado por S2.
#   - el HOOK (LD_PRELOAD / carga de modulo) NO genera telemetria propia:
#     punto ciego declarado (el HIDS ve el proceso, no la intercepcion).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `hook_capture.log` contiene el
#   token de entorno y la contrasena del fichero capturados por el hook.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA035"
HOKB64="${BASE}/ATA035_hook.so.b64"
CFB64="${BASE}/ATA035_credfetch.b64"
SO="${BASE}/hook.so"
CF="${BASE}/credfetch"
LOGF="${BASE}/hook_capture.log"
CRED="${BASE}/credencial_simulada.txt"
TOKEN="toy-token-4242"
PASSWORD="clave-simulada-7777"

echo "ATA035 · T1056.004 Credential API Hooking (LD_PRELOAD) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in base64 chmod sha256sum cat grep; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: todo bajo la carpeta del ataque; LD_PRELOAD solo a ESE hook.so.
for p in "$SO" "$CF" "$LOGF" "$CRED"; do
  case "$p" in
    "$HOME/lab-attack/ATA035/"*) : ;;
    *) echo "ERROR: ruta '$p' fuera de lab-attack/ATA035 (abortado por seguridad)" >&2; exit 1 ;;
  esac
done
case "$BASE" in
  "$HOME/lab-attack/ATA035"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA035; ABORTADO" >&2; exit 1 ;;
esac

# 0) MATERIALIZAR el payload PRE-COMPILADO (decodificacion base64).
base64 -d "$HOKB64" > "$SO"
base64 -d "$CFB64" > "$CF"
chmod 700 "$CF"
chmod 600 "$SO"
echo "--- payload ---"
ls -l "$SO" "$CF"
sha256sum "$SO" "$CF"

# 1) Credencial SIMULADA (dato de juguete) que el proceso de laboratorio leera.
cat > "$CRED" <<TXT
${PASSWORD}
TXT

# 2) HOOK + ejecucion del proceso DE LABORATORIO (solo el proceso del ataque).
: > "$LOGF"   # log limpio (truncado con redireccion, sin binario externo)
echo "--- ejecucion con LD_PRELOAD (hook de API) ---"
SERVICE_TOKEN="$TOKEN" LD_PRELOAD="$SO" "$CF" "$CRED"
rc=$?
echo "credfetch_rc=${rc}"

# 3) PRUEBA DEL EFECTO (independiente de la alerta): el hook capturo lo interceptado.
echo "--- hook_capture.log ---"
cat "$LOGF"

cap_token=0
cap_pass=0
grep -q "SERVICE_TOKEN ${TOKEN}" "$LOGF" && cap_token=1
grep -q "fgets ${PASSWORD}" "$LOGF" && cap_pass=1
echo "capturado_token_env=${cap_token}"
echo "capturado_password_file=${cap_pass}"

if [ "$rc" -eq 0 ] && [ "$cap_token" -eq 1 ] && [ "$cap_pass" -eq 1 ]; then
  echo "CRED_API_HOOKING=OK (hook LD_PRELOAD capturo token de entorno y contrasena de fichero)"
else
  echo "CRED_API_HOOKING=FALLO (revisar el hook)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
