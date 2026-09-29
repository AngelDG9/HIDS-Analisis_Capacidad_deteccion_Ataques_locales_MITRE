#!/usr/bin/env bash
# ============================================================================
# ATA018 · T1056.001 Keylogging — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1056.001 Input Capture: Keylogging (Collection / Credential Access)
# Fuente  : custom (adaptacion CONTENIDA del enfoque de ART "Logging bash history
#           to syslog"; aqui NO se modifica /etc ni PAM ni auditd reales)
# Objetivo: capturar la ENTRADA de una sesion de terminal (comandos + una credencial
#           SIMULADA de juguete) mediante un wrapper que registra todo lo tecleado a
#           un fichero, y persistir el keylog en syslog con `logger`.
# Destino : captura en /home/angel/lab-attack/ATA018/ (NO vigilado -> sin FIM/watch)
#           syslog via `logger` (journald -> regla de fabrica 40700, level 0)
# Elevacion: NO (usuario angel). No se toca pam_tty_audit, auditd real ni /etc.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la captura DEBE quedar bajo $HOME/lab-attack/ATA018/;
#   - la "credencial" es SIMBOLICA de juguete (NUNCA una contrasena real);
#   - no se escribe fuera de lab-attack (salvo la linea de syslog via logger).
#
# Telemetria esperada (ver README §7):
#   - execve de tee/logger -> 80792 (deteccion; senales T1056.001-S1/S2) ancladas por S3.
#   - la escritura de la captura NO genera watch/FIM (lab-attack no esta vigilado).
#   - la persistencia en syslog cae en 40700 (level 0) -> NO alerta (punto conocido).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el fichero de captura contiene los
#   comandos tecleados y la credencial SIMULADA -> la entrada quedo registrada.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA018"
LOG="${BASE}/keylog_capture.log"
FAKE_USER="angel"
FAKE_PASS="ClaveDemo-Fake123"   # credencial SIMBOLICA de juguete (NO es real)

echo "ATA018 · T1056.001 Keylogging (wrapper tee + persistencia logger) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in tee logger grep wc bash; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: la captura debe quedar bajo la carpeta del ataque
case "$LOG" in
  "$HOME/lab-attack/ATA018"*) : ;;
  *) echo "ERROR: destino '$LOG' no esta bajo lab-attack/ATA018 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 1) WRAPPER KEYLOGGER: registra TODO lo que entra por stdin a un fichero y lo pasa
#    al shell (execve de tee). Simula la captura de una sesion de terminal de la victima.
rm -f "$LOG"
tee "$LOG" <<INPUT | bash
echo "== sesion de terminal capturada (victima: angel) =="
id
whoami
echo "usuario: ${FAKE_USER}"
echo "clave: ${FAKE_PASS}"
hostname
INPUT

# 2) PERSISTENCIA en syslog/journald (execve de logger). Regla de fabrica 40700 (level 0).
logger -t tfg-lab-keylog "T1056.001: keylog capturado (${FAKE_USER}:${FAKE_PASS}) [credencial de juguete]"

# 3) PRUEBA DE EXITO (la entrada quedo registrada; incluye la credencial simulada).
capt=$(wc -l < "$LOG")
echo "--- estado final ---"
ls -l "$LOG"
echo "lineas_capturadas=$capt"
echo "--- contenido de la captura ---"
cat "$LOG"
if [ "$capt" -ge 5 ] && grep -q "$FAKE_PASS" "$LOG" && grep -qi 'whoami' "$LOG"; then
  echo "KEYLOG=OK (entrada de la sesion capturada en fichero; credencial simulada registrada)"
else
  echo "KEYLOG=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
