#!/usr/bin/env bash
# ============================================================================
# ATA004 · T1489 Service Stop — atomica "Linux - Stop service using systemctl"
# GUID   : 42e3a5bd-1e45-427f-aa08-2a65fa29a820
# Fuente : atomic-red-team (commit 388942adbd9641f4dfdcf079d7efe9a75ec0ac43)
# Path   : atomics/T1489/T1489.yaml
# ----------------------------------------------------------------------------
# Cuerpo de la atomica: `sudo systemctl stop <service_name>` (default: cron),
# elevation_required: true.
#
# ⚠️ ELEVACION (declarada en el plan §2.3): este script se lanza YA ELEVADO por el
#    ejecutor -> `echo '<contrasena del laboratorio>' | sudo -S bash ATA004_ataque.sh`
#    (la contrasena SOLO en memoria, por stdin; NUNCA en el artefacto). Dentro del
#    script `systemctl stop` corre como root, SIN `sudo` anidado -> una sola elevacion.
#    El script aborta si no corre como root (comprobacion `id -u`).
#
# NUNCA se para `wazuh-agent` (regla del plan §12.3).
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). El t1 OFICIAL se sella tras
#         el scan FIM forzado (runbook §2 paso 7); estos quedan en ejecucion.out.
# ============================================================================
set -u

SERVICE="${SERVICE_NAME:-cron}"

echo "ATA004 · T1489 Service Stop (systemctl) — GUID 42e3a5bd-1e45-427f-aa08-2a65fa29a820"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: debe lanzarse YA ELEVADO (id -u != 0). Usa: echo '<contrasena del laboratorio>' | sudo -S bash $0" >&2
  exit 1
fi
if [ "$SERVICE" = "wazuh-agent" ]; then
  echo "ERROR: prohibido parar wazuh-agent (regla del plan §12.3)" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemctl no disponible" >&2
  exit 1
fi

echo "--- estado del servicio ANTES ---"
systemctl is-active "$SERVICE" || true

# Cuerpo de la atomica (parametrizado):
systemctl stop "$SERVICE"

echo "--- estado del servicio DESPUES ---"
systemctl is-active "$SERVICE" || true
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
