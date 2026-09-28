#!/usr/bin/env bash
# ============================================================================
# ATA003 · T1490 Inhibit System Recovery — ataque MANUAL (TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1490 Inhibit System Recovery (tactica Impact)
# Fuente  : custom (Atomic Red Team SOLO tiene pruebas Windows -> solo_windows)
# Objetivo: BORRAR unas "copias de seguridad" MOCK del laboratorio para simular
#           la inhibicion de la recuperacion (ransomware que destruye las copias
#           antes de cifrar).
# Destino : /home/angel/lab-legit/copias_seguridad/  (dir VIGILADO -> watch)
# Ejecuta : desde /home/angel/lab-attack/ATA003 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# QUE **NO** SE TOCA (regla dura del encargo): wazuh-agent, cron, chrony,
#   systemd real, /etc real, /var/backups real ni NINGUN servicio/timer del
#   sistema. Solo un directorio mock creado por el propio ataque bajo lab-legit.
#
# DECISION DE ALCANCE (ver README §4): la variante "deshabilitar un temporizador
#   lab-owned" (systemctl) se OMITE a proposito: exigiria root o una sesion
#   systemd de usuario y arriesga el sistema (prohibido por el encargo); ademas
#   `systemctl` ya queda cubierto por ATA004 (T1489). El vector de T1490 aqui es
#   el BORRADO de copias/puntos de recuperacion.
#
# Telemetria esperada (ver README §7):
#   - execve de rm -> 80792 (deteccion; senales T1490-S1/S2)
#   - watch de borrado en lab-legit -> 80781 (AMBIGUA; revision humana)
#
# Prueba de exito (INDEPENDIENTE de la alerta): `test -e` pasa de EXISTE a NO EXISTE.
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA003"
RP="${HOME}/lab-legit/copias_seguridad"

echo "ATA003 · T1490 Inhibit System Recovery (rm -rf de copias mock) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if [ ! -d "$(dirname "$RP")" ]; then
  echo "ERROR: no existe $(dirname "$RP") (¿la victima no revirtio a lab-listo?)" >&2
  exit 1
fi
if ! command -v rm >/dev/null 2>&1; then
  echo "ERROR: rm no disponible" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el objetivo DEBE ser exactamente el mock de lab-legit (aborta si no).
case "$RP" in
  "$HOME/lab-legit/copias_seguridad") : ;;
  *) echo "ERROR: objetivo '$RP' no es el mock esperado (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) Sembrar "copias de seguridad" mock (idempotente) si no existen.
#    mkdir es un execve de setup (cwd=ATA003 -> artefacto del ataque); printf es builtin.
if [ ! -d "$RP" ]; then
  mkdir -p "$RP"
  {
    printf 'TFG-HIDS · copia de seguridad SIMULADA (T1490/ATA003)\n'
    printf 'origen: srv-db-legacy  fecha: 2026-08-31  tipo: full\n'
  } > "$RP/backup_full_2026-08.tar"
  {
    printf 'TFG-HIDS · copia de seguridad SIMULADA (T1490/ATA003)\n'
    printf 'origen: srv-db-legacy  fecha: 2026-09-15  tipo: incremental\n'
  } > "$RP/backup_incremental_2026-09-15.tar"
  {
    printf 'id,cliente,cif,facturacion_eur,alta\n'
    printf '1001,Acme Iberica SL,B12345678,18450,2024-03-11\n'
    printf '1002,Comercial Delta SA,A87654321,9230,2025-01-22\n'
  } > "$RP/export_clientes_2026-08.csv"
  {
    printf 'TFG-HIDS · volcado SIMULADO de base de datos (T1490/ATA003)\n'
  } > "$RP/dump_postgres_2026-09.dump"
fi

echo "--- ANTES ---"
if [ -e "$RP" ]; then echo "existe: $RP"; ls -l "$RP"; else echo "NO existe: $RP"; fi

# 1) INHIBIR LA RECUPERACION: borrar las copias de seguridad mock.
rm -rf "$RP"

echo "--- DESPUES ---"
if [ -e "$RP" ]; then
  echo "BORRADO=FALLO (sigue existiendo)" >&2
else
  echo "BORRADO=OK (las copias de seguridad ya no existen)"
fi
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
