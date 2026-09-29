#!/usr/bin/env bash
# ============================================================================
# ATA032 · T1565.001 Stored Data Manipulation — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1565.001 Stored Data Manipulation (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: MANIPULAR datos EN REPOSO: alterar un registro de un libro mayor
#           (ledger) SIMULADO sin destruirlo (T1485) ni publicarlo (T1491).
#           Distinto de ATA026/T1565.002 (manipulacion EN TRANSITO): aqui el
#           objeto es un ACTIVO CONCRETO en reposo (un ledger con integridad).
# Destino : /home/angel/lab-legit/finanzas/ledger_2026.csv (ruta VIGILADA con -p wa)
# Ejecuta : desde /home/angel/lab-attack/ATA032 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el objetivo DEBE ser exactamente el ledger de lab-legit;
#   - JAMAS se toca /etc, PAM, bases de datos reales ni datos reales.
#
# Telemetria esperada (ver README §5):
#   - execve de sed -> 80792 (deteccion; senal T1565.001-S1) anclado por S2.
#   - escritura en el ledger (lab-legit) -> watch 80790/80781 -> AMBIGUA (efecto).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el marcador manipulado ("999999.99"
#   y el asiento falso) esta PRESENTE y el sha256 cambio (antes != despues).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA032"
TARGET="${HOME}/lab-legit/finanzas/ledger_2026.csv"

echo "ATA032 · T1565.001 Stored Data Manipulation (sed -i sobre ledger) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in sed mkdir grep sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el objetivo DEBE ser exactamente el ledger de lab-legit.
case "$TARGET" in
  "$HOME/lab-legit/finanzas/ledger_2026.csv") : ;;
  *) echo "ERROR: objetivo '$TARGET' no es el ledger de lab-legit (abortado)" >&2; exit 1 ;;
esac

# 0) SEMILLA del ledger SIMULADO (datos de juguete; idempotente).
mkdir -p "$(dirname "$TARGET")"
if [ ! -f "$TARGET" ]; then
  cat > "$TARGET" <<'CSV'
asiento,fecha,concepto,importe_eur,saldo_eur
A-1001,2026-09-01,Ingreso cliente Acme,18450.00,18450.00
A-1002,2026-09-05,Pago proveedor Delta,-9230.00,9220.00
A-1003,2026-09-10,Ingreso cliente Norte,4310.00,13530.00
CSV
fi

echo "--- ANTES (sha256) ---"
sha_antes=$(sha256sum "$TARGET" | awk '{print $1}')
echo "$sha_antes"

# 1) MANIPULACION EN REPOSO (replace): infla un asiento.
sed -i 's/^A-1002,2026-09-05,Pago proveedor Delta,-9230.00,9220.00/A-1002,2026-09-05,Pago proveedor Delta,1230.00,22220.00/' "$TARGET"
# 2) MANIPULACION EN REPOSO (append): inyecta un asiento FALSO.
sed -i '$a A-1004,2026-09-29,Ajuste manual no autorizado,999999.99,1022219.99' "$TARGET"

echo "--- DESPUES (sha256) ---"
sha_despues=$(sha256sum "$TARGET" | awk '{print $1}')
echo "$sha_despues"

# PRUEBA DEL EFECTO
if [ "$sha_antes" != "$sha_despues" ] \
   && grep -q '999999.99' "$TARGET" \
   && grep -q 'Ajuste manual no autorizado' "$TARGET"; then
  echo "MANIPULACION=OK (ledger alterado: sha256 antes != despues; marcadores presentes)"
else
  echo "MANIPULACION=FALLO (revisar el ledger)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
