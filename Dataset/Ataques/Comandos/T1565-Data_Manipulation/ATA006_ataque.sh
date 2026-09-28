#!/usr/bin/env bash
# ============================================================================
# ATA006 · T1565 Data Manipulation — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1565 Data Manipulation (tactica Impact)
# Fuente  : custom (Atomic Red Team NO tiene pruebas para T1565 -> sin_pruebas)
# Objetivo: ALTERAR el contenido de un fichero de datos FALSO del laboratorio
#           (escena de empresa: registro de clientes) con `sed -i` (replace +
#           append). No lo destruye (eso es T1485/ATA002) ni lo publica
#           (T1491/ATA007): lo MODIFICA sin destruirlo (accion de T1565).
# Destino : /home/angel/lab-legit/datos_clientes_2026.csv  (dir VIGILADO -> watch)
# Ejecuta : desde /home/angel/lab-attack/ATA006 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# ALCANCE (decision humana 2026-09-28): la tecnica es el CAMBIO DE CONTENIDO.
#   NO se falsean metadatos (touch -t / chmod): falsear fecha/modo es T1070.006
#   (Timestomp), OTRA tecnica, y ensuciaria la atribucion de T1565. Se omite.
#
# Telemetria esperada (ver README §7):
#   - execve de sed -> 80792 (deteccion; senales T1565-S1/S2)
#   - watch de escritura en lab-legit -> 80790/80781 (AMBIGUA; revision humana)
#
# Prueba de exito (INDEPENDIENTE de la alerta): el marcador inyectado (999999 y
#   el registro falso "Mallory Consulting SL") esta PRESENTE y el hash cambio.
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA006"
TARGET="${HOME}/lab-legit/datos_clientes_2026.csv"

echo "ATA006 · T1565 Data Manipulation (sed -i) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if [ ! -d "$(dirname "$TARGET")" ]; then
  echo "ERROR: no existe $(dirname "$TARGET") (¿la victima no revirtio a lab-listo?)" >&2
  exit 1
fi
for t in sed grep; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el objetivo DEBE ser exactamente el registro de clientes de lab-legit.
case "$TARGET" in
  "$HOME/lab-legit/datos_clientes_2026.csv") : ;;
  *) echo "ERROR: objetivo '$TARGET' no es el esperado (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) Semilla determinista del registro de clientes FALSO (idempotente; builtin, sin execve).
#    (El unico evento que deja es un write de bash sobre lab-legit -> artefacto de setup.)
if [ ! -f "$TARGET" ]; then
  {
    printf 'id,cliente,cif,facturacion_eur,alta\n'
    printf '1001,Acme Iberica SL,B12345678,18450,2024-03-11\n'
    printf '1002,Comercial Delta SA,A87654321,9230,2025-01-22\n'
    printf '1003,Talleres Norte SL,B11223344,4310,2026-02-08\n'
  } > "$TARGET"
fi

echo "--- ANTES (hash) ---"
sha256sum "$TARGET"

# 1) MANIPULACION DEL CONTENIDO (replace): infla la facturacion de un cliente.
sed -i 's/^1002,Comercial Delta SA,A87654321,9230,/1002,Comercial Delta SA,A87654321,999999,/' "$TARGET"
# 2) MANIPULACION DEL CONTENIDO (append): inyecta un cliente FALSO.
sed -i '$a 1004,Mallory Consulting SL,B99999999,777777,2026-09-01' "$TARGET"

echo "--- DESPUES (hash) ---"
sha256sum "$TARGET"

# PRUEBA DE EXITO
if grep -q '999999' "$TARGET" && grep -q 'Mallory Consulting SL' "$TARGET"; then
  echo "MANIPULACION=OK (marcadores inyectados presentes; contenido alterado)"
else
  echo "MANIPULACION=FALLO" >&2
fi
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
