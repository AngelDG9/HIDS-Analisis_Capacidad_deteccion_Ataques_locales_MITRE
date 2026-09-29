#!/usr/bin/env bash
# ============================================================================
# ATA017 · T1657 Financial Theft — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1657 Financial Theft (tactica Impact — sabotaje/fraude)
# Fuente  : custom (la prueba ART depende de servicios/red -> sin NAT se escribe a mano)
# Objetivo: SABOTAJE/FRAUDE sobre un LIBRO DE CUENTAS local SIMULADO (datos de juguete):
#           se añade una TRANSFERENCIA FRAUDULENTA y se altera el saldo; ademas se
#           "sustrae" una cartera simulada copiandola a la carpeta del ataque.
# Destino : MODIFICACION en /home/angel/lab-legit (RUTA VIGILADA -> evento watch)
#           copia en /home/angel/lab-attack/ATA017/ (NO vigilado -> execve)
# Elevacion: NO (usuario angel). No se toca ninguna cuenta/servicio financiero real.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la copia DEBE quedar bajo $HOME/lab-attack/ATA017/;
#   - el libro/cartera son DATOS DE JUGUETE en lab-legit; JAMAS una cuenta real.
#
# Telemetria esperada (ver README §7):
#   - execve de sed/cp -> 80792 (deteccion; senales T1657-S1/S2) ancladas por S3.
#   - MODIFICACION bajo watch (lab-legit) -> 80790/80781/80782 -> AMBIGUA -> `artefacto`.
#
# Prueba de exito (INDEPENDIENTE de la alerta): el sha256 del libro CAMBIA, aparece la
#   transferencia fraudulenta (TRF-9999) y la copia en lab-attack es identica.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA017"
LEGIT="${HOME}/lab-legit"
LEDGER="${LEGIT}/libro_cuentas_2026.csv"
WALLET="${LEGIT}/cartera_simulada.txt"
OUT="${BASE}/collected"

echo "ATA017 · T1657 Financial Theft (sed -i sobre libro + cp de cartera) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cat sed cp grep mkdir sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: la copia debe quedar bajo la carpeta del ataque
case "$OUT" in
  "$HOME/lab-attack/ATA017"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA017 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) SIEMBRA de los datos financieros SIMULADOS (nombres creibles; sin datos reales)
#    en la ruta VIGILADA lab-legit (execve de cat -> filas watch).
cat > "$LEDGER" <<'CSV'
fecha,concepto,cuenta,importe_eur,saldo_eur
2026-09-01,Saldo inicial,ES91-CORP,0,128450.00
2026-09-10,Pago proveedor Logistica Norte,ES91-CORP,-15300.00,113150.00
2026-09-20,Cobro factura Acme Iberica,ES91-CORP,18450.00,131600.00
2026-09-25,Comisiones,ES91-CORP,-120.00,131480.00
CSV
cat > "$WALLET" <<'TXT'
cartera_simulada: 3 activos (datos de juguete)
- BTC  0.42
- ETH  5.10
- EUR  9800.00
TXT

# 1) FRAUDE: añadir una TRANSFERENCIA FRAUDULENTA al libro (execve de sed).
sed -i '$a 2026-09-29,TRF-9999 Transferencia Mallory Consulting SL,ES91-CORP,-25000.00,106480.00' "$LEDGER"

# 2) FRAUDE: alterar el saldo de la ultima linea legitima (execve de sed).
sed -i 's/^2026-09-25,Comisiones,ES91-CORP,-120.00,131480.00$/2026-09-25,Comisiones,ES91-CORP,-120.00,106480.00/' "$LEDGER"

# 3) SUSTRACCION: copiar el libro manipulado y la cartera a la carpeta del ataque (execve de cp).
mkdir -p "$OUT"
cp -f "$LEDGER" "$OUT/libro_cuentas_2026.csv"
cp -f "$WALLET" "$OUT/cartera_simulada.txt"

# 4) PRUEBA DE EXITO (fraude presente + copias identicas).
s_after=$(sha256sum "$LEDGER" | awk '{print $1}')
s_copy=$(sha256sum "$OUT/libro_cuentas_2026.csv" | awk '{print $1}')
fraude=$(grep -c 'TRF-9999' "$LEDGER")
echo "--- estado final ---"
ls -l "$LEDGER" "$WALLET" "$OUT/"
echo "fraude_lineas=$fraude"
echo "sha256 libro (tras fraude) = $s_after"
echo "sha256 copia               = $s_copy"
if [ "$fraude" -ge 1 ] && [ "$s_after" = "$s_copy" ] && [ -s "$OUT/cartera_simulada.txt" ]; then
  echo "FRAUDE=OK (transferencia fraudulenta añadida; libro y cartera sustraidos)"
else
  echo "FRAUDE=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
