#!/usr/bin/env bash
# ============================================================================
# ATA016_rev · T1213.006 Databases — repetición auditada (motivo: pre-staging)
# ----------------------------------------------------------------------------
# Corrección metodológica (§C): la SIEMBRA de la BD SQLite (antes dentro de [t0,t1],
#   con python3→92600) pasa a ANTES de t0 (modo prestage). La ventana mide SOLO la
#   colección (cp de la BD + grep de los registros).
# Mismo guion propio que el original, sin la creación de la BD dentro de la ventana.
#
# Uso:  bash ATA016_ataque_rev.sh prestage   # ANTES de t0 (siembra la BD en lab-legit)
#       bash ATA016_ataque_rev.sh attack     # ventana [t0,t1] (solo colección)
# Elevación: NO (usuario angel).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA016"
LEGIT="${HOME}/lab-legit"
DB="${LEGIT}/clientes_clientes.db"
OUT="${BASE}/collected"
MODE="${1:-attack}"

echo "ATA016_rev · T1213.006 Databases (cp + grep sobre SQLite local) — repeticion (pre-staging)"

case "$OUT" in
  "$HOME/lab-attack/ATA016"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA016 (abortado)" >&2; exit 1 ;;
esac

if [ "$MODE" = "prestage" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 no disponible" >&2; exit 1; }
  python3 - "$DB" <<'PY'
import os, sqlite3, sys
db = sys.argv[1]
os.makedirs(os.path.dirname(db), exist_ok=True)
if os.path.exists(db):
    os.remove(db)
con = sqlite3.connect(db)
con.execute("CREATE TABLE clientes (id INTEGER PRIMARY KEY, codigo TEXT, nombre TEXT, cif TEXT, alta TEXT)")
filas = [
    (1, "cli1001", "Acme Iberica SL",   "B12345678", "2024-03-11"),
    (2, "cli1002", "Comercial Delta SA","A87654321", "2025-01-22"),
    (3, "cli1003", "Talleres Norte SL","B11223344", "2026-02-08"),
    (4, "cli1004", "Logistica Sur SL",  "B55667788", "2026-05-30"),
]
con.executemany("INSERT INTO clientes VALUES (?,?,?,?,?)", filas)
con.commit(); con.close()
print("BD sembrada (prestage):", db)
PY
  echo "PRESTAGE=OK (BD SQLite sembrada en lab-legit antes de t0)"
  exit 0
fi

# ---- modo attack (ventana): SOLO colección ----
for t in cp grep mkdir sha256sum sort wc; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done
[ -f "$DB" ] || { echo "ERROR: falta la BD (¿prestage ANTES de t0?)" >&2; exit 1; }
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

magic=$(grep -a -c 'SQLite format 3' "$DB")
echo "es_sqlite(0/1)=$magic"
mkdir -p "$OUT"
grep -a -oE 'cli[0-9]{4}' "$DB" | sort -u > "$OUT/clientes_codigos.txt"
ncod=$(wc -l < "$OUT/clientes_codigos.txt")
cp -f "$DB" "$OUT/clientes.db"

s_src=$(sha256sum "$DB" | awk '{print $1}')
s_dst=$(sha256sum "$OUT/clientes.db" | awk '{print $1}')
echo "--- estado final ---"
ls -l "$DB" "$OUT/"
echo "codigos_extraidos=$ncod"
cat "$OUT/clientes_codigos.txt"
echo "sha256 origen  = $s_src"
echo "sha256 copiado = $s_dst"
if [ "$s_src" = "$s_dst" ] && [ "$magic" -ge 1 ] && [ "$ncod" -ge 4 ]; then
  echo "COLECCION=OK (BD SQLite valida copiada integra; $ncod registros extraidos)"
else
  echo "COLECCION=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
