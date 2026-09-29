#!/usr/bin/env bash
# ============================================================================
# ATA016 · T1213.006 Databases — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1213.006 Data from Information Repositories: Databases (Collection)
# Fuente  : custom (la prueba ART de T1213 depende de repositorios en red/SaaS -> sin NAT)
# Objetivo: RECOLECTAR informacion de una BASE DE DATOS LOCAL. La victima tiene un
#           SQLite (`clientes_clientes.db`) con datos de clientes FALSOS en la ruta
#           VIGILADA /home/angel/lab-legit. El atacante COPIA la BD y EXTRAE registros.
# Destino : LECTURA/COPIA de /home/angel/lab-legit (vigilada con -p wa, NO audita lectura)
#           salida en /home/angel/lab-attack/ATA016/ (NO vigilado -> execve)
# Elevacion: NO (usuario angel). No se instala nada.
#
# DEPENDENCIA (paso 0): `sqlite3` NO esta instalado en la victima (ni `strings`).
#   La BD SQLite REAL se crea con la stdlib de python3 (modulo `sqlite3`); el execve de
#   python3 cae en el punto ciego de fabrica 92600 (nivel 0) -> NO alerta. Se declara.
#   La COLECCION propiamente dicha (copiar la BD + extraer los registros) usa `cp`/`grep`.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la salida DEBE quedar bajo $HOME/lab-attack/ATA016/;
#   - solo se LEE/COPIA de lab-legit; JAMAS se toca una BD/servicio real.
#
# Telemetria esperada (ver README §7):
#   - execve de cp/grep -> 80792 (deteccion; senales T1213.006-S1/S2) ancladas por S3.
#   - SIEMBRA de la BD (escritura en lab-legit) -> watch 80790/80781/80782 -> AMBIGUA.
#
# Prueba de exito (INDEPENDIENTE de la alerta): la copia es una BD SQLite valida
#   (magic "SQLite format 3") con el MISMO sha256 que el original y >=4 codigos de
#   cliente extraidos.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA016"
LEGIT="${HOME}/lab-legit"
DB="${LEGIT}/clientes_clientes.db"
OUT="${BASE}/collected"

echo "ATA016 · T1213.006 Databases (cp + grep sobre SQLite local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in python3 cp grep mkdir sha256sum sort wc; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: toda la salida debe quedar bajo la carpeta del ataque
case "$OUT" in
  "$HOME/lab-attack/ATA016"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA016 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) SIEMBRA de la BD local SIMULADA (datos de juguete, sin datos reales) en la ruta
#    VIGILADA lab-legit. SQLite real via stdlib (python3 -> 92600, sin alerta; declarado).
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
print("BD sembrada:", db)
PY

# 1) VERIFICAR que el objetivo es una BD SQLite (execve de grep).
magic=$(grep -a -c 'SQLite format 3' "$DB")
echo "es_sqlite(0/1)=$magic"

# 2) EXTRACCION de registros de la BD (execve de grep + sort).
mkdir -p "$OUT"
grep -a -oE 'cli[0-9]{4}' "$DB" | sort -u > "$OUT/clientes_codigos.txt"
ncod=$(wc -l < "$OUT/clientes_codigos.txt")

# 3) COLECCION/EXFIL de la BD completa a lab-attack (execve de cp).
cp -f "$DB" "$OUT/clientes.db"

# 4) PRUEBA DE EXITO (sha256 origen == copia).
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
