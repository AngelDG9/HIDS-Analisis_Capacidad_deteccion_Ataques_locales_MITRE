#!/bin/bash
# ============================================================================
# exportar_acciones.sh — (HOST) exporta el CONTADOR DE ACCIONES de GHOSTS
# (tabla `history_timeline` de PostgreSQL) dentro de [t0,t1]. Bloque `legitimo-72h` (L1).
#
# Producto: Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv
#   (total + por handler + por hora → soporta FP/acción y FP/hora; R2 §2.2).
#
# Uso:
#   bash exportar_acciones.sh 2026-10-19T00:00:00Z 2026-10-22T00:00:00Z [SALIDA.csv]
# Sin secretos: PostgreSQL escucha en 127.0.0.1 y se inicializó con `initdb -A trust`.
# ============================================================================
set -eu
PSQL="D:/TFG-VMs/material-ghosts/pgsql/bin/psql.exe"
T0="${1:?falta t0 UTC (YYYY-MM-DDTHH:MM:SSZ)}"
T1="${2:?falta t1 UTC}"
OUT="${3:-Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv}"
# PostgreSQL necesita 'YYYY-MM-DD HH:MM:SS' (UTC naive)
T0SQL="${T0%Z}"; T0SQL="${T0SQL/T/ }"
T1SQL="${T1%Z}"; T1SQL="${T1SQL/T/ }"

mkdir -p "$(dirname "$OUT")"
GEN="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

run() { "$PSQL" -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -F',' -c "$1"; }

{
  echo "# ghosts_acciones.csv | metrica_version=1 boveda_version=1 | t0=${T0} t1=${T1} | generado=${GEN} | fuente=ghosts.history_timeline (createdutc UTC)"
  echo "tipo,clave,acciones"
  tot=$(run "select count(*) from history_timeline where createdutc >= '${T0SQL}' and createdutc < '${T1SQL}';")
  echo "total,,${tot}"
  run "select 'handler',coalesce(handler,'(nulo)'),count(*) from history_timeline where createdutc >= '${T0SQL}' and createdutc < '${T1SQL}' group by handler order by 3 desc;"
  run "select 'hora',to_char(date_trunc('hour',createdutc),'YYYY-MM-DD\"T\"HH24:00Z'),count(*) from history_timeline where createdutc >= '${T0SQL}' and createdutc < '${T1SQL}' group by 2 order by 2;"
} > "$OUT"

echo "exportado: $OUT"
head -n 5 "$OUT"
echo "..."
echo "total acciones: $(grep -c '^handler,' "$OUT" >/dev/null; grep '^total' "$OUT")"
