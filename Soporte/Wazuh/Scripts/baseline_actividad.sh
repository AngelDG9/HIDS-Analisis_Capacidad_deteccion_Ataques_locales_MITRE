#!/usr/bin/env bash
# ============================================================================
# TFG · HIDS — Actividad legítima de baseline (Fase 2 · tarea 2.10 · T-06/R-08)
# ============================================================================
# Genera actividad BENIGNA y variada en /home/angel/lab-legit durante N minutos
# y deja trazas en /home/angel/lab-legit/baseline_log.txt con timestamps UTC.
# De ahí se extraen t0 (primera línea START) y t1 (línea END).
#
# Uso:
#   bash baseline_actividad.sh <DURACION_MIN> [DIR_BASE]
#   bash baseline_actividad.sh 240                 # ventana de 4 h
#   bash baseline_actividad.sh 1                   # prueba en seco (1 min)
#
# Propiedades:
#   - Determinista (sin $RANDOM), sin secretos, re-ejecutable.
#   - Pensado para ejecutarse como usuario 'angel' (NO root): escribe en $HOME.
#   - Sobrevive a la desconexión SSH si se lanza con `nohup`.
#   - Escribe la línea END también si recibe SIGINT/SIGTERM.
#
# Formato del log (una línea por evento, UTC ISO8601):
#   # duracion_min=<N>
#   START <UTC ISO8601>
#   CYCLE <n> <UTC ISO8601>
#   ...
#   END <UTC ISO8601>
#
# El fichero baseline_log.txt vive en la RAÍZ de DIR_BASE y NO se incluye en
# los backups (el `tar` solo empaqueta el subdirectorio work/).
# ============================================================================
set -u
LC_ALL=C

DURACION_MIN="${1:-240}"
BASE="${2:-/home/angel/lab-legit}"
LOG="$BASE/baseline_log.txt"
INTERVALO=300   # segundos entre ciclos (~5 min)

case "$DURACION_MIN" in
  ''|*[!0-9]*) echo "ERROR: DURACION_MIN debe ser un entero de minutos" >&2; exit 2 ;;
esac

mkdir -p "$BASE" || { echo "ERROR: no se pudo crear $BASE" >&2; exit 1; }

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

END_WRITTEN=0
escribir_end() {
  if [ "$END_WRITTEN" -eq 0 ]; then
    echo "END $(ts)" >> "$LOG"
    END_WRITTEN=1
  fi
}
trap 'escribir_end; exit 0' INT TERM

START_EPOCH=$(date +%s)
END_EPOCH=$((START_EPOCH + DURACION_MIN * 60))

{
  echo "# duracion_min=$DURACION_MIN"
  echo "START $(ts)"
} >> "$LOG"

n=0
while :; do
  ahora=$(date +%s)
  [ "$ahora" -ge "$END_EPOCH" ] && break
  n=$((n + 1))

  # ---- ciclo de actividad legítima y variada ----------------------------
  mkdir -p "$BASE/work" "$BASE/backup"

  # 1) crear ficheros
  for i in 1 2 3 4 5; do
    printf 'legit baseline cycle %d file %d\n' "$n" "$i" > "$BASE/work/doc_${i}.txt"
  done

  # 2) leer ficheros
  cat "$BASE"/work/doc_*.txt >/dev/null 2>&1 || true

  # 3) escribir/append
  printf 'append cycle %d\n' "$n" >> "$BASE/work/doc_1.txt"

  # 4) backup legítimo del directorio (tar)
  tar -czf "$BASE/backup/backup_ciclo_${n}.tar.gz" -C "$BASE" work 2>/dev/null || true

  # 5) cp / mv / rm de temporales
  cp "$BASE/work/doc_2.txt" "$BASE/work/tmp_copy.txt" 2>/dev/null || true
  mv "$BASE/work/tmp_copy.txt" "$BASE/work/tmp_moved.txt" 2>/dev/null || true
  rm -f "$BASE/work/tmp_moved.txt"

  # 6) búsqueda / filtrado / hashing
  find "$BASE/work" -type f -name '*.txt' | sort > "$BASE/work/lista.txt"
  grep -r -l 'cycle' "$BASE/work" >/dev/null 2>&1 || true
  sha256sum "$BASE/work/doc_1.txt" > "$BASE/work/doc_1.sha256" 2>/dev/null || true

  # 7) lectura de journalctl
  journalctl -n 20 --no-pager >/dev/null 2>&1 || true

  # 8) inventario de paquetes
  apt list --installed >/dev/null 2>&1 || true

  # 9) limpieza legítima: conservar solo los 5 backups más recientes
  ls -1t "$BASE"/backup/backup_ciclo_*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f

  echo "CYCLE $n $(ts)" >> "$LOG"

  # ---- espera hasta el siguiente ciclo ----------------------------------
  ahora=$(date +%s)
  restante=$((END_EPOCH - ahora))
  [ "$restante" -le 0 ] && break
  sleep_for=$INTERVALO
  [ "$restante" -lt "$INTERVALO" ] && sleep_for=$restante
  sleep "$sleep_for"
done

escribir_end
echo "Baseline finalizado: $(grep -c '^CYCLE ' "$LOG" 2>/dev/null || echo 0) ciclos. Log: $LOG"
exit 0
