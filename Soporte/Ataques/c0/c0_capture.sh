#!/usr/bin/env bash
# c0_capture.sh — extrae eventos de audit REALES (execve) para el C0 base-contra-base.
# Uso (como root): bash c0_capture.sh <ruta_exe1> <ruta_exe2> ...
# Imprime, por cada binario, UNA linea con los registros concatenados del evento
# (SYSCALL+EXECVE+CWD+PATH+PROCTITLE) tal como los consume wazuh-logtest.
set -u
LOG="/var/log/audit/audit.log"
for e in "$@"; do
  syscall_line=$(grep -a 'type=SYSCALL' "$LOG" | grep -a -F "exe=\"${e}\"" | tail -1)
  if [ -z "$syscall_line" ]; then
    echo "ERROR: no se encontro evento execve para exe=${e}" >&2
    continue
  fi
  id=$(printf '%s\n' "$syscall_line" | sed -E 's/.*audit\(([0-9]+\.[0-9]+:[0-9]+)\).*/\1/')
  if [ -z "$id" ]; then
    echo "ERROR: no se pudo extraer el id de ${e}" >&2
    continue
  fi
  recs=$(grep -a -F "audit(${id})" "$LOG")
  if [ -z "$recs" ]; then
    echo "ERROR: sin registros para id=${id} (${e})" >&2
    continue
  fi
  printf '%s' "$recs" | tr -d '\n'
  echo
done
