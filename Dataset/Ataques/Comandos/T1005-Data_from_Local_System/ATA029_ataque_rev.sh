#!/usr/bin/env bash
# ============================================================================
# ATA029_rev · T1005 Data from Local System — repetición auditada (ART + PRE)
# ----------------------------------------------------------------------------
# Método corregido = PRUEBA DE ART + PRE-STAGING:
#   atomic  : "Find and dump sqlite databases (Linux)"
#   guid    : 00cbb875-7ae4-4cf1-b638-e543fd825300
#   path    : atomics/T1005/T1005.yaml
#   commit  : 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
#   comando : find . ! -executable -exec bash -c 'if [[ "$(head -c 15 {} | strings)"
#             == "SQLite format 3" ]]; then echo "{}"; ./sqlite_dump.sh {}; fi' \;
# Adaptación offline (§C): los 3 src/ (art, gta.db, sqlite_dump.sh) se pre-stean ANTES
#   de t0 en la carpeta del ataque, en lugar del `curl -O` remoto (sin NAT). El `cd $HOME`
#   del atómico se parametriza a la carpeta del ataque (cwd del lab, ancla H4); el resto
#   del comando es el de la atómica.
# Dependencias (pre-staging de paquetes §C): `sqlite3` y `strings` se instalan OFFLINE
#   desde .deb fijados (URL + sha256) ANTES de t0.
#
# Uso:  bash ATA029_ataque_rev.sh prestage   # ANTES de t0 (copia src + dpkg -i)
#       bash ATA029_ataque_rev.sh attack     # ventana [t0,t1]
# Elevación: SÍ solo para `dpkg -i` (sudo -S por stdin / SUDO_PW).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA029"
SRC="${HOME}/lab-attack/ATA029_src"
PKGS="${HOME}/lab-attack/ATA029_pkgs"
MODE="${1:-attack}"

echo "ATA029_rev · T1005 Data from Local System (atómica ART sqlite) — repeticion"

case "$BASE" in
  "$HOME/lab-attack/ATA029") : ;;
  *) echo "ERROR: BASE '$BASE' fuera de lab-attack/ATA029 (abortado)" >&2; exit 1 ;;
esac

if [ "$MODE" = "prestage" ]; then
  # 1) Contraseña de sudo solo de memoria (NUNCA en el repo).
  if [ -z "${SUDO_PW:-}" ]; then
    IFS= read -r SUDO_PW || true
  fi
  if [ -z "${SUDO_PW:-}" ]; then
    echo "ERROR: falta la contrasena de sudo (SUDO_PW o 1a linea de stdin)" >&2; exit 1
  fi
  sudo_cmd() { printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"; }

  # 2) Verifica el material pre-staged de la atómica (los 3 src/).
  for f in art gta.db sqlite_dump.sh; do
    [ -f "$SRC/$f" ] || { echo "ERROR: falta $SRC/$f (¿scp del src/ de la atómica?)" >&2; exit 1; }
  done
  # 3) Coloca los 3 ficheros en la carpeta del ataque (equivalente al `cd $HOME`+curl del atómico).
  cp -f "$SRC/art" "$SRC/gta.db" "$SRC/sqlite_dump.sh" "$BASE/"
  # El clon de ART está en un checkout Windows: normaliza el shebang a LF (si no, el ejecutor
  # fallaría con "required file not found" por el `\r`). No cambia el mecanismo.
  sed -i 's/\r$//' "$BASE/sqlite_dump.sh"
  chmod +x "$BASE/sqlite_dump.sh"

  # 4) Instala OFFLINE las dependencias fijadas (sqlite3 + binutils/`strings`).
  if ! command -v sqlite3 >/dev/null 2>&1 || ! command -v strings >/dev/null 2>&1; then
    if [ -d "$PKGS" ] && ls "$PKGS"/*.deb >/dev/null 2>&1; then
      sudo_cmd dpkg -i "$PKGS"/*.deb
    else
      echo "ERROR: faltan los .deb de dependencias en $PKGS" >&2; exit 1
    fi
  fi
  echo "sqlite3=$(sqlite3 --version 2>/dev/null | awk '{print $1}')"
  echo "strings=$(strings --version 2>/dev/null | head -1)"
  echo "PRESTAGE=OK (src/ + dependencias offline)"
  exit 0
fi

# ---- modo attack (ventana) ----
for t in find bash head strings sqlite3; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible (¿prestage?)" >&2; exit 1; }
done
[ -f "$BASE/gta.db" ] || { echo "ERROR: falta gta.db (¿prestage ANTES de t0?)" >&2; exit 1; }
[ -x "$BASE/sqlite_dump.sh" ] || chmod +x "$BASE/sqlite_dump.sh"

cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "--- comando atómico: find . ! -executable -exec bash -c '… head|strings → sqlite_dump.sh' ---"
find . ! -executable -exec bash -c 'if [[ "$(head -c 15 {} | strings)" == "SQLite format 3" ]]; then echo "{}"; ./sqlite_dump.sh {}; fi' \;

echo "--- prueba de efecto: el volcado anterior (tablas y filas) es la recoleccion ---"
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
