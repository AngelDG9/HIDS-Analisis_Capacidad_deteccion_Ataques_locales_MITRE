#!/usr/bin/env bash
# ============================================================================
# ATA012 · T1119 Automated Collection — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1119 Automated Collection (tactica Collection)
# Fuente  : custom (Atomic Red Team NO tiene pruebas Linux para T1119 -> solo_windows)
# Objetivo: recolectar automaticamente ficheros legibles y almacenarlos (stage)
#           para una exfiltracion posterior.
# Destino : /home/angel/lab-attack/ATA012/   (NO vigilado -> sin watch; deteccion por execve)
# Elevacion: NO (usuario angel; lee rutas world-readable).
#
# Telemetria esperada (ver README §7):
#   - execve de find / cp / tar -> 80792 (deteccion; senales T1119-S1..S3)
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). El t1 OFICIAL se sella tras
#         el scan FIM forzado (runbook §2 paso 7); estos quedan en ejecucion.out.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA012"
OUT="${BASE}/collected"
TAR="${BASE}/collected.tar.gz"

echo "ATA012 · T1119 Automated Collection (find/cp/tar) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in find cp tar; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# Staging: directorio de recoleccion (execve mkdir).
mkdir -p "$OUT"

# Recoleccion automatizada de ficheros de configuracion legibles (execve find + cp).
find /etc -maxdepth 2 -type f -readable \
     \( -name '*.conf' -o -name 'hosts' -o -name 'passwd' -o -name 'os-release' \) \
     -exec cp -t "$OUT" {} + 2>/dev/null

# Empaquetado / staging final (execve tar).
tar czf "$TAR" -C "$OUT" . 2>/dev/null

echo "--- estado final del staging ---"
ls -l "$TAR" 2>/dev/null || echo "(sin tar)"
find "$OUT" -type f | wc -l
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
