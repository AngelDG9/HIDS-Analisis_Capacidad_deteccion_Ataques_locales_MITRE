#!/usr/bin/env bash
# ============================================================================
# ATA007 · T1491 Defacement — ataque MANUAL (escrito por el TFG, NO copiado de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1491 Defacement (tactica Impact)
# Fuente  : custom (Atomic Red Team NO tiene pruebas Linux para T1491 -> solo_windows)
# Objetivo: modificar el contenido de una pagina "publica" simulada (mock web).
# Destino : /home/angel/lab-legit/public_site/index.html   (dir VIGILADO por auditd)
# Elevacion: NO (usuario angel). El fichero se borra al revertir a lab-listo.
#
# Telemetria esperada (ver README §7):
#   - execve de cp  -> 80792 (deteccion; senal T1491-S1)
#   - watch de escritura de lab-legit -> 80790/80781 (AMBIGUA; revision humana)
#
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). El t1 OFICIAL se sella tras
#         el scan FIM forzado (runbook §2 paso 7); estos quedan en ejecucion.out.
# ============================================================================
set -u

SRC="${HOME}/lab-attack/ATA007/defacement.html"       # pagina de defacement (la trae el artefacto)
DST="${HOME}/lab-legit/public_site/index.html"        # fichero "publico" simulado (dir VIGILADO)

echo "ATA007 · T1491 Defacement (cp) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -f "$SRC" ]; then
  echo "ERROR: no existe $SRC (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v cp >/dev/null 2>&1; then
  echo "ERROR: cp no disponible" >&2
  exit 1
fi

# 1) Siembra de la pagina "legitima" si no existe (execve mkdir + posible cp).
mkdir -p "$(dirname "$DST")"
[ -f "$DST" ] || cp "$SRC" "$DST"

# 2) DEFACEMENT: sobrescribe el contenido de la pagina publica simulada.
cp "$SRC" "$DST"

echo "--- estado final del objetivo ---"
ls -l "$DST"
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
