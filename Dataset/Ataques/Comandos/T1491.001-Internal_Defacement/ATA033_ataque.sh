#!/usr/bin/env bash
# ============================================================================
# ATA033 · T1491.001 Internal Defacement — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1491.001 Internal Defacement (tactica Impact)
# Fuente  : custom (escrito por el TFG; las atomicas de ART son Windows)
# Objetivo: DEFACEMENT INTERNO: reescribir la raiz web de un portal INTERNO
#           simulado (contenido servido), distinto de ATA007/T1491 (defacement
#           generico): aqui el OBJETO es el webroot de la intranet.
# Destino : /home/angel/lab-legit/intranet_web/index.html (ruta VIGILADA con -p wa)
# Ejecuta : desde /home/angel/lab-attack/ATA033 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el objetivo DEBE estar bajo $HOME/lab-legit/intranet_web;
#   - JAMAS se toca un webroot real (/var/www), servicios ni datos reales.
#
# Telemetria esperada (ver README §5):
#   - execve de cp -> 80792 (deteccion; senal T1491.001-S1) anclado por S2.
#   - escritura en el webroot (lab-legit) -> watch 80790/80781 -> AMBIGUA (efecto).
#
# Prueba de exito (INDEPENDIENTE de la alerta): index.html cambia (sha256 antes !=
#   despues) y contiene el marcador de defacement.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA033"
SRC="${BASE}/deface_internal.html"
WEBROOT="${HOME}/lab-legit/intranet_web"
DST="${WEBROOT}/index.html"

echo "ATA033 · T1491.001 Internal Defacement (cp sobre webroot interno) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -f "$SRC" ]; then
  echo "ERROR: no existe $SRC (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cp mkdir sha256sum grep; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el webroot DEBE estar bajo lab-legit/intranet_web.
case "$DST" in
  "$HOME/lab-legit/intranet_web/"*) : ;;
  *) echo "ERROR: objetivo '$DST' no esta bajo lab-legit/intranet_web (abortado)" >&2; exit 1 ;;
esac

# 0) SEMILLA de la pagina "legitima" del portal interno (si no existe).
mkdir -p "$WEBROOT"
if [ ! -f "$DST" ]; then
  cat > "$DST" <<'HTML'
<!doctype html><html><head><title>Intranet Corporativa</title></head>
<body><h1>Portal interno</h1><p>Acceso restringido a empleados.</p></body></html>
HTML
fi

echo "--- ANTES (sha256) ---"
sha_antes=$(sha256sum "$DST" | awk '{print $1}')
echo "$sha_antes"

# 1) DEFACEMENT INTERNO: reescribe el index del portal.
cp -f "$SRC" "$DST"

echo "--- DESPUES (sha256) ---"
sha_despues=$(sha256sum "$DST" | awk '{print $1}')
echo "$sha_despues"
echo "--- cabecera del fichero servido ---"
head -n 3 "$DST"

# PRUEBA DEL EFECTO
if [ "$sha_antes" != "$sha_despues" ] && grep -q 'COMPROMETIDA' "$DST"; then
  echo "DEFACEMENT=OK (webroot interno reescrito: sha256 antes != despues; marcador presente)"
else
  echo "DEFACEMENT=FALLO (revisar el webroot)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
