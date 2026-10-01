#!/usr/bin/env bash
# ============================================================================
# ATA014_rev · T1114 Email Collection — repetición auditada (motivo: pre-staging)
# ----------------------------------------------------------------------------
# Corrección metodológica (§C): la SIEMBRA del buzón (antes dentro de [t0,t1]) pasa a
#   ANTES de t0 (modo prestage). La ventana mide SOLO la recolección (grep + cp).
# Mismo guion propio que el original, sin la escritura de la semilla dentro de la ventana.
#
# Uso:  bash ATA014_ataque_rev.sh prestage   # ANTES de t0 (siembra el mbox en lab-legit)
#       bash ATA014_ataque_rev.sh attack     # ventana [t0,t1] (solo recolección)
# Elevación: NO (usuario angel).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA014"
LEGIT="${HOME}/lab-legit"
BOX="${LEGIT}/mailbox_angel_2026.mbox"
OUT="${BASE}/collected"
MODE="${1:-attack}"

echo "ATA014_rev · T1114 Email Collection (grep + cp sobre mbox local) — repeticion (pre-staging)"

case "$OUT" in
  "$HOME/lab-attack/ATA014"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA014 (abortado)" >&2; exit 1 ;;
esac

if [ "$MODE" = "prestage" ]; then
  mkdir -p "$LEGIT"
  cat > "$BOX" <<'MBOX'
From angel@empresa.local Mon Sep 28 09:12:00 2026
To: angel@empresa.local
Subject: Presupuesto Q4 - cifras internas
X-Folder: INBOX
Estado: revision pendiente del comite de direccion.

From contabilidad@empresa.local Mon Sep 28 10:41:12 2026
To: angel@empresa.local
Subject: Nóminas septiembre - adjunto protegido
X-Folder: INBOX
Adjunto simulado: nominas_2026-09.xlsx (datos de juguete).

From direccion@empresa.local Tue Sep 29 08:05:44 2026
To: angel@empresa.local
Subject: Contrato confidencial cliente Acme
X-Folder: Archivo
Clausulas y cifras simuladas del contrato.
MBOX
  echo "PRESTAGE=OK (mbox sembrado en lab-legit antes de t0; $(grep -c '^From ' "$BOX") mensajes)"
  exit 0
fi

# ---- modo attack (ventana): SOLO recolección ----
for t in grep cp mkdir sha256sum awk; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: $t no disponible" >&2; exit 1; }
done
[ -f "$BOX" ] || { echo "ERROR: falta el mbox (¿prestage ANTES de t0?)" >&2; exit 1; }
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

n=$(grep -c '^From ' "$BOX")
echo "mensajes_en_buzon=$n"
mkdir -p "$OUT"
grep -a '^Subject:' "$BOX" > "$OUT/asuntos.txt"
cp -f "$BOX" "$OUT/mailbox_angel_2026.mbox"

s_src=$(sha256sum "$BOX" | awk '{print $1}')
s_dst=$(sha256sum "$OUT/mailbox_angel_2026.mbox" | awk '{print $1}')
echo "--- estado final ---"
ls -l "$BOX" "$OUT/"
echo "sha256 origen  = $s_src"
echo "sha256 copiado = $s_dst"
if [ "$s_src" = "$s_dst" ] && [ "$n" -ge 3 ]; then
  echo "RECOLECCION=OK ($n mensajes recolectados; copia identica)"
else
  echo "RECOLECCION=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
