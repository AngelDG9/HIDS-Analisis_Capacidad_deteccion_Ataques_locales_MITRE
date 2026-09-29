#!/usr/bin/env bash
# ============================================================================
# ATA014 · T1114 Email Collection — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1114 Email Collection (tactica Collection)
# Fuente  : custom (ART no trae prueba Linux utilizable sin red para T1114)
# Objetivo: RECOLECTAR el correo local de la victima: un buzon mbox SIMULADO
#           (escena de empresa, datos de juguete) que vive en la ruta VIGILADA
#           /home/angel/lab-legit. Se localiza/parsea el buzon y se COPIA lo
#           recolectado a la carpeta del ataque.
# Destino : LECTURA en /home/angel/lab-legit (vigilada con -p wa: NO audita lectura)
#           COPIA   en /home/angel/lab-attack/ATA014/ (NO vigilado -> execve)
# Elevacion: NO (usuario angel). No se instala nada.
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la salida DEBE quedar bajo $HOME/lab-attack/ATA014/;
#   - solo se LEE de lab-legit; JAMAS se toca /etc, PAM, correo real ni datos reales.
#
# Telemetria esperada (ver README §7):
#   - execve de grep/cp -> 80792 (deteccion; senales T1114-S1/S2) ancladas por T1114-S3.
#   - SIEMBRA del buzon (escritura en lab-legit) -> watch 80790/80781/80782 -> AMBIGUA
#     (efecto del ataque, no deteccion declarada) -> veredicto humano `artefacto`.
#
# Prueba de exito (INDEPENDIENTE de la alerta): el buzon tiene >=3 mensajes y la
#   copia en lab-attack conserva el MISMO sha256 que el original.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA014"
LEGIT="${HOME}/lab-legit"
BOX="${LEGIT}/mailbox_angel_2026.mbox"
OUT="${BASE}/collected"

echo "ATA014 · T1114 Email Collection (grep + cp sobre mbox local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cat grep cp mkdir sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: toda la salida debe quedar bajo la carpeta del ataque
case "$OUT" in
  "$HOME/lab-attack/ATA014"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA014 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) La victima tiene un buzon local SIMULADO (datos de juguete; sin datos reales).
#    Se siembra aqui porque lab-listo parte con lab-legit vacio; representa el
#    correo PRE-EXISTENTE que el atacante recolecta. Escritura en ruta VIGILADA.
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

# 1) RECOLECCION: localizar/contar los mensajes del buzon (execve de grep).
n=$(grep -c '^From ' "$BOX")
echo "mensajes_en_buzon=$n"

# 2) RECOLECCION: extraer los asuntos a la carpeta del ataque (execve de grep).
mkdir -p "$OUT"
grep -a '^Subject:' "$BOX" > "$OUT/asuntos.txt"

# 3) COPIA del buzon completo a lab-attack (execve de cp).
cp -f "$BOX" "$OUT/mailbox_angel_2026.mbox"

# 4) PRUEBA DE EXITO (sha256 origen == copia). El execve de sha256sum/awk no esta
#    declarado -> fila `artefacto_ataque` (auto), nunca `ruido`.
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
