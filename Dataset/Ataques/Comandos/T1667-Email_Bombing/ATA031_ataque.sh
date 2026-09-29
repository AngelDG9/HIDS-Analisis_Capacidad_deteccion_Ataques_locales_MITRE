#!/usr/bin/env bash
# ============================================================================
# ATA031 · T1667 Email Bombing — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1667 Email Bombing (tactica Impact)
# Fuente  : custom (escrito por el TFG)
# Objetivo: SATURAR un buzon local SIMULADO por VOLUMEN de mensajes: se entregan
#           N mensajes ACOTADOS en un Maildir de juguete (lab-legit/Maildir) y se
#           demuestra el CRECIMIENTO. Distinto de ATA014 (leer buzon) y ATA015
#           (regla de reenvio): aqui el mecanismo es el VOLUMEN.
# Destino : /home/angel/lab-legit/Maildir/new/ (ruta VIGILADA con -w ... -p wa)
# Ejecuta : desde /home/angel/lab-attack/ATA031 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No hay MTA real instalado.
#
# GUARDARRAILES DUROS (abortan si no se cumplen):
#   - N <= 50 (cota dura); el Maildir DEBE estar bajo $HOME/lab-legit;
#   - JAMAS se toca correo real, /var/mail, Postfix/Exim ni cuentas reales.
#
# Telemetria esperada (ver README §5):
#   - execve de cp -> 80792 (deteccion; senal T1667-S1) anclado por T1667-S2.
#   - escrituras masivas en lab-legit -> watch 80790/80781 -> AMBIGUA (efecto).
#   - NO hay syslog de MTA: no hay MTA local (declarado, ver README §5).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el Maildir gana N mensajes y su
#   recuento total pasa de `antes` a `antes+N`.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA031"
MAILDIR="${HOME}/lab-legit/Maildir/new"
TEMPLATE="${BASE}/msg_template.eml"
N=25

echo "ATA031 · T1667 Email Bombing (Maildir local, N=${N}) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cp mkdir ls wc; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# --- GUARDARRAILES DUROS ---
case "$MAILDIR" in
  "$HOME/lab-legit/Maildir"*) : ;;
  *) echo "ERROR: Maildir '$MAILDIR' fuera de lab-legit (abortado por seguridad)" >&2; exit 1 ;;
esac
case "$N" in
  ''|*[!0-9]*) echo "ERROR: N no numerico (abortado)" >&2; exit 1 ;;
esac
if [ "$N" -gt 50 ]; then
  echo "ERROR: N=$N supera la cota dura 50 (abortado por seguridad)" >&2
  exit 1
fi

# 0) SEMILLA del mensaje plantilla (datos de juguete; builtin, sin execve).
mkdir -p "$MAILDIR"
cat > "$TEMPLATE" <<'EML'
From: promociones@ofertas.local
To: victima@empresa.local
Subject: Oferta imperdible - reclama ya
Date: Tue, 29 Sep 2026 09:00:00 +0000
Message-Id: <bomb-plantilla@ofertas.local>
X-Bulk: yes

Contenido de juguete (sin datos reales).
EML

# 1) ESTADO ANTES.
antes=$(ls -1 "$MAILDIR" | wc -l)
echo "mensajes_antes=${antes}"

# 2) BOMBARDEO: N entregas acotadas (execve de cp por mensaje -> volumen).
i=1
while [ "$i" -le "$N" ]; do
  dst=$(printf '%s/bomb_%03d.eml' "$MAILDIR" "$i")
  cp -f "$TEMPLATE" "$dst"
  i=$((i + 1))
done

# 3) ESTADO DESPUES + PRUEBA DEL CRECIMIENTO.
despues=$(ls -1 "$MAILDIR" | wc -l)
delta=$((despues - antes))
echo "mensajes_despues=${despues}"
echo "delta_mensajes=${delta}"
echo "--- tamano del Maildir ---"
du -sh "$MAILDIR" 2>/dev/null || true

if [ "$delta" -eq "$N" ]; then
  echo "EMAIL_BOMBING=OK (buzon saturado con ${N} mensajes nuevos; crecimiento demostrado)"
else
  echo "EMAIL_BOMBING=FALLO (delta=${delta} != ${N})" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
