#!/usr/bin/env bash
# ============================================================================
# ATA022 · T1567.001 Exfiltration Over Code Repository — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1567.001 Exfiltration Over Web Service: Exfiltration to Code
#           Repository (tactica Exfiltration)
# Fuente  : custom (escrito por el TFG)
# Objetivo: EXFILTRAR un fichero de "codigo fuente" a un REPOSITORIO DE CODIGO
#           simulado mediante `git push`. El repositorio es un `git` bare LOCAL
#           creado DENTRO de lab-attack (`file://…`), NO un remoto real.
# Destino : file:///home/angel/lab-attack/ATA022/repo.git (repositorio local)
# Ejecuta : desde /home/angel/lab-attack/ATA022 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️⚠️ GUARDARRAIL DURO (R6): PROHIBIDO `git push` a un remoto REAL (GitHub,
#      GitLab, el repo del TFG…). El remoto DEBE empezar por
#      `file:///home/angel/lab-attack/ATA022/`. Si no, EL GUION ABORTA antes
#      de empujar. SIN credenciales. Repositorio de laboratorio (desechable).
#
# Telemetria esperada (ver README §5):
#   - execve de git (init/commit/push/cat-file) -> 80792 (deteccion; T1567.001-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA022/*` (T1567.001-S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el repo bare RECIBIO el commit y
#   el blob del fichero en el repo tiene el MISMO sha256 que el original.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA022"
BARE="${BASE}/repo.git"
WORK="${BASE}/work"
DATA_LOCAL="${BASE}/codigo_fuente_secreto.ini"
FNAME="codigo_fuente_secreto.ini"

echo "ATA022 · T1567.001 Exfiltration to Code Repository (git push a bare local) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in git mkdir cp sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAILES: bare/work DEBEN quedar bajo la carpeta del ataque.
case "$BARE" in "$HOME/lab-attack/ATA022"*) : ;; *) echo "ERROR: bare fuera de lab-attack/ATA022 (abortado)" >&2; exit 1 ;; esac
case "$WORK" in "$HOME/lab-attack/ATA022"*) : ;; *) echo "ERROR: work fuera de lab-attack/ATA022 (abortado)" >&2; exit 1 ;; esac

# 0) SIEMBRA del "codigo fuente" a exfiltrar (datos de juguete; builtin printf).
if [ ! -f "$DATA_LOCAL" ]; then
  {
    printf '# configuracion interna (datos de JUGUETE, no reales)\n'
    printf '[produccion]\n'
    printf 'db_host=db01.empresa.local\n'
    printf 'db_user=app_prod\n'
    printf 'feature_flags=checkout_v2,eta_v3\n'
  } > "$DATA_LOCAL"
fi
echo "--- FICHERO A EXFILTRAR (sha256 local) ---"
sha256sum "$DATA_LOCAL"

# 1) Crear el "repositorio de codigo" BARE local (execve de git).
git init --bare "$BARE" >/dev/null

# 2) Preparar un repositorio de trabajo (execve de git) y commitear el dato.
mkdir -p "$WORK"
git -C "$WORK" init -q
git -C "$WORK" config user.email "angel@empresa.local"
git -C "$WORK" config user.name "angel"
cp -f "$DATA_LOCAL" "$WORK/$FNAME"
git -C "$WORK" add "$FNAME"

# 3) GUARDARRAIL DURO: el remoto DEBE ser file://… bajo lab-attack/ATA022 (JAMAS GitHub).
git -C "$WORK" remote add origin "file://${BARE}" 2>/dev/null || git -C "$WORK" remote set-url origin "file://${BARE}"
REMOTE="$(git -C "$WORK" remote get-url origin)"
case "$REMOTE" in
  "file://${HOME}/lab-attack/ATA022/"*) : ;;
  *) echo "ERROR: remoto '$REMOTE' NO es el repositorio LOCAL del laboratorio; ABORTADO (R6)" >&2; exit 1 ;;
esac
case "$REMOTE" in
  *http*|*git@*|*github*|*gitlab*) echo "ERROR: remoto con pinta de REAL; ABORTADO (R6)" >&2; exit 1 ;;
esac
echo "remoto_verificado=$REMOTE"

git -C "$WORK" commit -q -m "snapshot configuracion interna"

# 4) EXFILTRACION: empujar el commit al repositorio de codigo LOCAL (execve de git).
echo ">>> git push al repositorio de codigo local"
git -C "$WORK" push -q -u origin "$(git -C "$WORK" rev-parse --abbrev-ref HEAD)"

# 5) PRUEBA DE EXITO: el repo bare RECIBIO el commit y el blob coincide byte a byte.
echo "--- repositorio de codigo (contenido recibido) ---"
git --git-dir="$BARE" log --oneline --all
s_local=$(sha256sum "$DATA_LOCAL" | awk '{print $1}')
s_repo=$(git --git-dir="$BARE" cat-file -p "HEAD:${FNAME}" | sha256sum | awk '{print $1}')
echo "sha256 local            = $s_local"
echo "sha256 en el repo (blob)= $s_repo"
if [ -n "$(git --git-dir="$BARE" log --oneline --all)" ] && [ "$s_local" = "$s_repo" ]; then
  echo "EXFIL_REPO=OK (el repositorio de codigo local recibio el dato; blob identico)"
else
  echo "EXFIL_REPO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
