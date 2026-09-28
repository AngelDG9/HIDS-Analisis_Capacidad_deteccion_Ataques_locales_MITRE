#!/usr/bin/env bash
# ============================================================================
# ATA011 · T1074 Data Staged — ataque MANUAL (escrito por el TFG, NO de ART)
# ----------------------------------------------------------------------------
# Tecnica : T1074 Data Staged (tactica Collection)
# Fuente  : custom (la prueba ART de T1074 en Linux descarga de GitHub -> NO es
#           ejecutable en un laboratorio SIN NAT; se escribe a mano)
# Objetivo: REUNIR (stage) unos datos simulados en un directorio de "puesta en
#           escena" ($BASE/staging) con `mkdir -p` + `cp`, dejandolos listos
#           para una exfiltracion posterior (ATA009 / ATA010).
#           NO se usa `find` masivo (eso es T1119 / ATA012) ni se comprime
#           (eso es T1560 / ATA013): la accion caracteristica de T1074 es REUNIR.
# Destino : /home/angel/lab-attack/ATA011/staging/  (NO vigilado -> deteccion por execve)
# Ejecuta : desde /home/angel/lab-attack/ATA011 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# Prueba de exito (INDEPENDIENTE de la alerta): el directorio de staging existe,
#   contiene los ficheros reunidos y hay un manifiesto con sus sha256.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC). t1 OFICIAL tras el scan FIM.
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA011"
SRC="${BASE}/recoleccion"
STAGE="${BASE}/staging"
MANIFEST="${BASE}/staging_manifest.sha256"

echo "ATA011 · T1074 Data Staged (mkdir + cp) — custom (manual)"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in mkdir cp sha256sum; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: todo el ataque debe quedar bajo su carpeta de lab-attack
# (JAMAS el sistema real: ni /etc, ni /home/angel/lab-legit, ni dispositivos).
case "$STAGE" in
  "$HOME/lab-attack/ATA011"*) : ;;
  *) echo "ERROR: destino '$STAGE' no esta bajo lab-attack/ATA011 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) Semilla determinista de los datos simulados "recolectados" (builtin printf; sin execve).
#    Escena de empresa: informes de ventas, clientes y proveedores (datos de juguete).
if [ ! -d "$SRC" ]; then
  mkdir -p "$SRC"
  {
    printf 'periodo,region,canal,unidades,importe_eur\n'
    printf '2026-Q3,Norte,Directo,1420,182340.50\n'
    printf '2026-Q3,Sur,Distribuidor,980,121780.00\n'
    printf '2026-Q3,Este,Online,2015,268910.75\n'
  } > "$SRC/informe_ventas_2026-Q3.csv"
  {
    printf 'id,cliente,cif,segmento\n'
    printf '1001,Acme Iberica SL,B12345678,PYME\n'
    printf '1002,Comercial Delta SA,A87654321,Corporativo\n'
    printf '1003,Talleres Norte SL,B11223344,PYME\n'
  } > "$SRC/clientes_activos_2026.csv"
  {
    printf 'proveedor,nif,contrato,importe_eur\n'
    printf 'Logistica Norte SL,B55667788,2026-0142,15300\n'
    printf 'Suministros Vela SA,A99887766,2026-0207,8720\n'
  } > "$SRC/plantilla_proveedores_2026.csv"
fi

# 1) DIRECTORIO DE PUESTA EN ESCENA (execve de mkdir)
mkdir -p "$STAGE"

# 2) REUNIR los datos en el staging (execve de cp)
cp -f "$SRC/informe_ventas_2026-Q3.csv"    "$STAGE/"
cp -f "$SRC/clientes_activos_2026.csv"     "$STAGE/"
cp -f "$SRC/plantilla_proveedores_2026.csv" "$STAGE/"

# 3) Manifiesto del staging ("empaquetado" de la lista de lo reunido; SIN comprimir).
( cd "$STAGE" && sha256sum ./* > "$MANIFEST" )
chmod 600 "$MANIFEST" 2>/dev/null || true

echo "--- STAGING (contenido) ---"
ls -l "$STAGE"

# PRUEBA DE EXITO (sin execve extra: glob de bash)
shopt -s nullglob
files=("$STAGE"/*.csv)
if [ "${#files[@]}" -ge 3 ] && [ -s "$MANIFEST" ]; then
  echo "STAGING=OK (${#files[@]} ficheros reunidos; manifiesto con sha256)"
else
  echo "STAGING=FALLO" >&2
fi
# Convencion tanda B (instrumentacion t0/t1): asentar 1 s para que la marca local
# NO sea degenerada (T1_LOCAL > T0). La ventana OFICIAL [t0,t1] la sella el operador
# en la victima (UTC); este `sleep` es inofensivo y su execve no es una senal declarada.
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
