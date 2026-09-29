#!/usr/bin/env bash
# ============================================================================
# ATA034 · T1560.003 Archive via Custom Method — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1560.003 Archive via Custom Method (tactica Collection)
# Fuente  : custom (escrito por el TFG)
# Objetivo: ARCHIVAR el material recolectado con un METODO PROPIO, SIN utilidad
#           estandar de archivado (ni tar/zip/gzip) y SIN binario externo: se
#           implementa con BUILTINS de bash (`read`/`printf`/redireccion). Es el
#           TERCER VERTICE del trio de archivo:
#             - ATA030/T1560.001 utility (tar)      -> DETECTADO por execve
#             - ATA013/T1560.002 library (python3)  -> NO detectado (punto ciego 92600)
#             - ATA034/T1560.003 custom (builtins)  -> probamos SI deja senal
# Destino : /home/angel/lab-attack/ATA034/collected_ATA034.arc (+ reconstructed/)
# Ejecuta : desde /home/angel/lab-attack/ATA034 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el material, el archivo y la reconstruccion DEBEN quedar bajo
#     $HOME/lab-attack/ATA034/;
#   - JAMAS se archiva /etc, el home real ni datos reales.
#
# Telemetria esperada (ver README §5):
#   - NO se declara senal audit_exe: el METODO PROPIO no usa binario externo
#     -> el archivado en si NO deja execve (punto ciego por AUSENCIA de
#     telemetria de herramienta, distinto del silenciamiento 92600 de ATA013).
#   - las ESCRITURAS del .arc en la carpeta del ataque -> watch 80790/80781
#     (AMBIGUA -> artefacto).
#   - PRUEBA DE "SIN BINARIO EXTERNO": el bucle de archivado se ejecuta con
#     PATH=/nonexistent; si necesitase cualquier binario externo FALLARIA.
#
# Prueba de exito (INDEPENDIENTE de la alerta): el .arc tiene formato propio
#   (cabecera MAGIC) y la RECONSTRUCCION reproduce los 3 ficheros con sha256
#   identico al original (3/3).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA034"
STAGE="${BASE}/staging"
ARC="${BASE}/collected_ATA034.arc"
OUTDIR="${BASE}/reconstructed"
MAGIC="ATA034-CUSTOM-ARCHIVE v1"
MARK=$'\x1f'   # separador de unidad (US): marca cada linea de contenido

echo "ATA034 · T1560.003 Archive via Custom Method (builtins, sin utilidad) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in mkdir sha256sum awk cat; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible (fase de semilla/evidencia)" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: material, archivo y reconstruccion bajo la carpeta del ataque.
for d in "$STAGE" "$ARC" "$OUTDIR"; do
  case "$d" in
    "$HOME/lab-attack/ATA034"*) : ;;
    *) echo "ERROR: ruta '$d' fuera de lab-attack/ATA034 (abortado por seguridad)" >&2; exit 1 ;;
  esac
done
case "$BASE" in
  "$HOME/lab-attack/ATA034"*) : ;;
  *) echo "ERROR: BASE fuera de lab-attack/ATA034; ABORTADO" >&2; exit 1 ;;
esac

# 0) MATERIAL recolectado (datos de juguete) que el atacante va a archivar.
mkdir -p "$STAGE"
[ -f "$STAGE/informe_interno.txt" ] || cat > "$STAGE/informe_interno.txt" <<'TXT'
Informe interno simulado: resumen de negocio Q3 (datos de juguete).
Contacto: direccion@empresa-simulada.example
TXT
[ -f "$STAGE/clientes.csv" ] || cat > "$STAGE/clientes.csv" <<'CSV'
id,cliente,facturacion_eur
1001,Acme Iberica SL,18450
1002,Comercial Delta SA,9230
CSV
[ -f "$STAGE/credenciales_servicio.txt" ] || cat > "$STAGE/credenciales_servicio.txt" <<'TXT'
usuario=svc_backup
token_simulado=ZZZZ-9999
TXT

FILES=(informe_interno.txt clientes.csv credenciales_servicio.txt)

# 1) ARCHIVADO CON METODO PROPIO (SOLO BUILTINS).
#    Formato propio (contenedor casero), NO tar/zip/gzip:
#      MAGIC
#      FILE <nombre>
#      <US><linea_invertida>   (una por linea)
#      END <nombre> <nlineas>
#    La "codificacion" es invertir cada linea; el enmarcado es propio. Si en el
#    bucle se invocase CUALQUIER binario externo, PATH=/nonexistent lo haria
#    fallar -> la prueba demuestra que NO se uso ningun binario externo.
SAVE_PATH="$PATH"
PATH=/nonexistent
: > "$ARC"
printf '%s\n' "$MAGIC" >> "$ARC"
for f in "${FILES[@]}"; do
  printf 'FILE %s\n' "$f" >> "$ARC"
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    rev=""
    i=${#line}
    while [ "$i" -gt 0 ]; do
      i=$((i - 1))
      rev+="${line:$i:1}"
    done
    printf '%s%s\n' "$MARK" "$rev" >> "$ARC"
  done < "${STAGE}/${f}"
  printf 'END %s %s\n' "$f" "$n" >> "$ARC"
done
PATH="$SAVE_PATH"

echo "--- cabecera del archivo propio ---"
head -n 6 "$ARC"
echo "--- sha256 del archivo propio ---"
sha256sum "$ARC"

# 2) RECONSTRUCCION (con el MISMO metodo propio: parsear el contenedor).
mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/* 2>/dev/null || true
name=""
while IFS= read -r line; do
  case "$line" in
    "$MAGIC") continue ;;
    "FILE "*) name="${line#FILE }"; : > "${OUTDIR}/${name}" ;;
    "END "*) name="" ;;
    *)
      if [ -n "$name" ]; then
        revl="${line:1}"
        orig=""
        j=${#revl}
        while [ "$j" -gt 0 ]; do
          j=$((j - 1))
          orig+="${revl:$j:1}"
        done
        printf '%s\n' "$orig" >> "${OUTDIR}/${name}"
      fi
      ;;
  esac
done < "$ARC"

# 3) PRUEBA DEL EFECTO (independiente de la alerta): sha256 original == reconstruido.
ok=0
for f in "${FILES[@]}"; do
  s_src=$(sha256sum "${STAGE}/${f}" | awk '{print $1}')
  s_out=$(sha256sum "${OUTDIR}/${f}" | awk '{print $1}')
  if [ "$s_src" = "$s_out" ] && [ -n "$s_src" ]; then ok=$((ok + 1)); fi
done
echo "--- estado final ---"
ls -l "$OUTDIR"
echo "reconstruidos_sha256_ok=${ok}/3"
echo "nota: el ARCHIVADO se hizo con PATH=/nonexistent (solo builtins; ningun binario externo)"
if [ "$ok" -eq 3 ] && head -n 1 "$ARC" | grep -q "ATA034-CUSTOM-ARCHIVE"; then
  echo "ARCHIVE_CUSTOM=OK (formato propio + reconstruccion 3/3 con sha256 identico; sin binario externo)"
else
  echo "ARCHIVE_CUSTOM=FALLO (revisar formato/reconstruccion)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
