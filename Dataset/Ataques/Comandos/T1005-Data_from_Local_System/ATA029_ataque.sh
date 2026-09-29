#!/usr/bin/env bash
# ============================================================================
# ATA029 · T1005 Data from Local System — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1005 Data from Local System (tactica Collection)
# Fuente  : custom (ART tiene atomicas Linux adaptables; se escribe guion propio
#           KISS para no depender del clon de ART ni de red)
# Objetivo: RECOLECCION DIRIGIDA de ficheros locales concretos (una LISTA
#           DECLARADA, no una busqueda exhaustiva como T1119/ATA012): los datos
#           de juguete viven en /home/angel/lab-legit (VIGILADO) y se copian a
#           la carpeta del ataque.
# Destino : LECTURA en /home/angel/lab-legit/srv_data (watch -p wa: NO audita lectura)
#           COPIA   en /home/angel/lab-attack/ATA029/loot/
# Ejecuta : desde /home/angel/lab-attack/ATA029 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - la salida DEBE quedar bajo $HOME/lab-attack/ATA029/;
#   - la lista de origen DEBE estar bajo lab-legit/srv_data;
#   - solo se LEE de lab-legit; JAMAS /etc, PAM ni datos reales.
#
# Telemetria esperada (ver README §5):
#   - execve de cp -> 80792 (deteccion; senal T1005-S1) anclado por T1005-S2.
#   - SIEMBRA + escrituras en lab-legit -> watch 80790/80781 -> AMBIGUA.
#   - LECCION "leer no deja rastro": `-p wa` NO audita la lectura -> el hecho de
#     leer lab-legit no genera alerta; la deteccion es el execve del lector.
#
# Prueba de exito (INDEPENDIENTE de la alerta): cada fichero declarado esta en
#   loot/ con el MISMO sha256 que el original y el total recolectado coincide.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA029"
SRCDIR="${HOME}/lab-legit/srv_data"
OUT="${BASE}/loot"
FILES="empleados_2026.csv notas_direccion.txt config_servicio.conf"

echo "ATA029 · T1005 Data from Local System (recoleccion dirigida con cp) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in cp mkdir sha256sum awk grep; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAILES: origen bajo lab-legit/srv_data y salida bajo lab-attack/ATA029.
case "$SRCDIR" in
  "$HOME/lab-legit/srv_data") : ;;
  *) echo "ERROR: origen '$SRCDIR' no es lab-legit/srv_data (abortado por seguridad)" >&2; exit 1 ;;
esac
case "$OUT" in
  "$HOME/lab-attack/ATA029"*) : ;;
  *) echo "ERROR: destino '$OUT' no esta bajo lab-attack/ATA029 (abortado por seguridad)" >&2; exit 1 ;;
esac

# 0) SEMILLA de los datos locales SIMULADOS (datos de juguete; escena de empresa).
#    lab-listo parte con lab-legit vacio -> se siembra aqui lo que el atacante
#    recolecta. Escritura en ruta VIGILADA (watch) -> efecto declarado AMBIGUA.
mkdir -p "$SRCDIR"
[ -f "$SRCDIR/empleados_2026.csv" ] || cat > "$SRCDIR/empleados_2026.csv" <<'CSV'
id,nombre,departamento,salario_eur
1,Ana Ruiz,Ingenieria,42000
2,Luis Pena,Ventas,38000
3,Marta Gil,Finanzas,45500
CSV
[ -f "$SRCDIR/notas_direccion.txt" ] || cat > "$SRCDIR/notas_direccion.txt" <<'TXT'
Acta de direccion (simulada): objetivo de facturacion Q4 = 1.250.000 EUR.
TXT
[ -f "$SRCDIR/config_servicio.conf" ] || cat > "$SRCDIR/config_servicio.conf" <<'CONF'
[servicio]
host=10.0.0.12
usuario_svc=svc_lectura
token_simulado=AAAA-BBBB-CCCC
CONF

# 1) RECOLECCION DIRIGIDA: solo los ficheros de la LISTA DECLARADA.
mkdir -p "$OUT"
echo "--- ficheros declarados en la lista: $FILES ---"
for f in $FILES; do
  cp -f "${SRCDIR}/${f}" "${OUT}/${f}"
done

# 2) PRUEBA DEL EFECTO (independiente de la alerta): sha256 origen == copia.
ok=0
total=0
for f in $FILES; do
  total=$((total + 1))
  s_src=$(sha256sum "${SRCDIR}/${f}" | awk '{print $1}')
  s_dst=$(sha256sum "${OUT}/${f}" | awk '{print $1}')
  if [ "$s_src" = "$s_dst" ] && [ -n "$s_src" ]; then ok=$((ok + 1)); fi
done
echo "--- estado final ---"
ls -l "$OUT"
n_recolectados=$(ls -1 "$OUT" | wc -l)
echo "ficheros_recolectados=${n_recolectados}/3"
echo "coincidencias_sha256=${ok}/3"
if [ "$ok" -eq 3 ] && [ "$n_recolectados" -eq 3 ]; then
  echo "RECOLECCION=OK (3/3 ficheros dirigidos copiados con sha256 identico)"
else
  echo "RECOLECCION=FALLO (revisar recoleccion)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
