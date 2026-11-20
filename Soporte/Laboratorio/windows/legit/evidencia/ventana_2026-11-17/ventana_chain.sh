#!/bin/bash
# VENTANA LEGITIMA WINDOWS DE 72 h: t0 = 2026-11-17T00:00:00Z, t1 = 2026-11-20T00:00:00Z.
# La contrasena llega por la variable de entorno TFG_MANAGER_PW (nunca en este fichero).
set -u
L=/d/TFG-VMs/lab-logs/ventana_20261117.txt
R=/d/TFG/HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE
cd "$R" || exit 1
CTL=Soporte/Laboratorio/windows/windows_legit_host_control.ps1
VR="/c/Program Files/VMware/VMware Workstation/vmrun.exe"
T0=2026-11-17T00:00:00Z; T1=2026-11-20T00:00:00Z
FECHA=2026-11-17
log() { echo "[$(date -u +%FT%TZ)] $*" >> "$L"; }
wait_until() { t=$(date -u -d "$1" +%s); while [ "$(date -u +%s)" -lt "$t" ]; do sleep 20; done; }
ctl() { powershell -NoProfile -ExecutionPolicy Bypass -File "$CTL" -Phase "$@" >> "$L" 2>&1; }
log "VENTANA 72 h programada. t0=$T0 t1=$T1. PW_longitud=${#TFG_MANAGER_PW}. Preparacion a las 22:15Z (23:15 local)"
[ -z "${TFG_MANAGER_PW:-}" ] && { log "FALLO: sin TFG_MANAGER_PW"; exit 1; }
wait_until "2026-11-16 22:15:00"
log "arrancando manager"
"$VR" -T ws start "D:\TFG-VMs\wazuh-server\wazuh-server.vmx" nogui >> "$L" 2>&1
K="$HOME/.ssh/id_ed25519_tfg_lab"
for i in $(seq 1 40); do ssh -q -i "$K" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new angel@192.168.65.128 'echo OK' 2>/dev/null | grep -q OK && break; sleep 10; done
rc=1
for i in $(seq 1 24); do
  log "PREP intento $i"
  if [ $i -le 12 ]; then ctl prep; rc=$?; else
    log "SALIDA DE EMERGENCIA: tras 24 min sin memoria suficiente se baja el minimo de RAM a 1100 MB (DESVIACION DECLARADA)"
    ctl prep -RamMinMb 1100; rc=$?
  fi
  log "PREP rc=$rc"; [ $rc -eq 0 ] && break
  log "AVISO: reintento en 2 min (si es G-W12 por memoria: cerrar aplicaciones)"; sleep 120
done
[ $rc -ne 0 ] && { log "PREP FALLO tras reintentos: ventana NO lanzada (esperando revision)"; exit 1; }
wait_until "2026-11-16 23:40:00"
log "ARM"; ctl arm -T0 $T0 -T1 $T1; rc=$?; log "ARM rc=$rc"
if [ $rc -ne 0 ]; then log "ARM fallo: reintento con RAM minima 1100 (desviacion declarada)"; ctl arm -T0 $T0 -T1 $T1 -RamMinMb 1100; rc=$?; log "ARM(2) rc=$rc"; fi
[ $rc -ne 0 ] && { log "ARM FALLO: ventana NO lanzada (esperando revision)"; exit 1; }
log "WATCH_LOOP arranca (144 chequeos; termina en t1)"
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte/Laboratorio/windows/legit/watch_loop.ps1 >> "$L" 2>&1
log "WATCH_LOOP fin rc=$?"
wait_until "2026-11-20 00:02:00"
log "COSECHA"; ctl cosecha; rc=$?; log "COSECHA rc=$rc"; [ $rc -ne 0 ] && { log "COSECHA FALLO: parado (VM encendida, esperando revision)"; exit 1; }
log "CRUDO"; ctl crudo; rc=$?; log "CRUDO rc=$rc"; [ $rc -ne 0 ] && { log "CRUDO FALLO: parado (esperando revision)"; exit 1; }
log "ANALISIS"
python -I _artefactos/scripts/analizar_ensayo_windows.py --crudo D:/TFG-VMs/legitimo-windows-$FECHA/crudo --cosecha D:/TFG-VMs/legitimo-windows-$FECHA/cosecha --t0 $T0 --t1 $T1 --out /d/TFG-VMs/lab-logs/informe_VENTANA_$FECHA.md >> "$L" 2>&1
log "ANALISIS rc=$?"
log "CLEANUP"; ctl cleanup; log "CLEANUP rc=$?"
git -c core.autocrlf=false checkout -- Soporte/Laboratorio/windows/recetas/bloques_windows.env Soporte/Laboratorio/windows/recetas/calendario_windows.json >> "$L" 2>&1
log "VENTANA TERMINADA (falta el snapshot final y el analisis, a mano)"
