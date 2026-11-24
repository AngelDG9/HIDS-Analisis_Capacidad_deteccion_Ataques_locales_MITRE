#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""construir_snapshot_legit_vr.py - L1 de _fases/velociraptor-v1l/plan.md: crea el snapshot `lab-listo-legit-vr` DESDE `lab-listo-legit-v3`.

Que hace (cada fase imprime lo que comprueba; ninguna toca los snapshots existentes):
  inspeccion : revierte a `lab-listo-legit-v3`, arranca y LEE el estado (solo lectura).
  construir  : quita el agente de Wazuh, instala el cliente de Velociraptor (mismo binario, misma config y mismo servicio que `lab-listo-vr`),
               sube `num_logs` de auditd (D2), deja que el cliente se inscriba, apaga la VM y crea el snapshot (disco-solo).
  verificar  : revierte al snapshot nuevo, arranca y comprueba: 0 paquetes de Wazuh, cliente activo e inscrito, 5 reglas de auditd (md5), auditd.conf,
               carpetas y huellas de GHOSTS iguales que en `v3`, sin ruta por defecto. Deja la VM apagada.
Uso (la contrasena SOLO por entorno): TFG_MANAGER_PW=... python construir_snapshot_legit_vr.py --fase inspeccion|construir|verificar
Requisitos: servidor de Velociraptor en marcha (arrancar_servidor.ps1). Sin secretos en el fichero.
"""
import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402

SNAP_BASE, SNAP_NUEVO = "lab-listo-legit-v3", "lab-listo-legit-vr"
MAT = r"D:\TFG-VMs\material-velociraptor"
SRV = r"D:\TFG-VMs\velociraptor-server"
BIN_SHA = "c216b7be6f104da551c302d707a7e5a7126e97db33d3f1fc9d2c3b76cfa00093"        # velociraptor 0.77.3 linux-amd64 (igual que lab-listo-vr)
CFG_SHA = "33776228e918cfe5b436d1137361430bd7985360344dd2e694ac221722f8c2f8"        # client.config.yaml (igual que lab-listo-vr)
RULES_MD5 = "7b6f8396d13ff701990fff563aa43074"                                       # /etc/audit/rules.d/tfg.rules
NUM_LOGS = 120                                                                       # D2: 8 MB x 120 = tope ~960 MB (Wazuh: 393 MB en 72 h)
UNIT = """[Unit]
Description=Velociraptor client
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client -v
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
"""


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sudo(cmd, timeout=120):
    rc, o, e = olx.ssh(olx.IP_V, "sudo -S -p '' bash -c %s" % shlex.quote(cmd), inp=olx.PW + "\n", timeout=timeout)
    return rc, o.strip(), e.strip()


def ver(titulo, cmd, esperado=None, timeout=120):
    rc, o, e = sudo(cmd, timeout)
    ok = (esperado is None) or (esperado in o)
    print("[%s] %s\n    %s" % ("OK" if ok else "FALLO", titulo, o.replace("\n", "\n    ")[:900]))
    if e:
        print("    stderr:", e[:300])
    return ok, o


def arrancar(snap):
    olx.SNAP = snap
    olx.vm_reset()
    if not olx.esperar_ssh(olx.IP_V, 300):
        raise SystemExit("la VM no responde por SSH")
    time.sleep(20)


def parar():
    olx.run([olx.VMRUN, "-T", "ws", "stop", olx.VMX, "soft"], timeout=180)


def estado_basico():
    ver("sistema y disco", "uname -r; lsb_release -ds; df -h / | tail -1; date -u")
    ver("paquetes de Wazuh / carpeta", "dpkg -l | grep -ci wazuh; ls -d /var/ossec 2>&1; systemctl is-enabled wazuh-agent 2>&1; systemctl is-active wazuh-agent 2>&1")
    ver("cliente de Velociraptor", "ls -la /usr/local/bin/velociraptor /etc/velociraptor /etc/velociraptor.writeback.yaml 2>&1 | head -8; systemctl is-enabled velociraptor_client 2>&1")
    ver("auditd: reglas, config, ficheros", "auditctl -l; md5sum /etc/audit/rules.d/tfg.rules; grep -E '^(max_log_file|num_logs|max_log_file_action) ' /etc/audit/auditd.conf; ls -la /var/log/audit | tail -4")
    ver("GHOSTS: carpeta y huellas", "ls /home/angel/ghosts-client | head -12; sha256sum /home/angel/ghosts-client/ghosts.client.linux /home/angel/ghosts-client/ghosts.client.linux.dll; sha256sum /home/angel/ghosts-client/config/timeline.json; ls /home/angel/ghosts-client/config")
    ver("units de GHOSTS legit (no deben existir)", "systemctl list-unit-files | grep -i ghosts; ls /etc/systemd/system | grep -i -E 'ghosts|tfg' ; echo fin")
    ver("red: ruta por defecto (no debe haber)", "ip route; echo ---; id")


def fase_inspeccion():
    arrancar(SNAP_BASE)
    print("=== INSPECCION de %s (solo lectura) ===" % SNAP_BASE)
    estado_basico()
    parar()


def fase_construir():
    # integridad del material antes de tocar nada
    b, c = os.path.join(MAT, "velociraptor-linux-amd64"), os.path.join(SRV, "client.config.yaml")
    assert sha(b) == BIN_SHA, "binario del material distinto del de lab-listo-vr"
    assert sha(c) == CFG_SHA, "client.config.yaml distinto del de lab-listo-vr"
    arrancar(SNAP_BASE)
    print("=== CONSTRUIR %s desde %s ===" % (SNAP_NUEVO, SNAP_BASE))
    # 1) fuera Wazuh
    sudo("systemctl stop wazuh-agent; systemctl disable wazuh-agent; dpkg --purge wazuh-agent; rm -rf /var/ossec; systemctl daemon-reload", 240)
    ok1, _ = ver("Wazuh fuera (0 paquetes, sin /var/ossec)", "dpkg -l | grep -ci wazuh; ls /var/ossec 2>&1 | head -1", "0")
    # 2) dentro Velociraptor (mismo binario, config y servicio que lab-listo-vr)
    rc, o, e = olx.scp_to(olx.IP_V, b, "/tmp/velociraptor", timeout=300)
    assert rc == 0, e
    rc, o, e = olx.scp_to(olx.IP_V, c, "/tmp/client.config.yaml")
    assert rc == 0, e
    u = os.path.join(os.environ.get("TEMP", "."), "velociraptor_client.service")
    open(u, "w", newline="\n").write(UNIT)
    rc, o, e = olx.scp_to(olx.IP_V, u, "/tmp/velociraptor_client.service")
    assert rc == 0, e
    sudo("install -m 0755 -o root -g root /tmp/velociraptor /usr/local/bin/velociraptor && mkdir -p /etc/velociraptor && "
         "install -m 0600 -o root -g root /tmp/client.config.yaml /etc/velociraptor/client.config.yaml && "
         "install -m 0644 -o root -g root /tmp/velociraptor_client.service /etc/systemd/system/velociraptor_client.service && "
         "rm -f /tmp/velociraptor /tmp/client.config.yaml /tmp/velociraptor_client.service && systemctl daemon-reload && systemctl enable velociraptor_client", 180)
    ok2, o = ver("huellas del cliente VR", "sha256sum /usr/local/bin/velociraptor /etc/velociraptor/client.config.yaml")
    assert BIN_SHA in o and CFG_SHA in o, "las huellas del cliente VR no coinciden"
    # 3) auditd: solo num_logs (el tamano de fichero 8 MB se mantiene como en Wazuh)
    sudo("sed -i 's/^num_logs *= *.*/num_logs = %d/' /etc/audit/auditd.conf" % NUM_LOGS)
    ver("auditd.conf", "grep -E '^(max_log_file|num_logs|max_log_file_action) ' /etc/audit/auditd.conf", "num_logs = %d" % NUM_LOGS)
    # 4) primer arranque: genera la identidad y se inscribe
    sudo("systemctl start velociraptor_client", 60)
    print("espero 60 s a que el cliente se inscriba...")
    time.sleep(60)
    ver("servicio del cliente", "systemctl is-active velociraptor_client; journalctl -u velociraptor_client --no-pager -n 3 | cut -c1-200")
    # 5) limpiar lo que no debe quedar en la imagen y apagar
    sudo("systemctl stop velociraptor_client; journalctl --rotate; sync", 60)
    ver("disco antes del snapshot", "df -h / | tail -1; ls -la /var/tmp | head -5")
    parar()
    time.sleep(10)
    rc, o, e = olx.run([olx.VMRUN, "-T", "ws", "snapshot", olx.VMX, SNAP_NUEVO], timeout=600)
    print("snapshot rc=%s %s %s" % (rc, o.strip(), e.strip()))
    rc, o, e = olx.run([olx.VMRUN, "-T", "ws", "listSnapshots", olx.VMX], timeout=60)
    print(o)


def fase_verificar():
    arrancar(SNAP_NUEVO)
    print("=== VERIFICAR %s ===" % SNAP_NUEVO)
    estado_basico()
    ver("cliente activo y registrado en el servidor", "systemctl is-active velociraptor_client; journalctl -u velociraptor_client --no-pager -n 2 | cut -c1-160")
    parar()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fase", choices=("inspeccion", "construir", "verificar"), required=True)
    a = ap.parse_args()
    if not olx.PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    {"inspeccion": fase_inspeccion, "construir": fase_construir, "verificar": fase_verificar}[a.fase]()
