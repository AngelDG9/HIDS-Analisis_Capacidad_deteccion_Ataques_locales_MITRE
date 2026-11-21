#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inventario_artifacts_velociraptor.py - inventario REAL de los artifacts `Linux.*` y `Generic.*` del binario de Velociraptor.

Ejecuta `velociraptor query "SELECT ... FROM artifact_definitions()"` en la VM Linux (por SSH, sin servidor) y lo clasifica con un
criterio escrito y comprobable por el texto de la definicion (NO por la documentacion):
  clase:  deteccion  = el artifact marca/clasifica como sospechoso (Detection.*, Yara, Quarantine, SSHBruteforce, AnomalousFiles...)
          telemetria = registra continuamente actividad (type CLIENT_EVENT: Events.*) o instantanea del sistema (Sys.*, Network.*, Pslist...)
          forense    = recolecta artefactos bajo demanda (Forensics.*, Search.*, Applications.*, Triage.*)
          otro       = utilidades/mantenimiento
  origen: auditd (audit()/auditctl), journal, ebpf, procfs (pslist/proc), ficheros (glob/parse_*), red (netstat/pcap), otro
  modifica_el_sistema: si la definicion INSTALA reglas (auditctl -a ...) o ejecuta cambios -> importa para «telemetria identica a Wazuh».
Uso: python inventario_artifacts_velociraptor.py --out Soporte/Laboratorio/velociraptor/inventario_artifacts_linux.csv
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SSH = r"C:\Program Files\Git\usr\bin\ssh.exe"
KEY = os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519_tfg_lab")
Q = ("SELECT name, type, description, "
     "raw AS fuentes FROM artifact_definitions() WHERE name =~ '^(Linux|Generic)\\\\.'")


def clasifica(name, tipo, texto):
    n = name.lower()
    if re.search(r"remediation|bashshell|installdeb|rekey|cleanuptemp|fetchbinary|\.utils\.", n):
        clase = "respuesta"            # ejecuta/cambia cosas: no es deteccion ni telemetria (verificacion independiente 2026-11-21)
    elif re.search(r"detection|yara|bruteforce|anomalous|ransom|malware", n):
        clase = "deteccion"
    elif tipo.lower() == "client_event" or ".events." in n or re.search(r"\.sys\.|\.network\.|pslist|netstat|\.proc\.|\.mounts|\.users\.|\.ssh\.|crontab|services|bashhistory", n):
        clase = "telemetria"
    elif re.search(r"forensic|search|applications|triage|ntfs|registry|mft|evtx", n):
        clase = "forense"
    else:
        clase = "otro"
    t = texto.lower()
    origen = []
    for k, pat in (("auditd", r"audit\(|auditctl|audit\.log"), ("journal", r"journal"), ("ebpf", r"ebpf|bpf"),
                   ("procfs", r"pslist|/proc/|proc\.|process\.|pids\("), ("red", r"netstat|pcap|connections|dns|arp"),
                   ("ficheros", r"glob\(|parse_|read_file|filesystem|stat\(")):
        if re.search(pat, t):
            origen.append(k)
    perm_escribe = bool(re.search(r"FILESYSTEM_WRITE|MACHINE_STATE|SERVER_ADMIN", texto))
    modifica = "si" if ((re.search(r"auditctl", t) and '"-a"' in t) or perm_escribe or re.search(r"pcap|packetcapture|remediation|installdeb|rekey|bashshell|cleanuptemp|fetchbinary", n)) else "no"
    return clase, "|".join(origen) or "otro", modifica


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.65.129")
    ap.add_argument("--out", default=os.path.join(REPO, "Soporte", "Laboratorio", "velociraptor", "inventario_artifacts_linux.csv"))
    a = ap.parse_args()
    p = subprocess.run([SSH, "-q", "-i", KEY, "-o", "BatchMode=yes", "angel@" + a.ip, "/usr/local/bin/velociraptor query \"%s\" --format json" % Q.replace("\\\\", "\\\\\\\\")],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    txt = p.stdout
    i = txt.find("[")
    filas = []
    dec = json.JSONDecoder()
    pos = i
    while 0 <= pos < len(txt):                      # la consulta puede devolver varios arrays JSON seguidos
        try:
            obj, end = dec.raw_decode(txt, pos)
        except ValueError:
            break
        filas += obj if isinstance(obj, list) else [obj]
        pos = txt.find("[", end)
    if not filas:
        sys.exit("sin filas: %s" % p.stderr[-300:])
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        fh.write("# inventario_artifacts_linux.csv | Velociraptor v0.77.3 (binario linux-amd64) | artifacts Linux.* y Generic.* | extraido con `velociraptor query ... artifact_definitions()` en la VM | clasificacion por texto de la definicion (script inventario_artifacts_velociraptor.py)\n")
        w.writerow(["name", "tipo", "clase", "origen_datos", "modifica_el_sistema", "descripcion_1a_linea"])
        for r in sorted(filas, key=lambda x: x["name"]):
            clase, origen, modifica = clasifica(r["name"], r.get("type", ""), (r.get("fuentes") or "") + " " + (r.get("description") or ""))
            desc = (r.get("description") or "").strip().split("\n")[0][:160].replace(",", ";")
            w.writerow([r["name"], r.get("type", ""), clase, origen, modifica, desc])
    print("artifacts=%d -> %s" % (len(filas), a.out))


if __name__ == "__main__":
    main()
