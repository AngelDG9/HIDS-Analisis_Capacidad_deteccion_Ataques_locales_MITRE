#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""orquestar_ataques_linux.py - F3: repite los ataques Linux (VERSION 2) con lanzador local.

Que hace (una ventana = un ataque x una iteracion), igual que el runbook de
`Soporte/Ataques/piloto_procedimiento.md` PERO:
  * el ataque NO cuelga de una sesion SSH: SSH solo lo inicia y el proceso lo ejecuta una
    unidad transitoria de systemd (`systemd-run --uid=angel --pipe --wait`), como el legitimo;
  * el manager lleva `logall_json=yes` (se guarda TODO: archives + alerts);
  * se guarda por ventana: salida del ataque, t0/t1, alertas (Detalle/raw CSV) y las lineas
    CRUDAS de alerts y archives del agente 001 en [t0-60 s, t1+120 s].

Fases (`--fase`):  pre  = logall_json on + comprobaciones;  run = ventanas;  post = copia
cruda del manager (sha256) + logall_json off.   La contrasena de las VMs SOLO por la variable de
entorno TFG_MANAGER_PW (nunca en ficheros, ni en argumentos de proceso: viaja por stdin).

Salidas: <--out>/Logs/<tag>/..., <--out>/CSV/..., <--out>/windows_index.csv y, fuera del repo,
<--raw>/<tag>_{alerts,archives}_001.jsonl.gz.   Reanudable: salta lo ya `OK` en el indice.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import glob
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SSH = r"C:\Program Files\Git\usr\bin\ssh.exe"
SCP = r"C:\Program Files\Git\usr\bin\scp.exe"
KEY = os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519_tfg_lab")
VMRUN = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
VMX = r"D:\TFG-VMs\victima-linux\victima-linux.vmx"
SNAP = "lab-listo"
IP_V, IP_M, IP_H = "192.168.65.129", "192.168.65.128", "192.168.65.1"
LAB = "/home/angel/lab-attack"
AGENTE = "001"
AGENTE_NOMBRE = "victima-linux"
CMD_DIR = os.path.join(REPO, "Dataset", "Ataques", "Comandos")
SINK = os.path.join(REPO, "Soporte", "Ataques", "receiver", "sink_http.py")
SLICER = os.path.join(REPO, "Soporte", "Ataques", "v2", "slice_ventana_manager.py")
LOGALL = os.path.join(REPO, "Soporte", "Laboratorio", "ghosts", "logall_json_ctl.sh")
SETTLE_S = 90          # H2: asentamiento tras agente Active, antes de t0

# contrasena de sudo: la lee el propio script por stdin (primera linea)
SUDO_STDIN = {"ATA024", "ATA027", "ATA037", "ATA044", "ATA038"}
# el literal historico es `echo pw | sudo -S bash ATAxxx_ataque.sh` (todo el script como root)
SUDO_WRAPPER = {"ATA004", "ATA054", "ATA055"}
# receptores del host (HTTP 9090 + TCP 9091); se levantan para estos
SINK_ATAS = {"ATA008", "ATA009", "ATA010", "ATA019", "ATA020", "ATA021", "ATA023", "ATA026",
             "ATA041", "ATA042", "ATA043", "ATA048", "ATA049", "ATA050"}
# infraestructura aun no montada para el orquestador: se anotan como PENDIENTE (no se inventan)
# (vacio: los 10 casos que faltaban ya tienen su infraestructura: rsync, paquetes, rclone y reinicio)
PENDIENTE = {}

PW = os.environ.get("TFG_MANAGER_PW", "")
OUT = RAW = None
_LOG_FH = None


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    linea = "[%s] %s" % (now_utc(), msg)
    print(linea, flush=True)
    if _LOG_FH:
        _LOG_FH.write(linea + "\n")
        _LOG_FH.flush()


def run(cmd, inp=None, timeout=120, binary=False):
    """subprocess.run sin shell; devuelve (rc, stdout, stderr). Nunca lleva la contrasena en argv."""
    try:
        p = subprocess.run(cmd, input=(inp.encode() if isinstance(inp, str) else inp), capture_output=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b"") if binary else (e.stdout or b"").decode("utf-8", "replace"), "TIMEOUT"
    if binary:
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def _ssh_base(ip):
    return [SSH, "-q", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=6", "angel@" + ip]


def ssh(ip, remote, inp=None, timeout=120, binary=False):
    return run(_ssh_base(ip) + [remote], inp=inp, timeout=timeout, binary=binary)


def scp_to(ip, local, remote, recursive=False, timeout=120):
    cmd = [SCP, "-q", "-i", KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if recursive:
        cmd.append("-r")
    return run(cmd + [local, "angel@%s:%s" % (ip, remote)], timeout=timeout)


def scp_from(ip, remote, local, timeout=120):
    cmd = [SCP, "-q", "-i", KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
           "angel@%s:%s" % (ip, remote), local]
    return run(cmd, timeout=timeout)


def msudo(script: str, timeout=180, binary=False):
    """Ejecuta un script bash en el MANAGER como root (sudo -S; la contrasena va por stdin)."""
    b64 = base64.b64encode(script.encode()).decode()
    return ssh(IP_M, "sudo -S -p '' bash -c 'echo %s | base64 -d | bash'" % b64,
               inp=PW + "\n", timeout=timeout, binary=binary)


def mgr_now() -> str:
    rc, out, _ = ssh(IP_M, "date -u +%Y-%m-%dT%H:%M:%SZ", timeout=30)
    return out.strip() if rc == 0 and out.strip() else now_utc()


def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ----------------------------------------------------------------------------- especificaciones
def cargar_especificaciones():
    """Una entrada por (ata, variante): scripts del directorio de la tecnica + metadatos."""
    out = []
    for p in sorted(glob.glob(os.path.join(CMD_DIR, "T*", "ATA*_ataque.sh")) +
                    glob.glob(os.path.join(CMD_DIR, "T*", "ATA*_ataque_rev.sh"))):
        b = os.path.basename(p)
        ata = b.split("_")[0]
        rev = b.endswith("_ataque_rev.sh")
        d = os.path.dirname(p)
        out.append({"ata": ata, "variante": "rev" if rev else "base", "script": p, "dir": d,
                    "nombre": b, "clave": ata + ("_rev" if rev else "")})
    out.sort(key=lambda s: (s["ata"], s["variante"] == "rev"))
    return out


def ficheros_a_copiar(spec):
    d = spec["dir"]
    res = []
    for f in sorted(os.listdir(d)):
        fp = os.path.join(d, f)
        if os.path.isdir(fp) or "_esperado" in f or f.lower() == "readme.md" or "pre_registro" in f:
            continue
        res.append(fp)
    return res


def tag_de(spec, it):
    return "%s_rev%d" % (spec["ata"], it) if spec["variante"] == "rev" else "%s_iter%d" % (spec["ata"], it)


# ----------------------------------------------------------------------------- victima / agente
def vm_reset():
    run([VMRUN, "-T", "ws", "stop", VMX, "soft"], timeout=180)
    rc, o, e = run([VMRUN, "-T", "ws", "revertToSnapshot", VMX, SNAP], timeout=300)
    if rc != 0:
        raise RuntimeError("revert rc=%s %s %s" % (rc, o.strip(), e.strip()))
    rc, o, e = run([VMRUN, "-T", "ws", "start", VMX, "nogui"], timeout=300)
    if rc != 0:
        raise RuntimeError("start rc=%s %s %s" % (rc, o.strip(), e.strip()))


def esperar_ssh(ip, seg=300):
    t = time.time()
    while time.time() - t < seg:
        rc, out, _ = ssh(ip, "echo OK", timeout=20)
        if rc == 0 and "OK" in out:
            return True
        time.sleep(6)
    return False


def agente_activo() -> bool:
    rc, out, _ = msudo("/var/ossec/bin/agent_control -l", timeout=60)
    return bool(re.search(r"ID:\s*%s,\s*Name:\s*%s,.*Active" % (AGENTE, AGENTE_NOMBRE), out))


def esperar_agente(seg=360):
    t = time.time()
    while time.time() - t < seg:
        rc, out, _ = ssh(IP_V, "systemctl is-active wazuh-agent auditd", timeout=20)
        if rc == 0 and out.split().count("active") >= 2 and agente_activo():
            return True
        time.sleep(8)
    return False


def espacio_manager_gb() -> float:
    rc, out, _ = ssh(IP_M, "df -BG --output=avail / | tail -1", timeout=30)
    m = re.search(r"(\d+)", out or "")
    return float(m.group(1)) if m else 0.0


# ----------------------------------------------------------------------------- ventana
class Sink:
    def __init__(self, logfile):
        self.p = None
        self.logfile = logfile

    def start(self):
        self.p = subprocess.Popen([sys.executable, "-I", SINK, "--bind", IP_H, "--port", "9090",
                                   "--tcp-port", "9091", "--log", self.logfile],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except Exception:
                self.p.kill()


def lanzar_local(spec, modo, d_dest):
    """SSH solo INICIA; el ataque lo ejecuta una unidad de systemd (padre = systemd, no sshd)."""
    ata = spec["ata"]
    nombre = spec["nombre"]
    inner = "bash %s" % nombre
    if modo:
        inner += " " + modo
    if ata in SUDO_WRAPPER:
        inner = "sudo -S " + inner
    cmd = ("sudo -S -p '' systemd-run --uid=angel --gid=angel --pipe --wait --collect -q "
           "-p WorkingDirectory=%s %s" % (d_dest, inner))
    lineas = PW + "\n"                               # la 1a linea la consume el `sudo` exterior
    if ata in SUDO_STDIN or ata in SUDO_WRAPPER:
        lineas += PW + "\n"                          # la 2a la lee el propio ataque (stdin)
    return cmd, lineas


MATERIAL = r"D:\TFG-VMs\material-linux-v2"
RSYNC_CONF = """port = 9873
use chroot = no
address = 192.168.65.128
pid file = /tmp/rsyncd_tfg.pid
log file = /tmp/rsyncd_tfg.log
[share]
    path = /home/angel/lab-share/export
    read only = yes
[incoming]
    path = /home/angel/lab-share/incoming
    read only = no
"""
RSYNC_UP = """set -u
pkill -f rsyncd_tfg.conf 2>/dev/null; rm -rf /home/angel/lab-share /tmp/rsyncd_tfg.conf /tmp/rsyncd_tfg.log
mkdir -p /home/angel/lab-share/export/rrhh /home/angel/lab-share/export/finanzas /home/angel/lab-share/incoming
printf 'empleado,bruto_eur\\nA. Gomez,2450.00\\nB. Ruiz,2600.00\\nC. Soto,2300.00\\n' > /home/angel/lab-share/export/rrhh/nominas_2026.csv
printf 'trimestre,region,importe_eur\\n2026-Q3,Norte,121780.00\\n2026-Q3,Sur,98410.50\\n' > /home/angel/lab-share/export/finanzas/ventas_2026.csv
cat > /tmp/rsyncd_tfg.conf <<'EOF'
__CONF__
EOF
rsync --daemon --config=/tmp/rsyncd_tfg.conf
sleep 2
rsync --list-only rsync://192.168.65.128:9873/ && echo RSYNC_UP_OK
"""


def scp_many(ip, locales, remoto, timeout=300):
    cmd = [SCP, "-q", "-i", KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"] + list(locales) + ["angel@%s:%s" % (ip, remoto)]
    return run(cmd, timeout=timeout)


def rsync_up():
    rc, o, e = ssh(IP_M, "bash -s", inp=RSYNC_UP.replace("__CONF__", RSYNC_CONF.strip()), timeout=60)
    if "RSYNC_UP_OK" not in o:
        raise RuntimeError("no arranca el daemon rsync del manager: %s %s" % (o.strip()[-120:], e.strip()[-120:]))


def rsync_down(ldir):
    try:
        rc, o, e = ssh(IP_M, "find /home/angel/lab-share -type f -exec sha256sum {} + 2>/dev/null; pkill -f rsyncd_tfg.conf; "
                       "rm -rf /home/angel/lab-share /tmp/rsyncd_tfg.conf /tmp/rsyncd_tfg.pid /tmp/rsyncd_tfg.log", timeout=60)
        open(os.path.join(ldir, "recurso_remoto.txt"), "w", encoding="utf-8", newline="\n").write(o)
    except Exception as ex:                                  # noqa: BLE001
        log("rsync_down: %s" % ex)


def extras_pre(spec, d_dest):
    """Material fijado (URL + sha256 verificados en el host) que entra ANTES de t0."""
    ata, rev = spec["ata"], spec["variante"] == "rev"
    if ata == "ATA029" and rev:
        ssh(IP_V, "mkdir -p %s/ATA029_src %s/ATA029_pkgs" % (LAB, LAB))
        src = os.path.join(REPO, "Soporte", "Ataques", "atomic-red-team", "atomics", "T1005", "src")
        rc, o, e = scp_many(IP_V, [os.path.join(src, f) for f in ("art", "gta.db", "sqlite_dump.sh")], LAB + "/ATA029_src/")
        if rc != 0:
            raise RuntimeError("scp src ATA029: %s" % e)
        rc, o, e = scp_many(IP_V, sorted(glob.glob(os.path.join(MATERIAL, "sqlite_debs", "*.deb"))), LAB + "/ATA029_pkgs/")
        if rc != 0:
            raise RuntimeError("scp debs ATA029: %s" % e)
    if ata == "ATA049":
        import zipfile
        z = os.path.join(MATERIAL, "rclone", "rclone-v1.75.1-linux-amd64.zip")
        dst = os.path.join(MATERIAL, "rclone", "bin")
        os.makedirs(dst, exist_ok=True)
        with zipfile.ZipFile(z) as zf:
            with zf.open("rclone-v1.75.1-linux-amd64/rclone") as src_f, open(os.path.join(dst, "rclone"), "wb") as out_f:
                out_f.write(src_f.read())
        rc, o, e = scp_to(IP_V, os.path.join(dst, "rclone"), d_dest + "/rclone")
        if rc != 0:
            raise RuntimeError("scp rclone: %s" % e)
    if ata in ("ATA051", "ATA052", "ATA053"):
        ssh(IP_V, "mkdir -p /home/angel/lab-legit/tandaB_debs")
        rc, o, e = scp_many(IP_V, sorted(glob.glob(os.path.join(MATERIAL, "gui_debs", "*.deb"))), "/home/angel/lab-legit/tandaB_debs/", timeout=600)
        if rc != 0:
            raise RuntimeError("scp debs GUI: %s" % e)


def boot_id():
    rc, o, _ = ssh(IP_V, "cat /proc/sys/kernel/random/boot_id", timeout=20)
    return o.strip() if rc == 0 else ""


def esperar_reinicio(antes, seg=720):
    """ATA038: espera a que la victima vuelva con otro boot_id y el agente 001 Active."""
    t = time.time()
    while time.time() - t < seg:
        b = boot_id()
        if b and b != antes:
            if esperar_agente(420):
                return b
            raise RuntimeError("la victima reinicio pero el agente no vuelve a Active")
        time.sleep(6)
    raise RuntimeError("la victima no reinicia en %d s" % seg)


def ventana(spec, it, timeout_ataque):
    ata = spec["ata"]
    tag = tag_de(spec, it)
    ldir = os.path.join(OUT, "Logs", tag)
    os.makedirs(ldir, exist_ok=True)
    meta = {"tag": tag, "ata": ata, "variante": spec["variante"], "iter": it, "version": 2,
            "lanzador": "systemd-run --uid=angel --pipe --wait (SSH solo inicia)", "logall_json": "yes",
            "inicio_utc": now_utc(), "script_sha256": sha256_file(spec["script"])}
    sink = Sink(os.path.join(ldir, "sink.log")) if ata in SINK_ATAS else None
    t_ini = time.time()
    try:
        # no cruzar la medianoche UTC (el manager rota los diarios a las 00:00Z)
        ahora = dt.datetime.now(dt.timezone.utc)
        if ahora.hour == 23 and ahora.minute >= 50:
            esp = (dt.datetime.combine(ahora.date() + dt.timedelta(days=1), dt.time(0, 3),
                                       tzinfo=dt.timezone.utc) - ahora).total_seconds()
            log("espero %.0f s para no cruzar la medianoche" % esp)
            time.sleep(esp)
        if sink:
            sink.start()
        if ata in ("ATA039", "ATA040"):
            rsync_up()
        vm_reset()
        if not esperar_ssh(IP_V, 300):
            raise RuntimeError("la victima no responde por SSH tras el arranque")
        if not esperar_agente(420):
            raise RuntimeError("el agente 001 no llega a Active")
        log("%s agente Active; asentamiento %d s" % (tag, SETTLE_S))
        time.sleep(SETTLE_S)
        dv = ssh(IP_V, "date -u +%Y-%m-%dT%H:%M:%SZ", timeout=30)[1].strip()
        dm = mgr_now()
        meta["reloj_victima"], meta["reloj_manager"] = dv, dm
        d_dest = "%s/%s" % (LAB, ata)
        rc, o, e = ssh(IP_V, "mkdir -p %s" % d_dest)
        if rc != 0:
            raise RuntimeError("mkdir destino: %s" % e)
        for f in ficheros_a_copiar(spec):
            rc, o, e = scp_to(IP_V, f, d_dest + "/")
            if rc != 0:
                raise RuntimeError("scp %s: %s" % (os.path.basename(f), e))
        if ata == "ATA008":
            at = os.path.join(REPO, "Soporte", "Ataques", "atomic-red-team", "atomics", "T1048.002", "src")
            if os.path.isdir(at):
                scp_to(IP_V, at, d_dest + "/", recursive=True)      # deja ATA008/src/artifact
        if ata == "ATA047":                               # su prestaging arranca el sink dentro de la victima
            scp_to(IP_V, SINK, d_dest + "/")
        extras_pre(spec, d_dest)
        ssh(IP_V, "chmod +x %s/*.sh 2>/dev/null; true" % d_dest)
        rc, o, _ = ssh(IP_V, "sha256sum %s/%s" % (d_dest, spec["nombre"]))
        meta["sha256_en_victima"] = o.split()[0] if o.split() else ""
        if meta["sha256_en_victima"] != meta["script_sha256"]:
            raise RuntimeError("sha256 del script distinto entre repo y victima")
        with open(os.path.join(ldir, "sha256_artefacto.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("%s  %s\n" % (meta["script_sha256"], spec["nombre"]))

        # PRESTAGE (antes de t0): rev -> modo `prestage`; base con `_prestaging.sh`
        pres = None
        if spec["variante"] == "rev":
            pres = "bash %s prestage" % spec["nombre"]
        elif os.path.isfile(os.path.join(spec["dir"], "%s_prestaging.sh" % ata)):
            pres = "bash %s_prestaging.sh" % ata
        if pres:
            rc, o, e = ssh(IP_V, "cd %s && %s" % (d_dest, pres), inp=PW + "\n" + PW + "\n", timeout=300)
            open(os.path.join(ldir, "prestage.out"), "w", encoding="utf-8", newline="\n").write(o + e)
            meta["prestage_rc"] = rc
            if rc != 0:
                raise RuntimeError("prestage rc=%s" % rc)

        # VENTANA: lanzamiento local; t0 = la marca T0= que imprime el propio ataque
        modo = "attack" if spec["variante"] == "rev" else ""
        cmd, entrada = lanzar_local(spec, modo, d_dest)
        if ata == "ATA038":
            meta["boot_id_antes"] = boot_id()
        t_lanz = mgr_now()
        rc, o, e = ssh(IP_V, cmd, inp=entrada, timeout=timeout_ataque)
        meta["lanzamiento_rc"] = rc
        open(os.path.join(ldir, "ejecucion.out"), "w", encoding="utf-8", newline="\n").write(o + (("\n--STDERR--\n" + e) if e.strip() else ""))
        m = re.search(r"T0=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", o)
        t0 = m.group(1) if m else t_lanz
        meta["t0_fuente"] = "marca T0= del ataque" if m else "reloj del manager al lanzar"
        if ata == "ATA038":
            # t1 lo sella el operador TRAS la reconexion del agente (como en la version 1)
            meta["boot_id_despues"] = esperar_reinicio(meta.get("boot_id_antes", ""))
            time.sleep(20)
        else:
            # FIM forzado + 30 s, t1
            msudo("/var/ossec/bin/agent_control -r -u %s" % AGENTE, timeout=90)
            time.sleep(30)
        t1 = mgr_now()
        meta["t0"], meta["t1"] = t0, t1
        with open(os.path.join(ldir, "times.log"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("T0=%s\nT1=%s\nLANZADO_MANAGER=%s\nRELOJ_VICTIMA=%s\nRELOJ_MANAGER=%s\n" % (
                t0, t1, t_lanz, dv, dm))
        if spec["ata"] == "ATA024" and spec["variante"] == "rev":
            ssh(IP_V, "cd %s && bash %s cleanup" % (d_dest, spec["nombre"]), inp=PW + "\n" + PW + "\n", timeout=120)
        # esperar y extraer (v1: +60 s)
        time.sleep(60)
        dia = t0[:10]
        y, mo, dd = dia[:4], dt.datetime.strptime(dia, "%Y-%m-%d").strftime("%b"), dia[8:10]
        diario = "/var/ossec/logs/alerts/%s/%s/ossec-alerts-%s.json" % (y, mo, dd)
        rc, o, e = msudo("bash /home/angel/extract_window.sh %s %s %s %s %d; chmod a+r /tmp/%s_iter%d-Detalle*.csv" % (diario, t0, t1, ata, it, ata, it), timeout=240)
        meta["extraccion_rc"] = rc
        open(os.path.join(ldir, "extraccion.out"), "w", encoding="utf-8", newline="\n").write(o + e)
        os.makedirs(os.path.join(OUT, "CSV"), exist_ok=True)
        base = "%s_iter%d" % (ata, it) if spec["variante"] == "base" else "%s_rev%d" % (ata, it)
        for suf in ("Detalle.csv", "Detalle_raw.csv"):
            scp_from(IP_M, "/tmp/%s_iter%d-%s" % (ata, it, suf), os.path.join(OUT, "CSV", "%s-%s" % (base, suf)))
        det = os.path.join(OUT, "CSV", "%s-Detalle.csv" % base)
        meta["filas_detalle"] = max(0, sum(1 for _ in open(det, encoding="utf-8", errors="replace")) - 1) if os.path.isfile(det) else -1
        # lineas CRUDAS de alerts y archives del agente 001 (se guarda TODO)
        os.makedirs(RAW, exist_ok=True)
        d0 = (dt.datetime.strptime(t0, "%Y-%m-%dT%H:%M:%SZ") - dt.timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d1 = (dt.datetime.strptime(t1, "%Y-%m-%dT%H:%M:%SZ") + dt.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for kind in ("alerts", "archives"):
            rc, blob, e = ssh(IP_M, "sudo -S -p '' python3 /home/angel/slice_ventana_manager.py %s %s %s %s" % (kind, AGENTE, d0, d1),
                              inp=PW + "\n", timeout=300, binary=True)
            with gzip.GzipFile(os.path.join(RAW, "%s_%s_%s.jsonl.gz" % (tag, kind, AGENTE)), "wb", mtime=0) as gz:
                gz.write(blob)
            meta["lineas_%s" % kind] = blob.count(b"\n")
        meta["estado"] = "OK" if meta.get("lanzamiento_rc", 1) == 0 and meta["filas_detalle"] >= 0 else "REVISAR"
    except Exception as ex:                                  # noqa: BLE001 - se anota y se sigue
        meta["estado"] = "FALLO"
        meta["error"] = str(ex)[:300]
        log("%s FALLO: %s" % (tag, ex))
    finally:
        if sink:
            sink.stop()
        if ata in ("ATA039", "ATA040"):
            rsync_down(ldir)
        meta["fin_utc"] = now_utc()
        meta["segundos"] = round(time.time() - t_ini)
        with open(os.path.join(ldir, "lanzamiento.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=1)
    return meta


def indice_escribir(meta):
    p = os.path.join(OUT, "windows_index.csv")
    nuevo = not os.path.isfile(p)
    cols = ["tag", "ata", "variante", "iter", "estado", "t0", "t1", "lanzamiento_rc", "filas_detalle",
            "lineas_alerts", "lineas_archives", "segundos", "inicio_utc", "error"]
    with open(p, "a", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        if nuevo:
            w.writerow(cols)
        w.writerow([meta.get(c, "") for c in cols])


def indice_ok():
    p = os.path.join(OUT, "windows_index.csv")
    ok = set()
    if os.path.isfile(p):
        for r in csv.DictReader(open(p, encoding="utf-8")):
            if r["estado"] == "OK":
                ok.add(r["tag"])
    return ok


# ----------------------------------------------------------------------------- fases
def fase_pre():
    log("PRE: copia de logall_json_ctl.sh y del cortador al manager")
    scp_to(IP_M, LOGALL, "/home/angel/logall_json_ctl.sh")
    scp_to(IP_M, SLICER, "/home/angel/slice_ventana_manager.py")
    scp_to(IP_M, os.path.join(REPO, "_artefactos", "scripts", "extraer_alertas.py"), "/home/angel/extraer_alertas.py.nuevo")
    rc, o, _ = ssh(IP_M, "sha256sum /home/angel/extraer_alertas.py /home/angel/extraer_alertas.py.nuevo | awk '{print $1}' | uniq | wc -l", timeout=30)
    if o.strip() != "1":
        raise SystemExit("extraer_alertas.py del manager NO coincide con el del repo")
    ssh(IP_M, "rm -f /home/angel/extraer_alertas.py.nuevo")
    gb = espacio_manager_gb()
    log("PRE: espacio libre en el manager = %.0f GB" % gb)
    if gb < 6:
        raise SystemExit("poco espacio en el manager (<6 GB)")
    rc, o, e = ssh(IP_M, "bash /home/angel/logall_json_ctl.sh status", inp=PW + "\n", timeout=120)
    if "<logall_json>yes" in o:
        log("PRE: logall_json ya estaba en yes (no se reinicia el manager)")
    else:
        rc, o, e = ssh(IP_M, "bash /home/angel/logall_json_ctl.sh on", inp=PW + "\n", timeout=300)
        log("PRE: logall on -> rc=%s %s" % (rc, (o + e).strip().replace("\n", " | ")[:200]))
    rc, o, e = ssh(IP_M, "bash /home/angel/logall_json_ctl.sh status", inp=PW + "\n", timeout=120)
    log("PRE: status -> %s" % o.strip().replace("\n", " | "))
    if "yes" not in o:
        raise SystemExit("logall_json no quedo en yes")


def fase_run(args):
    specs = cargar_especificaciones()
    if args.only:
        sel = set(args.only.split(","))
        specs = [s for s in specs if s["clave"] in sel or s["ata"] in sel]
    hechos = indice_ok() if not args.force else set()
    for s in specs:
        for it in (1, 2):
            tag = tag_de(s, it)
            if str(it) not in args.iters.split(","):
                continue
            if tag in hechos:
                log("%s ya OK: salto" % tag)
                continue
            if s["clave"] in PENDIENTE:
                m = {"tag": tag, "ata": s["ata"], "variante": s["variante"], "iter": it, "estado": "PENDIENTE",
                     "error": PENDIENTE[s["clave"]], "inicio_utc": now_utc()}
                indice_escribir(m)
                log("%s PENDIENTE: %s" % (tag, m["error"]))
                continue
            if espacio_manager_gb() < 3:
                raise SystemExit("espacio del manager < 3 GB: paro la campana")
            log("=== %s (ventana %d/%d) ===" % (tag, it, 2))
            for intento in (1, 2):
                meta = ventana(s, it, args.timeout)
                if meta["estado"] != "FALLO":
                    break
                log("%s reintento tras FALLO" % tag)
            indice_escribir(meta)
            log("%s -> %s (t0=%s t1=%s filas=%s %ss)" % (tag, meta["estado"], meta.get("t0"), meta.get("t1"),
                                                         meta.get("filas_detalle"), meta.get("segundos")))


def fase_post(args):
    """Copia cruda del manager (alerts+archives de los dias de la campana) con sha256; luego logall off."""
    dest = args.crudo
    os.makedirs(dest, exist_ok=True)
    dias = sorted({r["t0"][:10] for r in csv.DictReader(open(os.path.join(OUT, "windows_index.csv"), encoding="utf-8")) if r.get("t0")})
    log("POST: dias de la campana %s" % dias)
    listado = []
    for dia in dias:
        y, mo, dd = dia[:4], dt.datetime.strptime(dia, "%Y-%m-%d").strftime("%b"), dia[8:10]
        for kind, base in (("alerts", "ossec-alerts"), ("archives", "ossec-archive")):
            for suf in (".json", ".json.gz", ".json.sum", ".log.gz", ".log.sum", ".log"):
                listado.append("/var/ossec/logs/%s/%s/%s/%s-%s%s" % (kind, y, mo, base, dd, suf))
    stage = "/tmp/tfg-ataques-v2-crudo"
    sh = "rm -rf %s; mkdir -p %s/alerts %s/archives %s/manager\n" % (stage, stage, stage, stage)
    for p in listado:
        sub = "alerts" if "/alerts/" in p else "archives"
        sh += '[ -f "%s" ] && cp "%s" %s/%s/\n' % (p, p, stage, sub)
    sh += "cp /var/ossec/logs/ossec.log %s/manager/ 2>/dev/null\n" % stage
    sh += "cp /var/ossec/var/run/wazuh-analysisd.state /var/ossec/var/run/wazuh-remoted.state %s/manager/ 2>/dev/null\n" % stage
    sh += "for ym in %s; do cp /var/ossec/logs/wazuh/$ym/ossec-*.log.gz %s/manager/ 2>/dev/null; cp /var/ossec/logs/api/$ym/api.log-*.gz %s/manager/ 2>/dev/null; done\n" % (
        " ".join(sorted({d[:4] + "/" + dt.datetime.strptime(d, "%Y-%m-%d").strftime("%b") for d in dias})), stage, stage)
    sh += "df -h / > %s/manager/df.txt; date -u > %s/manager/date_utc.txt; chmod -R a+rX %s; echo STAGE_OK\n" % (stage, stage, stage)
    rc, o, e = msudo(sh, timeout=600)
    if "STAGE_OK" not in o:
        raise SystemExit("no se pudo preparar la copia cruda: %s %s" % (o, e))
    for sub in ("alerts", "archives", "manager"):
        os.makedirs(os.path.join(dest, sub), exist_ok=True)
        rc, _, e = run([SCP, "-q", "-r", "-i", KEY, "-o", "BatchMode=yes", "angel@%s:%s/%s/." % (IP_M, stage, sub),
                        os.path.join(dest, sub)], timeout=1800)
        if rc != 0:
            raise SystemExit("scp %s rc=%s %s" % (sub, rc, e))
    ssh(IP_M, "sudo -S -p '' rm -rf %s" % stage, inp=PW + "\n")
    lin = ["fichero\tbytes\tsha256"]
    for f in sorted(glob.glob(os.path.join(dest, "**", "*"), recursive=True)):
        if os.path.isfile(f) and not f.endswith("MANIFEST.tsv"):
            lin.append("%s\t%d\t%s" % (os.path.relpath(f, dest).replace("\\", "/"), os.path.getsize(f), sha256_file(f)))
    open(os.path.join(dest, "MANIFEST.tsv"), "w", encoding="utf-8", newline="\n").write("\n".join(lin) + "\n")
    open(os.path.join(dest, "crudo.done"), "w", encoding="utf-8", newline="\n").write("crudo_utc=%s\nficheros=%d\n" % (now_utc(), len(lin) - 1))
    log("POST: copia cruda OK (%d ficheros) en %s" % (len(lin) - 1, dest))
    if not args.no_off:
        rc, o, e = ssh(IP_M, "bash /home/angel/logall_json_ctl.sh off", inp=PW + "\n", timeout=300)
        log("POST: logall off -> rc=%s %s" % (rc, (o + e).strip().replace("\n", " | ")[:200]))


def main():
    global OUT, RAW, _LOG_FH
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fase", choices=("pre", "run", "post", "todo"), default="todo")
    ap.add_argument("--out", default=os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "linux_v2"))
    ap.add_argument("--raw", default=r"D:\TFG-VMs\ataques-linux-v2-2026-11-20\raw")
    ap.add_argument("--crudo", default=r"D:\TFG-VMs\ataques-linux-v2-2026-11-20\crudo")
    ap.add_argument("--only", default="", help="lista de ATA (p.ej. ATA011,ATA009) o clave (ATA014_rev)")
    ap.add_argument("--iters", default="1,2")
    ap.add_argument("--timeout", type=int, default=900, help="segundos maximos del ataque")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-off", action="store_true", help="no apagar logall_json en post")
    ap.add_argument("--log", default=r"D:\TFG-VMs\lab-logs\ataques_linux_v2.txt")
    args = ap.parse_args()
    if not PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    OUT, RAW = args.out, args.raw
    os.makedirs(OUT, exist_ok=True)
    _LOG_FH = open(args.log, "a", encoding="utf-8", newline="\n")
    log("ORQUESTADOR fase=%s out=%s" % (args.fase, OUT))
    if args.fase in ("pre", "todo"):
        fase_pre()
    if args.fase in ("run", "todo"):
        fase_run(args)
    if args.fase in ("post", "todo"):
        fase_post(args)
    log("ORQUESTADOR fin")


if __name__ == "__main__":
    main()
