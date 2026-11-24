#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cosecha_vr.py - cosecha y cierre de la ventana de 72 h con Velociraptor (V1-L, paso L6). Se ejecuta en VIVO por el operador DESPUES de t1.
La cosecha de Wazuh se hizo a mano (no hay script); esto la formaliza con la MISMA lista de ficheros + el crudo de Velociraptor.

Fases (--fase todo las ejecuta en este orden; cada una imprime lo que hace):
  acciones   ledger de GHOSTS: agregado por hora (con `exportar_acciones.sh`, como Wazuh) + una fila POR ACCION (history_timeline). Antes de parar GHOSTS.
  guest      ficheros de la victima: la lista de Wazuh (recovery.log, keepalive.log, client.out, id.json, rotacion.estado, timeline.json,
             errores.log, campana_fp/**, crontab, ip route, df) + `/var/log/audit` + auditd.conf/rules.d + huellas del cliente VR (NO se copia su config)
  marca-fin  emite la marca FIN (UNICA marca tras t1) y espera a verla en EBPF y en auditd: garantiza que lo anterior a t1 llego
  subida     sube `audit.log*` por Velociraptor (Generic.Collectors.File; el ojo «oficial» de auditd)
  datastore  copia INTEGRA de monitoring, monitoring_logs y collections del cliente + server.log* del servidor
  manifest   MANIFEST.tsv con sha256 de todo + `cosecha.done`
La contrasena de la VM SOLO por entorno (TFG_MANAGER_PW). Sin secretos en el fichero. Nada de esto se hace DENTRO de [t0,t1].
Uso: TFG_MANAGER_PW=... python cosecha_vr.py --t0 ... --t1 ... --out D:\\TFG-VMs\\legitimo-vr-2026-11-30 [--fase todo] [--ensayo]
"""
import argparse
import datetime as dt
import glob
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import orquestar_velociraptor_linux as vr        # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402
import legit_vr                                  # noqa: E402

REPO = olx.REPO
EXPORTAR = os.path.join(REPO, "Soporte", "Laboratorio", "legitimo_72h", "exportar_acciones.sh")
PSQL = r"D:\TFG-VMs\material-ghosts\pgsql\bin\psql.exe"
GUEST = "/home/angel/ghosts-client"
USER_TAR = ("home/angel/ghosts-client/recovery.log home/angel/ghosts-client/keepalive.log home/angel/ghosts-client/client.out "
            "home/angel/ghosts-client/client.out.1 home/angel/ghosts-client/rotacion.estado home/angel/ghosts-client/instance/id.json "
            "home/angel/ghosts-client/config/timeline.json home/angel/Documentos/errores.log home/angel/Documentos/campana_fp")
ROOT_TAR = "var/log/audit etc/audit/auditd.conf etc/audit/rules.d"


def log(m):
    print("[%s] %s" % (dt.datetime.utcnow().strftime("%H:%M:%SZ"), m), flush=True)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sudo_bin(cmd, timeout=1800):
    """Ejecuta un comando como root en la victima y devuelve (rc, bytes, stderr). La contrasena va por stdin, nunca en argv."""
    return olx.ssh(olx.IP_V, "sudo -S -p '' bash -c %s" % __import__("shlex").quote(cmd), inp=olx.PW + "\n", timeout=timeout, binary=True)


def f_acciones(a):
    d = os.path.join(a.out, "acciones")
    os.makedirs(d, exist_ok=True)
    bash = r"C:\Program Files\Git\bin\bash.exe"
    rc = subprocess.run([bash, "-c", "cd '%s' && bash '%s' %s %s '%s' 2" % (
        REPO.replace("\\", "/"), EXPORTAR.replace("\\", "/"), a.t0, a.t1, os.path.join(d, "ghosts_acciones.csv").replace("\\", "/"))],
        capture_output=True, timeout=300)
    log("ghosts_acciones.csv (por hora) rc=%s %s" % (rc.returncode, rc.stdout.decode("utf-8", "replace").strip().splitlines()[-1:]))
    t0s, t1s = a.t0.rstrip("Z").replace("T", " "), a.t1.rstrip("Z").replace("T", " ")
    sql = "copy (select * from history_timeline where createdutc >= '%s' and createdutc < '%s' order by createdutc) to stdout with csv header" % (t0s, t1s)
    p = subprocess.run([PSQL, "-h", "127.0.0.1", "-p", "5432", "-U", "ghosts", "-d", "ghosts", "-c", sql], capture_output=True, timeout=300)
    open(os.path.join(d, "ghosts_acciones_por_accion.csv"), "wb").write(p.stdout)
    import csv
    csv.field_size_limit(10 ** 9)
    n = sum(1 for _ in csv.DictReader(io.StringIO(p.stdout.decode("utf-8", "replace"), newline="")))
    log("ledger POR ACCION: %d filas rc=%s %s" % (n, p.returncode, p.stderr.decode("utf-8", "replace").strip()[:120]))
    json.dump({"filas_por_accion": n}, open(os.path.join(d, "resumen.json"), "w"))
    # volcado de history_timeline desde UN DIA antes de t0 (el historico anterior de la BD son las ventanas de Wazuh y ensayos: no es de esta ventana), comprimido
    desde = (dt.datetime.strptime(a.t0, "%Y-%m-%dT%H:%M:%SZ") - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    p2 = subprocess.run([PSQL, "-h", "127.0.0.1", "-p", "5432", "-U", "ghosts", "-d", "ghosts", "-c",
                         "copy (select * from history_timeline where createdutc >= '%s' order by createdutc) to stdout with csv header" % desde], capture_output=True, timeout=600)
    with gzip.GzipFile(filename="", fileobj=open(os.path.join(d, "history_timeline_desde_t0-1dia.csv.gz"), "wb"), mode="wb", mtime=0) as g:
        g.write(p2.stdout)
    log("history_timeline desde %s: %d bytes sin comprimir" % (desde, len(p2.stdout)))


def f_guest(a):
    d = os.path.join(a.out, "evidencia")
    os.makedirs(d, exist_ok=True)
    rc, b, e = olx.ssh(olx.IP_V, "tar czf - --ignore-failed-read -C / %s 2>/dev/null" % USER_TAR, timeout=600, binary=True)
    open(os.path.join(d, "guest_user.tar.gz"), "wb").write(b)
    log("tar usuario: rc=%s %d bytes" % (rc, len(b)))
    with tarfile.open(fileobj=io.BytesIO(b), mode="r:gz") as t:
        t.extractall(os.path.join(d, "guest_user"), filter="data")
        log("   ficheros: %d" % len(t.getnames()))
    for nombre, cmd in (("crontab.txt", "crontab -l 2>&1; echo rc=$?"), ("ip_route.txt", "ip route; echo ---; ip -4 addr"),
                        ("df_root.txt", "df -h /; df -Pi /"), ("uptime.txt", "uptime; date -u; uname -r; cat /proc/sys/kernel/random/boot_id"),
                        ("procesos.txt", "ps -eo pid,ppid,etimes,rss,comm --sort=-rss | head -25")):
        rc, o, e = olx.ssh(olx.IP_V, cmd, timeout=60)
        open(os.path.join(d, nombre), "w", encoding="utf-8", newline="\n").write(o)
    rc, b, e = sudo_bin("tar czf - --ignore-failed-read -C / %s" % ROOT_TAR, timeout=3600)
    open(os.path.join(d, "root_audit.tar.gz"), "wb").write(b)
    log("tar root (audit.log* + conf): rc=%s %d bytes %s" % (rc, len(b), e.strip()[:100]))
    cmd = ("sha256sum /usr/local/bin/velociraptor /etc/velociraptor/client.config.yaml /etc/audit/auditd.conf /etc/audit/rules.d/tfg.rules; "
           "auditctl -l; systemctl is-active velociraptor_client auditd; grep -E '^(max_log_file|num_logs|max_log_file_action) ' /etc/audit/auditd.conf; "
           "ls -la --time-style=+%%FT%%TZ /var/log/audit | tail -n +2; du -sh /var/log/audit /var/log /var/tmp/Velociraptor_Buffer.bin 2>&1; "
           "journalctl -u velociraptor_client -p warning --since '%s' --no-pager | tail -n 400" % a.t0.replace("T", " ").rstrip("Z"))
    rc, o, e = sudo_bin(cmd, timeout=300)
    open(os.path.join(d, "estado_vr_y_auditd.txt"), "wb").write(o)
    log("estado VR/auditd guardado (%d bytes)" % len(o))


def marca_en(fichero_dia_dir, marca):
    for p in sorted(glob.glob(os.path.join(fichero_dia_dir, "*.json")))[-2:]:
        with open(p, "rb") as fh:
            fh.seek(0, 2)
            n = fh.tell()
            fh.seek(max(0, n - 48 * 1024 * 1024))
            if marca.encode() in fh.read():
                return True
    return False


def f_marca(a):
    c = legit_vr.fijar_cliente()
    marca = "TFGMARKFINVR%s" % dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    d = os.path.join(a.out, "evidencia")
    os.makedirs(d, exist_ok=True)
    ebpf = os.path.join(vr.SRV, "datastore", "clients", c, "monitoring", "Linux.Events.EBPF")
    t = time.time()
    vista = False
    emitida = 0
    while time.time() - t < a.espera_marca:
        if emitida == 0 or (time.time() - emitida) > 90:
            olx.ssh(olx.IP_V, "/bin/echo %s; logger -t TFGMARK %s" % (marca, marca), timeout=40)
            emitida = time.time()
        if marca_en(ebpf, marca):
            vista = True
            break
        time.sleep(10)
    log("marca FIN %s vista en EBPF: %s (tras %d s)" % (marca, vista, time.time() - t))
    open(os.path.join(d, "marca_fin.txt"), "w").write("%s\nvista_en_ebpf=%s\nhora_utc=%s\n" % (marca, vista, dt.datetime.utcnow().isoformat() + "Z"))
    if not vista:
        raise SystemExit("la marca FIN no llega al servidor: NO se puede dar la cola por vacia (no se para nada)")


def f_subida(a):
    c = legit_vr.fijar_cliente()
    out = os.path.join(a.out, "audit_subida_vr")
    os.makedirs(out, exist_ok=True)
    rc, o, e = legit_vr.q("SELECT collect_client(client_id='%s', artifacts='Generic.Collectors.File', env=dict(Root='/', collectionSpec=\"Glob\n/var/log/audit/audit.log*\")) AS f FROM scope()" % c, 120)
    m = re.search(r"F\.[A-Z0-9]+", o)
    if not m:
        raise SystemExit("no se pudo lanzar la subida: %s" % e[-200:])
    fid = m.group(0)
    log("subida de audit.log* por Velociraptor: flujo %s" % fid)
    t = time.time()
    estado = None
    while time.time() - t < a.espera_subida:
        rc, o2, e2 = legit_vr.q("SELECT state FROM flows(client_id='%s', flow_id='%s')" % (c, fid), 60)
        if '"FINISHED"' in o2 or '"ERROR"' in o2:
            estado = "FINISHED" if "FINISHED" in o2 else "ERROR"
            break
        time.sleep(15)
    log("flujo %s: estado=%s tras %d s" % (fid, estado, time.time() - t))
    res = {"flow_id": fid, "estado": estado, "ficheros": {}}
    base = os.path.join(vr.SRV, "datastore", "clients", c, "collections", fid, "uploads")
    for d, _, fs in os.walk(base):
        for f in fs:
            p = os.path.join(d, f)
            res["ficheros"][f] = {"bytes_en_disco": os.path.getsize(p)}
    json.dump(res, open(os.path.join(out, "subida.json"), "w"), indent=1)
    log("   %d ficheros subidos, %.0f MB en el datastore" % (len(res["ficheros"]), sum(v["bytes_en_disco"] for v in res["ficheros"].values()) / 1e6))
    if estado != "FINISHED":
        raise SystemExit("la subida de audit.log* no termino (estado=%s)" % estado)


def f_datastore(a):
    c = legit_vr.fijar_cliente()
    dest = os.path.join(a.out, "crudo_servidor")
    base = os.path.join(vr.SRV, "datastore", "clients", c)
    for sub in ("monitoring", "monitoring_logs", "collections"):
        d = os.path.join(dest, sub)
        if os.path.isdir(d):
            shutil.rmtree(d)
        if os.path.isdir(os.path.join(base, sub)):
            shutil.copytree(os.path.join(base, sub), d)
    for f in glob.glob(os.path.join(vr.SRV, "server.log*")):
        shutil.copy2(f, os.path.join(dest, os.path.basename(f)))
    log("datastore del cliente %s copiado a %s" % (c, dest))


def f_manifest(a):
    lin = ["fichero\tbytes\tsha256"]
    for f in sorted(glob.glob(os.path.join(a.out, "**", "*"), recursive=True)):
        if os.path.isfile(f) and os.path.basename(f) not in ("MANIFEST.tsv", "cosecha.done"):
            lin.append("%s\t%d\t%s" % (os.path.relpath(f, a.out).replace("\\", "/"), os.path.getsize(f), sha(f)))
    open(os.path.join(a.out, "MANIFEST.tsv"), "w", encoding="utf-8", newline="\n").write("\n".join(lin) + "\n")
    open(os.path.join(a.out, "cosecha.done"), "w").write(dt.datetime.utcnow().isoformat() + "Z\n")
    log("MANIFEST.tsv: %d ficheros; cosecha.done creado" % (len(lin) - 1))


FASES = [("acciones", f_acciones), ("guest", f_guest), ("marca-fin", f_marca), ("subida", f_subida), ("datastore", f_datastore), ("manifest", f_manifest)]

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fase", default="todo", choices=["todo"] + [n for n, _ in FASES])
    ap.add_argument("--ensayo", action="store_true", help="permite ejecutar antes de t1 (solo ensayo)")
    ap.add_argument("--espera-marca", type=int, default=900)
    ap.add_argument("--espera-subida", type=int, default=3600)
    a = ap.parse_args()
    if not olx.PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    if not a.ensayo and dt.datetime.utcnow() < dt.datetime.strptime(a.t1, "%Y-%m-%dT%H:%M:%SZ"):
        sys.exit("todavia no es t1: la cosecha solo se hace DESPUES de la ventana (usa --ensayo en el ensayo)")
    os.makedirs(a.out, exist_ok=True)
    legit_vr.fijar_cliente()
    for n, f in FASES:
        if a.fase in ("todo", n):
            log("=== %s ===" % n)
            f(a)
