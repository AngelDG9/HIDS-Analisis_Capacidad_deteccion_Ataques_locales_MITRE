#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""orquestar_velociraptor_linux.py - piloto V0d de Velociraptor en Linux (ventanas de ataque con el cliente VR, SIN Wazuh).

Reutiliza del orquestador de Wazuh (orquestar_ataques_linux.py) el lanzador (`systemd-run`, SSH solo inicia), la copia de
material, el sink y el reset de la VM (aqui desde `lab-listo-vr`). Cambia lo especifico de Velociraptor:
  * el servidor (PC) lleva una TABLA DE MONITORIZACION con una de dos configuraciones (`--cfg`):
      E = solo Linux.Events.EBPF            (porque con EBPF activo los demas eventos NO entregan filas: hallazgo del 21-nov)
      O = el resto de Linux.Events.* (ProcessExecutions, TrackProcesses, Journal, DNS, HTTPConnections, SSHLogin, SSHBruteforce)
  * marca de INICIO (se espera a verla en el servidor antes de t0) y marca de FIN (despues de t1+120 s): si no llegan,
    la ventana FALLA (no se cuenta vacia);
  * t0 = marca `T0=` del ataque; t1 = fin del lanzamiento + 30 s; recorte [t0-60 s, t1+120 s] del datastore del servidor.
La contrasena de las VMs SOLO por la variable de entorno TFG_MANAGER_PW (nunca en ficheros).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402

REPO = olx.REPO
EXE = r"D:\TFG-VMs\material-velociraptor\velociraptor.exe"
SRV = r"D:\TFG-VMs\velociraptor-server"
API = os.path.join(SRV, "api.config.yaml")
CLIENTE = "C.dbc4d0ba705d6d27"
MON = os.path.join(SRV, "datastore", "clients", CLIENTE, "monitoring")
SNAP_VR = "lab-listo-vr"
CFG = {"E": ["Linux.Events.EBPF"],
       "O": ["Linux.Events.ProcessExecutions", "Linux.Events.TrackProcesses", "Linux.Events.Journal", "Linux.Events.DNS",
             "Linux.Events.HTTPConnections", "Linux.Events.SSHLogin", "Linux.Events.SSHBruteforce"]}
# Ganchos para configuraciones nuevas (pasada de los «ojos», cfg S): se rellenan desde orquestar_velociraptor_ojos.py. E y O no cambian.
FIJAR = {}      # cfg -> funcion(cfg) que deja la tabla de monitorizacion del servidor y devuelve la tabla
POST = {}       # cfg -> funcion(meta, ldir, rdir, t0, t1) tras la marca de FIN (p. ej. subir audit.log); si lanza, la ventana FALLA
SUBS_EXTRA = ()  # carpetas extra del datastore del cliente a copiar en --fase post (cfg S: «collections», con las subidas originales)
CFG["S"] = ["Linux.Events.EBPF"]
PILOTO = ["ATA001", "ATA002", "ATA008", "ATA009", "ATA011", "ATA012"]
OUT = RAW = None


def now_utc_dt():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------- servidor
def vr_query(vql, timeout=120):
    env = dict(os.environ, __COMPAT_LAYER="RunAsInvoker")
    p = subprocess.run([EXE, "-a", API, "query", vql, "--format", "json"], capture_output=True, timeout=timeout, env=env, cwd=SRV)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def tabla_actual():
    rc, o, e = vr_query("SELECT get_client_monitoring().artifacts.artifacts AS a FROM scope()")
    if rc != 0:
        raise RuntimeError("get_client_monitoring rc=%s %s" % (rc, e[-200:]))
    return json.loads(o)[0]["a"]


def fijar_cfg(cfg):
    """Deja en la tabla del servidor SOLO los artifacts de la configuracion (y el Generic.Client.Stats que viene de serie)."""
    quiero = set(CFG[cfg])
    todos = set(CFG["E"]) | set(CFG["O"])
    for a in sorted(todos - quiero):
        vr_query("SELECT rm_client_monitoring(artifact='%s') AS r FROM scope()" % a)
    for a in sorted(quiero):
        vr_query("SELECT add_client_monitoring(artifact='%s') AS r FROM scope()" % a)
    t = set(tabla_actual())
    if (t & todos) != quiero:
        raise RuntimeError("la tabla de monitorizacion no quedo como se pidio: %s" % sorted(t))
    return sorted(t)


def cola_hoy(artifact, mb=24):
    """Ultimos `mb` MB del fichero de resultados de hoy (suficiente para buscar una marca reciente)."""
    p = os.path.join(MON, artifact, now_utc_dt().strftime("%Y-%m-%d") + ".json")
    if not os.path.isfile(p):
        return b""
    with open(p, "rb") as fh:
        fh.seek(0, 2)
        n = fh.tell()
        fh.seek(max(0, n - mb * 1024 * 1024))
        return fh.read()


def marca_vista(cfg, marca):
    b = marca.encode()
    arts = ["Linux.Events.EBPF"] if cfg in ("E", "S") else ["Linux.Events.Journal"]
    return any(b in cola_hoy(a) for a in arts)


def emitir_marca(marca):
    olx.ssh(olx.IP_V, "/bin/echo %s; logger -t TFGMARK %s" % (marca, marca), timeout=40)


def esperar_marca(cfg, marca, seg, repetir=True):
    t = time.time()
    k = 0
    while time.time() - t < seg:
        if k == 0 or (repetir and k % 5 == 0):
            emitir_marca(marca)
        if marca_vista(cfg, marca):
            return round(time.time() - t)
        k += 1
        time.sleep(4)
    return None


# ----------------------------------------------------------------------------- ventana
def reglas_audit():
    rc, o, e = olx.ssh(olx.IP_V, "sudo -S -p '' auditctl -l", inp=olx.PW + "\n", timeout=40)
    return o.strip()


MGR_VMX = r"D:\TFG-VMs\wazuh-server\wazuh-server.vmx"


def manager_on():
    """ATA039/ATA040 usan un daemon rsync en la VM manager (192.168.65.128), apagada en el resto de la pasada de Velociraptor: se enciende solo para ellos."""
    rc, o, e = olx.run([olx.VMRUN, "-T", "ws", "list"], timeout=60)
    if MGR_VMX.lower() not in o.lower():
        rc, o, e = olx.run([olx.VMRUN, "-T", "ws", "start", MGR_VMX, "nogui"], timeout=300)
        if rc != 0:
            raise RuntimeError("no arranca la VM manager: %s %s" % (o.strip(), e.strip()))
    if not olx.esperar_ssh(olx.IP_M, 300):
        raise RuntimeError("la VM manager no responde por SSH")


def manager_off():
    olx.run([olx.VMRUN, "-T", "ws", "stop", MGR_VMX, "soft"], timeout=180)


def esperar_reinicio_vr(antes, seg=720):
    """ATA038: espera a que la victima vuelva con otro boot_id (el cliente de Velociraptor se comprueba despues con la marca FIN)."""
    t = time.time()
    while time.time() - t < seg:
        b = olx.boot_id()
        if b and b != antes:
            return b
        time.sleep(6)
    raise RuntimeError("la victima no reinicia en %d s" % seg)


def ventana(spec, it, cfg, timeout_ataque):
    ata, tag = spec["ata"], olx.tag_de(spec, it)
    ldir = os.path.join(OUT, "Logs", tag)
    rdir = os.path.join(RAW, tag)
    os.makedirs(ldir, exist_ok=True)
    os.makedirs(rdir, exist_ok=True)
    meta = {"tag": tag, "ata": ata, "iter": it, "cfg": cfg, "tabla": CFG[cfg], "hids": "velociraptor-0.77.3", "snapshot": SNAP_VR,
            "lanzador": "systemd-run --uid=angel --pipe --wait (SSH solo inicia)", "inicio_utc": iso(now_utc_dt()),
            "script_sha256": olx.sha256_file(spec["script"])}
    sink = olx.Sink(os.path.join(ldir, "sink.log")) if ata in olx.SINK_ATAS else None
    t_ini = time.time()
    try:
        if sink:
            sink.start()
        if ata in ("ATA039", "ATA040"):
            manager_on()
            olx.rsync_up()
        meta["tabla_servidor"] = FIJAR.get(cfg, fijar_cfg)(cfg)
        olx.vm_reset()
        if not olx.esperar_ssh(olx.IP_V, 300):
            raise RuntimeError("la victima no responde por SSH")
        mi = "TFGMARKINI%s" % re.sub(r"\W", "", tag + cfg + str(int(time.time())))
        s = esperar_marca(cfg, mi, 480)
        meta["marca_ini_seg"] = s
        meta["marca_ini"] = mi
        if s is None:
            raise RuntimeError("la marca de INICIO no llega al servidor (tuberia no operativa)")
        time.sleep(olx.SETTLE_S)
        dv = olx.ssh(olx.IP_V, "date -u +%Y-%m-%dT%H:%M:%SZ", timeout=30)[1].strip()
        dh = iso(now_utc_dt())
        meta["reloj_victima"], meta["reloj_host"] = dv, dh
        meta["auditd_antes"] = reglas_audit()
        d_dest = "%s/%s" % (olx.LAB, ata)
        rc, o, e = olx.ssh(olx.IP_V, "mkdir -p %s" % d_dest)
        if rc != 0:
            raise RuntimeError("mkdir destino: %s" % e)
        for f in olx.ficheros_a_copiar(spec):
            rc, o, e = olx.scp_to(olx.IP_V, f, d_dest + "/")
            if rc != 0:
                raise RuntimeError("scp %s: %s" % (os.path.basename(f), e))
        if ata == "ATA008":
            at = os.path.join(REPO, "Soporte", "Ataques", "atomic-red-team", "atomics", "T1048.002", "src")
            if os.path.isdir(at):
                olx.scp_to(olx.IP_V, at, d_dest + "/", recursive=True)
        if ata == "ATA047":                               # su prestaging arranca el sink dentro de la victima
            olx.scp_to(olx.IP_V, olx.SINK, d_dest + "/")
        olx.extras_pre(spec, d_dest)                      # material fijado (rclone, debs): no hace nada en los demas casos
        olx.ssh(olx.IP_V, "chmod +x %s/*.sh 2>/dev/null; true" % d_dest)
        rc, o, _ = olx.ssh(olx.IP_V, "sha256sum %s/%s" % (d_dest, spec["nombre"]))
        meta["sha256_en_victima"] = o.split()[0] if o.split() else ""
        if meta["sha256_en_victima"] != meta["script_sha256"]:
            raise RuntimeError("sha256 del script distinto entre repo y victima")
        pres = "bash %s_prestaging.sh" % ata if os.path.isfile(os.path.join(spec["dir"], "%s_prestaging.sh" % ata)) else None
        if pres:
            rc, o, e = olx.ssh(olx.IP_V, "cd %s && %s" % (d_dest, pres), inp=olx.PW + "\n" + olx.PW + "\n", timeout=300)
            open(os.path.join(ldir, "prestage.out"), "w", encoding="utf-8", newline="\n").write(o + e)
            meta["prestage_rc"] = rc
            if rc != 0:
                raise RuntimeError("prestage rc=%s" % rc)
        # --- VENTANA
        cmd, entrada = olx.lanzar_local(spec, "", d_dest)
        if ata == "ATA038":
            meta["boot_id_antes"] = olx.boot_id()
        t_lanz = now_utc_dt()
        rc, o, e = olx.ssh(olx.IP_V, cmd, inp=entrada, timeout=timeout_ataque)
        meta["lanzamiento_rc"] = rc
        open(os.path.join(ldir, "ejecucion.out"), "w", encoding="utf-8", newline="\n").write(o + (("\n--STDERR--\n" + e) if e.strip() else ""))
        m = re.search(r"T0=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", o)
        t0 = m.group(1) if m else iso(t_lanz)
        meta["t0_fuente"] = "marca T0= del ataque" if m else "reloj del host al lanzar"
        if ata == "ATA038":                               # t1 lo sella el operador TRAS el reinicio (como en Wazuh)
            meta["boot_id_despues"] = esperar_reinicio_vr(meta.get("boot_id_antes", ""))
            time.sleep(20)
        else:
            time.sleep(30)
        t1 = iso(now_utc_dt())
        meta["t0"], meta["t1"] = t0, t1
        with open(os.path.join(ldir, "times.log"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("T0=%s\nT1=%s\nLANZADO_HOST=%s\nRELOJ_VICTIMA=%s\nRELOJ_HOST=%s\n" % (t0, t1, iso(t_lanz), dv, dh))
        time.sleep(125)                                  # cubre t1+120 s antes de la marca de fin
        mf = "TFGMARKFIN%s" % re.sub(r"\W", "", tag + cfg + str(int(time.time())))
        s = esperar_marca(cfg, mf, 420)
        meta["marca_fin_seg"] = s
        meta["marca_fin"] = mf
        if s is None:
            raise RuntimeError("la marca de FIN no llega al servidor: la ventana puede estar incompleta")
        meta["auditd_despues"] = reglas_audit()
        if meta["auditd_despues"] != meta["auditd_antes"]:
            raise RuntimeError("las reglas de auditd cambiaron durante la ventana (sin ojos fiables)")
        # --- RECORTE y anclas
        a0 = ext._iso(t0) - dt.timedelta(seconds=60)
        a1 = ext._iso(t1) + dt.timedelta(seconds=120)
        if cfg in POST:
            POST[cfg](meta, ldir, rdir, a0, a1)
        anclas = []
        for f in glob.glob(os.path.join(olx.CMD_DIR, "T*", "%s_esperado.csv" % ata)):
            anclas = ext.cargar_anclas(f)
        resumen = {}
        for art in ext.ARTIFACTS:
            lineas, sin_hora = ext.recortar_artifact(MON, art, a0, a1)
            ext.escribir_gz(os.path.join(rdir, art + ".jsonl.gz"), lineas)
            r = {"filas": len(lineas), "sin_hora": sin_hora, "anclas_generico": ext.contar_anclas(lineas, anclas)}
            if art == "Linux.Events.EBPF":
                r["anclas_exec_estricto"] = ext.contar_anclas_exec_ebpf(lineas, anclas)
            resumen[art] = r
        meta["resumen"] = resumen
        meta["anclas"] = [list(a) for a in anclas]
        with open(os.path.join(ldir, "sha256_recortes.txt"), "w", encoding="utf-8", newline="\n") as fh:
            for f in sorted(glob.glob(os.path.join(rdir, "*.gz"))):
                fh.write("%s  %s\n" % (ext.sha256_file(f), os.path.basename(f)))
        meta["estado"] = "OK" if meta.get("lanzamiento_rc", 1) == 0 else "REVISAR"
    except Exception as ex:                              # noqa: BLE001 - se anota y se sigue
        meta["estado"] = "FALLO"
        meta["error"] = str(ex)[:300]
        olx.log("%s FALLO: %s" % (tag, ex))
    finally:
        if sink:
            sink.stop()
        if ata in ("ATA039", "ATA040"):
            olx.rsync_down(ldir)
        meta["fin_utc"] = iso(now_utc_dt())
        meta["segundos"] = round(time.time() - t_ini)
        with open(os.path.join(ldir, "lanzamiento.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=1)
    return meta


def indice_ok():
    p = os.path.join(OUT, "indice.csv")
    if not os.path.isfile(p):
        return set()
    return {r["tag"] for r in csv.DictReader(open(p, encoding="utf-8")) if r.get("estado") == "OK"}


def indice_escribir(meta):
    p = os.path.join(OUT, "indice.csv")
    nuevo = not os.path.isfile(p)
    cols = ["tag", "cfg", "estado", "t0", "t1", "marca_ini_seg", "marca_fin_seg", "segundos", "error"]
    with open(p, "a", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        if nuevo:
            w.writerow(cols)
        w.writerow([meta.get(c, "") for c in cols])


def fase_run(args):
    specs = [s for s in olx.cargar_especificaciones() if s["variante"] == "base" and s["ata"] in args.only.split(",")]
    hechos = indice_ok() if not args.force else set()
    for s in specs:
        for it in [int(x) for x in args.iters.split(",")]:
            tag = olx.tag_de(s, it)
            if tag in hechos:
                olx.log("%s ya OK: salto" % tag)
                continue
            olx.log("=== %s cfg=%s ===" % (tag, args.cfg))
            for intento in (1, 2):
                meta = ventana(s, it, args.cfg, args.timeout)
                if meta["estado"] != "FALLO":
                    break
                olx.log("%s reintento tras FALLO" % tag)
            indice_escribir(meta)
            olx.log("%s -> %s (t0=%s t1=%s %ss)" % (tag, meta["estado"], meta.get("t0"), meta.get("t1"), meta.get("segundos")))


def fase_post(args):
    """Copia INTEGRA del datastore de eventos del cliente (monitoring, monitoring_logs) y logs del servidor, con sha256."""
    import shutil
    dest = args.crudo
    os.makedirs(dest, exist_ok=True)
    base = os.path.join(SRV, "datastore", "clients", CLIENTE)
    for sub in ("monitoring", "monitoring_logs") + tuple(SUBS_EXTRA):
        d = os.path.join(dest, sub)
        if os.path.isdir(d):
            shutil.rmtree(d)
        shutil.copytree(os.path.join(base, sub), d)
    for f in ("server.log", "server.log.err"):
        if os.path.isfile(os.path.join(SRV, f)):
            shutil.copy2(os.path.join(SRV, f), os.path.join(dest, f))
    lin = ["fichero\tbytes\tsha256"]
    for f in sorted(glob.glob(os.path.join(dest, "**", "*"), recursive=True)):
        if os.path.isfile(f) and not f.endswith("MANIFEST.tsv"):
            lin.append("%s\t%d\t%s" % (os.path.relpath(f, dest).replace("\\", "/"), os.path.getsize(f), ext.sha256_file(f)))
    open(os.path.join(dest, "MANIFEST.tsv"), "w", encoding="utf-8", newline="\n").write("\n".join(lin) + "\n")
    olx.log("POST: copia cruda OK (%d ficheros) en %s" % (len(lin) - 1, dest))


def main():
    global OUT, RAW
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fase", choices=("run", "post"), default="run")
    ap.add_argument("--cfg", choices=("E", "O", "S"), default="E")
    ap.add_argument("--only", default=",".join(PILOTO))
    ap.add_argument("--iters", default="1,2")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--out", default=os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Velociraptor", "linux_piloto"))
    ap.add_argument("--raw", default=r"D:\TFG-VMs\ataques-velociraptor-linux-piloto\raw")
    ap.add_argument("--crudo", default=r"D:\TFG-VMs\ataques-velociraptor-linux-piloto\crudo")
    ap.add_argument("--log", default=r"D:\TFG-VMs\lab-logs\velociraptor_piloto.txt")
    args = ap.parse_args()
    if not olx.PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    olx.SNAP = SNAP_VR
    OUT = os.path.join(args.out, "cfg" + args.cfg)
    RAW = os.path.join(args.raw, "cfg" + args.cfg)
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(RAW, exist_ok=True)
    olx._LOG_FH = open(args.log, "a", encoding="utf-8", newline="\n")
    olx.log("ORQUESTADOR-VR fase=%s cfg=%s out=%s" % (args.fase, args.cfg, OUT))
    if args.fase == "run":
        fase_run(args)
    else:
        fase_post(args)
    olx.log("ORQUESTADOR-VR fin")


if __name__ == "__main__":
    main()
