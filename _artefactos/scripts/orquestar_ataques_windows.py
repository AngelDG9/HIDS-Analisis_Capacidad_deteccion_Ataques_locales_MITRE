#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""orquestar_ataques_windows.py - F3: repite los ataques Windows (VERSION 2) con lanzador local.

Igual que `orquestar_ataques_linux.py` (reutiliza sus ayudas) pero para `victima-windows`:
  * el ataque NO cuelga de `sshd.exe`: SSH solo CREA y DISPARA una tarea programada
    (`TFG-Attack-<ATA>`, usuario angel, token interactivo, nivel mas alto) y el proceso lo lanza el
    Programador de tareas (padre = servicio Schedule, no sshd). Es el mismo mecanismo que ya se
    usaba en los casos S1 y el que usa el legitimo;
  * se usa el snapshot `lab-listo-windows-ataques-gui` (autologon de angel, sesion 1) para todos;
  * el manager lleva `logall_json=yes` (lo activa/apaga la fase pre/post del orquestador Linux o
    `logall_json_ctl.sh`); se guarda por ventana la salida del ataque (`evidencias/`), alertas
    (Detalle CSV) y las lineas crudas de alerts y archives del agente 002.

Fases (`--fase`): pre (servicios del host + logall on) | run | post (copia cruda + logall off + servicios off).
Contrasena de las VMs SOLO en la variable de entorno TFG_MANAGER_PW (la misma para el invitado: se usa
solo para sudo del manager; el invitado entra por clave SSH). Sin secretos en ficheros.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import gzip
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as L  # noqa: E402  (reutiliza run/ssh/scp/msudo/log/sha256...)

VMX = r"D:\TFG-VMs\victima-windows\victima-windows.vmx"
SNAP = "lab-listo-windows-ataques-gui"
IP_W = "192.168.65.130"
AGENTE, AGENTE_NOMBRE = "002", "victima-windows"
CMD_DIR = os.path.join(L.REPO, "Dataset", "Ataques", "Comandos", "windows")
SERV = os.path.join(L.REPO, "_artefactos", "scripts", "arrancar_servicios_host.py")
RAIZ_W = r"C:\lab-attack"
PENDIENTE = {
    "ATA067": "reinicio de la victima a mitad de ventana (manejo propio)",
}


def cargar_especificaciones():
    out = []
    for p in sorted(glob.glob(os.path.join(CMD_DIR, "T*", "ATA*_ataque.ps1"))):
        b = os.path.basename(p)
        out.append({"ata": b.split("_")[0], "script": p, "dir": os.path.dirname(p), "nombre": b})
    out.sort(key=lambda s: s["ata"])
    return out


def ficheros(spec):
    res = []
    for f in sorted(os.listdir(spec["dir"])):
        fp = os.path.join(spec["dir"], f)
        if "_esperado" in f or f.lower() == "readme.md" or "pre_registro" in f or f == "preparar_tarea_s1.ps1":
            continue
        res.append(fp)
    return res


def vm_reset():
    L.run([L.VMRUN, "-T", "ws", "stop", VMX, "soft"], timeout=180)
    rc, o, e = L.run([L.VMRUN, "-T", "ws", "revertToSnapshot", VMX, SNAP], timeout=300)
    if rc != 0:
        raise RuntimeError("revert rc=%s %s %s" % (rc, o.strip(), e.strip()))
    rc, o, e = L.run([L.VMRUN, "-T", "ws", "start", VMX, "nogui"], timeout=300)
    if rc != 0:
        raise RuntimeError("start rc=%s %s %s" % (rc, o.strip(), e.strip()))


def agente_activo():
    rc, out, _ = L.msudo("/var/ossec/bin/agent_control -l", timeout=60)
    return bool(re.search(r"ID:\s*%s,\s*Name:\s*%s,.*Active" % (AGENTE, AGENTE_NOMBRE), out))


def esperar_agente(seg=480):
    t = time.time()
    while time.time() - t < seg:
        rc, out, _ = L.ssh(IP_W, "sc query WazuhSvc", timeout=25)
        if rc == 0 and "RUNNING" in out and agente_activo():
            return True
        time.sleep(8)
    return False


def tarea_estado(tn):
    rc, out, _ = L.ssh(IP_W, 'schtasks /query /tn %s /fo csv /nh' % tn, timeout=40)
    m = re.findall(r'"([^"]*)"', out)
    return m[2] if len(m) >= 3 else ("?" if rc else "")


def ventana(spec, it, timeout_ataque):
    ata = spec["ata"]
    tag = "%s_iter%d" % (ata, it)
    ldir = os.path.join(L.OUT, "Logs", tag)
    os.makedirs(ldir, exist_ok=True)
    tn = "TFG-Attack-%s" % ata
    meta = {"tag": tag, "ata": ata, "variante": "base", "iter": it, "version": 2, "so": "windows",
            "lanzador": "schtasks (angel, interactivo, nivel mas alto); SSH solo crea/dispara", "logall_json": "yes",
            "snapshot": SNAP, "inicio_utc": L.now_utc(), "script_sha256": L.sha256_file(spec["script"])}
    t_ini = time.time()
    try:
        ahora = dt.datetime.now(dt.timezone.utc)
        if ahora.hour == 23 and ahora.minute >= 50:
            esp = (dt.datetime.combine(ahora.date() + dt.timedelta(days=1), dt.time(0, 3),
                                       tzinfo=dt.timezone.utc) - ahora).total_seconds()
            L.log("espero %.0f s para no cruzar la medianoche" % esp)
            time.sleep(esp)
        vm_reset()
        if not L.esperar_ssh(IP_W, 360):
            raise RuntimeError("la victima no responde por SSH")
        if not esperar_agente(480):
            raise RuntimeError("el agente 002 no llega a Active")
        L.log("%s agente Active; asentamiento %d s" % (tag, L.SETTLE_S))
        time.sleep(L.SETTLE_S)
        meta["reloj_manager"] = L.mgr_now()
        rc, o, _ = L.ssh(IP_W, 'powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString(\'yyyy-MM-ddTHH:mm:ssZ\')"', timeout=60)
        meta["reloj_victima"] = o.strip()
        # estado limpio
        rc, o, _ = L.ssh(IP_W, "dir /b %s 2>nul" % RAIZ_W, timeout=40)
        meta["lab_attack_previo"] = o.strip()[:120]
        destino = "%s\\%s" % (RAIZ_W, ata)
        L.ssh(IP_W, 'cmd /c "if not exist %s md %s"' % (destino, destino), timeout=40)
        for f in ficheros(spec):
            rc, o, e = L.scp_to(IP_W, f, "C:/lab-attack/%s/" % ata, recursive=os.path.isdir(f))
            if rc != 0:
                raise RuntimeError("scp %s: %s" % (os.path.basename(f), e))
        rc, o, _ = L.ssh(IP_W, 'powershell -NoProfile -Command "(Get-FileHash %s\\%s -Algorithm SHA256).Hash.ToLower()"' % (destino, spec["nombre"]), timeout=60)
        meta["sha256_en_victima"] = o.strip()
        if meta["sha256_en_victima"] != meta["script_sha256"]:
            raise RuntimeError("sha256 del ataque distinto entre repo y victima (%s)" % meta["sha256_en_victima"])
        open(os.path.join(ldir, "sha256_artefacto.txt"), "w", encoding="utf-8", newline="\n").write(
            "%s  %s\n" % (meta["script_sha256"], spec["nombre"]))
        # crear la tarea ANTES de t0 (fuera de la ventana)
        rc, o, e = L.ssh(IP_W, 'schtasks /create /tn %s /tr "C:\\lab-attack\\%s\\run.cmd" /sc once /st 23:59 /ru angel /it /rl highest /f' % (tn, ata), timeout=60)
        meta["tarea_create_rc"] = rc
        if rc != 0:
            raise RuntimeError("schtasks /create rc=%s %s %s" % (rc, o.strip(), e.strip()))
        # VENTANA
        t_lanz = L.mgr_now()
        rc, o, e = L.ssh(IP_W, "schtasks /run /tn %s" % tn, timeout=60)
        meta["tarea_run_rc"] = rc
        if rc != 0:
            raise RuntimeError("schtasks /run rc=%s %s %s" % (rc, o.strip(), e.strip()))
        time.sleep(15)
        fin = time.time() + timeout_ataque
        est = ""
        while time.time() < fin:
            est = tarea_estado(tn)
            if est and est.lower() not in ("running", "en ejecuci\u00f3n", "en ejecucion", "?"):
                break
            time.sleep(10)
        meta["tarea_estado_final"] = est
        # FIM forzado + 30 s, t1
        L.msudo("/var/ossec/bin/agent_control -r -u %s" % AGENTE, timeout=90)
        time.sleep(30)
        t1 = L.mgr_now()
        # recoger evidencias y leer t0 del propio ataque
        ev_local = os.path.join(ldir, "evidencias")
        os.makedirs(ev_local, exist_ok=True)
        L.run([L.SCP, "-q", "-r", "-i", L.KEY, "-o", "BatchMode=yes", "angel@%s:C:/lab-attack/%s/evidencias/." % (IP_W, ata), ev_local], timeout=300)
        t0 = t_lanz
        tl = os.path.join(ev_local, "times.log")
        if os.path.isfile(tl):
            m = re.search(r"t0=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", open(tl, encoding="utf-8", errors="replace").read())
            if m:
                t0 = m.group(1)
                meta["t0_fuente"] = "times.log del ataque"
        meta.setdefault("t0_fuente", "reloj del manager al lanzar")
        meta["t0"], meta["t1"] = t0, t1
        open(os.path.join(ldir, "times.log.orquestador"), "w", encoding="utf-8", newline="\n").write(
            "T0=%s\nT1=%s\nLANZADO_MANAGER=%s\n" % (t0, t1, t_lanz))
        L.ssh(IP_W, "schtasks /delete /tn %s /f" % tn, timeout=40)
        time.sleep(60)
        # crudas del agente 002 (se guarda TODO) y Detalle
        os.makedirs(L.RAW, exist_ok=True)
        d0 = (dt.datetime.strptime(t0, "%Y-%m-%dT%H:%M:%SZ") - dt.timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d1 = (dt.datetime.strptime(t1, "%Y-%m-%dT%H:%M:%SZ") + dt.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rutas = {}
        for kind in ("alerts", "archives"):
            rc, blob, e = L.ssh(L.IP_M, "sudo -S -p '' python3 /home/angel/slice_ventana_manager.py %s %s %s %s" % (kind, AGENTE, d0, d1),
                                inp=L.PW + "\n", timeout=300, binary=True)
            p = os.path.join(L.RAW, "%s_%s_%s.jsonl.gz" % (tag, kind, AGENTE))
            with gzip.GzipFile(p, "wb", mtime=0) as gz:
                gz.write(blob)
            rutas[kind] = p
            meta["lineas_%s" % kind] = blob.count(b"\n")
        os.makedirs(os.path.join(L.OUT, "CSV"), exist_ok=True)
        det = os.path.join(L.OUT, "CSV", "%s-Detalle.csv" % tag)
        p = subprocess.run([sys.executable, "-I", os.path.join(L.REPO, "_artefactos", "scripts", "extraer_alertas_windows.py"),
                            "--alerts", rutas["alerts"], "--desde", t0, "--hasta", t1, "--agent-id", AGENTE,
                            "--agent-name", AGENTE_NOMBRE, "--detail", det], capture_output=True, text=True, encoding="utf-8", errors="replace")
        meta["extraccion_rc"] = p.returncode
        open(os.path.join(ldir, "extraccion.out"), "w", encoding="utf-8", newline="\n").write(p.stdout + p.stderr)
        meta["filas_detalle"] = max(0, sum(1 for _ in open(det, encoding="utf-8", errors="replace")) - 2) if os.path.isfile(det) else -1
        meta["estado"] = "OK" if p.returncode == 0 and meta["filas_detalle"] >= 0 else "REVISAR"
    except Exception as ex:                                  # noqa: BLE001
        meta["estado"] = "FALLO"
        meta["error"] = str(ex)[:300]
        L.log("%s FALLO: %s" % (tag, ex))
    finally:
        meta["fin_utc"] = L.now_utc()
        meta["segundos"] = round(time.time() - t_ini)
        json.dump(meta, open(os.path.join(ldir, "lanzamiento.json"), "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    return meta


def fase_pre():
    L.fase_pre()
    rc, o, e = L.run([sys.executable, "-I", SERV, "start"], timeout=180)
    L.log("PRE: servicios del host -> rc=%s %s" % (rc, (o + e).strip().replace("\n", " | ")[:300]))
    rc, o, e = L.run([sys.executable, "-I", SERV, "status"], timeout=120)
    L.log("PRE: servicios status -> %s" % (o + e).strip().replace("\n", " | ")[:300])


def fase_run(args):
    specs = cargar_especificaciones()
    if args.only:
        sel = set(args.only.split(","))
        specs = [s for s in specs if s["ata"] in sel]
    hechos = L.indice_ok() if not args.force else set()
    for s in specs:
        for it in (1, 2):
            tag = "%s_iter%d" % (s["ata"], it)
            if str(it) not in args.iters.split(",") or tag in hechos:
                continue
            if s["ata"] in PENDIENTE:
                L.indice_escribir({"tag": tag, "ata": s["ata"], "variante": "base", "iter": it, "estado": "PENDIENTE",
                                   "error": PENDIENTE[s["ata"]], "inicio_utc": L.now_utc()})
                L.log("%s PENDIENTE: %s" % (tag, PENDIENTE[s["ata"]]))
                continue
            if L.espacio_manager_gb() < 3:
                raise SystemExit("espacio del manager < 3 GB: paro la campana")
            L.log("=== %s ===" % tag)
            for intento in (1, 2):
                meta = ventana(s, it, args.timeout)
                if meta["estado"] != "FALLO":
                    break
                L.log("%s reintento tras FALLO" % tag)
            L.indice_escribir(meta)
            L.log("%s -> %s (t0=%s t1=%s filas=%s %ss)" % (tag, meta["estado"], meta.get("t0"), meta.get("t1"),
                                                         meta.get("filas_detalle"), meta.get("segundos")))


def fase_post(args):
    L.fase_post(args)
    L.run([sys.executable, "-I", SERV, "stop"], timeout=180)
    L.log("POST: servicios del host parados")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fase", choices=("pre", "run", "post", "todo"), default="todo")
    ap.add_argument("--out", default=os.path.join(L.REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "windows_v2"))
    ap.add_argument("--raw", default=r"D:\TFG-VMs\ataques-windows-v2-2026-11-20\raw")
    ap.add_argument("--crudo", default=r"D:\TFG-VMs\ataques-windows-v2-2026-11-20\crudo")
    ap.add_argument("--only", default="")
    ap.add_argument("--iters", default="1,2")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-off", action="store_true")
    ap.add_argument("--log", default=r"D:\TFG-VMs\lab-logs\ataques_windows_v2.txt")
    args = ap.parse_args()
    if not L.PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    L.OUT, L.RAW = args.out, args.raw
    os.makedirs(L.OUT, exist_ok=True)
    L._LOG_FH = open(args.log, "a", encoding="utf-8", newline="\n")
    L.log("ORQUESTADOR WINDOWS fase=%s out=%s" % (args.fase, L.OUT))
    if args.fase in ("pre", "todo"):
        fase_pre()
    if args.fase in ("run", "todo"):
        fase_run(args)
    if args.fase in ("post", "todo"):
        fase_post(args)
    L.log("ORQUESTADOR WINDOWS fin")


if __name__ == "__main__":
    main()
