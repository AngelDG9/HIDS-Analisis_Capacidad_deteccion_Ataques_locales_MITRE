#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probar_ojos_velociraptor.py - E1a del plan _fases/velociraptor-ojos/plan.md: prueba de MECANISMO de cada opcion de «ojos».

NO lanza ataques. Por cada opcion: tabla de monitorizacion del servidor -> VM revertida a `lab-listo-vr` -> actividad inocua y
reconocible en la VM (un comando con marca, crear/renombrar/borrar un fichero, chmod, un intento de conexion) -> se mira que filas
llegan al servidor, con que retraso y si ven cada tipo de actividad. Guarda las filas (gz) y un resumen JSON por opcion.

Opciones: A (EBPF por defecto) B (EBPF con Events afinado) G (TrackProcesses con reenvio) F1 (artifact propio con audit())
          F2 (artifact propio: sigue audit.log tal cual) E (Generic.Collectors.File sube audit.log entero al final)
La contrasena de las VMs SOLO por TFG_MANAGER_PW (entorno). Sin secretos en ficheros.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import orquestar_velociraptor_linux as vr        # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402

ART_DIR = os.path.join(olx.REPO, "Soporte", "Laboratorio", "velociraptor", "artifacts_propios")
CUSTOM = ["Custom.Linux.Events.AuditRaw", "Custom.Linux.Events.AuditLogTail"]
TODOS = sorted(set(vr.CFG["E"]) | set(vr.CFG["O"]) | set(CUSTOM))

# Eventos de EBPF por defecto (copiados de la definicion de Linux.Events.EBPF v0.77.3) con el cambio de la opcion B:
# security_file_open = N (era el 93 % del volumen) y se activan security_inode_rename y mkdir.
EBPF_DEFECTO = """bpf_attach Y|chdir N|fchownat Y|file_modification N|kill Y|magic_write N|mkdir N|module_free Y|mount Y|openat N|openat2 N|sched_process_exec Y|sched_process_exit Y|security_file_open Y|security_inode_mknod Y|security_inode_rename N|security_inode_symlink Y|security_kernel_post_read_file Y|security_socket_accept Y|security_socket_bind Y|security_socket_connect Y|setxattr Y|umount2 Y|unlink Y"""


def csv_ebpf(cambios):
    filas = []
    for it in EBPF_DEFECTO.split("|"):
        n, y = it.split()
        filas.append("%s,%s,%s" % (n, n, cambios.get(n, y)))
    return "Event,Desc,Enabled\\n" + "\\n".join(filas)


OPCIONES = {
    "A": {"tabla": [("Linux.Events.EBPF", {})], "art": ["Linux.Events.EBPF"]},
    "B": {"tabla": [("Linux.Events.EBPF", {"Events": csv_ebpf({"security_file_open": "N", "security_inode_rename": "Y", "mkdir": "Y"})})],
          "art": ["Linux.Events.EBPF"]},
    "G": {"tabla": [("Linux.Events.TrackProcesses", {"AlsoForwardUpdates": "Y"})], "art": ["Linux.Events.TrackProcesses"]},
    "F1": {"tabla": [("Custom.Linux.Events.AuditRaw", {})], "art": ["Custom.Linux.Events.AuditRaw"]},
    "F2": {"tabla": [("Custom.Linux.Events.AuditLogTail", {})], "art": ["Custom.Linux.Events.AuditLogTail"]},
    "E": {"tabla": [], "art": [], "coleccion": True},
    # todos los ojos a la vez (B + F1 + F2) y ademas la coleccion de audit.log*: prueba de coexistencia
    # EBPF «superconjunto» (los de fabrica + renombrados + mkdir): A y B se obtienen DESPUES filtrando por EventName
    "SUPER": {"tabla": [("Linux.Events.EBPF", {"Events": csv_ebpf({"security_inode_rename": "Y", "mkdir": "Y"})}),
                        ("Custom.Linux.Events.AuditRaw", {}), ("Custom.Linux.Events.AuditLogTail", {})],
              "art": ["Linux.Events.EBPF", "Custom.Linux.Events.AuditRaw", "Custom.Linux.Events.AuditLogTail"], "coleccion": True},
    "TODOS": {"tabla": [("Linux.Events.EBPF", {"Events": csv_ebpf({"security_file_open": "N", "security_inode_rename": "Y", "mkdir": "Y"})}),
                        ("Custom.Linux.Events.AuditRaw", {}), ("Custom.Linux.Events.AuditLogTail", {})],
              "art": ["Linux.Events.EBPF", "Custom.Linux.Events.AuditRaw", "Custom.Linux.Events.AuditLogTail"], "coleccion": True},
}
TOKENS = {"marca": "PROBEMARK", "fichero_creado": "probe_file", "fichero_renombrado": "probe_ren", "red": "probe_net",
          "evento_exec": "sched_process_exec", "evento_connect": "security_socket_connect", "evento_unlink": "unlink",
          "evento_rename": "security_inode_rename", "evento_open": "security_file_open"}


def vql(q, t=120):
    rc, o, e = vr.vr_query(q, timeout=t)
    return rc, o, e


def cargar_custom():
    for f in sorted(os.listdir(ART_DIR)):
        if f.endswith(".yaml"):
            p = os.path.join(ART_DIR, f).replace("\\", "/")
            rc, o, e = vql("SELECT artifact_set(definition=read_file(filename='%s')) AS r FROM scope()" % p)
            olx.log("artifact_set %s rc=%s %s" % (f, rc, (o + e)[-160:].replace("\n", " ")))
            if rc != 0:
                raise RuntimeError("artifact_set %s: %s" % (f, e[-200:]))


def vql_dict(d):
    """dict(...) de VQL. Los valores con saltos de linea (CSV) van entre comillas dobles (admiten \n); el resto, entre simples."""
    if not d:
        return "dict()"
    return "dict(" + ", ".join(('%s="%s"' if "\\n" in v else "%s='%s'") % (k, v) for k, v in d.items()) + ")"


def poner_tabla(tabla):
    for a in TODOS:
        vql("SELECT rm_client_monitoring(artifact='%s') AS r FROM scope()" % a)
    for a, p in tabla:
        q = "SELECT add_client_monitoring(artifact='%s'%s) AS r FROM scope()" % (a, (", parameters=" + vql_dict(p)) if p else "")
        rc, o, e = vql(q)
        if rc != 0:
            raise RuntimeError("add_client_monitoring %s: %s" % (a, e[-200:]))
    t = set(vr.tabla_actual())
    if {a for a, _ in tabla} - t:
        raise RuntimeError("la tabla no quedo como se pidio: %s" % sorted(t))
    return sorted(t)


def actividad(n):
    d = "/home/angel/lab-legit/probe"
    cmd = ("mkdir -p %(d)s; /bin/echo PROBEMARK_%(n)d; echo x > %(d)s/probe_file_%(n)d.txt; mv %(d)s/probe_file_%(n)d.txt %(d)s/probe_ren_%(n)d.txt; "
           "chmod 600 %(d)s/probe_ren_%(n)d.txt; rm -f %(d)s/probe_ren_%(n)d.txt; "
           "curl -s -m 3 http://192.168.65.1:9/probe_net_%(n)d >/dev/null 2>&1; true") % {"d": d, "n": n}
    olx.ssh(olx.IP_V, cmd, timeout=60)


def filas_desde(arts, t_desde):
    res = {}
    for a in arts:
        out = []
        for dia in ext.dias(t_desde, vr.now_utc_dt() + dt.timedelta(days=1)):
            for linea, row in ext.leer_filas(os.path.join(vr.MON, a, dia + ".json")):
                h = ext.hora_evento(row)
                if h is not None and h >= t_desde:
                    out.append((linea, h, row))
        res[a] = out
    return res


def contar(lineas):
    t = [l.decode("utf-8", "replace") for l in lineas]
    return {k: sum(1 for x in t if v in x) for k, v in TOKENS.items()}


def sonda_audit():
    """Estado de auditd en la VM: pid registrado en el kernel, perdidas, tamaño y lineas de marca en el audit.log."""
    rc, o, e = olx.ssh(olx.IP_V, "sudo -S -p '' auditctl -s; sudo -S -p '' stat -c 'audit.log bytes=%s mtime=%Y' /var/log/audit/audit.log; "
                       "sudo -S -p '' grep -c PROBEMARK /var/log/audit/audit.log; systemctl is-active auditd", inp=olx.PW + "\n" + olx.PW + "\n" + olx.PW + "\n" + olx.PW + "\n", timeout=60)
    return (o + e).strip()


def esperar_cliente(seg=240):
    t = time.time()
    while time.time() - t < seg:
        rc, o, e = vql("SELECT timestamp(epoch=last_seen_at/1000000) AS v FROM clients() WHERE client_id='%s'" % vr.CLIENTE, 60)
        try:
            v = json.loads(o)[0]["v"]
            if (vr.now_utc_dt() - dt.datetime.fromisoformat(v.replace("Z", "+00:00")[:26] + "+00:00")).total_seconds() < 90:
                return True
        except (ValueError, IndexError, KeyError):
            pass
        time.sleep(5)
    return False


def coleccionar_audit(out):
    """Opcion E: sube audit.log* con Generic.Collectors.File (el servidor lo guarda en zlib). Devuelve resumen por fichero."""
    r = {}
    rc, o, e = vql("SELECT collect_client(client_id='%s', artifacts='Generic.Collectors.File', env=dict(Root='/', collectionSpec=\"Glob\n/var/log/audit/audit.log*\")) AS f FROM scope()" % vr.CLIENTE)
    r["collect_rc"] = rc
    mf = re.search(r"F\.[A-Z0-9]+", o)
    fid = mf.group(0) if mf else None
    r["flow_id"] = fid
    estado = None
    for _ in range(60):
        rc, o2, e2 = vql("SELECT state FROM flows(client_id='%s', flow_id='%s')" % (vr.CLIENTE, fid), 60)
        if '"FINISHED"' in o2 or '"ERROR"' in o2:
            estado = "FINISHED" if "FINISHED" in o2 else "ERROR"
            break
        time.sleep(5)
    r["flow_estado"] = estado
    r["ficheros"] = {}
    for d, _, fs in os.walk(os.path.join(vr.SRV, "datastore", "clients", vr.CLIENTE, "collections", fid or "-", "uploads")):
        for f in fs:
            p = os.path.join(d, f)
            try:
                b = ext._flujos(open(p, "rb").read())
            except Exception as ex:                      # noqa: BLE001 - p. ej. ficheros auxiliares (indices) que no son zlib
                r["ficheros"][f] = {"bytes_en_disco": os.path.getsize(p), "no_descomprime": str(ex)[:80]}
                continue
            tx = b.decode("utf-8", "replace")
            r["ficheros"][f] = {"bytes_zlib": os.path.getsize(p), "bytes": len(b), "conteo": {k: tx.count(v) for k, v in TOKENS.items()}}
            with gzip.GzipFile(filename="", fileobj=open(os.path.join(out, f + ".gz"), "wb"), mode="wb", mtime=0) as g:
                g.write(b)
    return r


def sonda(op, args):
    cfg = OPCIONES[op]
    out = os.path.join(args.out, op)
    os.makedirs(out, exist_ok=True)
    res = {"opcion": op, "tabla": [a for a, _ in cfg["tabla"]], "parametros": {a: list(p) for a, p in cfg["tabla"]}, "inicio_utc": vr.iso(vr.now_utc_dt())}
    res["tabla_servidor"] = poner_tabla(cfg["tabla"])
    olx.vm_reset()
    if not olx.esperar_ssh(olx.IP_V, 300):
        raise RuntimeError("la victima no responde por SSH")
    res["cliente_conectado"] = esperar_cliente(240)
    res["audit_antes"] = sonda_audit()
    res["auditctl_antes"] = vr.reglas_audit()
    t_ini = vr.now_utc_dt()
    t_ref = t_ini - dt.timedelta(seconds=5)
    primera = None
    k = 0
    extra = 0
    while True:                                      # sale por las condiciones de abajo
        k += 1
        actividad(k)
        time.sleep(15)
        if cfg["art"]:
            f = filas_desde(cfg["art"], t_ref)
            lin = [x[0] for a in f for x in f[a]]
            if primera is None and contar(lin)["marca"] > 0:
                primera = round((vr.now_utc_dt() - t_ini).total_seconds())
            if primera is not None:
                extra += 1
        else:
            extra += 1
        if extra >= 4 or (vr.now_utc_dt() - t_ini).total_seconds() > args.max_seg:
            break
    res["segundos_hasta_primera_marca"] = primera
    res["iteraciones_actividad"] = k
    time.sleep(args.espera_final)
    t_fin = vr.now_utc_dt()
    res["audit_despues"] = sonda_audit()
    res["auditctl_despues"] = vr.reglas_audit()
    if cfg.get("coleccion"):
        res["coleccion"] = coleccionar_audit(out)
    if cfg["art"]:
        f = filas_desde(cfg["art"], t_ref)
        res["por_artifact"] = {}
        for a_, filas in f.items():
            ln = [x[0] for x in filas]
            ret = [x[2].get("_ts") - x[1].timestamp() for x in filas if b"PROBEMARK" in x[0] and isinstance(x[2].get("_ts"), (int, float))]
            h_marca = [x[1] for x in filas if b"PROBEMARK" in x[0]]
            res["por_artifact"][a_] = {"filas": len(ln), "filas_por_s": round(len(ln) / max(1, (t_fin - t_ini).total_seconds()), 2), "conteo": contar(ln),
                                       "retraso_medio_s": round(sum(ret) / len(ret), 1) if ret else None,
                                       "primera_marca_utc": vr.iso(min(h_marca)) if h_marca else None,
                                       "sample": [l.decode("utf-8", "replace")[:500] for l in ln if any(t in l for t in (b"probe_ren", b"probe_net"))][:3]}
            ext.escribir_gz(os.path.join(out, a_ + ".jsonl.gz"), ln)
        todas = [x for a_ in f for x in f[a_]]
        res["filas_total"] = len(todas)
        res["conteo"] = contar([x[0] for x in todas])
    res["fin_utc"] = vr.iso(vr.now_utc_dt())
    json.dump(res, open(os.path.join(out, "resumen.json"), "w", encoding="utf-8", newline="\n"), ensure_ascii=False, indent=1)
    olx.log("SONDA %s: %s" % (op, json.dumps({k: res.get(k) for k in ("filas_total", "segundos_hasta_primera_marca")} | {"por_artifact": {a_: v["filas"] for a_, v in res.get("por_artifact", {}).items()}, "coleccion": {f: v.get("bytes") for f, v in (res.get("coleccion") or {}).get("ficheros", {}).items()}}, ensure_ascii=False)))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--opciones", default="B,G,F2,F1,E")
    ap.add_argument("--out", default=r"D:\TFG-VMs\ataques-velociraptor-linux-ojos\sondas")
    ap.add_argument("--max-seg", type=int, default=600)
    ap.add_argument("--espera-final", type=int, default=100)
    ap.add_argument("--log", default=r"D:\TFG-VMs\lab-logs\velociraptor_ojos.txt")
    a = ap.parse_args()
    if not olx.PW:
        sys.exit("falta TFG_MANAGER_PW en el entorno")
    olx.SNAP = vr.SNAP_VR
    olx._LOG_FH = open(a.log, "a", encoding="utf-8", newline="\n")
    os.makedirs(a.out, exist_ok=True)
    cargar_custom()
    for op in a.opciones.split(","):
        olx.log("=== SONDA %s ===" % op)
        try:
            sonda(op, a)
        except Exception as ex:                      # noqa: BLE001
            olx.log("SONDA %s FALLO: %s" % (op, ex))
            os.makedirs(os.path.join(a.out, op), exist_ok=True)
            json.dump({"opcion": op, "estado": "FALLO", "error": str(ex)[:400]}, open(os.path.join(a.out, op, "resumen.json"), "w", encoding="utf-8"), ensure_ascii=False)
    poner_tabla([])
    olx.log("tabla del servidor dejada en neutro")


if __name__ == "__main__":
    main()
