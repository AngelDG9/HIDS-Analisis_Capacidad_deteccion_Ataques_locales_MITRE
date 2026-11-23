#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analizar_ojos_velociraptor.py - comparacion de los «ojos» de Velociraptor (Linux) sobre la pasada cfgS (plan _fases/velociraptor-ojos/plan.md, E3).

De los datos guardados en `raw/cfgS/<caso>_iterN/` (EBPF = superconjunto, auditd_ventana.log.gz) saca, por caso e iteracion, lo que ve cada VISTA:
  A  = EBPF de fabrica (eventos activados por defecto)            B = EBPF afinado (sin security_file_open, con rename y mkdir)
  AU = auditd (audit.log subido = los mismos bytes que lee Wazuh), con nuestras 5 reglas
Para comparar los tres sobre LA MISMA actividad se define el «conjunto del ataque»: los procesos que arrancan con directorio de trabajo
/home/angel/lab-attack/<ATA> y todos sus descendientes (arbol pid->ppid de EBPF, que ve a todos los procesos). Despues se cuenta, por vista:
  procesos (arranques con exito) | ficheros (crear/renombrar/borrar/abrir) | red (connect/bind/accept) | intentos de exec fallidos (solo auditd).
Filtros declarados: «ficheros» = solo rutas bajo /home/angel/, /etc/, /tmp/ o /var/tmp/ (se descartan bibliotecas, /proc, /sys...);
«red» = solo AF_INET/AF_INET6 (se descartan los sockets unix del arranque del proceso).
Sin secretos. Solo biblioteca estandar.  Uso: python analizar_ojos_velociraptor.py --raw RAW/cfgS --out salida.json [--md salida.md]
"""
import argparse
import collections
import gzip
import json
import os
import re

POR_DEFECTO = {"bpf_attach", "fchownat", "kill", "module_free", "mount", "sched_process_exec", "sched_process_exit", "security_file_open",
               "security_inode_mknod", "security_inode_symlink", "security_kernel_post_read_file", "security_socket_accept", "security_socket_bind",
               "security_socket_connect", "setxattr", "umount2", "unlink"}
VISTA_A = POR_DEFECTO
VISTA_B = (POR_DEFECTO - {"security_file_open"}) | {"security_inode_rename", "mkdir"}
FICH = {"security_file_open", "security_inode_mknod", "security_inode_symlink", "unlink", "security_inode_rename", "mkdir", "fchownat", "setxattr", "security_kernel_post_read_file"}
RED = {"security_socket_connect", "security_socket_bind", "security_socket_accept"}
RX = re.compile(rb"msg=audit\((\d+\.\d+):(\d+)\)")
CAMPO = re.compile(r'(\w+)=("([^"]*)"|\S+)')


PREFIJOS = ("/home/angel/", "/etc/", "/tmp/", "/var/tmp/")


def rutas_relevantes(d):
    return any(isinstance(d.get(k), str) and d.get(k).startswith(PREFIJOS) for k in ("pathname", "syscall_pathname", "old_path", "new_path", "file_name"))


def es_inet(d):
    return str((d.get("remote_addr") or d.get("local_addr") or {}).get("sa_family", "")) in ("AF_INET", "AF_INET6")


def leer(path):
    return gzip.open(path, "rb").read().splitlines() if os.path.isfile(path) else []


def ebpf(raw):
    out = []
    for l in leer(os.path.join(raw, "Linux.Events.EBPF.jsonl.gz")):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        s = r.get("System") or {}
        out.append((s.get("EventName"), s.get("ProcessID"), s.get("ParentProcessID"), r.get("EventData") or {}, s.get("ProcessName")))
    return out


def conjunto_ataque(ev, ata):
    base = "/home/angel/lab-attack/" + ata
    padre, raices = {}, set()
    for n, pid, ppid, d, _ in ev:
        if pid is not None and ppid is not None:
            padre.setdefault(pid, ppid)
        if n == "sched_process_exec":
            pwd = str(d.get("pwd", ""))
            if pwd == base or pwd.startswith(base + "/"):
                raices.add(pid)
    conj = set(raices)
    cambio = True
    while cambio:
        cambio = False
        for pid, pp in padre.items():
            if pid not in conj and pp in conj:
                conj.add(pid)
                cambio = True
    return conj


def eventos_audit(raw):
    """{(ts,seq): {tipo: [campos...]}} con SYSCALL (pid, ppid, key, success, exe, syscall) y PATH (name)."""
    ev = collections.OrderedDict()
    for l in leer(os.path.join(raw, "auditd_ventana.log.gz")):
        m = RX.search(l)
        if not m:
            continue
        t = l.decode("utf-8", "replace")
        tipo = t.split(" ", 1)[0].replace("type=", "")
        campos = {k: (q if v.startswith('"') else v) for k, v, q in CAMPO.findall(t)}
        ev.setdefault((m.group(1), m.group(2)), collections.defaultdict(list))[tipo].append(campos)
    return ev


def contar(raw, ata):
    e = ebpf(raw)
    conj = conjunto_ataque(e, ata)
    res = {"pids_ataque": len(conj), "filas_ebpf": len(e)}
    for nombre, vista in (("A", VISTA_A), ("B", VISTA_B)):
        c = collections.Counter()
        for n, pid, _, d, _ in e:
            if pid in conj and n in vista:
                if n == "sched_process_exec":
                    c["proc"] += 1
                elif n in FICH and rutas_relevantes(d):
                    c["fich"] += 1
                elif n in RED and es_inet(d):
                    c["red"] += 1
        c["filas_total"] = sum(1 for x in e if x[0] in vista)
        res[nombre] = dict(c)
    c = collections.Counter()
    for k, partes in eventos_audit(raw).items():
        sc = (partes.get("SYSCALL") or [{}])[0]
        if not sc:
            continue
        try:
            pid = int(sc.get("pid", "-1"))
        except ValueError:
            continue
        c["filas_total"] += 1
        if pid not in conj:
            continue
        clave = sc.get("key", "")
        if "audit-wazuh-c" in clave:
            c["proc" if sc.get("success") == "yes" else "exec_fallido"] += 1
        elif "audit-wazuh-w" in clave and any(str(p.get("name", "")).startswith(PREFIJOS) for p in partes.get("PATH", [])):
            c["fich"] += 1
    res["AU"] = dict(c)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--md")
    a = ap.parse_args()
    todo = {}
    for tag in sorted(os.listdir(a.raw)):
        todo[tag] = contar(os.path.join(a.raw, tag), tag.split("_")[0])
    json.dump(todo, open(a.out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    lin = ["| caso | pids ataque | A proc/fich/red | B proc/fich/red | AUDIT proc/fich/red(=0)/exec fallidos |", "|---|---|---|---|---|"]
    for t, r in todo.items():
        f = lambda v: "%d/%d/%d" % (v.get("proc", 0), v.get("fich", 0), v.get("red", 0))
        lin.append("| %s | %d | %s | %s | %s/%d |" % (t, r["pids_ataque"], f(r["A"]), f(r["B"]), f(r["AU"]), r["AU"].get("exec_fallido", 0)))
    txt = "\n".join(lin)
    if a.md:
        open(a.md, "w", encoding="utf-8").write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()
