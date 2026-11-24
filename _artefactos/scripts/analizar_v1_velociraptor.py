#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analizar_v1_velociraptor.py - V1-5: tabla caso x vista de Velociraptor Linux (55 casos x 2) a partir de lo guardado (plan _fases/velociraptor-v1/plan.md).

Entradas (solo lectura): `Logs/<tag>/lanzamiento.json` (meta con las anclas de auditd y de EBPF) y `raw/cfgS/<tag>/` (EBPF recortado, auditd_ventana).
Para cada caso (iteraciones 1 y 2) y cada senal de `tipo=deteccion` del fichero esperado (se excluyen `rule_id`, que es vocabulario de Wazuh):
  - AU       = eventos de comando de auditd con la senal (como en el meta)
  - AU_OK    = lo mismo contando solo execve que TIENEN EXITO (success=yes), para separar los intentos fallidos que auditd apunta y EBPF no
  - EBPF     = sched_process_exec de EBPF con la senal (como en el meta)
Clasificacion por senal:
  IGUAL            AU == EBPF
  FALLIDOS         AU != EBPF pero AU_OK == EBPF   (la diferencia son intentos de execve fallidos, p. ej. buscar el binario en el PATH)
  EBPF_MAS         EBPF > AU_OK                   (EBPF cuenta mas: p. ej. el nombre real del binario en auditd es otro: nc -> nc.openbsd)
  EBPF_MENOS       EBPF < AU_OK                   (posible perdida de eventos de EBPF o nombre distinto)
Ademas, por caso: visibilidad de la senal en cada ojo (AU>0, EBPF>0) y vistas procesos/ficheros/red (funciones de analizar_ojos_velociraptor).
Sin secretos. Solo biblioteca estandar.  Uso: python analizar_v1_velociraptor.py --out DIR_cfgS --raw RAW_cfgS --salida DIR
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analizar_ojos_velociraptor as ao          # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402


def anclas_ok(raw, anclas):
    """Anclas de auditd contando solo execve con exito (success=yes). Mismo criterio de exe/cwd que ext.contar_anclas_audit."""
    ev = {}
    for l in ao.leer(os.path.join(raw, "auditd_ventana.log.gz")):
        m = ext._RX_AUDIT.search(l)
        if not m:
            continue
        t = l.decode("utf-8", "replace")
        d = ev.setdefault((m.group(1), m.group(2)), {"cmd": False, "ok": False, "exe": None, "cwd": None})
        campos = {k: ext._valor_audit(v, q if q != "" or v.startswith('"') else None) for k, v, q in ext._RX_CAMPO.findall(t)}
        if t.lstrip().startswith("type=SYSCALL"):
            d["cmd"] = "audit-wazuh-c" in campos.get("key", "")
            d["ok"] = campos.get("success") == "yes"
            d["exe"] = campos.get("exe")
        elif t.lstrip().startswith("type=CWD"):
            d["cwd"] = campos.get("cwd")
    res = {}
    for sid, campo, patron in anclas:
        n = 0
        for d in ev.values():
            if not (d["cmd"] and d["ok"]):
                continue
            if campo == "audit_cwd":
                b = ext._base_cwd(patron)
                n += 1 if d["cwd"] is not None and (d["cwd"] == b or d["cwd"].startswith(b + "/")) else 0
            else:
                n += 1 if d["exe"] is not None and ((d["exe"] == patron) if "/" in patron else (os.path.basename(d["exe"]) == patron)) else 0
        res[sid] = n
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--salida", required=True)
    a = ap.parse_args()
    os.makedirs(a.salida, exist_ok=True)
    filas, vistas = [], {}
    for tag in sorted(os.listdir(a.raw)):
        m = json.load(open(os.path.join(a.out, "Logs", tag, "lanzamiento.json"), encoding="utf-8"))
        if m.get("estado") != "OK":
            continue
        anclas = [tuple(x) for x in m["anclas"] if x[1] != "rule_id"]
        # las anclas se RECALCULAN desde lo guardado con la regla corregida (ruta completa si la senal lleva barra); el meta de la ventana
        # conserva las cifras antiguas (regla de solo nombre), que NO se usan aqui
        au = ext.contar_anclas_audit(ao.leer(os.path.join(a.raw, tag, "auditd_ventana.log.gz")), anclas)
        eb = ext.contar_anclas_exec_ebpf(ao.leer(os.path.join(a.raw, tag, "Linux.Events.EBPF.jsonl.gz")), anclas)
        ok = anclas_ok(os.path.join(a.raw, tag), anclas)
        for sid, campo, patron in anclas:
            x, y, z = au.get(sid, 0), ok.get(sid, 0), eb.get(sid, 0)
            clase = "IGUAL" if x == z else ("FALLIDOS" if y == z else ("EBPF_MAS" if z > y else "EBPF_MENOS"))
            filas.append({"tag": tag, "ata": m["ata"], "iter": m["iter"], "senal": sid, "campo": campo, "patron": patron,
                          "AU": x, "AU_OK": y, "EBPF": z, "clase": clase})
        vistas[tag] = ao.contar(os.path.join(a.raw, tag), m["ata"])
    with open(os.path.join(a.salida, "anclas_por_senal.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(filas)
    json.dump(vistas, open(os.path.join(a.salida, "vistas_procesos_ficheros_red.json"), "w", encoding="utf-8"), indent=1)

    # resumen
    tot = collections.Counter(f["clase"] for f in filas)
    vis_au = sum(1 for f in filas if f["AU"] > 0)
    vis_eb = sum(1 for f in filas if f["EBPF"] > 0)
    por_caso = collections.defaultdict(lambda: {"AU": 0, "EBPF": 0, "n": 0})
    for f in filas:
        if f["iter"] == 1:
            c = por_caso[f["ata"]]
            c["n"] += 1
            c["AU"] += 1 if f["AU"] > 0 else 0
            c["EBPF"] += 1 if f["EBPF"] > 0 else 0
    casos_todo_au = sum(1 for c in por_caso.values() if c["AU"] == c["n"])
    casos_todo_eb = sum(1 for c in por_caso.values() if c["EBPF"] == c["n"])
    casos_alguna_au = sum(1 for c in por_caso.values() if c["AU"] > 0)
    casos_alguna_eb = sum(1 for c in por_caso.values() if c["EBPF"] > 0)
    # ficheros y red por caso (iteracion 1)
    nfich = {"A": 0, "B": 0, "AU": 0}
    nred = {"A": 0, "B": 0, "AU": 0}
    for tag, v in vistas.items():
        if tag.endswith("_iter1"):
            for k in nfich:
                nfich[k] += 1 if v[k].get("fich", 0) > 0 else 0
                nred[k] += 1 if v[k].get("red", 0) > 0 else 0
    n_casos = len(por_caso)
    res = {"senales_por_iteracion": len(filas), "clases": dict(tot), "casos": n_casos,
           "senales_vistas_AU": vis_au, "senales_vistas_EBPF": vis_eb,
           "casos_con_todas_las_senales_AU": casos_todo_au, "casos_con_todas_las_senales_EBPF": casos_todo_eb,
           "casos_con_alguna_senal_AU": casos_alguna_au, "casos_con_alguna_senal_EBPF": casos_alguna_eb,
           "casos_con_ficheros_(iter1)": nfich, "casos_con_red_(iter1)": nred}
    json.dump(res, open(os.path.join(a.salida, "resumen.json"), "w", encoding="utf-8"), indent=1)
    print(json.dumps(res, indent=1))
    dif = [f for f in filas if f["clase"] != "IGUAL" and f["iter"] == 1]
    print("\nSenales con diferencia AU vs EBPF (iter1): %d" % len(dif))
    for f in dif:
        print("  %-8s %-14s %-9s %-12s AU=%d AU_OK=%d EBPF=%d -> %s" % (f["ata"], f["senal"], f["campo"], os.path.basename(f["patron"].rstrip("*")) or f["patron"], f["AU"], f["AU_OK"], f["EBPF"], f["clase"]))


if __name__ == "__main__":
    main()
