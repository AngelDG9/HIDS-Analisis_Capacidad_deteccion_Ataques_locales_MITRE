#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_piloto_velociraptor.py - verificacion INDEPENDIENTE del piloto V0d de Velociraptor (Linux).

Recalcula todo desde la COPIA CRUDA (no desde los recortes) con codigo propio (no importa el extractor):
  1. sha256 de cada recorte contra sha256_recortes.txt y del crudo contra MANIFEST.tsv;
  2. marcas de inicio y fin vistas; estado OK; ventanas esperadas presentes;
  3. recorte recomputado desde crudo/monitoring == filas guardadas por artifact;
  4. anclas recomputadas (estrictas, sobre sched_process_exec de EBPF) == las del meta;
  5. determinismo: iter1 vs iter2 (mismas anclas estrictas) y tabla caso x artifact.
Uso: python verificar_piloto_velociraptor.py --out Dataset/.../linux_piloto --raw D:\\TFG-VMs\\...\\raw --crudo D:\\TFG-VMs\\...\\crudo --informe salida.md
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import csv
import datetime as dt
import glob
import gzip
import hashlib
import json
import os
import sys
import zlib

ESPERADAS = {"E": ["ATA001", "ATA002", "ATA008", "ATA009", "ATA011", "ATA012"], "O": ["ATA001", "ATA002", "ATA008", "ATA009", "ATA011", "ATA012"]}
ITERS = {"E": (1, 2), "O": (1,)}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def lineas_crudas(path):
    if not os.path.isfile(path):
        return []
    b = open(path, "rb").read()
    if b[:1] not in (b"{", b"", b"\n"):
        out = b""
        while b:
            o = zlib.decompressobj()
            out += o.decompress(b)
            b = o.unused_data
        b = out
    return [l for l in b.splitlines() if l.startswith(b"{")]


def parse_t(s):
    s = s.replace("Z", "+00:00")
    if "." in s:
        a, r = s.split(".", 1)
        dig = ""
        while r and r[0].isdigit():
            dig, r = dig + r[0], r[1:]
        s = a + "." + dig[:6].ljust(6, "0") + r
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def t_evento(r):
    s = r.get("System")
    if isinstance(s, dict) and isinstance(s.get("Timestamp"), str):
        return parse_t(s["Timestamp"])
    for k in ("Time", "Timestamp", "timestamp"):
        if isinstance(r.get(k), str):
            return parse_t(r[k])
    if isinstance(r.get("_ts"), (int, float)):
        return dt.datetime.fromtimestamp(r["_ts"], tz=dt.timezone.utc)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--crudo", required=True)
    ap.add_argument("--informe", required=True)
    a = ap.parse_args()
    fallos, filas_tabla = [], []
    # 1. crudo contra MANIFEST
    man = os.path.join(a.crudo, "MANIFEST.tsv")
    n_man = 0
    if not os.path.isfile(man):
        fallos.append("falta MANIFEST.tsv del crudo")
    else:
        for r in csv.DictReader(open(man, encoding="utf-8"), delimiter="\t"):
            p = os.path.join(a.crudo, r["fichero"])
            n_man += 1
            if not os.path.isfile(p) or sha(p) != r["sha256"]:
                fallos.append("crudo: sha256 distinto o falta %s" % r["fichero"])
    anclas_por_caso = {}
    for cfg in ("E", "O"):
        for ata in ESPERADAS[cfg]:
            for it in ITERS[cfg]:
                tag = "%s_iter%d" % (ata, it)
                ldir = os.path.join(a.out, "cfg" + cfg, "Logs", tag)
                rdir = os.path.join(a.raw, "cfg" + cfg, tag)
                mp = os.path.join(ldir, "lanzamiento.json")
                if not os.path.isfile(mp):
                    fallos.append("%s/%s: falta la ventana" % (cfg, tag))
                    continue
                m = json.load(open(mp, encoding="utf-8"))
                if m.get("estado") != "OK":
                    fallos.append("%s/%s: estado %s %s" % (cfg, tag, m.get("estado"), m.get("error", "")))
                    continue
                if m.get("marca_ini_seg") is None or m.get("marca_fin_seg") is None:
                    fallos.append("%s/%s: faltan marcas" % (cfg, tag))
                # 2. sha de recortes
                sp = os.path.join(ldir, "sha256_recortes.txt")
                for l in open(sp, encoding="utf-8"):
                    h, nom = l.split()
                    if sha(os.path.join(rdir, nom)) != h:
                        fallos.append("%s/%s: sha256 distinto en %s" % (cfg, tag, nom))
                # 3. recorte recomputado desde el crudo
                t0 = parse_t(m["t0"]) - dt.timedelta(seconds=60)
                t1 = parse_t(m["t1"]) + dt.timedelta(seconds=120)
                for art, r in m["resumen"].items():
                    d = t0.date()
                    todas = []
                    while d <= (t1 + dt.timedelta(seconds=600)).date():
                        todas += lineas_crudas(os.path.join(a.crudo, "monitoring", art, d.isoformat() + ".json"))
                        d += dt.timedelta(days=1)
                    dentro = []
                    for l in todas:
                        try:
                            tt = t_evento(json.loads(l))
                        except ValueError:
                            continue
                        if tt is not None and t0 <= tt <= t1:
                            dentro.append(l)
                    guardadas = [l for l in gzip.open(os.path.join(rdir, art + ".jsonl.gz")).read().splitlines() if l]
                    if len(dentro) != len(guardadas) or len(guardadas) != r["filas"]:
                        fallos.append("%s/%s %s: filas crudo=%d recorte=%d meta=%d" % (cfg, tag, art, len(dentro), len(guardadas), r["filas"]))
                    if art == "Linux.Events.EBPF" and cfg == "E":
                        ev = []
                        for l in dentro:
                            j = json.loads(l)
                            if (j.get("System") or {}).get("EventName") == "sched_process_exec":
                                ev.append(j.get("EventData") or {})
                        for sid, campo, pat in m["anclas"]:
                            n = 0
                            for e in ev:
                                if campo == "audit_cwd":
                                    base = pat.rstrip("*").rstrip("/")
                                    pw = str(e.get("pwd", ""))
                                    n += (pw == base or pw.startswith(base + "/"))
                                else:
                                    nombres = {os.path.basename(str(e.get("pathname", ""))), os.path.basename(str(e.get("cmdpath", "")))}
                                    if e.get("argv"):
                                        nombres.add(os.path.basename(str(e["argv"][0])))
                                    n += (pat in nombres)
                            if n != r["anclas_exec_estricto"].get(sid):
                                fallos.append("%s/%s ancla %s: recomputada=%d meta=%s" % (cfg, tag, sid, n, r["anclas_exec_estricto"].get(sid)))
                            anclas_por_caso.setdefault(ata, {}).setdefault(it, {})[sid] = n
                filas_tabla.append((cfg, tag, m["resumen"]))
    # 5. determinismo iter1 vs iter2 (E)
    difs = []
    for ata, d in anclas_por_caso.items():
        if 1 in d and 2 in d:
            for sid in d[1]:
                if (d[1][sid] > 0) != (d[2].get(sid, 0) > 0):
                    difs.append("%s %s: iter1=%d iter2=%s (visto/no visto distinto)" % (ata, sid, d[1][sid], d[2].get(sid)))
    L = ["# Verificacion del piloto V0d de Velociraptor (Linux)", "",
         "Recomputado desde la copia cruda con codigo independiente del extractor.", "",
         "- ficheros del crudo verificados contra MANIFEST: %d" % n_man,
         "- ventanas revisadas: %d" % len(filas_tabla),
         "- **fallos: %d**" % len(fallos)]
    L += ["  - " + f for f in fallos]
    L += ["- diferencias iter1 vs iter2 en 'visto/no visto' de anclas: %d" % len(difs)] + ["  - " + d for d in difs]
    L += ["", "## Tabla caso x artifact (filas en la ventana; anclas estrictas de EBPF)", "",
          "| cfg | ventana | " + " | ".join(x.split(".")[-1] for x in ("Linux.Events.EBPF", "Linux.Events.ProcessExecutions", "Linux.Events.TrackProcesses", "Linux.Events.Journal", "Linux.Events.DNS")) + " | anclas estrictas EBPF |", "|---|---|---|---|---|---|---|---|"]
    for cfg, tag, res in filas_tabla:
        L.append("| %s | %s | %s | %s |" % (cfg, tag, " | ".join(str(res[x]["filas"]) for x in ("Linux.Events.EBPF", "Linux.Events.ProcessExecutions", "Linux.Events.TrackProcesses", "Linux.Events.Journal", "Linux.Events.DNS")),
                                            json.dumps(res["Linux.Events.EBPF"].get("anclas_exec_estricto", {})) if cfg == "E" else "-"))
    open(a.informe, "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
    print("\n".join(L[:12]))
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
