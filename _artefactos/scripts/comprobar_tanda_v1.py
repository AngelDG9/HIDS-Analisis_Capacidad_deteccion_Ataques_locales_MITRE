#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comprobar_tanda_v1.py - comprobacion de INTEGRIDAD de lo guardado tras cada tanda de V1 (Velociraptor Linux). No sustituye a la verificacion independiente (V1-4).

Por cada ventana del indice con estado OK comprueba que NO FALTA ningun dato crudo:
  - existen los 11 ficheros del recorte (8 artifacts de eventos + audit.log + audit.log.1 + auditd_ventana) y no son vacios los que deben tener datos
    (EBPF, audit.log, audit.log.1, auditd_ventana);
  - sha256 de cada recorte == sha256_recortes.txt;  existen lanzamiento.json, ejecucion.out, times.log;
  - las 5 reglas de auditd antes y despues, e iguales;  marcas INI y FIN registradas;
  - el audit.log subido contiene las dos marcas;
y del crudo: sha256 de cada fichero == MANIFEST.tsv, y que existe la coleccion (flow) de cada ventana.
Uso: python comprobar_tanda_v1.py --out Dataset/.../linux_v1/cfgS --raw RAW/cfgS --crudo CRUDO [--casos ATA001,...]
Sin secretos. Solo biblioteca estandar. Sale con codigo 1 si falta algo.
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
import sys

ARTS = ["Linux.Events.%s" % n for n in ("DNS", "EBPF", "HTTPConnections", "Journal", "ProcessExecutions", "SSHBruteforce", "SSHLogin", "TrackProcesses")]
FICH = [a + ".jsonl.gz" for a in ARTS] + ["audit.log.gz", "audit.log.1.gz", "auditd_ventana.log.gz"]
NO_VACIOS = ["Linux.Events.EBPF.jsonl.gz", "audit.log.gz", "audit.log.1.gz", "auditd_ventana.log.gz"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--crudo", required=True)
    ap.add_argument("--casos", default="")
    a = ap.parse_args()
    casos = set(c for c in a.casos.split(",") if c)
    fallos, n = [], 0
    filas = list(csv.DictReader(open(os.path.join(a.out, "indice.csv"), encoding="utf-8")))
    for r in filas:
        tag = r["tag"]
        if r["estado"] != "OK" or (casos and tag.split("_")[0] not in casos):
            continue
        n += 1
        d, ld = os.path.join(a.raw, tag), os.path.join(a.out, "Logs", tag)
        for f in FICH:
            p = os.path.join(d, f)
            if not os.path.isfile(p):
                fallos.append("%s: falta %s" % (tag, f))
            elif f in NO_VACIOS and len(gzip.open(p, "rb").read()) == 0:
                fallos.append("%s: %s esta vacio" % (tag, f))
        for f in ("lanzamiento.json", "ejecucion.out", "times.log", "sha256_recortes.txt"):
            if not os.path.isfile(os.path.join(ld, f)):
                fallos.append("%s: falta Logs/%s" % (tag, f))
        try:
            for l in open(os.path.join(ld, "sha256_recortes.txt"), encoding="utf-8").read().splitlines():
                h, f = l.split()
                if sha(os.path.join(d, f)) != h:
                    fallos.append("%s: sha256 distinto en %s" % (tag, f))
            m = json.load(open(os.path.join(ld, "lanzamiento.json"), encoding="utf-8"))
            if len(m["auditd_antes"].splitlines()) != 5 or m["auditd_antes"] != m["auditd_despues"]:
                fallos.append("%s: reglas de auditd distintas de 5 o cambiadas" % tag)
            for k in ("marca_ini", "marca_fin"):
                tx = b"".join(gzip.open(os.path.join(d, f), "rb").read() for f in ("audit.log.1.gz", "audit.log.gz"))
                if m[k].encode() not in tx:
                    fallos.append("%s: %s no esta en el audit.log guardado" % (tag, k))
            fl = m["coleccion_audit"]["flow_id"]
            if not os.path.isdir(os.path.join(a.crudo, "collections", fl)):
                fallos.append("%s: falta la coleccion %s en el crudo" % (tag, fl))
        except Exception as ex:                                  # noqa: BLE001
            fallos.append("%s: no se pudo comprobar (%s)" % (tag, ex))
    k = 0
    for l in open(os.path.join(a.crudo, "MANIFEST.tsv"), encoding="utf-8").read().splitlines()[1:]:
        f, _, h = l.split("\t")
        p = os.path.join(a.crudo, f)
        if not os.path.isfile(p) or sha(p) != h:
            fallos.append("crudo: sha256 distinto o falta %s" % f)
        else:
            k += 1
    print("ventanas OK comprobadas: %d | ficheros del crudo con sha256 OK: %d" % (n, k))
    print("RESULTADO: " + ("COMPLETO, no falta nada" if not fallos else "%d PROBLEMAS" % len(fallos)))
    for f in fallos:
        print(" -", f)
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
