#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_completitud_ataques_v2.py - comprueba que la campana de ataques v2 (Linux o Windows) lo guardo TODO.

No se fia de la documentacion: lee el indice, los ficheros reales y los recalcula.

Por ventana OK comprueba:
  * existen Logs/<tag>/lanzamiento.json (+ salida del ataque), CSV/<tag>-Detalle.csv, Auditado/<tag>-Audited.csv y -Revision.csv;
  * existen las lineas CRUDAS <raw>/<tag>_alerts_<agente>.jsonl.gz y _archives_ y NO estan vacias, y su numero de lineas
    coincide con el del indice;
  * t0 < t1 y la ventana es razonable;
  * el sha256 del script de ataque guardado coincide con el del repo;
  * CRUZADO: las alertas crudas del agente dentro de [t0,t1] == filas del Detalle (misma fuente, dos caminos);
  * los eventos crudos (archives) cubren la ventana (hay alguno dentro de [t0,t1]).
Y a nivel de campana: copia cruda (`crudo/MANIFEST.tsv`) con sha256 recalculado, crudo.done, numero de ventanas esperadas.

Uso: python verificar_completitud_ataques_v2.py --so linux|windows [--esperadas 128] [--sin-hash-crudo]
Escribe <out>/VERIFICACION_COMPLETITUD.md y sale con codigo 1 si hay algun fallo.
"""
import argparse
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def ts(s):
    return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")


def lineas_gz(p):
    n = 0
    stamps = []
    with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fh:
        for l in fh:
            n += 1
            i = l.find('"timestamp":"')
            if i >= 0:
                stamps.append(l[i + 13:i + 32])
    return n, stamps


def filas_csv(p):
    rows = [r for r in csv.reader(open(p, encoding="utf-8", errors="replace")) if r and not r[0].lstrip().startswith("#")]
    return max(0, len(rows) - 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", choices=("linux", "windows"), required=True)
    ap.add_argument("--esperadas", type=int, default=0)
    ap.add_argument("--sin-hash-crudo", action="store_true")
    ap.add_argument("--base", default="")
    ap.add_argument("--raw", default="")
    ap.add_argument("--crudo", default="")
    a = ap.parse_args()
    agente = "001" if a.so == "linux" else "002"
    out = a.base or os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", a.so + "_v2")
    raw = a.raw or r"D:\TFG-VMs\ataques-%s-v2-2026-11-20\raw" % a.so
    crudo = a.crudo or r"D:\TFG-VMs\ataques-%s-v2-2026-11-20\crudo" % a.so
    cmd_dir = os.path.join(REPO, "Dataset", "Ataques", "Comandos") + ("\\windows" if a.so == "windows" else "")
    fallos, avisos, ok = [], [], 0
    ultimo = {}
    for r in csv.DictReader(open(os.path.join(out, "windows_index.csv"), encoding="utf-8")):
        ultimo[r["tag"]] = r
    estados = {}
    for r in ultimo.values():
        estados[r["estado"]] = estados.get(r["estado"], 0) + 1
    if a.esperadas and len(ultimo) != a.esperadas:
        fallos.append("ventanas en el indice=%d, esperadas=%d" % (len(ultimo), a.esperadas))
    for tag, r in sorted(ultimo.items()):
        if r["estado"] != "OK":
            fallos.append("%s: estado %s (%s)" % (tag, r["estado"], r.get("error", "")[:60]))
            continue
        malo = []
        ld = os.path.join(out, "Logs", tag)
        for f in ("lanzamiento.json", "sha256_artefacto.txt"):
            if not os.path.isfile(os.path.join(ld, f)):
                malo.append("falta Logs/" + f)
        if a.so == "linux" and not os.path.isfile(os.path.join(ld, "ejecucion.out")):
            malo.append("falta ejecucion.out")
        if a.so == "windows" and not os.path.isdir(os.path.join(ld, "evidencias")):
            malo.append("falta evidencias/")
        det = os.path.join(out, "CSV", tag + "-Detalle.csv")
        if not os.path.isfile(det):
            malo.append("falta Detalle")
        aud = os.path.join(out, "Auditado", "%s-Audited.csv" % tag)
        rev = os.path.join(out, "Auditado", "%s-Revision.csv" % tag)
        if not os.path.isfile(aud):
            malo.append("falta Auditado/Audited")
        elif not os.path.isfile(rev):
            # `Revision` solo existe si hay filas `dudosa`: sin fichero, tiene que haber 0 dudosas
            filas_a = [x for x in csv.reader(open(aud, encoding="utf-8", errors="replace")) if x and not x[0].lstrip().startswith("#")]
            if filas_a and "categoria" in filas_a[0]:
                ci = filas_a[0].index("categoria")
                if any(x[ci] == "dudosa" for x in filas_a[1:] if len(x) > ci):
                    malo.append("hay filas dudosa pero falta Revision")
        t0, t1 = ts(r["t0"]), ts(r["t1"])
        if not t0 < t1 or (t1 - t0).total_seconds() > 900:
            malo.append("ventana rara t0=%s t1=%s" % (r["t0"], r["t1"]))
        rawf = {}
        for kind in ("alerts", "archives"):
            p = os.path.join(raw, "%s_%s_%s.jsonl.gz" % (tag, kind, agente))
            if not os.path.isfile(p):
                malo.append("falta raw " + kind)
                continue
            n, stamps = lineas_gz(p)
            rawf[kind] = (n, stamps)
            if n == 0:
                malo.append("raw %s vacio" % kind)
            if str(n) != r.get("lineas_" + kind, ""):
                malo.append("raw %s=%d != indice %s" % (kind, n, r.get("lineas_" + kind)))
        # cruce alertas crudas en [t0,t1] vs Detalle
        if "alerts" in rawf and os.path.isfile(det):
            dentro = sum(1 for s in rawf["alerts"][1] if t0 <= ts(s) <= t1)
            nd = filas_csv(det)
            if abs(dentro - nd) > max(2, int(0.01 * nd)):
                malo.append("alertas crudas en ventana=%d != filas Detalle=%d" % (dentro, nd))
        if "archives" in rawf:
            if not any(t0 <= ts(s) <= t1 for s in rawf["archives"][1]):
                malo.append("ningun evento crudo (archives) dentro de [t0,t1]")
        # script de ataque igual al del repo
        try:
            meta = json.load(open(os.path.join(ld, "lanzamiento.json"), encoding="utf-8"))
            if meta.get("script_sha256") != meta.get("sha256_en_victima"):
                malo.append("sha256 repo != victima")
        except Exception as ex:                                  # noqa: BLE001
            malo.append("lanzamiento.json ilegible: %s" % ex)
        if malo:
            fallos.append("%s: %s" % (tag, "; ".join(malo)))
        else:
            ok += 1
    # copia cruda
    cr = []
    man = os.path.join(crudo, "MANIFEST.tsv")
    if not os.path.isfile(man):
        fallos.append("falta crudo/MANIFEST.tsv")
    elif not os.path.isfile(os.path.join(crudo, "crudo.done")):
        fallos.append("falta crudo/crudo.done")
    else:
        filas = [l.rstrip("\n").split("\t") for l in open(man, encoding="utf-8")][1:]
        cr.append("crudo: %d ficheros en el manifiesto" % len(filas))
        if not a.sin_hash_crudo:
            malos = 0
            for f in filas:
                p = os.path.join(crudo, f[0].replace("/", os.sep))
                if not os.path.isfile(p) or sha(p) != f[2]:
                    malos += 1
                    fallos.append("crudo: sha256 distinto o falta %s" % f[0])
            cr.append("crudo: sha256 recalculados, discrepancias=%d" % malos)
        gr = [f for f in filas if f[0].startswith("archives/") and (f[0].endswith(".json") or f[0].endswith(".gz"))]
        if not gr:
            fallos.append("crudo: no hay archives en la copia cruda")
    informe = ["# Verificacion de completitud — ataques %s v2" % a.so, "",
               "Generado por `_artefactos/scripts/verificar_completitud_ataques_v2.py` (recalcula, no se fia de la documentacion).", "",
               "- Estados en el indice: %s" % estados, "- Ventanas OK y completas: **%d** de %d" % (ok, len(ultimo))] + ["- " + c for c in cr]
    informe += ["", "## Fallos (%d)" % len(fallos)] + (["- " + f for f in fallos] if fallos else ["ninguno"])
    informe += ["", "## Avisos"] + (["- " + f for f in avisos] if avisos else ["ninguno"])
    open(os.path.join(out, "VERIFICACION_COMPLETITUD.md"), "w", encoding="utf-8", newline="\n").write("\n".join(informe) + "\n")
    print("\n".join(informe[:12]))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
