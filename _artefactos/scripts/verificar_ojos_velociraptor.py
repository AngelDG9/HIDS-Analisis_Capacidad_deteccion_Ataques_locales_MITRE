#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_ojos_velociraptor.py - verificacion INDEPENDIENTE de la pasada de «ojos» (cfgS) de Velociraptor Linux.

Recalcula desde la COPIA CRUDA (crudo/) con codigo propio (no importa el extractor ni el orquestador):
  1. sha256 de cada recorte (raw/cfgS/<caso>) contra sha256_recortes.txt, y de cada fichero del crudo contra MANIFEST.tsv;
  2. estado OK de las 18 ventanas esperadas (9 casos x 2) y marcas de inicio y fin presentes en el audit.log subido;
  3. recorte de EBPF recomputado desde crudo/monitoring == filas del recorte guardado (por hora del evento, [t0-60 s, t1+120 s]);
  4. anclas de auditd recomputadas desde el audit.log CRUDO de la coleccion (zlib) == las del meta;
  5. determinismo: iter1 == iter2 (anclas de auditd y de EBPF).
Uso: python verificar_ojos_velociraptor.py --out Dataset/.../linux_ojos/cfgS --raw RAW/cfgS --crudo CRUDO --informe salida.md
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
import re
import sys
import zlib

CASOS = ["ATA001", "ATA002", "ATA008", "ATA009", "ATA011", "ATA012", "ATA003", "ATA035", "ATA026"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def desc(b):
    """Descomprime una o varias corrientes zlib concatenadas; si no es zlib, devuelve tal cual."""
    if b[:1] in (b"{", b"t", b""):
        return b
    out = b""
    while b:
        o = zlib.decompressobj()
        out += o.decompress(b)
        b = o.unused_data
    return out


def t_iso(s):
    s = s.replace("Z", "+00:00")
    if "." in s:
        a, r = s.split(".", 1)
        dig = ""
        while r and r[0].isdigit():
            dig, r = dig + r[0], r[1:]
        s = a + "." + dig[:6].ljust(6, "0") + r
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def anclas_de(ata, repo):
    f = glob.glob(os.path.join(repo, "Dataset", "Ataques", "Comandos", "T*", ata + "_esperado.csv"))[0]
    lin = [l for l in open(f, encoding="utf-8") if not l.startswith("#") and l.strip()]
    return [(r["senal_id"], r["campo"], r["patron"]) for r in csv.DictReader(lin) if r.get("tipo") == "deteccion"]


def audit_anclas_propio(texto, anclas):
    """Cuenta por evento (ts:seq) las lineas SYSCALL con key audit-wazuh-c cuyo exe (o cwd del registro CWD) casa. Distinto codigo que el extractor."""
    ev = {}
    for l in texto.splitlines():
        m = re.search(r"msg=audit\(([\d.]+):(\d+)\)", l)
        if not m:
            continue
        e = ev.setdefault(m.groups(), {})
        if l.startswith("type=SYSCALL") and "key=\"audit-wazuh-c\"" in l:
            e["c"] = True
            x = re.search(r' exe="([^"]*)"', l)
            e["exe"] = os.path.basename(x.group(1)) if x else None
        elif l.startswith("type=CWD"):
            x = re.search(r'cwd="([^"]*)"', l)
            e["cwd"] = x.group(1) if x else None
    res = {}
    for sid, campo, pat in anclas:
        n = 0
        for e in ev.values():
            if not e.get("c"):
                continue
            if campo == "audit_cwd":
                b = pat.rstrip("*").rstrip("/")
                n += 1 if (e.get("cwd") or "").startswith(b) else 0
            else:
                n += 1 if e.get("exe") == pat else 0
        res[sid] = n
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--crudo", required=True)
    ap.add_argument("--informe", required=True)
    ap.add_argument("--repo", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    a = ap.parse_args()
    fallos, filas = [], []

    # 1a. sha256 del crudo
    n_ok = 0
    for l in open(os.path.join(a.crudo, "MANIFEST.tsv"), encoding="utf-8").read().splitlines()[1:]:
        f, _, h = l.split("\t")
        p = os.path.join(a.crudo, f)
        if not os.path.isfile(p) or sha(p) != h:
            fallos.append("crudo: sha256 distinto o falta %s" % f)
        else:
            n_ok += 1
    filas.append("- sha256 del crudo (MANIFEST.tsv): %d ficheros OK" % n_ok)

    # estado de las ventanas
    idx = {r["tag"]: r for r in csv.DictReader(open(os.path.join(a.out, "indice.csv"), encoding="utf-8"))}
    esperadas = ["%s_iter%d" % (c, i) for c in CASOS for i in (1, 2)]
    for t in esperadas:
        if t not in idx or idx[t]["estado"] != "OK":
            fallos.append("ventana %s no esta OK" % t)
    filas.append("- ventanas OK: %d de %d esperadas" % (sum(1 for t in esperadas if idx.get(t, {}).get("estado") == "OK"), len(esperadas)))

    # lectura unica del EBPF crudo (todas las ventanas a la vez)
    metas = {t: json.load(open(os.path.join(a.out, "Logs", t, "lanzamiento.json"), encoding="utf-8")) for t in esperadas}
    vent = {}
    for t, m in metas.items():
        vent[t] = (t_iso(m["t0"]) - dt.timedelta(seconds=60), t_iso(m["t1"]) + dt.timedelta(seconds=120))
    cuenta = {t: 0 for t in esperadas}
    for dia in sorted(glob.glob(os.path.join(a.crudo, "monitoring", "Linux.Events.EBPF", "*.json"))):
        for l in desc(open(dia, "rb").read()).splitlines():
            if not l.startswith(b"{"):
                continue
            try:
                ts = t_iso(json.loads(l)["System"]["Timestamp"])
            except (ValueError, KeyError):
                continue
            for t, (i, f) in vent.items():
                if i <= ts <= f:
                    cuenta[t] += 1

    anc = {}
    for t in esperadas:
        d = os.path.join(a.raw, t)
        # 1b. sha256 de recortes
        for l in open(os.path.join(a.out, "Logs", t, "sha256_recortes.txt"), encoding="utf-8").read().splitlines():
            h, f = l.split()
            if sha(os.path.join(d, f)) != h:
                fallos.append("%s: sha256 del recorte %s distinto" % (t, f))
        m = metas[t]
        # 2. marcas en el audit.log subido (recortes de raw = copia del fichero entero)
        txt = b"".join(desc(open(os.path.join(a.crudo, "collections", m["coleccion_audit"]["flow_id"], "uploads", "auto", "var", "log", "audit", n), "rb").read())
                       for n in ("audit.log.1", "audit.log")).decode("utf-8", "replace")
        for k in ("marca_ini", "marca_fin"):
            if m[k] not in txt:
                fallos.append("%s: marca %s ausente en el audit.log crudo" % (t, k))
        # 3. recorte EBPF
        guardadas = len([x for x in gzip.open(os.path.join(d, "Linux.Events.EBPF.jsonl.gz"), "rb").read().splitlines() if x.startswith(b"{")])
        if guardadas != cuenta[t]:
            fallos.append("%s: filas EBPF recomputadas %d != guardadas %d" % (t, cuenta[t], guardadas))
        # 4. anclas auditd desde el audit.log CRUDO, recortado por hora de auditd
        ini, fin = vent[t]
        lin = []
        for l in txt.splitlines():
            x = re.search(r"msg=audit\(([\d.]+):", l)
            if x and ini <= dt.datetime.fromtimestamp(float(x.group(1)), tz=dt.timezone.utc) <= fin:
                lin.append(l)
        anc[t] = audit_anclas_propio("\n".join(lin), anclas_de(m["ata"], a.repo))
        if anc[t] != m["audit"]["anclas_audit_estricto"]:
            fallos.append("%s: anclas auditd recomputadas %s != meta %s" % (t, anc[t], m["audit"]["anclas_audit_estricto"]))
    filas.append("- recorte EBPF recomputado desde crudo == guardado, y anclas de auditd recomputadas == meta, en las 18 ventanas (ver fallos)")

    # 5. determinismo
    for c in CASOS:
        if anc[c + "_iter1"] != anc[c + "_iter2"]:
            fallos.append("%s: iter1 != iter2 en anclas de auditd" % c)
        e1 = metas[c + "_iter1"]["resumen"]["Linux.Events.EBPF"]["anclas_exec_estricto"]
        e2 = metas[c + "_iter2"]["resumen"]["Linux.Events.EBPF"]["anclas_exec_estricto"]
        if e1 != e2:
            fallos.append("%s: iter1 != iter2 en anclas de EBPF" % c)
    filas.append("- determinismo iter1 == iter2 (anclas auditd y EBPF) en los 9 casos")

    txt = "# Verificacion independiente de la pasada de ojos (cfgS)\n\n" + "\n".join(filas) + "\n\n"
    txt += ("**RESULTADO: OK, sin fallos.**\n" if not fallos else "**RESULTADO: %d FALLOS**\n\n" % len(fallos) + "\n".join("- " + f for f in fallos) + "\n")
    open(a.informe, "w", encoding="utf-8").write(txt)
    print(txt)
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
