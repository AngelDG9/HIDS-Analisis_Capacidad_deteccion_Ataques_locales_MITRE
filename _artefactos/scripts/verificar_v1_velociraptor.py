#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_v1_velociraptor.py - verificacion INDEPENDIENTE de V1 (55 casos x 2, cfgS) de Velociraptor Linux (plan _fases/velociraptor-v1/plan.md, V1-4).

Recalcula desde la COPIA CRUDA (crudo/) con codigo propio (no importa el extractor ni el orquestador):
  1. sha256 de cada recorte (raw/cfgS/<caso>) contra sha256_recortes.txt, y de cada fichero del crudo contra MANIFEST.tsv;
  2. estado OK de las 110 ventanas esperadas (55 casos x 2) y marcas de inicio y fin presentes en el audit.log subido;
  3. recorte de EBPF recomputado desde crudo/monitoring == filas del recorte guardado (por hora del evento, [t0-60 s, t1+120 s]);
  4. anclas de auditd recomputadas desde el audit.log CRUDO de la coleccion (zlib) == las del meta;
  5. determinismo: iter1 vs iter2 (anclas de auditd y de EBPF): NO se supone igualdad; los casos que difieren se LISTAN (no son fallo de verificacion).
Uso: python verificar_v1_velociraptor.py --out Dataset/.../linux_ojos/cfgS --raw RAW/cfgS --crudo CRUDO --informe salida.md
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

ATAS_ESPERADAS = 55


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
    return [(r["senal_id"], r["campo"], r["patron"]) for r in csv.DictReader(lin) if r.get("tipo") == "deteccion" and r["campo"] != "rule_id"]


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
            e["path"] = x.group(1) if x else None
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
                n += 1 if ((e.get("path") == pat) if "/" in pat else (e.get("exe") == pat)) else 0
        res[sid] = n
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--crudo", required=True)
    ap.add_argument("--informe", required=True)
    ap.add_argument("--analisis", required=True, help="anclas_por_senal.csv de analizar_v1_velociraptor.py (cifras con la regla corregida)")
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
    casos = sorted({t.split("_")[0] for t in idx})
    if len(casos) != ATAS_ESPERADAS:
        fallos.append("el indice tiene %d casos, se esperaban %d" % (len(casos), ATAS_ESPERADAS))
    esperadas = ["%s_iter%d" % (c, i) for c in casos for i in (1, 2)]
    for t in esperadas:
        if t not in idx or idx[t]["estado"] != "OK":
            fallos.append("ventana %s no esta OK" % t)
    filas.append("- ventanas OK: %d de %d esperadas" % (sum(1 for t in esperadas if idx.get(t, {}).get("estado") == "OK"), len(esperadas)))

    # lectura unica del EBPF crudo (todas las ventanas a la vez)
    metas = {t: json.load(open(os.path.join(a.out, "Logs", t, "lanzamiento.json"), encoding="utf-8")) for t in esperadas}
    vent = {}
    for t, m in metas.items():
        vent[t] = (t_iso(m["t0"]) - dt.timedelta(seconds=60), t_iso(m["t1"]) + dt.timedelta(seconds=120))
    csvan = {}
    for r in csv.DictReader(open(a.analisis, encoding="utf-8")):
        csvan[(r["tag"], r["senal"])] = (int(r["AU"]), int(r["EBPF"]))
    execs = {t: [] for t in esperadas}                         # sched_process_exec de EBPF por ventana (para las anclas de EBPF, con codigo propio)
    cuenta = {t: 0 for t in esperadas}
    orden = sorted(vent.items(), key=lambda kv: kv[1][0])
    inicios = [v[0].timestamp() for _, v in orden]
    import bisect
    rx = re.compile(rb'"Timestamp":\s*"([^"]+)"')
    for dia in sorted(glob.glob(os.path.join(a.crudo, "monitoring", "Linux.Events.EBPF", "*.json"))):
        for l in desc(open(dia, "rb").read()).splitlines():
            if not l.startswith(b"{"):
                continue
            m = rx.search(l)
            if not m:
                continue
            try:
                ts = t_iso(m.group(1).decode()).timestamp()
            except ValueError:
                continue
            i = bisect.bisect_right(inicios, ts)
            for k in range(max(0, i - 3), i):                    # ventanas que empiezan antes que ts (pueden solaparse unas pocas)
                t, (ini, fin) = orden[k]
                if ini.timestamp() <= ts <= fin.timestamp():
                    cuenta[t] += 1
                    if b'"sched_process_exec"' in l:
                        try:
                            d = json.loads(l).get("EventData") or {}
                            execs[t].append((str(d.get("pathname", "")), str(d.get("cmdpath", "")), str((d.get("argv") or [""])[0]), str(d.get("pwd", ""))))
                        except ValueError:
                            pass

    anc = {}
    anc_eb = {}
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
        anclas = anclas_de(m["ata"], a.repo)
        anc[t] = audit_anclas_propio(chr(10).join(lin), anclas)
        # EBPF: anclas recomputadas desde el crudo (codigo propio)
        ebp = {}
        for sid, campo, pat in anclas:
            n = 0
            for pn, cp, a0, pwd in execs[t]:
                if campo == "audit_cwd":
                    b = pat.rstrip("*").rstrip("/")
                    n += 1 if (pwd == b or pwd.startswith(b + "/")) else 0
                elif "/" in pat:
                    n += 1 if pat in (pn, cp) else 0
                else:
                    n += 1 if pat in (os.path.basename(pn), os.path.basename(cp), os.path.basename(a0)) else 0
            ebp[sid] = n
        anc_eb[t] = ebp
        for sid in anc[t]:
            esp = csvan.get((t, sid))
            if esp is None:
                fallos.append("%s: senal %s no esta en el analisis" % (t, sid))
            elif esp != (anc[t][sid], ebp[sid]):
                fallos.append("%s %s: recomputado (AU,EBPF)=%s != analisis %s" % (t, sid, (anc[t][sid], ebp[sid]), esp))
        # coherencia con el registro de la ventana (regla antigua de solo nombre): solo las senales sin ruta completa deben coincidir
        for sid, campo, pat in anclas:
            if "/" not in pat or campo == "audit_cwd":
                if m["audit"]["anclas_audit_estricto"].get(sid) != anc[t][sid]:
                    fallos.append("%s %s: auditd recomputado %s != meta %s" % (t, sid, anc[t][sid], m["audit"]["anclas_audit_estricto"].get(sid)))
    filas.append("- recorte EBPF recomputado desde crudo == guardado, y anclas de auditd y de EBPF recomputadas desde el crudo == analisis (regla corregida), y == meta donde la regla antigua coincide, en las 110 ventanas (los fallos, si los hay, se listan abajo)")

    # 5. determinismo (se lista; no es fallo)
    difieren = []
    for c in casos:
        e1, e2 = anc_eb[c + "_iter1"], anc_eb[c + "_iter2"]
        if anc[c + "_iter1"] != anc[c + "_iter2"] or e1 != e2:
            difieren.append("%s: auditd %s vs %s | EBPF %s vs %s" % (c, anc[c + "_iter1"], anc[c + "_iter2"], e1, e2))
    filas.append("- determinismo iter1 vs iter2 (anclas auditd y EBPF): %d de %d casos IGUALES; difieren %d" % (len(casos) - len(difieren), len(casos), len(difieren)))
    for d in difieren:
        filas.append("  - " + d)

    txt = "# Verificacion independiente de V1 (55 casos x 2, cfgS)\n\n" + "\n".join(filas) + "\n\n"
    txt += ("**RESULTADO: OK, sin fallos.**\n" if not fallos else "**RESULTADO: %d FALLOS**\n\n" % len(fallos) + "\n".join("- " + f for f in fallos) + "\n")
    open(a.informe, "w", encoding="utf-8").write(txt)
    print(txt)
    sys.exit(1 if fallos else 0)


if __name__ == "__main__":
    main()
