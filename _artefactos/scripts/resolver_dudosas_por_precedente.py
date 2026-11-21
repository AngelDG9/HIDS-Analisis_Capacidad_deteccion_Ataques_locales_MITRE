#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""resolver_dudosas_por_precedente.py - resuelve filas `dudosa` de la campana v2 SOLO por precedente de la v1.

NO es revision humana. Para cada fila `dudosa` de un `-Revision.csv` v2 busca, en los `-Audited.csv` de la v1 con
`revision=resuelta`, la clave (rule_id, prefijo de motivo, atribucion). Si en la v1 esa clave tiene UN SOLO veredicto
(unanime) y al menos `--min-apoyo` filas, copia ese veredicto; si no, la fila queda `dudosa` (se declara, no se inventa).

Salida (en --out): `<tag>-Revision.csv` con `veredicto`, `nota`, `revisor`, `fecha` rellenados donde hay precedente, y
`resumen_precedente.csv` (por clave: apoyo v1, veredicto, filas v2 resueltas/no). Los originales no se tocan.
Despues se pliegan con `filtrar_ruido*.py --revision` (el guardarrail del filtro rechaza `ruido` sobre filas del ataque).

Uso: python resolver_dudosas_por_precedente.py --v1 <dir Auditado v1> --v2 <dir Auditado v2> --out <dir salida> [--min-apoyo 10]
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import collections
import csv
import datetime as dt
import glob
import os
import re

REVISOR = "regla:precedente_v1_unanime(NO humano)"


def leer(p):
    com = []
    filas = []
    for x in csv.reader(open(p, encoding="utf-8", newline="")):
        if x and x[0].startswith("#"):
            com.append(x)
        elif x:
            filas.append(x)
    return com, filas[0], filas[1:]


def clave(h, r):
    m = re.sub(r"[:=].*", "", r[h.index("motivo")])
    return (r[h.index("rule_id")], m, r[h.index("atribucion")])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v1", required=True)
    ap.add_argument("--v2", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-apoyo", type=int, default=10)
    ap.add_argument("--detalle-dir", default="", help="carpeta CSV/ con <tag>-Detalle.csv: sirve para saber si la fila pertenece a la carpeta del ataque")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    v1 = collections.defaultdict(collections.Counter)
    for p in glob.glob(os.path.join(a.v1, "*-Audited.csv")):
        _, h, rs = leer(p)
        for r in rs:
            if r[h.index("revision")] == "resuelta" and r[h.index("veredicto_humano")]:
                v1[clave(h, r)][r[h.index("veredicto_humano")]] += 1
    hoy = dt.date.today().isoformat()
    resumen = collections.defaultdict(lambda: [0, 0])
    total = res = 0
    for p in sorted(glob.glob(os.path.join(a.v2, "*-Revision.csv"))):
        com, h, rs = leer(p)
        iv, inota, irev, ifec = (h.index(c) for c in ("veredicto", "nota", "revisor", "fecha"))
        out = []
        pertenece = {}
        tag = os.path.basename(p).replace("-Revision.csv", "")
        dp = os.path.join(a.detalle_dir, tag + "-Detalle.csv") if a.detalle_dir else ""
        if dp and os.path.isfile(dp):
            _, hd, rd = leer(dp)
            cols = [hd.index(c) for c in ("audit_cwd", "audit_file", "audit_dir", "syscheck_path") if c in hd]
            it_, ir_ = hd.index("timestamp_utc"), hd.index("rule_id")
            for x in rd:
                pertenece[(x[it_], x[ir_])] = " ".join(x[i] for i in cols if i < len(x))
        for r in rs:
            r = r + [""] * (len(h) - len(r))
            k = clave(h, r)
            c = v1.get(k)
            total += 1
            ver = next(iter(c)) if c and len(c) == 1 else ""
            # guardarrail: una fila que pertenece a la carpeta del ataque (la prueba esta en `evidencia`) NO se declara `ruido`
            texto = (r[h.index("evidencia")] if "evidencia" in h else "") + " " + pertenece.get((r[h.index("timestamp_utc")], r[h.index("rule_id")]), "")
            del_ataque = bool(re.search(r"lab-attack[/\\]ATA\d+", texto, re.I))
            if c and len(c) == 1 and sum(c.values()) >= a.min_apoyo and not r[iv] and not (ver == "ruido" and del_ataque):
                r[iv] = ver
                r[inota] = "precedente v1 unanime n=%d clave=%s/%s/%s" % (sum(c.values()), k[0], k[1], k[2][:30])
                r[irev] = REVISOR
                r[ifec] = hoy
                resumen[k][0] += 1
                res += 1
            else:
                resumen[k][1] += 1
            out.append(r)
        with open(os.path.join(a.out, os.path.basename(p)), "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerows(com)
            w.writerow(h)
            w.writerows(out)
    with open(os.path.join(a.out, "resumen_precedente.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rule_id", "motivo", "atribucion", "apoyo_v1", "veredicto_v1", "v2_resueltas", "v2_sin_resolver"])
        for k, (ok, no) in sorted(resumen.items(), key=lambda kv: -(kv[1][0] + kv[1][1])):
            c = v1.get(k, {})
            w.writerow([k[0], k[1], k[2], sum(c.values()) if c else 0, "|".join("%s:%d" % kv for kv in c.items()) if c else "", ok, no])
    print("dudosas=%d resueltas_por_precedente=%d sin_resolver=%d" % (total, res, total - res))


if __name__ == "__main__":
    main()
