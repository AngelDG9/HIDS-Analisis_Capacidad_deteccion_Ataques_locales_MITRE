#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comparar_linux_windows_v2.py - tabla comparativa Linux <-> Windows (Wazuh) con datos v2, sin comparar `M` en bruto.

Une, por configuracion (C0/C1) y umbral N: TPR (T4), FPR (T4), y del plano legitimo (T3) #FP, FP/hora y FP/accion.
Las unidades NO son comparables en bruto (Linux M=342 966 con auditd; Windows M=21 589): por eso van FP/hora y FP/accion.
Entradas: Hojas/T4_rendimiento_v2.csv, T4_rendimiento_windows_v2.csv, T3_legitimo.csv, T3_legitimo_windows.csv.
Salida : Hojas/comparacion_linux_windows_v2.csv (cabecera con sha256 de las entradas). Determinista, sin reloj.
"""
import csv
import hashlib
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
H = os.path.join(REPO, "Hojas")
UMBRALES = (0, 3, 7, 10, 12)


def leer(p):
    rows = [r for r in csv.reader(open(os.path.join(H, p), encoding="utf-8", newline="")) if r and not r[0].startswith("#")]
    return rows[0], rows[1:]


def sha(p):
    return hashlib.sha256(open(os.path.join(H, p), "rb").read()).hexdigest()


def t4(p):
    h, r = leer(p)
    return {x[h.index("metrica")]: {c: x[h.index(c)] for c in h} for x in r}


def t3(p):
    h, r = leer(p)
    out = {}
    for x in r:
        if x[h.index("seccion")] == "agregado":
            out[(x[h.index("config")], int(x[h.index("umbral")]))] = {c: x[h.index(c)] for c in h}
    return out


def main():
    ent = {"linux": ("T4_rendimiento_v2.csv", "T3_legitimo.csv"), "windows": ("T4_rendimiento_windows_v2.csv", "T3_legitimo_windows.csv")}
    cols = ["plataforma", "config", "umbral", "TPR", "FPR", "TNR", "Precision", "FP_unidades", "FP_por_hora", "FP_por_accion", "M_unidades"]
    filas = []
    for so, (f4, f3) in ent.items():
        d4, d3 = t4(f4), t3(f3)
        for cfg in ("C0", "C1"):
            for u in UMBRALES:
                k = "wazuh_%s_N%d" % (cfg, u)
                a = d3.get((cfg, u), {})
                filas.append([so, cfg, u, d4["TPR"].get(k, ""), d4["FPR"].get(k, ""), d4["TNR"].get(k, ""),
                              (d4.get("Precisión") or d4.get("Precision") or {}).get(k, ""),
                              a.get("#Unidades_FP", ""), a.get("FP_por_hora", ""), a.get("FP_por_accion", ""), a.get("#Unidades", "")])
    cab = ("# comparacion_linux_windows_v2.csv | TFG HIDS - comparacion Wazuh Linux<->Windows (datos de ataque v2) | "
           "NO comparar M en bruto: Linux incluye cada execve de auditd | C0={RS1}, C1={RS1,RS2}=virgen (en Windows C0=C1) | "
           + " | ".join("sha256_%s=%s" % (f.split(".")[0], sha(f)) for pair in ent.values() for f in pair))
    with open(os.path.join(H, "comparacion_linux_windows_v2.csv"), "w", encoding="utf-8", newline="") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(cols)
        w.writerows(filas)
    print("filas=%d" % len(filas))


if __name__ == "__main__":
    main()
