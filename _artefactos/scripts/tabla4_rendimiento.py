#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla4_rendimiento.py — T4 (métricas de rendimiento) del TFG HIDS.

Agrega `Hojas/T2_ataques.csv` + `Hojas/T3_legitimo.csv` y aplica las **7 fórmulas**
de `metrica_hids.py` (R2 §2.5). **No** recalcula la clasificación: T2/T3 ya la traen.

Matriz de confusión:
    plano ataque  : TP = #Casos_TP;  FN = N - TP;  TPR = TP/N
    plano legítimo: FP = #Unidades_FP; TN = M - FP; FPR = FP/M; TNR = 1-FPR
    plano alerta  : A_TP = #Alertas_TP; A_FP = #Alertas_FP; P = A_TP/(A_TP+A_FP)

**Hoy `M` no existe** (L11): `FPR`, `TNR`, `GM` y la `Precisión`/`F1`/`Usabilidad`
que dependen de legítimo quedan **vacíos** (nada de humo). Salida: `Hojas/T4_rendimiento.csv`
(formato ancho: columnas = HIDS × config × umbral + bloque de fórmulas literales).
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

DEFAULT_T2 = "Hojas/T2_ataques.csv"
DEFAULT_T3 = "Hojas/T3_legitimo.csv"
DEFAULT_OUT = "Hojas/T4_rendimiento.csv"

# Fila -> (etiqueta, P-Excel, fórmula literal)
FILAS = [
    ("#Casos", "#Attack flows", "N = 55"),
    ("#Unidades_legitimas (M)", "#Clear flows", "denominador §2.2"),
    ("#Total", "#Total Flows", "#Casos + M"),
    ("#Casos_TP", "#pcaps TP", "§2.3"),
    ("#Casos_FN", "#pcaps FN", "N - #Casos_TP"),
    ("#Alertas_TP", "#Alerts TP", "A_TP"),
    ("#Alertas_correlacionadas_TP", "#Flow-correlated Alerts TP", "A_TP^c"),
    ("#Unidades_FP", "#Flows FP", "FP_uni"),
    ("#Unidades_TN", "#Flows TN", "M - FP_uni"),
    ("#Alertas_FP", "#Alerts FP", "A_FP"),
    ("#Alertas_correlacionadas_FP", "#Flow-correlated Alerts FP", "A_FP^c"),
    ("TPR", "TPR", "TPR = #Casos_TP / #Casos  (Excel B14 = B6/'T2'!$D$79)"),
    ("FPR", "FPR", "FPR = #Unidades_FP / M  (Excel B15 = B10/$B$4)"),
    ("TNR", "(añadido)", "TNR = 1 - FPR  (Excel %Flows_TN = 1 - %Flows_FP)"),
    ("Precisión", "(bloque fórmulas)", "P = A_TP / (A_TP + A_FP)  (Excel P = TP/(TP+FP))"),
    ("F1", "(bloque fórmulas)", "F1 = 2*P*R / (P + R), R = TPR  (Excel F1 = 2PR/(P+R))"),
    ("GM", "GM", "GM = sqrt(TPR * (1 - FPR))  (Excel B16 = SQRT(B14*(1-B15)))"),
    ("Usabilidad", "Operational Usability", "Usab = A_FP / A_TP  (Excel B17 = B12/B8)"),
    (
        "Usabilidad (correlacionadas)",
        "Operational Usability (correlated alerts)",
        "Usab^c = A_FP^c / A_TP^c  (Excel B18 = B13/B9)",
    ),
]


def _num(x, default=None):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return default


def _leer_t2(path):
    _, rows = TC.read_csv_rows(path, required=["ata_id", "config", "umbral", "Detection", "#Alertas",
                                               "#Alertas_correlacionadas"])
    return rows


def _leer_t3(path):
    if not os.path.isfile(path):
        return []
    _, rows = TC.read_csv_rows(path)
    return [r for r in rows if r.get("seccion") == "agregado"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T4 (rendimiento) — agrega T2+T3 y aplica fórmulas.")
    ap.add_argument("--t2", default=DEFAULT_T2)
    ap.add_argument("--t3", default=DEFAULT_T3)
    ap.add_argument("--hids", default="wazuh")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    t2 = _leer_t2(os.path.join(TC.ROOT, args.t2))
    t3 = _leer_t3(os.path.join(TC.ROOT, args.t3))

    # columnas = (config, umbral) presentes en T2, ordenadas
    claves = sorted({(r["config"], int(r["umbral"])) for r in t2}, key=lambda c: (c[0], c[1]))
    colnames = [f"{args.hids}_{cfg}_N{u}" for (cfg, u) in claves]

    # T3 map (config,umbral) -> bloque
    t3map = {}
    for r in t3:
        t3map[(r.get("config"), int(_num(r.get("umbral"), -1)))] = r

    cols = {}
    for (cfg, u) in claves:
        sel = [r for r in t2 if r["config"] == cfg and int(r["umbral"]) == u]
        casos = len(sel)
        casos_tp = sum(1 for r in sel if r.get("Detection") == "SÍ")
        casos_fn = casos - casos_tp
        alertas_tp = sum(int(_num(r.get("#Alertas"), 0)) for r in sel)
        alertas_corr_tp = sum(int(_num(r.get("#Alertas_correlacionadas"), 0)) for r in sel)

        leg = t3map.get((cfg, u))
        m = _num(leg.get("#Unidades")) if leg else None
        unidades_fp = _num(leg.get("#Unidades_FP")) if leg else None
        if leg and m is None:
            unidades_fp = None
        unidades_tn = (m - unidades_fp) if (m and unidades_fp is not None) else None
        alertas_fp = _num(leg.get("#Alertas_FP")) if leg else None
        alertas_corr_fp = _num(leg.get("#Alertas_correlacionadas")) if leg else None

        tpr_v = M.tpr(casos_tp, casos)
        fpr_v = M.fpr(unidades_fp, m) if (unidades_fp is not None) else None
        tnr_v = M.tnr(fpr_v)
        prec_v = M.precision(alertas_tp, alertas_fp) if alertas_fp is not None else None
        f1_v = M.f1(prec_v, tpr_v) if prec_v is not None else None
        gm_v = M.gm(tpr_v, tnr_v)
        usab_v = M.usabilidad(alertas_fp, alertas_tp) if alertas_fp is not None else None
        usabc_v = M.usabilidad(alertas_corr_fp, alertas_corr_tp) if alertas_corr_fp is not None else None

        cols[f"{args.hids}_{cfg}_N{u}"] = {
            "#Casos": casos,
            "#Unidades_legitimas (M)": "" if not m else int(m),
            "#Total": (casos + int(m)) if m else "",
            "#Casos_TP": casos_tp,
            "#Casos_FN": casos_fn,
            "#Alertas_TP": alertas_tp,
            "#Alertas_correlacionadas_TP": alertas_corr_tp,
            "#Unidades_FP": "" if unidades_fp is None else int(unidades_fp),
            "#Unidades_TN": "" if unidades_tn is None else int(unidades_tn),
            "#Alertas_FP": "" if alertas_fp is None else int(alertas_fp),
            "#Alertas_correlacionadas_FP": "" if alertas_corr_fp is None else int(alertas_corr_fp),
            "TPR": M.fmt_ratio(tpr_v),
            "FPR": M.fmt_ratio(fpr_v),
            "TNR": M.fmt_ratio(tnr_v),
            "Precisión": M.fmt_ratio(prec_v),
            "F1": M.fmt_ratio(f1_v),
            "GM": M.fmt_ratio(gm_v),
            "Usabilidad": M.fmt_usab(usab_v),
            "Usabilidad (correlacionadas)": M.fmt_usab(usabc_v),
        }

    header = ["metrica", "excel_profesor", "formula_literal"] + colnames
    filas = []
    for (etiqueta, excel, formula) in FILAS:
        fila = {"metrica": etiqueta, "excel_profesor": excel, "formula_literal": formula}
        for cn in colnames:
            fila[cn] = cols[cn].get(etiqueta, "")
        filas.append(fila)

    hay_m = any(v["#Unidades_legitimas (M)"] != "" for v in cols.values())
    partes = [
        os.path.basename(args.out),
        "TFG HIDS - R2 T4 (metricas de rendimiento)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"hids={args.hids}",
        f"M={'n/a (fallback L11: FPR/TNR/GM/Precision/F1/Usabilidad no publicables)' if not hay_m else 'instrumentado'}",
        f"columnas={','.join(colnames)}",
        "formulas_literales=metrica_hids.py (§2.5)",
        "layout=ancho(1 columna por HIDS x config x umbral; las filas de metrica pueden empezar por '#')",
        "columnas_csv=" + ",".join(header),
    ]
    comment = "# " + " | ".join(partes)

    TC.write_csv(os.path.join(TC.ROOT, args.out), header, filas, comment=comment)
    print(f"T4: {len(filas)} filas x {len(colnames)} cols -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
