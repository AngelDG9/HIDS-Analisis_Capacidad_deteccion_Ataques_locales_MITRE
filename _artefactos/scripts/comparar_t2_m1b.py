#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comparar_t2_m1b.py — comparación T2 M1b vs T2 M1a (histórico).

Compara **todas las columnas de datos** de `Hojas/T2_ataques.csv` (M1b) con la copia
histórica `Hojas/historico/T2_ataques_M1a.csv`. Una fila por
`(ata_id, config, umbral)` en `Hojas/T2_M1b_vs_M1a.csv`.

Esperado (plan §6.3): **550/550 idénticas**, `cambiada=NO` en todas.
Determinismo: sin reloj, orden `(n, config, umbral)`.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tabla_comun as TC  # noqa: E402

DEFAULT_M1A = "Hojas/historico/T2_ataques_M1a.csv"
DEFAULT_M1B = "Hojas/T2_ataques.csv"
DEFAULT_OUT = "Hojas/T2_M1b_vs_M1a.csv"

CLAVE = ("ata_id", "config", "umbral")
SALIDA = [
    "ata_id",
    "config",
    "umbral",
    "Detection_M1a",
    "Detection_M1b",
    "#Alertas_M1a",
    "#Alertas_M1b",
    "primera_M1a",
    "primera_M1b",
    "delta",
    "cambiada",
    "columnas_distintas",
]


def _clave(r: dict) -> tuple:
    return (r.get("ata_id", ""), r.get("config", ""), str(r.get("umbral", "")))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T2 M1b vs M1a — comparación determinista.")
    ap.add_argument("--m1a", default=DEFAULT_M1A)
    ap.add_argument("--m1b", default=DEFAULT_M1B)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    _, a_rows = TC.read_csv_rows(os.path.join(TC.ROOT, args.m1a))
    _, b_rows = TC.read_csv_rows(os.path.join(TC.ROOT, args.m1b))
    a = {_clave(r): r for r in a_rows}
    b = {_clave(r): r for r in b_rows}

    claves = sorted(set(a) | set(b), key=lambda k: (k[0], k[1], int(k[2]) if k[2].isdigit() else 0))
    columnas = sorted(set().union(*(set(r) for r in a_rows + b_rows)))
    columnas = [c for c in columnas if c not in CLAVE]

    filas = []
    cambiadas = 0
    for k in claves:
        ra, rb = a.get(k), b.get(k)
        if ra is None or rb is None:
            cambiadas += 1
            filas.append(
                {
                    "ata_id": k[0],
                    "config": k[1],
                    "umbral": k[2],
                    "Detection_M1a": (ra or {}).get("Detection", ""),
                    "Detection_M1b": (rb or {}).get("Detection", ""),
                    "#Alertas_M1a": (ra or {}).get("#Alertas", ""),
                    "#Alertas_M1b": (rb or {}).get("#Alertas", ""),
                    "primera_M1a": (ra or {}).get("primera_evidencia_rule_id", ""),
                    "primera_M1b": (rb or {}).get("primera_evidencia_rule_id", ""),
                    "delta": "",
                    "cambiada": "SÍ",
                    "columnas_distintas": "fila_ausente",
                }
            )
            continue
        difs = [c for c in columnas if (ra.get(c, "") or "") != (rb.get(c, "") or "")]
        delta = ""
        try:
            delta = str(int(float(rb.get("#Alertas", 0))) - int(float(ra.get("#Alertas", 0))))
        except (TypeError, ValueError):
            delta = ""
        if difs:
            cambiadas += 1
        filas.append(
            {
                "ata_id": k[0],
                "config": k[1],
                "umbral": k[2],
                "Detection_M1a": ra.get("Detection", ""),
                "Detection_M1b": rb.get("Detection", ""),
                "#Alertas_M1a": ra.get("#Alertas", ""),
                "#Alertas_M1b": rb.get("#Alertas", ""),
                "primera_M1a": ra.get("primera_evidencia_rule_id", ""),
                "primera_M1b": rb.get("primera_evidencia_rule_id", ""),
                "delta": delta,
                "cambiada": "SÍ" if difs else "NO",
                "columnas_distintas": ",".join(difs),
            }
        )

    # Resumen por (config, umbral) sobre M1b.
    resumen = {}
    for r in b_rows:
        key = (r.get("config", ""), str(r.get("umbral", "")))
        rr = resumen.setdefault(key, {"tp": 0, "fn": 0})
        if r.get("Detection") == "SÍ":
            rr["tp"] += 1
        else:
            rr["fn"] += 1

    partes = [
        os.path.basename(args.out),
        "TFG HIDS - T2 M1b vs M1a (comparacion de todas las columnas de datos)",
        "metrica_version=1",
        "boveda_version=2",
        f"m1a={args.m1a}",
        f"m1b={args.m1b}",
        f"filas={len(filas)}",
        f"cambiadas={cambiadas}",
        "criterio=clave(ata_id,config,umbral); se comparan TODAS las columnas restantes",
        "layout=largo(1 fila por ata_id x config x umbral)",
    ]
    for (cfg, u), rr in sorted(resumen.items(), key=lambda kv: (kv[0][0], int(kv[0][1]))):
        partes.append(f"{cfg}_N{u}: TP={rr['tp']}/FN={rr['fn']}")
    partes.append("columnas=" + ",".join(SALIDA))
    comment = "# " + " | ".join(partes)

    TC.write_csv(os.path.join(TC.ROOT, args.out), SALIDA, filas, comment=comment)
    print(f"T2 M1b vs M1a: {len(filas)} filas, {cambiadas} cambiadas -> {args.out}")
    return 1 if cambiadas else 0


if __name__ == "__main__":
    raise SystemExit(main())
