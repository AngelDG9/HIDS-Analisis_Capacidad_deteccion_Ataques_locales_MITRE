#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla1_clasificacion.py — T1 (clasificación, matriz MITRE espejo red↔host) del TFG HIDS.

Adapta la hoja `Techniques`/`Subtechniques` del Excel del profesor (v17) y las une con
`Hojas/corpus_host.csv` (v19.1), `Hojas/cobertura_p1_linux.csv` e
`Hojas/inventario_p1_windows.csv` (R2 §4.1). Hace **visibles** las **3 discrepancias**
declaradas (`T1029`, `T1602.001/.002`, `T1567.003`).

Salida: `Hojas/T1_clasificacion.csv`. Determinismo: orden por `id_tecnica`; sin reloj.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

DEFAULT_TABLA1 = "_recursos/reuniones/03/Tabla 1 - Matriz MITRE Enterprise v17.xlsx"
DEFAULT_CORPUS = "Hojas/corpus_host.csv"
DEFAULT_COBERTURA = "Hojas/cobertura_p1_linux.csv"
DEFAULT_INVENTARIO = "Hojas/inventario_p1_windows.csv"
DEFAULT_OUT = "Hojas/T1_clasificacion.csv"

HEADER = [
    "tactica",
    "otras_tacticas",
    "id_tactica",
    "tecnica",
    "id_tecnica",
    "subtecnica",
    "id_subtecnica",
    "plataformas",
    "p1_res",
    "only_network_detection_v17",
    "network_detection_v17",
    "host_eligible_v191",
    "dc_host",
    "dc_red",
    "cubierta_en_corpus",
    "estado_cobertura",
    "nota_desfase",
]

NOTA_DESFASE = {
    "T1029": "v17 solo-red; v19.1 host_eligible y medida (ATA021)",
    "T1602": "v17 solo-red; v19.1 host_eligible (padre sin discrepancia en v19.1)",
    "T1602.001": "v17 solo-red; v19.1 host_eligible; no factible (Network Devices)",
    "T1602.002": "v17 solo-red; v19.1 host_eligible; no factible (Network Devices)",
    "T1567.003": "v17 subt. solo-red; v19.1 host_eligible y medida (ATA050)",
}


def _v17_map(path):
    import openpyxl

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    tech, sub = {}, {}
    ws = wb["Techniques"]
    for r in range(2, ws.max_row + 1):
        tid = ws.cell(row=r, column=2).value
        if tid:
            tech[str(tid)] = {
                "name": ws.cell(row=r, column=3).value or "",
                "tactic_ids": ws.cell(row=r, column=4).value or "",
                "network": ws.cell(row=r, column=7).value or "",
                "only_network": ws.cell(row=r, column=8).value or "",
            }
    ws = wb["Subtechniques"]
    for r in range(2, ws.max_row + 1):
        sid = ws.cell(row=r, column=2).value
        if sid:
            sub[str(sid)] = {
                "name": ws.cell(row=r, column=3).value or "",
                "parent": ws.cell(row=r, column=4).value or "",
                "network": ws.cell(row=r, column=6).value or "",
                "only_network": ws.cell(row=r, column=7).value or "",
            }
    return tech, sub


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T1 (clasificacion) — matriz MITRE red<->host.")
    ap.add_argument("--tabla1", default=DEFAULT_TABLA1)
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    ap.add_argument("--cobertura", default=DEFAULT_COBERTURA)
    ap.add_argument("--inventario", default=DEFAULT_INVENTARIO)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    _, corpus_rows = TC.read_csv_rows(os.path.join(TC.ROOT, args.corpus))
    _, cob_rows = TC.read_csv_rows(os.path.join(TC.ROOT, args.cobertura))
    _, inv_rows = TC.read_csv_rows(os.path.join(TC.ROOT, args.inventario))

    corpus = {r["tecnica_id"]: r for r in corpus_rows}
    cobertura = {r["tecnica"]: r for r in cob_rows}
    inventario = {r["tecnica_id"]: r for r in inv_rows}

    tech17, sub17 = _v17_map(os.path.join(TC.ROOT, args.tabla1))

    ids = sorted(set(cobertura) | set(inventario))
    filas = []
    for tid in ids:
        c = corpus.get(tid, {})
        cob = cobertura.get(tid, {})
        inv = inventario.get(tid, {})
        v = tech17.get(tid) or sub17.get(tid) or {}
        es_sub = bool(c.get("es_subtecnica", "no").strip().lower() in ("si", "sí", "yes"))
        tacticas = [t for t in str(c.get("tacticas", cob.get("tactica", ""))).split(";") if t]
        tactica = tacticas[0] if tacticas else str(cob.get("tactica", ""))
        otras = ";".join(tacticas[1:])
        if es_sub:
            parent = str(c.get("padre_id", sub17.get(tid, {}).get("parent", "")))
            tecnica_name = str(corpus.get(parent, {}).get("nombre", tech17.get(parent, {}).get("name", "")))
            sub_name = str(c.get("nombre", ""))
            id_sub = tid
            id_tec = parent
        else:
            tecnica_name = str(c.get("nombre", ""))
            sub_name = ""
            id_sub = ""
            id_tec = tid
        id_tactica = ""
        base_tec = tech17.get(id_tec, {})
        if base_tec:
            id_tactica = str(base_tec.get("tactic_ids", "") or "")
        filas.append(
            {
                "tactica": tactica,
                "otras_tacticas": otras,
                "id_tactica": id_tactica,
                "tecnica": tecnica_name,
                "id_tecnica": id_tec,
                "subtecnica": sub_name,
                "id_subtecnica": id_sub,
                "plataformas": str(c.get("plataformas", cob.get("plataformas", inv.get("plataformas", "")))),
                "p1_res": str(c.get("priority", "")),
                "only_network_detection_v17": str(v.get("only_network", "")).upper() or "NO",
                "network_detection_v17": str(v.get("network", "")).upper() or "NO",
                "host_eligible_v191": str(c.get("host_eligible", "")),
                "dc_host": str(c.get("dc_host", "")),
                "dc_red": str(c.get("dc_red", "")),
                "cubierta_en_corpus": str(cob.get("ata_o_cubierta_por", "")),
                "estado_cobertura": str(cob.get("estado", inv.get("factibilidad", ""))),
                "nota_desfase": NOTA_DESFASE.get(tid, "—"),
            }
        )

    n_desfase = sum(1 for f in filas if f["nota_desfase"] != "—")
    partes = [
        os.path.basename(args.out),
        "TFG HIDS - R2 T1 (clasificacion; matriz MITRE red<->host)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"fuente_tabla1={TC.rel(os.path.join(TC.ROOT, args.tabla1))}",
        f"n_tecnicas={len(filas)}",
        f"n_discrepancias_declaradas={n_desfase}",
        "columnas=" + ",".join(HEADER),
    ]
    comment = "# " + " | ".join(partes)
    TC.write_csv(os.path.join(TC.ROOT, args.out), HEADER, filas, comment=comment)
    print(f"T1: {len(filas)} filas ({n_desfase} discrepancias) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
