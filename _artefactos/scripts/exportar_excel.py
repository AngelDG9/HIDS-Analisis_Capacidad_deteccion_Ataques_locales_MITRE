#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exportar_excel.py — export reproducible CSV -> `.xlsx` (R2 §5, CA-R2-10).

El **CSV es la fuente de verdad**; el `.xlsx` es un **export**. Se escriben **una hoja
por tabla + Requisitos + Leyenda** con **propiedades fijadas** (`created`/`modified`
constantes, autor constante) y **timestamps de zip fijados** para que **dos exports den
el mismo `sha256`** (reproducible byte a byte).

Nota: solo exporta; no toca los CSV de entrada.
"""

from __future__ import annotations

import argparse
import csv
import os
import re as _re
import sys
from datetime import datetime
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tabla_comun as TC  # noqa: E402

DEFAULT_HOJAS = "Hojas"
DEFAULT_OUT = "Estudio-Wazuh/TFG_HIDS_Wazuh_linux.xlsx"
FECHA_FIJA = datetime(2026, 1, 1, 0, 0, 0)
FECHA_ISO = "2026-01-01T00:00:00Z"
AUTOR = "TFG HIDS"

# orden de las hojas (CSV -> nombre de hoja)
ORDEN = [
    ("T1_clasificacion.csv", "T1_clasificacion"),
    ("T2_ataques.csv", "T2_ataques"),
    ("T3_legitimo.csv", "T3_legitimo"),
    ("T4_rendimiento.csv", "T4_rendimiento"),
    ("T5_pruning.csv", "T5_pruning"),
    ("T5_steps.csv", "T5_steps"),
    ("requisitos_estudio.csv", "Requisitos"),
    ("leyenda.csv", "Leyenda"),
]


def _leer_csv(path):
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not TC.es_comentario(ln)]
    rdr = csv.reader(lines)
    return [row for row in rdr]


def _celda(valor, col):
    if valor == "":
        return ""
    if str(col).strip().startswith("%"):
        return f"{valor} %"
    return valor


def exportar(hojas_dir, out_path):
    from openpyxl import Workbook

    wb = Workbook()
    wb.remove(wb.active)
    for csv_name, sheet_name in ORDEN:
        rows = _leer_csv(os.path.join(hojas_dir, csv_name))
        if rows is None:
            continue
        ws = wb.create_sheet(title=sheet_name[:31])
        for r in rows:
            out_row = [_celda(v, rows[0][i] if rows[0] and i < len(rows[0]) else "") for i, v in enumerate(r)]
            ws.append(out_row)

    wb.properties.created = FECHA_FIJA
    wb.properties.modified = FECHA_FIJA
    wb.properties.creator = AUTOR
    wb.properties.lastModifiedBy = AUTOR
    wb.properties.title = "TFG HIDS - tablas normalizadas (R2)"

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    tmp = out_path + ".tmp"
    wb.save(tmp)
    _fijar_zip(tmp, out_path)
    os.remove(tmp)


def _fijar_zip(src, dst):
    """Reescribe el zip con timestamps fijos y normaliza `docProps/core.xml`.

    openpyxl reescribe `dcterms:modified` con la hora actual en `Workbook.save`; aquí se
    **normaliza** a la constante `2026-01-01T00:00:00Z` para que el export sea reproducible
    (minga determinista byte a byte). Los timestamps de las entradas del zip también se fijan.
    """
    zi_fecha = (1980, 1, 1, 0, 0, 0)
    with ZipFile(src, "r") as zin, ZipFile(dst, "w", ZIP_DEFLATED) as zout:
        for item in sorted(zin.infolist(), key=lambda i: i.filename):
            data = zin.read(item.filename)
            if item.filename == "docProps/core.xml":
                data = _re.sub(
                    rb"(<dcterms:modified[^>]*>)[^<]*(</dcterms:modified>)",
                    rb"\g<1>" + FECHA_ISO.encode("ascii") + rb"\g<2>",
                    data,
                )
                data = _re.sub(
                    rb"(<dcterms:created[^>]*>)[^<]*(</dcterms:created>)",
                    rb"\g<1>" + FECHA_ISO.encode("ascii") + rb"\g<2>",
                    data,
                )
            info = ZipInfo(item.filename, date_time=zi_fecha)
            info.compress_type = ZIP_DEFLATED
            info.external_attr = item.external_attr
            zout.writestr(info, data)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export CSV -> xlsx reproducible.")
    ap.add_argument("--hojas", default=DEFAULT_HOJAS)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    hojas = os.path.join(TC.ROOT, args.hojas) if not os.path.isabs(args.hojas) else args.hojas
    out_path = os.path.join(TC.ROOT, args.out) if not os.path.isabs(args.out) else args.out
    exportar(hojas, out_path)
    print(f"xlsx: {TC.rel(out_path)} sha256={TC.sha256_file(out_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
