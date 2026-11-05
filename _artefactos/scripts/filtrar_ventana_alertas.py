#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ventana_alertas.py - Filtra un `alertas_detalle.csv` al endpoint medido
y a la ventana UTC, y recalcula el catálogo de `rule_id`.

Contexto
--------
`extraer_alertas.py --detail` vuelca **todas** las alertas de los ficheros de
entrada, sin distinguir el agente que las generó. En una ventana del estudio
legítimo eso mete en el mismo CSV:

  * alertas del **endpoint medido** (`victima-linux`, agente `001`), y
  * alertas del **manager** (`wazuh-server`, agente `000`): sesiones PAM/SSH
    del operador que entra al manager a cosechar, `sudo`, etc.

Solo las primeras pertenecen a la medida. Este script deja el detalle con:

  * `agent_name == --agente`, y
  * `timestamp_utc` dentro de `[--desde, --hasta]` (ambos inclusive, **UTC**).

Conserva la cabecera comentada del original y añade una línea `#` con el
recuento del filtro. El CSV de salida mantiene columnas y orden de filas.

Además escribe el catálogo agregado por `rule_id` con **el mismo esquema y
semántica que `extraer_alertas.aggregate`** (nivel/descripción/grupos de la
primera aparición, recuento, primer/último instante a segundos, `rs_origen`).

Uso
---
    python _artefactos/scripts/filtrar_ventana_alertas.py \\
        --in  Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/alertas_detalle_sin_filtrar.csv \\
        --out Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/alertas_detalle.csv \\
        --ruleids-out Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/ruleids_legitimos.csv \\
        --agente victima-linux \\
        --desde 2026-11-02T00:00:00Z --hasta 2026-11-05T00:00:00Z

Los timestamps se comparan **en UTC**; no se convierte a hora local en ningún
punto.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone

CSV_HEADER = [
    "rule_id",
    "rule_level",
    "rule_description",
    "groups",
    "count",
    "first_seen",
    "last_seen",
    "rs_origen",
]

COLS_TS = ("timestamp_utc", "timestamp", "ts")
COLS_AG = ("agent_name", "agente")
COLS_RID = ("rule_id", "ruleid", "id")
COLS_LEVEL = ("rule_level", "level")
COLS_DESC = ("rule_description", "description")
COLS_GROUPS = ("rule_groups", "groups")
COLS_RS = ("rs_origen", "rs")

TAG_FILTRO = "# filtrado_ventana_alertas.py"


# --------------------------------------------------------------------------
# Tiempo (UTC, sin conversiones locales)
# --------------------------------------------------------------------------
def parse_ts(value: str) -> datetime:
    """Parsea ISO8601 (`Z`, `+0000`, `+00:00`). Sin zona => UTC."""
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:
        s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Lectura del detalle
# --------------------------------------------------------------------------
def _localizar(header, candidatos, que):
    norm = [h.strip().lower() for h in header]
    for c in candidatos:
        if c in norm:
            return norm.index(c)
    raise SystemExit(f"ERROR: no encuentro la columna de {que} en {header}")


def leer_detalle(path):
    """Devuelve (comentarios, header, filas)."""
    comentarios = []
    header = None
    filas = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for linea in fh:
            if linea.startswith("#"):
                comentarios.append(linea.rstrip("\r\n"))
                continue
            if not linea.strip():
                continue
            if header is None:
                header = next(csv.reader([linea]))
                continue
            filas.append(next(csv.reader([linea])))
    if header is None:
        raise SystemExit(f"ERROR: {path} no tiene cabecera")
    return comentarios, header, filas


def filtrar(filas, header, agente, desde, hasta):
    i_ts = _localizar(header, COLS_TS, "timestamp")
    i_ag = _localizar(header, COLS_AG, "agente")
    dentro, fuera_ag, fuera_ventana = [], 0, 0
    for fila in filas:
        if len(fila) <= max(i_ts, i_ag):
            fuera_ventana += 1
            continue
        if fila[i_ag].strip() != agente:
            fuera_ag += 1
            continue
        try:
            ts = parse_ts(fila[i_ts])
        except ValueError:
            fuera_ventana += 1
            continue
        if desde <= ts <= hasta:
            dentro.append(fila)
        else:
            fuera_ventana += 1
    return dentro, fuera_ag, fuera_ventana, i_ts, i_ag


# --------------------------------------------------------------------------
# Catálogo por rule_id (misma semántica que extraer_alertas.aggregate)
# --------------------------------------------------------------------------
def agregar(dentro, header):
    i_rid = _localizar(header, COLS_RID, "rule_id")
    i_ts = _localizar(header, COLS_TS, "timestamp")
    i_lvl = _localizar(header, COLS_LEVEL, "nivel")
    i_desc = _localizar(header, COLS_DESC, "descripción")
    i_grp = _localizar(header, COLS_GROUPS, "grupos")
    i_rs = _localizar(header, COLS_RS, "rs_origen")

    agg = {}
    for fila in dentro:
        rid = fila[i_rid].strip() or "?"
        ts = parse_ts(fila[i_ts])
        e = agg.get(rid)
        if e is None:
            e = {
                "level": fila[i_lvl],
                "description": fila[i_desc],
                "groups": fila[i_grp],
                "count": 0,
                "first": ts,
                "last": ts,
                "rs": fila[i_rs],
            }
            agg[rid] = e
        e["count"] += 1
        if ts < e["first"]:
            e["first"] = ts
        if ts > e["last"]:
            e["last"] = ts

    filas = [
        [
            rid,
            e["level"],
            e["description"],
            e["groups"],
            e["count"],
            fmt_ts(e["first"]),
            fmt_ts(e["last"]),
            e["rs"],
        ]
        for rid, e in agg.items()
    ]
    filas.sort(key=lambda r: (int(r[0]) if r[0].isdigit() else 10**12, r[0]))
    return filas


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def escribir_detalle(path, comentarios, header, filas, nota):
    comentarios = [c for c in comentarios if not c.startswith(TAG_FILTRO)]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        for c in comentarios:
            fh.write(c + "\n")
        fh.write(nota + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(filas)


def escribir_ruleids(path, filas):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CSV_HEADER)
        w.writerows(filas)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Filtra alertas_detalle.csv por agente y ventana UTC; recalcula ruleids."
    )
    ap.add_argument("--in", dest="entrada", required=True, help="detalle de entrada")
    ap.add_argument("--out", dest="salida", required=True, help="detalle filtrado")
    ap.add_argument("--ruleids-out", default=None, help="catálogo por rule_id")
    ap.add_argument("--agente", default="victima-linux", help="agente medido")
    ap.add_argument("--desde", required=True, help="inicio de ventana (UTC ISO8601)")
    ap.add_argument("--hasta", required=True, help="fin de ventana (UTC ISO8601)")
    args = ap.parse_args(argv)

    desde = parse_ts(args.desde)
    hasta = parse_ts(args.hasta)
    if hasta < desde:
        ap.error("--hasta es anterior a --desde")

    comentarios, header, filas = leer_detalle(args.entrada)
    dentro, fuera_ag, fuera_ventana, _i_ts, _i_ag = filtrar(
        filas, header, args.agente, desde, hasta
    )

    nota = (
        f"{TAG_FILTRO} | agente={args.agente} | "
        f"ventana={fmt_ts(desde)}..{fmt_ts(hasta)} (UTC, ambos inclusive) | "
        f"entrada={len(filas)} salida={len(dentro)} "
        f"descartadas_agente={fuera_ag} descartadas_ventana={fuera_ventana} | "
        f"fuente={os.path.basename(args.entrada)}"
    )
    escribir_detalle(args.salida, comentarios, header, dentro, nota)
    print(
        f"detalle: entrada={len(filas)} salida={len(dentro)} "
        f"descartadas_agente={fuera_ag} descartadas_ventana={fuera_ventana} -> {args.salida}"
    )

    if args.ruleids_out:
        tabla = agregar(dentro, header)
        escribir_ruleids(args.ruleids_out, tabla)
        n_unknown = sum(1 for r in tabla if r[7] == "UNKNOWN")
        print(f"ruleids: filas={len(tabla)} unknown={n_unknown} -> {args.ruleids_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
