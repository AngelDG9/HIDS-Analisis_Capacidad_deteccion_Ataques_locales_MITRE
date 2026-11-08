#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cruzar_doble_uso.py — T5 · reglas de **doble uso** (bloque `legitimo-analisis`, L2).

Cruza el **catálogo de ruido de las 72 h** con las **detecciones canónicas** de los
ataques y produce `Hojas/T5_doble_uso.csv` (11 filas, una por regla del catálogo).

Definición congelada (`plan.md` §3.4): una `rule.id` es de **doble uso** si
  1. aparece en el catálogo de ruido de las 72 h (es FP en el legítimo), **y**
  2. es `categoria=deteccion` en **≥1 caso canónico** de ataque.

Lado legítimo: del **índice evento↔alerta** (`unidad` = línea de `archives`), no del
`timestamp`. Lado ataque: de los `-Audited.csv` **canónicos** (`rev1` si el ATA está en
`Hojas/repeticiones.csv`; si no `iter1`), con `rs_origen ∈ C1` y `N=0`.

Determinismo: sin reloj, orden numérico de `rule_id`, LF, UTF-8 sin BOM.
"""

from __future__ import annotations

import argparse
import collections
import csv
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

DEFAULT_CATALOGO = "Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv"
DEFAULT_INDICE = "Dataset/Legitimo/legitimo_72h/analisis/eventos_alerta_72h.csv.gz"
DEFAULT_AUDITADO = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_REPETICIONES = "Hojas/repeticiones.csv"
DEFAULT_OUT = "Hojas/T5_doble_uso.csv"

HEADER = [
    "rule_id", "rule_level", "rs_origen", "groups", "legit_alertas", "legit_unidades",
    "legit_auto", "pct_auto", "attack_detecciones", "attack_casos", "attack_casos_lista",
    "doble_uso", "nota",
]


def _sort_rid(rid):
    s = str(rid)
    return (0, int(s)) if s.isdigit() else (1, s)


def _leer_indice(path):
    """`rule_id -> (unidades, auto)` del índice evento↔alerta (ignora `#` y cabecera)."""
    unidades = collections.Counter()
    auto = collections.Counter()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(ln for ln in fh if not ln.lstrip().startswith("# "))
        for r in rd:
            rid = str(r.get("rule_id") or "").strip()
            if not rid:
                continue
            unidades[rid] += 1
            if str(r.get("auto_ruido") or "").strip() == "1":
                auto[rid] += 1
    return unidades, auto


def _repeticiones(path):
    _, rows = TC.read_csv_rows(path, required=["ata_id"])
    return {str(r["ata_id"]).strip() for r in rows}


def _detecciones(auditado_dir, repeticiones, config_rs, umbral):
    """`rule_id -> (n_detecciones, set(casos))` sobre las 55 ventanas canónicas."""
    det = collections.Counter()
    casos = collections.defaultdict(set)
    for f in sorted(os.listdir(auditado_dir)):
        if not f.endswith("-Audited.csv"):
            continue
        ata = f.split("_")[0]
        if f != f"{ata}_{M.ventana_canonica(ata, repeticiones)}-Audited.csv":
            continue
        _, rows = TC.read_csv_rows(os.path.join(auditado_dir, f))
        for x in rows:
            if x.get("categoria") != M.CATEGORIA_DETECCION:
                continue
            if x.get("rs_origen") not in config_rs:
                continue
            try:
                lvl = int(float(x.get("rule_level") or 0))
            except (TypeError, ValueError):
                lvl = 0
            if lvl < umbral:
                continue
            rid = str(x.get("rule_id") or "").strip()
            det[rid] += 1
            casos[rid].add(ata)
    return det, casos


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T5 — cruce de reglas de doble uso (legítimo x ataque).")
    ap.add_argument("--catalogo", default=DEFAULT_CATALOGO)
    ap.add_argument("--indice", default=DEFAULT_INDICE)
    ap.add_argument("--auditado", default=DEFAULT_AUDITADO)
    ap.add_argument("--repeticiones", default=DEFAULT_REPETICIONES)
    ap.add_argument("--config", default="C1")
    ap.add_argument("--umbral", type=int, default=0)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    _, cat = TC.read_csv_rows(os.path.join(TC.ROOT, args.catalogo),
                              required=["rule_id", "rule_level", "rs_origen", "count"])
    unidades, auto = _leer_indice(os.path.join(TC.ROOT, args.indice))
    rep = _repeticiones(os.path.join(TC.ROOT, args.repeticiones))
    det, casos = _detecciones(os.path.join(TC.ROOT, args.auditado), rep,
                              set(M.CONFIGS[args.config]), args.umbral)

    # Casos cubiertos por cada regla (para detectar redundancia de evidencia)
    filas = []
    for r in sorted(cat, key=lambda x: _sort_rid(x["rule_id"])):
        rid = str(r["rule_id"]).strip()
        u = unidades.get(rid, 0)
        a = auto.get(rid, 0)
        n_det = det.get(rid, 0)
        cs = sorted(casos.get(rid, set()))
        doble = "SÍ" if (u > 0 and len(cs) > 0) else "NO"
        nota = ""
        if rid == "11":
            nota = "UNKNOWN (stats); sin unidad en archives: no entra en C1"
        elif doble == "SÍ":
            otros = [(o, casos[o]) for o in casos
                     if o != rid and set(cs) <= casos[o] and det[o] > n_det]
            if otros:
                o, _ = max(otros, key=lambda kv: det[kv[0]])
                nota = f"redundante: {o} ya cubre {';'.join(cs)}"
            else:
                nota = f"principal: cubre {len(cs)}/55 casos"
        elif u > 0:
            nota = "solo legitimo (FP-only; nunca deteccion en ataque)"
        else:
            nota = "sin unidad en archives"
        filas.append({
            "rule_id": rid,
            "rule_level": str(r.get("rule_level", "")).strip(),
            "rs_origen": str(r.get("rs_origen", "")).strip(),
            "groups": (r.get("groups") or "").strip(),
            "legit_alertas": int(float(r.get("count") or 0)),
            "legit_unidades": u,
            "legit_auto": a,
            "pct_auto": f"{100.0 * a / u:.4f}" if u else "",
            "attack_detecciones": n_det,
            "attack_casos": len(cs),
            "attack_casos_lista": ";".join(cs),
            "doble_uso": doble,
            "nota": nota,
        })

    n_doble = sum(1 for f in filas if f["doble_uso"] == "SÍ")
    comment = "# T5_doble_uso.csv | " + " | ".join([
        "TFG HIDS - T5 reglas de doble uso (catalogo de ruido 72 h x detecciones canonicas)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"config={args.config}",
        f"umbral={args.umbral}",
        f"catalogo={args.catalogo}",
        f"indice={args.indice}",
        f"auditado={args.auditado}",
        "t2=n/a (T5_doble_uso se recalcula de Auditado; no consume T2)",
        "unidad_legitimo=evento decodificado (linea de archives)",
        "ventana_canonica=rev1_si_repeticiones_else_iter1",
        f"reglas={len(filas)}",
        f"doble_uso={n_doble}",
        "declaracion=quitar una regla de doble uso redundante NO baja el TPR pero cambia la PRIMERA evidencia del caso (T5 mide rendimiento, no calidad de evidencia)",
        "layout=largo(1 fila por rule_id)",
    ])
    TC.write_csv(os.path.join(TC.ROOT, args.out), HEADER, filas, comment=comment)
    print(f"T5_doble_uso: {len(filas)} reglas, {n_doble} de doble uso -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
