#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla3_legitimo.py — T3 (plano LEGÍTIMO) del TFG HIDS (bloque `reencuadre-metrica`).

Unidad = **evento/registro decodificado** por el HIDS; denominador `M` **instrumentado**
con `<logall_json>` (Wazuh) — `archives.json` (R2 §2.2). Complementos: **acción de
GHOSTS** y **hora**.

**Hoy `M` no existe** (`L0`/`L1` pendientes): sin `--detalle`/`--unidades` el script
escribe solo la **plantilla** (cabecera + comentario) y **declara** el fallback `L11`
(`#Unidades = n/a`; FPR-por-evento **no** se publica). El número llega en `L1`.

Clasificación de la ventana: se **reutiliza** `filtrar_ruido.py --modo baseline`
(no se reimplementa el filtro, R2 §7); aquí se reciben filas ya con `categoria`.

Salida: `Hojas/T3_legitimo.csv` (meta + bloque config×umbral + detalle por `rule.id`),
formato largo con columna `seccion` ∈ {agregado, detalle_ruleid}.

Determinismo (RNF-01): sin reloj, orden estable, LF, UTF-8 sin BOM.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

DEFAULT_OUT = "Hojas/T3_legitimo.csv"

META_COLS = [
    "seccion",
    "corrida",
    "hids",
    "so",
    "tipo_trafico",
    "fuente_generadora",
    "inicio_utc",
    "fin_utc",
    "duracion_h",
    "tamano",
    "n_acciones_ghosts",
    "n_ips_o_entidades",
    "config",
    "umbral",
]
BLOQUE_COLS = [
    "#Unidades",
    "#Alertas",
    "#Alertas_correlacionadas",
    "#rule.id_distintos",
    "#Unidades_FP",
    "#Unidades_TN",
    "%Unidades_FP",
    "%Unidades_TN",
    "#Alertas_FP",
    "#Alertas_FP_sin_auto_ruido",
    "FP_por_accion",
    "FP_por_hora",
]
DETALLE_COLS = [
    "rule.id",
    "rule_level",
    "groups",
    "rs_origen",
    "#alertas_legitimas",
    "#unidades_con_la_regla",
    "#alertas_correlacionadas",
    "es_TP_en_algun_ataque",
    "veredicto",
]
HEADER = META_COLS + BLOQUE_COLS + DETALLE_COLS


def _num(x, default=None):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return default


def _contar_unidades(path: str):
    if not path:
        return None
    if not os.path.isfile(path):
        return None
    n = 0
    with open(path, "rb") as fh:
        for _ in fh:
            n += 1
    return n


def _bloque(rows, config_rs, umbral, m, meta):
    sel = [r for r in rows if r.get("rs_origen") in config_rs and (_num(r.get("rule_level"), -1.0) >= umbral)]
    n_alertas = len(sel)
    asin_auto = sum(1 for r in sel if r.get("categoria") != M.CATEGORIA_AUTO_RUIDO)
    unidades_fp = sorted({r.get("unidad", "") for r in sel if r.get("unidad", "") != ""})
    rids = sorted({r.get("rule_id", "") for r in sel})
    # correlacionadas = Σ por unidad (rule.id distintos)
    por_unidad = {}
    for r in sel:
        u = r.get("unidad", "")
        por_unidad.setdefault(u, set()).add(r.get("rule_id", ""))
    corr = sum(len(v) for v in por_unidad.values())
    out = {
        "#Unidades": m if m is not None else M.FORMATO_N_A,
        "#Alertas": n_alertas,
        "#Alertas_correlacionadas": corr,
        "#rule.id_distintos": len(rids),
        "#Unidades_FP": len(unidades_fp),
        "#Alertas_FP": n_alertas,
        "#Alertas_FP_sin_auto_ruido": asin_auto,
    }
    if m:
        fp = len(unidades_fp)
        pct_fp = fp / m
        out["#Unidades_TN"] = m - fp
        out["%Unidades_FP"] = M.fmt_pct(pct_fp)
        out["%Unidades_TN"] = M.fmt_pct(1.0 - pct_fp)
    else:
        out["#Unidades_TN"] = ""
        out["%Unidades_FP"] = ""
        out["%Unidades_TN"] = ""
    acc = _num(meta.get("n_acciones_ghosts"))
    dur = _num(meta.get("duracion_h"))
    out["FP_por_accion"] = M.fmt_usab(n_alertas / acc) if acc else ""
    out["FP_por_hora"] = M.fmt_usab(n_alertas / dur) if dur else ""
    out["_rids"] = rids
    return out


def _detalle(rows, config_rs, umbral, m):
    por_rid = {}
    for r in rows:
        if r.get("rs_origen") not in config_rs:
            continue
        if _num(r.get("rule_level"), -1.0) < umbral:
            continue
        rid = r.get("rule_id", "")
        d = por_rid.setdefault(rid, {"n": 0, "unidades": set(), "level": r.get("rule_level", ""),
                                     "groups": r.get("rule_groups", ""), "rs": r.get("rs_origen", "")})
        d["n"] += 1
        if r.get("unidad", ""):
            d["unidades"].add(r["unidad"])
    out = []
    for rid in sorted(por_rid, key=lambda s: (len(s), s)):
        d = por_rid[rid]
        veredicto = M.CATEGORIA_AUTO_RUIDO if str(rid) in ("80791",) else ""
        out.append(
            {
                "rule.id": rid,
                "rule_level": d["level"],
                "groups": d["groups"],
                "rs_origen": d["rs"],
                "#alertas_legitimas": d["n"],
                "#unidades_con_la_regla": len(d["unidades"]),
                "#alertas_correlacionadas": len(d["unidades"]),
                "es_TP_en_algun_ataque": "",
                "veredicto": veredicto,
            }
        )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T3 (legitimo) — bloque + detalle por rule.id.")
    ap.add_argument("--detalle", default="", help="CSV de detalle por alerta (con columna unidad)")
    ap.add_argument("--archives", default="", help="archives.json (M = nº de líneas)")
    ap.add_argument("--unidades-count", type=int, default=None, help="M explicitado")
    ap.add_argument("--corrida", default="L1-linux-wazuh-72h")
    ap.add_argument("--hids", default="wazuh")
    ap.add_argument("--so", default="linux")
    ap.add_argument("--tipo-trafico", default="(Legitimo) actividad sintetica GHOSTS")
    ap.add_argument("--fuente-generadora", default="GHOSTS")
    ap.add_argument("--inicio-utc", default="")
    ap.add_argument("--fin-utc", default="")
    ap.add_argument("--duracion-h", default="")
    ap.add_argument("--tamano", default="")
    ap.add_argument("--n-acciones-ghosts", default="")
    ap.add_argument("--n-ips-o-entidades", default="")
    ap.add_argument("--config", nargs="+", default=list(M.CONFIGS_VIRGEN))
    ap.add_argument("--umbral", nargs="+", type=int, default=list(M.UMBRALES))
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    m = args.unidades_count if args.unidades_count is not None else _contar_unidades(args.archives)
    if args.archives and not os.path.isfile(args.archives):
        print(f"AVISO: no existe {args.archives}; M = n/a (fallback L11)", file=sys.stderr)

    meta = {
        "corrida": args.corrida,
        "hids": args.hids,
        "so": args.so,
        "tipo_trafico": args.tipo_trafico,
        "fuente_generadora": args.fuente_generadora,
        "inicio_utc": args.inicio_utc,
        "fin_utc": args.fin_utc,
        "duracion_h": args.duracion_h,
        "tamano": args.tamano,
        "n_acciones_ghosts": args.n_acciones_ghosts,
        "n_ips_o_entidades": args.n_ips_o_entidades,
    }

    filas = []
    estado = "sin_datos"
    if args.detalle and os.path.isfile(args.detalle):
        _, rows = TC.read_csv_rows(args.detalle, required=["rule_id", "rs_origen"])
        estado = "calculado"
        for cfg in args.config:
            cfg_rs = set(M.CONFIGS[cfg])
            for u in args.umbral:
                blk = _bloque(rows, cfg_rs, u, m, meta)
                fila = dict(meta, seccion="agregado", config=cfg, umbral=u)
                for c in BLOQUE_COLS:
                    if c in blk:
                        fila[c] = blk[c]
                    elif c not in DETALLE_COLS:
                        fila[c] = ""
                filas.append(fila)
                for d in _detalle(rows, cfg_rs, u, m):
                    fila = dict(meta, seccion="detalle_ruleid", config=cfg, umbral=u)
                    for c in DETALLE_COLS:
                        fila[c] = d.get(c, "")
                    filas.append(fila)

    partes = [
        os.path.basename(args.out),
        "TFG HIDS - R2 T3 (plano legitimo; unidad=evento decodificado)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"estado={estado}",
        f"unidad={M.UNIDAD_LEGITIMO}",
        f"M={'n/a (fallback L11)' if not m else m}",
        f"instrumentacion={'archives.json' if m else 'pendiente L0/L1'}",
        f"config={','.join(args.config)}",
        f"umbral={','.join(str(u) for u in args.umbral)}",
        f"detalle={TC.rel(args.detalle) if args.detalle else '-'}",
        "layout=largo(seccion=agregado|detalle_ruleid)",
        "columnas=" + ",".join(HEADER),
    ]
    comment = "# " + " | ".join(partes)

    TC.write_csv(os.path.join(TC.ROOT, args.out), HEADER, filas, comment=comment)
    if m:
        print(f"T3: {len(filas)} filas (M={m}) -> {args.out}")
    else:
        print(f"T3: plantilla sin datos (M=n/a, L11) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
