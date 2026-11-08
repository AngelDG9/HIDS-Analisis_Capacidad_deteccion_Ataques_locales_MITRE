#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla5_pruning.py — T5 (pruning / mejora del rendimiento) del TFG HIDS.

Adapta el *pipeline* del repo hermano (`optimo_Snort_GM_v4.py`): variantes
`No Pruning | Pruning 500 | Pruning 1000 | Conservative | Generalized Conservative |
Aggressive (G-Mean)`, con `rule.id` en lugar de `SID` (R2 §4.5).

**Qué se puede calcular sin el legítimo (L1).** La **selección de reglas** (qué `rule.id`
quita cada variante) y el **TPR/%Deteccion** resultante (recalculado sobre los `-Audited.csv`
canónicos, por caso). **Qué NO.** Las columnas que dependen del legítimo
(`#Alertas_FP`, `Usabilidad`, `GM` por `TNR`): quedan **vacías** y se **declaran** hasta que
exista la ventana legítima (`L0`/`L1`). Nada de humo.

Salidas: `Hojas/T5_pruning.csv` + `Hojas/T5_steps.csv`. Determinismo: orden numérico
ascendente de `rule.id`; sin reloj.
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
DEFAULT_AUDITADO = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_REPETICIONES = "Hojas/repeticiones.csv"
DEFAULT_OUT = "Hojas/T5_pruning.csv"
DEFAULT_STEPS = "Hojas/T5_steps.csv"

HEADER = [
    "variante",
    "config",
    "umbral",
    "GM",
    "%Deteccion_casos",
    "#reglas_quitadas",
    "lista_rule.id_quitados",
    "#Alertas_total",
    "#Alertas_TP",
    "#Alertas_FP",
    "Usabilidad",
]
STEPS_HEADER = [
    "config",
    "umbral",
    "paso",
    "rule.id_quitado",
    "TP_casos",
    "FN_casos",
    "TN_unidades",
    "FP_unidades",
    "TPR",
    "TNR",
    "GM",
    "Alertas_TP",
    "Alertas_FP",
]


def _sort_rid(rid):
    s = str(rid)
    return (0, int(s)) if s.isdigit() else (1, s)


def _num(x, default=None):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return default


def _sha_txt(path):
    """`sha256` de una entrada (o `-` si no existe)."""
    p = os.path.join(TC.ROOT, path)
    if not os.path.isfile(p):
        return "-"
    return TC.sha256_file(p)


def _leer_t2(path):
    if not os.path.isfile(os.path.join(TC.ROOT, path)):
        return []
    _, rows = TC.read_csv_rows(path)
    return rows


def _leer_t3_detalle(path, cfg=None, umbral=None):
    """Detalle de T3. Si se pasa `cfg`/`umbral`, **filtra** ese bloque (una fila por
    `rule.id`); sin filtro devuelve todo (compatibilidad)."""
    if not os.path.isfile(os.path.join(TC.ROOT, path)):
        return []
    _, rows = TC.read_csv_rows(path)
    out = [r for r in rows if r.get("seccion") == "detalle_ruleid"]
    if cfg is not None:
        out = [r for r in out if r.get("config") == cfg]
    if umbral is not None:
        out = [r for r in out if int(_num(r.get("umbral"), -1)) == int(umbral)]
    return out


def _m_de_t3(path):
    """`M` (denominador legítimo) del bloque `agregado` de T3; `None` si no existe."""
    if not os.path.isfile(os.path.join(TC.ROOT, path)):
        return None
    _, rows = TC.read_csv_rows(path)
    for r in rows:
        if r.get("seccion") == "agregado":
            return _num(r.get("#Unidades"))
    return None


def _metricas(activas, por_caso, n_casos, leg_unidades, leg_alertas, m):
    """TPR/FP_uni/TNR/GM/Usabilidad de un conjunto de reglas activas (1 evento -> 1 alerta)."""
    casos_tp = sum(1 for s in por_caso.values() if s & activas)
    alertas_tp = sum(len(s & activas) for s in por_caso.values())
    fp_uni = sum(leg_unidades.get(r, 0) for r in activas)
    a_fp = sum(leg_alertas.get(r, 0) for r in activas)
    tpr = M.tpr(casos_tp, n_casos)
    fpr = M.fpr(fp_uni, m) if m else None
    tnr = M.tnr(fpr)
    return {
        "casos_tp": casos_tp,
        "alertas_tp": alertas_tp,
        "fp_uni": fp_uni,
        "a_fp": a_fp,
        "tpr": tpr,
        "tnr": tnr,
        "gm": M.gm(tpr, tnr),
        "usab": M.usabilidad(a_fp, alertas_tp),
    }


def _aggressive(base, mixed, leg_alertas, metricas_fn):
    """`Aggressive (G-Mean)` real (`formula_plantillas.md:78`).

    Parte de **Conservative**; ordena las reglas **mixtas** por impacto en el legítimo
    **desc** (empate: `rule.id` asc) y quita **solo si el GM mejora** (empate -> conservar).
    Determinista, sin heurísticas ocultas.
    """
    activas = set(base)
    cur = metricas_fn(activas)
    orden = sorted(mixed, key=lambda r: (-leg_alertas.get(r, 0), _sort_rid(r)))
    quitadas = []
    for r in orden:
        cand = activas - {r}
        m2 = metricas_fn(cand)
        if m2["gm"] is not None and cur["gm"] is not None and m2["gm"] > cur["gm"] + 1e-12:
            activas = cand
            cur = m2
            quitadas.append(r)
    return activas, cur, orden, quitadas


def _repeticiones(path):
    if not os.path.isfile(os.path.join(TC.ROOT, path)):
        return set()
    _, rows = TC.read_csv_rows(path, required=["ata_id"])
    return {r["ata_id"].strip() for r in rows}


def _reglas_por_caso(auditado_dir, repeticiones, config_rs, umbral):
    """{caso: set(rule.id deteccion)} por config×umbral, sobre la ventana canónica."""
    out = {}
    for f in sorted(os.listdir(auditado_dir)):
        if not f.endswith("-Audited.csv"):
            continue
        ata = f.split("_")[0]
        win = M.ventana_canonica(ata, repeticiones)
        if f != f"{ata}_{win}-Audited.csv":
            continue
        _, rows = TC.read_csv_rows(os.path.join(auditado_dir, f))
        s = set()
        for x in rows:
            if x.get("categoria") != M.CATEGORIA_DETECCION:
                continue
            if x.get("rs_origen") not in config_rs:
                continue
            if _num(x.get("rule_level"), -1.0) < umbral:
                continue
            s.add(x.get("rule_id", ""))
        out[ata] = s
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T5 (pruning) — variantes del pipeline del hermano.")
    ap.add_argument("--t2", default=DEFAULT_T2)
    ap.add_argument("--t3", default=DEFAULT_T3)
    ap.add_argument("--auditado", default=DEFAULT_AUDITADO)
    ap.add_argument("--repeticiones", default=DEFAULT_REPETICIONES)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--steps", default=DEFAULT_STEPS)
    args = ap.parse_args(argv)

    t2 = _leer_t2(args.t2)
    rep = _repeticiones(args.repeticiones)
    auditado_dir = os.path.join(TC.ROOT, args.auditado)
    m_legitimo = _m_de_t3(args.t3)

    claves = sorted({(r["config"], int(r["umbral"])) for r in t2}, key=lambda c: (c[0], c[1]))
    filas = []
    steps = []
    estado = "sin_datos" if (not t2 or not os.path.isdir(auditado_dir)) else "completo"
    if m_legitimo is None:
        estado = "parcial_sin_legitimo"

    for (cfg, u) in claves:
        cfg_rs = set(M.CONFIGS[cfg])
        por_caso = _reglas_por_caso(auditado_dir, rep, cfg_rs, u)
        n_casos = len(por_caso)
        sids_ataque = set().union(*por_caso.values()) if por_caso else set()

        # Bloque de T3 de ESTE config x umbral (una fila por rule.id del legítimo)
        det3 = _leer_t3_detalle(args.t3, cfg, u)
        leg_unidades = {r["rule.id"]: int(_num(r.get("#unidades_con_la_regla"), 0)) for r in det3}
        leg_alertas = {r["rule.id"]: int(_num(r.get("#alertas_legitimas"), 0)) for r in det3}
        leg_diff = {r["rule.id"]: int(_num(r.get("#alertas_correlacionadas"), 0)) for r in det3}
        sids_legitimo = set(leg_diff)
        sids_activos = sids_ataque | sids_legitimo

        def _met(activas):
            return _metricas(activas, por_caso, n_casos, leg_unidades, leg_alertas, m_legitimo)

        variantes = {
            "No Pruning": M.reglas_pruning_no_pruning(sids_activos),
            "Pruning 500": M.reglas_pruning_n(sids_activos, leg_diff, 500),
            "Pruning 1000": M.reglas_pruning_n(sids_activos, leg_diff, 1000),
            "Conservative": M.reglas_pruning_conservative(sids_activos, sids_legitimo, sids_ataque),
            "Generalized Conservative": M.reglas_pruning_generalized(sids_activos, sids_legitimo),
        }
        base_cons = variantes["Conservative"]
        mixed = sorted(set(sids_legitimo) & set(sids_ataque))
        agresivas, _cur, orden_mixtas, quitadas_mixtas = _aggressive(
            base_cons, mixed, leg_alertas, _met
        )
        variantes["Aggressive (G-Mean)"] = agresivas

        for var in M.PRUNING_VARIANTES:
            activas = variantes[var]
            quitadas = sorted(sids_activos - activas, key=_sort_rid)
            met = _met(activas)
            filas.append(
                {
                    "variante": var,
                    "config": cfg,
                    "umbral": u,
                    "GM": M.fmt_ratio(met["gm"]),
                    "%Deteccion_casos": M.fmt_det(100.0 * met["casos_tp"] / n_casos) if n_casos else "",
                    "#reglas_quitadas": len(quitadas),
                    "lista_rule.id_quitados": " ".join(str(q) for q in quitadas),
                    "#Alertas_total": met["alertas_tp"],
                    "#Alertas_TP": met["alertas_tp"],
                    "#Alertas_FP": met["a_fp"],
                    "Usabilidad": M.fmt_usab(met["usab"]),
                }
            )

        # T5_steps: pasos de la eliminación del `Aggressive` (FP-only y luego mixtas).
        # Solo se listan las reglas **quitadas**; las mixtas **conservadas** se declaran
        # en la cabecera (no hay columna para ellas).
        activas = set(sids_activos)
        secuencia = sorted(sids_legitimo - sids_ataque, key=_sort_rid) + list(quitadas_mixtas)
        for paso, rid in enumerate(secuencia, start=1):
            activas.discard(rid)
            met = _met(activas)
            steps.append(
                {
                    "config": cfg,
                    "umbral": u,
                    "paso": paso,
                    "rule.id_quitado": rid,
                    "TP_casos": met["casos_tp"],
                    "FN_casos": n_casos - met["casos_tp"],
                    "TN_unidades": int(m_legitimo - met["fp_uni"]) if m_legitimo else "",
                    "FP_unidades": met["fp_uni"],
                    "TPR": M.fmt_ratio(met["tpr"]),
                    "TNR": M.fmt_ratio(met["tnr"]),
                    "GM": M.fmt_ratio(met["gm"]),
                    "Alertas_TP": met["alertas_tp"],
                    "Alertas_FP": met["a_fp"],
                }
            )

    partes = [
        os.path.basename(args.out),
        "TFG HIDS - R2 T5 (pruning)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"estado={estado}",
        f"variantes={';'.join(M.PRUNING_VARIANTES)}",
        "N=500,1000 (escala NIDS; variante relativa declarada en formula_plantillas.md)",
        f"M={int(m_legitimo) if m_legitimo else 'n/a'}",
        "columnas_completadas=GM,#Alertas_FP,Usabilidad (T3/legitimo ya existe)",
        "declaracion=#Alertas_TP es A_TP^c (suma por caso de rule.id distintos) -> Usabilidad correlacionada (no la bruta de T4)",
        "declaracion=Aggressive (G-Mean) real: parte de Conservative, quita mixtas por impacto legitimo desc solo si GM mejora (empate -> conservar)",
        "layout=largo(1 fila por variante x config x umbral)",
        f"t2={args.t2}",
        f"t3={args.t3}",
        f"auditado={args.auditado}",
        f"sha256_entradas={_sha_txt(args.t2)},{_sha_txt(args.t3)}",
        "columnas=" + ",".join(HEADER),
    ]
    comment = "# " + " | ".join(partes)
    TC.write_csv(os.path.join(TC.ROOT, args.out), HEADER, filas, comment=comment)

    steps_comment = "# " + " | ".join(
        [
            os.path.basename(args.steps),
            "TFG HIDS - R2 T5 steps (pasos de la variante agresiva; solo reglas QUITADAS)",
            f"metrica_version={M.VERSION_METRICA}",
            f"boveda_version={M.VERSION_BOVEDA}",
            f"estado={estado}",
            f"auditado={args.auditado}",
            f"t2={args.t2}",
            f"t3={args.t3}",
            f"sha256_entradas={_sha_txt(args.t2)},{_sha_txt(args.t3)}",
            "declaracion=orden: FP-only (rule.id asc) y luego mixtas en orden de evaluacion (impacto legitimo desc); las mixtas CONSERVADAS no se listan",
            "layout=largo(1 fila por paso x config x umbral)",
            "columnas=" + ",".join(STEPS_HEADER),
        ]
    )
    TC.write_csv(os.path.join(TC.ROOT, args.steps), STEPS_HEADER, steps, comment=steps_comment)

    print(f"T5: {len(filas)} filas ({estado}) -> {args.out} + {args.steps}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
