#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clasificar_w07_windows.py — separa, de forma determinista, las alertas de W-07.

Contexto (T4b, 2026-11-12)
--------------------------
La extracción de campaña de Windows atribuye alertas a un caso en la ventana
``[ini - 10 s, fin + 60 s]``. En W-07 esa ventana capturó, además de las 6 acciones
reales (10:05:47–10:06:28Z), una ráfaga de mantenimiento programado de Windows
(10:07:19–10:07:29Z) y dos artefactos de ``__PSScriptPolicyTest``/``sdiagnhost``.
Este script NO decide el resultado canónico: solo deja explícito qué filas son del
caso y qué filas se excluyen, con el motivo, para que la tabla bruta y la filtrada
se puedan reproducir y auditar.

Entradas
--------
--detalle   CSV de alertas por alerta (el que produce ``extraer_alertas_windows.py``;
            admite líneas de comentario que empiezan por ``#``).
--ventanas  TSV de ventanas de campaña (``campo``/``ini``/``fin``; el de
            ``extraer_campana_windows.py --solo-ventanas``).
--caso      Caso a clasificar (por defecto ``W-07``).
--out-dir   Directorio de evidencia donde escribir las salidas.

Salidas
-------
w07_alertas_bruto.csv        Las 90 alertas de la ventana de atribución, sin filtro.
w07_alertas_caso_w07.csv     Las 20 alertas de las acciones de W-07 (sin artefactos).
w07_exclusiones.csv          Las 70 alertas excluidas, con motivo y detalle.
w07_variantes.csv            Las 4 cifras: canónico, sin_ajenas, sin_artefactos_ps,
                             sin_ambas (misma regla de detección: 67027 y level < 7).
w07_clasificacion.log        Resumen literal de la clasificación y de las variantes.

Criterio (explícito, sin IA)
----------------------------
1. ``fuera_ventana_atribucion``: fuera de ``[ini-10s, fin+60s]`` (no hay ninguna).
2. ``artefacto_powershell_policytest``: ``92213`` con ``win_target`` que contiene
   ``__PSScriptPolicyTest``, o ``91823`` con ``Invoke-command`` en la descripción.
   Son artefactos del propio PowerShell/diagnóstico, no detecciones. **Uno de ellos**
   (``92213`` a las 10:06:02.285Z) cae **dentro** de ``[ini, fin]`` y lo genera la
   acción 3 (``powershell``); los otros dos son de las 10:07:29Z. El detalle lo deja
   escrito ``detalle_exclusion``.
3. ``caso_w07``: ``ini <= ts <= fin`` y no es artefacto de policy test.
4. ``mantenimiento_windows_fuera_de_accion``: ``ts > fin`` (o ``ts < ini``) y no es
   artefacto de policy test. Es la ráfaga de mantenimiento programado de Windows
   (10:07:19–10:07:29Z, **fuera** de ``[ini, fin]``).

No se filtra por usuario ni por ``rule_id`` a mano: las reglas anteriores son el
criterio completo. Cualquier alerta que no case con 1–4 hace fallar el script.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import os
import sys
from collections import Counter

ATRIB_PRE_S = 10
ATRIB_POST_S = 60
POLICY_RULES = {"92213", "91823"}
REASON_ORDER = (
    "caso_w07",
    "artefacto_powershell_policytest",
    "mantenimiento_windows_fuera_de_accion",
    "fuera_ventana_atribucion",
)
UMBRAL_N7 = 7
RULE_EXEC = "67027"


def parse_ts(raw: str) -> dt.datetime:
    s = (raw or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def fmt_ts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def leer_detalle(path: str):
    with io.open(path, "r", encoding="utf-8-sig", newline="") as fh:
        lineas = [ln for ln in fh if not ln.startswith("#")]
    rd = csv.DictReader(lineas)
    if not rd.fieldnames:
        raise SystemExit(f"ERROR: {path} no tiene cabecera CSV")
    return list(rd.fieldnames), [dict(r) for r in rd]


def leer_ventanas(path: str, caso: str):
    with io.open(path, "r", encoding="utf-8-sig", newline="") as fh:
        lineas = [ln for ln in fh if not ln.startswith("#")]
    rd = csv.DictReader(lineas, delimiter="\t")
    campos = [c.strip().lower() for c in (rd.fieldnames or [])]
    if not {"caso", "ini", "fin"}.issubset(set(campos)):
        raise SystemExit(f"ERROR: {path} debe tener caso/ini/fin (tiene {campos})")
    for r in rd:
        if (r.get("caso") or "").strip() != caso:
            continue
        ini, fin = (r.get("ini") or "").strip(), (r.get("fin") or "").strip()
        if not ini or not fin:
            raise SystemExit(f"ERROR: {caso} no tiene ini/fin en {path}")
        return parse_ts(ini), parse_ts(fin)
    raise SystemExit(f"ERROR: {caso} no está en {path}")


def clasificar(fila: dict, ini: dt.datetime, fin: dt.datetime):
    """Devuelve (motivo, detalle) para una fila de alerta."""
    ts = parse_ts(fila.get("timestamp_utc", ""))
    rule = (fila.get("rule_id") or "").strip()
    target = fila.get("win_target") or ""
    desc = fila.get("rule_description") or ""
    if ts < ini - dt.timedelta(seconds=ATRIB_PRE_S) or ts > fin + dt.timedelta(seconds=ATRIB_POST_S):
        return "fuera_ventana_atribucion", f"ts={fmt_ts(ts)}"
    if rule == "92213" and "__PSScriptPolicyTest" in target:
        dentro = ini <= ts <= fin
        etiqueta = ("policy_test DENTRO de [ini,fin] (accion powershell)"
                    if dentro else "policy_test posterior a fin (diagnostico)")
        return "artefacto_powershell_policytest", f"{etiqueta}; win_target={target}"
    if rule == "91823" and "invoke-command" in desc.lower():
        dentro = ini <= ts <= fin
        etiqueta = ("policy_test DENTRO de [ini,fin] (accion powershell)"
                    if dentro else "policy_test posterior a fin (diagnostico)")
        return "artefacto_powershell_policytest", f"{etiqueta}; Invoke-command (sdiagnhost/diagnóstico)"
    if ini <= ts <= fin:
        return "caso_w07", ""
    # ts > fin (o ts < ini, ya cubierto arriba): la ráfaga de mantenimiento.
    img = (fila.get("win_image") or "").replace("\\\\", "\\")
    img = os.path.basename(img) if img else ""
    user = (fila.get("win_user") or "").strip()
    return "mantenimiento_windows_fuera_de_accion", f"{img} user={user}"


def escribir_csv(path: str, campos, filas, comentario: str):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(comentario.rstrip("\n") + "\n")
        w = csv.DictWriter(fh, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        for r in filas:
            w.writerow({k: r.get(k, "") for k in campos})
    print(f"-> {path} ({len(filas)} filas)")


def resumen(filas, campo_motivo):
    c = Counter(r[campo_motivo] for r in filas)
    reglas = {}
    for motivo in REASON_ORDER:
        reglas[motivo] = Counter()
    for r in filas:
        reglas[r[campo_motivo]][str(r.get("rule_id") or "")] += 1
    lineas = []
    for motivo in REASON_ORDER:
        if c.get(motivo):
            rs = ", ".join(f"{k}={v}" for k, v in sorted(reglas[motivo].items(), key=lambda kv: (-kv[1], kv[0])))
            lineas.append(f"{motivo}: {c[motivo]} ({rs})")
    return c, lineas


def _estado_variante(filas):
    """Aplica la regla de detección de la campaña: 67027 presente y level < 7."""
    rules = sorted({(r.get("rule_id") or "").strip()
                    for r in filas if (r.get("rule_id") or "").strip()})
    levels = []
    for r in filas:
        raw = (r.get("rule_level") or "").strip()
        if raw:
            try:
                levels.append(int(float(raw)))
            except ValueError:
                levels.append(0)
    level = max(levels) if levels else 0
    estado = "SI" if RULE_EXEC in rules and level < UMBRAL_N7 else "NO"
    return estado, rules, level


def calcular_variantes(clasificadas):
    """Devuelve las 4 cifras pedidas: canónico, sin_ajenas, sin_artefactos_ps, sin_ambas."""
    definiciones = (
        ("canonico", "sin exclusiones (bruto)", set()),
        ("sin_ajenas", "excluye mantenimiento_windows_fuera_de_accion (67)",
         {"mantenimiento_windows_fuera_de_accion"}),
        ("sin_artefactos_ps", "excluye artefacto_powershell_policytest (3)",
         {"artefacto_powershell_policytest"}),
        ("sin_ambas", "excluye ambos grupos (sensibilidad)",
         {"mantenimiento_windows_fuera_de_accion",
          "artefacto_powershell_policytest"}),
    )
    filas = []
    for nombre, nota, excluir in definiciones:
        sel = [r for r in clasificadas if r["_motivo"] not in excluir]
        estado, rules, level = _estado_variante(sel)
        filas.append({
            "variante": nombre,
            "excluidas": str(len(clasificadas) - len(sel)),
            "alertas": str(len(sel)),
            "rule_id": ";".join(rules),
            "level": str(level),
            "esperado_cumplido": estado,
            "nota": nota,
        })
    return filas


def escribir_variantes(path: str, filas, total: int):
    campos = ["variante", "excluidas", "alertas", "rule_id", "level",
              "esperado_cumplido", "nota"]
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            f"# W-07 - VARIANTES | total={total} | regla de deteccion: "
            f"rule_id={RULE_EXEC} y level<{UMBRAL_N7} | "
            f"sin_ajenas=67 mantenimiento (10:07:19-10:07:29Z, fuera de [ini,fin]); "
            f"sin_artefactos_ps=3 policy test (1 dentro de [ini,fin], accion 3; "
            f"2 a las 10:07:29Z)\n"
        )
        w = csv.DictWriter(fh, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        for r in filas:
            w.writerow(r)
    print(f"-> {path} ({len(filas)} filas)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detalle", required=True)
    ap.add_argument("--ventanas", required=True)
    ap.add_argument("--caso", default="W-07")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)

    ini, fin = leer_ventanas(args.ventanas, args.caso)
    campos, filas = leer_detalle(args.detalle)
    if not filas:
        raise SystemExit("ERROR: el detalle no tiene filas")

    clasificadas = []
    for r in filas:
        motivo, detalle = clasificar(r, ini, fin)
        r = dict(r)
        r["_motivo"] = motivo
        r["_detalle"] = detalle
        clasificadas.append(r)

    c, lineas = resumen(clasificadas, "_motivo")
    if set(c) - set(REASON_ORDER):
        raise SystemExit(f"ERROR: motivos no previstos: {sorted(set(c) - set(REASON_ORDER))}")
    if c.get("fuera_ventana_atribucion"):
        raise SystemExit(f"ERROR: {c['fuera_ventana_atribucion']} filas fuera de la ventana de atribución")

    os.makedirs(args.out_dir, exist_ok=True)
    cab = {
        "caso": (f"# {args.caso} | acciones=[{fmt_ts(ini)},{fmt_ts(fin)}] | "
                 f"atribucion=[ini-{ATRIB_PRE_S}s,fin+{ATRIB_POST_S}s] | "
                 f"fuente={os.path.basename(args.detalle)} | total={len(filas)}"),
        "bruto": (f"# {args.caso} — BRUTO | {len(filas)} alertas | sin filtro | "
                  f"ventana_atribucion=[{fmt_ts(ini - dt.timedelta(seconds=ATRIB_PRE_S))},"
                  f"{fmt_ts(fin + dt.timedelta(seconds=ATRIB_POST_S))}]"),
        "caso": (f"# {args.caso} — CASO | {c.get('caso_w07', 0)} alertas | "
                 f"filtro=acciones [{fmt_ts(ini)},{fmt_ts(fin)}] sin artefactos "
                 f"__PSScriptPolicyTest/Invoke-command"),
        "excl": (f"# {args.caso} — EXCLUSIONES | {len(filas) - c.get('caso_w07', 0)} alertas | "
                 f"3 artefactos policy_test (1 DENTRO de [ini,fin], accion 3; 2 posteriores) + "
                 f"67 mantenimiento (ts>{fmt_ts(fin)}) | "
                 f"NO es una decisión de resultado: es la trazabilidad de la tabla filtrada"),
    }

    bruto = [{k: r.get(k, "") for k in campos} for r in clasificadas]
    caso = [{k: r.get(k, "") for k in campos} for r in clasificadas if r["_motivo"] == "caso_w07"]
    excl_campos = list(campos) + ["motivo_exclusion", "detalle_exclusion"]
    excl = []
    for r in clasificadas:
        if r["_motivo"] == "caso_w07":
            continue
        d = {k: r.get(k, "") for k in campos}
        d["motivo_exclusion"] = r["_motivo"]
        d["detalle_exclusion"] = r["_detalle"]
        excl.append(d)

    escribir_csv(os.path.join(args.out_dir, "w07_alertas_bruto.csv"), campos, bruto, cab["bruto"])
    escribir_csv(os.path.join(args.out_dir, "w07_alertas_caso_w07.csv"), campos, caso, cab["caso"])
    escribir_csv(os.path.join(args.out_dir, "w07_exclusiones.csv"), excl_campos, excl, cab["excl"])

    variantes = calcular_variantes(clasificadas)
    escribir_variantes(os.path.join(args.out_dir, "w07_variantes.csv"), variantes, len(filas))

    log = [
        f"# {args.caso} — clasificación reproducible (T4b)",
        f"# fecha_utc={fmt_ts(dt.datetime.now(dt.timezone.utc))}",
        f"# detalle={args.detalle}",
        f"# ventanas={args.ventanas}",
        f"# acciones=[{fmt_ts(ini)},{fmt_ts(fin)}] atribucion=[ini-{ATRIB_PRE_S}s,fin+{ATRIB_POST_S}s]",
        f"# criterio: 92213 con __PSScriptPolicyTest y 91823 con Invoke-command => policy_test; "
        f"ts>{fmt_ts(fin)} => mantenimiento; resto dentro de acciones => caso_w07",
        f"total={len(filas)}",
    ] + lineas + [
        "",
        f"# variantes (misma regla de deteccion: rule_id={RULE_EXEC} y level<{UMBRAL_N7})",
    ] + [
        f"{v['variante']}: excluidas={v['excluidas']} alertas={v['alertas']} "
        f"level={v['level']} esperado={v['esperado_cumplido']}"
        for v in variantes
    ] + [
        f"caso_w07={c.get('caso_w07', 0)}",
        f"excluidas={len(filas) - c.get('caso_w07', 0)}",
        f"cuadre={'OK' if c.get('caso_w07', 0) + (len(filas) - c.get('caso_w07', 0)) == len(filas) else 'FALLO'}",
    ]
    log_path = os.path.join(args.out_dir, "w07_clasificacion.log")
    with io.open(log_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(log) + "\n")
    print("\n".join(log))
    print(f"-> {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
