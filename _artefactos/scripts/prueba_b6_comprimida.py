#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prueba_b6_comprimida.py — timeline de PRUEBA EN SECO para la campaña `B6`.

**No es un artefacto de la ventana.** Sirve para las pruebas en seco del bloque
`legitimo-v3` (T3, plan §5.3): ejecutar los **11 casos** de la campaña y sus **22
marcas** en una sola pasada, sin esperar a las 17:05-17:50Z de tres días distintos.

Cómo lo hace, sin inventar comandos:

1. lee los handlers `B6` **ya desplegados** en `d1.json`, `d2.json` y `d3.json`;
2. comprueba que sus comandos son **exactamente** los de
   `campana.acciones_b6(dia)` (misma fuente: `campana_casos.csv`);
3. conserva los huecos **intra-caso** originales (`GAP_INTRA`, 5-10 s) y fija la
   separación **entre casos** a `--separacion` segundos (por defecto **190 s**, >
   los 180 s que exige `extraer_campana.comprobar_ventanas`);
4. encadena los tres días en **un solo handler** que empieza en `--base` (UTC,
   `HH:MMZ`), y escribe la timeline en `--out`.

El resultado tiene las **mismas 63 acciones** (y por tanto las mismas 22 marcas)
que la campaña real; solo cambia el reloj. Determinista: dos ejecuciones son
byte-idénticas.

Uso:
    python _artefactos/scripts/prueba_b6_comprimida.py --base 12:00Z \
        --out /tmp/b6_prueba.json

Salida por consola: `inicio`, `fin`, `duracion_s`, `acciones`, `casos` y `marcas`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

import campana

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RECETAS = os.path.join(RAIZ, "Soporte", "Laboratorio", "legitimo_72h", "recetas")
GUARDIAN_S = 60


def hms_to_s(h: str) -> int:
    hh, mm, ss = (int(x) for x in h.split(":"))
    return hh * 3600 + mm * 60 + ss


def s_to_hms(s: int) -> str:
    s %= 24 * 3600
    return f"{s // 3600:02d}:{(s // 60) % 60:02d}:{s % 60:02d}"


def _handler_b6(tl):
    cand = [h for h in tl.get("TimeLineHandlers", [])
            if h.get("UtcTimeOff") == campana.B6["off"]]
    if len(cand) != 1:
        raise SystemExit(f"ERROR: se esperaba 1 handler B6 (UtcTimeOff={campana.B6['off']}) "
                         f"y hay {len(cand)}")
    return cand[0]


def construir(recetas=RECETAS, base_s=None, separacion=190):
    """Devuelve (timeline, meta). Verifica que los comandos son los del CSV."""
    if base_s is None:
        raise SystemExit("ERROR: falta la hora base")
    eventos, meta_dias = [], []
    for dia in (1, 2, 3):
        path = os.path.join(recetas, f"d{dia}.json")
        if not os.path.isfile(path):
            raise SystemExit(f"ERROR: falta {path}")
        with open(path, encoding="utf-8") as fh:
            tl = json.load(fh)
        h = _handler_b6(tl)
        cmds = [e["Command"] for e in h["TimeLineEvents"]]
        esperadas = campana.acciones_b6(dia)
        if len(cmds) != len(esperadas):
            raise SystemExit(f"ERROR: d{dia}/B6 tiene {len(cmds)} eventos y el CSV "
                             f"{len(esperadas)}")
        for i, (cmd, a) in enumerate(zip(cmds, esperadas)):
            if cmd != a["comando"]:
                raise SystemExit(f"ERROR: d{dia}/B6 evento {i} no coincide con el CSV")
        meta_dias.append({"dia": dia, "n": len(cmds), "casos": len(
            {a["caso"] for a in esperadas})})
        eventos.append((dia, esperadas, cmds))

    # --- re-tiempo: intra-caso original, entre casos `separacion` -------------
    plan = []          # [(comando, gap_previo_s, dia, caso, tipo)]
    for dia, esperadas, cmds in eventos:
        prev_caso = None
        for i, (a, cmd) in enumerate(zip(esperadas, cmds)):
            if i == 0:
                gap = 0 if not plan else separacion
            elif a["caso"] != prev_caso:
                gap = separacion
            else:
                gap = a["t"] - esperadas[i - 1]["t"]
            plan.append({"cmd": cmd, "gap": gap, "dia": dia,
                         "caso": a["caso"], "tipo": a["tipo"]})
            prev_caso = a["caso"]

    total = sum(p["gap"] for p in plan)
    off_s = base_s + total + GUARDIAN_S
    evs = []
    for i, p in enumerate(plan):
        if i + 1 < len(plan):
            dl = plan[i + 1]["gap"]
        else:
            dl = GUARDIAN_S
        evs.append({"Command": p["cmd"], "DelayAfter": int(dl) * 1000})
    tl = {
        "Status": "Run",
        "TimeLineHandlers": [{
            "HandlerType": "Command",
            "Initial": "",
            "UtcTimeOn": s_to_hms(base_s),
            "UtcTimeOff": s_to_hms(off_s),
            "Loop": True,
            "HandlerArgs": {},
            "TimeLineEvents": evs,
        }],
    }
    meta = {
        "inicio": s_to_hms(base_s),
        "fin": s_to_hms(base_s + total),
        "duracion_s": total,
        "acciones": len(plan),
        "casos": len({p["caso"] for p in plan}),
        "marcas": sum(1 for p in plan if p["tipo"] in ("inicio", "fin")),
        "separacion_s": separacion,
        "dias": meta_dias,
    }
    return tl, meta


def main(argv=None):
    ap = argparse.ArgumentParser(description="Timeline comprimida de la campaña B6 (prueba).")
    ap.add_argument("--base", required=True, help="hora UTC de inicio (HH:MMZ)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--recetas", default=RECETAS)
    ap.add_argument("--separacion", type=int, default=190,
                    help="segundos entre casos (debe ser > 180; def. 190)")
    args = ap.parse_args(argv)

    if args.separacion <= 180:
        ap.error("--separacion debe ser > 180 s (ventana de atribución)")
    m = re.match(r"^(\d{1,2}):(\d{2})Z?$", args.base.strip())
    if not m:
        ap.error("--base debe ser HH:MMZ")
    base_s = int(m.group(1)) * 3600 + int(m.group(2)) * 60

    tl, meta = construir(args.recetas, base_s, args.separacion)
    if base_s + meta["duracion_s"] + GUARDIAN_S > 24 * 3600:
        ap.error("la prueba no puede cruzar medianoche UTC con este formato")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(tl, fh, indent=1, ensure_ascii=False)
        fh.write("\n")

    print(f"inicio={meta['inicio']} fin={meta['fin']} duracion_s={meta['duracion_s']} "
          f"acciones={meta['acciones']} casos={meta['casos']} marcas={meta['marcas']} "
          f"separacion_s={meta['separacion_s']}")
    for d in meta["dias"]:
        print(f"  d{d['dia']}: {d['n']} acciones, {d['casos']} casos")
    if meta["acciones"] != 63 or meta["marcas"] != 22 or meta["casos"] != 11:
        print("ERROR: los conteos no son 63/22/11", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
