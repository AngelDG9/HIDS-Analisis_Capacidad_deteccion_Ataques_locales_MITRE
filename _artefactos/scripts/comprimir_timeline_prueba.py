#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comprimir_timeline_prueba.py — aplana una timeline de PRUEBA en un solo handler.

**No es un artefacto de la ventana.** Las pruebas en seco del bloque `legitimo-v3`
(T3) comprimen la jornada: `construir_receta_legitima.py --dry` genera **5 handlers**
(de 26 s a 116 s). GHOSTS llama a `WorkingHours.Is()` **antes de cada evento** y, si
la hora actual ya pasó de `UtcTimeOff`, duerme hasta el día siguiente: en modo
comprimido eso **trunca la cola de cada bloque** (no ocurre en la receta real, con
bloques de 8 h). Resultado observado: 142 de 147 acciones.

Este script conserva **la misma secuencia y los mismos huecos** del dry, pero los
mete en **un único handler** con `UtcTimeOff` después del último evento (margen de
`--margen` segundos). Así `WorkingHours` nunca corta a mitad y se ejecutan las 147.

Uso:
    python _artefactos/scripts/comprimir_timeline_prueba.py \
        --in /tmp/d1.dry.json --base 12:00Z --out /tmp/d1.uno.json

Salida por consola: `acciones`, `inicio`, `fin`, `duracion_s`. Determinista.
"""

from __future__ import annotations

import argparse
import json
import os
import re


def hms_to_s(h: str) -> int:
    hh, mm, ss = (int(x) for x in h.split(":"))
    return hh * 3600 + mm * 60 + ss


def s_to_hms(s: int) -> str:
    s %= 24 * 3600
    return f"{s // 3600:02d}:{(s // 60) % 60:02d}:{s % 60:02d}"


def aplanar(tl, base_s: int, margen: int = 120):
    hs = tl.get("TimeLineHandlers") or []
    if not hs:
        raise SystemExit("ERROR: la timeline no tiene handlers")
    # tiempos absolutos (s desde medianoche) de cada evento, conservando los huecos
    abs_t, cmds = [], []
    for h in hs:
        on = hms_to_s(h["UtcTimeOn"])
        t = on
        for i, ev in enumerate(h["TimeLineEvents"]):
            if i:
                t += ev["DelayAfter"] / 1000.0
            abs_t.append(t)
            cmds.append(ev["Command"])
    if any(b < a for a, b in zip(abs_t, abs_t[1:])):
        raise SystemExit("ERROR: los eventos no están en orden temporal")

    offset = base_s - abs_t[0]
    evs = []
    for i, (t, cmd) in enumerate(zip(abs_t, cmds)):
        if i + 1 < len(abs_t):
            dl = abs_t[i + 1] - t
        else:
            dl = margen
        evs.append({"Command": cmd, "DelayAfter": int(round(dl * 1000))})

    inicio = base_s
    fin = int(round(base_s + (abs_t[-1] - abs_t[0])))
    out = {
        "Status": "Run",
        "TimeLineHandlers": [{
            "HandlerType": "Command",
            "Initial": "",
            "UtcTimeOn": s_to_hms(inicio),
            "UtcTimeOff": s_to_hms(fin + margen),
            "Loop": True,
            "HandlerArgs": {},
            "TimeLineEvents": evs,
        }],
    }
    return out, {"acciones": len(evs), "inicio": s_to_hms(inicio),
                 "fin": s_to_hms(fin), "duracion_s": fin - inicio}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aplana una timeline de prueba en 1 handler.")
    ap.add_argument("--in", dest="entrada", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", required=True, help="hora UTC de inicio (HH:MMZ)")
    ap.add_argument("--margen", type=int, default=120,
                    help="segundos de margen tras el último evento (def. 120)")
    args = ap.parse_args(argv)

    m = re.match(r"^(\d{1,2}):(\d{2})Z?$", args.base.strip())
    if not m:
        ap.error("--base debe ser HH:MMZ")
    base_s = int(m.group(1)) * 3600 + int(m.group(2)) * 60

    with open(args.entrada, encoding="utf-8") as fh:
        tl = json.load(fh)
    out, meta = aplanar(tl, base_s, args.margen)
    if base_s + meta["duracion_s"] + args.margen > 24 * 3600:
        ap.error("la prueba no puede cruzar medianoche UTC con este formato")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"acciones={meta['acciones']} inicio={meta['inicio']} fin={meta['fin']} "
          f"duracion_s={meta['duracion_s']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
