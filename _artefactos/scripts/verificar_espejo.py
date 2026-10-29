#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_espejo.py — comprueba que la receta Windows es **espejo** de la de Linux.

Compara `Soporte/Laboratorio/legitimo_72h/recetas/d{1,2,3}.json` (Linux) con
`Soporte/Laboratorio/windows/recetas/w{1,2,3}.json` (Windows) y **falla si un solo hueco
difiere**. Comprueba, por día y por handler:

1. **Estructura**: mismo número de handlers (5 de jornada + `B6`), mismo `HandlerType`,
   `Loop` y `HandlerArgs`.
2. **Ventanas**: mismo `UtcTimeOn` y `UtcTimeOff` (byte a byte).
3. **Conteo**: mismo número de eventos por bloque y por día.
4. **Ritmo**: la secuencia de `DelayAfter` es **idéntica**, elemento a elemento.
5. **Unidad**: cada acción Windows es **un** `cmd.exe` — el `Command` no lleva `cmd /c`
   (lo añade el handler), no hay `start`, no hay `|` fuera de `powershell -Command` y los
   bucles (`for /L`, `for /f`) aparecen **exactamente** donde Linux tenía su fan-out
   (`xargs`), con el mismo abanico (12).

Uso:
    python _artefactos/scripts/verificar_espejo.py
    python _artefactos/scripts/verificar_espejo.py --linux DIR --windows DIR
    python _artefactos/scripts/verificar_espejo.py --silencio   # solo el veredicto

Devuelve 0 si PASS y 1 si FALLA.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR_LINUX = os.path.join("Soporte", "Laboratorio", "legitimo_72h", "recetas")
DIR_WIN = os.path.join("Soporte", "Laboratorio", "windows", "recetas")

#: Abanico declarado del `xargs` de Linux (`seq 1 12` ⇒ 12 ficheros).
FANOUT_ESPERADO = 12
#: Máximo de hijos admitido en una acción (el `xargs` de 12 + el propio `cmd`).
MAX_HIJOS = FANOUT_ESPERADO

RE_BLOQUE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})$")
#: Binarios de Windows que **sí** crean proceso hijo (los demás son builtins de `cmd`).
#: `cmd` entra por el fan-out: `for … do @cmd /c copy` abre 12 hijos, como los 12 `cp` de
#: Linux (el `copy` es builtin y sin el `cmd` hijo el espejo abriría 0 procesos).
EXTERNOS = {
    "cmd",
    "certutil", "tar", "robocopy", "xcopy", "curl.exe", "powershell", "systeminfo",
    "ipconfig", "route", "fsutil", "eventcreate", "sc", "tasklist", "schtasks", "reg",
    "find", "findstr", "more", "sort", "hostname", "whoami", "attrib", "expand", "makecab",
    "fsutil.exe", "where", "net", "wevtutil", "bitsadmin", "arp", "nslookup", "tracert",
    "ping", "nbtstat", "getmac",
}


def _cargar(directorio: str, prefijo: str):
    datos = {}
    for day in (1, 2, 3):
        path = os.path.join(directorio, f"{prefijo}{day}.json")
        if not os.path.isfile(path):
            raise SystemExit(f"ERROR: falta {path}")
        with open(path, encoding="utf-8") as fh:
            datos[day] = json.load(fh)
    return datos


# --------------------------------------------------------------------------
# Unidad de proceso (1 acción = 1 `cmd.exe` + hijos declarados)
# --------------------------------------------------------------------------
def _segmentos(cmd: str):
    """Segmentos de primer nivel (`&`, `&&`, `|`) sin romper `2>&1` ni comillas."""
    out, buf, q, i = [], [], False, 0
    while i < len(cmd):
        c = cmd[i]
        if c == '"':
            q = not q
        if not q:
            if cmd.startswith(" && ", i):
                out.append("".join(buf))
                buf, i = [], i + 4
                continue
            if cmd.startswith("2>&1", i):
                buf.append("2>&1")
                i += 4
                continue
            if c in "&|":
                out.append("".join(buf))
                buf, i = [], i + 1
                continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _hijos_segmento(seg: str) -> int:
    """Procesos hijos que lanza **un** segmento (0 si es un builtin de `cmd`)."""
    # `if [not] errorlevel N ( … )`: cuenta lo que hay dentro del paréntesis
    m = re.match(r"^if\s+(?:not\s+)?(?:errorlevel\s+\d+|\S+\s*==\s*\S+|exist\s+\S+)\s*\((.*)\)"
                 r"(?:\s*else\s*\((.*)\))?$", seg, re.S)
    if m:
        return sum(_hijos_segmento(s) for grupo in m.groups() if grupo
                   for s in _segmentos(grupo))
    if seg.startswith("if "):
        # `if exist X del …` (una sola orden, builtin)
        resto = re.sub(r"^if\s+(?:not\s+)?(?:exist\s+\S+|errorlevel\s+\d+)", "", seg).strip()
        return _hijos_segmento(resto) if resto else 0
    m = re.match(r"^for\s+/([LfIi])\s+%[A-Za-z]\s+in\s*\((.*?)\)\s*do\s+@?(.*)$", seg, re.S)
    if m:
        modo, cabecera, cuerpo = m.group(1), m.group(2), m.group(3)
        if modo == "L":
            try:
                ini, _paso, fin = (int(x) for x in cabecera.split(","))
                vueltas = max(0, fin - ini + 1)
            except ValueError:
                vueltas = 1
        elif modo.lower() == "f":
            vueltas = FANOUT_ESPERADO          # lotes.txt lo genera `seq 1 12`
        else:
            vueltas = 1
        base = sum(_hijos_segmento(s) for s in _segmentos(cuerpo))
        return vueltas * base
    if re.match(r"^for\s+%[A-Za-z]\s+in\s*\(", seg):
        m2 = re.match(r"^for\s+%[A-Za-z]\s+in\s*\((.*?)\)\s*do\s+@?(.*)$", seg, re.S)
        if m2:
            return sum(_hijos_segmento(s) for s in _segmentos(m2.group(2)))
    tok = (seg.split() or [""])[0].lower().lstrip("@")
    if tok == "powershell":
        return 1
    return 1 if tok in EXTERNOS else 0


def hijos(cmd: str) -> int:
    """Hijos estimados de una acción Windows (0 = todo builtins de `cmd`)."""
    return sum(_hijos_segmento(s) for s in _segmentos(cmd))


def _es_fanout_linux(cmd: str) -> bool:
    return bool(re.search(r"(?:^|&&\s*)xargs\s", cmd))


def hijos_linux(cmd: str) -> int:
    """Procesos que abre una acción Linux (binarios por segmento + hijos declarados)."""
    import construir_receta_legitima as L
    n = len(L.binarios_de(cmd))
    if _es_fanout_linux(cmd):
        n += FANOUT_ESPERADO
    return n


# --------------------------------------------------------------------------
# Comparación
# --------------------------------------------------------------------------
def comparar(dir_linux: str, dir_win: str, verbose=True):
    lx = _cargar(dir_linux, "d")
    wn = _cargar(dir_win, "w")
    fallos, avisos = [], []
    tabla = []

    for day in (1, 2, 3):
        hl, hw = lx[day].get("TimeLineHandlers", []), wn[day].get("TimeLineHandlers", [])
        if len(hl) != len(hw):
            fallos.append(f"d{day}/w{day}: {len(hw)} handlers != {len(hl)} de Linux")
            continue
        for k, (a, b) in enumerate(zip(hl, hw)):
            etiqueta = f"d{day}/w{day} B{k + 1}" if k < len(hl) - 1 else f"d{day}/w{day} B6"
            for campo in ("HandlerType", "Loop", "HandlerArgs"):
                if a.get(campo) != b.get(campo):
                    fallos.append(f"{etiqueta}: {campo} {b.get(campo)!r} != {a.get(campo)!r}")
            if a.get("UtcTimeOn") != b.get("UtcTimeOn"):
                fallos.append(f"{etiqueta}: UtcTimeOn {b.get('UtcTimeOn')} != "
                              f"{a.get('UtcTimeOn')}")
            if a.get("UtcTimeOff") != b.get("UtcTimeOff"):
                fallos.append(f"{etiqueta}: UtcTimeOff {b.get('UtcTimeOff')} != "
                              f"{a.get('UtcTimeOff')}")
            ea, eb = a.get("TimeLineEvents", []), b.get("TimeLineEvents", [])
            if len(ea) != len(eb):
                fallos.append(f"{etiqueta}: {len(eb)} acciones != {len(ea)} de Linux")
                continue
            da = [int(e["DelayAfter"]) for e in ea]
            db = [int(e["DelayAfter"]) for e in eb]
            if da != db:
                malos = [i for i, (x, y) in enumerate(zip(da, db)) if x != y]
                fallos.append(f"{etiqueta}: {len(malos)} `DelayAfter` distintos "
                              f"(primero en #{malos[0]}: {db[malos[0]]} != {da[malos[0]]})")
            gaps = [d / 1000.0 for d in da[:-1]]
            tabla.append({
                "dia": day, "bloque": "B6" if k == len(hl) - 1 else f"B{k + 1}",
                "utc": f"{a['UtcTimeOn'][:5]}-{a['UtcTimeOff'][:5]}",
                "n_linux": len(ea), "n_win": len(eb),
                "huecos": len(gaps),
                "hueco_min_s": min(gaps) if gaps else 0,
                "hueco_max_min": (max(gaps) / 60) if gaps else 0,
                "ritmo_igual": da == db,
            })

            # unidad de proceso y fan-out 1:1
            for i, (el, ew) in enumerate(zip(ea, eb)):
                cmd = ew["Command"]
                etq = f"{etiqueta} #{i}"
                if re.search(r"(?:^|&)\s*cmd /c\b", cmd, re.I):
                    fallos.append(f"{etq}: `cmd /c` de primer nivel (doble envoltorio)")
                if re.search(r"(?:^|& )\s*start\s", cmd, re.I):
                    fallos.append(f"{etq}: `start` (proceso desacoplado)")
                if "|" in cmd and "powershell" not in cmd:
                    fallos.append(f"{etq}: `|` fuera de PowerShell")
                if cmd.count('"') % 2:
                    fallos.append(f"{etq}: comillas descompensadas")
                h = hijos(cmd)
                if h > MAX_HIJOS:
                    fallos.append(f"{etq}: {h} hijos (> {MAX_HIJOS})")
                # Regla 1 — el `xargs` de Linux se replica con un bucle de 12 procesos.
                if _es_fanout_linux(el["Command"]):
                    if not re.search(r"(?:^|& )\s*for /[Lf] ", cmd):
                        fallos.append(f"{etq}: el `xargs` de Linux no tiene bucle en Windows")
                    elif h != FANOUT_ESPERADO:
                        fallos.append(f"{etq}: el bucle lanza {h} procesos y el `xargs` de "
                                      f"Linux abre {FANOUT_ESPERADO}")
                    continue
                # Regla 2 — el resto no puede abrir más procesos que su pareja Linux (+1 de
                # tolerancia declarada: `sha256sum f1 f2` es 1 proceso y en Windows son 2).
                h_lx = hijos_linux(el["Command"])
                if h > h_lx + 1:
                    fallos.append(f"{etq}: Windows abre {h} procesos y Linux {h_lx} (+1 de "
                                  f"tolerancia)")

    resumen = {"tabla": tabla, "fallos": fallos, "avisos": avisos}
    if verbose:
        for f in fallos:
            print("FALLO:", f)
        for a in avisos:
            print("aviso:", a)
    return resumen


def imprimir_tabla(tabla):
    print(f"{'día':>3} {'bloque':>6} {'UTC':>11} {'acc.L':>6} {'acc.W':>6} {'huecos':>6} "
          f"{'mín':>5} {'máx':>6}  ritmo")
    for r in tabla:
        print(f"{r['dia']:>3} {r['bloque']:>6} {r['utc']:>11} {r['n_linux']:>6} "
              f"{r['n_win']:>6} {r['huecos']:>6} {r['hueco_min_s']:>4.0f}s "
              f"{r['hueco_max_min']:>5.1f}m  {'=' if r['ritmo_igual'] else 'DISTINTO'}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Espejo Linux ↔ Windows de la receta legítima")
    ap.add_argument("--linux", default=os.path.join(RAIZ, DIR_LINUX))
    ap.add_argument("--windows", default=os.path.join(RAIZ, DIR_WIN))
    ap.add_argument("--silencio", action="store_true")
    args = ap.parse_args(argv)

    res = comparar(args.linux, args.windows, verbose=not args.silencio)
    if not args.silencio:
        imprimir_tabla(res["tabla"])
    total_l = sum(r["n_linux"] for r in res["tabla"])
    total_w = sum(r["n_win"] for r in res["tabla"])
    if res["fallos"]:
        print(f"FALLA — {len(res['fallos'])} diferencia(s) de espejo")
        return 1
    print(f"PASA — espejo exacto: {total_l} acciones Linux = {total_w} acciones Windows "
          f"({len(res['tabla'])} bloques, mismos conteos, mismas ventanas y mismos "
          f"`DelayAfter`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
