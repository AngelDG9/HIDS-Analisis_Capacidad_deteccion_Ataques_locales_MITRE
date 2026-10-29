#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cobertura_herramientas_windows.py — cobertura de los binarios del corpus por la receta Windows.

Mismo **criterio** que `cobertura_exes.py` (CA-04 del bloque Linux):

- **Denominador** = los `basenames` distintos de las detecciones `Audit: Command: <ruta>` del
  corpus de ataques de **Linux** (`Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*-Audited.csv`).
  Se lee **en frío**: no se reejecuta nada ni se escribe en `Dataset/`. Se reutiliza la
  función del script de Linux para que los dos contadores no discrepen.
- **Numerador** = herramientas de la receta Windows (`Soporte/Laboratorio/windows/recetas/w{1,2,3}.json`)
  cuyo `basename` (sin `.exe`, sin ruta) está en el corpus.
- **Campaña (`B6`) aparte** (`--campana`): se cuentan los binarios de los handlers `B6`
  de las mismas recetas; si no se pide, no se suman (igual que `cobertura_exes.py`).

> **Alcance declarado (corregido 2026-10-29).** El plan `windows-legit-prep` §7 (W2)
> describía este script como «análogo de `cobertura_exes.py`, pero contra el ruleset y el
> inventario». La orden de W2 (B-1) fija el criterio operativo: **contra el corpus Linux**,
> con el mismo **procedimiento** de conteo. Pero el número **no es comparable**: mide
> **solape de `basename`** con el corpus **Linux**; **no** es cobertura equivalente ni
> comparable con el 23/50 de Linux (el corpus es Linux-específico). Además, `find` de
> Windows es un filtro de texto y **no** el `find` GNU ⇒ estrictamente comparables:
> **2/50** (`curl`, `tar`). La lectura «contra ruleset + inventario» no se hace aquí
> (requiere mapear cada binario a reglas candidatas, que es análisis de `B1`/`L2`); queda
> declarada en el plan como pendiente, no simulada.

No hay umbral pre-registrado para Windows (CA-04 es de Linux): `--min` es opcional y, si
no se pasa, el resultado es `RESULT=INFO`.

Uso:
    python _artefactos/scripts/cobertura_herramientas_windows.py
    python _artefactos/scripts/cobertura_herramientas_windows.py --campana
    python _artefactos/scripts/cobertura_herramientas_windows.py --min 22
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campana_windows as cw  # noqa: E402
import cobertura_exes as ce  # noqa: E402  (mismo criterio de corpus)

#: Builtins de `cmd` / palabras de control: no son herramientas.
BUILTINS = {
    "cd", "chdir", "md", "mkdir", "rd", "rmdir", "del", "erase", "copy", "move", "ren",
    "rename", "dir", "type", "echo", "set", "if", "for", "call", "start", "exit",
    "setlocal", "endlocal", "cls", "pushd", "popd", "title", "color", "ver", "vol",
    "time", "date", "pause", "shift", "goto", "choice", "rem",
}
#: El propio shell no es una «herramienta» del inventario.
SHELLS = {"cmd"}

#: Coincidencia **solo nominal** de `basename`: el binario de Windows no es la misma
#: herramienta que el del corpus Linux. `find` de Windows es un filtro de texto
#: (`find "x" fichero`), no el `find` GNU ⇒ no cuenta como comparación estricta.
NOMINALES = {"find"}

#: Redirecciones (`>nul`, `2>nul`, `>> fichero`, `2>&1`) fuera del token de comando.
RE_REDIR = re.compile(r"\d?>>?\s*(?:nul|[^\s&|)]+)", re.I)
#: Prefijo `if [not] errorlevel N` / `if [not] exist X` / `if A==B`.
RE_IF = re.compile(r"^if\s+(?:not\s+)?(?:errorlevel\s+\d+|\S+\s*==\s*\S+|exist\s+\S+)\s*",
                   re.I)
#: `for /L %i in (…) do <cuerpo>` (y `/f`, `/d`, `/r`).
RE_FOR = re.compile(r"^for\s+/[a-z]\s+%{1,2}[A-Za-z]\s+in\s*\(.*?\)\s*do\s+(.*)$", re.I | re.S)


def _segmentos(cmd: str):
    """Segmentos de primer nivel (`&`, `&&`, `||`, `|`) sin romper comillas ni `2>&1`."""
    out, buf, q, i = [], [], False, 0
    while i < len(cmd):
        c = cmd[i]
        if c == '"':
            q = not q
        if not q:
            if cmd.startswith("&&", i) or cmd.startswith("||", i):
                out.append("".join(buf))
                buf, i = [], i + 2
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


def _paren(seg: str):
    """(contenido del primer grupo, resto) respetando comillas."""
    nivel, q = 0, False
    for i, c in enumerate(seg):
        if c == '"':
            q = not q
            continue
        if q:
            continue
        if c == "(":
            nivel += 1
        elif c == ")":
            nivel -= 1
            if nivel == 0:
                return seg[1:i], seg[i + 1:]
    return seg[1:], ""


def _tokens(cmd: str):
    """Herramientas (basenames) que ejecuta un comando de `cmd`."""
    out = set()
    for seg in _segmentos(cmd):
        out |= _tokens_seg(seg)
    return out


def _tokens_seg(seg: str):
    seg = RE_REDIR.sub(" ", seg).strip().lstrip("@").strip()
    if not seg:
        return set()
    if seg.startswith("("):
        dentro, resto = _paren(seg)
        out = _tokens(dentro)
        resto = resto.strip()
        if resto.lower().startswith("else"):
            out |= _tokens(resto[4:].strip())
        elif resto:
            out |= _tokens(resto)
        return out
    m = RE_FOR.match(seg)
    if m:
        return _tokens(m.group(1))
    m = re.match(r"^@?cmd(?:\.exe)?\s+/[ck]\s+(.*)$", seg, re.I | re.S)
    if m:
        return _tokens(m.group(1))
    limpio = RE_IF.sub("", seg).strip()
    if limpio != seg:
        return _tokens(limpio) if limpio else set()
    tok = seg.split()[0].strip('"').strip("'").lstrip("@")
    if not tok or tok.startswith("%") or "=" in tok:
        return set()
    base = tok.replace("/", "\\").split("\\")[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if not base or base in BUILTINS or base in SHELLS:
        return set()
    return {base}


def binarios_de(cmd: str):
    return sorted(_tokens(cmd))


def _handlers(recetas: str):
    for day in (1, 2, 3):
        path = os.path.join(recetas, f"w{day}.json")
        if not os.path.isfile(path):
            raise SystemExit(f"ERROR: falta {path}")
        with open(path, encoding="utf-8") as fh:
            tl = json.load(fh)
        yield day, tl.get("TimeLineHandlers", [])


def _es_b6(h) -> bool:
    """Handler de la campaña: mismo cierre que `B6` y arranque dentro del bloque."""
    return (h.get("UtcTimeOff") == cw.B6["off"]
            and str(h.get("UtcTimeOn", "")) >= cw.B6["on"])


def binarios_receta(recetas: str):
    """Herramientas de la JORNADA (sin `B6`), como `cobertura_exes.binarios_receta`."""
    out = set()
    for _day, handlers in _handlers(recetas):
        for h in handlers:
            if _es_b6(h):
                continue
            for ev in h.get("TimeLineEvents", []):
                out.update(_tokens(ev.get("Command", "")))
    return out


def binarios_campana(recetas: str):
    """Herramientas de los handlers `B6` (campaña)."""
    out = set()
    for _day, handlers in _handlers(recetas):
        for h in handlers:
            if not _es_b6(h):
                continue
            for ev in h.get("TimeLineEvents", []):
                out.update(_tokens(ev.get("Command", "")))
    return out


def _norm(nombre: str) -> str:
    base = nombre.replace("/", "\\").split("\\")[-1].strip().lower()
    return base[:-4] if base.endswith(".exe") else base


def cobertura(recetas: str, raiz: str = None, campana: bool = False):
    """Devuelve el informe de cobertura (sin imprimir)."""
    raiz = raiz or os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    corpus, n_rutas, n_filas = ce.basenames_corpus(raiz)
    corpus_norm = {_norm(b): b for b in corpus}
    total = len(corpus)

    rec = binarios_receta(recetas)
    cub = sorted(b for b in rec if b in corpus_norm)
    extra = sorted(b for b in rec if b not in corpus_norm)
    faltan = sorted(v for k, v in corpus_norm.items() if k not in rec)

    inf = {
        "corpus": total, "rutas": n_rutas, "filas": n_filas,
        "receta": len(rec), "cubiertos": cub, "extra": extra, "faltan": faltan,
        "cobertura": len(cub), "pct": (100.0 * len(cub) / total) if total else 0.0,
    }
    if campana:
        camp = binarios_campana(recetas)
        nuevas = sorted(b for b in camp if b in corpus_norm and b not in rec)
        conjunto = set(cub) | {b for b in camp if b in corpus_norm}
        inf.update({
            "campana": len(camp), "campana_nuevas": nuevas,
            "conjunto": len(conjunto),
            "pct_conjunto": (100.0 * len(conjunto) / total) if total else 0.0,
        })
    return inf


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Cobertura de los binarios del corpus Linux por la receta Windows.")
    ap.add_argument("--raiz", default=None, help="raíz del repo (por defecto, tres niveles arriba)")
    ap.add_argument("--recetas", default=None, help="carpeta de las recetas Windows")
    ap.add_argument("--campana", action="store_true", help="suma el bloque B6 (campaña)")
    ap.add_argument("--min", type=int, default=None, help="umbral opcional (no hay CA de Windows)")
    args = ap.parse_args(argv)

    raiz = args.raiz or os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    recetas = args.recetas or cw.dir_recetas(raiz)

    inf = cobertura(recetas, raiz, args.campana)
    print(f"corpus Linux: {inf['corpus']} basenames distintos "
          f"({inf['rutas']} rutas; {inf['filas']} filas de detección)")
    print(f"receta Windows ({os.path.basename(recetas)}/w1-w3.json, sin B6): "
          f"{inf['receta']} herramientas")
    print(f"  cubiertos ({len(inf['cubiertos'])}): " + " ".join(inf["cubiertos"]))
    print(f"  fuera del corpus ({len(inf['extra'])}): " + " ".join(inf["extra"]))
    print(f"  faltan ({len(inf['faltan'])}): " + " ".join(inf["faltan"]))
    print(f"cobertura_herramientas_windows = {inf['cobertura']}/{inf['corpus']} = "
          f"{inf['pct']:.1f} %")
    nominales = [b for b in inf["cubiertos"] if b in NOMINALES]
    estrictos = [b for b in inf["cubiertos"] if b not in NOMINALES]
    nota = (f"NOTA: {inf['cobertura']}/{inf['corpus']} mide **solape de `basename`** con el "
            "corpus **Linux**; **no** es cobertura equivalente ni comparable con el 23/50 de "
            "Linux (el corpus es Linux-específico).")
    if nominales:
        nota += (f" Incluye `{'`, `'.join(nominales)}` como solape **nominal** (el `find` de "
                 "Windows es un filtro de texto y **no** el `find` GNU).")
    nota += (f" Estrictamente comparables: **{len(estrictos)}/{inf['corpus']}** "
             f"({', '.join(estrictos) if estrictos else '—'}).")
    print(nota)

    if args.campana:
        print(f"campaña B6: {inf['campana']} herramientas; aporta "
              f"{len(inf['campana_nuevas'])} nuevas: "
              + (" ".join(inf["campana_nuevas"]) if inf["campana_nuevas"] else "—"))
        print(f"conjunto (receta + campaña) = {inf['conjunto']}/{inf['corpus']} = "
              f"{inf['pct_conjunto']:.1f} %")

    if args.min is None:
        print("umbral = — (no hay CA de Windows; criterio heredado de CA-04)")
        print("RESULT=INFO")
        return 0
    ok = inf["cobertura"] >= args.min
    print(f"umbral = {args.min}/{inf['corpus']} -> " + ("OK" if ok else "NO CUMPLE"))
    print("RESULT=" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
