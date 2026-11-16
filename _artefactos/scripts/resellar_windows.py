#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""resellar_windows.py - regenera las entradas Windows de `sha256sums.txt` (sello global).

Uso (tras cambiar cualquier fichero sellado):

    python _artefactos/scripts/resellar_windows.py            # escribe el sello
    python _artefactos/scripts/resellar_windows.py --dry-run  # solo dice que cambiaria

Hace dos cosas, y nada mas:
  1. actualiza el `sha256` de las entradas que YA estan en el sello y son rutas Windows
     (`verificar_sellos_windows.es_ruta_windows`) cuyo fichero ha cambiado;
  2. anade las rutas criticas (`RUTAS_CRITICAS`) que aun no estan sellado.
No borra entradas, no toca las de Linux y escribe LF (con CRLF `sha256sum -c` falla).
Despues se comprueba con `python _artefactos/scripts/verificar_sellos_windows.py` y
`sha256sum -c Soporte/Laboratorio/legitimo_72h/sha256sums.txt`.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import verificar_sellos_windows as V  # noqa: E402


def resellar(sello: str = V.SELLO, raiz: str = V.RAIZ, escribir: bool = True):
    with open(sello, "rb") as fh:
        texto = fh.read().decode("utf-8")
    if "\r" in texto:
        raise SystemExit("el sello tiene CRLF: arreglarlo antes (sha256sum -c lo rechazaria)")
    lineas = texto.split("\n")
    presentes, actualizadas = set(), []
    for i, ln in enumerate(lineas):
        m = re.match(r"^([0-9a-f]{64})  (.+)$", ln)
        if not m:
            continue
        h, ruta = m.groups()
        presentes.add(ruta)
        f = os.path.join(raiz, ruta)
        if os.path.isfile(f) and V.es_ruta_windows(ruta):
            nuevo = V.sha256_file(f)
            if nuevo != h:
                lineas[i] = f"{nuevo}  {ruta}"
                actualizadas.append(ruta)
    if lineas and lineas[-1] == "":
        lineas = lineas[:-1]
    nuevas = [r for r in V.RUTAS_CRITICAS if r not in presentes and os.path.isfile(os.path.join(raiz, r))]
    for r in nuevas:
        lineas.append(f"{V.sha256_file(os.path.join(raiz, r))}  {r}")
    if escribir and (actualizadas or nuevas):
        with open(sello, "wb") as fh:
            fh.write(("\n".join(lineas) + "\n").encode("utf-8"))
    return actualizadas, nuevas


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Regenera las entradas Windows del sello global.")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    act, nue = resellar(escribir=not a.dry_run)
    for r in act:
        print("ACTUALIZADA", r)
    for r in nue:
        print("NUEVA      ", r)
    print(f"{'(dry-run) ' if a.dry_run else ''}actualizadas={len(act)} nuevas={len(nue)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
