#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Promociona a `Dataset/` los productos de una ventana legitima VALIDA.

Copia (no mueve) los productos desde `Soporte/Laboratorio/legitimo_72h/ventana_<t0>/`
(y `…/campana/` para `campana_ventanas.tsv`) a `Dataset/Legitimo/legitimo_72h/` y
**antepone una linea `#` de procedencia** a cada CSV
con `metrica_version`, `boveda_version`, `t0`/`t1` y el `sha256` del fichero de origen.
El producto de `Soporte/` **no se modifica**.

Uso:
    python _artefactos/scripts/promover_ventana_legitimo.py --check
    python _artefactos/scripts/promover_ventana_legitimo.py --apply

`--check` solo verifica que los origenes existen y muestra sus huellas.
`--apply` escribe las copias + `PROMOCION.md` y **verifica** que la copia, quitando la
linea de cabecera anadida, es **byte a byte identica** al origen.

No borra nada y no toca los origenes. Sin secretos.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VENTANA = REPO / "Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02"
DESTINO = REPO / "Dataset/Legitimo/legitimo_72h"
T0 = "2026-11-02T00:00:00Z"
T1 = "2026-11-05T00:00:00Z"
METRICA_VERSION = 1
BOVEDA_VERSION = 2

# (nombre, es_csv)  -> todos se promocionan; los CSV llevan cabecera de procedencia
FICHEROS = [
    ("alertas_detalle.csv", True),
    ("ruleids_legitimos.csv", True),
    ("denominador_M.csv", True),
    ("ghosts_acciones.csv", True),
    ("campana_fp.csv", True),
    ("ventana_meta.md", False),
]
# campana_ventanas.tsv vive en campana/ (plan 15.1); se promociona tambien.
CAMPANA_VENTANAS = REPO / "Soporte/Laboratorio/legitimo_72h/campana/campana_ventanas.tsv"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def cabecera(sha_origen: str, origen: Path) -> bytes:
    # Cada fichero declara SU ruta real (no todas viven en ventana_<t0>/).
    origen_rel = origen.relative_to(REPO).as_posix()
    linea = (
        f"# promocion | metrica_version={METRICA_VERSION} boveda_version={BOVEDA_VERSION} "
        f"| t0={T0} t1={T1} | sha256_origen={sha_origen} "
        f"| origen={origen_rel} "
        f"| ventana=legitimo-v3 | estado=VALIDA_CON_INCIDENCIA\n"
    )
    return linea.encode("utf-8")


def inventario() -> list[tuple[str, Path, bool]]:
    items = [(n, VENTANA / n, csv_) for n, csv_ in FICHEROS]
    items.append(("campana_ventanas.tsv", CAMPANA_VENTANAS, True))
    return items


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="solo verificar origenes (defecto)")
    g.add_argument("--apply", action="store_true", help="escribir copias + PROMOCION.md")
    a = ap.parse_args(argv)
    if not a.apply:
        a.check = True

    faltan = [str(p) for _, p, _ in inventario() if not p.exists()]
    if faltan:
        print("FALTAN origenes:")
        for f in faltan:
            print("  " + f)
        return 2

    print("origenes:")
    for nombre, p, _ in inventario():
        print(f"  {sha256_file(p)}  {p.relative_to(REPO).as_posix()}  ({p.stat().st_size} B)")
    if a.check and not a.apply:
        print("\n--check: solo lectura (nada escrito).")
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    filas = []
    for nombre, origen, es_csv in inventario():
        datos = origen.read_bytes()
        sha_origen = sha256_bytes(datos)
        salida = datos if not es_csv else cabecera(sha_origen, origen) + datos
        destino = DESTINO / nombre
        destino.write_bytes(salida)
        # verificacion: quitar la cabecera anadida debe devolver el origen exacto
        if es_csv:
            n = len(cabecera(sha_origen, origen))
            ok = destino.read_bytes()[n:] == datos
        else:
            ok = destino.read_bytes() == datos
        if not ok:
            print(f"FALLO de integridad en {nombre}")
            return 3
        filas.append((nombre, sha_origen, sha256_file(destino), destino.stat().st_size))

    lineas = [
        "# `PROMOCION.md` — promoción de la ventana `legitimo-v3` a `Dataset/`",
        "",
        f"> Ventana **{T0} .. {T1}** · veredicto **VÁLIDA CON INCIDENCIA** (V6) ·",
        f"> `metrica_version={METRICA_VERSION}`, `boveda_version={BOVEDA_VERSION}`.",
        "> Copia **desde** `Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/` y",
        "> `Soporte/Laboratorio/legitimo_72h/campana/` (los originales **no** se modifican).",
        "> A cada CSV se le antepone **una línea `#`** de procedencia con",
        "> `t0`/`t1` y el `sha256` del origen; la copia, sin esa línea, es **byte a byte idéntica**",
        "> al origen.",
        "",
        "| Fichero | `sha256` origen | `sha256` copia promovida | Bytes |",
        "|---|---|---|---|",
    ]
    for nombre, so, sc, b in filas:
        lineas.append(f"| `{nombre}` | `{so}` | `{sc}` | {b} |")
    lineas += [
        "",
        "## Ficha inválida anterior (L1, 19–22/10)",
        "",
        "La ficha **PREPARADA** de L1 que ocupaba `Dataset/Legitimo/legitimo_72h/ventana_meta.md`",
        "se **retiró** el 2026-11-05. Su contenido es idéntico (salvo fin de línea CRLF) a",
        "`Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/ventana_meta_INVALIDA_2026-10-19.md`",
        "(LF, `sha256 061d555bebc923369c7a4f48dca6db9be5122324b21c3284beafc1dfe3b2451a`).",
        "Huella de la copia retirada (CRLF): **`1fe77e48bb3e5c99f796e057bdcfaa81848ec23ba43883e64c6826698c9fbd07`**.",
        "",
        "## Trazabilidad",
        "",
        "- Productos y evidencia: `Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/`.",
        "- Campaña FP: `Soporte/Laboratorio/legitimo_72h/campana/` (`campana_ventanas.tsv`).",
        "- Veredicto literal: `…/veredicto_validez.md`. Ficha: `…/ventana_meta.md`.",
        "- Sellado: `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` (v3) +",
        "  `Soporte/Metrica/boveda_congelacion.md` (v2).",
        "",
    ]
    (DESTINO / "PROMOCION.md").write_text("\n".join(lineas), encoding="utf-8")

    print("\npromocionado:")
    for nombre, so, sc, b in filas:
        print(f"  {sc}  Dataset/Legitimo/legitimo_72h/{nombre}  ({b} B)")
    print(f"  -> {(DESTINO / 'PROMOCION.md').relative_to(REPO).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
