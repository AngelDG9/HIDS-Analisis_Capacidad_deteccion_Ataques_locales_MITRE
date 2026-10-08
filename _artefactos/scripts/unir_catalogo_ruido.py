#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unir_catalogo_ruido.py — Une los catálogos de ruido por ventana (v1+v2).

Bloque `fase-02b-baseline` (§2.3). Helper **offline, mínimo y determinista**:
fusiona los dos catálogos **por ventana** del baseline en el **esquema
agregado idéntico al de Linux** (`Dataset/Legitimo/ruleids_legitimos.csv`).

NO modifica `extraer_alertas.py` ni `filtrar_ruido.py` (integridad de huellas):
solo *lee* los catálogos por ventana y *escribe* la unión.

Entrada (catálogo por ventana, `CSV_HEADER` del extractor congelado):

    rule_id,rule_level,rule_description,groups,count,first_seen,last_seen,rs_origen

Salida (esquema de unión, idéntico al del catálogo Linux):

    rule_id,rule_level,rule_description,groups,rs_origen,count_v1,count_v2,count_total,ventanas

Convenciones (paridad con `Dataset/Legitimo/ruleids_legitimos.csv`):

  - `ventanas` ∈ {`v1`, `v2`, `v1+v2`}.
  - `count_total = count_v1 + count_v2`. Si un `rule_id` **no** aparece en una
    ventana, su `count` es **0** y `ventanas` refleja solo la(s) que lo tienen
    (**no se inventa** ningún campo ni cuenta).
  - Metadatos (`rule_level`, `rule_description`, `groups`, `rs_origen`) se
    toman de la **v1** (primer evento); de la **v2** si el `rule_id` solo está
    ahí. Igual que la nota del catálogo Linux
    (`rule_description = primer evento de la v1`).
  - Orden **estable** por `rule_id` (numérico ascendente).
  - Salida **UTF-8 sin BOM** y fin de línea **LF**: misma entrada → mismos
    bytes (determinista, R-13).
  - Primera línea `#` de metadatos (mismo estilo que el catálogo Linux).
  - Los ficheros de entrada **no** se modifican.

Uso (por defecto, la convención por SO `Dataset/Legitimo/windows/`):

    python3 _artefactos/scripts/unir_catalogo_ruido.py

    python3 _artefactos/scripts/unir_catalogo_ruido.py \
        --v1 Dataset/Legitimo/windows/ruleids_legitimos_v1.csv \
        --v2 Dataset/Legitimo/windows/ruleids_legitimos_v2.csv \
        --out Dataset/Legitimo/windows/ruleids_legitimos.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Rutas por defecto (subárbol Windows; no se toca el baseline Linux)
# --------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = REPO_ROOT / "Dataset" / "Legitimo" / "windows"
DEFAULT_V1 = DEFAULT_DIR / "ruleids_legitimos_v1.csv"
DEFAULT_V2 = DEFAULT_DIR / "ruleids_legitimos_v2.csv"
DEFAULT_OUT = DEFAULT_DIR / "ruleids_legitimos.csv"

# Esquema del extractor congelado (por ventana).
IN_HEADER = [
    "rule_id",
    "rule_level",
    "rule_description",
    "groups",
    "count",
    "first_seen",
    "last_seen",
    "rs_origen",
]

# Esquema de unión (idéntico al catálogo Linux).
OUT_HEADER = [
    "rule_id",
    "rule_level",
    "rule_description",
    "groups",
    "rs_origen",
    "count_v1",
    "count_v2",
    "count_total",
    "ventanas",
]


# --------------------------------------------------------------------------
# Orden estable (el mismo criterio que el extractor: entero, luego texto)
# --------------------------------------------------------------------------
def _sort_key(rule_id: str) -> Tuple[int, str]:
    return (int(rule_id) if rule_id.isdigit() else 10 ** 12, rule_id)


# --------------------------------------------------------------------------
# Lectura de un catálogo por ventana
# --------------------------------------------------------------------------
def load_catalogo(path: Path, etiqueta: str) -> Dict[str, dict]:
    """Carga un catálogo por ventana. Salta líneas `#`. Devuelve `{rule_id: fila}`.

    Falla (ValueError) si el encabezado no es el del extractor congelado, si
    hay `rule_id` duplicado o si algún `count` no es un entero no negativo.
    """
    if not path.is_file():
        raise FileNotFoundError(f"no existe el catálogo {etiqueta}: {path}")

    # `utf-8-sig` tolera un BOM accidental en la entrada; la salida nunca lleva BOM.
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        lineas = [ln for ln in fh if not ln.lstrip().startswith("#")]
    if not lineas:
        raise ValueError(f"{etiqueta}: fichero sin cabecera: {path}")

    reader = csv.DictReader(lineas)
    if reader.fieldnames != IN_HEADER:
        raise ValueError(
            f"{etiqueta}: encabezado inesperado\n"
            f"  esperado: {','.join(IN_HEADER)}\n"
            f"  leído:    {','.join(reader.fieldnames or [])}"
        )

    catalogo: Dict[str, dict] = {}
    for fila in reader:
        rule_id = (fila.get("rule_id") or "").strip()
        if not rule_id:
            raise ValueError(f"{etiqueta}: fila sin `rule_id`: {fila}")
        if rule_id in catalogo:
            raise ValueError(
                f"{etiqueta}: `rule_id` duplicado ({rule_id}); el extractor "
                f"agrega por regla, la entrada no debería repetirlo"
            )
        try:
            count = int((fila.get("count") or "").strip())
        except ValueError:
            raise ValueError(f"{etiqueta}: `count` no entero en rule_id={rule_id}")
        if count < 0:
            raise ValueError(f"{etiqueta}: `count` negativo en rule_id={rule_id}")
        catalogo[rule_id] = {
            "rule_id": rule_id,
            "rule_level": fila.get("rule_level", ""),
            "rule_description": fila.get("rule_description", ""),
            "groups": fila.get("groups", ""),
            "count": count,
            "first_seen": (fila.get("first_seen") or "").strip(),
            "last_seen": (fila.get("last_seen") or "").strip(),
            "rs_origen": fila.get("rs_origen", ""),
        }
    return catalogo


# --------------------------------------------------------------------------
# Unión
# --------------------------------------------------------------------------
def unir(v1: Dict[str, dict], v2: Dict[str, dict]) -> List[List[str]]:
    """Fusiona v1 y v2 en filas del esquema de unión, ordenadas por `rule_id`."""
    filas: List[List[str]] = []
    for rule_id in sorted(set(v1) | set(v2), key=_sort_key):
        a = v1.get(rule_id)
        b = v2.get(rule_id)
        origen = a if a is not None else b  # metadatos: preferir v1
        c1 = a["count"] if a is not None else 0
        c2 = b["count"] if b is not None else 0
        if a is not None and b is not None:
            ventanas = "v1+v2"
        elif a is not None:
            ventanas = "v1"
        else:
            ventanas = "v2"
        filas.append(
            [
                rule_id,
                origen["rule_level"],
                origen["rule_description"],
                origen["groups"],
                origen["rs_origen"],
                str(c1),
                str(c2),
                str(c1 + c2),
                ventanas,
            ]
        )
    return filas


# --------------------------------------------------------------------------
# Línea `#` de metadatos (estilo del catálogo Linux)
# --------------------------------------------------------------------------
def _ventana_desc(catalogo: Dict[str, dict]) -> str:
    """`<min first_seen>-<max last_seen> (N alertas)`, o `(N alertas)` si no hay marcas."""
    n = sum(f["count"] for f in catalogo.values())
    firsts = [f["first_seen"] for f in catalogo.values() if f["first_seen"]]
    lasts = [f["last_seen"] for f in catalogo.values() if f["last_seen"]]
    if firsts and lasts:
        # Formato ISO8601 fijo -> min/max lexicográfico == cronológico.
        return f"{min(firsts)}-{max(lasts)} ({n} alertas)"
    return f"({n} alertas)"


def comentario_cabecera(out_name: str, v1: Dict[str, dict], v2: Dict[str, dict]) -> str:
    lasts = [f["last_seen"] for cat in (v1, v2) for f in cat.values() if f["last_seen"]]
    partes = [
        f"# {out_name}",
        "CATALOGO AGREGADO de ruido legitimo (union ventana1+ventana2)",
        "TFG HIDS - Fase 2b Windows (R-08)",
    ]
    if lasts:
        # Derivado de los datos (no del reloj): mantiene el determinismo.
        partes.append(f"generado={max(lasts)[:10]}")
    partes.append(f"v1: {_ventana_desc(v1)}")
    partes.append(f"v2: {_ventana_desc(v2)}")
    partes.append(
        "columnas: count_v1,count_v2,count_total y ventanas (v1 | v2 | v1+v2)"
    )
    partes.append(
        "rule_description = primer evento de la v1 (las reglas genericas varian por evento)"
    )
    return " | ".join(partes)


# --------------------------------------------------------------------------
# Escritura (UTF-8 sin BOM, LF)
# --------------------------------------------------------------------------
def escribir(out_path: Path, comentario: str, filas: Sequence[Sequence[str]]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(comentario + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(OUT_HEADER)
        writer.writerows(filas)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Une los catálogos de ruido por ventana (v1+v2) en el esquema "
            "agregado idéntico al de Linux."
        )
    )
    ap.add_argument("--v1", default=str(DEFAULT_V1), help="catálogo de la ventana 1")
    ap.add_argument("--v2", default=str(DEFAULT_V2), help="catálogo de la ventana 2")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="CSV de unión de salida")
    args = ap.parse_args(argv)

    try:
        v1 = load_catalogo(Path(args.v1), "v1")
        v2 = load_catalogo(Path(args.v2), "v2")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    filas = unir(v1, v2)

    ambas = sum(1 for f in filas if f[8] == "v1+v2")
    solo_v1 = sum(1 for f in filas if f[8] == "v1")
    solo_v2 = sum(1 for f in filas if f[8] == "v2")
    n_v1 = sum(f["count"] for f in v1.values())
    n_v2 = sum(f["count"] for f in v2.values())

    out_path = Path(args.out)
    comentario = comentario_cabecera(out_path.name, v1, v2)
    escribir(out_path, comentario, filas)

    print(
        f"union: rule_ids={len(filas)} (ambas={ambas}, solo_v1={solo_v1}, "
        f"solo_v2={solo_v2}) alertas_v1={n_v1} alertas_v2={n_v2} -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
