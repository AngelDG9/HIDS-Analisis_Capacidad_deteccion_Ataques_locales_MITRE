#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cobertura_atomic.py — Mapa de cobertura del corpus vs Atomic Red Team.

Cruza las técnicas del corpus (`Hojas/ATA_index.csv`) con los índices CSV del
clon de Atomic Red Team (ART)
(`Soporte/Ataques/atomic-red-team/atomics/Indexes/Indexes-CSV/`) y produce el
mapa de cobertura `Hojas/cobertura_atomic.csv`.

Pertenece al bloque `fase-03-atomic` (A2.3, R-12/R-13) del TFG. **Solo stdlib**
y **determinista** (no lee el reloj: la salida no contiene fecha). **Offline**:
no necesita red (el clon ya está descargado en el host).

Decisiones de cálculo (documentadas aquí porque son la especificación del CSV):

1. Se consideran los **tres índices** que pide el plan:
   `index.csv` (todas las plataformas), `linux-index.csv` y `windows-index.csv`.
   Formato real observado del clon (master `388942a`):
   `Tactic,Technique #,Technique Name,Test #,Test Name,Test GUID,Executor Name`.
2. Una fila del índice pertenece a la técnica `T` si su `Technique #` es
   **exactamente** `T` **o** una **subtecnica** suya (`T.<n>`). Es decir, los
   recuentos **incluyen las subtecnicas**. Esto reproduce el borrador del plan
   (§4): p. ej. T1048 -> 9 Linux / 7 Windows solo con `.002`/`.003`.
3. `tests_linux` / `tests_windows` = **nº de filas** de `linux-index.csv` /
   `windows-index.csv` que pertenecen a la técnica (subtecnicas incluidas).
4. `prueba_art` = `sí` si la técnica (subtecnicas incluidas) tiene >=1 fila en
   **cualquiera** de los tres índices; si no, `no`.
5. `path` = directorios existentes bajo `atomics/` cuyo nombre es `T` o empieza
   por `T.` (subtecnicas), ordenados y unidos por `;`
   (p. ej. `atomics/T1048;atomics/T1048.002;atomics/T1048.003`). Vacío si no hay.
6. `nota` (veredicto de cobertura para **Linux**, que es la víctima por defecto):
   - `sin_pruebas`     : `prueba_art=no` (ninguna prueba en ART).
   - `cubierta`        : hay pruebas en Linux y en Windows.
   - `solo_linux`      : pruebas solo en Linux.
   - `solo_windows`    : pruebas solo en Windows (en Linux -> script custom).
   - `otras_plataformas`: hay pruebas, pero ninguna en Linux ni Windows.
7. El CSV se ordena de forma **estable por `ata_id`**.
8. Si falta el clon o cualquiera de los tres índices -> **exit != 0** con
   mensaje claro en `stderr`.

Uso:
    python _artefactos/scripts/cobertura_atomic.py
    python _artefactos/scripts/cobertura_atomic.py --art <raiz-art> \\
        --corpus <ATA_index.csv> --out <cobertura_atomic.csv>
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Rutas por defecto (relativas a la raíz del repo).
# --------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO_ROOT / "Hojas" / "ATA_index.csv"
DEFAULT_ART = REPO_ROOT / "Soporte" / "Ataques" / "atomic-red-team"
DEFAULT_OUT = REPO_ROOT / "Hojas" / "cobertura_atomic.csv"

# Nombres de los índices del clon (plan §3.2).
INDEX_FILES = ("index.csv", "linux-index.csv", "windows-index.csv")

# Esquema exacto de salida (plan §3.2 / §8.1 CA3).
HEADER_COLUMNS = [
    "ata_id",
    "tecnica",
    "nombre",
    "prueba_art",
    "tests_linux",
    "tests_windows",
    "path",
    "nota",
]


# --------------------------------------------------------------------------
# Carga del corpus
# --------------------------------------------------------------------------
def load_corpus(path: str | Path) -> list[dict]:
    """Lee `ATA_index.csv` saltando las líneas de comentario (`# ...`)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No existe el corpus: {path}")
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    if not lines:
        raise ValueError(f"El corpus no tiene datos: {path}")
    reader = csv.DictReader(lines)
    rows = [r for r in reader if (r.get("tecnica") or "").strip()]
    return rows


# --------------------------------------------------------------------------
# Carga de los índices ART
# --------------------------------------------------------------------------
def index_dir(art_root: str | Path) -> Path:
    return Path(art_root) / "atomics" / "Indexes" / "Indexes-CSV"


def load_index(path: str | Path) -> list[dict]:
    """Lee un `*-index.csv` de ART y devuelve sus filas."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _belongs(technique_field: str, tecnica: str) -> bool:
    """True si `technique_field` es la técnica o una subtecnica suya."""
    return technique_field == tecnica or technique_field.startswith(tecnica + ".")


def _count(rows: list[dict], tecnica: str) -> int:
    return sum(1 for r in rows if _belongs((r.get("Technique #") or "").strip(), tecnica))


# --------------------------------------------------------------------------
# Directorios existentes de la técnica (path)
# --------------------------------------------------------------------------
def technique_dirs(atomics_dir: str | Path, tecnica: str) -> list[str]:
    """Directorios `atomics/<T>` y `atomics/<T>.<n>` existentes, ordenados."""
    atomics_dir = Path(atomics_dir)
    if not atomics_dir.is_dir():
        return []
    found = []
    for child in atomics_dir.iterdir():
        if not child.is_dir():
            continue
        name = child.name
        if name == tecnica or name.startswith(tecnica + "."):
            found.append(f"atomics/{name}")
    return sorted(found)


# --------------------------------------------------------------------------
# Cálculo del mapa
# --------------------------------------------------------------------------
def _ata_sort_key(ata_id: str):
    """Orden estable: numérico si es `ATA<n>`, si no, lexicográfico."""
    match = re.match(r"^ATA(\d+)$", ata_id or "")
    if match:
        return (0, int(match.group(1)), ata_id)
    return (1, 0, ata_id or "")


def _nota(prueba_art: str, linux: int, windows: int) -> str:
    if prueba_art == "no":
        return "sin_pruebas"
    if linux > 0 and windows > 0:
        return "cubierta"
    if linux > 0:
        return "solo_linux"
    if windows > 0:
        return "solo_windows"
    return "otras_plataformas"


def build_coverage(
    corpus_rows: list[dict],
    idx_all: list[dict],
    idx_linux: list[dict],
    idx_windows: list[dict],
    atomics_dir: str | Path,
) -> list[dict]:
    """Construye las filas del mapa de cobertura (orden estable por ata_id)."""
    out: list[dict] = []
    for row in corpus_rows:
        tecnica = (row.get("tecnica") or "").strip()
        nombre = (row.get("descripcion") or "").strip()
        linux = _count(idx_linux, tecnica)
        windows = _count(idx_windows, tecnica)
        present = (
            any(_belongs((r.get("Technique #") or "").strip(), tecnica) for r in idx_all)
            or linux > 0
            or windows > 0
        )
        prueba_art = "sí" if present else "no"
        path = ";".join(technique_dirs(atomics_dir, tecnica))
        out.append(
            {
                "ata_id": (row.get("ata_id") or "").strip(),
                "tecnica": tecnica,
                "nombre": nombre,
                "prueba_art": prueba_art,
                "tests_linux": linux,
                "tests_windows": windows,
                "path": path,
                "nota": _nota(prueba_art, linux, windows),
            }
        )
    out.sort(key=lambda r: _ata_sort_key(r["ata_id"]))
    return out


# --------------------------------------------------------------------------
# Salida
# --------------------------------------------------------------------------
def write_coverage(rows: list[dict], out_path: str | Path) -> Path:
    """Escribe el CSV determinista (sin fecha: solo cabecera + filas)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADER_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return out_path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _require_inputs(corpus: Path, art_root: Path) -> dict[str, Path]:
    """Valida clon + índices. Lanza `FileNotFoundError` con mensaje claro."""
    idx = index_dir(art_root)
    if not (Path(art_root) / "atomics").is_dir():
        raise FileNotFoundError(
            f"No se encuentra el clon de Atomic Red Team en {art_root} "
            f"(falta el directorio 'atomics/')."
        )
    paths = {}
    for name in INDEX_FILES:
        p = idx / name
        if not p.is_file():
            raise FileNotFoundError(f"Falta el índice de ART: {p}")
        paths[name] = p
    if not corpus.is_file():
        raise FileNotFoundError(f"No existe el corpus: {corpus}")
    return paths


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Genera el mapa de cobertura del corpus vs Atomic Red Team."
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="ATA_index.csv.")
    parser.add_argument("--art", default=str(DEFAULT_ART), help="Raíz del clon de ART.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="CSV de salida.")
    args = parser.parse_args(argv)

    corpus = Path(args.corpus)
    art_root = Path(args.art)

    try:
        paths = _require_inputs(corpus, art_root)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    try:
        corpus_rows = load_corpus(corpus)
        idx_all = load_index(paths["index.csv"])
        idx_linux = load_index(paths["linux-index.csv"])
        idx_windows = load_index(paths["windows-index.csv"])
    except (FileNotFoundError, ValueError, csv.Error) as exc:
        print(f"[ERROR] No se pudo leer la entrada: {exc}", file=sys.stderr)
        return 2

    rows = build_coverage(
        corpus_rows, idx_all, idx_linux, idx_windows, Path(art_root) / "atomics"
    )
    out = write_coverage(rows, args.out)

    n_si = sum(1 for r in rows if r["prueba_art"] == "sí")
    n_linux = sum(1 for r in rows if r["nota"] == "cubierta")
    print(f"[OK] {out} ({len(rows)} técnicas)")
    print(f"[INFO] prueba_art=sí: {n_si}/{len(rows)} | cubierta en Linux: {n_linux}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
