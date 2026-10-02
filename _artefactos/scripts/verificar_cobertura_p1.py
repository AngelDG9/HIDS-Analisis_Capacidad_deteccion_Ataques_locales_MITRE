#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_cobertura_p1.py — Comprobaciones AUTOMATICAS del cierre P1-Linux.

Bloque `fase-03-p1-cierre` (plan v3, §6.3). **Solo stdlib**, **offline**,
determinista (no lee el reloj ni la red).

Comprueba, sobre **las 72 filas P1-Linux** (`Hojas/cobertura_p1_linux.csv`):

- **C1 — Cuadre de la tabla.** El conjunto de `tecnica` del CSV coincide con la
  piscina P1-Linux derivada de `Hojas/corpus_host.csv`
  (`priority=P1` ∧ `host_eligible=YES` ∧ `plataformas∋Linux`); hay exactamente
  **72 filas** sin duplicados; la columna `estado`/`clasificacion` encaja en
  **exactamente 5 categorias** (`medida`, `cubierta_por_ata`, `cubierta_madre`,
  `cubierta_parcial`, `no_factible`) y el crosstab coincide con la tabla de
  totales del plan §7 (`48/6/8/2/8`); ninguna fila es incoherente.
- **C2 — Test padre/hijo.** Recorre la jerarquia de `corpus_host.csv` +
  `cobertura_p1_linux.csv` + `Hojas/ATA_index.csv` y **falla** si:
  (1) una madre `cubierta` tiene una hija del alcance que no es
  `medida`/`cubierta_por_ata`; (2) una hija se cubre por **otra hija** (hermana);
  (3) la cita apunta a un **descendiente** (madre usada para cubrir a sus hijas);
  (4) la cita **no resuelve** (el `ATA<NNN>` no existe o su tecnica no es la de
  la fila ni un ancestro suyo).

Uso:
    python _artefactos/scripts/verificar_cobertura_p1.py --todo
    python _artefactos/scripts/verificar_cobertura_p1.py --c1
    python _artefactos/scripts/verificar_cobertura_p1.py --c2

Exit `0` si todo pasa; `exit != 0` + mensaje claro en `stderr` al primer fallo.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COBERTURA = REPO_ROOT / "Hojas" / "cobertura_p1_linux.csv"
DEFAULT_CORPUS = REPO_ROOT / "Hojas" / "corpus_host.csv"
DEFAULT_ATA_INDEX = REPO_ROOT / "Hojas" / "ATA_index.csv"

# Las 5 categorias (cada fila en una sola). El orden es el del plan §7.
CATEGORIAS = ("medida", "cubierta_por_ata", "cubierta_madre", "cubierta_parcial", "no_factible")

# Tabla de totales del plan §7 (gate A+B+C, 4.º estado). Si el gate cambia algo,
# esta tabla y la de §7 se actualizan en el mismo commit.
TARGET_CATEGORIAS = {
    "medida": 48,
    "cubierta_por_ata": 6,
    "cubierta_madre": 8,
    "cubierta_parcial": 2,
    "no_factible": 8,
}
EXPECTED_TOTAL = 72

ATA_RE = re.compile(r"^ATA\d+$")


class ErrorCobertura(Exception):
    """Fallo de C1/C2 con mensaje apto para `stderr`."""


# ---------------------------------------------------------------------------
# E/S
# ---------------------------------------------------------------------------
def load_rows(path: str | Path, comment_prefix: str = "#") -> list[dict]:
    """Lee un CSV saltando lineas de comentario (`# ...`)."""
    path = Path(path)
    if not path.is_file():
        raise ErrorCobertura(f"no existe el fichero: {path}")
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith(comment_prefix)]
    if not lines:
        raise ErrorCobertura(f"el fichero no tiene datos: {path}")
    return [r for r in csv.DictReader(lines)]


# ---------------------------------------------------------------------------
# C1 — Cuadre
# ---------------------------------------------------------------------------
def p1_linux_pool(corpus_rows: list[dict]) -> list[str]:
    """Tecnicas de la piscina P1-Linux (orden estable del corpus)."""
    out = []
    for r in corpus_rows:
        plat = [p.strip() for p in (r.get("plataformas") or "").split(";")]
        if (
            (r.get("priority") or "").strip() == "P1"
            and (r.get("host_eligible") or "").strip() == "YES"
            and "Linux" in plat
        ):
            out.append((r.get("tecnica_id") or "").strip())
    return out


def categoria(row: dict) -> str:
    """Categoria (una de las 5) de una fila de cobertura."""
    estado = (row.get("estado") or "").strip()
    clas = (row.get("clasificacion") or "").strip()
    combinaciones = {
        ("medida", "medida"): "medida",
        ("cubierta", "cubierta_por_ata"): "cubierta_por_ata",
        ("cubierta", "cubierta_madre"): "cubierta_madre",
        ("cubierta_parcial", "cubierta_parcial"): "cubierta_parcial",
        ("no_factible", "no_factible"): "no_factible",
    }
    cat = combinaciones.get((estado, clas))
    if cat is None:
        raise ErrorCobertura(
            f"fila {row.get('tecnica')!r}: combinacion estado/clasificacion no valida "
            f"(estado={estado!r}, clasificacion={clas!r}); se esperaba una de {list(combinaciones)}"
        )
    return cat


def c1_check(
    cobertura_rows: list[dict],
    corpus_rows: list[dict],
    expected_total: int = EXPECTED_TOTAL,
    target: dict | None = None,
) -> dict:
    """C1: cuadre de la tabla. Devuelve el crosstab; lanza `ErrorCobertura` si falla."""
    target = TARGET_CATEGORIAS if target is None else target
    pool = p1_linux_pool(corpus_rows)
    pool_set = set(pool)

    # 1) sin duplicados
    tecnicas = [(r.get("tecnica") or "").strip() for r in cobertura_rows]
    dup = sorted({t for t in tecnicas if tecnicas.count(t) > 1})
    if dup:
        raise ErrorCobertura(f"C1: tecnicas duplicadas en el CSV: {dup}")

    # 2) conjunto exactamente igual a la piscina
    csv_set = set(tecnicas)
    faltan = sorted(pool_set - csv_set)
    sobran = sorted(csv_set - pool_set)
    if faltan or sobran:
        raise ErrorCobertura(
            f"C1: el conjunto de tecnicas del CSV no coincide con la piscina P1-Linux "
            f"(faltan={faltan}, sobran={sobran})"
        )

    # 3) total exacto
    if len(cobertura_rows) != expected_total:
        raise ErrorCobertura(
            f"C1: el CSV tiene {len(cobertura_rows)} filas; se esperaban {expected_total}"
        )

    # 4) coherencia fila a fila
    crosstab: Counter = Counter()
    for r in cobertura_rows:
        t = (r.get("tecnica") or "").strip()
        cat = categoria(r)
        crosstab[cat] += 1
        ata = (r.get("ata_o_cubierta_por") or "").strip()
        motivo = (r.get("motivo_codigo") or "").strip()
        detalle = (r.get("motivo_detalle") or "").strip()
        if cat in ("medida", "cubierta_por_ata") and not ATA_RE.match(ata):
            raise ErrorCobertura(
                f"C1: fila {t}: '{cat}' sin un ATA<NNN> valido en ata_o_cubierta_por "
                f"(valor={ata!r})"
            )
        if cat == "no_factible" and not motivo:
            raise ErrorCobertura(f"C1: fila {t}: 'no_factible' sin motivo_codigo")
        if cat == "cubierta_parcial" and not detalle:
            raise ErrorCobertura(f"C1: fila {t}: 'cubierta_parcial' sin motivo_detalle")

    # 5) crosstab contra la tabla de totales del plan
    real = {c: crosstab.get(c, 0) for c in CATEGORIAS}
    if real != target:
        raise ErrorCobertura(
            f"C1: crosstab por categoria no cuadra con el plan §7 "
            f"(real={real}, esperado={target})"
        )
    if sum(real.values()) != expected_total:
        raise ErrorCobertura(
            f"C1: la columna estado suma {sum(real.values())}; se esperaban {expected_total}"
        )
    return real


# ---------------------------------------------------------------------------
# C2 — padre/hijo
# ---------------------------------------------------------------------------
def parent_map(corpus_rows: list[dict]) -> dict:
    """tecnica -> padre_id (solo si es subtecnica con padre declarado)."""
    out = {}
    for r in corpus_rows:
        t = (r.get("tecnica_id") or "").strip()
        p = (r.get("padre_id") or "").strip()
        if t and p:
            out[t] = p
    return out


def ancestors(tecnica: str, parents: dict) -> set:
    """Conjunto de ancestros (padre, abuelo...) de `tecnica`."""
    out = set()
    seen = set()
    cur = parents.get(tecnica)
    while cur and cur not in seen:
        out.add(cur)
        seen.add(cur)
        cur = parents.get(cur)
    return out


def c2_check(cobertura_rows: list[dict], corpus_rows: list[dict], ata_index: dict) -> None:
    """C2: reglas padre/hijo. Lanza `ErrorCobertura` al primer fallo."""
    parents = parent_map(corpus_rows)
    by_tecnica = {(r.get("tecnica") or "").strip(): r for r in cobertura_rows}

    # (1) madre 'cubierta' con una hija del alcance no medida/cubierta por ATA
    for r in cobertura_rows:
        if (r.get("estado") or "").strip() != "cubierta":
            continue
        madre = (r.get("tecnica") or "").strip()
        hijas = [by_tecnica[c] for c, p in parents.items() if p == madre and c in by_tecnica]
        for h in hijas:
            cat_h = categoria(h)
            if cat_h not in ("medida", "cubierta_por_ata"):
                raise ErrorCobertura(
                    f"C2 (regla 1): la madre {madre} figura 'cubierta' pero la hija del "
                    f"alcance {h.get('tecnica')} tiene categoria {cat_h!r}; una madre solo se "
                    f"cubre si TODAS sus formas P1-Linux estan medida/cubierta por ATA"
                )

    # (2)(3)(4) citas
    for r in cobertura_rows:
        t = (r.get("tecnica") or "").strip()
        ata = (r.get("ata_o_cubierta_por") or "").strip()
        if not ata:
            continue
        if ata not in ata_index:
            raise ErrorCobertura(f"C2 (regla 4): la fila {t} cita {ata}, que no existe en ATA_index.csv")
        x = (ata_index[ata].get("tecnica") or "").strip()
        cat = categoria(r)
        if x == t:
            continue
        if cat == "medida":
            raise ErrorCobertura(
                f"C2: la fila {t} esta 'medida' pero cita {ata}, cuya tecnica es {x}; "
                f"una fila 'medida' debe citar su propia tecnica"
            )
        if x in ancestors(t, parents):
            # valido: el ATA esta etiquetado bajo la madre pero implementa la hija
            continue
        if t in ancestors(x, parents):
            raise ErrorCobertura(
                f"C2 (regla 3): la fila {t} cita {ata} cuya tecnica es un DESCENDIENTE "
                f"({x}); una madre no cubre a sus hijas"
            )
        if parents.get(x) and parents.get(x) == parents.get(t):
            raise ErrorCobertura(
                f"C2 (regla 2): la fila {t} se cubre por {ata} ({x}), que es una tecnica "
                f"hermana (otra hija del mismo padre); una hija no cubre a otra hija"
            )
        raise ErrorCobertura(
            f"C2 (regla 4): la fila {t} cita {ata} ({x}), que no es su tecnica ni un "
            f"ancestro suyo"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="C1+C2 del cierre P1-Linux.")
    parser.add_argument("--cobertura", default=str(DEFAULT_COBERTURA))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--ata-index", default=str(DEFAULT_ATA_INDEX))
    parser.add_argument("--todo", action="store_true", help="Ejecuta C1 y C2 (por defecto).")
    parser.add_argument("--c1", action="store_true", help="Solo C1.")
    parser.add_argument("--c2", action="store_true", help="Solo C2.")
    args = parser.parse_args(argv)

    # Por defecto (sin flags) o --todo -> ambas.
    run_c1 = args.todo or args.c1 or not (args.c1 or args.c2)
    run_c2 = args.todo or args.c2 or not (args.c1 or args.c2)

    try:
        corpus_rows = load_rows(args.corpus)
        cobertura_rows = load_rows(args.cobertura)
        if run_c1:
            crosstab = c1_check(cobertura_rows, corpus_rows)
            print(
                "[OK] C1 (cuadre): "
                + " | ".join(f"{c}={crosstab[c]}" for c in CATEGORIAS)
                + f" | total={sum(crosstab.values())}"
            )
        if run_c2:
            ata_rows = load_rows(args.ata_index)
            ata_index = {(r.get("ata_id") or "").strip(): r for r in ata_rows}
            c2_check(cobertura_rows, corpus_rows, ata_index)
            print(f"[OK] C2 (padre/hijo): sin violaciones sobre {len(cobertura_rows)} filas")
    except ErrorCobertura as exc:
        print(f"[FALLA] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
