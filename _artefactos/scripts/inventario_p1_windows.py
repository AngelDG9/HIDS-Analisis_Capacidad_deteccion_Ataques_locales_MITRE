#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inventario_p1_windows.py — Inventario reproducible de la piscina P1-Windows.

Bloque `fase-02b-diseno` (T-W2). **Solo stdlib**, **offline**, **determinista**
(no lee el reloj: la salida no contiene fecha). Cruza:

- `Hojas/corpus_host.csv` — corpus MITRE ATT&CK Enterprise v19.1 (host-eligible).
- `Soporte/Ataques/atomic-red-team/atomics/Indexes/Indexes-CSV/windows-index.csv`
  — índice de pruebas Windows de Atomic Red Team (ART).

y produce `Hojas/inventario_p1_windows.csv` con una fila **por técnica** de la
piscina **P1 host-eligible** (89 filas), con la columna `es_p1_linux`,
`p1_sin_linux`, `host_windows`, `tiene_prueba_art_windows`, `factibilidad` y `via`.

## Cuadre canónico (lo que el CSV debe reproducir)

| Conjunto | Nº | Origen |
|---|---|---|
| P1 host-eligible | **89** | `corpus_host.csv` (`priority=P1 ∧ host_eligible=YES`); el CSV crudo da 93 porque 4 son `solo_red`. |
| P1 ∧ Linux | **72** | = `Hojas/cobertura_p1_linux.csv` (P1-Linux cerrada). |
| P1 sin Linux | **17** | No citan Linux en `plataformas`. |
| · de esas, host Windows | **5** | T1114.001, T1114.002, T1185, T1213.002, T1557.001. |
| · de esas, sin host Windows | **12** | Nube / SaaS / IaaS / Network Devices → `no factible`. |
| P1 híbridas (Linux **y** Windows) | **72** | Las 72 P1-Linux citan también Windows (72/72). |
| · híbridas con prueba ART Windows | **36** | ≥1 fila (GUID distinto) en `windows-index.csv`. |
| · híbridas sin prueba ART Windows | **36** | → ataque propio. |
| P1 con prueba ART Windows (contando subtecnicas) | **38** | 36 híbridas + 2 Windows-only. |
| P1 con prueba ART Windows (test propio de la tecnica exacta) | **32** | 30 híbridas + 2 Windows-only; las **6** restantes solo tienen prueba en una subtecnica (T1056, T1074, T1114, T1491, T1557, T1567). |

**Factibilidad alineada con el plan §4.2:** ademas de las **12** P1 sin host Windows
(nube/SaaS/IaaS/red), **T1213.002** (Sharepoint) es **`no factible`** por depender de
**SaaS** y **T1114.002** (Remote Email Collection) es **`baja factibilidad`** por exigir
**servidor Exchange/nube**. Por eso `no factible` = **13** (12 sin host Windows + 1
Windows-only SaaS) y `baja factibilidad` = **1**.

## Criterio de las columnas

1. `plataformas`: se copia literal de `corpus_host.csv` (separadas por `;`).
2. `es_p1_linux` = `sí` si `plataformas ∋ Linux`; `p1_sin_linux` = `sí` si **no**.
3. `host_windows` = `sí` si `plataformas ∋ Windows`.
4. `tiene_prueba_art_windows` = `sí` si la técnica (o una subtecnica suya, `T` o
   `T.<n>`) tiene ≥1 fila **de GUID distinto** en `windows-index.csv`
   (`index.csv`/`windows-index.csv` del clon `388942a` traen **filas duplicadas**
   exactas: `windows-index.csv` 1587 filas → 1253 distintas; se cuenta por
   `(Technique #, Test GUID)` para no inflar el "¿tiene prueba?").
5. `factibilidad` = `factible` / `baja factibilidad` / `no factible`; `motivo` con el
   detalle.
6. `via` = `ART` (usar ART Windows tal cual/adaptado), `propia` (escribir el ataque)
   o `-` (no factible). La decisión **final** de via la toma el humano en el gate;
   aquí se da la **vía recomendada** por el plan (§4.4).

Uso:
    python _artefactos/scripts/inventario_p1_windows.py
    python _artefactos/scripts/inventario_p1_windows.py --out <ruta.csv>
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO_ROOT / "Hojas" / "corpus_host.csv"
DEFAULT_ART = REPO_ROOT / "Soporte" / "Ataques" / "atomic-red-team"
DEFAULT_OUT = REPO_ROOT / "Hojas" / "inventario_p1_windows.csv"

WINDOWS_INDEX = "windows-index.csv"

HEADER_COLUMNS = [
    "tecnica_id",
    "nombre",
    "tactica",
    "plataformas",
    "es_p1_linux",
    "p1_sin_linux",
    "host_windows",
    "tiene_prueba_art_windows",
    "factibilidad",
    "motivo",
    "via",
]

# --- Conjuntos declarados (cuadre canónico del plan §4.1/§4.2) --------------
# Las 5 P1 sin Linux con host Windows (T1114.001, T1185, T1557.001, T1114.002,
# T1213.002) se resuelven por excepción en `build_inventory` (plan §4.2).
# Windows-only con factibilidad "baja" (plan §4.2: servidor Exchange/nube).
WINDOWS_ONLY_BAJA = {
    "T1114.002": "baja factibilidad: Windows-only, pero requiere servidor Exchange/nube (no hay servicio real)",
}
# Windows-only "no factible" (plan §4.2: SaaS).
WINDOWS_ONLY_NO_FACTIBLES = {
    "T1213.002": "no factible: SaaS/SharePoint (no hay servicio real en el laboratorio)",
}
# Las 12 P1 sin Linux ni host Windows (nube / SaaS / IaaS / red → no factibles).
NO_FACTIBLES_SIN_WINDOWS = {
    "T1213.001",
    "T1213.003",
    "T1213.004",
    "T1213.005",
    "T1485.001",
    "T1496.003",
    "T1496.004",
    "T1530",
    "T1537",
    "T1557.004",
    "T1602.001",
    "T1602.002",
}
# Razón por la que cada grupo sin host Windows es no factible (motivo legible).
NO_FACTIBLE_MOTIVO_POR_PLATAFORMA = {
    "SaaS": "no factible: SaaS (no hay servicio real en el laboratorio)",
    "IaaS": "no factible: nube/IaaS (no hay servicio real en el laboratorio)",
    "Office Suite": "no factible: servicio Office/SaaS (no hay servicio real)",
    "Network Devices": "no factible: dispositivo de red (no está en el laboratorio)",
}
ESPERADO_TOTAL = 89
ESPERADO_P1_LINUX = 72
ESPERADO_P1_SIN_LINUX = 17


# ---------------------------------------------------------------------------
# Carga
# ---------------------------------------------------------------------------
def load_corpus(path: str | Path) -> list[dict]:
    """Lee `corpus_host.csv` saltando las líneas de comentario (`# ...`)."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"No existe el corpus: {path}")
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines()
             if not ln.lstrip().startswith("#")]
    if not lines:
        raise ValueError(f"El corpus no tiene datos: {path}")
    return [r for r in csv.DictReader(lines) if (r.get("tecnica_id") or "").strip()]


def load_windows_index(art_root: str | Path) -> list[dict]:
    path = Path(art_root) / "atomics" / "Indexes" / "Indexes-CSV" / WINDOWS_INDEX
    if not path.is_file():
        raise FileNotFoundError(f"Falta el índice Windows de ART: {path}")
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------------------
# Cálculo
# ---------------------------------------------------------------------------
def _belongs(technique_field: str, tecnica: str) -> bool:
    """True si `technique_field` es la técnica o una subtecnica suya (`T.<n>`)."""
    return technique_field == tecnica or technique_field.startswith(tecnica + ".")


def distinct_art_windows_tests(rows: list[dict], tecnica: str) -> int:
    """Nº de pruebas Windows de GUID distinto de la técnica (subtecnicas incluidas)."""
    guids = set()
    for r in rows:
        field = (r.get("Technique #") or "").strip()
        if _belongs(field, tecnica):
            guids.add((field, (r.get("Test GUID") or "").strip()))
    return len(guids)


def exact_art_techniques(win_rows: list[dict]) -> set[str]:
    """IDs de técnica que tienen un test **propio** (no solo vía subtecnica)."""
    return {
        (r.get("Technique #") or "").strip()
        for r in win_rows
        if (r.get("Technique #") or "").strip()
    }


def con_art_windows_exacto(rows: list[dict], win_rows: list[dict]) -> int:
    """Nº de técnicas del inventario con **test propio** de la técnica exacta."""
    exact = exact_art_techniques(win_rows)
    return sum(1 for r in rows if r["tecnica_id"] in exact)


def _split_plataformas(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(";") if p.strip()]


def _no_factible_motivo(plataformas: list[str]) -> str:
    for p in plataformas:
        if p in NO_FACTIBLE_MOTIVO_POR_PLATAFORMA:
            return NO_FACTIBLE_MOTIVO_POR_PLATAFORMA[p]
    return "no factible: solo nube / red (fuera del alcance local)"


def build_inventory(corpus_rows: list[dict], win_rows: list[dict]) -> list[dict]:
    # (docstring arriba)
    """Construye las filas del inventario P1-Windows (orden estable del corpus)."""
    out: list[dict] = []
    for r in corpus_rows:
        if (r.get("priority") or "").strip() != "P1":
            continue
        if (r.get("host_eligible") or "").strip() != "YES":
            continue

        tecnica = (r.get("tecnica_id") or "").strip()
        plataformas = _split_plataformas(r.get("plataformas") or "")
        tiene_linux = "Linux" in plataformas
        tiene_windows = "Windows" in plataformas
        art_win = distinct_art_windows_tests(win_rows, tecnica) > 0

        if tiene_linux:
            # Las 72 híbridas: Linux + Windows. Via ART si hay prueba Windows.
            via = "ART" if art_win else "propia"
            factibilidad = "factible"
            if art_win:
                motivo = "hibrida (Linux+Windows); prueba ART Windows >=1 -> ART tal cual/adaptado"
            else:
                motivo = "hibrida (Linux+Windows); sin prueba ART Windows -> ataque propio"
        elif tiene_windows:
            # 5 P1 sin Linux con host Windows (plan §4.2).
            if tecnica in WINDOWS_ONLY_NO_FACTIBLES:
                factibilidad = "no factible"
                via = "-"
                motivo = WINDOWS_ONLY_NO_FACTIBLES[tecnica]
            elif tecnica in WINDOWS_ONLY_BAJA:
                factibilidad = "baja factibilidad"
                via = "ART" if art_win else "propia"
                motivo = WINDOWS_ONLY_BAJA[tecnica]
            else:
                factibilidad = "factible"
                via = "ART" if art_win else "propia"
                motivo = "Windows-only; no citada en Linux; factible en VM Windows"
        else:
            # 12 nube / SaaS / IaaS / red: no factibles.
            factibilidad = "no factible"
            via = "-"
            motivo = _no_factible_motivo(plataformas)

        out.append(
            {
                "tecnica_id": tecnica,
                "nombre": (r.get("nombre") or "").strip(),
                "tactica": (r.get("tacticas") or "").strip(),
                "plataformas": ";".join(plataformas),
                "es_p1_linux": "sí" if tiene_linux else "no",
                "p1_sin_linux": "sí" if not tiene_linux else "no",
                "host_windows": "sí" if tiene_windows else "no",
                "tiene_prueba_art_windows": "sí" if art_win else "no",
                "factibilidad": factibilidad,
                "motivo": motivo,
                "via": via,
            }
        )
    return out


def resumen(rows: list[dict]) -> dict:
    """Cifras del cuadre (para la cabecera y la salida por consola)."""
    p1_linux = sum(1 for r in rows if r["es_p1_linux"] == "sí")
    sin_linux = sum(1 for r in rows if r["p1_sin_linux"] == "sí")
    win_only = sum(1 for r in rows if r["p1_sin_linux"] == "sí" and r["host_windows"] == "sí")
    no_fact = sum(1 for r in rows if r["factibilidad"] == "no factible")
    baja = sum(1 for r in rows if r["factibilidad"] == "baja factibilidad")
    art_win = sum(1 for r in rows if r["tiene_prueba_art_windows"] == "sí")
    # Desglose de las híbridas (todas las P1-Linux) y de las Windows-only.
    art_win_hibridas = sum(
        1 for r in rows if r["es_p1_linux"] == "sí" and r["tiene_prueba_art_windows"] == "sí"
    )
    art_win_wonly = sum(
        1
        for r in rows
        if r["p1_sin_linux"] == "sí"
        and r["host_windows"] == "sí"
        and r["tiene_prueba_art_windows"] == "sí"
    )
    return {
        "total": len(rows),
        "p1_linux": p1_linux,
        "p1_sin_linux": sin_linux,
        "host_windows_only": win_only,
        "no_factible": no_fact,
        "baja_factibilidad": baja,
        "con_art_windows": art_win,
        "art_win_hibridas": art_win_hibridas,
        "art_win_wonly": art_win_wonly,
    }


# ---------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------
def _cabecera_comentario(res: dict, con_art_exacto: int | None = None) -> str:
    if con_art_exacto is None:
        art_line = (
            f"# ART Windows (GUID distinto): {res['con_art_windows']} contando subtecnicas "
            "(nº exacto no calculado)\n"
        )
    else:
        via_subtec = res["con_art_windows"] - con_art_exacto
        art_line = (
            f"# ART Windows (GUID distinto): {res['con_art_windows']} contando subtecnicas | "
            f"{con_art_exacto} con test propio de la tecnica exacta ({via_subtec} via subtecnica)\n"
        )
    return (
        "# inventario_p1_windows.csv | bloque fase-02b-diseno (T-W2)\n"
        "# Fuente: Hojas/corpus_host.csv (MITRE ATT&CK v19.1) + "
        "Soporte/Ataques/atomic-red-team/atomics/Indexes/Indexes-CSV/windows-index.csv\n"
        f"# P1 host-eligible: {res['total']} | P1-Linux: {res['p1_linux']} | "
        f"P1 sin Linux: {res['p1_sin_linux']} (host Windows: {res['host_windows_only']})\n"
        f"# Factibilidad: no factible = {res['no_factible']} (12 nube/SaaS/red + T1213.002 SaaS) | "
        f"baja factibilidad = {res['baja_factibilidad']} (T1114.002 Exchange/nube)\n"
        f"# Hibridas (Linux+Windows): {res['p1_linux']} -> con prueba ART Windows: "
        f"{res['art_win_hibridas']} | sin prueba ART Windows: "
        f"{res['p1_linux'] - res['art_win_hibridas']}\n"
        f"# Windows-only con prueba ART Windows: {res['art_win_wonly']}\n"
        + art_line +
        "# Generado por _artefactos/scripts/inventario_p1_windows.py (determinista, sin fecha)\n"
    )


def write_inventory(
    rows: list[dict],
    res: dict,
    out_path: str | Path,
    con_art_exacto: int | None = None,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_cabecera_comentario(res, con_art_exacto))
        writer = csv.DictWriter(fh, fieldnames=HEADER_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Inventario reproducible de la piscina P1-Windows."
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="corpus_host.csv.")
    parser.add_argument("--art", default=str(DEFAULT_ART), help="Raíz del clon de ART.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="CSV de salida.")
    args = parser.parse_args(argv)

    try:
        corpus_rows = load_corpus(args.corpus)
        win_rows = load_windows_index(args.art)
    except (FileNotFoundError, ValueError, csv.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    rows = build_inventory(corpus_rows, win_rows)
    if len(rows) != ESPERADO_TOTAL:
        print(
            f"[ERROR] La piscina P1 host-eligible da {len(rows)}; se esperaban "
            f"{ESPERADO_TOTAL}. Revisa corpus_host.csv.",
            file=sys.stderr,
        )
        return 3

    res = resumen(rows)
    n_exacto = con_art_windows_exacto(rows, win_rows)
    out = write_inventory(rows, res, args.out, con_art_exacto=n_exacto)
    print(f"[OK] {out} ({res['total']} tecnicas)")
    print(
        f"[INFO] P1-Linux={res['p1_linux']} | P1 sin Linux={res['p1_sin_linux']} "
        f"(Windows-only={res['host_windows_only']}, no factibles={res['no_factible']}, "
        f"baja factibilidad={res['baja_factibilidad']})"
    )
    print(
        f"[INFO] hibridas con ART Windows={res['art_win_hibridas']} | "
        f"hibridas sin ART Windows={res['p1_linux'] - res['art_win_hibridas']} | "
        f"Windows-only con ART Windows={res['art_win_wonly']}"
    )
    print(
        f"[INFO] ART Windows: {res['con_art_windows']} con prueba contando subtecnicas | "
        f"{n_exacto} con test propio de la tecnica exacta "
        f"({res['con_art_windows'] - n_exacto} via subtecnica)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
