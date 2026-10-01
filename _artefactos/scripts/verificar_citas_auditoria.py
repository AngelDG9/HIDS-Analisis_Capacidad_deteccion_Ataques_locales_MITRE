#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_citas_auditoria.py — comprueba que TODAS las citas de
`Hojas/auditoria_origen.csv` resuelven contra el fichero citado.

Regla: una cita vale si resuelve. Formatos admitidos (uno por `; `):

  - `Bitacora/ATA<NNN>.json (campo, campo)`  -> el JSON existe y las claves (ruta con puntos) existen;
  - `<...>/README.md §<n>[, §<m>]`           -> cada encabezado `## <n>.` existe;
  - `Hojas/cobertura_atomic.csv (ATA<NNN> ...)` -> la fila existe y la `nota`/`tests_linux` citadas coinciden;
  - `<fichero>:<linea>[-<linea>]`            -> el fichero existe y la(s) línea(s) existen.

Salida: `[OK] N/N citas resuelven` (y lista de fallos, si los hay). Exit != 0 si falla alguna.

Uso:
    python _artefactos/scripts/verificar_citas_auditoria.py
    python _artefactos/scripts/verificar_citas_auditoria.py --csv Hojas/auditoria_origen.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CSV = REPO_ROOT / "Hojas" / "auditoria_origen.csv"

NOTAS = {"cubierta", "solo_linux", "solo_windows", "sin_pruebas", "otras_plataformas"}


def _lines_of(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _check_json(repo: Path, cita: str) -> str | None:
    m = re.match(r"^(?P<path>[^\s(]+\.json)\s*\((?P<fields>[^)]*)\)$", cita)
    if not m:
        return None
    p = repo / m.group("path")
    if not p.is_file():
        return f"no existe {m.group('path')}"
    data = json.loads(p.read_text(encoding="utf-8"))
    for field in [f.strip() for f in m.group("fields").split(",") if f.strip()]:
        node = data
        for part in field.split("."):
            if not isinstance(node, dict) or part not in node:
                return f"{m.group('path')}: falta la clave {field}"
            node = node[part]
    return ""


def _check_md_sections(repo: Path, cita: str) -> str | None:
    m = re.match(r"^(?P<path>[^\s(]+\.md)\s+(?P<secs>§\s*\d+(?:\s*,\s*§\s*\d+)*)$", cita)
    if not m:
        return None
    p = repo / m.group("path")
    if not p.is_file():
        return f"no existe {m.group('path')}"
    text = p.read_text(encoding="utf-8")
    for sec in re.findall(r"§\s*(\d+)", m.group("secs")):
        if not re.search(rf"^#{{1,3}}\s*{sec}\.", text, flags=re.MULTILINE):
            return f"{m.group('path')}: falta el encabezado §{sec}"
    return ""


def _check_cobertura(repo: Path, cita: str) -> str | None:
    m = re.match(r"^(?P<path>Hojas/cobertura_atomic\.csv)\s*\((?P<body>[^)]*)\)$", cita)
    if not m:
        return None
    p = repo / m.group("path")
    if not p.is_file():
        return f"no existe {m.group('path')}"
    rows = {r["ata_id"]: r for r in csv.DictReader(p.read_text(encoding="utf-8").splitlines())}
    body = m.group("body")
    am = re.search(r"(ATA\d+)", body)
    if not am or am.group(1) not in rows:
        return f"{m.group('path')}: fila {am.group(1) if am else '?'} no encontrada"
    row = rows[am.group(1)]
    for nota in NOTAS:
        if re.search(rf"\b{nota}\b", body) and row["nota"] != nota:
            return f"{m.group('path')} {am.group(1)}: nota citada '{nota}' != real '{row['nota']}'"
    tm = re.search(r"tests_linux=(\d+)", body)
    if tm and int(tm.group(1)) != int(row["tests_linux"]):
        return f"{m.group('path')} {am.group(1)}: tests_linux citado {tm.group(1)} != real {row['tests_linux']}"
    return ""


def _check_line(repo: Path, cita: str) -> str | None:
    m = re.match(r"^(?P<path>[^\s:]+\.(?:md|txt|csv|json)):(?P<a>\d+)(?:-(?P<b>\d+))?$", cita)
    if not m:
        return None
    p = repo / m.group("path")
    if not p.is_file():
        return f"no existe {m.group('path')}"
    total = _lines_of(p)
    a = int(m.group("a"))
    b = int(m.group("b")) if m.group("b") else a
    if a < 1 or b > total:
        return f"{m.group('path')}: líneas {a}-{b} fuera de rango (fichero con {total})"
    return ""


def verificar_cita(repo: Path, cita: str) -> str:
    """Devuelve '' si resuelve, o el motivo del fallo."""
    cita = cita.strip()
    for fn in (_check_json, _check_md_sections, _check_cobertura, _check_line):
        res = fn(repo, cita)
        if res is not None:
            return res
    return f"formato de cita no reconocido: {cita!r}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verifica que las citas de la auditoría resuelven.")
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--repo", default=str(REPO_ROOT))
    args = ap.parse_args(argv)

    repo = Path(args.repo)
    csv_path = Path(args.csv)
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    rows = [r for r in csv.DictReader(lines) if (r.get("ata_id") or "").strip()]

    total = 0
    fallos = []
    filas_ok = 0
    for r in rows:
        row_bad = False
        for cita in [c for c in (r.get("citas") or "").split("; ") if c.strip()]:
            total += 1
            motivo = verificar_cita(repo, cita)
            if motivo:
                fallos.append(f"{r['ata_id']}: {motivo}")
                row_bad = True
        if not row_bad:
            filas_ok += 1

    ok = total - len(fallos)
    if fallos:
        for f in fallos:
            print(f"[FALLO] {f}")
        print(f"[FALLA] {filas_ok}/{len(rows)} filas | {ok}/{total} citas resuelven")
        return 1
    print(f"[OK] {filas_ok}/{len(rows)} filas | {ok}/{total} citas resuelven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
