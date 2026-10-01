#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""anadir_fuente_motivo.py — T4/T5: sincroniza `fuente_norm`/`motivo_codigo`/`motivo_detalle`
del bloque `atomic` de las 43 bitácoras con `Hojas/auditoria_origen.csv`, de forma ADITIVA
y QUIRÚRGICA.

No usa `json.dump` (eso reformatearía todo el fichero). En su lugar:
  - INSERTA las claves que falten DENTRO del objeto `atomic`, respetando su estilo
    (multilínea -> una clave por línea; en una sola línea -> claves inline),
  - SUSTITUYE solo el valor de las claves que ya existen y han cambiado,
  - NO toca ninguna otra parte del fichero (nada de reindentar arrays ni objetos),
  - respeta el EOL LF y escribe UTF-8 sin BOM,
  - es idempotente: si ya está todo sincronizado, no hace nada.

Uso:
    python _artefactos/scripts/anadir_fuente_motivo.py
    python _artefactos/scripts/anadir_fuente_motivo.py --check
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BITACORA = REPO_ROOT / "Bitacora"
AUDITORIA = REPO_ROOT / "Hojas" / "auditoria_origen.csv"

FUENTE_NORM = {"ART_tal_cual": "art_tal_cual", "ART_adaptado": "art_adaptado", "propio": "propio"}


def load_auditoria() -> dict[str, dict]:
    with open(AUDITORIA, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return {r["ata_id"]: r for r in csv.DictReader(lines)}


def _localizar_atomic(text: str) -> tuple[int, int]:
    """Devuelve (inicio_llave, fin_llave) del bloque `atomic` respetando strings/escapes."""
    m = re.search(r'"atomic"\s*:\s*\{', text)
    if not m:
        raise ValueError("no se encontró el bloque 'atomic'")
    start = text.index("{", m.start())
    depth = 0
    i = start
    in_str = False
    esc = False
    while i < len(text):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return start, i + 1
        i += 1
    raise ValueError("bloque 'atomic' sin cerrar")


def _replace_in_inner(inner: str, claves: list[tuple[str, str]]) -> str:
    """Sustituye el valor de cada clave (ya presente) dentro del objeto `atomic`."""
    for k, v in claves:
        pat = re.compile(r'("' + re.escape(k) + r'"\s*:\s*)"(?:\\.|[^"\\])*"')
        inner, n = pat.subn(lambda m: m.group(1) + json.dumps(v, ensure_ascii=False), inner, count=1)
        if n == 0:
            raise ValueError(f"clave {k} no encontrada para sustituir")
    return inner


def procesar(path: Path, audit: dict, check: bool) -> str:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    ata = data.get("ata_id")
    if ata not in audit:
        return f"SKIP {path.name}: sin fila de auditoría"
    row = audit[ata]
    fn = FUENTE_NORM[row["fuente"]]
    mc = row["motivo_codigo"]
    md = row["motivo_detalle"]
    claves = [("fuente_norm", fn), ("motivo_codigo", mc), ("motivo_detalle", md)]

    inner_start, inner_end = _localizar_atomic(text)
    inner = text[inner_start:inner_end]

    atomic = data.get("atomic", {})
    if all(atomic.get(k) == v for k, v in claves):
        return f"OK   {path.name}: ya sincronizado"
    if check:
        return f"PEND {path.name}: sync {fn}/{mc}"

    presentes = {k: (f'"{k}"' in inner) for k, _ in claves}
    if all(presentes.values()):
        nuevo_inner = _replace_in_inner(inner, claves)
    else:
        # Sustituir las que ya están y añadir (con el estilo original) las que falten.
        ya = [(k, v) for k, v in claves if presentes[k]]
        faltan = [(k, v) for k, v in claves if not presentes[k]]
        if ya:
            inner = _replace_in_inner(inner, ya)
        multilinea = "\n" in inner
        if multilinea:
            lines = inner.split("\n")
            indent = "    "
            for ln in reversed(lines):
                if ln.strip() and ln.strip() != "{":
                    m = re.match(r"^(\s*)\"", ln)
                    if m:
                        indent = m.group(1)
                    break
            contenido = inner[1:].rstrip()  # sin '{' inicial y sin espacios hasta '}'
            assert contenido.endswith("}")
            contenido = contenido[:-1].rstrip()  # sin '}' final
            if contenido and not contenido.endswith(","):
                contenido += ","
            nuevas_lineas = "".join(
                f'\n{indent}"{k}": {json.dumps(v, ensure_ascii=False)}'
                + ("," if idx < len(faltan) - 1 else "")
                for idx, (k, v) in enumerate(faltan)
            )
            nuevo_inner = "{" + contenido + nuevas_lineas + "\n  }"
        else:
            # estilo en una línea: '{ "a": 1, "b": 2 }' -> insertar antes de ' }'.
            contenido = inner[1:].rstrip()  # sin '{' y sin espacios finales
            assert contenido.endswith("}")
            contenido = contenido[:-1].rstrip()  # sin '}'
            if contenido and not contenido.endswith(","):
                contenido += ", "
            elif contenido:
                contenido += " "
            extras = ", ".join(f'"{k}": {json.dumps(v, ensure_ascii=False)}' for k, v in faltan)
            nuevo_inner = "{" + contenido + extras + " }"

    nuevo_text = text[:inner_start] + nuevo_inner + text[inner_end:]
    # Sanidad: el resultado debe seguir siendo JSON válido y con las claves.
    chk = json.loads(nuevo_text)
    assert chk["atomic"]["fuente_norm"] == fn
    assert chk["atomic"]["motivo_codigo"] == mc
    assert chk["atomic"]["motivo_detalle"] == md
    path.write_text(nuevo_text, encoding="utf-8", newline="\n")
    return f"SYNC {path.name}: -> {fn}/{mc}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T4: fuente_norm + motivo en las 43 bitácoras.")
    ap.add_argument("--check", action="store_true", help="no escribe; solo informa")
    args = ap.parse_args(argv)
    audit = load_auditoria()
    n = 0
    for p in sorted(BITACORA.glob("ATA*.json")):
        msg = procesar(p, audit, args.check)
        if msg.startswith(("ADD", "SYNC")):
            n += 1
        if not msg.startswith("OK"):
            print(msg)
    print(f"[INFO] ficheros modificados: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
