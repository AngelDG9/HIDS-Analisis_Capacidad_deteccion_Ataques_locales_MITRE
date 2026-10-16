#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla_comun.py — utilidades de E/S deterministas para los scripts de tabla (R2).

Módulo de apoyo (KISS): lectura/escritura de CSV del repo (ignora líneas `#`),
huellas `sha256` y agregación determinista de cadenas de huellas. **No** contiene
lógica de la métrica (esa vive en `metrica_hids.py`) ni de la tabla alguna.

Reglas de escritura (R2 §6): UTF-8 **sin BOM**, fin de línea **LF**, **sin reloj**,
orden estable -> misma entrada, mismos bytes.
"""

from __future__ import annotations

import csv
import hashlib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def rel(path: str) -> str:
    """Ruta POSIX relativa a la raíz del repo (o la original si no está dentro)."""
    p = os.path.abspath(path)
    try:
        r = os.path.relpath(p, ROOT)
    except ValueError:
        return path
    if r.startswith(".."):
        return path
    return r.replace(os.sep, "/")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_cadena(files) -> str:
    """Huella agregada y determinista de una lista de ficheros (ordenada).

    Igual a la cadena de huellas del repo: sha256 sobre las líneas
    `"<ruta_rel>::<sha256>"` ordenadas. No depende del orden de entrada.
    """
    lineas = []
    for p in files:
        lineas.append(f"{rel(p)}::{sha256_file(p)}")
    lineas.sort()
    h = hashlib.sha256()
    for ln in lineas:
        h.update((ln + "\n").encode("utf-8"))
    return h.hexdigest()


def es_comentario(ln: str) -> bool:
    """True si la línea es un comentario `#` (no una fila de datos que empiece por `#`).

    Convención del repo: los comentarios son `# <texto>` (almohadilla **y** un carácter
    no alfanumérico). Así una fila de datos como `#Casos,#Attack flows,…` (T4) **no** se
    confunde con un comentario.
    """
    s = ln.lstrip()
    if not s.startswith("#"):
        return False
    rest = s[1:]
    return rest == "" or not rest[:1].isalnum()


def read_csv_rows(path: str, required=None):
    """Lee un CSV del repo ignorando líneas de comentario `#`.

    Devuelve `(fieldnames, filas)`; `filas` es lista de dict.
    """
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not es_comentario(ln)]
    reader = csv.DictReader(lines)
    fieldnames = list(reader.fieldnames or [])
    rows = list(reader)
    if required:
        missing = [c for c in required if c not in fieldnames]
        if missing:
            raise ValueError(f"{path}: faltan columnas {missing}; tiene {fieldnames}")
    return fieldnames, rows


def write_csv(path: str, header, rows, comment=None) -> None:
    """Escribe un CSV determinista: UTF-8 sin BOM, LF, sin reloj."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        if comment:
            fh.write(comment.rstrip("\n") + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        for r in rows:
            writer.writerow([r.get(c, "") for c in header])


def row_get(r: dict, key: str, default: str = "") -> str:
    v = r.get(key)
    return default if v is None else str(v)
