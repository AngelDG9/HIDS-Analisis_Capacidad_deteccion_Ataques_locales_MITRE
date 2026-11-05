# -*- coding: utf-8 -*-
"""Tests de `promover_ventana_legitimo.py` — procedencia de la promoción (legitimo-v3).

Fijan que **cada** copia promovida declara en su cabecera `#` **su** ruta real de
origen (existente en el repo) y el `sha256` de ese origen, y que el cuerpo es
idéntico al original sin la cabecera.

Regresión del defecto: `campana_ventanas.tsv` declaraba
`Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/campana_ventanas.tsv`, que no
existe; su origen real es `Soporte/Laboratorio/legitimo_72h/campana/campana_ventanas.tsv`.
"""
import hashlib
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import promover_ventana_legitimo as P  # noqa: E402


def _campos(linea: str) -> dict:
    campos = {}
    for trozo in linea.rstrip("\n").split(" | "):
        if "=" in trozo:
            k, v = trozo.split("=", 1)
            campos[k] = v
    return campos


def _cabecera(nombre: str) -> tuple[str, bytes]:
    with open(P.DESTINO / nombre, "rb") as fh:
        cruda = fh.readline()
    return cruda.decode("utf-8"), cruda


def test_todo_origen_promovido_existe_y_su_sha_coincide():
    for nombre, origen, es_csv in P.inventario():
        assert origen.exists(), f"origen real inexistente: {origen}"
        if not es_csv:
            continue
        linea, _ = _cabecera(nombre)
        campos = _campos(linea)
        assert "origen" in campos, f"{nombre}: cabecera sin origen"
        assert "sha256_origen" in campos, f"{nombre}: cabecera sin sha256_origen"
        rel = campos["origen"]
        ruta = P.REPO / rel
        assert ruta.exists(), f"{nombre}: origen declarado inexistente: {rel}"
        assert ruta == origen, (
            f"{nombre}: origen declarado {rel} != real "
            f"{origen.relative_to(P.REPO).as_posix()}"
        )
        assert hashlib.sha256(ruta.read_bytes()).hexdigest() == campos["sha256_origen"], (
            f"{nombre}: sha256_origen no coincide con {rel}"
        )


def test_cuerpo_promovido_identico_al_origen():
    for nombre, origen, es_csv in P.inventario():
        if not es_csv:
            continue
        _, cruda = _cabecera(nombre)
        datos = origen.read_bytes()
        promovido = (P.DESTINO / nombre).read_bytes()
        assert promovido[: len(cruda)] == cruda, f"{nombre}: cabecera distinta"
        assert promovido[len(cruda):] == datos, f"{nombre}: cuerpo distinto del origen"
