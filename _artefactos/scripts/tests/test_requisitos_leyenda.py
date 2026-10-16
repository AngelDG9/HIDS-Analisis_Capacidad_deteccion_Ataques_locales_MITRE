# -*- coding: utf-8 -*-
"""Tests de `requisitos_leyenda.py` — Requisitos + Leyenda · R2 (§4.6–§4.7)."""
from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import requisitos_leyenda as RL  # noqa: E402
import tabla1_clasificacion as T1  # noqa: E402
import tabla2_ataques as T2  # noqa: E402
import tabla3_legitimo as T3  # noqa: E402
import tabla5_pruning as T5  # noqa: E402


def _leer(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not TC_es_comentario(ln)]
    return list(csv.DictReader(lines))


def TC_es_comentario(ln):
    s = ln.lstrip()
    if not s.startswith("#"):
        return False
    rest = s[1:]
    return rest == "" or not rest[:1].isalnum()


def test_requisitos(tmp_path, monkeypatch):
    out_req = tmp_path / "req.csv"
    out_ley = tmp_path / "ley.csv"
    assert RL.main(["--out-req", str(out_req), "--out-ley", str(out_ley)]) == 0
    req = _leer(out_req)
    assert len(req) == 6
    por = {r["requisito"]: r for r in req}
    # "Ataque detectable por patrones/reglas" -> 2 (ATA013, ATA034)
    r4 = [r for r in req if r["columna_para_filtrar"] == "Detection"][0]
    assert r4["n_casos_que_no_lo_cumplen"] == "2"
    # "Cubren todas las técnicas P1" -> 8 (no_factible)
    r5 = [r for r in req if r["columna_para_filtrar"] == "estado_cobertura"][0]
    assert r5["n_casos_que_no_lo_cumplen"] == "8"
    assert por["Técnica detectable por host"]["wazuh"] == "SI"


def test_leyenda_cubre_columnas(tmp_path):
    out_req = tmp_path / "req.csv"
    out_ley = tmp_path / "ley.csv"
    assert RL.main(["--out-req", str(out_req), "--out-ley", str(out_ley)]) == 0
    ley = _leer(out_ley)
    cubiertas = {(r["tabla"], r["columna"]) for r in ley}
    for nombre, header in [
        ("T1", T1.HEADER),
        ("T2", T2.HEADER),
        ("T3", T3.HEADER),
        ("T5", T5.HEADER),
        ("T5_steps", T5.STEPS_HEADER),
    ]:
        for col in header:
            assert (nombre, col) in cubiertas, f"falta {nombre}.{col} en la leyenda"
    # glosario + formulas + virgen presentes
    tablas = {r["tabla"] for r in ley}
    assert {"GLOSARIO", "FORMULA", "VIRGEN"} <= tablas
