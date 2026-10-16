# -*- coding: utf-8 -*-
"""Tests de `tabla3_legitimo.py` — T3 (plano legítimo) · R2.

Cubren: plantilla sin datos (L11, `M = n/a`), el bloque config×umbral con `M` y el
detalle por `rule.id` (doble conteo §4), y el recuento de `M` desde un `archives.json`.
"""
from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import tabla3_legitimo as T3  # noqa: E402


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _detalle(tmp_path):
    header = ["rule_id", "rule_level", "rs_origen", "categoria", "rule_groups", "unidad"]
    rows = [
        ("80791", 3, "RS2", "auto_ruido", "audit", "u1"),
        ("80792", 3, "RS2", "deteccion", "audit", "u1"),
        ("80792", 3, "RS2", "deteccion", "audit", "u2"),
    ]
    p = tmp_path / "detalle.csv"
    _escribir(p, header, rows)
    return p


def _leer(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_L11_sin_datos(tmp_path):
    out = tmp_path / "T3.csv"
    assert T3.main(["--out", str(out)]) == 0
    texto = out.read_text(encoding="utf-8")
    assert "M=n/a (fallback L11)" in texto
    assert "estado=sin_datos" in texto
    filas = _leer(out)
    assert filas == []  # solo cabecera
    header = out.read_text(encoding="utf-8").splitlines()
    assert header[-1].startswith("seccion,") or any(ln.startswith("seccion,") for ln in header)


def test_bloque_con_M(tmp_path):
    det = _detalle(tmp_path)
    out = tmp_path / "T3.csv"
    assert T3.main([
        "--detalle", str(det), "--unidades-count", "4", "--config", "C1", "--umbral", "0",
        "--n-acciones-ghosts", "8", "--duracion-h", "2", "--out", str(out),
    ]) == 0
    ag = [f for f in _leer(out) if f["seccion"] == "agregado"]
    assert len(ag) == 1
    r = ag[0]
    assert r["#Unidades"] == "4"
    assert r["#Alertas"] == "3"
    assert r["#Unidades_FP"] == "2"
    assert r["#Unidades_TN"] == "2"
    assert r["%Unidades_FP"] == "0.5000"
    assert r["%Unidades_TN"] == "0.5000"
    assert r["#Alertas_FP_sin_auto_ruido"] == "2"  # sin el auto_ruido
    assert r["FP_por_accion"] == "0.3750"  # 3/8
    assert r["FP_por_hora"] == "1.5000"  # 3/2
    # correlacionadas = Σ_unidades(rule.id distintos) = u1{80791,80792}=2 + u2{80792}=1 = 3
    assert r["#Alertas_correlacionadas"] == "3"
    assert r["#rule.id_distintos"] == "2"
    det_rows = [f for f in _leer(out) if f["seccion"] == "detalle_ruleid"]
    assert sorted(x["rule.id"] for x in det_rows) == ["80791", "80792"]


def test_archives_count(tmp_path):
    det = _detalle(tmp_path)
    arch = tmp_path / "archives.json"
    arch.write_text('{"a":1}\n{"a":2}\n{"a":3}\n{"a":4}\n{"a":5}\n', encoding="utf-8")
    out = tmp_path / "T3.csv"
    assert T3.main(["--detalle", str(det), "--archives", str(arch), "--config", "C1",
                    "--umbral", "0", "--out", str(out)]) == 0
    r = [f for f in _leer(out) if f["seccion"] == "agregado"][0]
    assert r["#Unidades"] == "5"
