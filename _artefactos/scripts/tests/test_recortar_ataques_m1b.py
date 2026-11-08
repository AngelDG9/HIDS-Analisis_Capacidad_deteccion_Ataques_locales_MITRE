# -*- coding: utf-8 -*-
"""Tests de `recortar_ataques_m1b.py` y `comparar_t2_m1b.py` (bloque `legitimo-analisis`)."""

from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import comparar_t2_m1b as CMP  # noqa: E402
import recortar_ataques_m1b as REC  # noqa: E402
import tabla_comun as TC  # noqa: E402


def test_diff_lineas_replace_delete_insert():
    a = ["a", "b", "c"]
    b = ["a", "x", "c", "d"]
    d = REC._diff_lineas(a, b)
    tipos = [x[0] for x in d]
    assert "replace" in tipos and "insert" in tipos
    assert any(x[1] == "b" and x[2] == "x" for x in d)
    assert any(x[1] == "" and x[2] == "d" for x in d)


def test_verificar_entradas_sha(tmp_path):
    p = tmp_path / "alerta.csv"
    p.write_text("x\n", encoding="utf-8")
    sha = TC.sha256_file(str(p))
    ok = {"alerta": (str(p), sha), "esperado": (str(p), sha)}
    assert REC._verificar_entradas("v", ok) == []
    bad = {"alerta": (str(p), "0" * 64), "esperado": (str(p), sha)}
    assert REC._verificar_entradas("v", bad)


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def test_comparar_t2_sin_cambios(tmp_path):
    header = ["ata_id", "config", "umbral", "Detection", "#Alertas",
              "primera_evidencia_rule_id"]
    rows = [("ATA001", "C1", 0, "SÍ", 2, "80792"),
            ("ATA002", "C1", 0, "NO", 0, "")]
    m1a = tmp_path / "m1a.csv"
    m1b = tmp_path / "m1b.csv"
    out = tmp_path / "cmp.csv"
    _escribir(m1a, header, rows)
    _escribir(m1b, header, rows)
    assert CMP.main(["--m1a", str(m1a), "--m1b", str(m1b), "--out", str(out)]) == 0
    with open(out, encoding="utf-8") as fh:
        lineas = [ln for ln in fh if not ln.startswith("#")]
    assert lineas[1].startswith("ATA001")
    assert "cambiadas=0" in open(out, encoding="utf-8").readline()
