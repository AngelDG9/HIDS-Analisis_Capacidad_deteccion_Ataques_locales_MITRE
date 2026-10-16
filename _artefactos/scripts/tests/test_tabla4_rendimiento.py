# -*- coding: utf-8 -*-
"""Tests de `tabla4_rendimiento.py` — T4 (métricas) · R2.

Comprueba las 7 fórmulas agregando T2 + T3 sintéticos (con `M` instrumentado) y el caso
`M = n/a` (L11: FPR/TNR/GM/Precisión/F1/Usabilidad vacíos).
"""
from pathlib import Path
import csv
import math
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import tabla4_rendimiento as T4  # noqa: E402


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _t2(tmp_path):
    header = ["ata_id", "config", "umbral", "Detection", "#Alertas", "#Alertas_correlacionadas"]
    rows = [
        ("ATA900", "C1", 0, "SÍ", 3, 1),
        ("ATA901", "C1", 0, "NO", 0, 0),
    ]
    p = tmp_path / "T2.csv"
    _escribir(p, header, rows)
    return p


def _t3(tmp_path, con_m=True):
    header = ["seccion", "config", "umbral", "#Unidades", "#Unidades_FP", "#Unidades_TN",
              "#Alertas_FP", "#Alertas_correlacionadas"]
    rows = [("agregado", "C1", 0, "100" if con_m else "n/a", 10 if con_m else "", 90 if con_m else "",
             50, 20)]
    p = tmp_path / "T3.csv"
    _escribir(p, header, rows)
    return p


def _leer(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not (ln.startswith("#") and (len(ln) < 2 or not ln[1:2].isalnum()))]
    rows = list(csv.reader(lines))
    header = rows[0]
    return header, {r[0]: dict(zip(header, r)) for r in rows[1:]}


def test_formulas(tmp_path):
    out = tmp_path / "T4.csv"
    assert T4.main(["--t2", str(_t2(tmp_path)), "--t3", str(_t3(tmp_path)), "--out", str(out)]) == 0
    _, m = _leer(out)
    col = "wazuh_C1_N0"
    assert m["#Casos"][col] == "2"
    assert m["#Casos_TP"][col] == "1"
    assert m["#Casos_FN"][col] == "1"
    assert float(m["TPR"][col]) == 0.5
    assert float(m["FPR"][col]) == 0.1
    assert float(m["TNR"][col]) == 0.9
    assert abs(float(m["GM"][col]) - math.sqrt(0.5 * 0.9)) < 1e-6
    assert abs(float(m["Precisión"][col]) - 3 / 53) < 1e-6
    f1 = 2 * (3 / 53) * 0.5 / ((3 / 53) + 0.5)
    assert abs(float(m["F1"][col]) - f1) < 1e-6
    assert abs(float(m["Usabilidad"][col]) - 50 / 3) < 1e-4


def test_L11_sin_M(tmp_path):
    out = tmp_path / "T4.csv"
    assert T4.main(["--t2", str(_t2(tmp_path)), "--t3", str(_t3(tmp_path, con_m=False)),
                    "--out", str(out)]) == 0
    _, m = _leer(out)
    col = "wazuh_C1_N0"
    assert m["FPR"][col] == "" and m["TNR"][col] == "" and m["GM"][col] == ""
    # Precisión/F1/Usabilidad dependen de A_FP (alertas), no de M -> se publican
    assert m["Precisión"][col] == "0.056604"
    assert float(m["TPR"][col]) == 0.5  # TPR no depende de M
