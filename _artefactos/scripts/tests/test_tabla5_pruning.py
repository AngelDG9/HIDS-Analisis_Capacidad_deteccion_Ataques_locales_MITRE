# -*- coding: utf-8 -*-
"""Tests de `tabla5_pruning.py` — T5 (pruning) · R2.

Comprueba la **selección de reglas** de las variantes (No Pruning, Conservative,
Generalized, Pruning N) y el **TPR** recalculado, con un corpus sintético. Las columnas
que dependen del legítimo (`GM`, `#Alertas_FP`, `Usabilidad`) quedan vacías (declarado).
"""
from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import tabla5_pruning as T5  # noqa: E402

AUD_HEADER = ["ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level",
              "rule_groups", "rs_origen", "rule_description", "categoria", "motivo",
              "atribucion", "revision", "veredicto_humano", "evidencia"]


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _setup(tmp_path):
    aud = tmp_path / "Auditado"
    for ata in ("ATA900", "ATA901"):
        _escribir(aud / f"{ata}_iter1-Audited.csv", AUD_HEADER,
                  [(ata, 1, "2026-01-01T00:00:10Z", "victima-linux", "80792", 3,
                    "audit|audit_command", "RS2", "d", "deteccion", "", "", "", "", "")])
    rep = tmp_path / "repeticiones.csv"
    _escribir(rep, ["ata_id"], [])
    t2 = tmp_path / "T2.csv"
    _escribir(t2, ["ata_id", "config", "umbral", "Detection", "#Alertas"], [("ATA900", "C1", 0, "SÍ", 1)])
    # detalle legitimO: 80791 (FP-only) y 80792 (mixta)
    t3 = tmp_path / "T3.csv"
    _escribir(t3, ["seccion", "config", "umbral", "rule.id", "#alertas_correlacionadas"],
              [("detalle_ruleid", "C1", 0, "80791", 100), ("detalle_ruleid", "C1", 0, "80792", 5)])
    return aud, rep, t2, t3


def _leer(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_variantes(tmp_path):
    aud, rep, t2, t3 = _setup(tmp_path)
    out = tmp_path / "T5.csv"
    steps = tmp_path / "T5s.csv"
    assert T5.main(["--t2", str(t2), "--t3", str(t3), "--auditado", str(aud),
                    "--repeticiones", str(rep), "--out", str(out), "--steps", str(steps)]) == 0
    filas = {f["variante"]: f for f in _leer(out) if f["config"] == "C1" and f["umbral"] == "0"}
    assert filas["No Pruning"]["#reglas_quitadas"] == "0"
    assert filas["Conservative"]["#reglas_quitadas"] == "1"
    assert filas["Conservative"]["lista_rule.id_quitados"] == "80791"
    assert filas["Generalized Conservative"]["#reglas_quitadas"] == "2"  # quita ambas
    # leg_diff 80791=100, 80792=5 -> ninguno > 500 -> Pruning 500 quita 0
    assert filas["Pruning 500"]["#reglas_quitadas"] == "0"
    assert filas["No Pruning"]["%Deteccion_casos"] == "100.00"
    # GM/FP vacíos (legítimo L1)
    assert filas["No Pruning"]["GM"] == ""
    assert filas["No Pruning"]["#Alertas_FP"] == ""
