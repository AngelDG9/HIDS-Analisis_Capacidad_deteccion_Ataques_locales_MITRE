# -*- coding: utf-8 -*-
"""Tests de `tabla5_pruning.py` — T5 (pruning) · R2 + L2.

Comprueba la **selección de reglas** de las variantes (No Pruning, Conservative,
Generalized, Pruning N), el **TPR** recalculado y —desde L2— las columnas que dependen
del legítimo (`GM`, `#Alertas_FP`, `Usabilidad`) y el **`Aggressive (G-Mean)` real**
(parte de Conservative; quita mixtas solo si el GM mejora; empate -> conservar).
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
    # detalle legítimo: 80791 (FP-only) y 80792 (mixta)
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
    # Sin `M` en T3: GM/TNR no publicables; A_FP sí (0, el detalle no trae conteos)
    assert filas["No Pruning"]["GM"] == ""
    assert filas["No Pruning"]["#Alertas_FP"] == "0"
    assert filas["No Pruning"]["Usabilidad"] == "0.0000"


def test_columnas_legitimo_y_aggressive(tmp_path):
    """Con `M` y conteos: GM/A_FP/Usabilidad completos y Aggressive real."""
    aud = tmp_path / "Auditado"
    # ATA900 y ATA901 los detecta 80792; ATA901 además 80791
    _escribir(aud / "ATA900_iter1-Audited.csv", AUD_HEADER,
              [("ATA900", 1, "t", "v", "80792", 3, "audit", "RS2", "d", "deteccion", "", "", "", "", "")])
    _escribir(aud / "ATA901_iter1-Audited.csv", AUD_HEADER,
              [("ATA901", 1, "t", "v", "80792", 3, "audit", "RS2", "d", "deteccion", "", "", "", "", ""),
               ("ATA901", 1, "t", "v", "80791", 3, "audit", "RS2", "d", "deteccion", "", "", "", "", "")])
    rep = tmp_path / "rep.csv"
    _escribir(rep, ["ata_id"], [])
    t2 = tmp_path / "T2.csv"
    _escribir(t2, ["ata_id", "config", "umbral", "Detection", "#Alertas"],
              [("ATA900", "C1", 0, "SÍ", 1), ("ATA901", "C1", 0, "SÍ", 2)])
    t3 = tmp_path / "T3.csv"
    header = ["seccion", "config", "umbral", "#Unidades", "rule.id",
              "#alertas_legitimas", "#unidades_con_la_regla", "#alertas_correlacionadas"]
    _escribir(t3, header, [
        ("agregado", "C1", 0, 1000, "", "", "", ""),
        ("detalle_ruleid", "C1", 0, "", "80780", 100, 100, 100),
        ("detalle_ruleid", "C1", 0, "", "80791", 600, 600, 600),
        ("detalle_ruleid", "C1", 0, "", "80792", 5, 5, 5),
    ])
    out, steps = tmp_path / "T5.csv", tmp_path / "T5s.csv"
    assert T5.main(["--t2", str(t2), "--t3", str(t3), "--auditado", str(aud),
                    "--repeticiones", str(rep), "--out", str(out), "--steps", str(steps)]) == 0
    filas = {f["variante"]: f for f in _leer(out) if f["config"] == "C1" and f["umbral"] == "0"}

    # No Pruning: FP = 100+600+5 = 705; TNR = 1-0.705 = 0.295; GM = sqrt(0.295)
    assert filas["No Pruning"]["#Alertas_FP"] == "705"
    assert filas["No Pruning"]["GM"] == "0.543139"
    assert filas["No Pruning"]["Usabilidad"] == "235.0000"  # 705 / A_TP^c=3
    # Conservative quita 80780: FP = 605
    assert filas["Conservative"]["#Alertas_FP"] == "605"
    assert filas["Conservative"]["GM"] == "0.628490"
    # Aggressive: quita 80780 (FP-only) y 80791 (mixta, mejora GM); CONSERVA 80792
    assert filas["Aggressive (G-Mean)"]["#reglas_quitadas"] == "2"
    assert filas["Aggressive (G-Mean)"]["lista_rule.id_quitados"] == "80780 80791"
    assert filas["Aggressive (G-Mean)"]["#Alertas_FP"] == "5"
    assert filas["Aggressive (G-Mean)"]["%Deteccion_casos"] == "100.00"
    assert filas["Aggressive (G-Mean)"]["GM"] == "0.997497"

    # steps: solo las reglas quitadas, con TNR/GM/A_FP rellenos
    st = [r for r in _leer(steps) if r["config"] == "C1" and r["umbral"] == "0"]
    assert [r["rule.id_quitado"] for r in st] == ["80780", "80791"]
    assert st[-1]["TNR"] == "0.995000"
    assert st[-1]["GM"] == "0.997497"
    assert st[-1]["FP_unidades"] == "5"


def test_aggressive_empate_conserva(tmp_path):
    """Quitar una mixta con impacto 0 en el legítimo deja el GM igual -> se conserva."""
    aud = tmp_path / "Auditado"
    _escribir(aud / "ATA900_iter1-Audited.csv", AUD_HEADER,
              [("ATA900", 1, "t", "v", "80781", 3, "audit", "RS2", "d", "deteccion", "", "", "", "", ""),
               ("ATA900", 1, "t", "v", "12345", 3, "audit", "RS2", "d", "deteccion", "", "", "", "", "")])
    rep = tmp_path / "rep.csv"
    _escribir(rep, ["ata_id"], [])
    t2 = tmp_path / "T2.csv"
    _escribir(t2, ["ata_id", "config", "umbral", "Detection", "#Alertas"], [("ATA900", "C1", 0, "SÍ", 2)])
    t3 = tmp_path / "T3.csv"
    header = ["seccion", "config", "umbral", "#Unidades", "rule.id",
              "#alertas_legitimas", "#unidades_con_la_regla", "#alertas_correlacionadas"]
    _escribir(t3, header, [
        ("agregado", "C1", 0, 100, "", "", "", ""),
        ("detalle_ruleid", "C1", 0, "", "80781", 0, 0, 0),
    ])
    out, steps = tmp_path / "T5.csv", tmp_path / "T5s.csv"
    assert T5.main(["--t2", str(t2), "--t3", str(t3), "--auditado", str(aud),
                    "--repeticiones", str(rep), "--out", str(out), "--steps", str(steps)]) == 0
    filas = {f["variante"]: f for f in _leer(out) if f["config"] == "C1" and f["umbral"] == "0"}
    # GM = sqrt(1 * (1 - 0/100)) = 1.0 antes y después -> empate -> conservar
    assert filas["Conservative"]["GM"] == "1.000000"
    assert filas["Aggressive (G-Mean)"]["lista_rule.id_quitados"] == ""
    assert filas["Aggressive (G-Mean)"]["GM"] == "1.000000"
