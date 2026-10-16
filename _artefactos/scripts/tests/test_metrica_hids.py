# -*- coding: utf-8 -*-
"""Tests de `metrica_hids.py` (módulo congelado) — bloque `reencuadre-metrica` (R2).

Fija cada fórmula con vectores conocidos, los casos límite (denominador 0) y prohíbe
que otro script reimplemente las fórmulas (deben importarlas de `metrica_hids`).
"""
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import metrica_hids as M  # noqa: E402


def test_constantes_congeladas():
    assert M.VERSION_METRICA == 1
    assert M.N_CASOS == 55
    assert M.UMBRALES == (0, 3, 7, 10, 12)
    assert M.CONFIGS["C0"] == ("RS1",)
    assert M.CONFIGS["C1"] == ("RS1", "RS2")
    assert M.CONFIGS["C2"] == ("RS1", "RS2", "RS3")
    assert M.CONFIGS["C3"] == ("RS1", "RS2", "RS3", "RS4")
    assert M.CATEGORIAS == (
        "deteccion",
        "ruido_conocido",
        "auto_ruido",
        "dudosa",
        "artefacto_ataque",
    )


def test_tpr():
    assert M.tpr(0, 55) == 0.0
    assert M.tpr(53, 55) == pytest.approx(53 / 55)
    assert M.tpr(1, 0) == 0.0  # denominador 0 -> 0.0 (hermano)


def test_fpr_tnr():
    assert M.fpr(1, 4) == pytest.approx(0.25)
    assert M.fpr(0, 4) == 0.0
    assert M.fpr(1, 0) is None
    assert M.fpr(1, None) is None
    assert M.fpr(1, "n/a") is None
    assert M.tnr(0.25) == pytest.approx(0.75)
    assert M.tnr(None) is None


def test_precision():
    assert M.precision(1, 0) == 1.0
    assert M.precision(1, 1) == pytest.approx(0.5)
    assert M.precision(0, 0) == 0.0
    assert M.precision(3, 1) == pytest.approx(0.75)


def test_f1():
    assert M.f1(1, 1) == 1.0
    assert M.f1(0.5, 0.5) == pytest.approx(0.5)
    assert M.f1(0, 0) == 0.0
    assert M.f1(0.5, 1.0) == pytest.approx(2 * 0.5 * 1.0 / 1.5)


def test_gm():
    assert M.gm(1, 1) == pytest.approx(1.0)
    assert M.gm(0.5, 0.5) == pytest.approx(0.5)
    assert M.gm(0.0, 1.0) == 0.0
    assert M.gm(0.5, None) is None
    assert M.gm(1, 0) == 0.0


def test_usabilidad():
    assert M.usabilidad(0, 5) == 0.0
    assert M.usabilidad(5, 0) == 0.0  # a_tp=0 -> 0.0 (hermano)
    assert M.usabilidad(1, 2) == pytest.approx(0.5)


def test_ventanas():
    rep = {"ATA001", "ATA014"}
    assert M.ventana_canonica("ATA001", rep) == "rev1"
    assert M.ventana_canonica("ATA002", rep) == "iter1"
    assert M.ventana_control("ATA001", rep) == "rev2"
    assert M.ventana_control("ATA002", rep) == "iter2"


def test_pruning_variantes():
    activos = {"1", "2", "3"}
    leg = {"2": 600, "3": 10}
    assert M.reglas_pruning_no_pruning(activos) == activos
    assert M.reglas_pruning_n(activos, leg, 500) == {"1", "3"}  # quita 2 (600 > 500)
    assert M.reglas_pruning_n(activos, leg, 1000) == activos
    assert M.reglas_pruning_conservative(activos, {"2", "3"}, {"1"}) == {"1"}  # quita 2 (FP exclusivo)
    assert M.reglas_pruning_generalized(activos, {"2", "3"}) == {"1"}  # quita todas las FP
    assert len(M.PRUNING_VARIANTES) == 6


def test_formato():
    assert M.fmt_ratio(1 / 3) == "0.333333"
    assert M.fmt_ratio(None) == ""
    assert M.fmt_pct(0.5) == "0.5000"
    assert M.fmt_usab(25) == "25.0000"
    assert M.fmt_det(100) == "100.00"
    assert M.fmt_det(3.63636) == "3.64"


def test_modulo_sin_main():
    assert not hasattr(M, "main")


@pytest.mark.parametrize(
    "script",
    [
        "tabla1_clasificacion.py",
        "tabla2_ataques.py",
        "tabla3_legitimo.py",
        "tabla4_rendimiento.py",
        "tabla5_pruning.py",
        "requisitos_leyenda.py",
    ],
)
def test_scripts_importan_metrica(script):
    """Ningún script reimplementa las fórmulas: todas importan `metrica_hids`."""
    src = (SCRIPTS / script).read_text(encoding="utf-8")
    assert "import metrica_hids as M" in src
    for fn in ("def tpr", "def fpr", "def gm", "def f1", "def precision"):
        assert fn not in src, f"{script} reimplementa {fn}"
