# -*- coding: utf-8 -*-
"""Tests offline de `inventario_p1_windows.py` (bloque fase-02b-diseno, T-W2).

Cubren el cálculo puro con un **corpus de fixture** y el `windows-index.csv`
del clon ART en miniatura de `fixtures/atomic_repo/`. **No necesitan VMs, ni
red, ni el corpus real** y no ejecutan ninguna prueba atómica.
"""
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import inventario_p1_windows as inv  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CORPUS = FIXTURES / "inventario_windows_corpus.csv"
ART = FIXTURES / "atomic_repo"


def _build():
    return inv.build_inventory(inv.load_corpus(CORPUS), inv.load_windows_index(ART))


def _by_id(rows):
    return {r["tecnica_id"]: r for r in rows}


# --- Selección de la piscina -----------------------------------------------
def test_only_p1_host_eligible():
    rows = _build()
    ids = {r["tecnica_id"] for r in rows}
    # P2 (T1003) y host_eligible=NO (T1046) quedan fuera.
    assert ids == {"T1486", "T1490", "T1557.001", "T1213.001", "T1530"}
    assert len(rows) == 5


# --- Columnas de plataforma -------------------------------------------------
def test_hibrida_linux_windows_factible_art():
    r = _by_id(_build())["T1486"]
    assert r["es_p1_linux"] == "sí"
    assert r["p1_sin_linux"] == "no"
    assert r["host_windows"] == "sí"
    assert r["tiene_prueba_art_windows"] == "sí"
    assert r["factibilidad"] == "factible"
    assert r["via"] == "ART"


def test_windows_only_factible():
    r = _by_id(_build())["T1557.001"]
    assert r["es_p1_linux"] == "no"
    assert r["p1_sin_linux"] == "sí"
    assert r["host_windows"] == "sí"
    assert r["factibilidad"] == "factible"
    # Sin prueba ART Windows (nuestro fixture no la trae) -> ataque propio.
    assert r["tiene_prueba_art_windows"] == "no"
    assert r["via"] == "propia"
    # Alineación con el plan §4.2: T1213.002 (SaaS) -> no factible;
    # T1114.002 (Exchange/nube) -> baja factibilidad (no "factible").
    corpus = [
        {"tecnica_id": "T1213.002", "plataformas": "Office Suite;Windows",
         "priority": "P1", "host_eligible": "YES"},
        {"tecnica_id": "T1114.002", "plataformas": "Office Suite;Windows",
         "priority": "P1", "host_eligible": "YES"},
    ]
    by = {x["tecnica_id"]: x for x in inv.build_inventory(corpus, [])}
    assert by["T1213.002"]["factibilidad"] == "no factible"
    assert by["T1213.002"]["via"] == "-"
    assert "SaaS" in by["T1213.002"]["motivo"]
    assert by["T1114.002"]["factibilidad"] == "baja factibilidad"
    assert by["T1114.002"]["via"] == "propia"
    assert "Exchange" in by["T1114.002"]["motivo"]


def test_saas_no_factible():
    r = _by_id(_build())["T1213.001"]
    assert r["p1_sin_linux"] == "sí"
    assert r["host_windows"] == "no"
    assert r["factibilidad"] == "no factible"
    assert r["via"] == "-"
    assert "SaaS" in r["motivo"]


def test_iaas_no_factible():
    r = _by_id(_build())["T1530"]
    assert r["factibilidad"] == "no factible"
    assert "nube" in r["motivo"].lower() or "IaaS" in r["motivo"]


# --- Detección de prueba ART Windows (subtecnicas incluidas) ----------------
def test_art_windows_incluye_subtecnica():
    # T1490 tiene 2 pruebas Windows; T1486 tiene 1; T1486 no.
    r = _by_id(_build())["T1490"]
    assert r["tiene_prueba_art_windows"] == "sí"


def test_art_windows_ausente():
    # T1486 del fixture solo tiene prueba Windows; T1213.001 (SaaS) no aplica,
    # así que se comprueba un id factible sin prueba.
    assert _by_id(_build())["T1557.001"]["tiene_prueba_art_windows"] == "no"


def test_distinct_art_windows_counts_guids():
    rows = inv.load_windows_index(ART)
    # T1490 tiene 2 filas de GUID distinto en el fixture.
    assert inv.distinct_art_windows_tests(rows, "T1490") == 2
    assert inv.distinct_art_windows_tests(rows, "T1486") == 1
    assert inv.distinct_art_windows_tests(rows, "T1561") == 0
    # Titular matizado: contar subtecnicas vs test propio de la tecnica exacta.
    assert inv.exact_art_techniques(rows) == {"T1486", "T1490", "T1491.001"}
    assert inv.con_art_windows_exacto(
        [{"tecnica_id": "T1486"}, {"tecnica_id": "T1490"}, {"tecnica_id": "T1491"}], rows
    ) == 2  # T1491 solo cuenta por subtecnica (T1491.001) -> no exacta


# --- Resumen y determinismo -------------------------------------------------
def test_resumen_cuadre():
    res = inv.resumen(_build())
    assert res == {
        "total": 5,
        "p1_linux": 2,       # T1486, T1490
        "p1_sin_linux": 3,   # T1557.001, T1213.001, T1530
        "host_windows_only": 1,  # T1557.001
        "no_factible": 2,    # T1213.001, T1530
        "baja_factibilidad": 0,
        "con_art_windows": 2,  # T1486, T1490 (ambas hibridas)
        "art_win_hibridas": 2,
        "art_win_wonly": 0,  # T1557.001 no tiene prueba ART Windows en el fixture
    }


def test_csv_deterministic_bytes(tmp_path):
    rows = _build()
    res = inv.resumen(rows)
    a = inv.write_inventory(rows, res, tmp_path / "a.csv")
    b = inv.write_inventory(_build(), inv.resumen(_build()), tmp_path / "b.csv")
    assert a.read_bytes() == b.read_bytes()


def test_csv_header_y_comentario(tmp_path):
    rows = _build()
    out = inv.write_inventory(rows, inv.resumen(rows), tmp_path / "c.csv")
    lines = out.read_text(encoding="utf-8").splitlines()
    # Cabecera de comentario + cabecera real.
    assert lines[0].startswith("# inventario_p1_windows.csv")
    header = [ln for ln in lines if not ln.startswith("#")][0]
    assert header == ",".join(inv.HEADER_COLUMNS)


def test_corpus_skips_comment_line():
    rows = inv.load_corpus(CORPUS)
    assert len(rows) == 7


def test_falta_indice_windows(tmp_path, capsys):
    rc = inv.main([
        "--art", str(tmp_path / "no-existe"),
        "--corpus", str(CORPUS),
        "--out", str(tmp_path / "out.csv"),
    ])
    assert rc != 0
    assert not (tmp_path / "out.csv").exists()
