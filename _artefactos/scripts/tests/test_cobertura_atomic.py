# -*- coding: utf-8 -*-
"""Tests offline de `cobertura_atomic.py` (bloque fase-03-atomic, A2.3).

Cubren los **casos a-e de §8.2** del plan, con fixtures pequeños bajo
`tests/fixtures/atomic_repo/` (un clon ART en miniatura) y un corpus de
fixture. **No necesitan VMs ni red** y no ejecutan ninguna prueba atómica.
"""
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import cobertura_atomic as ca  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CORPUS = FIXTURES / "atomic_corpus.csv"
ART = FIXTURES / "atomic_repo"


def _build(corpus_rows=None):
    idx = ca.index_dir(ART)
    return ca.build_coverage(
        corpus_rows if corpus_rows is not None else ca.load_corpus(CORPUS),
        ca.load_index(idx / "index.csv"),
        ca.load_index(idx / "linux-index.csv"),
        ca.load_index(idx / "windows-index.csv"),
        ART / "atomics",
    )


def _by_id(rows):
    return {r["ata_id"]: r for r in rows}


# --- (a) técnica cubierta --------------------------------------------------
def test_case_a_covered_T1486():
    r = _by_id(_build())["ATA001"]
    assert r["tecnica"] == "T1486"
    assert r["prueba_art"] == "sí"
    assert r["tests_linux"] == 2
    assert r["tests_windows"] == 1
    assert r["path"] == "atomics/T1486"
    assert r["nota"] == "cubierta"


# --- (b) sin pruebas en ART ------------------------------------------------
def test_case_b_no_tests_T1561():
    r = _by_id(_build())["ATA005"]
    assert r["tecnica"] == "T1561"
    assert r["prueba_art"] == "no"
    assert r["tests_linux"] == 0
    assert r["tests_windows"] == 0
    assert r["path"] == ""
    assert r["nota"] == "sin_pruebas"


# --- (c) solo Windows ------------------------------------------------------
def test_case_c_windows_only_T1490():
    r = _by_id(_build())["ATA003"]
    assert r["tecnica"] == "T1490"
    assert r["prueba_art"] == "sí"
    assert r["tests_linux"] == 0
    assert r["tests_windows"] == 2
    assert r["nota"] == "solo_windows"


# --- (d) falta el índice / clon -> exit != 0 ------------------------------
def test_case_d_missing_clone(tmp_path, capsys):
    rc = ca.main(
        [
            "--art",
            str(tmp_path / "no-existe"),
            "--corpus",
            str(CORPUS),
            "--out",
            str(tmp_path / "out.csv"),
        ]
    )
    assert rc != 0
    assert not (tmp_path / "out.csv").exists()
    err = capsys.readouterr().err
    assert "Atomic Red Team" in err


def test_case_d_missing_index(tmp_path, capsys):
    # Clon con `atomics/` pero sin los índices CSV.
    (tmp_path / "atomics" / "Indexes" / "Indexes-CSV").mkdir(parents=True)
    rc = ca.main(
        [
            "--art",
            str(tmp_path),
            "--corpus",
            str(CORPUS),
            "--out",
            str(tmp_path / "out.csv"),
        ]
    )
    assert rc != 0
    assert not (tmp_path / "out.csv").exists()
    assert "índice" in capsys.readouterr().err


# --- (e) orden estable por ata_id ------------------------------------------
def test_case_e_stable_order():
    rows = _build()
    ids = [r["ata_id"] for r in rows]
    assert ids == sorted(ids)
    assert ids == ["ATA001", "ATA003", "ATA005", "ATA007", "ATA008"]


def test_case_e_order_independent_of_input_order():
    corpus = ca.load_corpus(CORPUS)
    assert _build(corpus) == _build(list(reversed(corpus)))


# --- Semántica de subtecnicas ----------------------------------------------
def test_subtechniques_included_in_counts():
    r = _by_id(_build())["ATA008"]
    assert r["tecnica"] == "T1048"
    assert r["tests_linux"] == 3  # 2 de T1048 + 1 de T1048.002
    assert r["tests_windows"] == 0
    assert r["path"] == "atomics/T1048;atomics/T1048.002"
    assert r["nota"] == "solo_linux"


def test_subtechnique_only_path():
    # T1491 solo tiene el directorio de la subtecnica T1491.001.
    r = _by_id(_build())["ATA007"]
    assert r["path"] == "atomics/T1491.001"
    assert r["nota"] == "solo_windows"


# --- Determinismo del CSV ---------------------------------------------------
def test_csv_deterministic_bytes(tmp_path):
    rows = _build()
    a = ca.write_coverage(rows, tmp_path / "a.csv")
    b = ca.write_coverage(_build(), tmp_path / "b.csv")
    assert a.read_bytes() == b.read_bytes()


def test_csv_header(tmp_path):
    out = ca.write_coverage(_build(), tmp_path / "c.csv")
    header = out.read_text(encoding="utf-8").splitlines()[0]
    assert header == "ata_id,tecnica,nombre,prueba_art,tests_linux,tests_windows,path,nota"


def test_corpus_skips_comment_line():
    rows = ca.load_corpus(CORPUS)
    assert len(rows) == 5
    assert rows[0]["ata_id"] == "ATA001"
