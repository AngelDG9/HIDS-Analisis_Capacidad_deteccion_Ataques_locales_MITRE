# -*- coding: utf-8 -*-
"""Tests unitarios de `extraer_tecnicas_host.py` sobre el fixture sintético.

Fixture: `tests/fixtures/stix_mini.json` (bundle mínimo con la cadena
DET→AN→DC real de T1039, T1486, T1046, T1595, T1059, T1074, una subtécnica
y una técnica deprecada).
"""
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import extraer_tecnicas_host as eth  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "stix_mini.json"


@pytest.fixture(scope="module")
def rows():
    return eth.extract_corpus(FIXTURE)


@pytest.fixture(scope="module")
def rows_by_id(rows):
    return {r["tecnica_id"]: r for r in rows}


# --- R-03: casos conocidos -------------------------------------------------
def test_ransomware_T1486_yes(rows_by_id):
    """T1486 Data Encrypted for Impact → host_eligible=YES y P1."""
    r = rows_by_id["T1486"]
    assert r["host_eligible"] == "YES"
    assert r["priority"] == "P1"
    assert r["dc_host"] >= 1
    assert r["motivo"] == "ok"


def test_command_interpreter_T1059_yes(rows_by_id):
    """T1059 Command and Scripting Interpreter → YES."""
    r = rows_by_id["T1059"]
    assert r["host_eligible"] == "YES"
    assert r["dc_host"] >= 1


def test_scan_T1595_no(rows_by_id):
    """T1595 Active Scanning: solo DC de red pura → NO / solo_red."""
    r = rows_by_id["T1595"]
    assert r["host_eligible"] == "NO"
    assert r["motivo"] == "solo_red"
    assert r["dc_host"] == 0
    assert r["dc_red"] >= 1


def test_network_discovery_T1046_hybrid_yes(rows_by_id):
    """T1046 Network Service Discovery en v19.1 es HÍBRIDA → YES.

    DESVIACIÓN DOCUMENTADA RESPECTO AL PLAN v2: el plan esperaba
    `host_eligible=NO` / `motivo=solo_red` para T1046 (suposición válida en
    versiones antiguas de ATT&CK). En el STIX v19.1 real, la Detection Strategy
    DET0376 → AN1057/1058/1059/1060 incluye **DC0032 Process Creation**
    (telemetría endpoint). Aplicando la interpretación amplia fijada
    (2026-09-19), T1046 resulta `YES` con motivo `ok` (es híbrida red+host).
    El caso "solo red → NO" queda cubierto por `test_scan_T1595_no`.
    """
    r = rows_by_id["T1046"]
    assert r["host_eligible"] == "YES"
    assert r["motivo"] == "ok"
    assert r["dc_host"] >= 1
    assert r["dc_red"] >= 1


# --- Deprecadas ------------------------------------------------------------
def test_deprecated_excluded(rows_by_id):
    """Las técnicas deprecated/revoked no se incluyen en el corpus."""
    assert "T9001" not in rows_by_id


# --- Herencia de subtécnicas ----------------------------------------------
def test_subtechnique_inherits_parent(rows_by_id):
    """Subtécnica sin detects propio hereda el padre de forma explícita."""
    r = rows_by_id["T1486.001"]
    assert r["es_subtecnica"] == "si"
    assert r["padre_id"] == "T1486"
    assert r["heredado_padre"] == "si"
    assert r["host_eligible"] == "YES"
    assert r["priority"] == "P1"
    assert "File Modification" in r["data_components"]


# --- Cadena v19 (DET→AN→DC) ------------------------------------------------
def test_T1039_detection_strategy_chain(rows_by_id):
    """T1039 → DET0410 → AN1145 → DC0102/39/55/54 → YES pese al DC de red."""
    r = rows_by_id["T1039"]
    assert r["host_eligible"] == "YES"
    assert r["dc_host"] >= 1
    assert r["dc_red"] >= 1
    for dc in ("Network Share Access", "File Creation", "File Access", "Drive Access"):
        assert dc in r["data_components"]
    # T1039 es de la táctica Collection → P1
    assert r["priority"] == "P1"


# --- Fallback de dirección de relación (DC↔pattern) ------------------------
def test_relationship_direction(rows_by_id):
    """`detects` directo DC↔pattern (fallback 5b) da el mismo resultado."""
    r = rows_by_id["T1074"]
    assert r["host_eligible"] == "YES"
    assert "File Modification" in r["data_components"]
    assert r["heredado_padre"] == "no"


# --- Cabecera con versión --------------------------------------------------
def test_collection_header(rows, tmp_path):
    """La cabecera del CSV indica la versión STIX (19.1)."""
    out = eth.write_csv(rows, tmp_path / "corpus_host.csv", version="19.1", fecha="2026-09-19")
    first_line = out.read_text(encoding="utf-8").splitlines()[0]
    assert "19.1" in first_line


def test_version_from_collection(rows):
    """Todas las filas llevan la versión del `x-mitre-collection`."""
    assert rows
    assert {r["stix_version"] for r in rows} == {"19.1"}
