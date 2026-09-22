# -*- coding: utf-8 -*-
"""Tests de integración sobre el STIX v19.1 real descargado.

Se saltan si el fichero no existe (p. ej. en un clon limpio, ya que el JSON
está en `.gitignore`). Regenerar con:

    python _artefactos/scripts/extraer_tecnicas_host.py --csv-only
"""
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import extraer_tecnicas_host as eth  # noqa: E402

STIX = Path(__file__).resolve().parents[2] / "mitre" / "enterprise-attack-v19.1.json"

pytestmark = pytest.mark.skipif(
    not STIX.exists(), reason="STIX v19.1 no descargado (gitignored)"
)


@pytest.fixture(scope="module")
def rows_by_id():
    return {r["tecnica_id"]: r for r in eth.extract_corpus(STIX)}


def test_real_version_19_1(rows_by_id):
    assert rows_by_id
    assert {r["stix_version"] for r in rows_by_id.values()} == {"19.1"}


def test_real_T1486_yes(rows_by_id):
    r = rows_by_id["T1486"]
    assert r["host_eligible"] == "YES"
    assert r["priority"] == "P1"


def test_real_T1595_no(rows_by_id):
    """T1595 Active Scanning es red pura → NO / solo_red."""
    r = rows_by_id["T1595"]
    assert r["host_eligible"] == "NO"
    assert r["motivo"] == "solo_red"


def test_real_T1046_hybrid_yes(rows_by_id):
    """T1046 en v19.1 es híbrida (Process Creation + red) → YES.

    DESVIACIÓN DOCUMENTADA respecto al plan v2 (que esperaba NO). Ver
    `test_network_discovery_T1046_hybrid_yes` en los tests unitarios.
    """
    r = rows_by_id["T1046"]
    assert r["host_eligible"] == "YES"
    assert r["dc_host"] >= 1
    assert r["dc_red"] >= 1


def test_real_T1039_yes(rows_by_id):
    """T1039 → DET0410 → AN1145/6/7 → DC0102/39/55/54."""
    r = rows_by_id["T1039"]
    assert r["host_eligible"] == "YES"
    for dc in ("Network Share Access", "File Creation", "File Access", "Drive Access"):
        assert dc in r["data_components"]
