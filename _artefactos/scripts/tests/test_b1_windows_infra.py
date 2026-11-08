# -*- coding: utf-8 -*-
"""Tests de B1.0: índice Windows (CA-B1-01) y plantilla de esperado v5."""
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[3]
INDEX = ROOT / "Hojas" / "ATA_index_windows.csv"
PLANTILLA = ROOT / "Soporte" / "Ataques" / "plantilla_esperado.md"


def _rows(path):
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_indice_windows_32_filas_ata056_087():
    rows = _rows(INDEX)
    assert len(rows) == 32
    ids = [r["ata_id"] for r in rows]
    assert ids == [f"ATA{i:03d}" for i in range(56, 88)]
    assert list(rows[0].keys()) == [
        "ata_id", "tactica", "tecnica", "descripcion", "artefacto", "estado", "plataforma"
    ]
    assert {r["plataforma"] for r in rows} == {"windows"}
    assert {r["estado"] for r in rows} == {"previsto"}
    assert sum(1 for r in rows if r["tactica"] == "Impact") == 13
    assert sum(1 for r in rows if r["tactica"] == "Exfiltration") == 10
    assert sum(1 for r in rows if r["tactica"] == "Collection") == 9


def test_plantilla_esperado_v5_aditiva():
    txt = PLANTILLA.read_text(encoding="utf-8")
    assert "version: 5" in txt
    assert "H4-W" in txt
    assert "win_image" in txt and "win_command_line" in txt and "win_cwd" in txt
    # El esquema de 7 columnas no se rompe.
    assert "senal_id,tipo,campo,patron,dato_componente,tecnica,nota" in txt
