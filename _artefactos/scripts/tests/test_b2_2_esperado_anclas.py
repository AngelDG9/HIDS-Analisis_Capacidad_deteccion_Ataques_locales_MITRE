# -*- coding: utf-8 -*-
"""Tests de B2.2: anclas H4-W de los `esperado` (ATA093-ATA097).

Regresion del defecto detectado en la prep de B2.2: los patrones S3/S4 se
sellaron con `ATAATA<NNN>` (placeholder mal sustituido), de modo que el ancla
nunca casaba y toda evidencia de proceso caia a `sin_ancla` (`deteccion=0`).

Cubren:
- ningun `esperado` Windows contiene el typo `ATAATA`;
- S3 = `*lab-attack*ATA<NNN>*` y S4 = `C:\\lab-attack\\ATA<NNN>\\*`;
- el ancla S3 casa con la linea sintetica `cmd /c C:\\lab-attack\\ATA<NNN>\\run.cmd`;
- `win_image` sigue siendo `powershell.exe`/`cmd.exe` y no se anade `rule_id`;
- `sha256(esperado) == pre_registro.sha256`.
"""
import csv
import hashlib
import re
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import filtrar_ruido_windows as F  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "Dataset" / "Ataques" / "Comandos" / "windows"

CASES = {
    "ATA093": "T1560.002-Archive_via_Library",
    "ATA094": "T1560.003-Archive_via_Custom_Method",
    "ATA095": "T1565.001-Stored_Data_Manipulation",
    "ATA096": "T1565.002-Transmitted_Data_Manipulation",
    "ATA097": "T1565.003-Runtime_Data_Manipulation",
}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _rows(path):
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_ningun_esperado_windows_con_typo_ataata():
    """Candado global: el placeholder `ATAATA` no puede volver a sellarse."""
    malos = []
    for path in BASE.glob("*/*_esperado.csv"):
        txt = path.read_text(encoding="utf-8")
        if "ATAATA" in txt:
            malos.append(str(path.relative_to(ROOT)))
    assert malos == [], f"esperado con typo ATAATA: {malos}"


def test_anclas_s3_s4_exactas_y_casan():
    for ata, carpeta in CASES.items():
        path = BASE / carpeta / f"{ata}_esperado.csv"
        rows = _rows(path)
        s3 = [r for r in rows if r["senal_id"].endswith("-S3")]
        s4 = [r for r in rows if r["senal_id"].endswith("-S4")]
        assert len(s3) == 1 and len(s4) == 1, ata
        s3, s4 = s3[0], s4[0]

        assert s3["campo"] == "win_command_line" and s3["tipo"] == "deteccion", ata
        assert s4["campo"] == "syscheck_path" and s4["tipo"] == "ambigua", ata
        assert s3["patron"] == f"*lab-attack*{ata}*", (ata, s3["patron"])
        assert s4["patron"] == f"C:\\lab-attack\\{ata}\\*", (ata, s4["patron"])

        # el ancla casa con la linea real que genera run.cmd
        synth = f"cmd /c C:\\lab-attack\\{ata}\\run.cmd"
        assert F.glob_match(synth, s3["patron"]), (ata, synth)
        # y con la invocacion literal del script
        synth2 = f'powershell  -NoProfile -ExecutionPolicy Bypass -File "C:\\lab-attack\\{ata}\\{ata}_ataque.ps1"'
        assert F.glob_match(synth2, s3["patron"]), (ata, synth2)

        # win_image intacta
        imagenes = [r["patron"] for r in rows if r["campo"] == "win_image"]
        assert imagenes == ["powershell.exe", "cmd.exe"], (ata, imagenes)
        # sin columna rule_id
        assert "rule_id" not in rows[0], ata


def test_sha256_esperado_coincide_con_pre_registro():
    for ata, carpeta in CASES.items():
        caso = BASE / carpeta
        esp = caso / f"{ata}_esperado.csv"
        pr = caso / f"{ata}_pre_registro.sha256"
        txt = pr.read_text(encoding="utf-8")
        m = re.search(r"sha256=([0-9a-f]{64})", txt)
        assert m, f"{ata}: pre_registro sin sha256"
        assert m.group(1) == _sha(esp), f"{ata}: sha256 no coincide"
        assert re.search(r"timestamp_utc=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", txt), ata
