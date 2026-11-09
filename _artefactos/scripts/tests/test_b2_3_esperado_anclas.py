# -*- coding: utf-8 -*-
"""Tests de B2.3: anclas H4-W y guardarrail VHD (ATA098-ATA102).

Cubren:
- S3 = `*lab-attack*ATA<NNN>*` y S4 = `C:\\lab-attack\\ATA<NNN>\\*`;
- el ancla S3 casa con `cmd /c C:\\lab-attack\\ATA<NNN>\\run.cmd`;
- `win_image` = `powershell.exe`/`cmd.exe`, sin `rule_id`;
- `sha256(esperado) == pre_registro.sha256`;
- cada `ataque.ps1` fija el VHD exacto del caso y no usa `\\\\.\\PhysicalDrive`.
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
    "ATA098": "T1561-Disk_Wipe",
    "ATA099": "T1561.001-Disk_Content_Wipe",
    "ATA100": "T1561.002-Disk_Structure_Wipe",
    "ATA101": "T1025-Data_from_Removable_Media",
    "ATA102": "T1052.001-Exfiltration_over_USB",
}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _rows(path):
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


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

        synth = f"cmd /c C:\\lab-attack\\{ata}\\run.cmd"
        assert F.glob_match(synth, s3["patron"]), (ata, synth)
        synth2 = f'powershell  -NoProfile -ExecutionPolicy Bypass -File "C:\\lab-attack\\{ata}\\{ata}_ataque.ps1"'
        assert F.glob_match(synth2, s3["patron"]), (ata, synth2)

        imagenes = [r["patron"] for r in rows if r["campo"] == "win_image"]
        assert imagenes == ["powershell.exe", "cmd.exe"], (ata, imagenes)
        assert "rule_id" not in rows[0], ata
        assert "ATAATA" not in path.read_text(encoding="utf-8"), ata


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


def test_guardarrail_vhd_en_los_scripts():
    for ata, carpeta in CASES.items():
        script = BASE / carpeta / f"{ata}_ataque.ps1"
        txt = script.read_text(encoding="utf-8")
        assert f"C:\\lab-attack\\{ata}\\labdisk100.vhd" in txt, ata
        assert "labdisk100.vhd" in txt, ata
        # nunca el disco fisico ni la unidad del sistema
        assert "\\\\.\\PhysicalDrive" not in txt, ata
        assert "Get-Disk -Number 0" not in txt, ata
