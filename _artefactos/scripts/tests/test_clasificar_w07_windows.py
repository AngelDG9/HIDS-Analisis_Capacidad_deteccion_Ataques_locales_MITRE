# -*- coding: utf-8 -*-
"""Tests de `clasificar_w07_windows.py` (corrección T4b de W-07).

Cubren el criterio determinista: acción dentro de `[ini, fin]`, artefacto de
`__PSScriptPolicyTest`/`Invoke-command` y mantenimiento posterior a `fin`.
"""

import csv
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import clasificar_w07_windows as C  # noqa: E402


def _leer_csv(path: Path):
    lineas = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    return list(csv.DictReader(lineas))


def test_clasifica_w07_bruto_filtrado_y_exclusiones(tmp_path):
    detalle = tmp_path / "detalle.csv"
    detalle.write_text(
        "timestamp_utc,rule_id,rule_level,rule_description,win_target,win_image,win_user\n"
        "2026-11-12T10:05:47.000Z,67027,3,A process was created.,,"
        "C:\\Windows\\System32\\cmd.exe,angel\n"
        "2026-11-12T10:06:02.000Z,92213,15,Executable file dropped,"
        "C:\\Users\\angel\\AppData\\Local\\Temp\\__PSScriptPolicyTest_x.ps1,"
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,DESKTOP\\angel\n"
        "2026-11-12T10:07:20.000Z,67027,3,A process was created.,,"
        "C:\\Windows\\System32\\taskhostw.exe,DESKTOP$\n"
        "2026-11-12T10:07:29.000Z,91823,14,\"Powershell script used \\\"Invoke-command\\\" cmdlet\",,,\n",
        encoding="utf-8",
    )
    ventanas = tmp_path / "ventanas.tsv"
    ventanas.write_text(
        "caso\tini\tfin\tmotivo\nW-07\t2026-11-12T10:05:46Z\t2026-11-12T10:06:30Z\t\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert C.main([
        "--detalle", str(detalle),
        "--ventanas", str(ventanas),
        "--caso", "W-07",
        "--out-dir", str(out),
    ]) == 0

    bruto = _leer_csv(out / "w07_alertas_bruto.csv")
    caso = _leer_csv(out / "w07_alertas_caso_w07.csv")
    excl = _leer_csv(out / "w07_exclusiones.csv")
    variantes = {r["variante"]: r for r in _leer_csv(out / "w07_variantes.csv")}

    assert len(bruto) == 4
    assert len(caso) == 1
    assert caso[0]["rule_id"] == "67027"
    assert len(excl) == 3
    motivos = sorted(r["motivo_exclusion"] for r in excl)
    assert motivos == [
        "artefacto_powershell_policytest",
        "artefacto_powershell_policytest",
        "mantenimiento_windows_fuera_de_accion",
    ]
    # El policy test de las 10:06:02 cae DENTRO de [ini,fin] y se declara como tal.
    dentro = [r for r in excl if r["timestamp_utc"].startswith("2026-11-12T10:06:02")]
    assert len(dentro) == 1
    assert "DENTRO de [ini,fin]" in dentro[0]["detalle_exclusion"]

    # Las 4 cifras: canónico 4/15/NO; sin ajenas 3/15/NO; sin PS 2/3/SI; sin ambas 1/3/SI.
    assert variantes["canonico"]["alertas"] == "4"
    assert variantes["canonico"]["level"] == "15"
    assert variantes["canonico"]["esperado_cumplido"] == "NO"
    assert variantes["sin_ajenas"]["alertas"] == "3"
    assert variantes["sin_ajenas"]["level"] == "15"
    assert variantes["sin_ajenas"]["esperado_cumplido"] == "NO"
    assert variantes["sin_artefactos_ps"]["alertas"] == "2"
    assert variantes["sin_artefactos_ps"]["level"] == "3"
    assert variantes["sin_artefactos_ps"]["esperado_cumplido"] == "SI"
    assert variantes["sin_ambas"]["alertas"] == "1"
    assert variantes["sin_ambas"]["level"] == "3"
    assert variantes["sin_ambas"]["esperado_cumplido"] == "SI"

    log = (out / "w07_clasificacion.log").read_text(encoding="utf-8")
    assert "caso_w07=1" in log
    assert "excluidas=3" in log
    assert "cuadre=OK" in log
    assert "sin_artefactos_ps: excluidas=2 alertas=2 level=3 esperado=SI" in log
