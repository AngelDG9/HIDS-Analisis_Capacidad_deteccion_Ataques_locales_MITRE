# -*- coding: utf-8 -*-
"""Tests de `cobertura_herramientas_windows.py` — cobertura de la receta Windows.

Mismo criterio que `cobertura_exes.py` (CA-04): denominador = `basenames` del corpus de
ataques de Linux; numerador = herramientas de la receta Windows que están en ese corpus.
La campaña (`B6`) se cuenta **aparte**.

Se fija lo que puede romperse en silencio:

1. **Parser** `cmd`: builtins (`dir`, `type`, `copy`…), paréntesis de `if`, `for /L` con
   `cmd /c`, redirecciones y pipes **dentro** de `powershell -Command`.
2. **`B6` fuera de la jornada**: la campaña no infla la receta.
3. **Cobertura real**: 3/50 (solo `curl`, `find`, `tar`); las demás herramientas de la
   receta no existen en el corpus Linux (se declara, no se maquilla).
"""

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import cobertura_herramientas_windows as C  # noqa: E402

RAIZ = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------
# 1) Parser de comandos de `cmd`
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cmd, esperado", [
    ("cd /d C:\\Users\\angel && (if not exist C:\\Users\\angel\\Documentos md "
     "C:\\Users\\angel\\Documentos) & > C:\\x\\llegada.txt echo %DATE%_%TIME%", set()),
    ("cd /d C:\\x && dir C:\\x", set()),
    ("cd /d C:\\x && type C:\\x\\agenda.txt", set()),
    ("> C:\\x\\hecho.txt echo RESULTADO=OK && type C:\\x\\huellas.txt >> C:\\x\\hecho.txt",
     set()),
    ("if errorlevel 1 (>> C:\\x\\errores.log echo rc) else (del /f /q C:\\x\\a)",
     set()),
    ("for /L %i in (1,1,12) do @cmd /c copy /y C:\\x\\a C:\\x\\lote_%i.txt", set()),
    ("for /L %i in (1,1,12) do @cmd /c xcopy /y C:\\x\\a C:\\x\\lote_%i.txt", {"xcopy"}),
    ("robocopy C:\\x\\origen C:\\x\\destino /MIR /NFL", {"robocopy"}),
    ("certutil -hashfile C:\\x\\a.txt SHA256", {"certutil"}),
    ("curl.exe -sS --max-time 3 -o C:\\x\\a.html http://intranet.local:8080/", {"curl"}),
    ("find /c /v \"\" C:\\x\\a.txt", {"find"}),
    ("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run > C:\\x\\r.txt 2>nul "
     "& if errorlevel 1 (> C:\\x\\rc.txt echo rc=1)", {"reg"}),
    ("sc query state= all > C:\\x\\s.txt", {"sc"}),
    ("eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO ofimatica /D \"nota; con ;\"",
     {"eventcreate"}),
    ("powershell -NoProfile -Command \"$c = (Get-Content a.csv) -replace ';',','; "
     "Set-Content b.csv -Value $c\"", {"powershell"}),
])
def test_parser_cmd(cmd, esperado):
    assert C._tokens(cmd) == esperado


# --------------------------------------------------------------------------
# 2) Receta vs campaña
# --------------------------------------------------------------------------
def _receta(path, handlers):
    path.write_text(json.dumps({"TimeLineHandlers": handlers}), encoding="utf-8")


def _handler(on, off, comandos):
    return {"HandlerType": "Command", "UtcTimeOn": on, "UtcTimeOff": off,
            "TimeLineEvents": [{"Command": c} for c in comandos]}


def test_b6_no_infla_la_receta(tmp_path):
    rec = tmp_path / "recetas"
    rec.mkdir()
    for d in (1, 2, 3):
        _receta(rec / f"w{d}.json", [
            _handler("08:00:00", "08:12:00", ["curl.exe -sS http://x/"]),
            _handler("17:06:00", "17:50:00", ["xcopy /y a b"]),
        ])
    assert C.binarios_receta(str(rec)) == {"curl"}
    assert C.binarios_campana(str(rec)) == {"xcopy"}


def test_cobertura_con_corpus_sintetico(tmp_path):
    raiz = tmp_path
    aud = raiz / "Dataset" / "Ataques" / "Resultados" / "Wazuh" / "linux" / "Auditado"
    aud.mkdir(parents=True)
    (aud / "ATA001-Audited.csv").write_text(
        "categoria,rule_description\n"
        "deteccion,\"Audit: Command: /usr/bin/curl.\"\n"
        "deteccion,\"Audit: Command: /usr/bin/tar.\"\n"
        "deteccion,\"Audit: Command: /usr/bin/sed.\"\n"
        "deteccion,\"Audit: Command: /usr/bin/curl.\"\n"
        "ruido,\"otra cosa\"\n", encoding="utf-8")
    rec = raiz / "recetas"
    rec.mkdir()
    for d in (1, 2, 3):
        _receta(rec / f"w{d}.json", [
            _handler("08:00:00", "08:12:00",
                     ["curl.exe -sS http://x/", "certutil -hashfile a SHA256"]),
            _handler("17:06:00", "17:50:00", ["certutil -hashfile b SHA256"]),
        ])
    inf = C.cobertura(str(rec), str(raiz), campana=True)
    assert inf["corpus"] == 3
    assert inf["rutas"] == 3 and inf["filas"] == 4
    assert inf["receta"] == 2
    assert inf["cubiertos"] == ["curl"]
    assert inf["cobertura"] == 1
    assert inf["campana"] == 1 and inf["campana_nuevas"] == []


# --------------------------------------------------------------------------
# 3) Número real (regresión)
# --------------------------------------------------------------------------
@pytest.mark.skipif(not (RAIZ / "Dataset").is_dir(), reason="sin Dataset")
def test_cobertura_real_3_de_50():
    inf = C.cobertura(str(RAIZ / "Soporte" / "Laboratorio" / "windows" / "recetas"),
                      str(RAIZ), campana=True)
    assert inf["corpus"] == 50, inf
    assert inf["receta"] == 10, inf
    assert inf["cubiertos"] == ["curl", "find", "tar"], inf
    assert inf["cobertura"] == 3, inf
    assert inf["campana"] == 15, inf


# --------------------------------------------------------------------------
# 4) Binarios anidados (C5-bis): `start` y `powershell -Command`
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cmd,esperado", [
    (r"cd /d C:\x && start /b whoami2.exe", {"whoami2"}),
    (r'cd /d C:\x && start /min "titulo" /b whoami2.exe', {"whoami2"}),
    (r'cd /d C:\x && powershell -NoProfile -Command "whoami2.exe"',
     {"powershell", "whoami2"}),
    (r'cd /d C:\x && powershell -NoProfile -Command "$p = Get-Item x; '
     r'whoami2.exe"', {"powershell", "whoami2"}),
])
def test_binario_anidado_se_ve(cmd, esperado):
    assert C._tokens(cmd) == esperado


@pytest.mark.parametrize("cmd,esperado", [
    (r"cd /d C:\x && start /b cmd /c echo x", set()),
    (r'cd /d C:\x && start "" /b cmd /c echo x', set()),
    (r'cd /d C:\x && powershell -NoProfile -Command "Write-Output x"',
     {"powershell"}),
    (r'cd /d C:\x && powershell -NoProfile -Command "$c = (Get-Content a.csv) '
     r'-replace \';\',\',\'; Set-Content b.csv -Value $c"', {"powershell"}),
])
def test_los_builtins_anidados_no_inflan(cmd, esperado):
    assert C._tokens(cmd) == esperado
