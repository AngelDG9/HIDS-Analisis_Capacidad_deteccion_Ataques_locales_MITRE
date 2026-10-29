# -*- coding: utf-8 -*-
"""Tests del validador de espejo Linux ↔ Windows (`verificar_espejo.py`).

Comprueban que el validador **no es decorativo**: pasa con las recetas versionadas y
**falla** en cuanto se toca un `DelayAfter`, se quita una acción, se cambian las ventanas o
se cuela un `cmd /c` (doble proceso) en una acción.
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima_windows as W   # noqa: E402
import verificar_espejo as E                    # noqa: E402

RAIZ = Path(W.RAIZ)
DIR_LINUX = RAIZ / E.DIR_LINUX
DIR_WIN = RAIZ / E.DIR_WIN


@pytest.fixture()
def copia(tmp_path):
    """Copia de las recetas versionadas para poder romperlas sin tocar el repo."""
    out = tmp_path / "espejo"
    out.mkdir()
    for day in (1, 2, 3):
        shutil.copy(DIR_WIN / f"w{day}.json", out / f"w{day}.json")
    return out


def _romper(copia, day, fn):
    p = copia / f"w{day}.json"
    tl = json.loads(p.read_text(encoding="utf-8"))
    fn(tl)
    p.write_text(json.dumps(tl, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _comparar(dir_win):
    return E.comparar(str(DIR_LINUX), str(dir_win), verbose=False)


# --------------------------------------------------------------------------
# pasa con lo versionado
# --------------------------------------------------------------------------
def test_las_recetas_versionadas_pasan():
    res = _comparar(DIR_WIN)
    assert res["fallos"] == [], res["fallos"][:5]
    assert sum(r["n_linux"] for r in res["tabla"]) == 504
    assert all(r["ritmo_igual"] for r in res["tabla"])


def test_main_devuelve_cero():
    assert E.main(["--silencio"]) == 0


# --------------------------------------------------------------------------
# falla en cuanto se rompe el espejo
# --------------------------------------------------------------------------
def test_detecta_un_delayafter_distinto(copia):
    _romper(copia, 1, lambda tl: tl["TimeLineHandlers"][1]["TimeLineEvents"][3].__setitem__(
        "DelayAfter", tl["TimeLineHandlers"][1]["TimeLineEvents"][3]["DelayAfter"] + 1))
    res = _comparar(copia)
    assert any("DelayAfter" in f for f in res["fallos"])


def test_detecta_un_conteo_distinto(copia):
    _romper(copia, 2, lambda tl: tl["TimeLineHandlers"][0]["TimeLineEvents"].pop())
    res = _comparar(copia)
    assert any("acciones !=" in f for f in res["fallos"])


def test_detecta_una_ventana_distinta(copia):
    _romper(copia, 3, lambda tl: tl["TimeLineHandlers"][2].__setitem__("UtcTimeOn", "10:21:00"))
    res = _comparar(copia)
    assert any("UtcTimeOn" in f for f in res["fallos"])


def test_detecta_mas_bloques(copia):
    _romper(copia, 1, lambda tl: tl["TimeLineHandlers"].append(dict(tl["TimeLineHandlers"][0])))
    res = _comparar(copia)
    assert any("handlers" in f for f in res["fallos"])


def test_detecta_doble_envoltorio_cmd(copia):
    _romper(copia, 2, lambda tl: tl["TimeLineHandlers"][1]["TimeLineEvents"][0].__setitem__(
        "Command", "cmd /c " + tl["TimeLineHandlers"][1]["TimeLineEvents"][0]["Command"]))
    res = _comparar(copia)
    assert any("cmd /c" in f for f in res["fallos"])


def test_detecta_un_pipe_fuera_de_powershell(copia):
    _romper(copia, 3, lambda tl: tl["TimeLineHandlers"][0]["TimeLineEvents"][0].__setitem__(
        "Command", tl["TimeLineHandlers"][0]["TimeLineEvents"][0]["Command"] + " | more"))
    res = _comparar(copia)
    assert any("|" in f for f in res["fallos"])


def test_detecta_un_bucle_nuevo_sin_pareja_en_linux(copia):
    """Un `for /L` que además hace 12 copias donde Linux no tenía `xargs`."""
    cmd = ('cd /d C:\\Users\\angel\\Documentos && for /L %i in (1,1,12) do @xcopy /y '
           'C:\\Users\\angel\\Documentos\\informes\\informe.txt '
           'C:\\Users\\angel\\Documentos\\informes\\lote_%i.txt')
    _romper(copia, 1, lambda tl: tl["TimeLineHandlers"][0]["TimeLineEvents"][0].__setitem__(
        "Command", cmd))
    res = _comparar(copia)
    assert any("procesos" in f for f in res["fallos"])


# --------------------------------------------------------------------------
# unidad de proceso: conteo de hijos
# --------------------------------------------------------------------------
def test_hijos_de_builtins_es_cero():
    assert E.hijos("cd /d C:\\Users\\angel && dir C:\\Users\\angel") == 0
    assert E.hijos("cd /d C:\\Users\\angel && type C:\\x.txt") == 0
    assert E.hijos("cd /d C:\\Users\\angel && del /f /q C:\\x.txt") == 0


def test_hijos_de_un_externo_es_uno():
    assert E.hijos("cd /d C:\\Users\\angel && certutil -hashfile C:\\x.txt SHA256") == 1
    assert E.hijos("cd /d C:\\Users\\angel && tar -czf C:\\a.tar.gz -C C:\\ a.txt") == 1


def test_hijos_de_un_bucle_con_fanout_es_doce():
    cmd = ("cd /d C:\\lab-legit\\campana\\W-09 && for /L %i in (1,1,12) do @xcopy /y "
           "C:\\lab-legit\\campana\\W-09\\plantilla.txt C:\\lab-legit\\campana\\W-09\\lote_%i.txt")
    assert E.hijos(cmd) == 12


def test_hijos_de_un_bucle_sin_externos_es_cero():
    assert E.hijos("cd /d C:\\Users\\angel && for /L %i in (1,1,12) do @echo %i>>C:\\lotes.txt") == 0


def test_hijos_de_un_error_cuenta_el_que_falla():
    cmd = ("cd /d C:\\Users\\angel\\Documentos && dir C:\\Users\\angel\\Documentos\\informe "
           ">nul 2>&1 & if errorlevel 1 (>> C:\\Users\\angel\\Documentos\\errores.log echo "
           "%DATE%_%TIME%\terror\truta_mal\tdir C:\\informe\trc=ge1)")
    assert E.hijos(cmd) == 0        # `dir` es builtin
