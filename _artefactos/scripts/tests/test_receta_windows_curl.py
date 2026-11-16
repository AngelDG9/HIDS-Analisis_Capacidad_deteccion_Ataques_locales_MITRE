# -*- coding: utf-8 -*-
"""El `curl.exe` de Windows (8.4.0, Schannel) NO admite `--compressed`: se niega a ejecutarse (rc=2)
SIN enviar la peticion. Medido en el ensayo WE0 (16-nov-2026): 34 de las 504 acciones de la receta
(todas las «sesion-web») no generaban trafico. Estos tests impiden que vuelva a pasar."""
from pathlib import Path
import json
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima_windows as W  # noqa: E402

RAIZ = Path(__file__).resolve().parents[3]
REC_W = RAIZ / "Soporte" / "Laboratorio" / "windows" / "recetas"
REC_L = RAIZ / "Soporte" / "Laboratorio" / "legitimo_72h" / "recetas"
CABECERA = "Accept-Encoding: gzip, deflate"


def _n(texto, aguja):
    return texto.count(aguja)


def test_ninguna_receta_de_windows_usa_flags_que_curl_exe_no_entiende():
    for d in ("w1", "w2", "w3"):
        assert "--compressed" not in (REC_W / f"{d}.json").read_text(encoding="utf-8"), d


def test_cada_accion_web_de_linux_tiene_su_equivalente_en_windows():
    """34 `--compressed` en Linux  <->  34 cabeceras `Accept-Encoding` en Windows (mismo trafico)."""
    linux = sum(_n((REC_L / f"d{i}.json").read_text(encoding="utf-8"), "--compressed") for i in (1, 2, 3))
    win = sum(_n((REC_W / f"w{i}.json").read_text(encoding="utf-8"), CABECERA) for i in (1, 2, 3))
    assert linux == win == 34, (linux, win)


def test_traduccion_unitaria():
    cmd = W._curl("-sS -A 'x' --compressed -o /home/angel/.cache/tfg-web/index.html http://intranet.local:8080/")
    assert "--compressed" not in cmd and CABECERA in cmd and cmd.startswith("curl.exe")
    assert "-o" in cmd and "http://intranet.local:8080/" in cmd


def test_el_conteo_de_acciones_no_cambia():
    tot = []
    for i in (1, 2, 3):
        d = json.loads((REC_W / f"w{i}.json").read_text(encoding="utf-8"))
        tot.append(sum(len(h["TimeLineEvents"]) for h in d["TimeLineHandlers"]))
    assert tot == [163, 178, 163]
