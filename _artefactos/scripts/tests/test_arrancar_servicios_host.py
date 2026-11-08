# -*- coding: utf-8 -*-
"""Tests de `arrancar_servicios_host.py` (B-2) — sin arrancar servicios ni tocar firewall.

Se fija: los 4 puertos del laboratorio (8080/9090/9091/9092), que 9091 va con el sink
HTTP, el bind del host (`192.168.65.1`), las reglas acotadas a `/24` y que `status` es
de solo lectura.
"""
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import arrancar_servicios_host as A  # noqa: E402


def test_bind_y_puertos_del_laboratorio():
    assert A.BIND == "192.168.65.1"
    puertos = {p for _n, ps, _a in A.SERVICIOS for p in ps}
    assert puertos == {8080, 9090, 9091, 9092}
    assert {p for _n, p in A.REGLAS} == {8080, 9090, 9091, 9092}


def test_9091_va_con_el_sink_http():
    sink = next(a for n, _p, a in A.SERVICIOS if n == "sink9090")
    assert "--tcp-port" in sink and "9091" in sink


def test_reglas_acotadas_a_la_subred():
    assert A.REMOTE == "192.168.65.0/24"
    assert {n for n, _p in A.REGLAS} == {
        "TFG-web-8080", "TFG-sink-9090", "TFG-sink-9091", "TFG-webdav-9092"
    }


def test_no_toca_puertos_del_manager():
    puertos = {p for _n, ps, _a in A.SERVICIOS for p in ps}
    assert not (puertos & {443, 1514, 1515, 55000})


def test_puerto_cerrado_y_status_es_lectura():
    assert A.puerto_abierto("127.0.0.1", 65533, timeout=0.2) is False
    assert A.main(["status"]) == 0
