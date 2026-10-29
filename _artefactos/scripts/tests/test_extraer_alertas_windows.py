# -*- coding: utf-8 -*-
"""Tests de `extraer_alertas_windows.py` — extractor de alertas de Windows (CA-W23).

Sin VMs ni red: fixtures sintéticos en `tmp_path` con la forma real de Wazuh 4.14.7
(`data.win.{system,eventdata}` y alias planos). Se fijan los bordes que importan:

1. **Columnas**: las 17 de Linux + `agent_id` + `win_image`, `win_command_line`,
   `win_cwd`, `win_user`, `event_id` (plan §7, W2).
2. **Filtro por agente `002`** y por ventana `[desde, hasta]` **inclusiva**.
3. **No se inventa**: si un campo no viene, se deja vacío y el contador lo dice.
4. **Sysmon** (`Image`/`CommandLine`/`CurrentDirectory`) y **Seguridad 4688**
   (`NewProcessName`/`CommandLine`/`SubjectUserName`) mapean al mismo ancla.
5. **`.gz`** de los ficheros rotados.
6. **CA-W23**: contra `Dataset/Legitimo/windows/baseline_detalle_v{1,2}.csv`
   reproduce **7 `rule_id`** y **72 + 87 = 159** alertas (solo lectura).
"""

import csv
import gzip
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import extraer_alertas_windows as X  # noqa: E402

UTC = timezone.utc
INI = datetime(2026, 11, 9, 17, 6, 0, tzinfo=UTC)
FIN = datetime(2026, 11, 9, 17, 10, 0, tzinfo=UTC)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def _sysmon(ts, aid="002", name="victima-windows", rule="67027", level=3,
            image=r"C:\Windows\System32\cmd.exe", cmdline="cmd /c systeminfo",
            cwd=r"C:\Users\angel", user="angel", event_id="1"):
    return {
        "timestamp": _iso(ts),
        "agent": {"id": aid, "name": name},
        "rule": {"id": rule, "level": level, "description": "A process was created.",
                 "groups": ["windows", "WEF"]},
        "data": {"win": {"system": {"eventID": event_id},
                         "eventdata": {"Image": image, "CommandLine": cmdline,
                                       "CurrentDirectory": cwd, "User": user}}},
    }


def _escribir(path, alertas, gz=False):
    datos = "".join(json.dumps(a) + "\n" for a in alertas).encode("utf-8")
    if gz:
        with gzip.open(path, "wb") as fh:
            fh.write(datos)
    else:
        Path(path).write_bytes(datos)
    return str(path)


# --------------------------------------------------------------------------
# 1) Columnas y mapeo de campos
# --------------------------------------------------------------------------
def test_columnas_actuales_mas_ancla_windows():
    assert X.DETAIL_HEADER[:17] == [
        "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
        "rule_groups", "rs_origen", "audit_exe", "audit_cwd", "audit_key", "audit_type",
        "audit_file", "audit_dir", "syscheck_path", "srcip", "srcuser", "dstuser",
    ]
    assert X.DETAIL_HEADER[17:] == [
        "agent_id", "win_image", "win_command_line", "win_cwd", "win_user", "event_id",
    ]
    assert X.CSV_HEADER == ["rule_id", "rule_level", "rule_description", "groups",
                            "count", "first_seen", "last_seen", "rs_origen"]


def test_sysmon_mapea_el_ancla(tmp_path):
    p = _escribir(tmp_path / "a.json", [_sysmon(INI + timedelta(seconds=1))])
    det, _agg, meta = X.extraer([p], INI, FIN, id_map={"67027": "RS1"})
    assert len(det) == 1
    fila = dict(zip(X.DETAIL_HEADER, det[0]))
    assert fila["agent_id"] == "002"
    assert fila["win_image"] == r"C:\Windows\System32\cmd.exe"
    assert fila["win_command_line"] == "cmd /c systeminfo"
    assert fila["win_cwd"] == r"C:\Users\angel"
    assert fila["win_user"] == "angel"
    assert fila["event_id"] == "1"
    assert fila["rs_origen"] == "RS1"
    assert meta["campos"] == {"win_image": 1, "win_command_line": 1, "win_cwd": 1,
                              "win_user": 1, "event_id": 1}


def test_seguridad_4688_usa_los_alias_de_4688(tmp_path):
    alerta = {
        "timestamp": _iso(INI),
        "agent": {"id": "002", "name": "victima-windows"},
        "rule": {"id": "60100", "level": 3, "description": "process", "groups": []},
        "data": {"win": {"system": {"eventID": "4688"},
                         "eventdata": {"NewProcessName": r"C:\Windows\System32\whoami.exe",
                                       "CommandLine": "whoami /all",
                                       "SubjectUserName": "angel"}}},
    }
    p = _escribir(tmp_path / "a.json", [alerta])
    det, _agg, _meta = X.extraer([p], INI, FIN)
    fila = dict(zip(X.DETAIL_HEADER, det[0]))
    assert fila["win_image"].endswith("whoami.exe")
    assert fila["win_command_line"] == "whoami /all"
    assert fila["win_user"] == "angel"
    assert fila["event_id"] == "4688"
    assert fila["win_cwd"] == ""          # 4688 no lo lleva: no se inventa


def test_alias_planos_tambien_valen(tmp_path):
    alerta = {
        "timestamp": _iso(INI),
        "agent": {"id": "002", "name": "victima-windows"},
        "rule": {"id": "67027", "level": 3, "description": "x", "groups": []},
        "data": {"win_image": r"C:\x\cmd.exe", "win_command_line": "cmd /c dir",
                 "win_cwd": r"C:\Users\angel", "win_user": "angel", "event_id": "1"},
    }
    p = _escribir(tmp_path / "a.json", [alerta])
    det, _agg, _meta = X.extraer([p], INI, FIN)
    fila = dict(zip(X.DETAIL_HEADER, det[0]))
    assert fila["win_image"] == r"C:\x\cmd.exe"
    assert fila["win_command_line"] == "cmd /c dir"
    assert fila["win_cwd"] == r"C:\Users\angel"


def test_campos_ausentes_no_se_inventan(tmp_path):
    alerta = {
        "timestamp": _iso(INI),
        "agent": {"id": "002", "name": "victima-windows"},
        "rule": {"id": "594", "level": 5, "description": "FIM", "groups": []},
        "syscheck": {"path": "/registry/key"},
    }
    p = _escribir(tmp_path / "a.json", [alerta])
    det, _agg, meta = X.extraer([p], INI, FIN)
    fila = dict(zip(X.DETAIL_HEADER, det[0]))
    for c in ("win_image", "win_command_line", "win_cwd", "win_user", "event_id"):
        assert fila[c] == "", c
    assert fila["syscheck_path"] == "/registry/key"
    assert all(v == 0 for v in meta["campos"].values())


# --------------------------------------------------------------------------
# 2) Agente y ventana
# --------------------------------------------------------------------------
def test_filtro_agente_y_ventana_inclusiva(tmp_path):
    alertas = [
        _sysmon(INI),                                  # borde inicial: dentro
        _sysmon(FIN),                                  # borde final: dentro
        _sysmon(INI - timedelta(milliseconds=1)),      # fuera
        _sysmon(FIN + timedelta(milliseconds=1)),      # fuera
        _sysmon(INI, aid="001", name="victima-linux"),  # otro agente
    ]
    p = _escribir(tmp_path / "a.json", alertas)
    det, _agg, meta = X.extraer([p], INI, FIN)
    assert len(det) == 2
    assert meta["otros_agentes"] == 1
    assert meta["en_ventana"] == 2 and meta["fuera_ventana"] == 2


def test_sin_agente_no_entra(tmp_path):
    alerta = {"timestamp": _iso(INI),
              "rule": {"id": "503", "level": 3, "description": "manager", "groups": []}}
    p = _escribir(tmp_path / "a.json", [alerta])
    det, _agg, meta = X.extraer([p], INI, FIN)
    assert det == [] and meta["sin_agente"] == 1


def test_id_manda_sobre_nombre(tmp_path):
    """Un `001` con nombre `victima-windows` no entra: el id es el filtro."""
    p = _escribir(tmp_path / "a.json", [_sysmon(INI, aid="001")])
    det, _agg, meta = X.extraer([p], INI, FIN)
    assert det == [] and meta["otros_agentes"] == 1


# --------------------------------------------------------------------------
# 3) .gz y agregado
# --------------------------------------------------------------------------
def test_lee_gz(tmp_path):
    p = _escribir(tmp_path / "ossec-alerts-09.json.gz",
                  [_sysmon(INI + timedelta(seconds=2))], gz=True)
    det, _agg, meta = X.extraer([p], INI, FIN)
    assert len(det) == 1 and meta["leidas"] == 1


def test_agregado_8_columnas_y_ventana(tmp_path):
    alertas = [
        _sysmon(INI + timedelta(seconds=1)),
        _sysmon(INI + timedelta(seconds=3)),
        _sysmon(FIN, rule="92201", level=9, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        _sysmon(INI, aid="001"),
    ]
    p = _escribir(tmp_path / "a.json", alertas)
    _det, agg, _meta = X.extraer([p], INI, FIN, id_map={"67027": "RS1", "92201": "RS1"})
    filas = {r[0]: r for r in agg}
    assert len(filas["67027"]) == len(X.CSV_HEADER)
    assert filas["67027"][4] == 2
    assert filas["67027"][5] == "2026-11-09T17:06:01Z"
    assert filas["67027"][6] == "2026-11-09T17:06:03Z"
    assert filas["67027"][7] == "RS1"
    assert filas["92201"][4] == 1


def test_linea_no_json_se_cuenta_y_no_rompe(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("{no es json}\n" + json.dumps(_sysmon(INI)) + "\n", encoding="utf-8")
    det, _agg, meta = X.extraer([str(p)], INI, FIN)
    assert len(det) == 1 and meta["no_json"] == 1 and meta["leidas"] == 2


# --------------------------------------------------------------------------
# 4) Regresión CA-W23 (productos congelados del 08/10)
# --------------------------------------------------------------------------
RAIZ = Path(__file__).resolve().parents[3]
DETALLE_V1 = RAIZ / "Dataset" / "Legitimo" / "windows" / "baseline_detalle_v1.csv"
DETALLE_V2 = RAIZ / "Dataset" / "Legitimo" / "windows" / "baseline_detalle_v2.csv"


@pytest.mark.skipif(not (DETALLE_V1.is_file() and DETALLE_V2.is_file()),
                    reason="faltan los productos históricos de Windows")
def test_ca_w23_regresion_historica():
    ok, inf, _ = X.regresion([str(DETALLE_V1), str(DETALLE_V2)], etiquetas=["v1", "v2"])
    assert ok, inf
    assert inf["ventanas"]["v1"]["filas"] == 72
    assert inf["ventanas"]["v2"]["filas"] == 87
    assert inf["total"] == 159
    assert inf["reglas"] == ["594", "598", "750", "60642", "60702", "67027", "92201"]
    assert inf["rs_origen"] == ["RS1"]


def test_regresion_sin_columna_de_agente_falla(tmp_path):
    p = tmp_path / "v1.csv"
    p.write_text("timestamp_utc,rule_id\n2026-10-08T00:45:15.681Z,67027\n",
                 encoding="utf-8")
    with pytest.raises(SystemExit):
        X.regresion([str(p)], etiquetas=["v1"])


def test_regresion_detecta_una_diferencia(tmp_path):
    """No se maquilla: si falta una fila, la regresión FALLA."""
    if not DETALLE_V1.is_file():
        pytest.skip("falta el producto histórico de Windows")
    with open(DETALLE_V1, encoding="utf-8", newline="") as fh:
        lineas = fh.read().splitlines()
    cab = next(i for i, ln in enumerate(lineas) if not ln.lstrip().startswith("#"))
    # quita la última fila de datos de una copia temporal
    recortado = tmp_path / "v1.csv"
    recortado.write_text("\n".join(lineas[:cab + 1] + lineas[cab + 1:-1]) + "\n",
                         encoding="utf-8")
    ok, inf, _ = X.regresion([str(recortado)], etiquetas=["v1"])
    assert not ok
    assert inf["ventanas"]["v1"]["filas"] == 71
