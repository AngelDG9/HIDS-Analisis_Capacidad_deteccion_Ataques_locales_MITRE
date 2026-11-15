# -*- coding: utf-8 -*-
"""Tests de `analizar_legitimo_windows.py` (T3-W, espejo de `analizar_legitimo_72h.py`).

Datos sintéticos: 3 horas de `archives` del endpoint `002` con eventos sin alerta, alertas
del usuario, alertas del operador (SSH/keepalive/latido) y alertas de nivel alto, más líneas
de otro agente y de fuera de ventana (no deben contar).
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import csv
import gzip
import hashlib
import io
import json
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import analizar_legitimo_windows as A  # noqa: E402
import contar_denominador as cd  # noqa: E402

T0 = datetime(2026, 11, 23, 0, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=3)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _ev(dt, agent="002", rule=None, level=3, image="", cmd="", parent="", target="", logon=""):
    ed = {}
    if image:
        ed["image"] = image
    if cmd:
        ed["commandLine"] = cmd
    if parent:
        ed["parentImage"] = parent
    if target:
        ed["destinationIp"] = target.split(":")[0]
        ed["destinationPort"] = target.split(":")[1]
    if logon:
        ed["logonType"] = logon
    rec = {"timestamp": _iso(dt), "agent": {"id": agent, "name": "victima-windows" if agent == "002" else "victima-linux"},
           "data": {"win": {"system": {"eventID": "4688"}, "eventdata": ed}}}
    if rule:
        rec["rule"] = {"id": rule, "level": level, "description": "d", "groups": ["windows"]}
    return json.dumps(rec)


@pytest.fixture()
def crudo(tmp_path):
    d = tmp_path / "archives"
    d.mkdir()
    lineas = []
    t = T0 + timedelta(minutes=1)
    # 60 eventos sin alerta
    for i in range(60):
        lineas.append(_ev(t + timedelta(minutes=i)))
    # 10 alertas del usuario (67027 nivel 3, cmd lanzado por ghosts)
    for i in range(10):
        lineas.append(_ev(t + timedelta(minutes=70 + i), rule="67027", image="C:\\Windows\\System32\\cmd.exe",
                          cmd="cmd /c dir C:\\Users\\angel", parent="C:\\Users\\angel\\ghosts-client\\ghosts.exe"))
    # 4 alertas del operador: sshd.exe, cmd hijo de sshd, schtasks de la tarea del laboratorio, latido
    lineas.append(_ev(t + timedelta(minutes=100), rule="67027", image="C:\\Windows\\System32\\OpenSSH\\sshd.exe"))
    lineas.append(_ev(t + timedelta(minutes=101), rule="92052", level=4, image="C:\\Windows\\System32\\cmd.exe",
                      parent="C:\\Windows\\System32\\OpenSSH\\sshd.exe"))
    lineas.append(_ev(t + timedelta(minutes=102), rule="67027", cmd="schtasks /run /tn TFG-WinLegit-Keepalive"))
    lineas.append(_ev(t + timedelta(minutes=103), rule="185001", level=3, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                      target="192.168.65.1:9095"))
    # 2 alertas de nivel alto del usuario
    lineas.append(_ev(t + timedelta(minutes=110), rule="92213", level=15, image="C:\\Users\\angel\\x.exe"))
    lineas.append(_ev(t + timedelta(minutes=111), rule="92027", level=7, image="C:\\Windows\\System32\\cmd.exe"))
    # 1 evento del propio HIDS con alerta (auto_ruido)
    lineas.append(_ev(t + timedelta(minutes=120), rule="67027",
                      image="C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"))
    # NO cuentan: otro agente, fuera de ventana, regla de nivel 2 (sin alerta)
    lineas.append(_ev(t + timedelta(minutes=5), agent="001", rule="80792"))
    lineas.append(_ev(T0 - timedelta(minutes=5), rule="67027"))
    lineas.append(_ev(T1 + timedelta(minutes=5), rule="67027"))
    lineas.append(_ev(t + timedelta(minutes=130), rule="1002", level=2))
    (d / "archives.json").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return d


def _run(crudo, out, **kw):
    return A.analizar(str(crudo / "archives.json"), T0, T1, str(out), **kw)


def test_M_coincide_con_contar_denominador(crudo, tmp_path):
    res, _, _ = _run(crudo, tmp_path / "o")
    ref, _ = cd.contar([str(crudo / "archives.json")], T0, T1, "002", "victima-windows")
    assert res["M_endpoint"] == ref["endpoint"]["eventos"] == 60 + 10 + 4 + 2 + 1 + 1   # +1 regla nivel 2
    assert res["M_total"] == ref["total"]["eventos"]


def test_fp_uni_y_operador_por_umbral(crudo, tmp_path):
    _, fpr, filas = _run(crudo, tmp_path / "o", n_acciones=504)
    por = {r["umbral_N"]: r for r in fpr}
    assert por[0]["FP_uni"] == por[3]["FP_uni"] == 10 + 4 + 2 + 1          # nivel >= 3
    assert por[0]["operador_uni"] == 4                                      # sshd, cmd/sshd, schtasks, latido
    assert por[7]["FP_uni"] == 2 and por[7]["operador_uni"] == 0            # 92213 (15) y 92027 (7)
    assert por[10]["FP_uni"] == 1 and por[12]["FP_uni"] == 1
    m = por[0]["M"]
    assert por[0]["FPR_canonico"] == round(17 / m, 6)
    assert por[0]["FPR_sin_operador"] == round((17 - 4) / m, 6)
    assert por[0]["FP_por_accion"] == round(17 / 504, 6)
    assert por[0]["FP_por_hora"] == round(17 / 3.0, 6)


def test_el_operador_se_detecta_por_evidencia_no_por_usuario(crudo, tmp_path):
    _, _, filas = _run(crudo, tmp_path / "o")
    mot = {f["rule_id"] + ":" + f["motivo_operador"] for f in filas if f["operador_legit"]}
    assert {"67027:ssh_operador", "92052:ssh_operador", "67027:tareas_operador", "185001:latido"} <= mot
    # las 10 acciones del usuario (padre ghosts.exe) NO son operador
    usuario = [f for f in filas if f["rule_id"] == "67027" and not f["operador_legit"]]
    assert len(usuario) >= 10


def test_auto_ruido_es_solo_agente_o_sysmon(crudo, tmp_path):
    res, _, filas = _run(crudo, tmp_path / "o")
    assert res["auto_ruido_uni"] == 1
    assert sum(f["auto_ruido"] for f in filas) == 1


def test_unidad_unica_y_con_formato_fichero_linea(crudo, tmp_path):
    _, _, filas = _run(crudo, tmp_path / "o")
    unidades = [f["unidad"] for f in filas]
    assert len(set(unidades)) == len(unidades)
    assert all(u.startswith("archives.json:") and u.split(":")[1].isdigit() for u in unidades)


def test_salidas_deterministas_byte_a_byte(crudo, tmp_path):
    _run(crudo, tmp_path / "a")
    _run(crudo, tmp_path / "b")
    for nombre in ("eventos_alerta_windows.csv.gz", "T3_detalle_windows.csv", "fpr_doble_windows.csv",
                   "catalogo_ruido_windows.csv", "catalogo_M1b_windows.csv", "resumen_windows.json",
                   "estabilidad_hora_windows.csv", "estabilidad_dia_windows.csv"):
        ha = hashlib.sha256((tmp_path / "a" / nombre).read_bytes()).hexdigest()
        hb = hashlib.sha256((tmp_path / "b" / nombre).read_bytes()).hexdigest()
        assert ha == hb, nombre


def test_catalogo_M1b_incluye_operador_y_artefactos_con_su_origen(crudo, tmp_path):
    _run(crudo, tmp_path / "o")
    txt = [l for l in (tmp_path / "o" / "catalogo_M1b_windows.csv").read_text(encoding="utf-8").splitlines()
           if not l.startswith("#")]
    filas = list(csv.DictReader(io.StringIO("\n".join(txt))))
    origen = {r["rule_id"]: r["origen_catalogo"] for r in filas}
    assert origen["67027"] == "ventana"
    assert origen["60106"] == "operador"                 # no ejercitada, pero entra (corpus por SSH)
    assert origen["92213"] == "artefacto_ataque"
    assert origen["92052"] == "artefacto_entrega" and origen["92032"] == "artefacto_entrega"
    just = {r["rule_id"]: r["justificacion"] for r in filas}
    assert "POR ALERTA" in just["92052"]                 # M-23: se clasifica por alerta, no la regla entera


def test_cabecera_declara_bovedav3_y_plataforma(crudo, tmp_path):
    _run(crudo, tmp_path / "o")
    cab = (tmp_path / "o" / "fpr_doble_windows.csv").read_text(encoding="utf-8").splitlines()[0]
    assert "boveda_version=3" in cab and "plataforma=windows" in cab and "metrica_version=1" in cab


def test_indice_gz_sin_mtime_y_con_las_columnas(crudo, tmp_path):
    _run(crudo, tmp_path / "o")
    raw = (tmp_path / "o" / "eventos_alerta_windows.csv.gz").read_bytes()
    assert raw[4:8] == b"\x00\x00\x00\x00"               # mtime=0 (determinista)
    cab = gzip.decompress(raw).decode("utf-8").splitlines()[0].split(",")
    assert cab == A.IDX_HEADER


def test_estabilidad_por_hora_suma_M(crudo, tmp_path):
    res, _, _ = _run(crudo, tmp_path / "o")
    txt = [l for l in (tmp_path / "o" / "estabilidad_hora_windows.csv").read_text(encoding="utf-8").splitlines()
           if not l.startswith("#")]
    filas = list(csv.DictReader(io.StringIO("\n".join(txt))))
    assert sum(int(f["eventos_M"]) for f in filas) == res["M_endpoint"]
    assert sum(int(f["alertas"]) for f in filas) == 17


def test_integracion_con_tabla3_la_misma_herramienta_que_linux(crudo, tmp_path):
    import tabla3_legitimo as T3
    res, _, _ = _run(crudo, tmp_path / "o")
    out = tmp_path / "T3.csv"
    rc = T3.main(["--so", "windows", "--corrida", "W-test", "--detalle", str(tmp_path / "o" / "T3_detalle_windows.csv"),
                  "--unidades-count", str(res["M_endpoint"]), "--out", str(out)])
    assert rc == 0
    txt = [l for l in out.read_text(encoding="utf-8").splitlines() if not l.startswith("#")]
    filas = list(csv.DictReader(io.StringIO("\n".join(txt))))
    agr = [f for f in filas if f.get("seccion") == "agregado" and f["config"] == "C1" and f["umbral"] == "0"]
    assert agr and agr[0]["#Unidades_FP"] == "17" and agr[0]["#Unidades"] == str(res["M_endpoint"])
