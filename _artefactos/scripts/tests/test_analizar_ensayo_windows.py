# -*- coding: utf-8 -*-
"""Tests de `analizar_ensayo_windows.py` (informe mecánico del ensayo/ventana Windows).

Datos 100 % sintéticos: un crudo y una cosecha de juguete con 3 horas de actividad, un
latido cada 5 min, alertas y un conteo de `.evtx`. Cada criterio tiene su caso que PASA y
su caso que FALLA, y los que no tienen datos salen `ND` (nunca `PASS` en silencio).
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import analizar_ensayo_windows as A  # noqa: E402

T0 = datetime(2026, 11, 21, 0, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=3)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _ev(dt, eid, canal="Security", agent="002", port=None):
    ed = {"destinationPort": str(port)} if port else {}
    return json.dumps({"timestamp": _iso(dt), "agent": {"id": agent, "name": "victima-windows"},
                       "data": {"win": {"system": {"eventID": str(eid), "channel": canal}, "eventdata": ed}}})


def _alerta(dt, rid="67027", cmd="cmd /c dir C:\\Users\\angel\\Documentos", image="C:\\Windows\\System32\\cmd.exe",
            parent="", agent="002"):
    win = {"system": {"eventID": "4688"}, "eventdata": {"newProcessName": image, "commandLine": cmd}}
    if parent:
        win["eventdata"]["parentImage"] = parent                  # campo Sysmon que lee el extractor
    return json.dumps({"timestamp": _iso(dt), "agent": {"id": agent, "name": "victima-windows"},
                       "rule": {"id": rid, "level": 3, "description": "A process was created.", "groups": ["windows"]},
                       "data": {"win": win}})


@pytest.fixture()
def mundo(tmp_path):
    """Crudo + cosecha sanos: eventos cada 3 min, latido cada 5 min, alertas cada 4 min."""
    crudo = tmp_path / "crudo"
    (crudo / "archives").mkdir(parents=True)
    (crudo / "alerts").mkdir()
    (crudo / "manager").mkdir()
    cos = tmp_path / "cosecha"
    (cos / "invitado" / "evtx").mkdir(parents=True)
    (cos / "invitado" / "agente").mkdir()
    (cos / "invitado" / "sistema").mkdir()

    arch, ale = [], []
    t = T0
    while t < T1:
        arch.append(_ev(t, 4688))
        t += timedelta(minutes=3)
    t = T0
    while t < T1:
        arch.append(_ev(t, 3, canal="Microsoft-Windows-Sysmon/Operational", port=9095))
        t += timedelta(minutes=5)
    arch.append(_ev(T0 + timedelta(minutes=1), 4688, agent="001"))          # otro agente: no cuenta
    t = T0
    while t < T1:
        ale.append(_alerta(t))
        t += timedelta(minutes=4)
    (crudo / "archives" / "archives.json").write_text("\n".join(arch) + "\n", encoding="utf-8")
    (crudo / "alerts" / "alerts.json").write_text("\n".join(ale) + "\n", encoding="utf-8")
    # manager sano
    (crudo / "manager" / "ossec.log").write_text("2026/11/21 01:00:00 wazuh-remoted: INFO: ok\n", encoding="utf-8")
    (crudo / "manager" / "wazuh-analysisd.state").write_text("events_dropped='0'\n", encoding="utf-8")
    # cosecha sana: el evtx tiene exactamente lo que hay en archives
    n4688 = sum(1 for l in arch if '"eventID": "4688"' in l and '"id": "002"' in l)
    nlat = sum(1 for l in arch if '"eventID": "3"' in l)
    (cos / "invitado" / "evtx" / "conteo_por_evento.csv").write_text(
        "log,eventid,count,primero_utc,ultimo_utc\n"
        f"Security,4688,{n4688},x,y\n"
        f"Microsoft-Windows-Sysmon/Operational,3,{nlat},x,y\n"
        "Security,5156,40000,x,y\n",                                      # excluido por el agente: se ignora
        encoding="ascii")
    (cos / "invitado" / "agente" / "ossec.log").write_text(
        "2026/11/21 00:00:01 wazuh-agent: INFO: Started\n", encoding="utf-8")
    (cos / "invitado" / "sistema" / "reinicios.txt").write_text(
        "desde_utc=2026-11-21\nreinicios_o_suspensiones=0\n", encoding="utf-8")
    (cos / "cosecha.done").write_text(
        "ficheros_invitado=30\nficheros_verificados=30\navisos_invitado=2\nevtx=5\ndelta_reloj_s=0.34\n",
        encoding="utf-8")
    return crudo, cos


def _res(mundo, **kw):
    crudo, cos = mundo
    r = A.analizar(str(crudo), str(cos), T0, T1, **kw)
    return {i: (est, det) for i, est, det in r["resultados"]}, r


def test_ensayo_sano_pasa_todo(mundo):
    r, _ = _res(mundo)
    assert {k: v[0] for k, v in r.items()} == {
        "A1": "PASS", "A2": "PASS", "A3": "INFO", "A4": "PASS", "A5": "PASS", "A6": "PASS",
        "A7": "PASS", "A8": "PASS", "A9": "PASS", "A10": "PASS", "A11": "PASS"}, r


def test_sin_cosecha_los_criterios_de_cosecha_son_nd_nunca_pass(mundo):
    crudo, _ = mundo
    r = {i: est for i, est, _ in A.analizar(str(crudo), "", T0, T1)["resultados"]}
    for k in ("A6", "A8", "A9", "A10", "A11"):
        assert r[k] == "ND", (k, r)


def test_a2_detecta_un_hueco_de_eventos(mundo):
    crudo, cos = mundo
    p = crudo / "archives" / "archives.json"
    # quita todos los eventos entre 00:30 y 01:30 (hueco de ~60 min) pero deja el latido
    keep = []
    for l in p.read_text(encoding="utf-8").splitlines():
        d = json.loads(l)
        h = d["timestamp"][11:16]
        es_latido = d["data"]["win"]["eventdata"].get("destinationPort") == "9095"
        if "00:30" <= h < "01:30" and not es_latido:
            continue
        keep.append(l)
    # sin latido tampoco: el hueco debe verse en `eventos`
    keep = [l for l in keep if not ("00:30" <= json.loads(l)["timestamp"][11:16] < "01:30")]
    p.write_text("\n".join(keep) + "\n", encoding="utf-8")
    r, _ = _res(mundo)
    assert r["A2"][0] == "FAIL" and "hueco máx eventos=" in r["A2"][1]
    assert r["A4"][0] == "FAIL"                                  # y el latido también falta


def test_a3_es_informativo_no_falla(mundo):
    r, _ = _res(mundo)
    assert r["A3"][0] == "INFO" and "Linux" in r["A3"][1]


def test_a5_operador_por_encima_del_umbral_falla(mundo):
    crudo, _ = mundo
    p = crudo / "alerts" / "alerts.json"
    extra = [_alerta(T0 + timedelta(minutes=i), rid="92052", image="C:\\Windows\\System32\\cmd.exe",
                     parent="C:\\Windows\\System32\\OpenSSH\\sshd.exe") for i in range(1, 60, 2)]
    p.write_text(p.read_text(encoding="utf-8") + "\n".join(extra) + "\n", encoding="utf-8")
    r, _ = _res(mundo)
    assert r["A5"][0] == "FAIL" and "ssh_operador" in r["A5"][1]


def test_a6_detecta_eventos_perdidos_en_archives(mundo):
    crudo, cos = mundo
    p = cos / "invitado" / "evtx" / "conteo_por_evento.csv"
    txt = p.read_text(encoding="ascii").replace("Security,4688,", "Security,4688,9", 1)   # 9xx > archives
    p.write_text(txt, encoding="ascii")
    r, _ = _res(mundo)
    assert r["A6"][0] == "FAIL" and "4688" in r["A6"][1]


def test_a6_ignora_los_ids_que_el_agente_excluye(mundo):
    """Security 5156 tiene 40.000 en el evtx y 0 en archives: el agente lo excluye por defecto."""
    r, _ = _res(mundo)
    assert r["A6"][0] == "PASS"


def test_a6_lee_la_exclusion_real_del_ossec_conf(mundo):
    crudo, cos = mundo
    (cos / "invitado" / "agente" / "ossec.conf").write_text(
        "<localfile><location>Security</location><query>Event/System[EventID != 4688]</query></localfile>",
        encoding="utf-8")
    r, _ = _res(mundo)
    # ahora 4688 NO se compara y 5156 SI (ya no esta excluido) => 40000 vs 0 => FAIL
    assert r["A6"][0] == "FAIL" and "5156" in r["A6"][1]


def test_a7_manager_con_eventos_descartados_falla(mundo):
    crudo, _ = mundo
    (crudo / "manager" / "wazuh-analysisd.state").write_text("events_dropped='12'\n", encoding="utf-8")
    r, _ = _res(mundo)
    assert r["A7"][0] == "FAIL" and "events_dropped=12" in r["A7"][1]


def test_a7_aviso_package_dropped_en_ventana_falla(mundo):
    crudo, _ = mundo
    (crudo / "manager" / "ossec.log").write_text(
        "2026/11/21 01:30:00 wazuh-remoted: WARNING: Package dropped. Could not append data into buffer.\n",
        encoding="utf-8")
    r, _ = _res(mundo)
    assert r["A7"][0] == "FAIL"


def test_a8_agente_con_buffer_lleno_falla_pero_reconectar_no(mundo):
    crudo, cos = mundo
    p = cos / "invitado" / "agente" / "ossec.log"
    p.write_text("2026/11/21 00:10:00 wazuh-agent: ERROR: (1137): Lost connection with manager.\n", encoding="utf-8")
    assert _res(mundo)[0]["A8"][0] == "PASS"                      # una reconexión por sí sola no es pérdida
    p.write_text("2026/11/21 00:20:00 wazuh-agent: WARNING: Agent buffer is full: Events may be lost.\n", encoding="utf-8")
    assert _res(mundo)[0]["A8"][0] == "FAIL"


def test_a9_a10_a11(mundo):
    crudo, cos = mundo
    (cos / "cosecha.done").write_text(
        "ficheros_invitado=30\nficheros_verificados=29\nevtx=5\ndelta_reloj_s=4.5\n", encoding="utf-8")
    (cos / "invitado" / "sistema" / "reinicios.txt").write_text("reinicios_o_suspensiones=1\n", encoding="utf-8")
    r, _ = _res(mundo)
    assert r["A9"][0] == "FAIL" and r["A10"][0] == "FAIL" and r["A11"][0] == "FAIL"


def test_informe_y_codigo_de_salida(mundo, tmp_path, capsys):
    crudo, cos = mundo
    out = tmp_path / "informe.md"
    rc = A.main(["--crudo", str(crudo), "--cosecha", str(cos), "--t0", "2026-11-21T00:00:00Z",
                 "--t1", "2026-11-21T03:00:00Z", "--out", str(out)])
    assert rc == 0
    txt = out.read_text(encoding="utf-8")
    assert "RESULT=PASS" in txt and "## Por hora (UTC)" in txt and "2026-11-21T01:00" in txt
    # con un FAIL el código de salida es 1
    (cos / "cosecha.done").write_text("ficheros_invitado=3\nficheros_verificados=2\nevtx=5\n", encoding="utf-8")
    assert A.main(["--crudo", str(crudo), "--cosecha", str(cos), "--t0", "2026-11-21T00:00:00Z",
                   "--t1", "2026-11-21T03:00:00Z"]) == 1
