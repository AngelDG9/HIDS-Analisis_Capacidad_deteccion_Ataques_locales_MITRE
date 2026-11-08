# -*- coding: utf-8 -*-
"""Tests de `filtrar_ruido_windows.py` — B1.0 (H4-W, replay baseline, artefacto).

Cubren:
- replay CA-B1-08: v1 (72) con catálogo v1 -> 0; v2 (87) con v1+v2 -> 0;
- H4-W: `win_image` + ancla + evento de ejecución -> `deteccion`;
- H4-W: `win_image` sin ancla / evento no ejecución -> `dudosa` (`sin_ancla`);
- pertenencia al ataque por `win_command_line` -> `artefacto_ataque`;
- `auto_ruido` vacío (declarado) y modo baseline absorbe novedades.
"""
from pathlib import Path
import csv
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import filtrar_ruido_windows as F  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]

HEADER = [
    "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
    "rule_groups", "rs_origen", "win_image", "win_command_line", "win_cwd",
    "win_user", "event_id", "syscheck_path", "win_target", "win_target_user",
]


def _escribir(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in HEADER})


def _esperado(path, lineas):
    path.write_text("senal_id,tipo,campo,patron,dato_componente,tecnica,nota\n" + "\n".join(lineas) + "\n",
                    encoding="utf-8")


def _leer(path):
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_replay_baseline_ca_b1_08():
    assert F.main(["--replay-baseline"]) == 0


def test_h4w_deteccion(tmp_path):
    alerta = tmp_path / "alerta.csv"
    _escribir(alerta, [{
        "timestamp_utc": "2026-01-01T00:00:10Z",
        "agent_name": "victima-windows",
        "rule_id": "92029",
        "rule_level": "6",
        "rule_groups": "sysmon|sysmon_eid1_detections|windows",
        "rs_origen": "RS1",
        "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "win_command_line": r"powershell.exe -File C:\lab-attack\ATA074\run.ps1",
        "win_cwd": r"C:\lab-attack\ATA074",
        "event_id": "1",
    }])
    esp = tmp_path / "ATA074_esperado.csv"
    _esperado(esp, [
        r"T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,test",
        r"T1041-S2,deteccion,win_command_line,*ATA074*,Command Execution,T1041,ancla H4-W",
    ])
    out = tmp_path / "out.csv"
    assert F.main(["--alerta", str(alerta), "--ata", "ATA074", "--esperado", str(esp),
                   "--catalogo", str(ROOT / F.DEFAULT_CATALOGO), "--out", str(out)]) == 0
    fila = _leer(out)[0]
    assert fila["categoria"] == "deteccion"
    assert fila["motivo"] == "senal:T1041-S1"
    assert fila["evidencia"].startswith("win_image=")


def test_h4w_sin_ancla(tmp_path):
    alerta = tmp_path / "alerta.csv"
    _escribir(alerta, [{
        "timestamp_utc": "2026-01-01T00:00:10Z",
        "agent_name": "victima-windows",
        "rule_id": "92029",
        "rule_level": "6",
        "rule_groups": "sysmon|sysmon_eid1_detections|windows",
        "rs_origen": "RS1",
        "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "win_command_line": r"powershell.exe -File C:\Users\angel\otro.ps1",
        "win_cwd": r"C:\Users\angel",
        "event_id": "1",
    }])
    esp = tmp_path / "ATA074_esperado.csv"
    _esperado(esp, [
        r"T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,test",
        r"T1041-S2,deteccion,win_command_line,*ATA074*,Command Execution,T1041,ancla H4-W",
    ])
    out = tmp_path / "out.csv"
    assert F.main(["--alerta", str(alerta), "--ata", "ATA074", "--esperado", str(esp),
                   "--catalogo", str(ROOT / F.DEFAULT_CATALOGO), "--out", str(out)]) == 0
    fila = _leer(out)[0]
    assert fila["categoria"] == "dudosa"
    assert fila["motivo"] == "sin_ancla:T1041-S1"


def test_h4w_evento_no_ejecucion(tmp_path):
    alerta = tmp_path / "alerta.csv"
    _escribir(alerta, [{
        "timestamp_utc": "2026-01-01T00:00:10Z",
        "agent_name": "victima-windows",
        "rule_id": "92213",
        "rule_level": "15",
        "rule_groups": "sysmon|sysmon_eid11_detections|windows",
        "rs_origen": "RS1",
        "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "win_command_line": r"powershell.exe -File C:\lab-attack\ATA074\run.ps1",
        "win_cwd": r"C:\lab-attack\ATA074",
        "event_id": "11",
    }])
    esp = tmp_path / "ATA074_esperado.csv"
    _esperado(esp, [
        r"T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,test",
        r"T1041-S2,deteccion,win_command_line,*ATA074*,Command Execution,T1041,ancla H4-W",
    ])
    out = tmp_path / "out.csv"
    assert F.main(["--alerta", str(alerta), "--ata", "ATA074", "--esperado", str(esp),
                   "--catalogo", str(ROOT / F.DEFAULT_CATALOGO), "--out", str(out)]) == 0
    fila = _leer(out)[0]
    assert fila["categoria"] == "dudosa"
    assert fila["motivo"] == "sin_ancla:T1041-S1"


def test_artefacto_ataque_por_command_line(tmp_path):
    alerta = tmp_path / "alerta.csv"
    _escribir(alerta, [{
        "timestamp_utc": "2026-01-01T00:00:10Z",
        "agent_name": "victima-windows",
        "rule_id": "99999",
        "rule_level": "3",
        "rule_groups": "windows",
        "rs_origen": "RS1",
        "win_image": r"C:\Windows\System32\cmd.exe",
        "win_command_line": r"cmd.exe /c copy C:\lab-attack\ATA074\datos.txt C:\lab-attack\ATA074\staging\datos.txt",
        "event_id": "1",
    }])
    esp = tmp_path / "ATA074_esperado.csv"
    _esperado(esp, [
        r"T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,test",
    ])
    out = tmp_path / "out.csv"
    assert F.main(["--alerta", str(alerta), "--ata", "ATA074", "--esperado", str(esp),
                   "--catalogo", str(ROOT / F.DEFAULT_CATALOGO), "--out", str(out)]) == 0
    fila = _leer(out)[0]
    assert fila["categoria"] == "artefacto_ataque"
    assert fila["motivo"] == "del_ataque"
    assert "ATA074" in fila["evidencia"]


def test_auto_ruido_vacio(tmp_path):
    fila = {
        "win_image": r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
        "rule_id": "67027",
    }
    assert F.detectar_auto_ruido(fila) is None


# --------------------------------------------------------------------------
# B1.0-SSH.1 — canal SSH: `auto_ruido` del servicio y predicado OPERADOR_WIN
# --------------------------------------------------------------------------
SENAL_67027 = [{
    "senal_id": "S1", "tipo": "deteccion", "campo": "rule_id", "patron": "67027",
    "dato_componente": "", "tecnica": "",
}]


def _clasif(row, operador=True):
    return F.clasificar(row, set(), SENAL_67027, False, [], "ATA056", operador=operador)


def test_auto_ruido_solo_imagen_sshd():
    assert F.detectar_auto_ruido(
        {"win_image": r"C:\Windows\System32\OpenSSH\sshd.exe"}
    ) == (r"win_image=C:\Windows\System32\OpenSSH\sshd.exe", "canal-ssh")
    # Los hijos del canal NO son auto_ruido (plan §5.2, regla 2).
    assert F.detectar_auto_ruido({"win_image": r"C:\Windows\System32\cmd.exe"}) is None


def test_operador_logon_red_angel():
    c = _clasif({"rule_id": "60106", "win_user": "angel", "logon_type": "3"})
    assert (c["categoria"], c["motivo"]) == ("ruido_conocido", "operador:60106")
    assert c["evidencia"] == "win_user=angel|logon_type=3"


def test_operador_usa_el_usuario_efectivo_no_el_subject():
    # En 4624 el `win_user` normalizado es la cuenta subject (equipo); el efectivo es
    # `win_target_user`. El predicado debe usar el segundo.
    c = _clasif({"rule_id": "60106", "win_user": "DESKTOP-BTMCFA5$",
                 "win_target_user": "angel", "logon_type": "3"})
    assert (c["categoria"], c["motivo"]) == ("ruido_conocido", "operador:60106")


def test_operador_logoff_red_angel():
    c = _clasif({"rule_id": "60137", "win_user": "angel", "logon_type": "3"})
    assert (c["categoria"], c["motivo"]) == ("ruido_conocido", "operador:60137")


def test_operador_servicio_sshd_virtual():
    for rid, ev in (("67024", "win_user=sshd_1660"), ("67023", "win_user=sshd_1660")):
        c = _clasif({"rule_id": rid, "win_user": "sshd_1660", "logon_type": "5"})
        assert (c["categoria"], c["motivo"], c["evidencia"]) == (
            "ruido_conocido", f"operador:{rid}", ev)


def test_operador_67028_angel_y_sshd():
    for user in ("angel", "sshd_4236"):
        c = _clasif({"rule_id": "67028", "win_user": user})
        assert (c["categoria"], c["motivo"]) == ("ruido_conocido", "operador:67028")


def test_operador_67022_por_ip_del_plan():
    c = _clasif({"rule_id": "67022", "srcip": "192.168.65.1"})
    assert (c["categoria"], c["motivo"]) == ("ruido_conocido", "operador:67022")


def test_operador_no_exime_sin_evidencia():
    # Sin `logon_type=3` no se demuestra que sea el logon de red: NO se excluye.
    c = _clasif({"rule_id": "60106", "win_user": "angel", "logon_type": "2"})
    assert c["categoria"] == "deteccion" and c["motivo"] == "novel"
    # Otro usuario no es el operador.
    c = _clasif({"rule_id": "60106", "win_user": "otro", "logon_type": "3"})
    assert c["categoria"] == "deteccion"
    # 67022 sin la IP del operador no se excluye.
    c = _clasif({"rule_id": "67022", "srcip": "10.0.0.5"})
    assert c["categoria"] == "deteccion"


def test_sin_operador_es_la_sensibilidad():
    row = {"rule_id": "60106", "win_user": "angel", "logon_type": "3"}
    assert _clasif(row, operador=True)["categoria"] == "ruido_conocido"
    assert _clasif(row, operador=False)["categoria"] == "deteccion"


def test_conflicto_operador_avisa_si_una_senal_declara_la_regla():
    senales = [{"senal_id": "S9", "tipo": "deteccion", "campo": "rule_id",
                "patron": "67028", "dato_componente": "", "tecnica": ""}]
    avisos = F.conflictos_operador(senales)
    assert len(avisos) == 1 and "67028" in avisos[0]


# --------------------------------------------------------------------------
# G-SSH.1 — CANDADO: una fila del ataque NUNCA cae en auto_ruido/ruido_conocido
# --------------------------------------------------------------------------
SENAL_99999 = [{
    "senal_id": "S9", "tipo": "deteccion", "campo": "rule_id", "patron": "99999",
    "dato_componente": "", "tecnica": "",
}]


def test_candado_60106_con_evidencia_de_ataque_no_es_ruido():
    row = {
        "rule_id": "60106", "win_user": "angel", "win_target_user": "angel",
        "logon_type": "3", "win_cwd": r"C:\lab-attack\ATA056",
    }
    c = F.clasificar(row, set(), SENAL_67027, False, [], "ATA056")
    # No casa ninguna señal (SENAL_67027 no aplica a 60106): artefacto determinista.
    assert c["categoria"] == "artefacto_ataque"
    assert c["categoria"] != "ruido_conocido"
    assert c["categoria"] != "auto_ruido"


def test_candado_sshd_con_evidencia_de_ataque_no_es_auto_ruido():
    row = {
        "rule_id": "67027", "win_image": r"C:\Windows\System32\OpenSSH\sshd.exe",
        "win_cwd": r"C:\lab-attack\ATA056",
    }
    # `detectar_auto_ruido` sí lo reconocería, pero el candado va antes.
    assert F.detectar_auto_ruido(row) is not None
    c = F.clasificar(row, set(), SENAL_99999, False, [], "ATA056")
    # No casa ninguna señal (SENAL_99999 no aplica a 67027): artefacto determinista.
    assert c["categoria"] == "artefacto_ataque"
    assert c["categoria"] != "auto_ruido"
    assert c["categoria"] != "ruido_conocido"


def test_candado_no_afecta_a_una_fila_ajena_al_ataque():
    # Sin evidencia de ataque, el orden Linux se mantiene: sshd.exe -> auto_ruido.
    row = {"rule_id": "67027", "win_image": r"C:\Windows\System32\OpenSSH\sshd.exe",
           "win_cwd": r"C:\Users\angel"}
    c = F.clasificar(row, set(), SENAL_67027, False, [], "ATA056")
    assert c["categoria"] == "auto_ruido"


def test_dry_run_canonico_0_y_sin_operador_30(tmp_path):
    detalle = ROOT / "Soporte" / "Ataques" / "c0" / "windows" / "canal_ssh_detalle.csv"
    esperado = ROOT / "Soporte" / "Ataques" / "c0" / "windows" / "canal_esperado_sintetico.csv"
    catalogo = ROOT / F.DEFAULT_CATALOGO
    if not (detalle.is_file() and esperado.is_file()):
        pytest.skip("faltan los artefactos del canal")
    out = tmp_path / "canal-Audited.csv"
    assert F.main(["--alerta", str(detalle), "--ata", "ATA056", "--iter", "1",
                   "--esperado", str(esperado), "--catalogo", str(catalogo),
                   "--out", str(out)]) == 0
    filas = _leer(out)
    assert len(filas) == 45
    assert sum(1 for f in filas if f["categoria"] == "deteccion") == 0
    out2 = tmp_path / "canal-sinop-Audited.csv"
    assert F.main(["--alerta", str(detalle), "--ata", "ATA056", "--iter", "1",
                   "--esperado", str(esperado), "--catalogo", str(catalogo),
                   "--sin-operador", "--out", str(out2)]) == 0
    filas2 = _leer(out2)
    assert sum(1 for f in filas2 if f["categoria"] == "deteccion") == 30


def test_modo_baseline_absorbe_novedad(tmp_path):
    alerta = tmp_path / "alerta.csv"
    _escribir(alerta, [{
        "timestamp_utc": "2026-01-01T00:00:10Z",
        "agent_name": "victima-windows",
        "rule_id": "99999",
        "rule_level": "3",
        "rule_groups": "windows",
        "rs_origen": "RS1",
    }])
    out = tmp_path / "out.csv"
    assert F.main(["--alerta", str(alerta), "--modo", "baseline",
                   "--catalogo", str(ROOT / F.DEFAULT_CATALOGO), "--out", str(out)]) == 0
    fila = _leer(out)[0]
    assert fila["categoria"] == "ruido_conocido"
    assert fila["motivo"] == "baseline"
