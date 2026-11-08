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

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import filtrar_ruido_windows as F  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]

HEADER = [
    "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
    "rule_groups", "rs_origen", "win_image", "win_command_line", "win_cwd",
    "win_user", "event_id", "syscheck_path", "win_target",
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
