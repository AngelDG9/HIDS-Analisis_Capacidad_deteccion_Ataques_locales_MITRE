# -*- coding: utf-8 -*-
"""Tests de `canal_windows.py` — huella del canal SSH (B1.0-SSH.1).

Sin VMs: detalle sintético con la forma de `extraer_alertas_windows.py`.
Se fija que:
1. entran las reglas de identidad del canal y la imagen `sshd.exe`;
2. **no** entran los hijos (`cmd.exe`) ni el ruido ajeno;
3. la salida tiene exactamente las 7 columnas del plan y es determinista.
"""
import csv
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import canal_windows as C  # noqa: E402

HEADER = [
    "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
    "rule_groups", "rs_origen", "audit_exe", "audit_cwd", "audit_key", "audit_type",
    "audit_file", "audit_dir", "syscheck_path", "srcip", "srcuser", "dstuser",
    "agent_id", "win_image", "win_command_line", "win_cwd", "win_user", "event_id",
    "win_target", "logon_type", "win_parent_image", "win_target_user",
]

FILAS = [
    # logon de red SSH
    {"rule_id": "60106", "rule_level": "3", "event_id": "4624", "srcip": "",
     "win_user": "DESKTOP-BTMCFA5$", "win_target_user": "angel", "logon_type": "3"},
    # logon de servicio
    {"rule_id": "67024", "rule_level": "3", "event_id": "4624", "srcip": "",
     "win_user": "sshd_1660", "win_target_user": "sshd_1660", "logon_type": "5"},
    # proceso del servicio
    {"rule_id": "67027", "rule_level": "3", "event_id": "4688", "srcip": "",
     "win_image": r"C:\Windows\System32\OpenSSH\sshd.exe", "win_user": "SYSTEM"},
    # hijo del canal: NO es canal
    {"rule_id": "92052", "rule_level": "4", "event_id": "1", "srcip": "",
     "win_image": r"C:\Windows\System32\cmd.exe",
     "win_parent_image": r"C:\Windows\System32\OpenSSH\sshd.exe",
     "win_user": "angel", "win_target_user": "angel"},
    # ruido ajeno
    {"rule_id": "92213", "rule_level": "15", "event_id": "11", "srcip": "",
     "win_image": r"C:\Users\angel\nota.txt"},
]


def _escribir(path, filas):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HEADER, lineterminator="\n")
        w.writeheader()
        for r in filas:
            w.writerow({k: r.get(k, "") for k in HEADER})


def test_es_canal_solo_identidad_y_servicio():
    assert C.es_canal(FILAS[0]) and C.es_canal(FILAS[1]) and C.es_canal(FILAS[2])
    assert not C.es_canal(FILAS[3])   # cmd.exe hijo de sshd
    assert not C.es_canal(FILAS[4])


def test_construir_7_columnas_y_usuario_efectivo():
    canal = C.construir(FILAS)
    assert len(canal) == 3
    for fila in canal:
        assert len(fila) == len(C.SALIDA) == 7
    fila60106 = next(f for f in canal if f[0] == "60106")
    assert fila60106[4] == "angel"        # target_user, no la cuenta subject
    assert fila60106[5] == "3"


def test_main_determinista(tmp_path):
    entrada = tmp_path / "detalle.csv"
    _escribir(entrada, FILAS)
    out1 = tmp_path / "a" / "canal.csv"
    out2 = tmp_path / "b" / "canal.csv"
    assert C.main(["--alerta", str(entrada), "--out", str(out1)]) == 0
    assert C.main(["--alerta", str(entrada), "--out", str(out2)]) == 0
    assert out1.read_bytes() == out2.read_bytes()
    texto = out1.read_text(encoding="utf-8")
    assert texto.startswith("# canal.csv")
    assert "columnas: " + ",".join(C.SALIDA) in texto
