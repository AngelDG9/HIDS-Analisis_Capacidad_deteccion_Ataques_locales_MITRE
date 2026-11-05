# -*- coding: utf-8 -*-
"""Tests de `filtrar_ventana_alertas.py` — filtro por agente + ventana UTC.

Cubren: exclusión del manager, ventana inclusiva en UTC (con desfases `+01:00`),
conservación de la cabecera comentada y de las columnas, recálculo del catálogo
por `rule_id` (misma semántica que `extraer_alertas.aggregate`) e idempotencia.
"""
from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import filtrar_ventana_alertas as F  # noqa: E402

HEADER = [
    "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
    "rule_groups", "rs_origen", "audit_exe", "audit_cwd", "audit_key",
    "audit_type", "audit_file", "audit_dir", "syscheck_path", "srcip",
    "srcuser", "dstuser",
]

FILAS = [
    # fuera de ventana por abajo (2026-11-01T23:59:59Z)
    ["2026-11-01T23:59:59.000Z", "victima-linux", "80792", "3", "Audit: Command: /usr/bin/date.", "audit|audit_command", "RS2", "/usr/bin/date", "/home/angel", "audit-wazuh-c", "SYSCALL", "/usr/bin/date", "", "", "", "", ""],
    # dentro, borde inferior exacto
    ["2026-11-02T00:00:00.000Z", "victima-linux", "80792", "3", "Audit: Command: /usr/bin/bash.", "audit|audit_command", "RS2", "/usr/bin/bash", "/home/angel", "audit-wazuh-c", "SYSCALL", "/usr/bin/bash", "", "", "", "", ""],
    # manager (se excluye aunque esté en ventana)
    ["2026-11-02T00:30:01.644Z", "wazuh-server", "5501", "3", "PAM: Login session opened.", "pam|syslog", "RS1", "", "", "", "", "", "", "", "", "", ""],
    # dentro, con descripción que lleva coma (comillas CSV)
    ["2026-11-03T12:00:00.500Z", "victima-linux", "80790", "3", "Audit: Created: /home/angel/a,b.tar.gz.", "audit|audit_watch_create", "RS2", "/usr/bin/tar", "/home/angel", "audit-wazuh-w", "SYSCALL", "a,b.tar.gz", "home/angel", "", "", "", ""],
    # dentro, con desfase +01:00 => 2026-11-04T23:59:59Z
    ["2026-11-05T00:59:59.000+01:00", "victima-linux", "80791", "3", "Audit: Deleted: var/run/.", "audit|audit_watch_delete", "RS2", "/var/ossec/bin/wazuh-agentd", "/var/ossec", "audit-wazuh-w", "SYSCALL", "var/run/", "var/run/", "", "", "", ""],
    # borde superior exacto: 2026-11-05T01:00:00+01:00 == 2026-11-05T00:00:00Z
    ["2026-11-05T01:00:00.000+01:00", "victima-linux", "80792", "3", "Audit: Command: /usr/bin/date.", "audit|audit_command", "RS2", "/usr/bin/date", "/home/angel", "audit-wazuh-c", "SYSCALL", "/usr/bin/date", "", "", "", "", ""],
    # fuera de ventana por arriba
    ["2026-11-05T00:00:01.000Z", "victima-linux", "80792", "3", "Audit: Command: /usr/bin/date.", "audit|audit_command", "RS2", "/usr/bin/date", "/home/angel", "audit-wazuh-c", "SYSCALL", "/usr/bin/date", "", "", "", "", ""],
]


def _escribir(path, filas=FILAS, comentario="# detalle_rs.csv | prueba | columnas: " + ",".join(HEADER)):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(comentario + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(HEADER)
        w.writerows(filas)
    return path


def _leer(path):
    lineas = path.read_text(encoding="utf-8").splitlines()
    comentarios = [ln for ln in lineas if ln.startswith("#")]
    datos = [ln for ln in lineas if not ln.startswith("#")]
    return comentarios, list(csv.DictReader(datos))


def _ejecutar(tmp_path, entrada, salida=None, ruleids=None):
    salida = salida or (tmp_path / "alertas_detalle.csv")
    ruleids = ruleids or (tmp_path / "ruleids_legitimos.csv")
    rc = F.main([
        "--in", str(entrada), "--out", str(salida),
        "--ruleids-out", str(ruleids), "--agente", "victima-linux",
        "--desde", "2026-11-02T00:00:00Z", "--hasta", "2026-11-05T00:00:00Z",
    ])
    assert rc == 0
    return salida, ruleids


def test_filtra_agente_y_ventana_utc(tmp_path):
    entrada = _escribir(tmp_path / "entrada.csv")
    salida, _ = _ejecutar(tmp_path, entrada)
    _com, filas = _leer(salida)
    # quedan: borde inferior, 80790, 80791(+01:00), borde superior (+01:00)
    assert [f["rule_id"] for f in filas] == ["80792", "80790", "80791", "80792"]
    assert all(f["agent_name"] == "victima-linux" for f in filas)
    assert filas[0]["timestamp_utc"] == "2026-11-02T00:00:00.000Z"
    assert filas[-1]["timestamp_utc"] == "2026-11-05T01:00:00.000+01:00"
    # la coma dentro de la descripción sobrevive
    assert filas[1]["rule_description"] == "Audit: Created: /home/angel/a,b.tar.gz."


def test_cabecera_comentada_y_columnas(tmp_path):
    entrada = _escribir(tmp_path / "entrada.csv")
    salida, _ = _ejecutar(tmp_path, entrada)
    comentarios, _filas = _leer(salida)
    assert comentarios[0].startswith("# detalle_rs.csv | prueba")
    assert any(c.startswith(F.TAG_FILTRO) for c in comentarios)
    nota = next(c for c in comentarios if c.startswith(F.TAG_FILTRO))
    assert "entrada=7 salida=4" in nota
    assert "descartadas_agente=1" in nota
    assert "descartadas_ventana=2" in nota
    assert _filas and list(_filas[0].keys()) == HEADER


def test_ruleids_semantica_agregada(tmp_path):
    entrada = _escribir(tmp_path / "entrada.csv")
    _salida, ruleids = _ejecutar(tmp_path, entrada)
    _com, filas = _leer(ruleids)
    por_id = {f["rule_id"]: f for f in filas}
    assert set(por_id) == {"80790", "80791", "80792"}
    # 80792: dos filas (borde inferior y borde superior), nivel/desc de la primera
    assert por_id["80792"]["count"] == "2"
    assert por_id["80792"]["first_seen"] == "2026-11-02T00:00:00Z"
    assert por_id["80792"]["last_seen"] == "2026-11-05T00:00:00Z"
    assert por_id["80792"]["rule_description"] == "Audit: Command: /usr/bin/bash."
    assert por_id["80792"]["rs_origen"] == "RS2"
    assert por_id["80791"]["first_seen"] == "2026-11-04T23:59:59Z"
    assert list(filas[0].keys()) == F.CSV_HEADER
    # orden numérico
    assert [f["rule_id"] for f in filas] == ["80790", "80791", "80792"]


def test_idempotente(tmp_path):
    """Re-filtrar no duplica la línea de filtro ni altera las filas."""
    entrada = _escribir(tmp_path / "entrada.csv")
    salida, ruleids = _ejecutar(tmp_path, entrada)
    _com, primeras = _leer(salida)
    _ejecutar(tmp_path, salida, salida, ruleids)
    comentarios, segundas = _leer(salida)
    assert segundas == primeras
    assert sum(1 for c in comentarios if c.startswith(F.TAG_FILTRO)) == 1
