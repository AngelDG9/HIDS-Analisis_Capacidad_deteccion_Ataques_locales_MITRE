# -*- coding: utf-8 -*-
"""Tests offline de `filtrar_ruido.py` (Fase 3 · A2.1).

Cubren los casos **a–h** de `plan.md` §8 **sin VMs**: usan el fixture sintético
`tests/fixtures/filtro_*` y los ficheros reales del paso 0
(`Dataset/Legitimo/baseline_detalle_{v1,v2}.csv`, generados por
`extraer_alertas.py --detail`).

Determinismo (caso d): misma entrada -> salida **byte a byte** idéntica.
"""
from pathlib import Path
import csv
import hashlib
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import extraer_alertas as ea  # noqa: E402
import filtrar_ruido as fr  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]
CATALOGO = ROOT / "Dataset" / "Legitimo" / "ruleids_legitimos.csv"
DET_V1 = ROOT / "Dataset" / "Legitimo" / "baseline_detalle_v1.csv"
DET_V2 = ROOT / "Dataset" / "Legitimo" / "baseline_detalle_v2.csv"

ESP_EJEMPLO = FIX / "filtro_esperado_ejemplo.csv"
ALERTA_EJEMPLO = FIX / "filtro_alerta_ejemplo.csv"


# --------------------------------------------------------------------------
# utilidades
# --------------------------------------------------------------------------
def fila(ts, rid, exe="", cwd="", key="", typ="", file="", d="", syscheck="",
         groups="", rs="RS1", agent="victima-linux", desc="x", level="3",
         srcip="", srcuser="", dstuser=""):
    return {
        "timestamp_utc": ts,
        "agent_name": agent,
        "rule_id": rid,
        "rule_level": level,
        "rule_description": desc,
        "rule_groups": groups,
        "rs_origen": rs,
        "audit_exe": exe,
        "audit_cwd": cwd,
        "audit_key": key,
        "audit_type": typ,
        "audit_file": file,
        "audit_dir": d,
        "syscheck_path": syscheck,
        "srcip": srcip,
        "srcuser": srcuser,
        "dstuser": dstuser,
    }


def escribe_csv(path, campos, filas, comentario=None):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        if comentario:
            fh.write(comentario + "\n")
        w = csv.DictWriter(fh, fieldnames=campos, lineterminator="\n")
        w.writeheader()
        for r in filas:
            w.writerow(r)


def lee_salida(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def alerta_tmp(tmp_path, filas, nombre="alerta.csv"):
    p = tmp_path / nombre
    escribe_csv(p, ea.DETAIL_HEADER, filas, comentario="# fixture de test")
    return p


def esperado_tmp(tmp_path, filas, nombre="esperado.csv"):
    p = tmp_path / nombre
    escribe_csv(p, fr.SIGNAL_HEADER, filas)
    return p


# --------------------------------------------------------------------------
# caso (a): modo baseline -> 0 detección; todo en {auto_ruido, ruido_conocido}
# --------------------------------------------------------------------------
@pytest.mark.parametrize("detalle", [DET_V1, DET_V2])
def test_a_modo_baseline_sin_deteccion(tmp_path, detalle):
    out = tmp_path / (detalle.stem + "-Audited.csv")
    rc = fr.main([
        "--alerta", str(detalle), "--ata", "ATA000",
        "--catalogo", str(CATALOGO), "--modo", "baseline",
        "--out", str(out),
    ])
    assert rc == fr.EXIT_OK
    rows = lee_salida(out)
    assert rows, "la salida no puede estar vacía"
    cats = {r["categoria"] for r in rows}
    assert cats <= {"auto_ruido", "ruido_conocido"}
    assert all(r["categoria"] != "deteccion" for r in rows)
    # el auto-ruido del baseline es no nulo (80791/80792)
    assert sum(1 for r in rows if r["categoria"] == "auto_ruido") > 0


# --------------------------------------------------------------------------
# caso (b): rule.id no en catálogo -> deteccion/novel
# --------------------------------------------------------------------------
def test_b_novedad_es_deteccion(tmp_path):
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "999999", exe="/usr/bin/python3",
             cwd="/home/angel", key="audit-wazuh-c", typ="SYSCALL"),
    ])
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "S1", "tipo": "deteccion", "campo": "rule_id",
         "patron": "80790", "dato_componente": "File Creation",
         "tecnica": "T1486", "nota": ""},
    ])
    out = tmp_path / "b-Audited.csv"
    assert fr.main(["--alerta", str(alerta), "--ata", "ATA001",
                    "--catalogo", str(CATALOGO), "--esperado", str(esp),
                    "--out", str(out)]) == fr.EXIT_OK
    r = lee_salida(out)[0]
    assert r["categoria"] == "deteccion"
    assert r["motivo"] == "novel"


# --------------------------------------------------------------------------
# caso (c): auto-ruido por campos (80791/wazuh-agentd, 80792/cwd=/var/ossec)
# --------------------------------------------------------------------------
def test_c_auto_ruido_por_campos(tmp_path):
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "80791",
             exe="/var/ossec/bin/wazuh-agentd", cwd="/var/ossec",
             key="audit-wazuh-w", typ="SYSCALL", groups="audit|audit_watch_delete",
             rs="RS2"),
        fila("2026-09-23T10:00:01.000Z", "80792", exe="/usr/bin/ps",
             cwd="/var/ossec", key="audit-wazuh-c", typ="SYSCALL",
             groups="audit|audit_command", rs="RS2"),
    ])
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "S1", "tipo": "deteccion", "campo": "audit_key",
         "patron": "lab-attack*", "dato_componente": "File Modification",
         "tecnica": "T1486", "nota": ""},
    ])
    out = tmp_path / "c-Audited.csv"
    assert fr.main(["--alerta", str(alerta), "--ata", "ATA001",
                    "--catalogo", str(CATALOGO), "--esperado", str(esp),
                    "--out", str(out)]) == fr.EXIT_OK
    rows = lee_salida(out)
    assert {r["rule_id"] for r in rows} == {"80791", "80792"}
    assert all(r["categoria"] == "auto_ruido" for r in rows)
    assert not any(r["categoria"] == "deteccion" for r in rows)


# --------------------------------------------------------------------------
# caso (d): determinismo byte a byte
# --------------------------------------------------------------------------
def test_d_determinismo_byte_a_byte(tmp_path):
    out = tmp_path / "d-Audited.csv"
    rev = tmp_path / "d-Revision.csv"
    args = ["--alerta", str(ALERTA_EJEMPLO), "--ata", "ATA001",
            "--catalogo", str(CATALOGO), "--esperado", str(ESP_EJEMPLO),
            "--out", str(out), "--rev-out", str(rev)]
    assert fr.main(args) == fr.EXIT_OK
    b_out1, b_rev1 = out.read_bytes(), rev.read_bytes()
    assert fr.main(args) == fr.EXIT_OK
    b_out2, b_rev2 = out.read_bytes(), rev.read_bytes()
    assert b_out1 == b_out2
    assert b_rev1 == b_rev2
    assert hashlib.sha256(b_out1).hexdigest() == hashlib.sha256(b_out2).hexdigest()


# --------------------------------------------------------------------------
# caso (e): señal deteccion sobre regla conocida -> deteccion
# --------------------------------------------------------------------------
def test_e_senal_gana_al_catalogo(tmp_path):
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "80790", exe="/usr/bin/bash",
             cwd="/home/angel", key="lab-attack-w", typ="SYSCALL",
             file="/home/angel/lab-attack/x.txt",
             groups="audit|audit_watch_create", rs="RS2"),
    ])
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "E1", "tipo": "deteccion", "campo": "audit_key",
         "patron": "lab-attack*", "dato_componente": "File Creation",
         "tecnica": "T1486", "nota": ""},
    ])
    out = tmp_path / "e-Audited.csv"
    assert fr.main(["--alerta", str(alerta), "--ata", "ATA001",
                    "--catalogo", str(CATALOGO), "--esperado", str(esp),
                    "--out", str(out)]) == fr.EXIT_OK
    r = lee_salida(out)[0]
    assert r["categoria"] == "deteccion"
    assert r["motivo"] == "senal:E1"
    assert r["atribucion"] == "T1486|File Creation"
    assert r["evidencia"] == "audit_key=lab-attack-w"


# --------------------------------------------------------------------------
# caso (f): ambigua -> revisión -> veredicto -> --revision
# --------------------------------------------------------------------------
def test_f_revision_humana_se_pliega(tmp_path):
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "550", typ="",
             groups="ossec|syscheck|syscheck_file", rs="RS1",
             syscheck="/home/angel/lab-attack/secret.txt"),
    ])
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "A1", "tipo": "ambigua", "campo": "syscheck_path",
         "patron": "/home/angel/lab-attack/*", "dato_componente": "File Modification",
         "tecnica": "T1486", "nota": ""},
    ])
    out = tmp_path / "f-Audited.csv"
    rev = tmp_path / "f-Revision.csv"
    args = ["--alerta", str(alerta), "--ata", "ATA001", "--catalogo", str(CATALOGO),
            "--esperado", str(esp), "--out", str(out), "--rev-out", str(rev)]
    assert fr.main(args) == fr.EXIT_OK
    r = lee_salida(out)[0]
    assert r["categoria"] == "dudosa"
    assert r["motivo"] == "ambigua:A1"
    assert r["revision"] == "pendiente"

    # el humano rellena el veredicto en el CSV de revisión
    rev_rows = lee_salida(rev)
    assert len(rev_rows) == 1 and rev_rows[0]["veredicto"] == ""
    rev_rows[0]["veredicto"] = "ruido"
    rev_rows[0]["nota"] = "FIM de dir propio del baseline"
    rev_rows[0]["revisor"] = "angel"
    rev_rows[0]["fecha"] = "2026-09-25"
    escribe_csv(rev, fr.OUT_HEADER + fr.REV_EXTRA, rev_rows)

    assert fr.main(args + ["--revision", str(rev)]) == fr.EXIT_OK
    r2 = lee_salida(out)[0]
    assert r2["revision"] == "resuelta"
    assert r2["veredicto_humano"] == "ruido"
    assert r2["categoria"] == "ruido_conocido"
    assert "revisor=angel" in r2["evidencia"]


# --------------------------------------------------------------------------
# caso (g): rs_origen se copia sin alterar (RS1..RS4/UNKNOWN)
# --------------------------------------------------------------------------
def test_g_rs_origen_sin_alterar(tmp_path):
    filas = [
        fila(f"2026-09-23T10:00:0{i}.000Z", str(80000 + i), rs=rs,
             key="audit-wazuh-c", exe="/usr/bin/bash", cwd="/home/angel",
             typ="SYSCALL")
        for i, rs in enumerate(["RS1", "RS2", "RS3", "RS4", "UNKNOWN"])
    ]
    alerta = alerta_tmp(tmp_path, filas)
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "S1", "tipo": "deteccion", "campo": "rule_id",
         "patron": "1", "dato_componente": "x", "tecnica": "T1", "nota": ""},
    ])
    out = tmp_path / "g-Audited.csv"
    assert fr.main(["--alerta", str(alerta), "--ata", "ATA001",
                    "--catalogo", str(CATALOGO), "--esperado", str(esp),
                    "--out", str(out)]) == fr.EXIT_OK
    rows = lee_salida(out)
    assert [r["rs_origen"] for r in rows] == ["RS1", "RS2", "RS3", "RS4", "UNKNOWN"]


# --------------------------------------------------------------------------
# caso (h): ataque sin fichero de señales -> exit != 0
# --------------------------------------------------------------------------
def test_h_sin_señales_falla(tmp_path):
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "80790", key="audit-wazuh-c"),
    ])
    out = tmp_path / "h-Audited.csv"
    rc = fr.main(["--alerta", str(alerta), "--ata", "ATA999",
                  "--catalogo", str(CATALOGO), "--out", str(out)])
    assert rc != 0
    assert rc == fr.EXIT_NO_SIGNALS
    assert not out.exists()


# --------------------------------------------------------------------------
# H3 (fase-03-afinado §4.1) — predicado OPERADOR y golden del falso negativo
# --------------------------------------------------------------------------
# Señales NO relacionadas con las reglas del predicado: garantizan `sin_campos`
# (ninguna señal evaluable) para las reglas sin campos `audit.*`.
ESP_VACIO_ROWS = [
    {"senal_id": "N1", "tipo": "deteccion", "campo": "audit_key",
     "patron": "lab-attack*", "dato_componente": "File Modification",
     "tecnica": "T1486", "nota": ""},
    {"senal_id": "N2", "tipo": "ambigua", "campo": "syscheck_path",
     "patron": "/home/angel/lab-attack/*", "dato_componente": "File Modification",
     "tecnica": "T1486", "nota": ""},
]


def _corre_fila(tmp_path, alerta_fila, nombre):
    esp = esperado_tmp(tmp_path, ESP_VACIO_ROWS, nombre=nombre + "-esperado.csv")
    alerta = alerta_tmp(tmp_path, [alerta_fila], nombre=nombre + "-alerta.csv")
    out = tmp_path / (nombre + "-Audited.csv")
    rev = tmp_path / (nombre + "-Revision.csv")
    rc = fr.main(["--alerta", str(alerta), "--ata", "ATA001", "--catalogo",
                  str(CATALOGO), "--esperado", str(esp), "--out", str(out),
                  "--rev-out", str(rev)])
    assert rc == fr.EXIT_OK
    return lee_salida(out)[0]


def test_h3_5715_srcip_operador_autoexcluido(tmp_path):
    """5715 con srcip del operador -> ruido_conocido / operador:5715, revision vacía."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T20:31:20.000Z", "5715",
             groups="syslog|sshd|authentication_success", rs="RS1",
             desc="sshd: authentication success.", srcip="192.168.65.1",
             dstuser="angel"),
        "op5715",
    )
    assert r["categoria"] == "ruido_conocido"
    assert r["motivo"] == "operador:5715"
    assert r["revision"] == ""
    assert r["evidencia"] == "srcip=192.168.65.1"


def test_h3_golden_5715_srcip_ajeno_dudosa(tmp_path):
    """⭐ GOLDEN: 5715 con srcip AJENO (atacante) -> NO se excluye -> dudosa."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T20:31:20.000Z", "5715",
             groups="syslog|sshd|authentication_success", rs="RS1",
             desc="sshd: authentication success.", srcip="10.0.0.99",
             dstuser="angel"),
        "atk5715",
    )
    assert r["categoria"] == "dudosa"
    assert r["categoria"] != "ruido_conocido"
    assert r["motivo"] == "sin_campos"
    assert r["revision"] == "pendiente"


def test_h3_5715_sin_srcip_dudosa(tmp_path):
    """⚠️ Si falta el campo de origen -> condición NO satisfecha -> dudosa."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T20:31:20.000Z", "5715",
             groups="syslog|sshd|authentication_success", rs="RS1",
             desc="sshd: authentication success.", dstuser="angel"),
        "sin5715",
    )
    assert r["categoria"] == "dudosa"
    assert r["motivo"] == "sin_campos"


def test_h3_5715_grupo_incorrecto_dudosa(tmp_path):
    """CA-H3-d: un 5715 con grupo distinto NO entra en el predicado -> dudosa."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T20:31:20.000Z", "5715", groups="audit|audit_command",
             rs="RS2", desc="x", srcip="192.168.65.1"),
        "grp5715",
    )
    assert r["categoria"] == "dudosa"


@pytest.mark.parametrize("rid", ["5501", "5502"])
def test_h3_golden_pam_nunca_autoexcluida(tmp_path, rid):
    """⭐ GOLDEN: 5501/5502 con dstuser=angel -> NO auto-excluidas -> dudosa (decisión A)."""
    groups = ("pam|syslog|authentication_success" if rid == "5501"
              else "pam|syslog")
    desc = ("PAM: Login session opened." if rid == "5501"
            else "PAM: Login session closed.")
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T20:31:20.000Z", rid, groups=groups, rs="RS1",
             desc=desc, srcuser="angel", dstuser="angel"),
        "pam" + rid,
    )
    assert r["categoria"] == "dudosa"
    assert r["categoria"] != "ruido_conocido"
    assert r["motivo"] == "sin_campos"
    assert r["revision"] == "pendiente"


def test_h3_19004_sca_autoexcluido(tmp_path):
    """19004 con grupo sca -> auto-excluido (regla + grupo), sin condición de origen."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T21:43:10.000Z", "19004", groups="sca", rs="RS1",
             desc="SCA summary", level="7"),
        "sca19004",
    )
    assert r["categoria"] == "ruido_conocido"
    assert r["motivo"] == "operador:19004"
    assert r["evidencia"] == "rule_group=sca"


def test_h3_19004_grupo_incorrecto_no_operador(tmp_path, capsys):
    """CA-H3-d: un 19004 sin grupo sca NO entra en el predicado → no es `operador:`."""
    r = _corre_fila(
        tmp_path,
        fila("2026-09-25T21:43:10.000Z", "19004", groups="ossec", rs="RS1"),
        "grp19004",
    )
    assert r["motivo"] != "operador:19004"
    assert r["categoria"] in ("dudosa", "deteccion")


def test_h3_senal_deteccion_sobre_predicado_gana_y_conflicto(tmp_path, capsys):
    """CA-H3-b: señal deteccion declarada sobre 5715 -> deteccion + CONFLICTO por stderr."""
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-25T20:31:20.000Z", "5715",
             groups="syslog|sshd|authentication_success", rs="RS1",
             desc="sshd: authentication success.", srcip="192.168.65.1",
             dstuser="angel"),
    ], nombre="conf-alerta.csv")
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "D1", "tipo": "deteccion", "campo": "rule_id",
         "patron": "5715", "dato_componente": "Remote Login", "tecnica": "T1078",
         "nota": ""},
    ], nombre="conf-esperado.csv")
    out = tmp_path / "conf-Audited.csv"
    rc = fr.main(["--alerta", str(alerta), "--ata", "ATA001", "--catalogo",
                  str(CATALOGO), "--esperado", str(esp), "--out", str(out)])
    assert rc == fr.EXIT_OK
    r = lee_salida(out)[0]
    assert r["categoria"] == "deteccion"
    assert r["motivo"] == "senal:D1"
    err = capsys.readouterr().err
    assert "CONFLICTO" in err
    assert "5715" in err


def test_h3_conflicto_por_rule_group(tmp_path, capsys):
    """La garantía anti-frágil también cubre una señal rule_group que casa sca."""
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-25T21:43:10.000Z", "19004", groups="sca", rs="RS1"),
    ], nombre="cg-alerta.csv")
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "G1", "tipo": "ambigua", "campo": "rule_group",
         "patron": "sca", "dato_componente": "x", "tecnica": "T1", "nota": ""},
    ], nombre="cg-esperado.csv")
    out = tmp_path / "cg-Audited.csv"
    rc = fr.main(["--alerta", str(alerta), "--ata", "ATA001", "--catalogo",
                  str(CATALOGO), "--esperado", str(esp), "--out", str(out)])
    assert rc == fr.EXIT_OK
    err = capsys.readouterr().err
    assert "CONFLICTO" in err and "19004" in err


def test_h3_columnas_origen_en_detail_header():
    """CA-H3-e: el detalle gana srcip,srcuser,dstuser; el OUT_HEADER (15) no cambia."""
    assert ea.DETAIL_HEADER[-3:] == ["srcip", "srcuser", "dstuser"]
    assert len(fr.OUT_HEADER) == 15
    assert "srcip" not in fr.OUT_HEADER


# --------------------------------------------------------------------------
# columnas exactas §5
# --------------------------------------------------------------------------
def test_columnas_exactas_salida():
    assert fr.OUT_HEADER == [
        "ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level",
        "rule_groups", "rs_origen", "rule_description", "categoria", "motivo",
        "atribucion", "revision", "veredicto_humano", "evidencia",
    ]


# --------------------------------------------------------------------------
# cabo 1 (fase-03-piloto-custom §6.1): default de --out/--rev-out por SO
# --------------------------------------------------------------------------
def test_default_audited_dir_bajo_linux():
    """CA7: el default cae en `.../Wazuh/linux/Auditado` (guard de regresión)."""
    norm = fr.DEFAULT_AUDITED_DIR.replace("\\", "/")
    assert norm == "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"


def test_sin_out_escribe_bajo_linux_auditado(tmp_path, monkeypatch):
    """CA7: sin `--out`, la salida aterriza en `<cwd>/…/Wazuh/linux/Auditado/`."""
    monkeypatch.chdir(tmp_path)
    alerta = alerta_tmp(tmp_path, [
        fila("2026-09-23T10:00:00.000Z", "80790", exe="/usr/bin/cp",
             cwd="/home/angel/lab-attack/ATA007", key="audit-wazuh-c", typ="SYSCALL"),
    ], nombre="cabo1-alerta.csv")
    esp = esperado_tmp(tmp_path, [
        {"senal_id": "T1491-S1", "tipo": "deteccion", "campo": "audit_exe",
         "patron": "cp", "dato_componente": "Process Creation", "tecnica": "T1491",
         "nota": ""},
    ], nombre="cabo1-esperado.csv")
    rc = fr.main(["--alerta", str(alerta), "--ata", "ATA007",
                  "--catalogo", str(CATALOGO), "--esperado", str(esp)])
    assert rc == fr.EXIT_OK
    out = tmp_path / fr.DEFAULT_AUDITED_DIR / "ATA007_iter1-Audited.csv"
    assert out.is_file()
    assert "linux" in out.parts and "Auditado" in out.parts



# --------------------------------------------------------------------------
# no regresión de extraer_alertas.py (--test y --detail offline)
# --------------------------------------------------------------------------
def test_extraer_test_mode_sigue_ok(capsys):
    assert ea.main(["--test"]) == 0


def test_extraer_detail_offline(tmp_path):
    """El detalle extrae los campos confirmados en el paso 0 (offline, sintético)."""
    alerts = tmp_path / "alerts.jsonl"
    alerts.write_text(
        '{"timestamp":"2026-09-23T01:00:00.100+0000","rule":{"id":"80791","level":3,'
        '"description":"Audit: Deleted: var/run/.","groups":["audit","audit_watch_delete"]},'
        '"agent":{"name":"victima-linux"},'
        '"data":{"audit":{"type":"SYSCALL","exe":"/var/ossec/bin/wazuh-agentd",'
        '"cwd":"/var/ossec","key":"audit-wazuh-w","file":{"name":"var/run/x"}}}}\n'
        '{"timestamp":"2026-09-23T01:00:01.100+0000","rule":{"id":"554","level":5,'
        '"description":"File added to the system.","groups":["ossec","syscheck"]},'
        '"agent":{"name":"victima-linux"},'
        '"syscheck":{"path":"/etc/x"}}\n',
        encoding="utf-8",
    )
    out = tmp_path / "det.csv"
    rc = ea.main(["--alerts", str(alerts), "--desde", "2026-09-23T00:59:00Z",
                  "--hasta", "2026-09-23T01:01:00Z", "--detail", str(out),
                  "--ruleset-dir", str(tmp_path / "none"),
                  "--etc-rules-dir", str(tmp_path / "none")])
    assert rc == 0
    rows = lee_salida(out)
    assert len(rows) == 2
    a0 = rows[0]
    assert a0["rule_id"] == "80791"
    assert a0["audit_exe"] == "/var/ossec/bin/wazuh-agentd"
    assert a0["audit_cwd"] == "/var/ossec"
    assert a0["audit_key"] == "audit-wazuh-w"
    assert a0["audit_type"] == "SYSCALL"
    assert a0["audit_file"] == "var/run/x"
    a1 = rows[1]
    assert a1["syscheck_path"] == "/etc/x"
    assert a1["rs_origen"] == "UNKNOWN"
