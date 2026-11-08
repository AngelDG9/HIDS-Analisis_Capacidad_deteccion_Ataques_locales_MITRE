# -*- coding: utf-8 -*-
"""Tests de `analizar_legitimo_72h.py` y `cruzar_doble_uso.py` — L2 (`legitimo-analisis`).

Cubren: unidad = línea de `archives` (1:1 evento↔alerta), `M` recalculado, predicado
`auto_ruido` por campos, catálogo (suma de `count`), catálogo M1b (unión declarada),
determinismo del `.gz` y el cruce de doble uso (legítimo × ataque).
"""
from pathlib import Path
import csv
import gzip
import hashlib
import json
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import analizar_legitimo_72h as L2  # noqa: E402
import cruzar_doble_uso as DU  # noqa: E402

RULEIDS_HEADER = ["rule_id", "rule_level", "rule_description", "groups", "rs_origen", "count",
                  "first_seen", "last_seen"]
RULEIDS = [
    ("11", 4, "", "stats", "UNKNOWN", 1, "2026-11-02T00:48:11Z", "2026-11-02T00:48:11Z"),
    ("554", 5, "File added.", "ossec|syscheck", "RS1", 1, "2026-11-02T11:15:40Z", "2026-11-02T11:15:40Z"),
    ("591", 3, "Log file rotated.", "ossec", "RS1", 0, "", ""),
    ("1002", 2, "Unknown problem somewhere.", "syslog", "RS2", 0, "", ""),
    ("80791", 3, "Audit: Deleted.", "audit|audit_watch_delete", "RS2", 1, "", ""),
    ("80792", 3, "Audit: Command.", "audit|audit_command", "RS2", 2, "", ""),
]
RULEIDS_HIST_HEADER = ["rule_id", "rule_level", "rule_description", "groups", "rs_origen",
                       "count_v1", "count_v2", "count_total", "ventanas"]
RULEIDS_HIST = [
    ("5402", 3, "sudo", "syslog|sudo", "RS1", 1, 1, 2, "v1+v2"),
    ("5501", 3, "PAM open", "pam", "RS1", 1, 1, 2, "v1+v2"),
]
CAMPANA_HEADER = ["caso", "ini", "fin", "n_acciones", "n_eventos", "alertas", "rule_id", "level",
                  "esperado_cumplido"]


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _ev(ts, rid=None, level=3, agent="001", **data):
    rec = {"timestamp": ts, "agent": {"id": agent, "name": "victima-linux" if agent == "001" else "wazuh-server"},
           "full_log": "x"}
    if rid is not None:
        rec["rule"] = {"id": rid, "level": level, "groups": ["audit"] if rid.startswith("807") else ["ossec"]}
    if data:
        rec["data"] = data
    return json.dumps(rec, ensure_ascii=False)


def _fixtures(tmp_path):
    den = tmp_path / "denominador"
    den.mkdir()
    lineas = [
        _ev("2026-11-02T00:00:01.000+0000"),                                # sin rule (no alerta)
        _ev("2026-11-02T00:00:02.000+0000", "80792", 3,
            audit={"exe": "/var/ossec/bin/wazuh-agentd", "cwd": "/home/angel"}),  # auto (exe)
        _ev("2026-11-02T00:00:03.000+0000", "80792", 3,
            audit={"exe": "/usr/bin/bash", "cwd": "/home/angel"}),          # NO auto
        _ev("2026-11-02T00:00:04.000+0000", "591", 3, agent="000"),          # manager
        _ev("2026-11-02T00:00:05.000+0000", "1002", 2),                      # nivel 2 (no alerta)
        _ev("2026-11-02T00:00:06.000+0000", "554", 5),                       # RS1
        _ev("2026-11-05T00:00:01.000+0000", "80792", 3),                     # fuera de ventana
    ]
    (den / "ossec-archive-01.json").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    with gzip.open(den / "ossec-archive-02.json.gz", "wt", encoding="utf-8", newline="") as fh:
        fh.write(_ev("2026-11-02T01:00:00.000+0000", "80791", 3,
                     audit={"exe": "/usr/bin/rm", "cwd": "/var/ossec"}) + "\n")  # auto (cwd)

    ruleids = tmp_path / "ruleids.csv"
    _escribir(ruleids, RULEIDS_HEADER, RULEIDS)
    hist = tmp_path / "ruleids_hist.csv"
    _escribir(hist, RULEIDS_HIST_HEADER, RULEIDS_HIST)
    camp = tmp_path / "campana.csv"
    _escribir(camp, CAMPANA_HEADER, [
        ("C-01", "2026-11-02T00:00:00Z", "2026-11-02T00:00:10Z", "", "", 2,
         "80792", 3, "SI"),
    ])
    return den, ruleids, hist, camp


def _args(den, ruleids, hist, camp, out):
    return ["--archives", str(den), "--ruleids", str(ruleids), "--ruleids-historico", str(hist),
            "--campana", str(camp), "--out-dir", str(out), "--detalle-out", str(out / "detalle.csv")]


def _leer(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("# ")]
    return list(csv.DictReader(lines))


def _leer_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("# ")]
    return list(csv.DictReader(lines))


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_indice_M_y_auto(tmp_path):
    den, ruleids, hist, camp = _fixtures(tmp_path)
    out = tmp_path / "out"
    assert L2.main(_args(den, ruleids, hist, camp, out)) == 0

    idx = _leer_gz(out / "eventos_alerta_72h.csv.gz")
    # M_endpoint = 5 (eventos 1,2,3,5,6); el del manager y el de fuera de ventana no cuentan
    assert len(idx) == 4  # 2 alertas 80792 + 554 + 80791 (nivel 2 excluido, sin rule excluido)
    assert {r["unidad"].split(":")[0] for r in idx} == {"01", "02"}
    # 1:1: unidad única
    assert len({r["unidad"] for r in idx}) == 4
    # auto: exe wazuh-agentd y cwd /var/ossec; el bash NO
    assert sum(int(r["auto_ruido"]) for r in idx) == 2
    auto = [r for r in idx if r["auto_ruido"] == "1"]
    assert {r["rule_id"] for r in auto} == {"80791", "80792"}
    # rs_origen sale del catálogo
    assert {r["rule_id"]: r["rs_origen"] for r in idx}["554"] == "RS1"

    dia = _leer(out / "estabilidad_dia.csv")
    assert len(dia) == 1
    assert dia[0]["M"] == "6"  # 5 eventos del fichero 01 + 1 del fichero 02
    assert dia[0]["FP_uni_C1_N0"] == "4"
    assert dia[0]["auto"] == "2"

    det = _leer(out / "detalle.csv")
    assert len(det) == 4
    assert {r["categoria"] for r in det} == {"auto_ruido", "ruido_conocido"}


def test_catalogos_y_campana(tmp_path):
    den, ruleids, hist, camp = _fixtures(tmp_path)
    out = tmp_path / "out"
    assert L2.main(_args(den, ruleids, hist, camp, out)) == 0

    cat = _leer(out / "catalogo_ruido_72h.csv")
    assert len(cat) == 6
    assert sum(int(r["count"]) for r in cat) == 5  # 1+1+0+0+1+2
    assert sum(int(r["alertas_auto"]) for r in cat) == 2
    # `rule 11` está en el catálogo pero no tiene unidad (stats)
    r11 = [r for r in cat if r["rule_id"] == "11"][0]
    assert r11["alertas_auto"] == "0" and r11["alertas_no_auto"] == "0"

    m1b = _leer(out / "catalogo_M1b.csv")
    assert len(m1b) == 10  # 6 de 72 h + las 4 históricas (unión declarada)
    hist_rows = [r for r in m1b if r["origen_catalogo"] == "baseline_historico"]
    assert {r["rule_id"] for r in hist_rows} == {"5402", "5501", "5502", "5715"}
    assert all(r["count_72h"] == "0" for r in hist_rows)

    camp_out = _leer(out / "campana_estabilidad.csv")
    assert len(camp_out) == 1
    assert camp_out[0]["alertas"] == "3"  # 2x80792 + 554 en [ini-10s, fin+60s]
    assert camp_out[0]["nivel_max"] == "5"  # 554 es nivel 5


def test_gz_determinista(tmp_path):
    den, ruleids, hist, camp = _fixtures(tmp_path)
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    assert L2.main(_args(den, ruleids, hist, camp, out1)) == 0
    assert L2.main(_args(den, ruleids, hist, camp, out2)) == 0
    assert _sha(out1 / "eventos_alerta_72h.csv.gz") == _sha(out2 / "eventos_alerta_72h.csv.gz")


AUD_HEADER = ["ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level",
              "rule_groups", "rs_origen", "rule_description", "categoria", "motivo",
              "atribucion", "revision", "veredicto_humano", "evidencia"]


def test_doble_uso(tmp_path):
    aud = tmp_path / "Auditado"
    for ata, rid in (("ATA001", "80792"), ("ATA002", "80781")):
        _escribir(aud / f"{ata}_iter1-Audited.csv", AUD_HEADER,
                  [(ata, 1, "2026-01-01T00:00:10Z", "victima-linux", rid, 3, "audit",
                    "RS2", "d", "deteccion", "", "", "", "", "")])
    rep = tmp_path / "rep.csv"
    _escribir(rep, ["ata_id"], [])
    cat = tmp_path / "cat.csv"
    _escribir(cat, ["rule_id", "rule_level", "rs_origen", "groups", "count"],
              [("554", 5, "RS1", "ossec", 1), ("80781", 3, "RS2", "audit", 1),
               ("80792", 3, "RS2", "audit", 3), ("11", 4, "UNKNOWN", "stats", 1)])
    idx = tmp_path / "idx.csv"
    _escribir(idx, ["unidad", "timestamp_utc", "rule_id", "rule_level", "rs_origen", "auto_ruido"],
              [("01:1", "t", "554", 5, "RS1", 0), ("01:2", "t", "80781", 3, "RS2", 0),
               ("01:3", "t", "80792", 3, "RS2", 1)])
    out = tmp_path / "T5.csv"
    assert DU.main(["--catalogo", str(cat), "--indice", str(idx), "--auditado", str(aud),
                    "--repeticiones", str(rep), "--out", str(out)]) == 0
    filas = {r["rule_id"]: r for r in _leer(out)}
    assert filas["554"]["doble_uso"] == "NO"
    assert filas["80781"]["doble_uso"] == "SÍ"
    assert filas["80781"]["attack_casos"] == "1"
    assert filas["80792"]["doble_uso"] == "SÍ"
    assert filas["80792"]["attack_detecciones"] == "1"
    assert filas["11"]["doble_uso"] == "NO"
    # 80781 es redundante: 80792 ya cubre ATA002? no (80792 cubre ATA001) -> nota "principal"
    assert filas["80781"]["nota"].startswith("principal")
