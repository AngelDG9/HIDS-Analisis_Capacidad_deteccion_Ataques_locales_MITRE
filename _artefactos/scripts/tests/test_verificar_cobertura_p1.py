# -*- coding: utf-8 -*-
"""Tests offline de `verificar_cobertura_p1.py` (bloque fase-03-p1-cierre, §6.3).

Cubren C1 (cuadre) y C2 (padre/hijo) con fixtures pequeños **en memoria** (y un
CSV temporal para `load_rows`). **No necesitan VMs ni red.**
"""
from pathlib import Path
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import verificar_cobertura_p1 as vc  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures en memoria
# ---------------------------------------------------------------------------
def corpus_row(tecnica, padre="", **kw):
    return {
        "tecnica_id": tecnica,
        "nombre": kw.get("nombre", tecnica),
        "es_subtecnica": "si" if padre else "no",
        "padre_id": padre,
        "tacticas": kw.get("tacticas", "Impact"),
        "plataformas": kw.get("plataformas", "Linux;Windows"),
        "host_eligible": kw.get("host_eligible", "YES"),
        "priority": kw.get("priority", "P1"),
    }


CORPUS = [
    corpus_row("T1000"),
    corpus_row("T1000.001", padre="T1000"),
    corpus_row("T1000.002", padre="T1000"),
    corpus_row("T2000"),
    corpus_row("T3000", host_eligible="NO"),  # fuera de la piscina
    corpus_row("T4000", priority="P2"),       # fuera de la piscina
    corpus_row("T5000", plataformas="Windows"),  # fuera de la piscina
]

TARGET_OK = {
    "medida": 1,
    "cubierta_por_ata": 1,
    "cubierta_madre": 1,
    "cubierta_parcial": 0,
    "no_factible": 1,
}


def cov_row(tecnica, estado, clasificacion, ata="", motivo="", detalle=""):
    return {
        "tecnica": tecnica,
        "tactica": "Impact",
        "nombre": tecnica,
        "es_subtecnica": "",
        "padre_id": "",
        "plataformas": "Linux",
        "estado": estado,
        "clasificacion": clasificacion,
        "ata_o_cubierta_por": ata,
        "motivo_codigo": motivo,
        "motivo_detalle": detalle,
        "cita": "fixture",
    }


def cov_ok():
    return [
        cov_row("T1000", "cubierta", "cubierta_madre"),
        cov_row("T1000.001", "cubierta", "cubierta_por_ata", ata="ATA001"),
        cov_row("T1000.002", "medida", "medida", ata="ATA002"),
        cov_row("T2000", "no_factible", "no_factible", motivo="otra_plataforma"),
    ]


ATA_INDEX = {
    "ATA001": {"ata_id": "ATA001", "tecnica": "T1000"},       # bajo la madre, implementa la hija
    "ATA002": {"ata_id": "ATA002", "tecnica": "T1000.002"},
    "ATA009": {"ata_id": "ATA009", "tecnica": "T9999"},       # tecnica ajena
}


# ---------------------------------------------------------------------------
# Piscina P1-Linux
# ---------------------------------------------------------------------------
def test_pool_p1_linux():
    pool = vc.p1_linux_pool(CORPUS)
    assert pool == ["T1000", "T1000.001", "T1000.002", "T2000"]


# ---------------------------------------------------------------------------
# C1 — caso OK
# ---------------------------------------------------------------------------
def test_c1_ok():
    crosstab = vc.c1_check(cov_ok(), CORPUS, expected_total=4, target=TARGET_OK)
    assert crosstab == TARGET_OK


def test_c1_total_incorrecto():
    with pytest.raises(vc.ErrorCobertura, match="4 filas"):
        vc.c1_check(cov_ok(), CORPUS, expected_total=5, target=TARGET_OK)


def test_c1_categoria_descuadrada():
    target = dict(TARGET_OK, no_factible=0, medida=2)
    with pytest.raises(vc.ErrorCobertura, match="crosstab"):
        vc.c1_check(cov_ok(), CORPUS, expected_total=4, target=target)


def test_c1_tecnica_faltante():
    rows = [r for r in cov_ok() if r["tecnica"] != "T2000"]
    with pytest.raises(vc.ErrorCobertura, match="faltan"):
        vc.c1_check(rows, CORPUS, expected_total=4, target=TARGET_OK)


def test_c1_tecnica_extra():
    rows = cov_ok() + [cov_row("T2001", "no_factible", "no_factible", motivo="x")]
    with pytest.raises(vc.ErrorCobertura, match="sobran"):
        vc.c1_check(rows, CORPUS, expected_total=5, target=TARGET_OK)


def test_c1_tecnica_duplicada():
    rows = cov_ok() + [cov_row("T2000", "no_factible", "no_factible", motivo="x")]
    with pytest.raises(vc.ErrorCobertura, match="duplicadas"):
        vc.c1_check(rows, CORPUS, expected_total=5, target=TARGET_OK)


def test_c1_cubierta_por_ata_sin_ata():
    rows = cov_ok()
    rows[1]["ata_o_cubierta_por"] = ""
    with pytest.raises(vc.ErrorCobertura, match="ata_o_cubierta_por"):
        vc.c1_check(rows, CORPUS, expected_total=4, target=TARGET_OK)


def test_c1_no_factible_sin_motivo():
    rows = cov_ok()
    rows[3]["motivo_codigo"] = ""
    with pytest.raises(vc.ErrorCobertura, match="motivo_codigo"):
        vc.c1_check(rows, CORPUS, expected_total=4, target=TARGET_OK)


def test_c1_combinacion_estado_invalida():
    rows = cov_ok()
    rows[0]["clasificacion"] = "cubierta_por_ata"  # estado 'cubierta' + madre -> valido; aqui forzamos mala
    rows[0]["estado"] = "medida"
    with pytest.raises(vc.ErrorCobertura, match="combinacion"):
        vc.c1_check(rows, CORPUS, expected_total=4, target=TARGET_OK)


# ---------------------------------------------------------------------------
# C2 — caso OK y las 4 violaciones
# ---------------------------------------------------------------------------
def test_c2_ok():
    vc.c2_check(cov_ok(), CORPUS, ATA_INDEX)  # no lanza


def test_c2_regla1_madre_cubierta_con_hija_no_medida():
    rows = cov_ok()
    rows[2] = cov_row("T1000.002", "no_factible", "no_factible", motivo="x")
    with pytest.raises(vc.ErrorCobertura, match="regla 1"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


def test_c2_regla2_hija_por_hermana():
    rows = cov_ok()
    rows[1]["ata_o_cubierta_por"] = "ATA002"  # ATA002 -> T1000.002 (hermana)
    with pytest.raises(vc.ErrorCobertura, match="regla 2"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


def test_c2_regla3_madre_cubierta_por_descendiente():
    rows = cov_ok()
    rows[1]["ata_o_cubierta_por"] = "ATA001"  # deja .001 correcto
    rows[2]["ata_o_cubierta_por"] = "ATA002"
    # madre T1000 cita a una hija -> descendiente
    rows[0]["ata_o_cubierta_por"] = "ATA002"
    with pytest.raises(vc.ErrorCobertura, match="regla 3"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


def test_c2_regla4_ata_inexistente():
    rows = cov_ok()
    rows[1]["ata_o_cubierta_por"] = "ATA999"
    with pytest.raises(vc.ErrorCobertura, match="no existe"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


def test_c2_regla4_tecnica_ajena():
    rows = cov_ok()
    rows[1]["ata_o_cubierta_por"] = "ATA009"  # tecnica T9999, ajena
    with pytest.raises(vc.ErrorCobertura, match="regla 4"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


def test_c2_medida_cita_ancestro():
    rows = cov_ok()
    rows[2]["ata_o_cubierta_por"] = "ATA001"  # T1000 (ancestro), no su propia tecnica
    with pytest.raises(vc.ErrorCobertura, match="'medida'"):
        vc.c2_check(rows, CORPUS, ATA_INDEX)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def test_ancestors():
    parents = vc.parent_map(CORPUS)
    assert vc.ancestors("T1000.001", parents) == {"T1000"}
    assert vc.ancestors("T1000", parents) == set()


def test_categoria_valida():
    assert vc.categoria(cov_row("T1", "medida", "medida")) == "medida"
    assert vc.categoria(cov_row("T1", "cubierta", "cubierta_madre")) == "cubierta_madre"


def test_load_rows_salta_comentarios(tmp_path):
    p = tmp_path / "c.csv"
    p.write_text("# comentario\ntecnica,estado\nT1,medida\n", encoding="utf-8")
    rows = vc.load_rows(p)
    assert len(rows) == 1
    assert rows[0]["tecnica"] == "T1"


# ---------------------------------------------------------------------------
# CLI (--c1 solo, --c2 solo, --todo)
# ---------------------------------------------------------------------------
def _write_fixtures(tmp_path):
    import csv as _csv

    corpus = tmp_path / "corpus.csv"
    with open(corpus, "w", encoding="utf-8", newline="\n") as fh:
        w = _csv.DictWriter(
            fh,
            fieldnames=["tecnica_id", "nombre", "es_subtecnica", "padre_id",
                        "tacticas", "plataformas", "host_eligible", "priority"],
            lineterminator="\n",
        )
        w.writeheader()
        for r in CORPUS:
            w.writerow(r)

    cov = tmp_path / "cobertura.csv"
    with open(cov, "w", encoding="utf-8", newline="\n") as fh:
        w = _csv.DictWriter(fh, fieldnames=list(cov_ok()[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(cov_ok())

    ata = tmp_path / "ata.csv"
    with open(ata, "w", encoding="utf-8", newline="\n") as fh:
        w = _csv.DictWriter(fh, fieldnames=["ata_id", "tecnica"], lineterminator="\n")
        w.writeheader()
        for k, v in ATA_INDEX.items():
            w.writerow({"ata_id": k, "tecnica": v["tecnica"]})
    return str(corpus), str(cov), str(ata)


def test_cli_c2_solo(tmp_path, capsys):
    corpus, cov, ata = _write_fixtures(tmp_path)
    rc = vc.main(["--c2", "--corpus", corpus, "--cobertura", cov, "--ata-index", ata])
    assert rc == 0
    assert "C2 (padre/hijo)" in capsys.readouterr().out


def test_cli_c1_solo_falla(tmp_path, capsys):
    corpus, cov, ata = _write_fixtures(tmp_path)
    # El target por defecto (72) no cuadra con el fixture -> exit != 0
    rc = vc.main(["--c1", "--corpus", corpus, "--cobertura", cov, "--ata-index", ata])
    assert rc != 0
    assert "[FALLA]" in capsys.readouterr().err


def test_cli_todo(tmp_path, capsys):
    corpus, cov, ata = _write_fixtures(tmp_path)
    rc = vc.main(["--todo", "--corpus", corpus, "--cobertura", cov, "--ata-index", ata])
    # C1 (cuadre contra el target 72) falla primero con el fixture -> exit != 0
    assert rc != 0
    assert "C1" in capsys.readouterr().err
