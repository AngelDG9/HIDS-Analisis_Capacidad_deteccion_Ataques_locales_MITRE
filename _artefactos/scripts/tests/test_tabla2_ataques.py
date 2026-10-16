# -*- coding: utf-8 -*-
"""Tests de `tabla2_ataques.py` — T2 (plano ataque) · bloque `reencuadre-metrica` (R2).

Cubren: ventana canónica (D3), selección config/umbral, doble conteo, L8 (C2/C3 vacías),
determinismo byte a byte y la **prueba de humo** (CA-R2-09: C1 × N=0 = 53/55).
"""
from pathlib import Path
import csv
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import tabla2_ataques as T2  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]

AUD_HEADER = [
    "ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level",
    "rule_groups", "rs_origen", "rule_description", "categoria", "motivo",
    "atribucion", "revision", "veredicto_humano", "evidencia",
]


def _escribir(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _fixture(tmp_path, casos, repeticiones=()):
    """Crea auditado/, ata_index.csv, repeticiones.csv y bitacoras/ sintéticos.

    `casos`: {ata_id: {ventana: [(rule_id, level, rs, categoria, ts), ...]}}
    """
    aud = tmp_path / "Auditado"
    bit = tmp_path / "bitacoras"
    bit.mkdir(parents=True, exist_ok=True)
    idx_rows = []
    for i, ata in enumerate(sorted(casos), start=1):
        for win, filas in casos[ata].items():
            rows = [(ata, 1, ts, "victima-linux", rid, lvl, "audit|audit_command", rs,
                     "desc", cat, "", "", "", "", "") for (rid, lvl, rs, cat, ts) in filas]
            _escribir(aud / f"{ata}_{win}-Audited.csv", AUD_HEADER, rows)
        idx_rows.append([ata, "Impact", "T1000", "Tecnica", f"Dataset/Comandos/{ata}/", "cerrado"])
        # bitacora (usa la primera ventana disponible)
        win0 = sorted(casos[ata])[0]
        meta = {
            "ata_id": ata, "sistema": "linux", "doble_iteracion": "iguales",
            "atomic": {"fuente": "propio"},
            "iteraciones": [
                {"iter": 1, "t0": "2026-01-01T00:00:00Z", "t1": "2026-01-01T00:00:30Z",
                 "duracion_s": 30, "audited": f"{ata}_{win0}-Audited.csv", "metrico_o2": "1/1"}
            ],
        }
        import json
        (bit / f"{ata}.json").write_text(json.dumps(meta), encoding="utf-8")
    _escribir(tmp_path / "ata_index.csv", ["ata_id", "tactica", "tecnica", "descripcion", "artefacto", "estado"], idx_rows)
    rep = [[a] for a in repeticiones]
    _escribir(tmp_path / "repeticiones.csv", ["ata_id"], rep)
    return aud, tmp_path / "ata_index.csv", tmp_path / "repeticiones.csv", bit


def _run(tmp_path, aud, idx, rep, bit, out, config=("C1",), umbral=("0",)):
    argv = ["--auditado", str(aud), "--ata-index", str(idx), "--repeticiones", str(rep),
            "--bitacora", str(bit), "--out", str(out)]
    argv += ["--config", *config, "--umbral", *umbral]
    assert T2.main(argv) == 0
    with open(out, encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_ventana_canonica(tmp_path):
    casos = {
        "ATA900": {  # no en repeticiones -> iter1 (detectado); iter2 SIN deteccion
            "iter1": [("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:10Z")],
            "iter2": [("80791", 3, "RS2", "auto_ruido", "2026-01-01T00:01:10Z")],
        },
        "ATA901": {  # en repeticiones -> rev1 (detectado); iter1 SIN deteccion
            "iter1": [("80791", 3, "RS2", "auto_ruido", "2026-01-01T00:00:10Z")],
            "rev1": [("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:20Z")],
        },
    }
    aud, idx, rep, bit = _fixture(tmp_path, casos, repeticiones=("ATA901",))
    filas = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2.csv")
    por = {f["ata_id"]: f for f in filas}
    assert por["ATA900"]["ventana_canonica"] == "iter1"
    assert por["ATA901"]["ventana_canonica"] == "rev1"
    assert por["ATA900"]["Detection"] == "SÍ"
    assert por["ATA901"]["Detection"] == "SÍ"
    assert por["ATA901"]["primera_evidencia_rule_id"] == "80792"


def test_umbral_no_borra_caso(tmp_path):
    casos = {"ATA902": {"iter1": [("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:10Z")]}}
    aud, idx, rep, bit = _fixture(tmp_path, casos)
    f0 = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2_n0.csv", umbral=("0",))
    f7 = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2_n7.csv", umbral=("7",))
    assert f0[0]["Detection"] == "SÍ" and f0[0]["#rule.id_distintos"] == "1"
    assert f7[0]["Detection"] == "NO" and f7[0]["#rule.id_distintos"] == "0"


def test_config_c0_vs_c1(tmp_path):
    casos = {"ATA903": {"iter1": [
        ("550", 3, "RS1", "deteccion", "2026-01-01T00:00:10Z"),
        ("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:11Z"),
    ]}}
    aud, idx, rep, bit = _fixture(tmp_path, casos)
    fc0 = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2_c0.csv", config=("C0",))
    fc1 = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2_c1.csv", config=("C1",))
    assert fc0[0]["#rule.id_distintos"] == "1"  # solo RS1
    assert fc1[0]["#rule.id_distintos"] == "2"  # RS1+RS2
    # doble conteo: 2 alertas (RS1+RS2), 2 rule.id distintos
    assert fc1[0]["#Alertas"] == "2"


def test_L8_c2_vacio(tmp_path):
    casos = {"ATA904": {"iter1": [("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:10Z")]}}
    aud, idx, rep, bit = _fixture(tmp_path, casos)
    filas = _run(tmp_path, aud, idx, rep, bit, tmp_path / "T2_c2.csv", config=("C2",))
    assert filas[0]["Detection"] == ""
    assert filas[0]["#rule.id_distintos"] == ""


def test_determinismo(tmp_path):
    casos = {"ATA905": {"iter1": [("80792", 3, "RS2", "deteccion", "2026-01-01T00:00:10Z")]}}
    aud, idx, rep, bit = _fixture(tmp_path, casos)
    da = tmp_path / "a"
    db = tmp_path / "b"
    da.mkdir()
    db.mkdir()
    _run(tmp_path, aud, idx, rep, bit, da / "out.csv")
    _run(tmp_path, aud, idx, rep, bit, db / "out.csv")
    assert (da / "out.csv").read_bytes() == (db / "out.csv").read_bytes()


def test_smoke_corpus_real_53_55(tmp_path):
    """CA-R2-09: C1 × N=0 sobre el corpus congelado reproduce 53/55.

    Las rutas de entrada se anclan a la raíz del repo (`ROOT`) para que el test
    pase desde cualquier cwd (los defaults del script son relativos al cwd).
    """
    out = tmp_path / "T2_real.csv"
    assert T2.main([
        "--auditado", str(ROOT / T2.DEFAULT_AUDITADO),
        "--ata-index", str(ROOT / T2.DEFAULT_ATA_INDEX),
        "--repeticiones", str(ROOT / T2.DEFAULT_REPETICIONES),
        "--bitacora", str(ROOT / T2.DEFAULT_BITACORA),
        "--config", "C1", "--umbral", "0", "--out", str(out),
    ]) == 0
    rows = list(csv.DictReader([ln for ln in out.read_text(encoding="utf-8").splitlines()
                                if not ln.startswith("#")]))
    assert len(rows) == 55
    tp = [r["ata_id"] for r in rows if r["Detection"] == "SÍ"]
    fn = [r["ata_id"] for r in rows if r["Detection"] == "NO"]
    assert len(tp) == 53
    assert sorted(fn) == ["ATA013", "ATA034"]
