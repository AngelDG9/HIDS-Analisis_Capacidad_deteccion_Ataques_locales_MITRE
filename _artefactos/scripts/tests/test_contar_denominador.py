# -*- coding: utf-8 -*-
"""Tests de `contar_denominador.py` â€” denominador `M` desde `archives.json` (L1).

Cubren: el modo `--test`, el conteo total/endpoint con ventana UTC inclusiva,
el aislamiento por agente, la lectura de `.gz`, la determinaciÃ³n (mismos bytes) y la
cabecera obligatoria (`metrica_version`/`boveda_version`/`sha256`).
"""
from pathlib import Path
import csv
import gzip
import sys

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import contar_denominador as CD  # noqa: E402


LINEAS = [
    '{"timestamp":"2026-10-19T00:00:01.000+0000","agent":{"id":"001","name":"victima-linux"}}',
    '{"timestamp":"2026-10-19T01:30:00.000+0000","agent":{"id":"000","name":"wazuh-server"}}',
    '{"timestamp":"2026-10-22T00:00:00.000+0000","agent":{"id":"001","name":"victima-linux"}}',
    '{"timestamp":"2026-10-22T00:00:01.000+0000","agent":{"id":"001","name":"victima-linux"}}',
    '{"timestamp":"2026-10-18T23:59:59.000+0000","agent":{"id":"001","name":"victima-linux"}}',
    '{"timestamp":"2026-10-20T12:00:00.000+0000","agent":{"id":"002","name":"victima-windows"}}',
    '{"agent":{"id":"001"}}',
    'no es json',
]


def _escribir(path, lineas=LINEAS):
    path.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return path


def _leer(path):
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def test_modo_test():
    assert CD.main(["--test"]) == 0


def test_conteo_y_ventana(tmp_path):
    arch = _escribir(tmp_path / "archives.json")
    out = tmp_path / "denominador_M.csv"
    assert CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z",
                    "--out", str(out), str(arch)]) == 0
    filas = {f["ambito"]: f for f in _leer(out)}
    # en ventana: 19T00:00:01(001), 19T01:30(000), 22T00:00:00(001), 20T12:00(002) = 4
    assert filas["total"]["eventos"] == "4"
    # endpoint 001: 19T00:00:01, 22T00:00:00 = 2
    assert filas["endpoint"]["eventos"] == "2"
    assert filas["endpoint"]["primer_ts"] == "2026-10-19T00:00:01Z"
    assert filas["endpoint"]["ultimo_ts"] == "2026-10-22T00:00:00Z"


def test_cabecera_obligatoria(tmp_path):
    arch = _escribir(tmp_path / "archives.json")
    out = tmp_path / "denominador_M.csv"
    CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z", "--out", str(out), str(arch)])
    primera = out.read_text(encoding="utf-8").splitlines()[0]
    assert "metrica_version=1" in primera
    assert "boveda_version=1" in primera
    assert "sha256_entradas=" in primera


def test_gz(tmp_path):
    arch = tmp_path / "archives.json.gz"
    with gzip.open(arch, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(LINEAS) + "\n")
    out = tmp_path / "denominador_M.csv"
    assert CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z", "--out", str(out), str(arch)]) == 0
    filas = {f["ambito"]: f for f in _leer(out)}
    assert filas["total"]["eventos"] == "4"


def test_multifile_y_determinismo(tmp_path):
    a = _escribir(tmp_path / "archives.json", LINEAS[:4])
    b = _escribir(tmp_path / "archives.json-2", LINEAS[4:])
    out1 = tmp_path / "m1.csv"
    out2 = tmp_path / "m2.csv"
    CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z", "--out", str(out1), str(a), str(b)])
    CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z", "--out", str(out2), str(a), str(b)])
    # mismos bytes (determinista salvo la lÃ­nea de comentario con sha256, que tambiÃ©n lo es)
    assert out1.read_bytes() == out2.read_bytes()


# --------------------------------------------------------------------------
# Bloque `legitimo-fix` (Â§8.3): rangos, --estricto, --manifest y dedupe
# --------------------------------------------------------------------------
def test_rango_por_fichero(tmp_path, capsys):
    a = _escribir(tmp_path / "a.json", LINEAS[:2])
    b = _escribir(tmp_path / "b.json", LINEAS[2:4])
    out = tmp_path / "m.csv"
    assert CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z",
                    "--out", str(out), str(a), str(b)]) == 0
    txt = capsys.readouterr().out
    assert "rango=2026-10-19T00:00:01Z .. 2026-10-19T01:30:00Z" in txt
    assert "rango=2026-10-22T00:00:00Z .. 2026-10-22T00:00:00Z" in txt


def test_estricto_contiguos_ok(tmp_path):
    a = _escribir(tmp_path / "d19.json", [
        '{"timestamp":"2026-10-19T23:00:00.000+0000","agent":{"id":"001","name":"victima-linux"}}'])
    b = _escribir(tmp_path / "d20.json", [
        '{"timestamp":"2026-10-20T00:00:00.000+0000","agent":{"id":"001","name":"victima-linux"}}'])
    assert CD.main(["--estricto", str(a), str(b)]) == 0


def test_estricto_solape_falla(tmp_path, capsys):
    a = _escribir(tmp_path / "d19.json", [
        '{"timestamp":"2026-10-19T23:00:00.000+0000","agent":{"id":"001","name":"victima-linux"}}',
        '{"timestamp":"2026-10-19T23:45:00.000+0000","agent":{"id":"001","name":"victima-linux"}}'])
    b = _escribir(tmp_path / "d20.json", [
        '{"timestamp":"2026-10-19T23:30:00.000+0000","agent":{"id":"001","name":"victima-linux"}}'])
    assert CD.main(["--estricto", str(a), str(b)]) == 3
    assert "SOLAPAN" in capsys.readouterr().err


def test_dedupe_sha256(tmp_path, capsys):
    a = _escribir(tmp_path / "archives.json", LINEAS[:2])
    b = tmp_path / "ossec-archive-20.json"
    b.write_bytes(a.read_bytes())          # mismo contenido (hardlink)
    out = tmp_path / "m.csv"
    assert CD.main(["--desde", "2026-10-19T00:00:00Z", "--hasta", "2026-10-22T00:00:00Z",
                    "--out", str(out), str(a), str(b)]) == 0
    txt = capsys.readouterr().out
    assert "DUPLICADO descartado" in txt
    assert "duplicados=1" in txt
    filas = {f["ambito"]: f for f in _leer(out)}
    assert filas["total"]["eventos"] == "2"


def test_manifest(tmp_path):
    a = tmp_path / "archives.json"
    with gzip.open(str(a) + ".gz", "wt", encoding="utf-8") as fh:
        fh.write("\n".join(LINEAS) + "\n")
    man = tmp_path / "manifest.tsv"
    assert CD.main(["--manifest", str(man), str(a) + ".gz"]) == 0
    lineas = man.read_text(encoding="utf-8").splitlines()
    assert lineas[0].split("\t") == ["fichero", "bytes", "sha256", "primer", "ultimo"]
    campos = lineas[1].split("\t")
    assert campos[0].endswith(".gz")
    assert len(campos[2]) == 64
    assert campos[3].startswith("2026-10-18T23:59:59")
