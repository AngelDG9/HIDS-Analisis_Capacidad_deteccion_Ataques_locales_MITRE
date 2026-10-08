# -*- coding: utf-8 -*-
"""Tests offline de `unir_catalogo_ruido.py` (bloque `fase-02b-baseline`, §2.3).

Sin VMs y sin red: usan catálogos sintéticos en `tmp_path` con el **esquema
del extractor congelado** y comprueban:

  - unión correcta (solo v1, solo v2, ambas, conteos y `ventanas`),
  - metadatos tomados de la v1 (o de la v2 si la regla solo está ahí),
  - orden estable por `rule_id`,
  - determinismo (2 pasadas → mismo `sha256`),
  - que **no** modifican los ficheros de entrada,
  - formato de salida (UTF-8 sin BOM, LF, cabecera `#` + esquema exacto),
  - tolerancia a la línea `#` de entrada y a CRLF en la entrada.
"""
from pathlib import Path
import csv
import hashlib
import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import unir_catalogo_ruido as uc  # noqa: E402


# --------------------------------------------------------------------------
# utilidades
# --------------------------------------------------------------------------
def fila(rid, count, level="3", desc="d", groups="g",
         first="2026-10-07T00:45:54Z", last="2026-10-07T00:46:00Z", rs="RS1"):
    """Fila del esquema por ventana (`IN_HEADER`)."""
    return [str(rid), level, desc, groups, str(count), first, last, rs]


def escribir_catalogo(path, filas, comentario=None, crlf=False):
    nl = "\r\n" if crlf else "\n"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        if comentario:
            fh.write(comentario + nl)
        writer = csv.writer(fh, lineterminator=nl)
        writer.writerow(uc.IN_HEADER)
        writer.writerows(filas)


def leer_filas(path):
    """Devuelve (linea_comentario, cabecera, [filas]) de la salida, como texto."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lineas = fh.read().split("\n")
    comentario = lineas[0]
    cabecera = lineas[1]
    cuerpo = [ln for ln in lineas[2:] if ln != ""]
    return comentario, cabecera, [ln.split(",") for ln in cuerpo]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def correr(tmp, v1, v2, out):
    return uc.main(["--v1", str(v1), "--v2", str(v2), "--out", str(out)])


# --------------------------------------------------------------------------
# 1) unión correcta: solo v1 / solo v2 / ambas y conteos
# --------------------------------------------------------------------------
def test_union_correcta(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "ruleids_legitimos.csv"

    escribir_catalogo(v1, [
        fila(300, 3, desc="both-v1"),
        fila(100, 5, desc="only-v1"),
    ])
    escribir_catalogo(v2, [
        fila(300, 4, desc="both-v2"),
        fila(200, 7, desc="only-v2"),
    ])

    assert correr(tmp_path, v1, v2, out) == 0

    _, cabecera, filas = leer_filas(out)
    assert cabecera == ",".join(uc.OUT_HEADER)

    # orden estable por rule_id y campos exactos
    assert filas == [
        ["100", "3", "only-v1", "g", "RS1", "5", "0", "5", "v1"],
        ["200", "3", "only-v2", "g", "RS1", "0", "7", "7", "v2"],
        ["300", "3", "both-v1", "g", "RS1", "3", "4", "7", "v1+v2"],
    ]


def test_count_cero_en_ventana_ausente(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(10, 2)])
    escribir_catalogo(v2, [fila(20, 9)])
    assert correr(tmp_path, v1, v2, out) == 0
    _, _, filas = leer_filas(out)
    por_id = {f[0]: f for f in filas}
    assert por_id["10"][5] == "2" and por_id["10"][6] == "0" and por_id["10"][8] == "v1"
    assert por_id["20"][5] == "0" and por_id["20"][6] == "9" and por_id["20"][8] == "v2"


def test_metadata_se_toma_de_v1(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(100, 1, level="7", desc="v1-desc",
                                groups="g1|g2", rs="RS1")])
    escribir_catalogo(v2, [fila(100, 4, level="3", desc="v2-desc",
                                groups="g9", rs="RS2")])
    assert correr(tmp_path, v1, v2, out) == 0
    _, _, filas = leer_filas(out)
    # level/description/groups/rs de la v1; conteos sumados
    assert filas[0][1:] == ["7", "v1-desc", "g1|g2", "RS1", "1", "4", "5", "v1+v2"]


def test_metadata_de_v2_cuando_solo_esta_en_v2(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(1, 1)])
    escribir_catalogo(v2, [fila(50, 2, level="11", desc="solo-v2", groups="x",
                                rs="RS2")])
    assert correr(tmp_path, v1, v2, out) == 0
    _, _, filas = leer_filas(out)
    assert filas[1][0:5] == ["50", "11", "solo-v2", "x", "RS2"]
    assert filas[1][5:] == ["0", "2", "2", "v2"]


def test_orden_numerico_no_lexicografico(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(80791, 1), fila(591, 1), fila(5402, 1)])
    escribir_catalogo(v2, [fila(80791, 1), fila(591, 1)])
    assert correr(tmp_path, v1, v2, out) == 0
    _, _, filas = leer_filas(out)
    assert [f[0] for f in filas] == ["591", "5402", "80791"]


# --------------------------------------------------------------------------
# 2) determinismo: 2 pasadas -> mismos bytes / mismo sha256
# --------------------------------------------------------------------------
def test_determinismo_mismo_sha256(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    # mismo nombre de salida en carpetas distintas: el comentario incluye el
    # basename de salida, así que el nombre debe coincidir para comparar bytes.
    out_a = tmp_path / "da" / "ruleids_legitimos.csv"
    out_b = tmp_path / "db" / "ruleids_legitimos.csv"
    escribir_catalogo(v1, [fila(300, 3), fila(100, 5), fila(2, 1)])
    escribir_catalogo(v2, [fila(300, 4), fila(200, 7)])

    assert correr(tmp_path, v1, v2, out_a) == 0
    assert correr(tmp_path, v1, v2, out_b) == 0
    assert out_a.read_bytes() == out_b.read_bytes()
    assert sha256(out_a) == sha256(out_b)


# --------------------------------------------------------------------------
# 3) no modifica los ficheros de entrada
# --------------------------------------------------------------------------
def test_no_modifica_ficheros_de_entrada(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(100, 5)], comentario="# cabecera v1")
    escribir_catalogo(v2, [fila(100, 4), fila(200, 1)], crlf=True)

    sha_v1, sha_v2 = sha256(v1), sha256(v2)
    assert correr(tmp_path, v1, v2, out) == 0
    assert sha256(v1) == sha_v1
    assert sha256(v2) == sha_v2
    # el comentario de entrada sigue ahí
    assert v1.read_text(encoding="utf-8").startswith("# cabecera v1")


# --------------------------------------------------------------------------
# 4) formato de salida: UTF-8 sin BOM, LF, comentario `#` + esquema exacto
# --------------------------------------------------------------------------
def test_salida_utf8_sin_bom_lf(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "ruleids_legitimos.csv"
    escribir_catalogo(v1, [fila(100, 5)])
    escribir_catalogo(v2, [fila(200, 1)])
    assert correr(tmp_path, v1, v2, out) == 0

    datos = out.read_bytes()
    assert not datos.startswith(b"\xef\xbb\xbf")   # sin BOM
    assert b"\r" not in datos                       # sin CR (LF)
    assert datos.endswith(b"\n")

    comentario, cabecera, _ = leer_filas(out)
    assert comentario.startswith("# ruleids_legitimos.csv")
    assert "CATALOGO AGREGADO de ruido legitimo (union ventana1+ventana2)" in comentario
    assert "ventanas (v1 | v2 | v1+v2)" in comentario
    assert "rule_description = primer evento de la v1" in comentario
    assert cabecera == ",".join(uc.OUT_HEADER)


def test_comentario_deriva_generado_y_ventanas(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(100, 2, first="2026-10-07T00:45:00Z",
                                last="2026-10-07T04:00:00Z")])
    escribir_catalogo(v2, [fila(200, 3, first="2026-10-07T12:00:01Z",
                                last="2026-10-07T16:00:01Z")])
    assert correr(tmp_path, v1, v2, out) == 0
    comentario, _, _ = leer_filas(out)
    assert "generado=2026-10-07" in comentario
    assert "v1: 2026-10-07T00:45:00Z-2026-10-07T04:00:00Z (2 alertas)" in comentario
    assert "v2: 2026-10-07T12:00:01Z-2026-10-07T16:00:01Z (3 alertas)" in comentario


# --------------------------------------------------------------------------
# 5) tolerancia de entrada: línea `#` y CRLF no cambian la salida
# --------------------------------------------------------------------------
def test_comentario_y_crlf_de_entrada_no_afectan(tmp_path):
    # mismo basename de salida (el comentario lo incluye) en carpetas distintas
    out_lf = tmp_path / "lf" / "union.csv"
    out_crlf = tmp_path / "crlf" / "union.csv"
    v1_lf = tmp_path / "v1_lf.csv"
    v1_crlf = tmp_path / "v1_crlf.csv"
    v2 = tmp_path / "v2.csv"

    filas = [fila(100, 5), fila(300, 3)]
    escribir_catalogo(v1_lf, filas)
    escribir_catalogo(v1_crlf, filas, comentario="# metadatos v1", crlf=True)
    escribir_catalogo(v2, [fila(300, 4)])

    assert correr(tmp_path, v1_lf, v2, out_lf) == 0
    assert correr(tmp_path, v1_crlf, v2, out_crlf) == 0
    assert out_lf.read_bytes() == out_crlf.read_bytes()


# --------------------------------------------------------------------------
# 6) entradas inválidas -> exit 2 (sin escribir salida)
# --------------------------------------------------------------------------
def test_encabezado_invalido_devuelve_2(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    v1.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    escribir_catalogo(v2, [fila(1, 1)])
    assert correr(tmp_path, v1, v2, out) == 2
    assert not out.exists()


def test_fichero_ausente_devuelve_2(tmp_path):
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v2, [fila(1, 1)])
    assert correr(tmp_path, tmp_path / "no_existe.csv", v2, out) == 2
    assert not out.exists()


def test_rule_id_duplicado_devuelve_2(tmp_path):
    v1 = tmp_path / "v1.csv"
    v2 = tmp_path / "v2.csv"
    out = tmp_path / "out.csv"
    escribir_catalogo(v1, [fila(100, 1), fila(100, 2)])
    escribir_catalogo(v2, [fila(100, 1)])
    assert correr(tmp_path, v1, v2, out) == 2
    assert not out.exists()


# --------------------------------------------------------------------------
# 7) rutas por defecto = convención por SO (no se ejecuta, solo se comprueba)
# --------------------------------------------------------------------------
def test_rutas_por_defecto_windows():
    assert uc.DEFAULT_DIR.parts[-2:] == ("Legitimo", "windows")
    assert uc.DEFAULT_V1.name == "ruleids_legitimos_v1.csv"
    assert uc.DEFAULT_V2.name == "ruleids_legitimos_v2.csv"
    assert uc.DEFAULT_OUT.name == "ruleids_legitimos.csv"
