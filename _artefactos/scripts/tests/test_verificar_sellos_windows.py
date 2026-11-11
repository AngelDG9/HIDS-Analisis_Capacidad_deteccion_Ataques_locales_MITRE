# -*- coding: utf-8 -*-
"""Tests de `verificar_sellos_windows.py` (C8).

Cubren el equivalente a `sha256sum -c` sobre las rutas Windows, la cobertura de la
lista blanca y el fallo por CRLF (GNU `sha256sum -c` leería `\\r` como parte del
nombre). El test real usa el sello versionado; los demás construyen un sello
mínimo en `tmp_path`.
"""

import hashlib
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import verificar_sellos_windows as S  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sello(tmp_path: Path, filas, crlf: bool = False) -> Path:
    nl = "\r\n" if crlf else "\n"
    p = tmp_path / "sha256sums.txt"
    p.write_bytes(nl.join(f"{h}  {r}" for h, r in filas).encode("utf-8") + nl.encode())
    return p


def _arbol(tmp_path: Path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("hola", encoding="utf-8")
    b.write_text("otra", encoding="utf-8")
    return a, b


def test_sello_correcto_pasa(tmp_path, monkeypatch):
    a, b = _arbol(tmp_path)
    monkeypatch.setattr(S, "RUTAS_CRITICAS", ("a.txt", "b.txt"))
    sello = _sello(tmp_path, [(_sha(a), "a.txt"), (_sha(b), "b.txt")])
    entradas, fallos = S.comprobar(str(sello), str(tmp_path))
    assert fallos == [], fallos
    assert {e["id"]: e["estado"] for e in entradas} == {
        "SELLO-01": "OK", "SELLO-02": "OK", "SELLO-03": "OK",
        "SELLO-04": "OK", "SELLO-05": "OK"}


def test_hash_obsoleto_falla(tmp_path, monkeypatch):
    a, b = _arbol(tmp_path)
    monkeypatch.setattr(S, "RUTAS_CRITICAS", ("a.txt", "b.txt"))
    sello = _sello(tmp_path, [(_sha(a), "a.txt"), ("0" * 64, "b.txt")])
    _, fallos = S.comprobar(str(sello), str(tmp_path))
    assert any("obsoletas" in f for f in fallos), fallos


def test_ruta_declarada_ausente_falla(tmp_path, monkeypatch):
    a, _ = _arbol(tmp_path)
    monkeypatch.setattr(S, "RUTAS_CRITICAS", ("a.txt", "no_existe.txt"))
    sello = _sello(tmp_path, [(_sha(a), "a.txt"), ("0" * 64, "no_existe.txt")])
    _, fallos = S.comprobar(str(sello), str(tmp_path))
    assert any("ausentes" in f for f in fallos), fallos


def test_cobertura_incompleta_falla(tmp_path, monkeypatch):
    a, b = _arbol(tmp_path)
    monkeypatch.setattr(S, "RUTAS_CRITICAS", ("a.txt", "b.txt"))
    sello = _sello(tmp_path, [(_sha(a), "a.txt")])
    _, fallos = S.comprobar(str(sello), str(tmp_path))
    assert any("sin sellar" in f and "b.txt" in f for f in fallos), fallos


def test_crlf_falla_porque_sha256sum_c_lo_rompe(tmp_path, monkeypatch):
    a, _ = _arbol(tmp_path)
    monkeypatch.setattr(S, "RUTAS_CRITICAS", ("a.txt",))
    sello = _sello(tmp_path, [(_sha(a), "a.txt")], crlf=True)
    _, fallos = S.comprobar(str(sello), str(tmp_path))
    assert any("CRLF" in f for f in fallos), fallos


def test_listar_imprime_toda_la_lista_blanca(capsys):
    assert S.main(["--listar"]) == 0
    salida = capsys.readouterr().out.splitlines()
    assert set(salida) == set(S.RUTAS_CRITICAS)


def test_sello_versionado_pasa():
    """El repo debe quedar con `sha256sum -c` limpio tras C8."""
    assert S.main([]) == 0
