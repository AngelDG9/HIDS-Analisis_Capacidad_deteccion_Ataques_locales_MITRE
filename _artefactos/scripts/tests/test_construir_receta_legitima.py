# -*- coding: utf-8 -*-
"""Tests de la receta legítima v2 — registro de errores (**F-1**) y `rc` real (**F-2**).

Fijan dos cosas que fallaron en la revisión del bloque `legitimo-v3`:

1. **F-1** — el registro se escribe con `printf` y **formato entre comillas simples**. Un
   `echo -e …\\t…` sin comillas no vale: el *shell* se come la barra invertida antes de que
   `echo` la vea y los campos salen **pegados** (`…Zterrortruta_mal…`). El test comprueba el
   texto de las **60** acciones (10 errores + 10 reintentos × 3 días) y, además, que el
   formato produce **5 campos separados por tabulador** (emulando `printf`).
2. **F-2** — el `rc` de **las dos** líneas sale de `$?`; no se teclea (`rc=0` prohibido).

El último test ejecuta de verdad una pareja con `bash` (si está disponible) y lee el fichero.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima as R  # noqa: E402


def _acciones_de_error():
    """(día, bloque, familia_receta, comando, cwd) de las 60 acciones error/reintento."""
    out = []
    for day in (1, 2, 3):
        for (bid, fam, cmd, cwd) in R.componer_dia(day):
            if fam in ("error", "reintento"):
                out.append((day, bid, fam, cmd, cwd))
    return out


def _linea(cmd: str, ts: str = "2026-11-02T08:00:00Z", rc: str = "1") -> str:
    """Emula lo que hará `printf` con el formato y los argumentos del comando."""
    m = R.RE_REGISTRO.search(cmd)
    assert m, f"comando sin el printf esperado: {cmd[:120]}"
    fmt = m.group(1).replace("\\t", "\t").replace("\\n", "\n")
    return fmt % (ts, m.group(2), m.group(3), m.group(4), rc)


def test_hay_60_acciones_de_error():
    assert len(_acciones_de_error()) == 60


def test_no_queda_echo_e_ni_tabuladores_sin_comillas():
    for day, bid, fam, cmd, _cwd in _acciones_de_error():
        assert "echo -e" not in cmd, f"d{day}/{bid}: echo -e en {cmd[:90]}"
        # `\t` solo puede aparecer dentro de las comillas simples del formato
        fuera_de_citas = __import__("re").sub(r"'[^']*'", "''", cmd)
        assert "\\t" not in fuera_de_citas, f"d{day}/{bid}: \\t sin comillas en {cmd[:90]}"
        m = R.RE_REGISTRO.search(cmd)
        assert m, f"d{day}/{bid}: sin printf reconocible"
        assert m.group(1) == R.FMT_REGISTRO, f"d{day}/{bid}: formato {m.group(1)!r}"


def test_el_formato_tiene_cinco_campos_por_tabulador():
    fmt = R.FMT_REGISTRO
    assert fmt.count("%s") == 5
    assert fmt.count("\\t") == 4
    assert fmt.endswith("\\n")
    for day, bid, fam, cmd, _cwd in _acciones_de_error():
        campos = _linea(cmd).rstrip("\n").split("\t")
        assert len(campos) == 5, f"d{day}/{bid}: {campos}"
        ts, tipo, familia, comando, rc = campos
        assert ts == "2026-11-02T08:00:00Z"
        assert tipo in ("error", "reintento") and tipo == fam
        assert familia in R.FAMILIAS_ERROR
        assert comando.strip(), "el comando del registro está vacío"
        assert rc.startswith("rc=") and rc[3:].isdigit(), f"rc mal formado: {rc!r}"


def test_ningun_campo_contiene_tabulador_ni_salto():
    for day, bid, _fam, cmd, _cwd in _acciones_de_error():
        campos = _linea(cmd).rstrip("\n").split("\t")
        assert all("\t" not in c and "\n" not in c for c in campos), f"d{day}/{bid}"


def test_rc_capturado_con_dollar_interrogacion_f2():
    """F-2: el `rc` de las dos líneas sale de `$?`; no hay `rc=0` tecleado."""
    for day, bid, fam, cmd, _cwd in _acciones_de_error():
        assert "r=$?;" in cmd, f"d{day}/{bid}: no captura $?"
        assert " $r >> " in cmd, f"d{day}/{bid}: no usa $r"
        assert "rc=0" not in cmd, f"d{day}/{bid}: rc tecleado"
    # y el rc emulado se propaga al campo
    cmd = next(c for d, b, f, c, _ in _acciones_de_error() if f == "reintento")
    assert _linea(cmd, rc="0").rstrip("\n").endswith("rc=0")


def test_error_y_reintento_van_emparejados():
    for day in (1, 2, 3):
        for bid in R.IDS_TRABAJO:
            bloque = R.componer_bloque(day, bid)
            for i, (_fam, cmd, _cwd) in enumerate(bloque):
                m = R.RE_REGISTRO.search(cmd)
                if not m or m.group(2) != "error":
                    continue
                assert i + 1 < len(bloque), f"d{day}/{bid}: error sin reintento"
                s = R.RE_REGISTRO.search(bloque[i + 1][1])
                assert s and s.group(2) == "reintento" and s.group(3) == m.group(3)
                assert s.group(4) != m.group(4), "el reintento repite el comando que falla"


def _bash():
    b = shutil.which("bash")
    if b:
        return b
    for p in (r"C:\Program Files\Git\bin\bash.exe",
              r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.isfile(p):
            return p
    return None


@pytest.mark.skipif(_bash() is None, reason="sin bash en este equipo")
def test_bash_real_escribe_dos_lineas_de_cinco_campos(tmp_path):
    """Ejecuta de verdad la pareja (fallo + reintento) con bash y lee `errores.log`."""
    log = tmp_path / "errores.log"
    acciones = R.pareja_error("ruta_mal", "ls -la no_existe", "ls -la .", ".", ".",
                              registro="errores.log")
    for _fam, cmd, _cwd in acciones:
        p = subprocess.run([_bash(), "-c", cmd], cwd=str(tmp_path),
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
    lineas = log.read_text(encoding="utf-8").splitlines()
    assert len(lineas) == 2, lineas
    campos = [l.split("\t") for l in lineas]
    assert all(len(c) == 5 for c in campos), campos
    assert campos[0][1] == "error" and campos[1][1] == "reintento"
    assert campos[0][2] == campos[1][2] == "ruta_mal"
    assert campos[0][4] != "rc=0", "el fallo no puede acabar con rc=0"
    assert campos[1][4] == "rc=0"
    assert campos[0][3] == "ls -la no_existe" and campos[1][3] == "ls -la ."
