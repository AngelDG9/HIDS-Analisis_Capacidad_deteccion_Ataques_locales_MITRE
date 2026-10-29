# -*- coding: utf-8 -*-
"""T-1 · tests de **ejecución** de la receta Windows (no de texto).

Los 259 tests anteriores eran estáticos: comprobaban que el `Command` *parecía* correcto.
Estos **ejecutan de verdad** los comandos en un sandbox de Windows (`%TEMP%`, rutas
remapeadas) y fallan si el comportamiento real no es el que se declaró:

1. **W-1 (fan-out)** — el `for … do @cmd /c copy` del lote crea **12 ficheros**
   (`lote_1.txt` … `lote_12.txt`). Con `xcopy` se creaban **0** (preguntaba «¿archivo o
   directorio?» y salía con rc=2).
2. **W-2 (del de un fichero inexistente)** — los 10 pares error/reintento de cada día
   escriben **10 líneas `error` + 10 líneas `reintento`**, de **5 campos** TSV. Con `del`
   sobre un fichero ausente el fallo devolvía rc=0 y solo salían 9.
3. **W-3 (`if` que se traga el resto de la línea)** — el `fin.txt` de cada caso de la
   campaña se escribe **siempre**, también cuando la limpieza previa no encuentra nada.
4. **W-4 (`md` de una carpeta existente)** — la estructura del día 2 y 3 no falla (rc≠0).
5. **L-1 (`sha256sum` sin redirección)** — la huella de la copia diaria se escribe en su
   `.sha256` y la acción siguiente la puede leer.

Se ejecutan solo en Windows (`skipif` fuera). En Linux quedan los tests estáticos.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima as L          # noqa: E402
import construir_receta_legitima_windows as W  # noqa: E402

SOLO_WINDOWS = pytest.mark.skipif(os.name != "nt", reason="ejecuta `cmd.exe` de Windows")


# --------------------------------------------------------------------------
# utilidades: recetas, sandbox y ejecución
# --------------------------------------------------------------------------
def _comandos(path):
    tl = json.loads(Path(path).read_text(encoding="utf-8"))
    return [e["Command"] for h in tl["TimeLineHandlers"] for e in h["TimeLineEvents"]]


@pytest.fixture(scope="module")
def recetas(tmp_path_factory):
    """Genera w1/w2/w3 en un directorio temporal (no toca el repositorio)."""
    out = tmp_path_factory.mktemp("receta_windows_ejec")
    W.generar(str(out), raiz=str(W.RAIZ), verbose=False)
    return out


@pytest.fixture
def caja(tmp_path):
    """Sandbox: las dos raíces de la receta, remapeadas dentro de `tmp_path`."""
    sb = tmp_path / "sb"
    (sb / "home").mkdir(parents=True)
    (sb / "campana").mkdir()
    return sb


def _remapear(cmd: str, sb: Path) -> str:
    """`C:\\Users\\angel` → `<sb>\\home` y `C:\\lab-legit\\campana` → `<sb>\\campana`."""
    return (cmd.replace(W.HOME_W, str(sb / "home"))
               .replace(W.BASE_CAMP_W, str(sb / "campana")))


def _cmd(cmd: str, sb: Path):
    """Ejecuta un `Command` de la receta tal cual lo lanzaría GHOSTS (`cmd /c`)."""
    real = _remapear(cmd, sb)
    p = subprocess.run(["cmd", "/c", real], cwd=str(sb), capture_output=True,
                       text=True, timeout=300)
    return p, real


def _accion(cmds, patron):
    """Primera acción de la lista que encaja con el patrón (falla si no hay ninguna)."""
    rx = re.compile(patron)
    for c in cmds:
        if rx.search(c):
            return c
    raise AssertionError(f"ninguna acción encaja con {patron}")


def _preparar_jornada(cmds, sb):
    """Deja el sandbox como lo tendría un día normal antes de los errores.

    Ejecuta la acción de estructura (`mkdir -p` → `md`) y crea `informe.txt`, que es lo
    que en la timeline real han hecho ya las acciones anteriores. No se simula el resto
    de la jornada (web, correo): no hace falta para probar los pares error/reintento.
    """
    p, real = _cmd(_accion(cmds, r"\(if not exist .*informes md "), sb)
    assert p.returncode == 0, (real, p.stdout, p.stderr)
    for d in ("informes", "actas", "copias", "correo"):
        assert (sb / "home" / "Documentos" / d).is_dir(), d
    (sb / "home" / "Documentos" / "informes" / "informe.txt").write_text(
        "informe del area\n", encoding="utf-8")
    # `actas\compartida_1.txt`: lo crea la acción del acta (B4) antes de estos errores.
    (sb / "home" / "Documentos" / "actas" / "compartida_1.txt").write_text(
        "acta de reunion\n", encoding="utf-8")


# --------------------------------------------------------------------------
# W-4 · la estructura se puede repetir (días 2 y 3)
# --------------------------------------------------------------------------
@SOLO_WINDOWS
def test_md_repetido_no_falla(recetas, caja):
    """W-4: el `mkdir -p` del día 2/3 vuelve a pasar por carpetas que ya existen."""
    cmds = _comandos(recetas / "w1.json")
    estructura = _accion(cmds, r"\(if not exist .*informes md ")
    for _ in range(2):
        p, real = _cmd(estructura, caja)
        assert p.returncode == 0, (real, p.stdout, p.stderr)


# --------------------------------------------------------------------------
# W-1 · el fan-out copia de verdad (12 ficheros)
# --------------------------------------------------------------------------
@SOLO_WINDOWS
def test_fanout_crea_los_12_ficheros(recetas, caja):
    """W-1: `for /f … do @cmd /c copy` crea `lote_1.txt` … `lote_12.txt`."""
    cmds = _comandos(recetas / "w1.json")
    _preparar_jornada(cmds, caja)
    # `seq 1 12 > lotes.txt` (la acción anterior de la timeline)
    p, real = _cmd(_accion(cmds, r"for /L %i in \(1,1,12\) do @echo"), caja)
    assert p.returncode == 0, (real, p.stdout, p.stderr)
    lotes_txt = caja / "home" / ".cache" / "tfg-web" / "lotes.txt"
    assert lotes_txt.read_text(encoding="utf-8").split() == [str(i) for i in range(1, 13)]

    fanout = _accion(cmds, r"for /f %i in \(")
    p, real = _cmd(fanout, caja)
    dest = caja / "home" / "Documentos" / "informes"
    creados = sorted(dest.glob("lote_*.txt"))
    assert len(creados) == 12, (real, p.stdout, p.stderr, [f.name for f in creados])
    assert sorted(f.name for f in creados) == sorted(f"lote_{i}.txt" for i in range(1, 13))
    for f in creados:
        assert f.read_text(encoding="utf-8") == "informe del area\n", f.name


@SOLO_WINDOWS
def test_fanout_de_la_campana_crea_los_12_ficheros(recetas, caja):
    """W-1 en W-09 (`C-10`): el `for /L` del caso también deja 12 lotes."""
    caso = [c for c in _comandos(recetas / "w3.json") if "\\W-09" in c]
    assert caso, "no se encontró el caso W-09 del día 3"
    # inicio (crea la carpeta y la marca) → plantilla + seq → fan-out
    for c in caso[:3]:
        p, real = _cmd(c, caja)
        assert p.returncode == 0, (real, p.stdout, p.stderr)
    fanout = _accion(caso, r"for /L %i in \(1,1,12\) do @cmd /c copy")
    p, real = _cmd(fanout, caja)
    creados = sorted((caja / "campana" / "W-09").glob("lote_*.txt"))
    assert len(creados) == 12, (real, p.stdout, p.stderr, [f.name for f in creados])


# --------------------------------------------------------------------------
# W-2 / W-3 · 10 pares error/reintento por día, 5 campos
# --------------------------------------------------------------------------
@SOLO_WINDOWS
@pytest.mark.parametrize("day", [1, 2, 3])
def test_los_10_errores_y_10_reintentos_se_escriben(recetas, caja, day):
    """W-2/W-3: 20 acciones → **10 `error` + 10 `reintento`**, 5 campos TSV cada una."""
    cmds = _comandos(recetas / f"w{day}.json")
    _preparar_jornada(cmds, caja)
    pares = [c for c in cmds if W.RE_ERRLOG.search(c)]
    assert len(pares) == 20, f"d{day}: {len(pares)} acciones de error/reintento"

    for c in pares:                      # en el orden de la timeline (el estado importa)
        p, real = _cmd(c, caja)          # cada acción es un `cmd` nuevo (errorlevel=0)
        salida = (p.stdout + p.stderr).lower()
        assert "no se reconoce" not in salida, (real, p.stderr)
        assert "is not recognized" not in salida and "no se encuentra" not in salida, \
            (real, p.stdout, p.stderr)

    log = caja / "home" / "Documentos" / "errores.log"
    assert log.is_file(), "no se creó errores.log"
    lineas = [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines() if l]
    campos = [l.split("\t") for l in lineas]
    malos = [c for c in campos if len(c) != 5]
    assert not malos, f"d{day}: líneas sin 5 campos: {malos}"
    errores = [c for c in campos if c[1] == "error"]
    reintentos = [c for c in campos if c[1] == "reintento"]
    assert len(errores) == 10, f"d{day}: {len(errores)} líneas `error` (se exigen 10):\n" + \
        "\n".join("\t".join(c) for c in campos)
    assert len(reintentos) == 10, f"d{day}: {len(reintentos)} `reintento` (se exigen 10)"
    # el fallo tiene que fallar de verdad y el reintento terminar bien
    assert all(not c[4].endswith("rc=0") for c in errores), [c[4] for c in errores]
    assert all(c[4].endswith("rc=0") for c in reintentos), [c[4] for c in reintentos]
    assert {c[2] for c in errores} == set(L.FAMILIAS_ERROR)


# --------------------------------------------------------------------------
# W-3 · la marca `fin.txt` de la campaña se escribe siempre
# --------------------------------------------------------------------------
@SOLO_WINDOWS
def test_todos_los_casos_sellan_fin_txt(recetas, caja):
    """W-3: tras `inicio` y `fin`, cada caso W-xx deja su `fin.txt`."""
    casos = set()
    for day in (1, 2, 3):
        cmds = _comandos(recetas / f"w{day}.json")
        for c in cmds:
            m = re.search(re.escape(W.BASE_CAMP_W) + r"\\(W-\d{2})\\", c)
            if m:
                casos.add((day, m.group(1)))
    assert len(casos) == 11, sorted(casos)          # W-01…W-11 (no hay W-04 duplicado)

    for day, caso in sorted(casos):
        cmds = _comandos(recetas / f"w{day}.json")
        del_caso = [c for c in cmds if f"\\{caso}\\" in c]
        inicio = _accion(del_caso, r"\(if not exist .*" + caso + r" md ")
        fin = _accion(del_caso, r"> .*\\" + caso + r"\\fin\.txt echo")
        for c in (inicio, fin):      # la marca no puede depender del rc de la limpieza
            _cmd(c, caja)
        marcador = caja / "campana" / caso / "fin.txt"
        assert marcador.is_file(), f"d{day} {caso}: no se escribió fin.txt ({fin[:120]})"
        assert marcador.read_text(encoding="utf-8").strip(), "fin.txt vacío"


# --------------------------------------------------------------------------
# L-1 · la huella se escribe en su fichero (Linux) y se puede leer
# --------------------------------------------------------------------------
def test_linux_la_huella_de_la_copia_se_redirige():
    """L-1: en `B5` el `sha256sum` escribe `.sha256` y el `cat` siguiente lo lee."""
    acciones = L.componer_dia(1)
    idx = next(i for i, (_b, _f, c, _w) in enumerate(acciones)
               if re.search(r"\bcat .*\.tar\.gz\.sha256$", c))
    anterior = acciones[idx - 1][2]
    assert re.search(r"\bsha256sum .* > .*\.tar\.gz\.sha256$", anterior), anterior
    # y el auditor del generador no encuentra ninguna lectura huérfana
    raiz = Path(W.RAIZ) / "Soporte" / "Laboratorio" / "legitimo_72h" / "recetas"
    datos = {d: json.loads((raiz / f"d{d}.json").read_text(encoding="utf-8"))
             for d in (1, 2, 3)}
    assert L.auditar_huellas_escritas(datos) == []


def test_el_auditor_l1_detecta_una_huella_sin_redireccion():
    """El auditor L-1 no es decorativo: si se quita el `>`, lo denuncia."""
    datos = {1: {"TimeLineHandlers": [
        {"TimeLineEvents": [{"Command": "cd /home/angel && sha256sum /home/angel/a.tar.gz"}]},
        {"TimeLineEvents": [{"Command": "cd /home/angel && cat /home/angel/a.tar.gz.sha256"}]},
        {"TimeLineEvents": []},
        {"TimeLineEvents": []},
        {"TimeLineEvents": []},
        {"TimeLineEvents": []},
    ]}}
    fallos = L.auditar_huellas_escritas(datos)
    assert fallos and "L-1" in fallos[0], fallos


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
def test_bash_sha256sum_redirigido_se_lee(tmp_path):
    """L-1 ejecutado: `sha256sum X > X.sha256` crea el fichero y `cat` lo lee."""
    script = (
        "set -e; mkdir -p documentos/informes documentos/actas copias; "
        "echo 'x' > documentos/informes/informe.txt; "
        "tar -czf copias/copia.tar.gz -C documentos informes actas; "
        "sha256sum copias/copia.tar.gz > copias/copia.tar.gz.sha256; "
        "cat copias/copia.tar.gz.sha256"
    )
    p = subprocess.run([_bash(), "-c", script], cwd=str(tmp_path),
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    sha = tmp_path / "copias" / "copia.tar.gz.sha256"
    assert sha.is_file(), "la huella no se escribió en su fichero"
    assert len(p.stdout.split()) >= 1 and p.stdout.split()[0] in sha.read_text(encoding="utf-8")
