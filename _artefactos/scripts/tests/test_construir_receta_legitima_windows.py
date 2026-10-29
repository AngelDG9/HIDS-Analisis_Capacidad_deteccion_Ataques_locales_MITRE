# -*- coding: utf-8 -*-
"""Tests de la receta Windows **espejo** (bloque `windows-legit-prep`, tanda W1).

Fijan lo que el plan §D2 y los CA-W1/CA-W2/CA-W3 exigen:

1. **Determinismo**: dos generaciones dejan los mismos bytes.
2. **Conteos**: 147/153/141 de jornada + 16/25/22 de campaña, y 5 + B6 handlers.
3. **Ritmo**: `DelayAfter` y ventanas idénticas a la receta Linux, elemento a elemento.
4. **Unidad**: una entrada = un `cmd.exe` (sin `cmd /c` dentro del `Command`), sin `|` fuera
   de `powershell -Command`, sin aleatoriedad y sin comandos mutantes.
5. **Errores**: 10 pares (fallo + reintento) por día, registro TSV de 5 campos y
   `if errorlevel` (nunca `%ERRORLEVEL%`).
6. **PowerShell**: solo el cifrado, el borrado seguro y el CSV de la campaña.

Los tests no escriben en el repositorio: generan en `tmp_path`.
"""

import json
import re
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima as L        # noqa: E402
import construir_receta_legitima_windows as W  # noqa: E402


# --------------------------------------------------------------------------
# utilidades
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def generado(tmp_path_factory):
    out = tmp_path_factory.mktemp("receta_windows")
    W.generar(str(out), raiz=str(W.RAIZ), verbose=False)
    return out


def _eventos(path, handler=None):
    tl = json.loads(Path(path).read_text(encoding="utf-8"))
    hs = tl["TimeLineHandlers"]
    if handler is not None:
        hs = [hs[handler]]
    return [e for h in hs for e in h["TimeLineEvents"]]


def _comandos(path):
    return [e["Command"] for e in _eventos(path)]


# --------------------------------------------------------------------------
# 1 · determinismo
# --------------------------------------------------------------------------
def test_dos_generaciones_byte_identicas(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    W.generar(str(a), raiz=str(W.RAIZ), verbose=False)
    W.generar(str(b), raiz=str(W.RAIZ), verbose=False)
    nombres = sorted(p.name for p in a.iterdir())
    assert nombres == sorted(p.name for p in b.iterdir())
    assert nombres == ["bloques_windows.env", "calendario_windows.json",
                       "receta_windows_resumen.md", "w1.json", "w2.json", "w3.json"]
    for n in nombres:
        assert (a / n).read_bytes() == (b / n).read_bytes(), n


# --------------------------------------------------------------------------
# 2 · conteos y estructura
# --------------------------------------------------------------------------
def test_conteos_y_handlers(generado):
    esperado = {1: (147, 16), 2: (153, 25), 3: (141, 22)}
    for day, (jor, camp) in esperado.items():
        tl = json.loads((generado / f"w{day}.json").read_text(encoding="utf-8"))
        assert tl["Status"] == "Run"
        assert set(tl) == {"Status", "TimeLineHandlers"}, "claves extra en la timeline"
        hs = tl["TimeLineHandlers"]
        assert len(hs) == len(L.BLOQUES_TRABAJO) + 1
        assert sum(len(h["TimeLineEvents"]) for h in hs[:-1]) == jor
        assert len(hs[-1]["TimeLineEvents"]) == camp
        for h in hs:
            assert h["HandlerType"] == "Command"
            assert h["Loop"] is True
            assert h["HandlerArgs"] == {}
            assert set(h) == {"HandlerType", "Initial", "UtcTimeOn", "UtcTimeOff", "Loop",
                              "HandlerArgs", "TimeLineEvents"}


def test_ventanas_y_delayafter_identicos_a_linux(generado):
    """CA-W2: mismo n, mismas ventanas y misma secuencia de `DelayAfter`, sin tolerancia."""
    for day in (1, 2, 3):
        lx = json.loads((Path(W.RAIZ) / "Soporte" / "Laboratorio" / "legitimo_72h" /
                         "recetas" / f"d{day}.json").read_text(encoding="utf-8"))
        wn = json.loads((generado / f"w{day}.json").read_text(encoding="utf-8"))
        assert len(lx["TimeLineHandlers"]) == len(wn["TimeLineHandlers"])
        for a, b in zip(lx["TimeLineHandlers"], wn["TimeLineHandlers"]):
            assert (a["UtcTimeOn"], a["UtcTimeOff"]) == (b["UtcTimeOn"], b["UtcTimeOff"])
            assert [e["DelayAfter"] for e in a["TimeLineEvents"]] == \
                   [e["DelayAfter"] for e in b["TimeLineEvents"]]


def test_total_de_la_ventana(generado):
    n = sum(len(_eventos(generado / f"w{d}.json")) for d in (1, 2, 3))
    assert n == 441 + 63 == 504


# --------------------------------------------------------------------------
# 3 · unidad y reglas duras (CA-W1 / CA-W3)
# --------------------------------------------------------------------------
def test_una_accion_es_un_cmd_sin_doble_envoltorio(generado):
    for day in (1, 2, 3):
        for cmd in _comandos(generado / f"w{day}.json"):
            # `cmd /c` de **primer nivel** sería doble envoltorio (el handler ya lo pone).
            assert not re.search(r"(?:^|&)\s*cmd /c\b", cmd, re.I), cmd
            # El único `cmd /c` admitido es el hijo del fan-out (`for … do @cmd /c copy`):
            # es el proceso que hace de `cp` y mantiene el abanico de 12 (W-1).
            if "cmd /c" in cmd.lower():
                assert re.search(r"for /[Lf] %\w+ in .*? do @cmd /c copy ", cmd), cmd
            assert not re.search(r"(?:^|& )\s*start\s", cmd, re.I), cmd
            assert re.match(r"^cd /d [A-Z]:\\", cmd), cmd


def test_sin_pipes_fuera_de_powershell(generado):
    for day in (1, 2, 3):
        for cmd in _comandos(generado / f"w{day}.json"):
            if "|" in cmd:
                assert "powershell -NoProfile -Command" in cmd, cmd


def test_sin_aleatoriedad_ni_mutantes_ni_evasion(generado):
    for day in (1, 2, 3):
        for cmd in _comandos(generado / f"w{day}.json"):
            assert "%RANDOM%" not in cmd and "Get-Random" not in cmd
            assert "-EncodedCommand" not in cmd
            assert "-WindowStyle" not in cmd
            assert "-ExecutionPolicy" not in cmd
            assert "^" not in cmd
            for pat in W.MUTANTES:
                assert not re.search(pat, cmd, re.I), (pat, cmd)


def test_cwd_realista_y_sin_rutas_linux(generado):
    for day in (1, 2, 3):
        for cmd in _comandos(generado / f"w{day}.json"):
            assert "/home/angel" not in cmd, cmd
            assert "$(date" not in cmd, cmd
            assert "System32" not in cmd, cmd
            d = re.match(r"^cd /d (\S+) && ", cmd).group(1)
            assert d in W.DIRS_CWD_W or d.startswith(W.BASE_CAMP_W + "\\"), d


def test_campana_en_lab_legit_y_casos_w(generado):
    tl = json.loads((generado / "w2.json").read_text(encoding="utf-8"))
    cmds = [e["Command"] for e in tl["TimeLineHandlers"][-1]["TimeLineEvents"]]
    assert cmds
    assert all(not re.search(r"\bC-0\d\b", c) for c in cmds), "quedan identificadores C-xx"
    assert any("C:\\lab-legit\\campana\\W-04" in c for c in cmds)
    assert all("C:\\lab-legit\\campana" in c for c in cmds)


def test_curl_traducido_sin_duplicar_el_binario(generado):
    for day in (1, 2, 3):
        curls = [c for c in _comandos(generado / f"w{day}.json") if "curl.exe" in c]
        assert curls
        for c in curls:
            assert "curl.exe curl" not in c, c
        # la sesión web (la que simula el navegador) lleva UA fija y cookie jar
        con_ua = [c for c in curls if W.UA_W in c]
        assert len(con_ua) >= 3, day
        assert any("-c " + W.CACHE_W + "\\cookies.txt" in c for c in curls), day


# --------------------------------------------------------------------------
# 4 · errores humanos
# --------------------------------------------------------------------------
def test_diez_errores_por_dia_con_reintento_y_cinco_campos(generado):
    for day in (1, 2, 3):
        cmds = _comandos(generado / f"w{day}.json")
        pares = [m.group(0) for m in (W.RE_ERRLOG.search(c) for c in cmds) if m]
        errores = [p for p in pares if "\terror\t" in p]
        reintentos = [p for p in pares if "\treintento\t" in p]
        assert len(errores) == 10, day
        assert len(reintentos) == 10, day
        for c in cmds:
            m = W.RE_ERRLOG.search(c)
            if not m:
                continue
            assert "%ERRORLEVEL%" not in c
            assert "if errorlevel 1" in c
            campos = c[m.start():m.end()].split(" echo ", 1)[1].split("\t")
            assert len(campos) == 5, campos
            assert campos[1] in ("error", "reintento")
            assert campos[2] in L.FAMILIAS_ERROR
            assert campos[4].startswith("rc=")
            if campos[1] == "reintento":
                assert "rc=0" in c, "el reintento debe registrar también el camino bueno"


def test_el_error_va_seguido_de_su_reintento(generado):
    for day in (1, 2, 3):
        tl = json.loads((generado / f"w{day}.json").read_text(encoding="utf-8"))
        for h in tl["TimeLineHandlers"][:len(L.BLOQUES_TRABAJO)]:
            evs = h["TimeLineEvents"]
            for i, ev in enumerate(evs):
                m = W.RE_ERRLOG.search(ev["Command"])
                if not m or m.group("tipo") != "error":
                    continue
                s = W.RE_ERRLOG.search(evs[i + 1]["Command"])
                assert s and s.group("tipo") == "reintento"
                assert s.group("fam") == m.group("fam")
                assert s.group("cmd") != m.group("cmd")


# --------------------------------------------------------------------------
# 5 · PowerShell: solo donde no hay nativo
# --------------------------------------------------------------------------
def test_powershell_solo_en_los_casos_declarados(generado):
    ps = []
    for day in (1, 2, 3):
        tl = json.loads((generado / f"w{day}.json").read_text(encoding="utf-8"))
        for i, h in enumerate(tl["TimeLineHandlers"]):
            for ev in h["TimeLineEvents"]:
                if "powershell -NoProfile -Command" not in ev["Command"]:
                    continue
                bloque = "B6" if i >= len(L.BLOQUES_TRABAJO) else L.BLOQUES_TRABAJO[i]["id"]
                ps.append((day, bloque, ev["Command"]))
    # 3 de jornada (un borrado seguro al día) + 4 de campaña (cifrar, descifrar, borrar, CSV)
    assert len(ps) == 7, len(ps)
    de_jornada = [x for x in ps if x[1] != "B6"]
    assert len(de_jornada) == 3
    for _d, _b, cmd in de_jornada:
        assert "Remove-Item -LiteralPath" in cmd, "solo el borrado seguro en la jornada"
    de_campana = [x for x in ps if x[1] == "B6"]
    assert any("CreateEncryptor" in c for _d, _b, c in de_campana)
    assert any("CreateDecryptor" in c for _d, _b, c in de_campana)
    assert any("Remove-Item -LiteralPath" in c for _d, _b, c in de_campana)
    assert any("-replace ';',','" in c for _d, _b, c in de_campana)


def test_el_cifrado_es_determinista_y_sin_secretos(generado):
    """Misma clave/IV literales (no aleatorios) y sin contraseñas escribidas."""
    enc = [c for c in _comandos(generado / "w2.json") if "CreateEncryptor" in c]
    assert len(enc) == 1
    assert "$k=[byte[]](0..31)" in enc[0] and "$v=[byte[]](0..15)" in enc[0]
    assert "demo-c05" not in enc[0]
    assert "ConvertTo-SecureString" not in enc[0]


# --------------------------------------------------------------------------
# 6 · validador y calendario
# --------------------------------------------------------------------------
def test_check_del_generador_pasa(generado):
    res = W.validar(str(generado), verbose=False)
    assert res["fallos"] == []
    assert res["dias"] == {1: 147, 2: 153, 3: 141}
    assert res["campana"] == {1: 16, 2: 25, 3: 22}


def test_check_detecta_un_delayafter_cambiado(generado, tmp_path):
    copia = tmp_path / "cop"
    copia.mkdir()
    for p in generado.iterdir():
        (copia / p.name).write_bytes(p.read_bytes())
    tl = json.loads((copia / "w1.json").read_text(encoding="utf-8"))
    tl["TimeLineHandlers"][0]["TimeLineEvents"][0]["DelayAfter"] += 1000
    (copia / "w1.json").write_text(json.dumps(tl, indent=1), encoding="utf-8")
    import verificar_espejo
    res = verificar_espejo.comparar(str(Path(W.RAIZ) / verificar_espejo.DIR_LINUX),
                                    str(copia), verbose=False)
    assert any("DelayAfter" in f for f in res["fallos"])


def test_calendario_y_env(generado):
    cal = json.loads((generado / "calendario_windows.json").read_text(encoding="utf-8"))
    assert cal["plataforma"] == "windows"
    assert cal["boveda_version"] == 3
    assert cal["total_ventana"] == 441
    assert cal["total_con_campana"] == 504
    assert cal["campana"]["acciones"] == {"d1": 16, "d2": 25, "d3": 22}
    assert cal["campana"]["inicios"] == {"d1": "17:06:00", "d2": "17:17:00",
                                         "d3": "17:11:00"}
    assert cal["espejo_de"]["sha256"]["d1"]
    env = dict(l.split("=", 1) for l in
               (generado / "bloques_windows.env").read_text(encoding="utf-8").splitlines()
               if l and not l.startswith("#") and "=" in l)
    assert env["TFG_PLATAFORMA"] == "windows"
    assert env["TFG_BOVEDA_VERSION"] == "3"
    assert env["TFG_CWD_BASE"] == W.HOME_W
    assert env["B6"] == "17:05-17:50 campana"


def test_mapa_de_dias_con_t0(tmp_path):
    out = tmp_path / "con_t0"
    W.generar(str(out), raiz=str(W.RAIZ), mapa=W._mapa_desde_t0("2026-11-09"), verbose=False)
    res = W.validar(str(out), mapa_esperado=W._mapa_desde_t0("2026-11-09"), verbose=False)
    assert res["fallos"] == []
    cal = json.loads((out / "calendario_windows.json").read_text(encoding="utf-8"))
    assert cal["mapa_dias"] == {"2026-11-09": 1, "2026-11-10": 2, "2026-11-11": 3}
