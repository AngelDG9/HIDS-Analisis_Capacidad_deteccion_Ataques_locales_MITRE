# -*- coding: utf-8 -*-
"""Tests de la campaña `B6` de Windows (bloque `windows-legit-prep`, W2).

Fijan lo que el plan §5 y §13 (CA-W3, CA-W14, CA-W18) exige **antes** de `t0`:

1. **11 casos** (`W-01`…`W-11`, sin `W-12`), reparto **3/4/4** y jitter
   **d1 17:06 · d2 17:17 · d3 17:11**, idénticos a Linux.
2. **0 mutación**: ni `schtasks /create`, ni `reg add`, ni `sc create/config`, ni
   `net user`, ni `msiexec`/instalación, ni escritura fuera de `…\\campana\\W-XX\\`.
3. **0 pipes** fuera de `powershell -Command`; 0 `%RANDOM%`/`Get-Random`; 0 evasión.
4. **22 marcas** y evidencia `hecho.txt` con `RESULTADO=OK`; esperado **por umbral**
   (`N ≥ 7` = 0; `N ≥ 3` cita `67027`).
5. **Comandos = los de `w{1,2,3}.json`** (misma orden, misma hora) y **mismas horas que
   la campaña de Linux** (espejo por ranuras).
6. **Tabla de equivalencia** completa (`C-01…C-12` ↔ `W-01…W-11`, `C-04` sin espejo).
7. **Doble generación** byte-idéntica del `.md` y del `.csv`, y el pre-registro cuadra.
"""

import hashlib
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import campana as L  # noqa: E402  (campaña Linux: solo lectura, para el espejo)
import campana_windows as C  # noqa: E402


# --------------------------------------------------------------------------
# Composición y validación
# --------------------------------------------------------------------------
def test_validador_de_la_campana_pasa():
    res = C.validar()
    assert res["fallos"] == [], res["fallos"]
    assert res["casos"] == 11
    assert res["marcas"] == 22
    assert res["acciones"] == {1: 16, 2: 25, 3: 22}
    assert res["acciones_total"] == 63


def test_ids_exactos_y_mecanismos_sin_c04():
    casos, _ = C.cargar()
    assert tuple(casos) == C.IDS
    assert "W-12" not in casos
    assert sorted(c["meta"]["mecanismo"] for c in casos.values()) == \
        ["C-01", "C-02", "C-03", "C-05", "C-06", "C-07",
         "C-08", "C-09", "C-10", "C-11", "C-12"]
    assert "C-04" not in {c["meta"]["mecanismo"] for c in casos.values()}


def test_reparto_jitter_y_horas():
    casos, _ = C.cargar()
    for dia, n in C.REPARTO.items():
        del_dia = [c for c in casos if casos[c]["meta"]["dia"] == str(dia)]
        assert len(del_dia) == n
        primera = min(casos[c]["meta"]["hora_inicio"] for c in del_dia)
        assert primera == C.INICIOS_PLAN[dia]


def test_marcas_locales_y_evidencia():
    casos, _ = C.cargar()
    marcas = 0
    for cid, c in casos.items():
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        ini, fin = accs[0], accs[-1]
        assert ini["tipo"] == "inicio" and fin["tipo"] == "fin"
        assert f"{C.BASE}\\{cid}\\inicio.txt" in ini["comando"]
        assert f"{C.BASE}\\{cid}\\fin.txt" in fin["comando"]
        assert "%DATE%_%TIME%" in ini["comando"]
        assert "%DATE%_%TIME%" in fin["comando"]
        evid = [a for a in accs if a["tipo"] == "evidencia"]
        assert len(evid) == 1
        assert f"{C.BASE}\\{cid}\\hecho.txt" in evid[0]["comando"]
        assert "RESULTADO=OK" in evid[0]["comando"]
        marcas += 2
    assert marcas == 22


def test_esperado_por_umbral():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        meta = c["meta"]
        assert meta["esperado_n7"] == "0", cid
        assert C.RULE_EXEC in meta["esperado_n3"], cid
        assert C.RULE_EXEC in meta["rule_ids"], cid
        assert meta["muta"] == "No", cid


# --------------------------------------------------------------------------
# No mutación (CA-W3) y H-1
# --------------------------------------------------------------------------
def test_auditoria_de_no_mutacion_pasa():
    res = C.auditar_no_mutacion()
    assert res["fallos"] == [], res["fallos"]
    assert res["comandos"] == 63
    for k, v in res["counts"].items():
        assert v == 0, f"{k} = {v}"
    assert res["efectos"] == {"descargas_http": 4, "registro_eventos": 1}


def test_ningun_pipe_fuera_de_powershell():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        for a in c["acciones"]:
            cmd = a["comando"]
            assert "|" not in C._sin_ps(cmd), f"{cid}: pipe fuera de PowerShell"
            if "|" in cmd:
                assert "powershell" in cmd and "-Command" in cmd, f"{cid}: pipe suelto"


def test_patrones_mutantes_cero_por_caso():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        texto = "\n".join(a["comando"] for a in c["acciones"])
        for nombre, pat in C.REGLAS_MUTACION.items():
            assert re.search(pat, texto, re.I) is None, f"{cid}: {nombre}"


def test_escrituras_solo_en_la_carpeta_del_caso():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        for a in c["acciones"]:
            for dest in C.destinos_escritura(a["comando"]):
                assert C._destino_ok(dest), f"{cid}: escritura en {dest}"


# --------------------------------------------------------------------------
# Coherencia con las recetas y con Linux
# --------------------------------------------------------------------------
def test_csv_es_el_b6_de_las_recetas():
    casos, _ = C.cargar()
    assert C._validar_contra_recetas(None, casos) == []


def test_b6_de_las_recetas_cierra_a_las_17_50_y_suma_63():
    handlers, fallos = C.leer_b6()
    assert fallos == []
    assert sum(len(h["TimeLineEvents"]) for h in handlers.values()) == 63
    for h in handlers.values():
        assert h["HandlerType"] == "Command"
        assert h["UtcTimeOff"] == C.B6["off"]
        assert h["Loop"] is True
        assert not h["HandlerArgs"]


def test_horas_identicas_a_la_campana_de_linux():
    for dia in (1, 2, 3):
        handlers, _ = C.leer_b6()
        t = C.hms_to_s(handlers[dia]["UtcTimeOn"])
        horas_w = []
        for ev in handlers[dia]["TimeLineEvents"]:
            horas_w.append(C.s_to_hms(t))
            t += int(ev["DelayAfter"]) // 1000
        assert horas_w == [a["hora"] for a in L.acciones_b6(dia)]


def test_ata_linux_coherente_con_las_fichas_linux():
    casos, _ = C.cargar()
    linux, _ = L.cargar()
    for cid, c in casos.items():
        twin = c["meta"]["mecanismo"]
        assert twin in linux
        assert set(c["meta"]["ata_linux"].split(";")) <= \
            set(linux[twin]["meta"]["ata"].split(";")), cid


def test_tecnica_y_rule_ids_bien_formados():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        tecs = c["meta"]["tecnica"].split(";")
        assert tecs and all(C.RE_TEC.match(t) for t in tecs), cid
        rules = c["meta"]["rule_ids"].split(";")
        assert rules and all(r == C.RULE_EXEC or re.fullmatch(r"\d{5}-\d{5}", r)
                             for r in rules), cid


# --------------------------------------------------------------------------
# Tabla de equivalencia y artefacto
# --------------------------------------------------------------------------
def test_equivalencia_completa():
    lin = [e["linux"] for e in C.EQUIVALENCIA]
    assert lin == [f"C-{i:02d}" for i in range(1, 13)]
    wins = [e["win"] for e in C.EQUIVALENCIA if e["win"] != "—"]
    assert wins == list(C.IDS)
    comparables = [e for e in C.EQUIVALENCIA if e["comparable"].startswith("sí")]
    parciales = [e for e in C.EQUIVALENCIA if e["comparable"].startswith("**parcial")]
    assert len(comparables) == 8
    assert len(parciales) == 3
    assert [e["linux"] for e in C.EQUIVALENCIA if e["win"] == "—"] == ["C-04"]


def test_casos_windows_md_declara_prediccion_efectos_y_desviaciones():
    txt = open(C.ruta_md(), encoding="utf-8").read()
    for s in ("Es una predicción, no una medida", "No existe corpus de ataques Windows",
              "Efectos declarados fuera de la carpeta", "`descargas_http`",
              "`registro_eventos`", "web_access.log",
              "Tabla de equivalencia Linux ↔ Windows", "sin espejo",
              "Volumen declarado (acciones y procesos)", "**75**",
              "Prerrequisitos en el invitado (WE0-2b)",
              "Desviaciones respecto del plan (declaradas)",
              "Qué es predicción y qué queda para WE0"):
        assert s in txt, f"falta en casos_windows.md: {s}"
    casos = C.construir_casos()
    for cid, c in casos.items():
        for a in sorted(c["acciones"], key=lambda x: x["orden"]):
            assert a["comando"] in txt, f"comando no documentado en {cid}"


def test_csv_tiene_cabecera_con_sha_y_9_columnas_de_salida():
    cab = C._leer_cabecera(C.ruta_csv())
    assert cab and "sha256_casos_md=" in cab[0]
    assert "corpus_windows=NO_EXISTE" in cab[0]
    _, filas = C.cargar()
    assert len(filas) == 11


def test_doble_generacion_identica():
    """Dos `--docs` seguidos → mismo `sha256` (determinismo, plan §7)."""
    antes_md = hashlib.sha256(Path(C.ruta_md()).read_bytes()).hexdigest()
    antes_csv = hashlib.sha256(Path(C.ruta_csv()).read_bytes()).hexdigest()
    C.escribir_docs(verbose=False)
    assert hashlib.sha256(Path(C.ruta_md()).read_bytes()).hexdigest() == antes_md
    assert hashlib.sha256(Path(C.ruta_csv()).read_bytes()).hexdigest() == antes_csv
    # `validar` no reescribe nada
    assert C.validar()["fallos"] == []
    assert hashlib.sha256(Path(C.ruta_csv()).read_bytes()).hexdigest() == antes_csv


def test_validador_detecta_mutacion_si_se_cuela():
    """El validador no es decorativo: un `schtasks /create` debe fallar."""
    fallos = C.validar_comando(
        r'cd /d C:\lab-legit\campana\W-01 && schtasks /create /tn X /tr calc /sc once')
    assert any("mutante" in f for f in fallos), fallos
    fallos = C.validar_comando(
        r'cd /d C:\lab-legit\campana\W-01 && dir C:\Windows\System32 | findstr x')
    assert any("PowerShell" in f for f in fallos), fallos
    fallos = C.validar_comando(
        r'cd /d C:\lab-legit\campana\W-01 && dir C:\Users\otro\secreto.txt')
    assert any("fuera de la carpeta" in f for f in fallos), fallos
