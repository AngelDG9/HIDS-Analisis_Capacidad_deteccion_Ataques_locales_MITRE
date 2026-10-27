# -*- coding: utf-8 -*-
"""Tests de la campaña `B6` (bloque `legitimo-v3`, T2) — CA-27.

Fijan lo que el plan §5.2 exige **antes** de `t0`:

1. **11 casos** (C-01…C-12 sin C-04), reparto **3/4/4**, jitter **d1 17:06 · d2 17:17 ·
   d3 17:11** y separación **≥ 3 min** (ventanas de atribución sin solape).
2. **No mutación**: 0 `systemctl` de escritura, 0 `crontab` de escritura, 0
   `useradd/userdel`, 0 instalación y 0 escritura fuera de `~/Documentos/campana_fp/`
   (salvo `logger`, declarado).
3. **0 pipes, 0 `sudo`, 0 `random`, 0 comillas dobles**; primer token de la lista blanca.
4. **22 marcas** (`inicio`/`fin`), evidencia `hecho.txt` con `RESULTADO=OK` y esperado
   **por umbral** (`N ≥ 7` = 0; `N ≥ 3` cita `80792`).
5. El **pre-registro** (`casos.md` + `sha256` en la cabecera del CSV) cuadra.
6. **Doble generación**: dos ejecuciones del generador dejan los **6 ficheros** de la
   receta y `campana_casos.csv` **byte-idénticos**.
"""

import csv
import re
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import campana as C  # noqa: E402
import construir_receta_legitima as R  # noqa: E402


# --------------------------------------------------------------------------
# Composición
# --------------------------------------------------------------------------
def test_validador_de_la_campana_pasa():
    res = C.validar()
    assert res["fallos"] == [], res["fallos"]
    assert res["casos"] == 11
    assert res["marcas"] == 22
    assert res["acciones"] == {1: 16, 2: 25, 3: 22}
    assert res["acciones_total"] == 63


def test_ids_exactos_y_sin_c04():
    casos, _ = C.cargar()
    assert tuple(casos) == C.IDS
    assert "C-04" not in casos, "C-04 se retiró en v4 (no mutación)"
    assert len(casos) == 11


def test_reparto_jitter_y_separacion():
    casos, _ = C.cargar()
    for dia, n in C.REPARTO.items():
        del_dia = [c for c in casos if casos[c]["meta"]["dia"] == str(dia)]
        assert len(del_dia) == n
        primera = casos[del_dia[0]]["meta"]["hora_inicio"]
        assert primera == C.INICIOS_PLAN[dia]
    for dia in (1, 2, 3):
        accs = C.acciones_b6(dia)
        ini = {a["caso"]: a["t"] for a in accs if a["tipo"] == "inicio"}
        fin = {a["caso"]: a["t"] for a in accs if a["tipo"] == "fin"}
        orden = sorted(ini, key=ini.get)
        for a, b in zip(orden, orden[1:]):
            assert ini[b] - fin[a] >= C.SEPARACION_MIN_S, (dia, a, b)
            # ventanas de atribución sin solape
            assert ini[b] - C.ATRIB_PRE_S > fin[a] + C.ATRIB_POST_S
        assert max(ini.values()) < C.hms_to_s(C.B6["off"])
        assert max(fin.values()) <= C.hms_to_s(C.B6["off"])


def test_orden_por_caso_marcas_evidencia_y_limpieza():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        tipos = [a["tipo"] for a in accs]
        assert tipos[0] == "inicio" and tipos[-1] == "fin", cid
        assert tipos.count("inicio") == 1 and tipos.count("fin") == 1, cid
        ev = [a for a in accs if a["tipo"] == "evidencia"]
        assert ev, f"{cid}: sin evidencia"
        for a in ev:
            assert f"/campana_fp/{cid}/hecho.txt" in a["comando"]
            assert "RESULTADO=OK" in a["comando"]
        # la limpieza va ANTES de fin (misma acción: rm && date > fin.txt)
        assert "rm " in accs[-1]["comando"], f"{cid}: no limpia antes de fin"
        assert "date -u +%FT%TZ > " in accs[-1]["comando"]
        # metadatos pre-registrados
        assert c["meta"]["muta"] == "No"
        assert c["meta"]["esperado_n7"] == "0"
        assert "80792" in c["meta"]["esperado_n3"]
        assert c["meta"]["evidencia"] and c["meta"]["coste"]
        assert c["meta"]["por_que"], f"{cid}: sin justificación"


# --------------------------------------------------------------------------
# Reglas duras (comandos)
# --------------------------------------------------------------------------
def _comandos():
    casos, _ = C.cargar()
    for cid, c in casos.items():
        for a in c["acciones"]:
            yield cid, a["comando"]


def test_cero_pipes_sudo_random_comillas():
    for cid, cmd in _comandos():
        assert not C.RE_PIPE.search(cmd), f"{cid}: pipe en {cmd[:80]}"
        assert not re.search(r"(?:^|\s)sudo(?:\s|$)", cmd), f"{cid}: sudo"
        assert not re.search(r"(?:^|[\s;&|])random(?:$|[\s;&|])", cmd), f"{cid}: random"
        assert '"' not in cmd, f"{cid}: comillas dobles"
        assert "echo -e" not in cmd


def test_primer_token_en_lista_blanca_y_rutas_en_la_campana():
    ok = C._binarios_ok()
    for cid, cmd in _comandos():
        for tok in R.binarios_de(cmd):
            assert tok in ok, f"{cid}: binario no permitido {tok}"
        for ruta in C.rutas_absolutas(cmd):
            if ruta in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                continue
            assert ruta == C.BASE or ruta.startswith(C.BASE + "/"), f"{cid}: {ruta}"


def test_cero_mutacion_no_hay_escrituras_de_sistema():
    """La salida literal que pide el plan: todo a 0 en los 63 comandos."""
    res = C.auditar_no_mutacion()
    assert res["comandos"] == 63
    assert res["fallos"] == [], res["fallos"]
    for k, v in res["counts"].items():
        if k == "efectos declarados":
            continue
        assert v == 0, (k, v)
    efectos = res["counts"]["efectos declarados"]
    assert set(efectos) == {"logger", "descargas_http"}
    assert efectos["logger"] == 1          # una sola línea de journal (C-11)
    assert efectos["descargas_http"] == 4  # 3 peticiones de C-09 + 1 de C-12


def test_efectos_declarados_estructura_y_uso():
    assert C.validar_efectos() == []
    assert list(C.EFECTOS_DECLARADOS) == ["logger", "descargas_http"]
    for nombre, e in C.EFECTOS_DECLARADOS.items():
        assert e["descripcion"].strip(), nombre
        assert e["verbos"], nombre
    assert C.verbo_efecto()["curl"] == "descargas_http"
    assert C.verbo_efecto()["wget"] == "descargas_http"
    assert C.verbo_efecto()["logger"] == "logger"


def test_un_efecto_externo_no_declarado_se_detecta():
    """O-5: la comprobación no es tautológica: sin declaración, `curl` falla."""
    cmd = ("cd /home/angel/Documentos/campana_fp/C-09 && curl -sS --max-time 3 "
           "-o /home/angel/Documentos/campana_fp/C-09/x.html http://intranet.local:8080/")
    assert C.validar_comando(cmd) == []
    fallos = C.validar_comando(cmd, declarados={})
    assert any("efecto externo NO declarado" in f for f in fallos), fallos


def test_contar_execve_coincide_con_los_comandos():
    ex = C.contar_execve()
    assert ex["total"] == 103
    assert ex["por_dia"] == {1: 25, 2: 34, 3: 44}
    assert sum(ex["por_dia"].values()) == ex["total"]
    # builtins fuera del recuento; hijos declarados dentro
    assert "echo" not in ex["por_binario"]
    assert "cd" not in ex["por_binario"]
    assert "printf" not in ex["por_binario"]
    assert ex["hijos"] == {"cp": 12, "curl": 1}
    assert ex["por_binario"]["date"] == 22
    assert ex["por_binario"]["mkdir"] == 13
    assert ex["por_binario"]["cp"] == 12      # los 12 hijos de xargs
    assert ex["por_binario"]["curl"] == 3     # 2 de C-09 + 1 hijo de timeout


def test_el_validador_detecta_mutaciones_si_se_cuelan():
    malos = [
        "cd /home/angel/Documentos/campana_fp/C-01 && systemctl start ssh",
        "cd /home/angel/Documentos/campana_fp/C-01 && crontab mi_copia.cron",
        "cd /home/angel/Documentos/campana_fp/C-01 && useradd intruso",
        "cd /home/angel/Documentos/campana_fp/C-01 && apt-get install -y jq",
        "cd /home/angel/Documentos/campana_fp/C-01 && echo x > /etc/motd",
        "cd /home/angel/Documentos/campana_fp/C-01 && cat /etc/hosts",
        "cd /home/angel/Documentos/campana_fp/C-01 && rm -f /home/angel/Documentos/informes/informe.txt",
        "cd /home/angel/Documentos/campana_fp/C-01 && cat a | wc -l",
        "cd /home/angel/Documentos/campana_fp/C-01 && sudo ls",
        "cd /home/angel/Documentos/campana_fp/C-01 && echo \"doble\"",
        "ls -la /home/angel",
    ]
    for cmd in malos:
        assert C.validar_comando(cmd), f"no detectado: {cmd}"


# --------------------------------------------------------------------------
# Pre-registro y documentos
# --------------------------------------------------------------------------
def test_sha_de_casos_md_en_la_cabecera_del_csv():
    cab = C.leer_cabecera(C.ruta_csv())
    m = next(re.search(r"sha256_casos_md=([0-9a-f]{64})", c) for c in cab
             if "sha256_casos_md" in c)
    assert m.group(1) == C.sha256_file(C.ruta_md())
    assert C.sha256_file(C.ruta_md()) in "\n".join(cab)


def test_docs_son_reproducibles():
    casos, _filas = C.cargar()
    md1 = C.render_md(casos)
    md2 = C.render_md(casos)
    assert md1 == md2
    sha = C.sha256_file(C.ruta_md())
    assert C.render_csv(casos, sha) == C.render_csv(casos, sha)
    assert C.render_csv(casos, sha).count("\n") > 11    # cabecera + columnas + 11 filas


def test_casos_md_tiene_una_ficha_por_caso_y_los_comandos():
    txt = open(C.ruta_md(), encoding="utf-8").read()
    casos, _ = C.cargar()
    for cid in casos:
        assert f"### {cid} ·" in txt
    for _cid, cmd in _comandos():
        assert cmd in txt, f"comando no documentado: {cmd[:80]}"
    assert "C-04" in txt and "retirada en v4" in txt


def test_casos_md_declara_efectos_execve_prerrequisitos_y_desviaciones():
    """O-1…O-4: lo que el tester pidió ver declarado en el artefacto."""
    txt = open(C.ruta_md(), encoding="utf-8").read()
    for s in ("Efectos declarados fuera de la carpeta", "`logger`", "`descargas_http`",
              "web_access.log", "Volumen declarado (acciones y `execve`)",
              "103", "d1 **25**", "d2 **34**", "d3 **44**",
              "Prerrequisitos en el invitado (T3/E0)", "campana_fp",
              "Desviaciones respecto del plan (declaradas)",
              "`BINARIOS_OK` = 36", "**34**", "`campana.py`",
              "C-10/plantilla.txt", "sha256sum f1 f2"):
        assert s in txt, f"falta en casos.md: {s}"


def test_calendario_declara_efectos_y_execve():
    import json
    raiz = Path(SCRIPTS).parents[1]
    cal = json.load(open(raiz / "Soporte" / "Laboratorio" / "legitimo_72h" /
                         "recetas" / "calendario.json", encoding="utf-8"))
    camp = cal["campana"]
    assert camp["efectos_declarados"] == ["logger", "descargas_http"]
    assert camp["execve"]["total"] == 103
    assert camp["execve"]["por_dia"] == {"d1": 25, "d2": 34, "d3": 44}
    assert camp["execve"]["hijos"] == {"cp": 12, "curl": 1}


# --------------------------------------------------------------------------
# B6 en las recetas y doble generación
# --------------------------------------------------------------------------
def test_b6_en_los_d_json_es_el_del_csv():
    for day in (1, 2, 3):
        tl = __import__("json").load(open(
            Path(SCRIPTS).parents[1] / "Soporte" / "Laboratorio" / "legitimo_72h" /
            "recetas" / f"d{day}.json", encoding="utf-8"))
        assert C.validar_timeline(tl, day) == []
        hs = tl["TimeLineHandlers"]
        assert len(hs) == len(R.BLOQUES_TRABAJO) + 1
        b6 = hs[-1]
        assert b6["UtcTimeOff"] == C.B6["off"]
        assert b6["UtcTimeOn"] == C.s_to_hms(C.acciones_b6(day)[0]["t"])


# --------------------------------------------------------------------------
# Cobertura (CA-04): receta v2 = 23/50; receta + campaña = 25/50
# --------------------------------------------------------------------------
def test_cobertura_receta_y_conjunto():
    import cobertura_exes as CO

    raiz = str(Path(SCRIPTS).parents[1])
    recetas = str(Path(raiz) / "Soporte" / "Laboratorio" / "legitimo_72h" / "recetas")
    corpus, n_rutas, n_filas = CO.basenames_corpus(raiz)
    assert len(corpus) == 50 and n_rutas == 51 and n_filas == 4107
    rec = CO.binarios_receta(recetas)
    assert len(rec & set(corpus)) == 23, sorted(rec & set(corpus))
    camp = CO.binarios_campana(C.ruta_csv())
    assert {"systemctl", "crontab"} <= camp
    assert len((rec | camp) & set(corpus)) == 25, sorted((rec | camp) & set(corpus))


def test_doble_generacion_identica(tmp_path):
    """Dos generaciones completas → 6 ficheros + campana_casos.csv idénticos."""
    import hashlib
    import shutil

    d1, d2 = tmp_path / "g1", tmp_path / "g2"
    assert R.main(["--out-dir", str(d1)]) == 0
    assert R.main(["--out-dir", str(d2)]) == 0
    for nombre in ("d1.json", "d2.json", "d3.json", "calendario.json",
                   "bloques.env", "receta_resumen.md"):
        a = hashlib.sha256((d1 / nombre).read_bytes()).hexdigest()
        b = hashlib.sha256((d2 / nombre).read_bytes()).hexdigest()
        assert a == b, f"{nombre} cambia entre generaciones"
    # el CSV de la campaña no lo escribe el generador, pero debe ser estable
    copia = tmp_path / "campana_casos.csv"
    shutil.copyfile(C.ruta_csv(), copia)
    antes = hashlib.sha256(copia.read_bytes()).hexdigest()
    res = C.validar()
    assert res["fallos"] == []
    despues = hashlib.sha256(Path(C.ruta_csv()).read_bytes()).hexdigest()
    assert antes == despues, "validar no debe reescribir el CSV"
