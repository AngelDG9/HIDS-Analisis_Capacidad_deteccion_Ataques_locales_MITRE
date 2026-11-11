# -*- coding: utf-8 -*-
"""Tests del validador de paridad Linux ↔ Windows (`verificar_paridad_windows.py`, C5).

Cubren los tres bloques y, sobre todo, la **regla diferencial**: si un invariante falla
en Linux y no en Windows, el validador falla. El caso testigo es el **pipe** (D-01):
se inyecta dentro de `powershell -Command` y el validador Windows debe cazarlo.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import construir_receta_legitima as L          # noqa: E402
import construir_receta_legitima_windows as W  # noqa: E402
import verificar_paridad_windows as V          # noqa: E402


# --------------------------------------------------------------------------
# Bloque 1 — paridad diferencial
# --------------------------------------------------------------------------
def test_bloque1_pasa_con_las_recetas_versionadas():
    filas, fallos, div = V.ejecutar_bloque1()
    assert fallos == [], fallos
    assert not any(f["estado"] == "FALLA" for f in filas)
    pipe = next(f for f in filas if f["id"] == "PIPE")
    assert pipe["lx_detecta"] is True and pipe["wn_detecta"] is True
    assert {f["id"] for f in filas} >= {
        "PIPE", "RANDOM", "MUTANTE", "EVASION", "CD", "PARES", "CONTEOS", "UNIDAD"}
    assert "EVASION" in div and "UNIDAD" in div


def test_main_bloque1_devuelve_cero():
    assert V.main(["--bloque", "1"]) == 0


def test_el_mutante_con_pipe_hace_fallar_a_los_dos():
    """El corpus inyecta `| more` en una acción y **ambos** validadores lo rechazan."""
    fallos_lx = V._validar_receta("lx", V._mut_pipe)
    fallos_wn = V._validar_receta("wn", V._mut_pipe)
    assert any("|" in f for f in fallos_lx), fallos_lx[:3]
    assert any("|" in f for f in fallos_wn), fallos_wn[:3]


def _mut_pipe_dentro_de_powershell(tl):
    for h in tl.get("TimeLineHandlers", []):
        for ev in h["TimeLineEvents"]:
            if 'powershell -NoProfile -Command "' in ev["Command"]:
                ev["Command"] = ev["Command"].replace(
                    '-Command "', '-Command "echo x | ', 1)
                return
    raise AssertionError("no hay ningún comando PowerShell en la receta")


def test_el_pipe_dentro_de_powershell_tambien_falla_en_windows():
    original = _mut_pipe_dentro_de_powershell
    fallos = V._validar_receta("wn", original)
    assert any("|" in f for f in fallos), fallos[:3]


def test_regla_diferencial_no_declarada_falla():
    estado, motivo = V._veredicto("PIPE", True, True, True, False)
    assert estado == "FALLA"
    assert "Windows no detecta" in motivo


def test_regla_diferencial_declarada_pasa():
    estado, motivo = V._veredicto("EVASION", False, True, False, True)
    assert estado == "N/A (declarada)"
    assert "PowerShell" in motivo


def test_las_divergencias_declaradas_tienen_motivo_prueba_y_test():
    for inv, d in V.DIVERGENCIAS_DECLARADAS.items():
        assert d.get("motivo") and d.get("prueba") and d.get("test"), inv


def test_evasion_es_windows_only():
    """Linux no tiene `-EncodedCommand`; Windows sí y debe rechazarlo."""
    cmd = (r"cd /d C:\Users\angel && powershell -NoProfile "
           r"-EncodedCommand AAAA")
    assert any("evasión" in f for f in W.validar_comando(cmd))
    for day in (1, 2, 3):
        tl = V._leer_json(str(Path(V.DIR_LX) / f"d{day}.json"))
        assert all("-EncodedCommand" not in str(ev["Command"])
                   for h in tl["TimeLineHandlers"] for ev in h["TimeLineEvents"])


def test_unidad_cmd_es_windows_only():
    """Linux no tiene `cmd.exe`; Windows rechaza el `cmd /c` de primer nivel."""
    cmd = r"cmd /c cd /d C:\Users\angel && echo x"
    assert any("cmd /c" in f for f in W.validar_comando(cmd))
    for day in (1, 2, 3):
        tl = V._leer_json(str(Path(V.DIR_LX) / f"d{day}.json"))
        assert all("cmd /c" not in str(ev["Command"])
                   for h in tl["TimeLineHandlers"] for ev in h["TimeLineEvents"])


# --------------------------------------------------------------------------
# Bloque 2 — sellos y metadatos
# --------------------------------------------------------------------------
def _m(path: Path, bv: str = "3"):
    path.write_text(
        "# contar_denominador.py | metrica_version=1 boveda_version=" + bv + " | x\n"
        "metrica_version,boveda_version,ambito,eventos\n"
        f"1,{bv},total,10\n"
        f"1,{bv},endpoint,8\n",
        encoding="utf-8")
    return path


def test_m_con_boveda_2_falla(tmp_path):
    entradas = V.comprobar_m(str(_m(tmp_path / "M.csv", "2")))
    est = {e["id"]: e["estado"] for e in entradas}
    assert est["M-01"] == "FALLO" and est["M-02"] == "FALLO"


def test_m_con_boveda_3_pasa(tmp_path):
    entradas = V.comprobar_m(str(_m(tmp_path / "M.csv", "3")))
    assert all(e["estado"] == "OK" for e in entradas), entradas


def test_sello_obsoleto_y_cobertura_incompleta(tmp_path, monkeypatch):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("hola", encoding="utf-8")
    b.write_text("otra", encoding="utf-8")
    bueno = hashlib.sha256(b"hola").hexdigest()
    sello = tmp_path / "sha256sums.txt"
    sello.write_text(f"{bueno}  {a}\n{'0' * 64}  {b}\n", encoding="utf-8")
    monkeypatch.setattr(V, "RUTAS_SELLO_OBLIGATORIAS",
                        (str(a), str(tmp_path / "c.txt")))
    entradas = V.comprobar_sellos(str(sello))
    est = {e["id"]: e["estado"] for e in entradas}
    assert est["SELLO-03"] == "FALLO"      # b.txt está obsoleto
    assert est["SELLO-04"] == "FALLO"      # falta c.txt
    assert "obsoletas" in next(e["detalle"] for e in entradas
                               if e["id"] == "SELLO-03")


def test_la_lista_blanca_del_sello_incluye_los_cuatro_de_D08():
    for p in ("Soporte/Laboratorio/windows/legit/heartbeat_sink.py",
              "_artefactos/scripts/etiquetar_operador_legit.py",
              "Soporte/Laboratorio/windows/manifiesto_snapshot.ps1",
              "Soporte/Laboratorio/windows/legit/BUILD.md"):
        assert p in V.RUTAS_SELLO_OBLIGATORIAS, p


def test_manifiesto_con_domain_82790(tmp_path):
    sha = hashlib.sha256(b"x").hexdigest()
    d = {
        "MANIFEST_FILES": 1, "MANIFEST_SHA256": sha,
        "cliente": {"ghosts_domain_fileversion": "8.2.7.90"},
        "ficheros": [{"ruta": "x", "sha256": sha, "bytes": 1}],
    }
    p = tmp_path / "manifiesto.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    entradas = V.comprobar_manifiesto(str(p))
    est = {e["id"]: e["estado"] for e in entradas}
    assert est["MANIF-03"] == "OK"


def test_crudo_done_manifest_sha256(tmp_path):
    crudo = tmp_path / "crudo"
    crudo.mkdir()
    man = crudo / "MANIFEST.tsv"
    man.write_text("fichero\tbytes\tsha256\n"
                   "archives.json\t10\tabc\n", encoding="utf-8")
    sha_man = hashlib.sha256(man.read_bytes()).hexdigest()
    (crudo / "denominador_manifest.tsv").write_text(
        "fichero\tbytes\tsha256\tprimer\tultimo\n"
        "archives.json\t10\tabc\t2026-11-11T00:00:00Z\t2026-11-11T01:00:00Z\n",
        encoding="utf-8")
    m = tmp_path / "M.csv"
    _m(m)
    (crudo / "crudo.done").write_text(
        "ficheros=1\n"
        f"manifest_sha256={sha_man}\n"
        "M_rc=0\n"
        f"M_csv={m}\n", encoding="utf-8")
    entradas = V.comprobar_crudo(str(crudo))
    assert all(e["estado"] == "OK" for e in entradas), entradas

    # Un byte cambiado en el MANIFEST invalida el sello declarado.
    man.write_text(man.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    entradas = V.comprobar_crudo(str(crudo))
    assert any(e["id"] == "CRUDO-02" and e["estado"] == "FALLO" for e in entradas)


# --------------------------------------------------------------------------
# Bloque 3 — canary
# --------------------------------------------------------------------------
def test_canary_genera_y_prueba_en_seco(tmp_path):
    entradas, fallos, res_ok, res_bad = V.ejecutar_bloque3(str(tmp_path))
    assert fallos == [], fallos
    assert res_ok["ok"] is True
    assert res_ok["enviados"] == len(V.PLANTILLAS_CANARY) == res_ok["reportados"]
    assert res_bad["ok"] is False
    assert [p["id"] for p in res_bad["faltan"]] == ["powershell"]


def test_canary_falla_cerrado_si_no_hay_historial(tmp_path):
    res = V.verificar_canary(None, str(tmp_path / "no_existe.tsv"))
    assert res["ok"] is False
    assert len(res["faltan"]) == len(V.PLANTILLAS_CANARY)
    assert res["error"]


def test_canary_cubre_las_formas_del_plan():
    formas = {p[1] for p in V.PLANTILLAS_CANARY}
    ids = {p[0] for p in V.PLANTILLAS_CANARY}
    assert len(V.PLANTILLAS_CANARY) >= 20
    assert len(ids) == len(V.PLANTILLAS_CANARY)
    for esperada in ("cmd /c", "redirección >", "redirección >>", "encadenado &&",
                     "if errorlevel", "for /L", "PowerShell simple", "eventcreate",
                     "robocopy", "curl.exe", "type de huella", "copy", "del", "md",
                     "start"):
        assert esperada in formas, esperada


def test_canary_lee_history_timeline_en_json_y_tsv(tmp_path):
    cmd = V.PLANTILLAS_CANARY[0][2]
    tsv = tmp_path / "h.tsv"
    tsv.write_text("createdutc\thandler\tcommand\n"
                   f"2026-11-11T00:00:00Z\tCommand\t{cmd}\n", encoding="utf-8")
    js = tmp_path / "h.json"
    js.write_text(json.dumps({"TimeLineEvents": [{"Command": cmd}]}), encoding="utf-8")
    assert V.leer_history_timeline(str(tsv)) == [cmd]
    assert V.leer_history_timeline(str(js)) == [cmd]


def test_canary_lee_la_tabla_de_psql_de_we02(tmp_path):
    """El export de WE0-2 es una tabla de `psql`, no TSV: también debe leerse."""
    cmd = V.PLANTILLAS_CANARY[0][2]
    p = tmp_path / "history.txt"
    p.write_text(
        "  id  |     createdutc      | handler | command\n"
        "------+---------------------+---------+-----------------------------\n"
        f" 7249 | 2026-11-11 17:57:35 | Command | {cmd}\n"
        "(1 fila)\n", encoding="utf-8")
    assert V.leer_history_timeline(str(p)) == [cmd]


def test_canary_falla_tambien_con_sobrantes(tmp_path):
    """C5-bis: el docstring dice `history_timeline == enviados`; sobrar también falla."""
    hist = V.escribir_history_simulado(str(tmp_path / "hist.tsv"))
    with open(hist, "a", encoding="utf-8") as fh:
        fh.write("extra\t2026-11-11T00:01:00Z\tCommand\techo sobrante\n")
    res = V.verificar_canary(None, hist)
    assert res["ok"] is False
    assert res["faltan"] == []
    assert res["sobran"] == ["echo sobrante"]


# --------------------------------------------------------------------------
# Bloque 2 — modo gate de `prep` (C5-bis): sin M/crudo es FALLO, no SKIP
# --------------------------------------------------------------------------
def test_bloque2_sin_m_ni_crudo_es_skip_por_defecto(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "_crudo_auto", lambda: None)
    monkeypatch.setattr(V, "comprobar_manifiesto",
                        lambda *a, **k: [V._estado("MANIF-01", True, "ok")])
    monkeypatch.setattr(V, "comprobar_sellos",
                        lambda *a, **k: [V._estado("SELLO-01", True, "ok")])
    entradas, fallos = V.ejecutar_bloque2(None, None, gate_prep=False)
    est = {e["id"]: e["estado"] for e in entradas}
    assert est["M-01"] == "SKIP" and est["CRUDO-01"] == "SKIP"
    assert fallos == []


def test_bloque2_en_gate_prep_sin_m_ni_crudo_es_fallo(tmp_path, monkeypatch):
    monkeypatch.setattr(V, "_crudo_auto", lambda: None)
    monkeypatch.setattr(V, "comprobar_manifiesto",
                        lambda *a, **k: [V._estado("MANIF-01", True, "ok")])
    monkeypatch.setattr(V, "comprobar_sellos",
                        lambda *a, **k: [V._estado("SELLO-01", True, "ok")])
    entradas, fallos = V.ejecutar_bloque2(None, None, gate_prep=True)
    est = {e["id"]: e["estado"] for e in entradas}
    assert est["M-01"] == "FALLO" and est["CRUDO-01"] == "FALLO"
    assert len(fallos) == 2
