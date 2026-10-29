# -*- coding: utf-8 -*-
"""Tests de `extraer_campana_windows.py` — tabla por caso de la campaña de Windows.

Sin VMs ni red: fixtures sintéticos en `tmp_path` (marcas ISO y locales, CSV de alertas
con campos de Sysmon, `MANIFEST.tsv`). Se fijan los bordes que importan:

1. **22 marcas** → `campana_ventanas_windows.tsv` con 11 filas.
2. **Filtro por agente `002`**: una fila del `001` no cuenta (y se informa).
3. **Atribución** `[ini−10 s, fin+60 s]` **inclusiva**.
4. **Dedupe por `MANIFEST`** (y por `sha256` si no hay manifiesto).
5. **`esperado_cumplido`**: `SI` si `67027` y `level < 7`; `NO` si ≥ 7;
   `NO_EJECUTADO` **solo** sin marcas; `NO_EVALUABLE` con motivo si faltan marcas,
   `hecho.txt` o el fichero de alertas.
6. **Marcas locales** de `cmd` (`%DATE%_%TIME%`): sin `--desfase-local` **no se adivina**
   y el caso queda **`NO_EVALUABLE` con motivo** (nunca `NO_EJECUTADO`, que es solo
   ausencia de marcas).
7. **Campos de Windows** (`win.eventdata.*`) se reconocen; si faltan, no se inventan.
"""

import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import campana_windows as C  # noqa: E402
import extraer_campana_windows as X  # noqa: E402

UTC = timezone.utc
BASE_DIA = datetime(2026, 11, 2, tzinfo=UTC)      # lunes ficticio (d1)


def _t(dia, s):
    return (BASE_DIA + timedelta(days=dia - 1)).replace(
        hour=s // 3600, minute=(s % 3600) // 60, second=s % 60)


def _casos_reales():
    """[(caso, dia, ini_dt, fin_dt)] de las 22 marcas del CSV real."""
    out = []
    for cid, c in C.construir_casos().items():
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        dia = int(c["meta"]["dia"])
        out.append((cid, dia,
                    _t(dia, C.hms_to_s(accs[0]["hora"])),
                    _t(dia, C.hms_to_s(accs[-1]["hora"]))))
    return out


def _cosecha(tmp_path, sin_hecho=(), locales=False, desfase=None):
    ev = tmp_path / "evidencia"
    for cid, _dia, ini, fin in _casos_reales():
        d = ev / "campana" / cid
        d.mkdir(parents=True, exist_ok=True)
        if locales:
            assert desfase is not None

            def _fmt(dt):
                loc = dt + desfase
                return loc.strftime("%d/%m/%Y_%H:%M:%S.00")
            (d / "inicio.txt").write_text(_fmt(ini) + "\n", encoding="utf-8")
            (d / "fin.txt").write_text(_fmt(fin) + "\n", encoding="utf-8")
        else:
            (d / "inicio.txt").write_text(X.fmt_ts(ini) + "\n", encoding="utf-8")
            (d / "fin.txt").write_text(X.fmt_ts(fin) + "\n", encoding="utf-8")
        if cid not in sin_hecho:
            (d / "hecho.txt").write_text("RESULTADO=OK\n", encoding="utf-8")
    return ev


def _alertas(path, filas, sysmon=True):
    cab = ["timestamp_utc", "agent_id", "agent_name", "rule_id", "rule_level"]
    if sysmon:
        cab += ["win.eventdata.image", "win.eventdata.commandLine",
                "win.eventdata.currentDirectory", "win.eventdata.user",
                "win.system.eventID"]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(cab)
        for r in filas:
            w.writerow(r)


def _fila(ts, aid="002", rule="67027", lvl="3"):
    return [X.fmt_ts(ts), aid,
            "victima-windows" if aid == "002" else "victima-linux",
            rule, lvl, r"C:\Windows\System32\cmd.exe", "cmd /c systeminfo",
            r"C:\Users\angel", "angel", "1"]


# --------------------------------------------------------------------------
# 1) Ventanas
# --------------------------------------------------------------------------
def test_solo_ventanas_escribe_22_marcas(tmp_path):
    ev = _cosecha(tmp_path)
    out = tmp_path / "campana_ventanas_windows.tsv"
    vent, avisos = X.leer_marcas(str(ev))
    X.escribir_ventanas(vent, str(out), avisos)
    lineas = [l for l in out.read_text(encoding="utf-8").splitlines()
              if not l.startswith("#")]
    assert len(lineas) == 12  # cabecera + 11
    assert sum(1 for v in vent.values() if v["ini"] and v["fin"]) == 11
    assert "marcas encontradas: 11" in "\n".join(avisos)
    assert X.comprobar_ventanas(vent) == []


def test_marca_local_sin_desfase_no_se_adivina(tmp_path):
    ev = _cosecha(tmp_path, locales=True, desfase=timedelta(hours=1))
    vent, avisos = X.leer_marcas(str(ev))
    assert any("desfase" in a for a in avisos), avisos
    assert all(v["ini"] is None and v["fin"] is None for v in vent.values())
    assert all("desfase" in v["motivo"] for v in vent.values()), vent


def test_marca_local_sin_desfase_es_no_evaluable_con_motivo(tmp_path):
    """B-2: hay marcas pero no se pueden convertir ⇒ NO_EVALUABLE, nunca NO_EJECUTADO."""
    ev = _cosecha(tmp_path, locales=True, desfase=timedelta(hours=1))
    vent, _ = X.leer_marcas(str(ev))
    filas = X.construir_tabla(vent, None, None, None, evidencia=str(ev))
    for f in filas:
        assert f["esperado_cumplido"] == "NO_EVALUABLE", f
        assert "desfase" in f["motivo"], f
    out = tmp_path / "campana_fp_windows.csv"
    X.escribir_csv(filas, str(out), {"sha_md": "x"})
    cab = [l for l in out.read_text(encoding="utf-8").splitlines()
           if l.startswith("#")][0]
    assert "no_evaluable_motivos=" in cab and "desfase" in cab
    # el motivo sobrevive al TSV intermedio
    tsv = tmp_path / "ventanas.tsv"
    X.escribir_ventanas(vent, str(tsv))
    recargadas = X.cargar_ventanas(str(tsv))
    assert all("desfase" in r["motivo"] for r in recargadas.values())


def test_sin_marcas_es_no_ejecutado(tmp_path):
    """NO_EJECUTADO queda reservado a la ausencia de marcas."""
    ev = tmp_path / "evidencia"
    ev.mkdir()
    vent, avisos = X.leer_marcas(str(ev))
    assert sum(1 for a in avisos if "sin marcas (NO_EJECUTADO)" in a) == 11, avisos
    filas = X.construir_tabla(vent, None, None, None, evidencia=str(ev))
    assert all(f["esperado_cumplido"] == "NO_EJECUTADO" for f in filas)
    assert all(f["motivo"] == "" for f in filas)


def test_marca_local_con_desfase_declarado(tmp_path):
    desfase = timedelta(hours=1)
    ev = _cosecha(tmp_path, locales=True, desfase=desfase)
    vent, _ = X.leer_marcas(str(ev), desfase=X.parse_offset("+01:00"))
    real = {cid: ini for cid, _d, ini, _f in _casos_reales()}
    for cid, v in vent.items():
        assert X.fmt_ts(v["ini"]) == X.fmt_ts(real[cid]), cid


def test_parse_marca_formatos():
    iso = X.parse_marca("2026-11-02T17:06:00Z")
    assert X.fmt_ts(iso) == "2026-11-02T17:06:00Z"
    loc = X.parse_marca("02/11/2026_18:06:00.12", X.parse_offset("+01:00"))
    assert X.fmt_ts(loc) == "2026-11-02T17:06:00Z"
    assert X.parse_marca("02-11-2026 18:06:00", X.parse_offset("-300")).hour == 23
    with pytest.raises(ValueError):
        X.parse_marca("02/11/2026_18:06:00")


# --------------------------------------------------------------------------
# 2) Filtro por agente y atribución
# --------------------------------------------------------------------------
def test_filtro_agente_002_y_atribucion_inclusiva(tmp_path):
    vent, _ = X.leer_marcas(str(_cosecha(tmp_path)))
    cid, _dia, ini, fin = _casos_reales()[0]
    al = tmp_path / "alertas.csv"
    _alertas(al, [
        _fila(ini + timedelta(seconds=1)),                     # dentro
        _fila(ini + timedelta(seconds=1), aid="001"),          # otro agente
        _fila(ini - timedelta(seconds=10)),                    # borde pre
        _fila(ini - timedelta(seconds=11)),                    # fuera
        _fila(fin + timedelta(seconds=60)),                    # borde post
        _fila(fin + timedelta(seconds=61)),                    # fuera
    ])
    res, meta = X.contar_alertas([str(al)], vent)
    assert res[cid]["alertas"] == 3, res[cid]
    assert meta["filas"] == 6 and meta["otros_agentes"] == 1
    assert meta["columna_agente"] == "agent_id"


def test_sin_columna_de_agente_falla(tmp_path):
    vent, _ = X.leer_marcas(str(_cosecha(tmp_path)))
    al = tmp_path / "alertas.csv"
    with open(al, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["timestamp_utc", "rule_id", "rule_level"])
        w.writerow(["2026-11-02T17:06:01Z", "67027", "3"])
    with pytest.raises(SystemExit):
        X.contar_alertas([str(al)], vent)


def test_las_alertas_de_otro_agente_no_cuentan_ni_como_fallo(tmp_path):
    vent, _ = X.leer_marcas(str(_cosecha(tmp_path)))
    cid, _dia, ini, _fin = _casos_reales()[0]
    al = tmp_path / "alertas.csv"
    _alertas(al, [_fila(ini + timedelta(seconds=1), aid="001")])
    res, meta = X.contar_alertas([str(al)], vent)
    assert all(v["alertas"] == 0 for v in res.values())
    assert meta["filas"] == 1 and meta["otros_agentes"] == 1


# --------------------------------------------------------------------------
# 3) Dedupe (MANIFEST y sha256)
# --------------------------------------------------------------------------
def test_dedupe_por_sha256_sin_manifiesto(tmp_path):
    filas = [["2026-11-02T17:06:01Z", "002", "victima-windows", "67027", "3",
              "cmd.exe", "cmd /c x", r"C:\Users\angel", "angel", "1"]]
    a1, a2 = tmp_path / "a1.csv", tmp_path / "a2.csv"
    _alertas(a1, filas)
    a2.write_bytes(a1.read_bytes())
    paths, notas = X.ficheros_unicos([str(a1), str(a2)], extensiones=(".csv",))
    assert len(paths) == 1, notas
    assert any("duplicado por sha256" in n for n in notas), notas


def test_dedupe_por_manifest_descarta_origen_duplicado(tmp_path):
    d = tmp_path / "alertas"
    d.mkdir()
    a1, a2 = d / "a1.csv", d / "a2.csv"
    _alertas(a1, [])
    a2.write_bytes(a1.read_bytes())
    man = d / "MANIFEST.tsv"
    with open(man, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("fichero\tbytes\tsha256\torigen\n")
        fh.write("a1.csv\t10\th1\tendpoint-002\n")
        fh.write("a2.csv\t10\th1\tDUPLICADO de a1.csv\n")
    paths, notas = X.ficheros_unicos([str(d)], extensiones=(".csv",))
    assert paths == [str(a1)], (paths, notas)
    assert any("MANIFEST: 1 ficheros únicos" in n for n in notas), notas


def test_archives_dedupe_y_filtro_agente(tmp_path):
    vent, _ = X.leer_marcas(str(_cosecha(tmp_path)))
    cid, _dia, ini, _fin = _casos_reales()[0]
    rec = {"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
           "agent": {"id": "002", "name": "victima-windows"}}
    ajeno = {"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.100+0000"),
             "agent": {"id": "001", "name": "victima-linux"}}
    a1 = tmp_path / "archives.json"
    a2 = tmp_path / "archives-copia.json"
    for p in (a1, a2):
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(rec) + "\n" + json.dumps(ajeno) + "\n")
    paths, _ = X.ficheros_unicos([str(a1), str(a2)])
    assert len(paths) == 1
    evc, meta = X.contar_eventos(paths, vent)
    assert evc[cid] == 1 and sum(evc.values()) == 1, evc


# --------------------------------------------------------------------------
# 4) Tabla final: 9 columnas, NO_EVALUABLE y NO_EJECUTADO
# --------------------------------------------------------------------------
def test_csv_9_columnas_y_no_evaluable(tmp_path):
    vent, _ = X.leer_marcas(str(_cosecha(tmp_path)))
    filas = X.construir_tabla(vent, None, None, None,
                              evidencia=str(tmp_path / "evidencia"))
    assert [k for k in filas[0] if k != "motivo"] == X.CSV_HEADER
    assert "motivo" in filas[0]
    assert len(filas) == 11
    assert all(f["n_acciones"] == "" and f["n_eventos"] == "" for f in filas)
    assert all(f["alertas"] == "" and f["level"] == "" for f in filas)
    assert all(f["esperado_cumplido"] == "NO_EVALUABLE" for f in filas)
    out = tmp_path / "campana_fp_windows.csv"
    X.escribir_csv(filas, str(out), {"sha_md": "abc"})
    cab = [l for l in out.read_text(encoding="utf-8").splitlines()
           if l.startswith("#")][0]
    assert "agente=002/victima-windows" in cab and "sha256_casos_md=abc" in cab
    with open(out, encoding="utf-8", newline="") as fh:
        rd = list(csv.DictReader([l for l in fh if not l.startswith("#")]))
    assert len(rd) == 11 and list(rd[0]) == X.CSV_HEADER


def test_sin_hecho_es_no_evaluable(tmp_path):
    """Hay marcas (el caso se intentó) pero falta la prueba de efecto ⇒ NO_EVALUABLE."""
    ev = _cosecha(tmp_path, sin_hecho=("W-02",))
    vent, _ = X.leer_marcas(str(ev))
    filas = X.construir_tabla(vent, None, None,
                              {"W-01": {"alertas": 1, "rules": {"67027"},
                                        "levels": [3]},
                               "W-02": {"alertas": 2, "rules": {"67027"},
                                        "levels": [3]}},
                              evidencia=str(ev))
    est = {f["caso"]: f["esperado_cumplido"] for f in filas}
    mot = {f["caso"]: f["motivo"] for f in filas}
    assert est["W-02"] == "NO_EVALUABLE"
    assert "hecho.txt" in mot["W-02"]
    assert est["W-01"] == "SI"


def test_nivel_alto_es_no(tmp_path):
    ev = _cosecha(tmp_path)
    vent, _ = X.leer_marcas(str(ev))
    cid = _casos_reales()[0][0]
    al = {"alertas": 5, "rules": {"67027", "92201"}, "levels": [3, 9]}
    filas = X.construir_tabla(vent, None, None, {cid: al}, evidencia=str(ev))
    fila = next(f for f in filas if f["caso"] == cid)
    assert fila["esperado_cumplido"] == "NO"
    assert fila["level"] == "9" and "92201" in fila["rule_id"]


def test_produccion_completa(tmp_path):
    """Marcas + alertas + acciones + archives → CSV con las 9 columnas rellenas."""
    ev = _cosecha(tmp_path)
    vent, _ = X.leer_marcas(str(ev))
    cid, _dia, ini, fin = _casos_reales()[0]
    al = tmp_path / "alertas.csv"
    _alertas(al, [_fila(ini + timedelta(seconds=2))])
    acciones = tmp_path / "acciones.csv"
    with open(acciones, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["createdutc", "handler", "command"])
        w.writerow([X.fmt_ts(ini + timedelta(seconds=1)), "Command", "cmd /c x"])
        w.writerow([X.fmt_ts(ini + timedelta(seconds=2)), "Command", "cmd /c y"])
    rec = {"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
           "agent": {"id": "002", "name": "victima-windows"}}
    ar = tmp_path / "archives.json"
    with open(ar, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(rec) + "\n")
    paths, _ = X.ficheros_unicos([str(ar)])
    eventos, _ = X.contar_eventos(paths, vent)
    nacc, _ = X.contar_acciones(str(acciones), vent)
    res, _ = X.contar_alertas([str(al)], vent)
    filas = X.construir_tabla(vent, nacc, eventos, res, evidencia=str(ev))
    fila = next(f for f in filas if f["caso"] == cid)
    assert fila["n_acciones"] == "2" and fila["n_eventos"] == "1"
    assert fila["alertas"] == "1" and fila["esperado_cumplido"] == "SI"


def test_autotest_del_modulo():
    assert X._autotest() == 0
