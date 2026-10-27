# -*- coding: utf-8 -*-
"""Tests de `extraer_campana.py` — tabla por caso de la campaña `B6`.

Sin VMs ni red: todo se construye con fixtures sintéticos en `tmp_path` (marcas,
copia de `archives` con `MANIFEST.tsv`, export por acción y `alertas_detalle.csv`).
Se fijan los cuatro bordes que importan:

1. **22 marcas** → `campana_ventanas.tsv` con 11 filas.
2. **Atribución** `[ini−10 s, fin+60 s]` **inclusiva** y solo del agente de la víctima.
3. **Dedupe** por `MANIFEST` (los hardlinks de `archives.json` no se cuentan dos veces).
4. **`esperado_cumplido`**: `SI` si `80792` y `level < 7`; `NO` si alerta a nivel ≥ 7;
   `NO_EJECUTADO` sin marcas o sin `hecho.txt`.
"""

import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import campana as C  # noqa: E402
import extraer_campana as X  # noqa: E402

UTC = timezone.utc
BASE_DIA = datetime(2026, 11, 2, tzinfo=UTC)      # lunes ficticio (d1)


def _t(dia, s):
    return (BASE_DIA + timedelta(days=dia - 1)).replace(
        hour=s // 3600, minute=(s % 3600) // 60, second=s % 60)


def _casos_reales():
    """[(caso, dia, ini_dt, fin_dt)] de las 11 marcas del CSV real."""
    out = []
    for dia in (1, 2, 3):
        accs = C.acciones_b6(dia)
        ini = {a["caso"]: a["t"] for a in accs if a["tipo"] == "inicio"}
        fin = {a["caso"]: a["t"] for a in accs if a["tipo"] == "fin"}
        for cid in sorted(ini):
            out.append((cid, dia, _t(dia, ini[cid]), _t(dia, fin[cid])))
    return out


def _cosecha(tmp_path, casos=None, sin_hecho=()):
    """Crea `evidencia/campana_fp/C-XX/{inicio,fin,hecho}.txt`."""
    ev = tmp_path / "evidencia"
    for cid, _dia, ini, fin in (casos if casos is not None else _casos_reales()):
        d = ev / "campana_fp" / cid
        d.mkdir(parents=True, exist_ok=True)
        (d / "inicio.txt").write_text(X.fmt_ts(ini) + "\n", encoding="utf-8")
        (d / "fin.txt").write_text(X.fmt_ts(fin) + "\n", encoding="utf-8")
        if cid not in sin_hecho:
            (d / "hecho.txt").write_text("RESULTADO=OK\nlineas=12\n", encoding="utf-8")
    return ev


def _archivo(path, filas):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in filas:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _evento(ts, agent_id="001", agent_name="victima-linux", log="x"):
    return {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "agent": {"id": agent_id, "name": agent_name}, "full_log": log}


# --------------------------------------------------------------------------
# 1) Ventanas
# --------------------------------------------------------------------------
def test_solo_ventanas_escribe_22_marcas(tmp_path):
    ev = _cosecha(tmp_path)
    out = tmp_path / "campana_ventanas.tsv"
    assert X.main(["--solo-ventanas", "--evidencia", str(ev), "--out", str(out)]) == 0
    lineas = [l for l in out.read_text(encoding="utf-8").splitlines()
              if not l.startswith("#")]
    rd = list(csv.DictReader(lineas, delimiter="\t"))
    assert len(rd) == 11
    assert sum(1 for r in rd if r["ini"]) == 11
    assert sum(1 for r in rd if r["fin"]) == 11
    assert [r["caso"] for r in rd] == list(C.IDS)
    # coherencia con el CSV de la campaña (mismo jitter)
    assert rd[0]["ini"] == "2026-11-02T17:06:00Z"


def test_ventanas_incompletas_y_solapes(tmp_path):
    casos = _casos_reales()
    ev = _cosecha(tmp_path, casos)
    (ev / "campana_fp" / "C-03" / "fin.txt").unlink()
    vent, avisos = X.leer_marcas(str(ev))
    assert vent["C-03"]["fin"] is None
    assert any("C-03" in a for a in avisos)
    fallos = X.comprobar_ventanas(vent)
    assert any("C-03" in f and "incompletas" in f for f in fallos)

    # solape artificial: C-02 empieza 30 s después del fin de C-01
    v = {k: dict(x) for k, x in vent.items()}
    v["C-02"]["ini"] = v["C-01"]["fin"] + timedelta(seconds=30)
    v["C-02"]["fin"] = v["C-02"]["ini"] + timedelta(seconds=20)
    fallos = X.comprobar_ventanas(v)
    assert any("solapadas" in f for f in fallos)


def test_marcas_en_formato_plano(tmp_path):
    """La cosecha puede dejar `evidencia/C-01_inicio.txt` (plano) en vez de carpetas."""
    ev = tmp_path / "ev"
    ev.mkdir()
    ini = BASE_DIA.replace(hour=17, minute=6, second=0)
    fin = ini + timedelta(seconds=30)
    (ev / "C-01_inicio.txt").write_text(X.fmt_ts(ini) + "\n", encoding="utf-8")
    (ev / "C-01_fin.txt").write_text(X.fmt_ts(fin) + "\n", encoding="utf-8")
    (ev / "C-01_hecho.txt").write_text("RESULTADO=OK\n", encoding="utf-8")
    vent, avisos = X.leer_marcas(str(ev))
    assert vent["C-01"]["ini"] == ini and vent["C-01"]["fin"] == fin
    assert X._evidencia_ok(str(ev), "C-01") is True


def test_ventanas_tsv_ida_y_vuelta(tmp_path):
    casos = _casos_reales()
    vent = {cid: {"ini": ini, "fin": fin} for cid, _d, ini, fin in casos}
    out = tmp_path / "v.tsv"
    X.escribir_ventanas(dict(sorted(vent.items())), str(out))
    recargado = X.cargar_ventanas(str(out))
    assert recargado == dict(sorted(vent.items()))


# --------------------------------------------------------------------------
# 2) archives: agente, ventana y dedupe
# --------------------------------------------------------------------------
def test_eventos_filtran_agente_y_ventana(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos)
    vent, _ = X.leer_marcas(str(ev))
    c1 = next(c for c in casos if c[0] == "C-01")
    a = tmp_path / "ossec-archive-02.json"
    _archivo(a, [
        _evento(c1[2] + timedelta(seconds=5)),                       # dentro, agente 001
        _evento(c1[2] + timedelta(seconds=6), agent_id="000",
                agent_name="wazuh-server"),                          # otro agente
        _evento(c1[3] + timedelta(seconds=1)),                       # después del fin
        _evento(c1[2] - timedelta(seconds=1)),                       # antes del inicio
    ])
    cuenta, meta = X.contar_eventos([str(a)], vent)
    assert cuenta["C-01"] == 1, cuenta
    assert meta["json_invalido"] == 0


def test_dedupe_por_manifest(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos)
    vent, _ = X.leer_marcas(str(ev))
    c1 = next(c for c in casos if c[0] == "C-01")
    d = tmp_path / "den"
    d.mkdir()
    fila = [_evento(c1[2] + timedelta(seconds=5))]
    _archivo(d / "ossec-archive-02.json", fila)
    _archivo(d / "archives.json", fila)          # mismo contenido (hardlink)
    import hashlib
    h = hashlib.sha256((d / "ossec-archive-02.json").read_bytes()).hexdigest()
    (d / "MANIFEST.tsv").write_text(
        "fichero\tbytes\tsha256\torigen\n"
        f"ossec-archive-02.json\t100\t{h}\tunico\n"
        f"ossec-archive-02.json.sum\t64\tabc\tunico\n"
        f"archives.json\t100\t{h}\tDUPLICADO de ossec-archive-02.json (descartado)\n",
        encoding="utf-8")
    paths, notas = X.ficheros_archivo([str(d)])
    assert [Path(p).name for p in paths] == ["ossec-archive-02.json"], notas
    cuenta, _ = X.contar_eventos(paths, vent)
    assert cuenta["C-01"] == 1


def test_dedupe_por_sha_sin_manifest(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    _archivo(a, [_evento(BASE_DIA)])
    b.write_bytes(a.read_bytes())                 # mismo sha256
    paths, notas = X.ficheros_archivo([str(a), str(b)])
    assert len(paths) == 1
    assert any("duplicado por sha256" in n for n in notas)


# --------------------------------------------------------------------------
# 3) acciones y alertas
# --------------------------------------------------------------------------
def test_acciones_por_accion(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos)
    vent, _ = X.leer_marcas(str(ev))
    c1 = next(c for c in casos if c[0] == "C-01")
    p = tmp_path / "acciones.csv"
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["createdutc", "handler", "command"])
        w.writerow([X.fmt_ts(c1[2]), "h", "a"])                 # borde ini (incluido)
        w.writerow([X.fmt_ts(c1[3]), "h", "b"])                 # borde fin (incluido)
        w.writerow([X.fmt_ts(c1[3] + timedelta(seconds=1)), "h", "c"])
    cuenta, meta = X.contar_acciones(str(p), vent)
    assert cuenta["C-01"] == 2, cuenta
    assert meta["columna"] == "createdutc"


def test_acciones_agregadas_se_rechazan(tmp_path):
    p = tmp_path / "ghosts_acciones.csv"
    p.write_text("# comentario\ntipo,clave,acciones\ntotal,,123\n"
                 "handler,B1,10\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        X.contar_acciones(str(p), {})


def test_alertas_bordes_y_agente(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos)
    vent, _ = X.leer_marcas(str(ev))
    c1 = next(c for c in casos if c[0] == "C-01")
    p = tmp_path / "alertas_detalle.csv"
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["timestamp_utc", "agent_name", "rule_id", "rule_level", "audit_exe"])
        w.writerow([X.fmt_ts(c1[2] - timedelta(seconds=10)), "victima-linux", "80792", "3", "/usr/bin/free"])
        w.writerow([X.fmt_ts(c1[2] - timedelta(seconds=11)), "victima-linux", "80792", "3", "/usr/bin/free"])
        w.writerow([X.fmt_ts(c1[2] + timedelta(seconds=5)), "victima-linux", "80792", "3", "/usr/bin/free"])
        w.writerow([X.fmt_ts(c1[3] + timedelta(seconds=60)), "victima-linux", "80791", "5", "/usr/bin/rm"])
        w.writerow([X.fmt_ts(c1[3] + timedelta(seconds=61)), "victima-linux", "80790", "3", "/usr/bin/rm"])
        w.writerow([X.fmt_ts(c1[2] + timedelta(seconds=5)), "wazuh-server", "80792", "3", "/usr/bin/free"])
    res = X.contar_alertas(str(p), vent)
    assert res["C-01"]["alertas"] == 3, res["C-01"]
    assert res["C-01"]["rules"] == {"80792", "80791"}
    assert max(res["C-01"]["levels"]) == 5
    assert all(v["alertas"] == 0 for k, v in res.items() if k != "C-01")


# --------------------------------------------------------------------------
# 4) Tabla final
# --------------------------------------------------------------------------
def test_tabla_completa_estados_y_columnas_real(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos, sin_hecho=("C-03",))
    out_v = tmp_path / "campana_ventanas.tsv"
    assert X.main(["--solo-ventanas", "--evidencia", str(ev), "--out", str(out_v)]) == 0
    vent = X.cargar_ventanas(str(out_v))
    c1, c2 = vent["C-01"]["ini"], vent["C-02"]["ini"]
    al = tmp_path / "alertas.csv"
    with open(al, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["timestamp_utc", "agent_name", "rule_id", "rule_level"])
        w.writerow([X.fmt_ts(c1 + timedelta(seconds=3)), "victima-linux", "80792", "3"])
        w.writerow([X.fmt_ts(c1 + timedelta(seconds=4)), "victima-linux", "80791", "3"])
        w.writerow([X.fmt_ts(c2 + timedelta(seconds=3)), "victima-linux", "80792", "8"])
    ar = tmp_path / "ar.json"
    _archivo(ar, [_evento(c1 + timedelta(seconds=3)), _evento(c2 + timedelta(seconds=3))])
    acc = tmp_path / "acc.csv"
    with open(acc, "w", encoding="utf-8", newline="\n") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["createdutc"])
        w.writerow([X.fmt_ts(c1 + timedelta(seconds=3))])
    out = tmp_path / "campana_fp.csv"
    assert X.main(["--ventanas", str(out_v), "--archives", str(ar),
                   "--acciones", str(acc), "--alertas", str(al),
                   "--evidencia", str(ev), "--out", str(out)]) == 0
    lineas = [l for l in out.read_text(encoding="utf-8").splitlines()
              if not l.startswith("#")]
    rd = list(csv.DictReader(lineas))
    assert list(rd[0].keys()) == X.CSV_HEADER
    assert len(rd) == 3                                   # d1 tiene 3 casos
    por = {r["caso"]: r for r in rd}
    assert por["C-01"]["esperado_cumplido"] == "SI"
    assert por["C-01"]["alertas"] == "2"
    assert por["C-01"]["rule_id"] == "80791;80792"
    assert por["C-01"]["level"] == "3"
    assert por["C-01"]["n_eventos"] == "1"
    assert por["C-01"]["n_acciones"] == "1"
    assert por["C-02"]["esperado_cumplido"] == "NO"        # nivel 8 >= 7
    assert por["C-03"]["esperado_cumplido"] == "NO_EJECUTADO"   # sin hecho.txt
    assert por["C-03"]["alertas"] == "0"
    # cabecera sellada
    cab = [l for l in out.read_text(encoding="utf-8").splitlines() if l.startswith("#")][0]
    assert re.search(r"sha256_casos_md=[0-9a-f]{64}", cab)
    assert "atribucion=[ini-10s,fin+60s]" in cab


def test_sin_fuentes_de_archives_o_acciones_deja_columnas_vacias(tmp_path):
    casos = [c for c in _casos_reales() if c[1] == 1]
    ev = _cosecha(tmp_path, casos)
    out_v = tmp_path / "v.tsv"
    X.main(["--solo-ventanas", "--evidencia", str(ev), "--out", str(out_v)])
    out = tmp_path / "c.csv"
    assert X.main(["--ventanas", str(out_v), "--out", str(out)]) == 0
    lineas = [l for l in out.read_text(encoding="utf-8").splitlines()
              if not l.startswith("#")]
    rd = list(csv.DictReader(lineas))
    assert all(r["n_acciones"] == "" and r["n_eventos"] == "" for r in rd)
    assert all(r["esperado_cumplido"] == "NO" for r in rd)   # sin alertas
