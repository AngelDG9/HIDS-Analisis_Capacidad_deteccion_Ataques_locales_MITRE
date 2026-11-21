# -*- coding: utf-8 -*-
"""Pruebas de los scripts del cierre de Wazuh (campana v2): resolver dudosas por precedente, bitacora v2 y verificador."""
import csv
import gzip
import json
import os
import subprocess
import sys

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
H_AUD = ["ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_groups", "rs_origen", "rule_description",
         "categoria", "motivo", "atribucion", "revision", "veredicto_humano", "evidencia"]
H_REV = H_AUD + ["veredicto", "nota", "revisor", "fecha"]


def _escribe(p, cab, filas, comentario="# prueba"):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow([comentario])
        w.writerow(cab)
        w.writerows(filas)


def _fila(ts, regla, motivo, atrib="", cat="dudosa", rev="", ver="", evid="", extra=()):
    base = ["ATA001", "1", ts, "victima-linux", regla, "3", "g", "RS2", "d", cat, motivo, atrib, rev, ver, evid]
    return base + list(extra)


def _run(*args):
    return subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")


def test_resolver_dudosas_solo_por_precedente_unanime_y_con_apoyo(tmp_path):
    v1 = tmp_path / "v1"
    v2 = tmp_path / "v2"
    # v1: la clave (5502, sin_campos, '') tiene 12 filas TODAS `ruido`; la clave (80792, ambigua, T1) mezcla ruido y artefacto
    filas_v1 = [_fila("2026-01-01T00:00:%02dZ" % i, "5502", "sin_campos", cat="ruido_conocido", rev="resuelta", ver="ruido") for i in range(12)]
    filas_v1 += [_fila("2026-01-01T01:00:%02dZ" % i, "80792", "ambigua:S1", "T1", cat="ruido_conocido", rev="resuelta", ver="ruido") for i in range(6)]
    filas_v1 += [_fila("2026-01-01T02:00:%02dZ" % i, "80792", "ambigua:S1", "T1", cat="artefacto_ataque", rev="resuelta", ver="artefacto") for i in range(6)]
    _escribe(str(v1 / "ATA001_iter1-Audited.csv"), H_AUD, filas_v1)
    # v2: una dudosa por clave + una que pertenece a la carpeta del ataque (no se puede declarar ruido) + una clave sin precedente
    filas_v2 = [
        _fila("2026-02-01T00:00:01Z", "5502", "sin_campos", extra=("", "", "", "")),
        _fila("2026-02-01T00:00:02Z", "80792", "ambigua:S1", "T1", extra=("", "", "", "")),
        _fila("2026-02-01T00:00:03Z", "554", "sin_campos", extra=("", "", "", "")),
        _fila("2026-02-01T00:00:04Z", "5502", "sin_campos", evid="audit_cwd=/home/angel/lab-attack/ATA001", extra=("", "", "", "")),
    ]
    _escribe(str(v2 / "ATA001_iter1-Revision.csv"), H_REV, filas_v2)
    out = tmp_path / "out"
    p = _run(os.path.join(SCRIPTS, "resolver_dudosas_por_precedente.py"), "--v1", str(v1), "--v2", str(v2), "--out", str(out), "--min-apoyo", "10")
    assert p.returncode == 0, p.stderr
    rows = [r for r in csv.reader(open(out / "ATA001_iter1-Revision.csv", encoding="utf-8")) if r and not r[0].startswith("#")]
    h = rows[0]
    ver = [r[h.index("veredicto")] for r in rows[1:]]
    assert ver == ["ruido", "", "", ""], ver          # unanime+apoyo -> ruido; mixta, sin precedente y "del ataque" -> siguen dudosas
    assert "NO humano" in rows[1][h.index("revisor")]
    assert "precedente v1 unanime" in rows[1][h.index("nota")]


def test_generar_bitacora_v2_sustituye_las_iteraciones_y_conserva_los_metadatos(tmp_path):
    base = tmp_path / "linux_v2"
    os.makedirs(base)
    with open(base / "windows_index.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["tag", "ata", "variante", "iter", "estado", "t0", "t1"])
        w.writerow(["ATA009_iter1", "ATA009", "base", "1", "FALLO", "", ""])
        w.writerow(["ATA009_iter1", "ATA009", "base", "1", "OK", "2026-11-20T01:14:55Z", "2026-11-20T01:15:27Z"])   # la ULTIMA fila manda
    v1 = tmp_path / "bitacora_v1"
    os.makedirs(v1)
    json.dump({"ata_id": "ATA009", "tecnica": "T1567", "sistema": "linux", "iteraciones": [{"iter": 1, "t0": "viejo"}]},
              open(v1 / "ATA009.json", "w", encoding="utf-8"))
    p = _run(os.path.join(SCRIPTS, "generar_bitacora_v2.py"), "--so", "linux", "--base", str(base), "--v1-dir", str(v1))
    assert p.returncode == 0, p.stderr
    j = json.load(open(base / "Bitacora" / "ATA009.json", encoding="utf-8"))
    assert j["tecnica"] == "T1567" and j["sistema"] == "linux"
    assert len(j["iteraciones"]) == 1 and j["iteraciones"][0]["t0"] == "2026-11-20T01:14:55Z"
    assert j["iteraciones"][0]["duracion_s"] == 32 and j["iteraciones"][0]["version_datos"] == 2
    assert j["iteraciones"][0]["audited"].endswith("linux_v2/Auditado/ATA009_iter1-Audited.csv")


def _campana_sintetica(tmp_path, archives_lineas=3, quitar_raw=False):
    base = tmp_path / "linux_v2"
    raw = tmp_path / "raw"
    crudo = tmp_path / "crudo"
    for d in (base / "Logs" / "ATA001_iter1", base / "CSV", base / "Auditado", raw, crudo):
        os.makedirs(d, exist_ok=True)
    t0, t1 = "2026-11-20T01:00:00Z", "2026-11-20T01:00:30Z"
    alertas = ['{"timestamp":"2026-11-20T01:00:%02d.000+0000","agent":{"id":"001"}}\n' % i for i in range(5, 10)]
    archives = ['{"timestamp":"2026-11-20T01:00:%02d.000+0000","agent":{"id":"001"}}\n' % i for i in range(archives_lineas)]
    if not quitar_raw:
        with gzip.open(raw / "ATA001_iter1_alerts_001.jsonl.gz", "wt", encoding="utf-8") as fh:
            fh.writelines(alertas)
        with gzip.open(raw / "ATA001_iter1_archives_001.jsonl.gz", "wt", encoding="utf-8") as fh:
            fh.writelines(archives)
    with open(base / "windows_index.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["tag", "ata", "variante", "iter", "estado", "t0", "t1", "lineas_alerts", "lineas_archives"])
        w.writerow(["ATA001_iter1", "ATA001", "base", "1", "OK", t0, t1, "5", str(archives_lineas)])
    json.dump({"script_sha256": "abc", "sha256_en_victima": "abc"}, open(base / "Logs" / "ATA001_iter1" / "lanzamiento.json", "w"))
    open(base / "Logs" / "ATA001_iter1" / "sha256_artefacto.txt", "w").write("abc  x\n")
    open(base / "Logs" / "ATA001_iter1" / "ejecucion.out", "w").write("ok\n")
    _escribe(str(base / "CSV" / "ATA001_iter1-Detalle.csv"), ["a", "b"], [["1", "2"]] * 5)
    _escribe(str(base / "Auditado" / "ATA001_iter1-Audited.csv"), H_AUD, [_fila("2026-11-20T01:00:05Z", "80792", "x", cat="deteccion")])
    man = crudo / "MANIFEST.tsv"
    (crudo / "archives").mkdir(exist_ok=True)
    open(crudo / "archives" / "a.json", "w").write("x")
    import hashlib
    open(man, "w", encoding="utf-8").write("fichero\tbytes\tsha256\narchives/a.json\t1\t%s\n" % hashlib.sha256(b"x").hexdigest())
    open(crudo / "crudo.done", "w").write("ok\n")
    return base, raw, crudo


def test_verificador_acepta_una_campana_completa(tmp_path):
    base, raw, crudo = _campana_sintetica(tmp_path)
    p = _run(os.path.join(SCRIPTS, "verificar_completitud_ataques_v2.py"), "--so", "linux", "--base", str(base), "--raw", str(raw),
             "--crudo", str(crudo), "--esperadas", "1")
    assert p.returncode == 0, p.stdout + p.stderr


def test_verificador_detecta_archives_vacios_y_falta_de_raw(tmp_path):
    base, raw, crudo = _campana_sintetica(tmp_path, archives_lineas=0)
    p = _run(os.path.join(SCRIPTS, "verificar_completitud_ataques_v2.py"), "--so", "linux", "--base", str(base), "--raw", str(raw), "--crudo", str(crudo))
    assert p.returncode == 1
    assert "archives vacio" in open(base / "VERIFICACION_COMPLETITUD.md", encoding="utf-8").read()
    base2, raw2, crudo2 = _campana_sintetica(tmp_path / "otra", quitar_raw=True)
    p2 = _run(os.path.join(SCRIPTS, "verificar_completitud_ataques_v2.py"), "--so", "linux", "--base", str(base2), "--raw", str(raw2), "--crudo", str(crudo2))
    assert p2.returncode == 1


def test_verificador_detecta_un_crudo_alterado(tmp_path):
    base, raw, crudo = _campana_sintetica(tmp_path)
    open(crudo / "archives" / "a.json", "w").write("alterado")
    p = _run(os.path.join(SCRIPTS, "verificar_completitud_ataques_v2.py"), "--so", "linux", "--base", str(base), "--raw", str(raw), "--crudo", str(crudo))
    assert p.returncode == 1
    assert "sha256 distinto" in open(base / "VERIFICACION_COMPLETITUD.md", encoding="utf-8").read()
