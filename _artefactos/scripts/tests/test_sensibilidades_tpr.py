# -*- coding: utf-8 -*-
"""Tests de `sensibilidades_tpr.py`: mismas variantes en Linux y Windows, descuentos por dato."""
from pathlib import Path
import csv
import json
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import sensibilidades_tpr as S  # noqa: E402

COLS = ["ata_id", "iter", "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_groups",
        "rs_origen", "rule_description", "categoria", "motivo", "atribucion", "revision",
        "veredicto_humano", "evidencia"]


def _caso(d, ata, filas):
    p = d / f"{ata}_iter1-Audited.csv"
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(COLS)
        for ts, rid, lvl, cat in filas:
            w.writerow([ata, 1, ts, "x", rid, lvl, "g", "RS1", "d", cat, "", "", "", "", ""])


def _t5(path, si):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["rule_id", "doble_uso"])
        for r in si:
            w.writerow([r, "SÍ"])
        w.writerow(["99999", "NO"])


@pytest.fixture()
def mundo(tmp_path):
    lin, win, al = tmp_path / "lin", tmp_path / "win", tmp_path / "alertas"
    for d in (lin, win, al):
        d.mkdir()
    # LINUX: 3 casos; 2 detectados solo por 80792 (doble uso), 1 por una regla propia de nivel 8
    _caso(lin, "ATA001", [("2026-09-28T10:00:00.000Z", "80792", 3, "deteccion")])
    _caso(lin, "ATA002", [("2026-09-28T10:01:00.000Z", "80792", 3, "deteccion")])
    _caso(lin, "ATA003", [("2026-09-28T10:02:00.000Z", "80792", 3, "deteccion"),
                          ("2026-09-28T10:02:01.000Z", "5902", 8, "deteccion")])
    _t5(tmp_path / "t5_lin.csv", ["80792"])
    # WINDOWS: 3 casos. A: solo envoltorio SSH (92052 padre sshd + 92032 padre cmd).
    # B: envoltorio + 67027 (doble uso). C: envoltorio + regla propia (92027 nivel 4)
    _caso(win, "ATA056", [("2026-11-09T10:00:00.000Z", "92052", 4, "deteccion"),
                          ("2026-11-09T10:00:01.000Z", "92032", 3, "deteccion")])
    _caso(win, "ATA057", [("2026-11-09T10:01:00.000Z", "92052", 4, "deteccion"),
                          ("2026-11-09T10:01:01.000Z", "67027", 3, "deteccion")])
    _caso(win, "ATA058", [("2026-11-09T10:02:00.000Z", "92052", 4, "deteccion"),
                          ("2026-11-09T10:02:01.000Z", "92027", 4, "deteccion")])
    _t5(tmp_path / "t5_win.csv", ["67027"])
    lineas = []
    for ts, rid, parent in (("2026-11-09T10:00:00.000", "92052", r"C:\Windows\System32\OpenSSH\sshd.exe"),
                            ("2026-11-09T10:00:01.000", "92032", r"C:\Windows\System32\cmd.exe"),
                            ("2026-11-09T10:01:00.000", "92052", r"C:\Windows\System32\OpenSSH\sshd.exe"),
                            ("2026-11-09T10:02:00.000", "92052", r"C:\Windows\System32\OpenSSH\sshd.exe")):
        lineas.append(json.dumps({"timestamp": ts + "+0000", "agent": {"id": "002"}, "rule": {"id": rid},
                                  "data": {"win": {"eventdata": {"parentImage": parent}}}}))
    (al / "ossec-alerts-09.json").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return lin, win, al, tmp_path


def _tpr(filas, plat, var, n):
    f = [x for x in filas if x["plataforma"] == plat and x["variante"] == var and x["umbral_N"] == n][0]
    return f["casos_detectados"]


def test_linux_sin_doble_uso_deja_solo_la_regla_propia(mundo):
    lin, win, al, tp = mundo
    filas, du = S.calcular("linux", str(lin), str(tp / "t5_lin.csv"))
    assert du == ["80792"]
    assert _tpr(filas, "linux", "canonico", 3) == 3
    assert _tpr(filas, "linux", "sin_doble_uso", 3) == 1
    assert _tpr(filas, "linux", "sin_entrega", 3) == 3        # en Linux no hay equivalente: igual que el canonico


def test_windows_sin_entrega_no_hunde_el_tpr_si_hay_otras_alertas(mundo):
    lin, win, al, tp = mundo
    filas, du = S.calcular("windows", str(win), str(tp / "t5_win.csv"), str(al))
    assert _tpr(filas, "windows", "canonico", 3) == 3
    # A pierde sus dos alertas de entrega; B conserva 67027; C conserva 92027
    assert _tpr(filas, "windows", "sin_entrega", 3) == 2
    # sin doble uso (67027): B pierde 67027 pero conserva el 92052 de entrega
    assert _tpr(filas, "windows", "sin_doble_uso", 3) == 3
    # sin entrega NI doble uso: solo C se mantiene (92027)
    assert _tpr(filas, "windows", "sin_entrega_ni_doble_uso", 3) == 1


def test_sin_crudo_de_alertas_la_variante_de_entrega_es_ND_no_un_numero_inventado(mundo):
    lin, win, al, tp = mundo
    filas, _ = S.calcular("windows", str(win), str(tp / "t5_win.csv"), None)
    assert _tpr(filas, "windows", "sin_entrega", 3) == "ND"
    assert _tpr(filas, "windows", "canonico", 3) == 3          # las que no necesitan el crudo si salen


def test_el_padre_decide_no_la_regla_entera(mundo):
    """92052 con un padre NO sshd (p. ej. `svchost.exe`) NO se descuenta."""
    lin, win, al, tp = mundo
    (al / "ossec-alerts-09.json").write_text(json.dumps(
        {"timestamp": "2026-11-09T10:00:00.000+0000", "agent": {"id": "002"}, "rule": {"id": "92052"},
         "data": {"win": {"eventdata": {"parentImage": r"C:\Windows\System32\svchost.exe"}}}}) + "\n",
        encoding="utf-8")
    filas, _ = S.calcular("windows", str(win), str(tp / "t5_win.csv"), str(al))
    assert _tpr(filas, "windows", "sin_entrega", 3) == 3       # ya no cae ninguno por entrega


def test_doble_uso_lo_decide_el_dato_t5(mundo):
    lin, win, al, tp = mundo
    _t5(tp / "t5_lin.csv", [])                                  # T5 sin reglas de doble uso
    filas, du = S.calcular("linux", str(lin), str(tp / "t5_lin.csv"))
    assert du == [] and _tpr(filas, "linux", "sin_doble_uso", 3) == 3


def test_salida_determinista_y_cabecera(mundo, tmp_path):
    lin, win, al, tp = mundo
    args = ["--linux-audited", str(lin), "--windows-audited", str(win), "--t5-linux", str(tp / "t5_lin.csv"),
            "--t5-windows", str(tp / "t5_win.csv"), "--alertas-windows", str(al)]
    S.main(args + ["--out", str(tmp_path / "a.csv")])
    S.main(args + ["--out", str(tmp_path / "b.csv")])
    a, b = (tmp_path / "a.csv").read_bytes(), (tmp_path / "b.csv").read_bytes()
    assert a == b and b"\r" not in a
    txt = a.decode("utf-8").splitlines()
    assert txt[0].startswith("# T2_sensibilidades_comparadas.csv") and "doble_uso_linux=80792" in txt[0]
    assert txt[1] == "plataforma,variante,umbral_N,casos_detectados,casos_total,TPR"
    assert len(txt) == 2 + 2 * len(S.VARIANTES) * len(S.UMBRALES)


def test_la_ventana_canonica_es_rev1_si_hay_repeticion(mundo, tmp_path):
    """Igual que `tabla2_ataques`: `rev1` para los casos de `repeticiones.csv`, `iter1` para el resto."""
    lin, win, al, tp = mundo
    # ATA001 repetido: su iter1 detecta (80792) pero su rev1 (la canonica) detecta con una regla propia de nivel 8
    _caso(lin, "ATA001", [("2026-09-28T10:00:00.000Z", "80792", 3, "deteccion")])
    p = lin / "ATA001_rev1-Audited.csv"
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(COLS)
        w.writerow(["ATA001", 1, "2026-09-28T10:00:00.000Z", "x", "5902", 8, "g", "RS1", "d", "deteccion", "", "", "", "", ""])
    rep = tp / "rep.csv"
    rep.write_text("ata_id,tecnica\nATA001,T1\n", encoding="utf-8")
    sin, _ = S.calcular("linux", str(lin), str(tp / "t5_lin.csv"))
    con, _ = S.calcular("linux", str(lin), str(tp / "t5_lin.csv"), None, S.leer_repeticiones(str(rep)))
    assert _tpr(sin, "linux", "sin_doble_uso", 3) == 1      # con iter1: ATA001 solo tenia 80792 (doble uso)
    assert _tpr(con, "linux", "sin_doble_uso", 3) == 2      # con rev1 (canonica): ATA001 detecta por 5902


def test_falta_la_ventana_canonica_es_un_error_no_un_silencio(mundo, tmp_path):
    lin, win, al, tp = mundo
    (tp / "rep.csv").write_text("ata_id\nATA002\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        S.calcular("linux", str(lin), str(tp / "t5_lin.csv"), None, S.leer_repeticiones(str(tp / "rep.csv")))


T4_REPO = Path(__file__).resolve().parents[3] / "Hojas"


@pytest.mark.skipif(not (T4_REPO / "T4_rendimiento.csv").is_file(), reason="sin Hojas/ (clon parcial)")
def test_el_canonico_reproduce_la_tabla_T4_oficial():
    """Si esto falla, la herramienta no esta midiendo lo mismo que la tabla del TFG."""
    raiz = T4_REPO.parent

    def t4(nombre):
        filas = S._leer(str(T4_REPO / nombre))
        tpr = [f for f in filas if f["metrica"] == "TPR"][0]
        return {n: float(tpr[f"wazuh_C1_N{n}"]) for n in S.UMBRALES}

    rep = S.leer_repeticiones(str(raiz / "Hojas" / "repeticiones.csv"))
    lin, _ = S.calcular("linux", str(raiz / S.DEF_LINUX_AUDITED), str(raiz / S.DEF_T5_LINUX), None, rep)
    win, _ = S.calcular("windows", str(raiz / S.DEF_WIN_AUDITED), str(raiz / S.DEF_T5_WIN), None, rep)
    for plat, filas, ref in (("linux", lin, t4("T4_rendimiento.csv")), ("windows", win, t4("T4_rendimiento_windows_b2.csv"))):
        for n in S.UMBRALES:
            f = [x for x in filas if x["variante"] == "canonico" and x["umbral_N"] == n][0]
            assert round(f["TPR"], 6) == round(ref[n], 6), (plat, n, f["TPR"], ref[n])
