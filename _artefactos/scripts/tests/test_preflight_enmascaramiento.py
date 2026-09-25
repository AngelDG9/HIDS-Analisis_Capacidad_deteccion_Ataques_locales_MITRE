# -*- coding: utf-8 -*-
"""Tests offline de `preflight_enmascaramiento.py` (Fase 3 · A2.2).

Cubren los **8 casos de `plan.md` §6** (MALO, BUENO, HERMANA, DECLARADO,
MULTINIVEL, RS4, INCOMPLETO, DETERMINISMO) **sin VMs**: usan el manifiesto real
`Soporte/Wazuh/Configuracion/active_ruleset.txt`, las capturas reales del paso 0
(`tests/fixtures/preflight_logtest_{base,candidato}.txt`) y los ficheros de reglas
propias de fixture.

El determinismo (R-13) se comprueba comparando el informe **byte a byte**.
"""
from pathlib import Path
import hashlib
import sys

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import preflight_enmascaramiento as pf  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]

RULESET = ROOT / "Soporte" / "Wazuh" / "Configuracion" / "active_ruleset.txt"
REPO_LOCAL = ROOT / "Soporte" / "Wazuh" / "Reglas" / "local_rules.xml"

BASE = FIX / "preflight_logtest_base.txt"
CAND = FIX / "preflight_logtest_candidato.txt"
EVENTOS = FIX / "preflight_eventos.jsonl"

LOCAL_EMPTY = FIX / "preflight_local_empty.xml"
LOCAL_MALO = FIX / "preflight_local_malo.xml"
LOCAL_BUENO = FIX / "preflight_local_bueno.xml"
LOCAL_MULTINIVEL = FIX / "preflight_local_multinivel.xml"
LOCAL_HERMANA = FIX / "preflight_local_hermana.xml"
EXTERNAL_RS4 = FIX / "preflight_external_rs4.xml"

DECL_VACIA = FIX / "preflight_decl_vacia.csv"
DECL_CADENA = FIX / "preflight_decl_cadena.csv"
DECL_HERMANA = FIX / "preflight_decl_hermana.csv"

SIN_EXTERNAS = str(FIX / "preflight_no_existe_*.xml")


def ejecutar(local, decl=DECL_VACIA, external=SIN_EXTERNAS, base=None, cand=None,
             out=None, eventos=None):
    args = [
        "--local-rules", str(local),
        "--external-rules", str(external) if external is not SIN_EXTERNAS else SIN_EXTERNAS,
        "--active-ruleset", str(RULESET),
        "--declaraciones", str(decl),
    ]
    if base is not None:
        args += ["--logtest-base", str(base)]
    if cand is not None:
        args += ["--logtest-candidato", str(cand)]
    if eventos is not None:
        args += ["--eventos", str(eventos)]
    if out is not None:
        args += ["--out", str(out)]
    return pf.main(args)


# --------------------------------------------------------------------------
# MALO — regla propia hija de 5710 -> FALLA (exit 1)
# --------------------------------------------------------------------------
def test_caso_malo_falla(capsys):
    rc = ejecutar(LOCAL_MALO)
    assert rc == pf.EXIT_FALLA == 1
    salida = capsys.readouterr().out
    assert "RESULTADO: FALLA" in salida
    assert "100000 -> 5710" in salida


# --------------------------------------------------------------------------
# BUENO — regla propia suelta; capturas sin cambio -> PASA (exit 0)
# --------------------------------------------------------------------------
def test_caso_bueno_pasa(capsys):
    rc = ejecutar(LOCAL_BUENO, base=BASE, cand=BASE, eventos=EVENTOS)
    assert rc == pf.EXIT_PASA == 0
    salida = capsys.readouterr().out
    assert "RESULTADO: PASA" in salida
    assert "Estado: **EJECUTADO**" in salida


# --------------------------------------------------------------------------
# HERMANA — sin declarar -> FALLA; declarada tipo=hermana -> PASA
# --------------------------------------------------------------------------
def test_caso_hermana_falla_sin_declarar(capsys):
    rc = ejecutar(LOCAL_HERMANA, base=BASE, cand=CAND, eventos=EVENTOS)
    assert rc == pf.EXIT_FALLA == 1
    salida = capsys.readouterr().out
    assert "5710" in salida and "100000" in salida
    assert "[NO DECLARADO]" in salida
    assert "RESULTADO: FALLA" in salida


def test_caso_hermana_pasa_si_declarada(capsys):
    rc = ejecutar(LOCAL_HERMANA, decl=DECL_HERMANA, base=BASE, cand=CAND, eventos=EVENTOS)
    assert rc == pf.EXIT_PASA == 0
    salida = capsys.readouterr().out
    assert "[DECLARADO]" in salida
    assert "RESULTADO: PASA" in salida


# --------------------------------------------------------------------------
# DECLARADO — el caso MALO + fila tipo=cadena -> PASA
# --------------------------------------------------------------------------
def test_caso_declarado_pasa(capsys):
    rc = ejecutar(LOCAL_MALO, decl=DECL_CADENA, base=BASE, cand=BASE)
    assert rc == pf.EXIT_PASA == 0
    assert "RESULTADO: PASA" in capsys.readouterr().out


def test_declaracion_con_tipo_distinto_no_excusa(capsys):
    # una fila tipo=hermana NO declara un hallazgo de cadena
    rc = ejecutar(LOCAL_MALO, decl=DECL_HERMANA, base=BASE, cand=BASE)
    assert rc == pf.EXIT_FALLA == 1
    assert "RESULTADO: FALLA" in capsys.readouterr().out


# --------------------------------------------------------------------------
# MULTINIVEL — propia A -> propia B -> 5710 -> FALLA (transitivo)
# --------------------------------------------------------------------------
def test_caso_multinivel_falla(capsys):
    rc = ejecutar(LOCAL_MULTINIVEL)
    assert rc == pf.EXIT_FALLA == 1
    salida = capsys.readouterr().out
    assert "100010 -> 100011 -> 5710" in salida


# --------------------------------------------------------------------------
# RS4 — external_*.xml con <if_sid> de base -> FALLA
# --------------------------------------------------------------------------
def test_caso_rs4_falla(capsys):
    rc = ejecutar(LOCAL_EMPTY, external=EXTERNAL_RS4)
    assert rc == pf.EXIT_FALLA == 1
    salida = capsys.readouterr().out
    assert "100500 -> 5710" in salida
    assert "RESULTADO: FALLA" in salida


# --------------------------------------------------------------------------
# INCOMPLETO — reglas propias y sin capturas -> exit 3 + aviso explícito
# --------------------------------------------------------------------------
def test_caso_incompleto(capsys):
    rc = ejecutar(LOCAL_BUENO)
    assert rc == pf.EXIT_INCOMPLETO == 3
    salida = capsys.readouterr().out
    assert "Estado: **NO EJECUTADO**" in salida
    assert "C2 NO EJECUTADO" in salida
    assert "RESULTADO: INCOMPLETO" in salida


# --------------------------------------------------------------------------
# DETERMINISMO — dos ejecuciones, misma entrada -> informe byte a byte idéntico
# --------------------------------------------------------------------------
def test_determinismo_byte_a_byte(tmp_path):
    out1 = tmp_path / "informe1.md"
    out2 = tmp_path / "informe2.md"
    args = dict(local=LOCAL_HERMANA, decl=DECL_HERMANA, base=BASE, cand=CAND,
                eventos=EVENTOS)
    assert ejecutar(out=out1, **args) == pf.EXIT_PASA
    assert ejecutar(out=out2, **args) == pf.EXIT_PASA
    b1, b2 = out1.read_bytes(), out2.read_bytes()
    assert b1 == b2
    assert hashlib.sha256(b1).hexdigest() == hashlib.sha256(b2).hexdigest()


# --------------------------------------------------------------------------
# 0 reglas propias (repo real) -> PASA trivial, sin exigir C2
# --------------------------------------------------------------------------
def test_repo_cero_reglas_pasa(capsys):
    rc = ejecutar(REPO_LOCAL, decl=DECL_VACIA,
                  external=ROOT / "Soporte" / "Wazuh" / "Reglas" / "external_*.xml")
    assert rc == pf.EXIT_PASA == 0
    salida = capsys.readouterr().out
    assert "Reglas propias analizadas: **0**" in salida
    assert "RESULTADO: PASA" in salida


# --------------------------------------------------------------------------
# Parser: ignora comentarios XML
# --------------------------------------------------------------------------
def test_parser_ignora_comentarios_xml():
    assert pf.parse_rules_file(str(LOCAL_EMPTY), "RS3") == []
    assert pf.parse_rules_file(str(REPO_LOCAL), "RS3") == []


def test_parser_extrae_padres_y_separadores(tmp_path):
    f = tmp_path / "r.xml"
    f.write_text(
        "<group name='g,'>\n"
        "  <rule id='100'><if_sid>1, 2</if_sid><if_matched_sid>3</if_matched_sid></rule>\n"
        "  <rule id='101'><if_sid>1,2, 3</if_sid></rule>\n"
        "</group>\n",
        encoding="utf-8",
    )
    reglas = {r.rid: r for r in pf.parse_rules_file(str(f), "RS3")}
    assert reglas["100"].padres == ["1", "2", "3"]
    assert reglas["101"].padres == ["1", "2", "3"]


# --------------------------------------------------------------------------
# Parser de capturas logtest
# --------------------------------------------------------------------------
def test_parse_logtest_base_y_candidato():
    base = pf.parse_logtest(str(BASE))
    cand = pf.parse_logtest(str(CAND))
    assert len(base) == len(cand) == 12
    assert base[-1] == "5710"      # el evento "Invalid user" lo ganaba la base
    assert cand[-1] == "100000"    # con la hermana -> lo gana la propia
    assert base[:-1] == cand[:-1]  # el resto de eventos no cambia


def test_parse_logtest_capturas_de_distinto_tamano_falla(tmp_path, capsys):
    corta = tmp_path / "corta.txt"
    corta.write_text(BASE.read_text(encoding="utf-8").split("**Phase 1:")[0],
                     encoding="utf-8")
    rc = ejecutar(LOCAL_HERMANA, base=corta, cand=CAND)
    assert rc == pf.EXIT_USO == 2


# --------------------------------------------------------------------------
# Manifiesto y resolución por fichero de origen
# --------------------------------------------------------------------------
def test_manifiesto_resuelve_base_y_propia(tmp_path):
    rangos = pf.parse_active_ruleset(str(RULESET))
    assert rangos, "el manifiesto real debe tener el bloque de detalle"
    propia = pf.Regla("100000", "RS3", "x", [])
    por_id = {"100000": propia}
    # 5710 vive en 0095-sshd_rules.xml (RS1)
    assert pf.resolver_ancestro("5710", por_id, rangos)[0] == "RS1"
    # 80790 vive en 0365-auditd_rules.xml (RS2); el rango solapa con fortigate
    rs, nota, ambigua = pf.resolver_ancestro("80790", por_id, rangos)
    assert rs == "RS2"
    assert ambigua is True and nota.startswith("ambigua_por_rangos")
    # una regla propia se resuelve por su fichero, no por el manifiesto
    assert pf.resolver_ancestro("100000", por_id, rangos)[0] == "RS3"
    # id fuera de todo rango -> no resoluble
    assert pf.resolver_ancestro("424242", por_id, rangos)[0] is None


# --------------------------------------------------------------------------
# Uso / entradas
# --------------------------------------------------------------------------
def test_uso_local_rules_inexistente(tmp_path):
    assert pf.main(["--local-rules", str(tmp_path / "no.xml"),
                    "--active-ruleset", str(RULESET),
                    "--declaraciones", str(DECL_VACIA)]) == pf.EXIT_USO


def test_columnas_declaracion():
    assert pf.DECL_HEADER == [
        "regla_propia", "tipo", "regla_base", "motivo",
        "revision_rs1", "revisor", "fecha",
    ]


def test_exit_codes():
    assert (pf.EXIT_PASA, pf.EXIT_FALLA, pf.EXIT_USO, pf.EXIT_INCOMPLETO) == (0, 1, 2, 3)
