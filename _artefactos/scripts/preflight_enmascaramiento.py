#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""preflight_enmascaramiento.py — Pre-flight anti-enmascaramiento (Fase 3 · A2.2 · R-09/R-13).

En Wazuh **una alerta por evento**: una regla propia (RS3/RS4) que case el mismo
evento que una base (RS1/RS2) **suprime** la base e **infravaloraría RS1**. Esta
herramienta es la operacionalización del §9.8 de
`Soporte/Wazuh/Configuracion/rulesets_diseno.md`: convierte el compromiso escrito
en un **examen con código de salida**.

Dos chequeos, un mismo gate
---------------------------
* **C1 · Cadena `<if_sid>`/`<if_matched_sid>` (estático, offline).** Parsea las
  reglas propias candidatas (`local_rules.xml` = RS3; `external_*.xml` = RS4;
  **ignora comentarios XML**), construye el grafo *regla -> padres* y resuelve el
  RS de cada ancestro **por el fichero de origen** del manifiesto
  `active_ruleset.txt` (rango `MIN_ID..MAX_ID` de cada fichero). Recorre
  **transitivamente** (multinivel: propia -> propia -> base). Si una regla propia
  alcanza un ancestro **RS1/RS2** -> **ENMASCARA (cadena)**.
* **C2 · Hermana (empírico).** Una regla **sin `<if_sid>`** que captura **el
  mismo evento** que una base también la suprime y no es decidible estáticamente.
  Se detecta cotejando dos capturas de `wazuh-logtest -v` sobre la **misma lista
  de eventos**: `--logtest-base` (sin reglas propias) y `--logtest-candidato`
  (con las propias). Si un evento cuya base ganaba RS1/RS2 pasa a ganarlo una
  propia -> **ENMASCARA (hermana)**. Sin capturas, C2 queda **NO EJECUTADO**
  (nunca se pasa en silencio) y el resultado es **INCOMPLETO**.

Declaración (§9.5–§9.6)
-----------------------
Un solapamiento aceptado conscientemente se declara en
`Soporte/Wazuh/Configuracion/solapamientos_declarados.csv`
(`regla_propia,tipo,regla_base,motivo,revision_rs1,revisor,fecha`). El examen
**PASA una pareja `(regla_propia, tipo, regla_base)` solo si existe su fila**;
es la única vía de aceptar un solapamiento y queda trazado y versionado.

Contrato (§5)
-------------
Informe legible (stdout y, con `--out`, a fichero). **Sin reloj** -> misma
entrada = informe **byte a byte** idéntico (R-13).

Códigos de salida::

    0  PASA        se puede desplegar
    1  FALLA       enmascaramiento NO declarado
    2  uso/entrada
    3  INCOMPLETO  C2 no ejecutado o ancestro no resoluble

**Solo `exit 0` permite desplegar.** Sin reglas propias -> PASA trivial, sin
exigir C2.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------
# Constantes (deben coincidir con `preflight_enmascaramiento.md`)
# --------------------------------------------------------------------------
RS_BASE = ("RS1", "RS2")
RS_PROPIAS = ("RS3", "RS4")
RS_TODOS = RS_BASE + RS_PROPIAS
TIPOS = ("cadena", "hermana")

EXIT_PASA = 0
EXIT_FALLA = 1
EXIT_USO = 2
EXIT_INCOMPLETO = 3

DEFAULT_LOCAL_RULES = "Soporte/Wazuh/Reglas/local_rules.xml"
DEFAULT_EXTERNAL_RULES = "Soporte/Wazuh/Reglas/external_*.xml"
DEFAULT_ACTIVE_RULESET = "Soporte/Wazuh/Configuracion/active_ruleset.txt"
DEFAULT_DECLARACIONES = "Soporte/Wazuh/Configuracion/solapamientos_declarados.csv"

DECL_HEADER = [
    "regla_propia",
    "tipo",
    "regla_base",
    "motivo",
    "revision_rs1",
    "revisor",
    "fecha",
]

_RESULTADO_TXT = {
    EXIT_PASA: "PASA",
    EXIT_FALLA: "FALLA",
    EXIT_INCOMPLETO: "INCOMPLETO",
}

_COMENT_XML = re.compile(r"<!--.*?-->", re.DOTALL)
_XML_DECL = re.compile(r"<\?xml.*?\?>", re.DOTALL)
_RULE_RE = re.compile(r"<\s*rule\b")
_ID_SPLIT = re.compile(r"[,\s]+")


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Regla:
    """Regla propia: id, ruleset de origen, fichero e ids padre."""

    __slots__ = ("rid", "rs", "fichero", "padres")

    def __init__(self, rid: str, rs: str, fichero: str, padres):
        self.rid = rid
        self.rs = rs
        self.fichero = fichero
        self.padres = padres

    def __repr__(self):
        return f"Regla({self.rid},{self.rs},{self.padres})"


# --------------------------------------------------------------------------
# Parseo de reglas propias (C1) — ignora comentarios XML
# --------------------------------------------------------------------------
def parse_rules_file(path: str, rs: str):
    """Devuelve la lista de `Regla` del fichero. Ignora comentarios XML.

    Un fichero sin ninguna `<rule>` (p. ej. el esqueleto documentado de RS3 en
    Fase 2) devuelve lista vacía, no un error.
    """
    with open(path, "r", encoding="utf-8") as fh:
        texto = fh.read()
    texto = _XML_DECL.sub("", texto)
    texto = _COMENT_XML.sub("", texto)
    if not _RULE_RE.search(texto):
        return []
    try:
        root = ET.fromstring("<__preflight_root>" + texto + "</__preflight_root>")
    except ET.ParseError as exc:
        raise ValueError(f"{path}: XML inválido tras ignorar comentarios: {exc}")
    reglas = []
    for el in root.iter("rule"):
        rid = (el.get("id") or "").strip()
        if not rid:
            continue
        padres = []
        for tag in ("if_sid", "if_matched_sid"):
            for hijo in el.findall(tag):
                for token in _ID_SPLIT.split((hijo.text or "").strip()):
                    if token:
                        padres.append(token)
        reglas.append(Regla(rid, rs, os.path.normpath(path), padres))
    return reglas


def cargar_reglas_propias(local_rules: str, external_glob: str):
    """Carga RS3 (`local_rules.xml`) y RS4 (`external_*.xml`)."""
    reglas = parse_rules_file(local_rules, "RS3")
    for path in sorted(glob.glob(external_glob)):
        reglas.extend(parse_rules_file(path, "RS4"))
    return reglas


# --------------------------------------------------------------------------
# Manifiesto del ruleset (resolución RS por fichero de origen)
# --------------------------------------------------------------------------
def parse_active_ruleset(path: str):
    """Devuelve [(min, max, rs, fichero)] del bloque DETALLE POR FICHERO."""
    rangos = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if len(parts) < 5 or parts[0] not in RS_TODOS:
                continue
            try:
                mn = int(parts[1])
                mx = int(parts[2])
                int(parts[3])
            except ValueError:
                # línea del bloque RESUMEN (2º campo textual) -> ignorar
                continue
            rangos.append((mn, mx, parts[0], parts[4]))
    return rangos


def resolver_ancestro(rid: str, propias_por_id: dict, rangos):
    """Clasifica un ancestro.

    Devuelve `(rs, fichero_o_nota, ambigua)`. `rs` es `None` si no es resoluble.
    La resolución es **por fichero de origen** (rangos del manifiesto); ante
    rangos solapados se elige el **más específico** (menor span) y si persiste el
    empate se marca `ambigua`.
    """
    regla = propias_por_id.get(rid)
    if regla is not None:
        return regla.rs, regla.fichero, False
    try:
        num = int(rid)
    except ValueError:
        return None, "id_no_numerico", False
    coincidencias = [
        (mx - mn, rs, fichero)
        for (mn, mx, rs, fichero) in rangos
        if mn <= num <= mx
    ]
    if not coincidencias:
        return None, "no_encontrado_en_active_ruleset", False
    rss = sorted({c[1] for c in coincidencias})
    if len(rss) == 1:
        return rss[0], "", False
    coincidencias.sort(key=lambda c: (c[0], c[1], c[2]))
    return coincidencias[0][1], "ambigua_por_rangos:" + ",".join(rss), True


# --------------------------------------------------------------------------
# C1 — cadena <if_sid>/<if_matched_sid> (transitivo)
# --------------------------------------------------------------------------
def c1_analizar(reglas_propias, rangos):
    """Devuelve (hallazgos, irresolubles, ambiguedades, avisos).

    hallazgo = dict(propia, tipo='cadena', base, rs_base, cadena=[...], nota)
    """
    propias_por_id = {}
    colisiones = []
    for r in reglas_propias:
        if r.rid in propias_por_id and propias_por_id[r.rid].rs != r.rs:
            colisiones.append(r.rid)
        propias_por_id.setdefault(r.rid, r)

    hallazgos = []
    irresolubles = []
    ambiguedades = []
    avisos = []
    for rid in sorted(colisiones):
        avisos.append(f"id propio duplicado en RS3 y RS4: {rid}")

    for raiz in sorted(reglas_propias, key=lambda r: (int(r.rid) if r.rid.isdigit() else 0, r.rid)):
        if raiz.rid in colisiones:
            continue
        vistos = set()
        pila = [(raiz.rid, [raiz.rid])]
        while pila:
            actual, camino = pila.pop()
            if actual in vistos:
                continue
            vistos.add(actual)
            regla = propias_por_id.get(actual)
            if regla is None:
                continue
            for padre in regla.padres:
                if padre in propias_por_id:
                    if padre not in colisiones:
                        pila.append((padre, camino + [padre]))
                    continue
                rs, nota, ambigua = resolver_ancestro(padre, propias_por_id, rangos)
                if rs is None:
                    irresolubles.append((raiz.rid, padre, nota))
                elif rs in RS_BASE:
                    hallazgos.append(
                        {
                            "propia": raiz.rid,
                            "tipo": "cadena",
                            "base": padre,
                            "rs_base": rs,
                            "cadena": camino + [padre],
                            "nota": nota,
                        }
                    )
                    if ambigua:
                        ambiguedades.append((raiz.rid, padre, nota))
                else:
                    # ancestro clasificado como propio por el manifiesto pero no
                    # presente en los ficheros analizados -> no se puede seguir
                    irresolubles.append(
                        (raiz.rid, padre, f"propio_no_analizado:{rs}")
                    )

    # deduplicar por (propia, base) conservando el camino más corto
    unicos = {}
    for h in hallazgos:
        clave = (h["propia"], h["base"])
        prev = unicos.get(clave)
        if prev is None or len(h["cadena"]) < len(prev["cadena"]):
            unicos[clave] = h
    hallazgos = [unicos[k] for k in sorted(unicos, key=lambda k: (k[0], k[1]))]

    irresolubles = sorted(set(irresolubles))
    ambiguedades = sorted(set(ambiguedades))
    return hallazgos, irresolubles, ambiguedades, avisos


# --------------------------------------------------------------------------
# C2 — hermana (logtest diferencial)
# --------------------------------------------------------------------------
_PHASE1 = "**Phase 1:"
_PHASE3 = "**Phase 3:"
_ID_LINE = re.compile(r"^\s*id:\s*'([^']*)'")


def parse_logtest(path: str):
    """Extrae la regla ganadora de cada evento de una captura de `wazuh-logtest -v`."""
    ganadoras = []
    en_phase3 = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith(_PHASE1):
                en_phase3 = False
            elif line.startswith(_PHASE3):
                en_phase3 = True
            elif en_phase3:
                m = _ID_LINE.match(line)
                if m:
                    ganadoras.append(m.group(1).strip())
                    en_phase3 = False
    return ganadoras


def c2_analizar(base_path, cand_path, propias_por_id, rangos):
    """Devuelve (hallazgos, irresolubles, base, cand)."""
    base = parse_logtest(base_path)
    cand = parse_logtest(cand_path)
    if len(base) != len(cand):
        raise ValueError(
            f"las capturas no cubren la misma lista de eventos: "
            f"{os.path.basename(base_path)}={len(base)} vs "
            f"{os.path.basename(cand_path)}={len(cand)}"
        )
    hallazgos = []
    irresolubles = []
    for i, (b, c) in enumerate(zip(base, cand), start=1):
        if b == c:
            continue
        rs_b, nota_b, _ = resolver_ancestro(b, propias_por_id, rangos)
        rs_c, nota_c, _ = resolver_ancestro(c, propias_por_id, rangos)
        if rs_b in RS_BASE and rs_c in RS_PROPIAS:
            hallazgos.append(
                {
                    "propia": c,
                    "tipo": "hermana",
                    "base": b,
                    "rs_base": rs_b,
                    "evento": i,
                }
            )
        elif rs_b is None or rs_c is None:
            irresolubles.append(
                (i, b, rs_b or nota_b, c, rs_c or nota_c)
            )
        # base->base u propia->propia: cambio informativo, no enmascaramiento
    # deduplicar por (propia, base) conservando el primer evento
    unicos = {}
    for h in hallazgos:
        unicos.setdefault((h["propia"], h["base"]), h)
    hallazgos = [unicos[k] for k in sorted(unicos, key=lambda k: (k[0], k[1]))]
    return hallazgos, sorted(set(irresolubles)), base, cand


# --------------------------------------------------------------------------
# Declaraciones
# --------------------------------------------------------------------------
def load_declaraciones(path: str):
    """Devuelve (claves, filas, errores, avisos). Clave = (propia, tipo, base).

    Un fichero ausente **no es un error de uso**: se trata como "sin
    declaraciones" (todo hallazgo será NO DECLARADO -> FALLA). Así el pre-flight
    puede ejecutarse con 0 reglas propias antes de que exista el CSV.
    """
    if not path or not os.path.isfile(path):
        return set(), [], [], [f"no existe el fichero de declaraciones: {path} (se trata como vacío)"]
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    campos = list(reader.fieldnames or [])
    faltan = [c for c in DECL_HEADER if c not in campos]
    if faltan:
        return set(), [], [f"{path}: faltan columnas {faltan}; tiene {campos}"], []
    claves = set()
    filas = []
    errores = []
    for idx, row in enumerate(reader, start=2):
        propia = (row.get("regla_propia") or "").strip()
        tipo = (row.get("tipo") or "").strip()
        base = (row.get("regla_base") or "").strip()
        if not (propia or tipo or base):
            continue  # fila vacía
        if tipo not in TIPOS:
            errores.append(f"{path}:{idx}: tipo '{tipo}' no válido (esperado {TIPOS})")
            continue
        if not propia or not base:
            errores.append(f"{path}:{idx}: regla_propia/regla_base vacíos")
            continue
        if not (row.get("revision_rs1") or "").strip():
            errores.append(f"{path}:{idx}: revision_rs1 vacío (§9.6)")
            continue
        claves.add((propia, tipo, base))
        filas.append(
            {
                "regla_propia": propia,
                "tipo": tipo,
                "regla_base": base,
                "motivo": (row.get("motivo") or "").strip(),
                "revision_rs1": (row.get("revision_rs1") or "").strip(),
                "revisor": (row.get("revisor") or "").strip(),
                "fecha": (row.get("fecha") or "").strip(),
            }
        )
    return claves, filas, errores, []


# --------------------------------------------------------------------------
# Informe (determinista, sin reloj)
# --------------------------------------------------------------------------
def _linea_entrada(etiqueta, path, n=None, sha=True, extra=""):
    if not path or not os.path.isfile(path):
        return f"- {etiqueta}: (no aportado)"
    partes = [f"- {etiqueta}: {_disp(path)}"]
    if sha:
        partes.append(f"sha256={sha256_file(path)}")
    if n is not None:
        partes.append(f"n={n}")
    if extra:
        partes.append(extra)
    return " ".join(partes)


def _disp(path: str) -> str:
    """Ruta para mostrar en el informe: normalizada a '/' (determinismo multiplataforma)."""
    return path.replace("\\", "/")


def construir_informe(datos) -> str:
    L = []
    L.append("# Pre-flight anti-enmascaramiento (Fase 3 · A2.2 · R-09/R-13)")
    L.append("")
    L.append("> Herramienta: `_artefactos/scripts/preflight_enmascaramiento.py`.")
    L.append("> **Solo `RESULTADO: PASA` (`exit 0`) permite desplegar reglas propias.**")
    L.append("")

    L.append("## Entradas")
    L.append("")
    L.append(_linea_entrada("reglas propias RS3", datos["local_rules"], n=datos["n_rs3"]))
    if datos["externals"]:
        for p in datos["externals"]:
            L.append(_linea_entrada("reglas propias RS4", p))
    else:
        L.append(f"- reglas propias RS4: (ninguna) glob=`{_disp(datos['external_glob'])}`")
    L.append(_linea_entrada("ruleset base", datos["active_ruleset"], n=len(datos["rangos"]), extra="rangos"))
    L.append(_linea_entrada("declaraciones", datos["declaraciones_path"], n=len(datos["decl_filas"])))
    if datos["c2_ejecutado"]:
        L.append(_linea_entrada("logtest base", datos["logtest_base"], n=len(datos["base_ev"])))
        L.append(_linea_entrada("logtest candidato", datos["logtest_candidato"], n=len(datos["cand_ev"])))
    else:
        L.append(f"- logtest base: {_disp(datos['logtest_base']) if datos['logtest_base'] else '(no aportado)'}")
        L.append(f"- logtest candidato: {_disp(datos['logtest_candidato']) if datos['logtest_candidato'] else '(no aportado)'}")
    L.append("")

    L.append("## C1 · Cadena `<if_sid>`/`<if_matched_sid>` (estático, offline)")
    L.append("")
    L.append(f"Reglas propias analizadas: **{len(datos['reglas_propias'])}**")
    for r in sorted(datos["reglas_propias"], key=lambda x: (int(x.rid) if x.rid.isdigit() else 0, x.rid)):
        padres = ",".join(r.padres) if r.padres else "-"
        L.append(f"  - `{r.rid}` ({r.rs}) padres=[{padres}] fichero={_disp(r.fichero)}")
    if not datos["reglas_propias"]:
        L.append("  - (ninguna)")
    L.append("")
    L.append("Cadenas que alcanzan una base (ENMASCARA):")
    if datos["c1_hallazgos"]:
        for h in datos["c1_hallazgos"]:
            estado = datos["estado_declaracion"](h)
            L.append(
                f"  - {' -> '.join(h['cadena'])}  "
                f"(base {h['base']} = {h['rs_base']})  [{estado}]"
            )
    else:
        L.append("  - (ninguna)")
    L.append("")
    L.append("Ancestros no resolubles:")
    if datos["c1_irresolubles"]:
        for propia, padre, nota in datos["c1_irresolubles"]:
            L.append(f"  - propia `{propia}` -> ancestro `{padre}` ({nota})")
    else:
        L.append("  - (ninguno)")
    L.append("")

    L.append("## C2 · Hermana (empírico, logtest diferencial)")
    L.append("")
    if datos["c2_ejecutado"]:
        L.append("Estado: **EJECUTADO**")
        L.append(f"Eventos comparados: **{len(datos['base_ev'])}**")
        L.append("Hallazgos hermana (base RS1/RS2 -> propia RS3/RS4):")
        if datos["c2_hallazgos"]:
            for h in datos["c2_hallazgos"]:
                estado = datos["estado_declaracion"](h)
                L.append(
                    f"  - evento {h['evento']}: {h['base']} ({h['rs_base']}) -> "
                    f"{h['propia']} ({datos['rs_de'](h['propia'])})  [{estado}]"
                )
        else:
            L.append("  - (ninguna)")
        if datos["c2_irresolubles"]:
            L.append("Eventos con regla no resoluble:")
            for ev, b, nb, c, nc in datos["c2_irresolubles"]:
                L.append(f"  - evento {ev}: base `{b}` ({nb}) / candidata `{c}` ({nc})")
    else:
        L.append("Estado: **NO EJECUTADO**")
        L.append("")
        L.append(
            "AVISO: no se aportaron las capturas `--logtest-base` y "
            "`--logtest-candidato`; **C2 NO EJECUTADO** (nunca se pasa en silencio) "
            "-> resultado **INCOMPLETO**."
        )
    L.append("")

    L.append("## Declaraciones aplicadas")
    L.append("")
    if datos["decl_filas"]:
        for d in datos["decl_filas"]:
            L.append(
                f"  - ({d['regla_propia']},{d['tipo']},{d['regla_base']}) "
                f"revision_rs1={d['revision_rs1']} revisor={d['revisor']} fecha={d['fecha']}"
            )
    else:
        L.append("  - (ninguna)")
    usadas = datos["decl_usadas"]
    no_usadas = [d for d in datos["decl_filas"] if (d["regla_propia"], d["tipo"], d["regla_base"]) not in usadas]
    if no_usadas:
        L.append("")
        L.append("Declaraciones no aplicadas (no hubo hallazgo coincidente):")
        for d in no_usadas:
            L.append(f"  - ({d['regla_propia']},{d['tipo']},{d['regla_base']})")
    if datos["avisos"]:
        L.append("")
        L.append("Avisos:")
        for a in datos["avisos"]:
            L.append(f"  - {a}")
    L.append("")

    L.append(f"RESULTADO: {datos['resultado']}")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    # Salida reproducible y sin colisiones de locale (Windows/cp1252 no soporta
    # caracteres como '∩'): forzamos UTF-8 en stdout/stderr.
    for _flujo in (sys.stdout, sys.stderr):
        try:
            _flujo.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(
        description="Pre-flight anti-enmascaramiento de reglas propias (Fase 3, A2.2)."
    )
    ap.add_argument("--local-rules", default=DEFAULT_LOCAL_RULES, help="RS3 (local_rules.xml)")
    ap.add_argument(
        "--external-rules",
        default=DEFAULT_EXTERNAL_RULES,
        help="glob de RS4 (external_*.xml)",
    )
    ap.add_argument("--active-ruleset", default=DEFAULT_ACTIVE_RULESET, help="manifiesto RS por fichero")
    ap.add_argument("--declaraciones", default=DEFAULT_DECLARACIONES, help="CSV de solapamientos declarados")
    ap.add_argument("--logtest-base", help="captura wazuh-logtest -v SIN reglas propias")
    ap.add_argument("--logtest-candidato", help="captura wazuh-logtest -v CON las reglas propias")
    ap.add_argument("--eventos", help="(opcional) JSONL de eventos para cotejar el nº de eventos")
    ap.add_argument("--out", help="escribe el informe también en este fichero")
    args = ap.parse_args(argv)

    # --- entradas obligatorias ---
    if not os.path.isfile(args.local_rules):
        print(f"ERROR: no existe --local-rules: {args.local_rules}", file=sys.stderr)
        return EXIT_USO
    if not os.path.isfile(args.active_ruleset):
        print(f"ERROR: no existe --active-ruleset: {args.active_ruleset}", file=sys.stderr)
        return EXIT_USO

    try:
        reglas_propias = cargar_reglas_propias(args.local_rules, args.external_rules)
        rangos = parse_active_ruleset(args.active_ruleset)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USO

    externals = sorted(glob.glob(args.external_rules))
    if not rangos:
        print(f"ERROR: {args.active_ruleset} no contiene el bloque de detalle por fichero", file=sys.stderr)
        return EXIT_USO

    claves_decl, decl_filas, decl_errores, decl_avisos = load_declaraciones(args.declaraciones)
    if decl_errores:
        for e in decl_errores:
            print(f"ERROR: {e}", file=sys.stderr)
        return EXIT_USO
    avisos_decl = decl_avisos

    propias_por_id = {}
    for r in reglas_propias:
        propias_por_id.setdefault(r.rid, r)

    # --- C1 ---
    c1_hallazgos, c1_irresolubles, c1_ambiguedades, avisos = c1_analizar(reglas_propias, rangos)

    # --- C2 ---
    c2_ejecutado = bool(args.logtest_base and args.logtest_candidato)
    c2_hallazgos = []
    c2_irresolubles = []
    base_ev, cand_ev = [], []
    if c2_ejecutado:
        for p in (args.logtest_base, args.logtest_candidato):
            if not os.path.isfile(p):
                print(f"ERROR: no existe la captura: {p}", file=sys.stderr)
                return EXIT_USO
        try:
            c2_hallazgos, c2_irresolubles, base_ev, cand_ev = c2_analizar(
                args.logtest_base, args.logtest_candidato, propias_por_id, rangos
            )
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_USO
        if args.eventos:
            if not os.path.isfile(args.eventos):
                print(f"ERROR: no existe --eventos: {args.eventos}", file=sys.stderr)
                return EXIT_USO
            n_ev = sum(1 for ln in open(args.eventos, encoding="utf-8") if ln.strip())
            if n_ev != len(base_ev):
                print(
                    f"ERROR: --eventos tiene {n_ev} eventos y las capturas {len(base_ev)}; "
                    "no cubren la misma lista",
                    file=sys.stderr,
                )
                return EXIT_USO

    # --- declaraciones aplicadas ---
    hallazgos = c1_hallazgos + c2_hallazgos

    def estado_declaracion(h):
        return "DECLARADO" if (h["propia"], h["tipo"], h["base"]) in claves_decl else "NO DECLARADO"

    claves_usadas = {(h["propia"], h["tipo"], h["base"]) for h in hallazgos}
    no_declarados = [h for h in hallazgos if estado_declaracion(h) == "NO DECLARADO"]

    # --- resultado ---
    if not reglas_propias:
        resultado = EXIT_PASA
    elif no_declarados:
        resultado = EXIT_FALLA
    elif c1_irresolubles or c2_irresolubles or not c2_ejecutado:
        resultado = EXIT_INCOMPLETO
    else:
        resultado = EXIT_PASA

    if not reglas_propias and not c2_ejecutado:
        avisos.append("0 reglas propias -> PASA trivial (C2 no se exige)")

    datos = {
        "local_rules": args.local_rules,
        "external_glob": args.external_rules,
        "externals": externals,
        "n_rs3": sum(1 for r in reglas_propias if r.rs == "RS3"),
        "active_ruleset": args.active_ruleset,
        "rangos": rangos,
        "declaraciones_path": args.declaraciones,
        "decl_filas": decl_filas,
        "decl_usadas": claves_usadas,
        "reglas_propias": reglas_propias,
        "c1_hallazgos": c1_hallazgos,
        "c1_irresolubles": c1_irresolubles,
        "c2_ejecutado": c2_ejecutado,
        "c2_hallazgos": c2_hallazgos,
        "c2_irresolubles": c2_irresolubles,
        "logtest_base": args.logtest_base,
        "logtest_candidato": args.logtest_candidato,
        "base_ev": base_ev,
        "cand_ev": cand_ev,
        "avisos": sorted(set(avisos + avisos_decl + [f"rangos solapados en {p}/{b}: {n}" for (p, b, n) in c1_ambiguedades])),
        "estado_declaracion": estado_declaracion,
        "rs_de": lambda rid: (propias_por_id[rid].rs if rid in propias_por_id else "?"),
        "resultado": _RESULTADO_TXT[resultado],
    }

    informe = construir_informe(datos)
    print(informe, end="" if informe.endswith("\n") else "\n")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(informe)
    return resultado


if __name__ == "__main__":
    raise SystemExit(main())
