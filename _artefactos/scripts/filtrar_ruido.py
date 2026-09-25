#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ruido.py — Filtro de ruido y etiquetado auditado de alertas (Fase 3 · A2.1).

Toma la **ventana de alertas de un ataque** (una fila por alerta; salida de
`extraer_alertas.py --detail`) y el **catálogo baseline**
(`Dataset/Legitimo/ruleids_legitimos.csv`) y produce
`ATA<NNN>_iter{N}-Audited.csv`: cada alerta clasificada por capa (`rs_origen`
copiado sin alterar) y etiquetada con una de cuatro categorías.

Categorías y **orden exacto** de decisión (`plan.md` §2; gana el primero):

    1. auto_ruido       si el ORIGEN es el propio Wazuh (por campos, no por rule.id)
    2. deteccion        si casa una SEÑAL ESPERADA de tipo `deteccion`
    3. dudosa           si casa una SEÑAL ESPERADA de tipo `ambigua`
                        (o si no es evaluable ninguna señal: falta el campo)
    4. deteccion        si rule.id NO está en el catálogo (motivo `novel`)
    5. ruido_conocido   si rule.id SÍ está en el catálogo

`auto_ruido` es **categoría propia** y **nunca** cuenta como detección. Si una
señal `deteccion` apuntara a un proceso de Wazuh se emite **CONFLICTO** por
stderr (no se resuelve en silencio).

Señales esperadas (`ATA<NNN>_esperado.csv`, plan §2):
    senal_id,tipo,campo,patron,dato_componente,tecnica,nota
    tipo  ∈ {deteccion, ambigua}
    campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key, syscheck_path}
    patron: literal o glob `*`/`?` (fnmatch)

Sin fichero de señales la herramienta **falla ruidosamente** (exit != 0); solo
el modo explícito `--modo baseline` permite pasar una ventana sin ataque.

El fichero de revisión (`ATA<NNN>_iter{N}-Revision.csv`) contiene las filas
dudosas + columnas `veredicto,nota,revisor,fecha` para el humano. Al re-ejecutar
con `--revision <fichero>` los veredictos se pliegan (`revision=resuelta`).

Determinismo (R-13): la salida no contiene reloj y depende solo de las entradas;
misma entrada -> salida **byte a byte** idéntica.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import hashlib
import os
import sys

# --------------------------------------------------------------------------
# Constantes (deben coincidir con `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`)
# --------------------------------------------------------------------------
CATEGORIAS = ("deteccion", "ruido_conocido", "auto_ruido", "dudosa")

# §3 — procesos del propio Wazuh (se comparan por nombre base de `audit.exe`)
WAZUH_PROCESOS = {
    "wazuh-agentd",
    "wazuh-syscheckd",
    "wazuh-logcollector",
    "wazuh-modulesd",
    "wazuh-execd",
    "wazuh-db",
    "wazuh-analysisd",
}
WAZUH_CWD = "/var/ossec"
WAZUH_RUN_GLOB = "/var/ossec/var/run/*"

SIGNAL_TIPOS = ("deteccion", "ambigua")
SIGNAL_CAMPOS = (
    "rule_id",
    "rule_group",
    "audit_exe",
    "audit_cwd",
    "audit_key",
    "syscheck_path",
)
SIGNAL_HEADER = [
    "senal_id",
    "tipo",
    "campo",
    "patron",
    "dato_componente",
    "tecnica",
    "nota",
]

OUT_HEADER = [
    "ata_id",
    "iter",
    "timestamp_utc",
    "agent_name",
    "rule_id",
    "rule_level",
    "rule_groups",
    "rs_origen",
    "rule_description",
    "categoria",
    "motivo",
    "atribucion",
    "revision",
    "veredicto_humano",
    "evidencia",
]
REV_EXTRA = ["veredicto", "nota", "revisor", "fecha"]

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_SIGNALS = 3

DEFAULT_CATALOGO = "Dataset/Legitimo/ruleids_legitimos.csv"
DEFAULT_AUDITED_DIR = "Dataset/Ataques/Resultados/Wazuh/Auditado"
DEFAULT_COMANDOS_DIR = "Dataset/Ataques/Comandos"


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv_rows(path: str, required: list[str] | None = None):
    """Lee un CSV del repo ignorando líneas de comentario `#`.

    Devuelve (fieldnames, filas) donde filas es lista de dict.
    """
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    fieldnames = list(reader.fieldnames or [])
    rows = list(reader)
    if required:
        missing = [c for c in required if c not in fieldnames]
        if missing:
            raise ValueError(f"{path}: faltan columnas {missing}; tiene {fieldnames}")
    return fieldnames, rows


def glob_match(value: str, pattern: str) -> bool:
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch.fnmatchcase(value, pattern)
    return value == pattern


def basename(value: str) -> str:
    v = (value or "").strip().strip('"')
    return os.path.basename(v) if v else ""


# --------------------------------------------------------------------------
# Carga de entradas
# --------------------------------------------------------------------------
def load_catalogo(path: str) -> set[str]:
    _, rows = read_csv_rows(path, required=["rule_id"])
    return {str(r["rule_id"]).strip() for r in rows if str(r.get("rule_id", "")).strip()}


def load_signals(path: str):
    _, rows = read_csv_rows(path, required=SIGNAL_HEADER)
    signals = []
    errores = []
    for i, r in enumerate(rows, start=2):
        senal_id = (r.get("senal_id") or "").strip()
        tipo = (r.get("tipo") or "").strip()
        campo = (r.get("campo") or "").strip()
        patron = r.get("patron") or ""
        if not senal_id:
            errores.append(f"línea {i}: senal_id vacío")
            continue
        if tipo not in SIGNAL_TIPOS:
            errores.append(f"línea {i}: tipo '{tipo}' no válido (esperado {SIGNAL_TIPOS})")
            continue
        if campo not in SIGNAL_CAMPOS:
            errores.append(f"línea {i}: campo '{campo}' no válido (esperado {SIGNAL_CAMPOS})")
            continue
        signals.append(
            {
                "senal_id": senal_id,
                "tipo": tipo,
                "campo": campo,
                "patron": patron,
                "dato_componente": (r.get("dato_componente") or "").strip(),
                "tecnica": (r.get("tecnica") or "").strip(),
            }
        )
    if errores:
        raise ValueError("señales inválidas en " + path + ": " + "; ".join(errores))
    return signals


# --------------------------------------------------------------------------
# Auto-ruido (§3) — por campos, nunca por rule.id
# --------------------------------------------------------------------------
def _ruta_abs(value: str, cwd: str) -> str:
    v = (value or "").strip().strip('"')
    if not v:
        return ""
    if v.startswith("/"):
        return v
    if cwd:
        return os.path.normpath(cwd.rstrip("/") + "/" + v.lstrip("/"))
    return v


def detectar_auto_ruido(row: dict):
    """Devuelve (evidencia, proceso) si la alerta es del propio Wazuh, o None."""
    exe = (row.get("audit_exe") or "").strip()
    base = basename(exe)
    if base in WAZUH_PROCESOS:
        return f"audit_exe={exe}", base

    cwd = (row.get("audit_cwd") or "").strip()
    if cwd == WAZUH_CWD:
        proceso = base or f"cwd={WAZUH_CWD}"
        return f"audit_cwd={cwd}", proceso

    for field in ("audit_file", "audit_dir", "syscheck_path"):
        raw = row.get(field) or ""
        p = _ruta_abs(raw, cwd)
        if p and glob_match(p, WAZUH_RUN_GLOB):
            return f"{field}={raw}", (base or "ruta")
    return None


# --------------------------------------------------------------------------
# Señales esperadas
# --------------------------------------------------------------------------
def _valor_campo(row: dict, campo: str):
    if campo == "rule_group":
        grupos = [g for g in (row.get("rule_groups") or "").split("|") if g]
        return grupos or None
    val = (row.get(campo) or "").strip()
    return val or None


def _match_campo(row: dict, campo: str, patron: str):
    """(evaluable, casado, valor). evaluable=False si el campo está ausente."""
    val = _valor_campo(row, campo)
    if val is None:
        return False, False, ""
    if campo == "rule_group":
        for g in val:
            if glob_match(g, patron):
                return True, True, g
        return True, False, "|".join(val)
    if campo == "audit_exe":
        if glob_match(val, patron):
            return True, True, val
        if glob_match(basename(val), patron):
            return True, True, val
        return True, False, val
    return True, glob_match(val, patron), val


def evaluar_senales(row: dict, signals):
    """Devuelve dict con match_deteccion, match_ambigua, alguna_evaluable."""
    match_det = None
    match_amb = None
    alguna_evaluable = False
    for s in signals:
        evaluable, casa, valor = _match_campo(row, s["campo"], s["patron"])
        if not evaluable:
            continue
        alguna_evaluable = True
        if not casa:
            continue
        if s["tipo"] == "deteccion" and match_det is None:
            match_det = (s, valor)
        elif s["tipo"] == "ambigua" and match_amb is None:
            match_amb = (s, valor)
    return {
        "match_deteccion": match_det,
        "match_ambigua": match_amb,
        "alguna_evaluable": alguna_evaluable,
    }


def _atribucion(sig: dict) -> str:
    tec = sig.get("tecnica", "")
    dc = sig.get("dato_componente", "")
    return "|".join(p for p in (tec, dc) if p)


# --------------------------------------------------------------------------
# Clasificación (§2)
# --------------------------------------------------------------------------
def clasificar(row: dict, catalogo: set[str], signals, modo_baseline: bool, conflictos: list):
    rid = str(row.get("rule_id") or "").strip()
    out = {
        "categoria": "",
        "motivo": "",
        "atribucion": "",
        "revision": "",
        "veredicto_humano": "",
        "evidencia": "",
    }

    auto = detectar_auto_ruido(row)
    # Conflicto: señal deteccion que apunta a un proceso de Wazuh (se evalúa igual)
    if not modo_baseline and signals:
        ev = evaluar_senales(row, signals)
        if auto and ev["match_deteccion"] is not None:
            s, _ = ev["match_deteccion"]
            conflictos.append(
                f"rule_id={rid} timestamp={row.get('timestamp_utc')}: la señal "
                f"{s['senal_id']} (deteccion) apunta a un proceso de Wazuh "
                f"({auto[1]}); prevalece auto_ruido (revisar la señal)"
            )

    # 1. auto_ruido
    if auto:
        out["categoria"] = "auto_ruido"
        out["motivo"] = f"auto_ruido:{auto[1]}"
        out["evidencia"] = auto[0]
        return out

    # 2-3. señales esperadas (solo en modo ataque)
    if not modo_baseline and signals:
        ev = evaluar_senales(row, signals)
        if ev["match_deteccion"] is not None:
            s, valor = ev["match_deteccion"]
            out["categoria"] = "deteccion"
            out["motivo"] = f"senal:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        if ev["match_ambigua"] is not None:
            s, valor = ev["match_ambigua"]
            out["categoria"] = "dudosa"
            out["motivo"] = f"ambigua:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["revision"] = "pendiente"
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        if not ev["alguna_evaluable"]:
            out["categoria"] = "dudosa"
            out["motivo"] = "sin_campos"
            out["revision"] = "pendiente"
            out["evidencia"] = ""
            return out

    # 4-5. catálogo
    if rid not in catalogo:
        # En modo baseline la ventana se declara sin ataque: una novedad no puede
        # contar como detección y se absorbe como ruido conocido (plan §8-a).
        if not modo_baseline:
            out["categoria"] = "deteccion"
            out["motivo"] = "novel"
            out["evidencia"] = f"rule_id={rid}"
            return out
    out["categoria"] = "ruido_conocido"
    out["motivo"] = "baseline"
    out["evidencia"] = f"rule_id={rid}"
    return out


def _clave_revision(row: dict) -> tuple:
    return (
        (row.get("timestamp_utc") or "").strip(),
        str(row.get("rule_id") or "").strip(),
        (row.get("agent_name") or "").strip(),
        (row.get("evidencia") or "").strip(),
    )


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def write_csv(path: str, header: list[str], rows, comment: str | None = None) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        if comment:
            fh.write(comment.rstrip("\n") + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        for r in rows:
            writer.writerow([r.get(c, "") for c in header])


def construir_comentario(nombre, ata, it, modo, entradas, conteos) -> str:
    parts = [
        f"{nombre} | TFG HIDS - Fase 3 A2.1 (R-09/R-13) | ata={ata} iter={it}",
        f"modo={'baseline' if modo == 'baseline' else 'ataque'}",
    ]
    for etiqueta, path, sha in entradas:
        parts.append(f"{etiqueta}={path} sha256={sha}")
    parts.append(
        "conteos: filas={filas} deteccion={deteccion} auto_ruido={auto_ruido} "
        "ruido_conocido={ruido_conocido} dudosa={dudosa}".format(**conteos)
    )
    parts.append("columnas: " + ",".join(OUT_HEADER))
    return "# " + " | ".join(parts)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def _descubrir_esperado(ata_id: str) -> str | None:
    patron = os.path.join(DEFAULT_COMANDOS_DIR, "*", f"{ata_id}_esperado.csv")
    hits = sorted(glob.glob(patron))
    return hits[0] if len(hits) == 1 else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Filtro de ruido y etiquetado auditado de alertas (Fase 3, A2.1)."
    )
    ap.add_argument("--alerta", required=True, help="CSV de detalle (una fila por alerta)")
    ap.add_argument("--ata", required=True, help="identificador del ataque (ATA001...)")
    ap.add_argument("--iter", type=int, default=1, help="iteración (1 o 2)")
    ap.add_argument("--catalogo", default=DEFAULT_CATALOGO, help="catálogo baseline")
    ap.add_argument("--esperado", help="ATA<NNN>_esperado.csv (obligatorio salvo --modo baseline)")
    ap.add_argument(
        "--modo",
        choices=("ataque", "baseline"),
        default="ataque",
        help="'baseline' = ventana sin ataque (no exige señales)",
    )
    ap.add_argument("--revision", help="CSV de revisión previo a plegar")
    ap.add_argument("--out", help="CSV audited de salida")
    ap.add_argument("--rev-out", help="CSV de revisión de salida")
    args = ap.parse_args(argv)

    # --- entradas ---
    if not os.path.isfile(args.alerta):
        print(f"ERROR: no existe el fichero de alertas: {args.alerta}", file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isfile(args.catalogo):
        print(f"ERROR: no existe el catálogo: {args.catalogo}", file=sys.stderr)
        return EXIT_USAGE

    modo_baseline = args.modo == "baseline"
    esperado = args.esperado
    if not modo_baseline:
        if not esperado:
            esperado = _descubrir_esperado(args.ata)
        if not esperado:
            print(
                f"ERROR: falta el fichero de señales esperadas para {args.ata} "
                f"(esperado {DEFAULT_COMANDOS_DIR}/*/{args.ata}_esperado.csv). "
                "Sin señales, el filtro no puede atribuir ataques; usa --esperado "
                "o --modo baseline si la ventana no contiene ataque.",
                file=sys.stderr,
            )
            return EXIT_NO_SIGNALS
        if not os.path.isfile(esperado):
            print(f"ERROR: no existe el fichero de señales: {esperado}", file=sys.stderr)
            return EXIT_NO_SIGNALS

    try:
        _, alertas = read_csv_rows(args.alerta)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        catalogo = load_catalogo(args.catalogo)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    signals = []
    if not modo_baseline:
        try:
            signals = load_signals(esperado)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not signals:
            print(f"ERROR: {esperado} no contiene señales", file=sys.stderr)
            return EXIT_NO_SIGNALS

    # --- clasificación ---
    conflictos: list[str] = []
    filas = []
    for r in alertas:
        c = clasificar(r, catalogo, signals, modo_baseline, conflictos)
        fila = {
            "ata_id": args.ata,
            "iter": args.iter,
            "timestamp_utc": r.get("timestamp_utc", ""),
            "agent_name": r.get("agent_name", ""),
            "rule_id": r.get("rule_id", ""),
            "rule_level": r.get("rule_level", ""),
            "rule_groups": r.get("rule_groups", ""),
            "rs_origen": r.get("rs_origen", ""),
            "rule_description": r.get("rule_description", ""),
            **c,
        }
        filas.append(fila)

    filas.sort(key=lambda x: (x["timestamp_utc"], x["rule_id"], x["evidencia"]))

    # --- plegar revisión humana ---
    if args.revision:
        if not os.path.isfile(args.revision):
            print(f"ERROR: no existe el fichero de revisión: {args.revision}", file=sys.stderr)
            return EXIT_USAGE
        _, rev_rows = read_csv_rows(args.revision)
        rev_map = {}
        for rr in rev_rows:
            clave = (
                (rr.get("timestamp_utc") or "").strip(),
                str(rr.get("rule_id") or "").strip(),
                (rr.get("agent_name") or "").strip(),
                (rr.get("evidencia") or "").strip(),
            )
            rev_map[clave] = rr
        usadas = set()
        for fila in filas:
            if fila["categoria"] != "dudosa":
                continue
            clave = _clave_revision(fila)
            rr = rev_map.get(clave)
            if rr is None:
                continue
            veredicto = (rr.get("veredicto") or "").strip().lower()
            if veredicto not in ("deteccion", "ruido"):
                continue
            usadas.add(clave)
            fila["categoria"] = "deteccion" if veredicto == "deteccion" else "ruido_conocido"
            fila["revision"] = "resuelta"
            fila["veredicto_humano"] = veredicto
            extras = []
            if (rr.get("revisor") or "").strip():
                extras.append(f"revisor={rr['revisor'].strip()}")
            if (rr.get("fecha") or "").strip():
                extras.append(f"fecha={rr['fecha'].strip()}")
            if (rr.get("nota") or "").strip():
                extras.append(f"nota={rr['nota'].strip()}")
            if extras:
                sep = ";" if fila["evidencia"] else ""
                fila["evidencia"] = fila["evidencia"] + sep + ";".join(extras)
        for clave, rr in rev_map.items():
            if clave in usadas:
                continue
            if (rr.get("veredicto") or "").strip():
                print(
                    f"AVISO: revisión con clave no encontrada en la ventana (ignorada): {clave}",
                    file=sys.stderr,
                )

    # --- salidas ---
    out = args.out or os.path.join(
        DEFAULT_AUDITED_DIR, f"{args.ata}_iter{args.iter}-Audited.csv"
    )
    rev_out = args.rev_out or os.path.join(
        DEFAULT_AUDITED_DIR, f"{args.ata}_iter{args.iter}-Revision.csv"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)

    conteos = {
        "filas": len(filas),
        "deteccion": sum(1 for f in filas if f["categoria"] == "deteccion"),
        "auto_ruido": sum(1 for f in filas if f["categoria"] == "auto_ruido"),
        "ruido_conocido": sum(1 for f in filas if f["categoria"] == "ruido_conocido"),
        "dudosa": sum(1 for f in filas if f["categoria"] == "dudosa"),
    }
    entradas = [("alerta", args.alerta, sha256_file(args.alerta))]
    entradas.append(("catalogo", args.catalogo, sha256_file(args.catalogo)))
    if not modo_baseline:
        entradas.append(("esperado", esperado, sha256_file(esperado)))
    if args.revision:
        entradas.append(("revision", args.revision, sha256_file(args.revision)))

    comment = construir_comentario(
        os.path.basename(out), args.ata, args.iter, args.modo, entradas, conteos
    )
    write_csv(out, OUT_HEADER, filas, comment=comment)

    dudosas = [f for f in filas if f["categoria"] == "dudosa"]
    if dudosas:
        rev_rows = [dict(f, veredicto="", nota="", revisor="", fecha="") for f in dudosas]
        rev_comment = construir_comentario(
            os.path.basename(rev_out), args.ata, args.iter, args.modo, entradas, conteos
        )
        write_csv(rev_out, OUT_HEADER + REV_EXTRA, rev_rows, comment=rev_comment)

    for c in conflictos:
        print(f"CONFLICTO: {c}", file=sys.stderr)

    print(
        f"filas={conteos['filas']} deteccion={conteos['deteccion']} "
        f"auto_ruido={conteos['auto_ruido']} "
        f"ruido_conocido={conteos['ruido_conocido']} dudosa={conteos['dudosa']} -> {out}"
    )
    if dudosas:
        print(f"revisión pendiente: {len(dudosas)} filas -> {rev_out}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
