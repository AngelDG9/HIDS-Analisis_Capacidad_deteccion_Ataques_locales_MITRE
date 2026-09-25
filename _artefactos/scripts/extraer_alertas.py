#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_alertas.py — Agrega alertas de Wazuh por `rule.id` en una ventana UTC.

Fase 2 · tarea 2.10 (T-06 · R-08). Reutilizable en Fase 3 (T-10/T-11).

Lee el fichero de alertas del **manager** (`/var/ossec/logs/alerts/alerts.json`,
una alerta JSON por línea), filtra por `timestamp` en la ventana [--desde,
--hasta] (UTC) y agrega por `rule.id`, produciendo un CSV con:

    rule_id,rule_level,rule_description,groups,count,first_seen,last_seen,rs_origen

`rs_origen` se asigna **por el fichero de reglas que define el `rule.id`**
(criterio de `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §4):

    /var/ossec/ruleset/rules/0365-auditd_rules.xml  -> RS2
    /var/ossec/etc/rules/local_rules.xml            -> RS3
    /var/ossec/etc/rules/external_*.xml             -> RS4
    /var/ossec/ruleset/rules/*.xml  (resto)         -> RS1
    cualquier otro origen                           -> UNKNOWN

El mapa `rule.id -> RS` se construye escaneando los ficheros de reglas activos
(`--ruleset-dir`, `--etc-rules-dir`). Si un `rule.id` no resuelve -> `UNKNOWN`
(nunca se inventa).

Nota: `alerts.json` sella el `timestamp` en **UTC** (p. ej.
`2026-09-23T00:09:10.511+0000`), aunque el reloj de la VM esté en Europe/Madrid.

Uso (en el manager, como root para poder leer /var/ossec):
    sudo python3 extraer_alertas.py \
        --desde 2026-09-23T00:45:00Z --hasta 2026-09-23T04:45:00Z \
        --out Dataset/Legitimo/ruleids_legitimos.csv

Modo de prueba trivial (sin /var/ossec, datos sintéticos embebidos):
    python3 extraer_alertas.py --test

Fase 3 (A2.1) — además del agregado, admite:
    --detail  RUTA.csv    una fila por alerta (columnas §1.3 del plan, ampliadas
                          con `audit_file`/`audit_dir` confirmadas en el paso 0)
    --muestra RUTA.jsonl  líneas JSON CRUDAS representativas de la ventana
                          (hasta --max-por-regla por rule.id; por defecto 5)
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone
from glob import glob

# --------------------------------------------------------------------------
# Constantes de clasificación (rulesets_diseno.md §4)
# --------------------------------------------------------------------------
DEFAULT_ALERTS = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_RULESET_DIR = "/var/ossec/ruleset/rules"
DEFAULT_ETC_RULES_DIR = "/var/ossec/etc/rules"

AUDITD_BASENAME = "0365-auditd_rules.xml"
LOCAL_BASENAME = "local_rules.xml"

RULE_ID_RE = re.compile(r'rule\s+id="(\d+)"')

CSV_HEADER = [
    "rule_id",
    "rule_level",
    "rule_description",
    "groups",
    "count",
    "first_seen",
    "last_seen",
    "rs_origen",
]

# --------------------------------------------------------------------------
# Detalle por alerta (paso 0 · Fase 3 A2.1)
#
# Nombres de campo **confirmados con datos reales** (2026-09-25, manager
# Wazuh 4.14.7, alertas de auditd y de FIM):
#   - auditd:  data.audit.{type, exe, cwd, key, file.name, directory.name}
#   - FIM:     syscheck.path
# `audit_file` y `audit_dir` se añaden a la lista candidata del plan §1.3
# porque el criterio de auto-ruido (§2, cláusula de ruta) necesita la ruta
# del objeto auditado, que en auditd vive en `data.audit.file.name` /
# `data.audit.directory.name`.
# --------------------------------------------------------------------------
DETAIL_HEADER = [
    "timestamp_utc",
    "agent_name",
    "rule_id",
    "rule_level",
    "rule_description",
    "rule_groups",
    "rs_origen",
    "audit_exe",
    "audit_cwd",
    "audit_key",
    "audit_type",
    "audit_file",
    "audit_dir",
    "syscheck_path",
]


# --------------------------------------------------------------------------
# Tiempo
# --------------------------------------------------------------------------
def parse_ts(value: str) -> datetime:
    """Parsea un timestamp ISO8601 (acepta `Z` y `+0000`). Naive => UTC."""
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # `+0000` -> `+00:00` (Python < 3.11 no lo admite sin ':')
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:
        s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Clasificación rule.id -> RS (por fichero de origen)
# --------------------------------------------------------------------------
def classify_file(path: str, ruleset_dir: str, etc_rules_dir: str) -> str:
    d = os.path.normpath(os.path.dirname(path))
    base = os.path.basename(path)
    if d == os.path.normpath(ruleset_dir):
        return "RS2" if base == AUDITD_BASENAME else "RS1"
    if d == os.path.normpath(etc_rules_dir):
        if base == LOCAL_BASENAME:
            return "RS3"
        if base.startswith("external_") and base.endswith(".xml"):
            return "RS4"
        return "UNKNOWN"
    return "UNKNOWN"


def build_id_map(ruleset_dir: str, etc_rules_dir: str) -> tuple[dict[str, str], list[str]]:
    """Devuelve (mapa id->RS, avisos)."""
    id_map: dict[str, str] = {}
    warnings: list[str] = []
    files = sorted(glob(os.path.join(ruleset_dir, "*.xml"))) + sorted(
        glob(os.path.join(etc_rules_dir, "*.xml"))
    )
    for path in files:
        rs = classify_file(path, ruleset_dir, etc_rules_dir)
        if rs == "UNKNOWN":
            warnings.append(f"fichero con origen no clasificable: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            warnings.append(f"no se pudo leer {path}: {exc}")
            continue
        for rid in RULE_ID_RE.findall(text):
            if rid in id_map and id_map[rid] != rs:
                warnings.append(
                    f"rule.id {rid} definido en dos RS ({id_map[rid]} y {rs}): {path}"
                )
            id_map[rid] = rs
    return id_map, warnings


# --------------------------------------------------------------------------
# Agregación
# --------------------------------------------------------------------------
def aggregate(alert_lines, desde: datetime, hasta: datetime, id_map: dict[str, str]):
    """Agrega líneas JSON de alertas. Devuelve (filas, n_total, n_en_ventana)."""
    import json

    agg: dict[str, dict] = {}
    n_total = 0
    n_window = 0
    n_bad = 0
    for line in alert_lines:
        line = line.strip()
        if not line:
            continue
        n_total += 1
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            n_bad += 1
            continue
        ts_raw = alert.get("timestamp")
        if not ts_raw:
            continue
        try:
            ts = parse_ts(ts_raw)
        except ValueError:
            n_bad += 1
            continue
        if not (desde <= ts <= hasta):
            continue
        n_window += 1

        rule = alert.get("rule", {}) or {}
        rid = str(rule.get("id", "")).strip() or "?"
        groups = rule.get("groups", []) or []
        if isinstance(groups, str):
            groups = [groups]

        entry = agg.get(rid)
        if entry is None:
            entry = {
                "level": rule.get("level", ""),
                "description": rule.get("description", ""),
                "groups": groups,
                "count": 0,
                "first": ts,
                "last": ts,
            }
            agg[rid] = entry
        entry["count"] += 1
        if ts < entry["first"]:
            entry["first"] = ts
        if ts > entry["last"]:
            entry["last"] = ts

    rows = []
    for rid, e in agg.items():
        rows.append(
            [
                rid,
                e["level"],
                e["description"],
                "|".join(str(g) for g in e["groups"]),
                e["count"],
                fmt_ts(e["first"]),
                fmt_ts(e["last"]),
                id_map.get(rid, "UNKNOWN"),
            ]
        )
    rows.sort(key=lambda r: (int(r[0]) if r[0].isdigit() else 10**12, r[0]))
    return rows, n_total, n_window, n_bad


def write_csv(rows, out_path: str, header=CSV_HEADER) -> None:
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def write_csv_commented(rows, out_path: str, header, comment=None) -> None:
    """CSV con línea `#` opcional de cabecera y fin de línea LF (determinista)."""
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        if comment:
            fh.write(comment.rstrip("\n") + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def fmt_ts_z(value: str) -> str:
    """Normaliza un timestamp a UTC con sufijo `Z` conservando milisegundos."""
    dt = parse_ts(value)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{dt.microsecond // 1000:03d}Z"
    )


# --------------------------------------------------------------------------
# Detalle por alerta (una fila por alerta)
# --------------------------------------------------------------------------
def extract_detail(alert_lines, desde: datetime, hasta: datetime, id_map: dict[str, str]):
    """Devuelve (filas, n_total, n_en_ventana, n_bad); filas ordenadas de forma estable."""
    import json

    rows = []
    n_total = 0
    n_window = 0
    n_bad = 0
    for line in alert_lines:
        line = line.strip()
        if not line:
            continue
        n_total += 1
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            n_bad += 1
            continue
        ts_raw = alert.get("timestamp")
        if not ts_raw:
            continue
        try:
            ts = parse_ts(ts_raw)
        except ValueError:
            n_bad += 1
            continue
        if not (desde <= ts <= hasta):
            continue
        n_window += 1

        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}
        groups = rule.get("groups", []) or []
        if isinstance(groups, str):
            groups = [groups]
        data = alert.get("data", {}) or {}
        audit = data.get("audit", {}) or {}
        audit_file = (audit.get("file", {}) or {}).get("name", "")
        audit_dir = (audit.get("directory", {}) or {}).get("name", "")
        syscheck = alert.get("syscheck", {}) or {}
        rid = str(rule.get("id", "")).strip() or "?"

        rows.append(
            [
                fmt_ts_z(ts_raw),
                agent.get("name", ""),
                rid,
                rule.get("level", ""),
                rule.get("description", ""),
                "|".join(str(g) for g in groups),
                id_map.get(rid, "UNKNOWN"),
                audit.get("exe", ""),
                audit.get("cwd", ""),
                audit.get("key", ""),
                audit.get("type", ""),
                audit_file,
                audit_dir,
                syscheck.get("path", ""),
            ]
        )

    rows.sort(key=lambda r: (r[0], r[2], r[7], r[9], r[13], r[11], r[12]))
    return rows, n_total, n_window, n_bad


# --------------------------------------------------------------------------
# Muestra cruda (JSONL) — representativa y determinista
# --------------------------------------------------------------------------
def select_muestra(alert_lines, desde: datetime, hasta: datetime, max_por_regla: int):
    """Selecciona hasta `max_por_regla` líneas crudas por `rule.id`, repartidas de
    forma uniforme sobre las ocurrencias en la ventana. Determinista (mismo
    fichero -> misma salida)."""
    import json

    buckets: dict[str, list] = {}
    n_window = 0
    for line in alert_lines:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            alert = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        ts_raw = alert.get("timestamp")
        if not ts_raw:
            continue
        try:
            ts = parse_ts(ts_raw)
        except ValueError:
            continue
        if not (desde <= ts <= hasta):
            continue
        n_window += 1
        rid = str((alert.get("rule", {}) or {}).get("id", "")).strip() or "?"
        buckets.setdefault(rid, []).append((ts, stripped))

    out = []
    for rid in sorted(buckets):
        items = buckets[rid]
        n = len(items)
        if max_por_regla <= 0 or n <= max_por_regla:
            sel = list(range(n))
        elif max_por_regla == 1:
            sel = [0]
        else:
            sel = sorted(
                {int(round(i * (n - 1) / (max_por_regla - 1))) for i in range(max_por_regla)}
            )
        out.extend(items[i] for i in sel)
    out.sort(key=lambda t: (t[0], t[1]))
    return [raw for _, raw in out], n_window, len(buckets)


# --------------------------------------------------------------------------
# Modo de prueba trivial (datos sintéticos embebidos, sin /var/ossec)
# --------------------------------------------------------------------------
def run_test() -> int:
    sample = [
        '{"timestamp":"2026-09-23T00:45:05.100+0000","rule":{"id":"5710","level":5,'
        '"description":"sshd: Attempt to login using a non-existent user",'
        '"groups":["syslog","sshd","authentication_failed"]},"agent":{"name":"victima-linux"}}',
        '{"timestamp":"2026-09-23T00:47:31.200+0000","rule":{"id":"80791","level":3,'
        '"description":"Audit: Deleted: var/run/.","groups":["audit","audit_watch_delete"]},'
        '"agent":{"name":"victima-linux"}}',
        '{"timestamp":"2026-09-23T00:50:00.000+0000","rule":{"id":"999999","level":0,'
        '"description":"regla inexistente (origen no resuelto)","groups":[]},'
        '"agent":{"name":"victima-linux"}}',
        '{"timestamp":"2026-09-22T23:00:00.000+0000","rule":{"id":"5501","level":3,'
        '"description":"PAM: Login session opened.","groups":["pam"]},'
        '"agent":{"name":"victima-linux"}}',
    ]
    id_map = {"5710": "RS1", "80791": "RS2"}  # 999999 -> UNKNOWN; 5501 fuera de ventana
    desde = parse_ts("2026-09-23T00:45:00Z")
    hasta = parse_ts("2026-09-23T01:00:00Z")
    rows, n_total, n_window, n_bad = aggregate(sample, desde, hasta, id_map)
    print("# MODO TEST (datos sintéticos; no lee /var/ossec)")
    print(f"# alertas leídas={n_total} en_ventana={n_window} no_json={n_bad}")
    writer = csv.writer(sys.stdout)
    writer.writerow(CSV_HEADER)
    writer.writerows(rows)
    expected = {"5710": "RS1", "80791": "RS2", "999999": "UNKNOWN"}
    got = {r[0]: r[7] for r in rows}
    ok = got == expected and len(rows) == 3
    print(f"# test: {'OK' if ok else 'FALLO'} (esperado {expected}, obtenido {got})", file=sys.stderr)
    return 0 if ok else 1


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Agrega alertas de Wazuh por rule.id en una ventana UTC."
    )
    ap.add_argument("--alerts", default=DEFAULT_ALERTS, help="ruta a alerts.json")
    ap.add_argument("--desde", help="inicio de ventana (UTC ISO8601)")
    ap.add_argument("--hasta", help="fin de ventana (UTC ISO8601)")
    ap.add_argument(
        "--out",
        default=None,
        help="CSV agregado de salida (por defecto ruleids_legitimos.csv si no se "
        "pide --detail ni --muestra)",
    )
    ap.add_argument(
        "--detail",
        metavar="RUTA.csv",
        help="escribe una fila por alerta (paso 0, fixture del filtro)",
    )
    ap.add_argument(
        "--muestra",
        metavar="RUTA.jsonl",
        help="escribe lineas JSON crudas representativas de la ventana",
    )
    ap.add_argument(
        "--max-por-regla",
        type=int,
        default=5,
        help="maximo de lineas crudas por rule.id en --muestra (por defecto 5)",
    )
    ap.add_argument("--ruleset-dir", default=DEFAULT_RULESET_DIR)
    ap.add_argument("--etc-rules-dir", default=DEFAULT_ETC_RULES_DIR)
    ap.add_argument("--test", action="store_true", help="modo de prueba trivial")
    args = ap.parse_args(argv)

    if args.test:
        return run_test()

    if not args.desde or not args.hasta:
        ap.error("--desde y --hasta son obligatorios (o usa --test)")

    desde = parse_ts(args.desde)
    hasta = parse_ts(args.hasta)
    if hasta < desde:
        ap.error("--hasta es anterior a --desde")

    id_map, warnings = build_id_map(args.ruleset_dir, args.etc_rules_dir)
    for w in warnings:
        print(f"AVISO: {w}", file=sys.stderr)

    if not os.path.isfile(args.alerts):
        print(f"ERROR: no existe el fichero de alertas: {args.alerts}", file=sys.stderr)
        return 2

    want_agg = args.out is not None or (args.detail is None and args.muestra is None)

    if args.detail or args.muestra:
        with open(args.alerts, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

        if args.detail:
            rows, n_total, n_window, n_bad = extract_detail(lines, desde, hasta, id_map)
            comment = (
                f"# {os.path.basename(args.detail)} | detalle por alerta (una fila/alerta) | "
                f"TFG HIDS - Fase 3 A2.1 (paso 0) | alertas={args.alerts} | "
                f"ventana={fmt_ts(desde)}..{fmt_ts(hasta)} | leidas={n_total} "
                f"en_ventana={n_window} no_json={n_bad} | columnas: "
                + ",".join(DETAIL_HEADER)
            )
            write_csv_commented(rows, args.detail, DETAIL_HEADER, comment=comment)
            print(f"detalle: filas={len(rows)} en_ventana={n_window} -> {args.detail}")

        if args.muestra:
            muestras, n_window, n_reglas = select_muestra(
                lines, desde, hasta, args.max_por_regla
            )
            with open(args.muestra, "w", encoding="utf-8", newline="\n") as fh:
                for raw in muestras:
                    fh.write(raw + "\n")
            print(
                f"muestra: lineas={len(muestras)} en_ventana={n_window} "
                f"rule_ids={n_reglas} max_por_regla={args.max_por_regla} -> {args.muestra}"
            )

        if want_agg:
            out = args.out or "ruleids_legitimos.csv"
            rows, n_total, n_window, n_bad = aggregate(lines, desde, hasta, id_map)
            write_csv(rows, out)
            n_unknown = sum(1 for r in rows if r[7] == "UNKNOWN")
            print(
                f"alertas leídas={n_total} en_ventana={n_window} no_json={n_bad} "
                f"rule_ids={len(rows)} unknown={n_unknown} -> {out}"
            )
        return 0

    with open(args.alerts, "r", encoding="utf-8", errors="replace") as fh:
        rows, n_total, n_window, n_bad = aggregate(fh, desde, hasta, id_map)

    out = args.out or "ruleids_legitimos.csv"
    write_csv(rows, out)
    n_unknown = sum(1 for r in rows if r[7] == "UNKNOWN")
    print(
        f"alertas leídas={n_total} en_ventana={n_window} no_json={n_bad} "
        f"rule_ids={len(rows)} unknown={n_unknown} -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
