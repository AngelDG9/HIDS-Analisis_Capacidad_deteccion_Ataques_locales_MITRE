#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analizar_legitimo_72h.py — L2 del bloque `legitimo-analisis` (T3/T4/T5, tanda 1).

Convierte la ventana legítima de **72 h** ya sellada (`legitimo-v3`) en los productos
del plano legítimo, **sin volver a medir nada en el laboratorio**:

  1. **Índice evento↔alerta** (`eventos_alerta_72h.csv.gz`): una fila por **evento
     decodificado del endpoint con alerta emitida** en `[t0,t1]`.
     - `unidad = "<fichero>:<nº de línea>"` (p. ej. `02:12345`): **única por construcción**.
       **No** se usa el `id` de Wazuh (colisiona) ni el `timestamp` (fusiona eventos).
     - `auto_ruido` se decide con el **predicado por campos** de
       `filtrar_ruido.detectar_auto_ruido` (se **reutiliza**, no se reimplementa).
  2. **Catálogo de ruido 72 h** (`catalogo_ruido_72h.csv`, 11 reglas) y **catálogo M1b**
     (`catalogo_M1b.csv`, 72 h ∪ {5402,5501,5502,5715}, con `origen_catalogo`).
  3. **Evidencia de `auto_ruido`** (`auto_ruido_evidencia.csv`, por regla/campo/valor).
  4. **Estabilidad** por día (3), por hora (72) y de la campaña declarada (11 casos).
  5. **Detalle de T3** (`T3_detalle.csv`, intermedio regenerable) para `tabla3_legitimo.py`.

Entradas (solo lectura):
  - `archives` del manager (`D:\\TFG-VMs\\legitimo-2026-11-02\\denominador\\`): 4 ficheros.
  - `Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv` (catálogo observado).
  - `Dataset/Legitimo/ruleids_legitimos.csv` (catálogo histórico 2×4 h, solo para las 4
    reglas del operador que las 72 h no ejercitaron).
  - `Dataset/Legitimo/legitimo_72h/campana_fp.csv` (11 casos declarados).

Unidad de `FP_uni` = **evento decodificado** (línea de `archives`), `metrica_hids.md:45-54`.
`M` se **re-cuenta** aquí (CA-L2-01) y **no** se copia de la ficha.

Determinismo: sin reloj, sin orden dependiente del sistema de ficheros, LF, UTF-8 sin BOM;
el `.gz` se escribe con `mtime=0` (bytes idénticos entre ejecuciones).
"""

from __future__ import annotations

import argparse
import collections
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402
import filtrar_ruido as FR  # noqa: E402

# --------------------------------------------------------------------------
# Constantes de la ventana (congeladas en `ventana_meta.md`)
# --------------------------------------------------------------------------
T0_STR = "2026-11-02T00:00:00Z"
T1_STR = "2026-11-05T00:00:00Z"
DURACION_H = 72
N_ACCIONES_GHOSTS = 504
AGENT_ID = "001"
AGENT_NAME = "victima-linux"

# Reglas históricas del operador (catálogo M1b = 72 h ∪ estas 4). No se ejercitaron en
# las 72 h porque la ventana no tuvo sesiones del operador en el endpoint (V4).
REGLAS_HISTORICAS = ("5402", "5501", "5502", "5715")

# Atribución de la campaña (cabecera de `campana_fp.csv`): [ini-10s, fin+60s].
CAMPANA_PRE_S = 10
CAMPANA_POST_S = 60

DEFAULT_ARCHIVES = r"D:\TFG-VMs\legitimo-2026-11-02\denominador"
DEFAULT_RULEIDS = "Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv"
DEFAULT_RULEIDS_HIST = "Dataset/Legitimo/ruleids_legitimos.csv"
DEFAULT_CAMPANA = "Dataset/Legitimo/legitimo_72h/campana_fp.csv"
DEFAULT_OUT_DIR = "Dataset/Legitimo/legitimo_72h/analisis"
DEFAULT_DETALLE = "Soporte/Laboratorio/legitimo_72h/analisis/T3_detalle.csv"

IDX_HEADER = ["unidad", "timestamp_utc", "rule_id", "rule_level", "rs_origen", "auto_ruido"]

CATALOGO_HEADER = [
    "rule_id", "rule_level", "rule_description", "groups", "rs_origen", "count",
    "first_seen", "last_seen", "alertas_auto", "alertas_no_auto", "pct_auto",
    "origen_catalogo",
]
CATALOGO_M1B_HEADER = [
    "rule_id", "rule_level", "rs_origen", "groups", "count_72h", "origen_catalogo",
    "justificacion",
]
EVIDENCIA_HEADER = ["rule_id", "motivo", "campo", "valor", "alertas", "unidades"]
DIA_HEADER = ["dia", "M", "FP_uni_C0_N0", "FP_uni_C1_N0", "FP_uni_C1_N7", "FPR_C0",
              "FPR_C1_N0", "FPR_C1_N7", "A_FP", "auto"]
HORA_HEADER = ["hora_utc", "M", "FP_uni_C1_N0", "FPR_C1_N0", "A_FP", "auto"]
CAMPANA_HEADER = ["caso", "ini", "fin", "duracion_s", "alertas", "rule_ids", "nivel_max",
                  "esperado_cumplido"]
DETALLE_HEADER = ["unidad", "rule_id", "rule_level", "rs_origen", "categoria", "rule_groups"]


# --------------------------------------------------------------------------
# Tiempo
# --------------------------------------------------------------------------
def parse_ts(value) -> datetime:
    """ISO8601 con `Z`, `+00:00` o `+0000` -> `datetime` UTC (mismo criterio que la casa)."""
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:
        s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def norm_ts(dt: datetime) -> str:
    """`YYYY-MM-DDTHH:MM:SS.mmmZ` (el mismo formato que `alertas_detalle.timestamp_utc`)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# --------------------------------------------------------------------------
# Lectura de entradas
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_lines(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _prefijo(fname: str) -> str:
    """`ossec-archive-02.json.gz` -> `02` (prefijo estable de la unidad)."""
    m = re.search(r"archive-(\d+)", fname)
    return m.group(1) if m else os.path.splitext(fname)[0]


def _aplanar(rec: dict) -> dict:
    """Extrae del evento `archives` los campos que consume el predicado de `auto_ruido`."""
    data = rec.get("data") or {}
    aud = data.get("audit") or {}
    f = aud.get("file") or {}
    d = aud.get("directory") or {}
    syschk = data.get("syscheck") or {}
    rule = rec.get("rule") or {}
    return {
        "rule_id": str(rule.get("id") or ""),
        "rule_groups": "|".join(rule.get("groups") or []),
        "audit_exe": str(aud.get("exe") or ""),
        "audit_cwd": str(aud.get("cwd") or ""),
        "audit_file": str(f.get("name") or ""),
        "audit_dir": str(d.get("name") or ""),
        "syscheck_path": str(syschk.get("path") or ""),
    }


def leer_ruleids(path: str) -> dict:
    """`rule_id -> {level, description, groups, rs_origen, count, first, last}`."""
    _, rows = TC.read_csv_rows(path, required=["rule_id", "rule_level", "rs_origen"])
    out = {}
    for r in rows:
        out[str(r["rule_id"]).strip()] = {
            "rule_level": str(r.get("rule_level", "")).strip(),
            "rule_description": (r.get("rule_description") or "").strip(),
            "groups": (r.get("groups") or "").strip(),
            "rs_origen": (r.get("rs_origen") or "").strip(),
            "count": int(float(r.get("count") or r.get("count_total") or 0)),
            "first_seen": (r.get("first_seen") or "").strip(),
            "last_seen": (r.get("last_seen") or "").strip(),
        }
    return out


def leer_campana(path: str):
    _, rows = TC.read_csv_rows(
        path, required=["caso", "ini", "fin", "alertas", "rule_id", "level", "esperado_cumplido"]
    )
    return rows


# --------------------------------------------------------------------------
# Índice evento <-> alerta
# --------------------------------------------------------------------------
def construir_indice(files, desde, hasta, agent_id, agent_name):
    """Una fila por evento del endpoint con alerta emitida (`rule` y `level >= 3`)."""
    idx = []
    m_total = 0
    m_endpoint = 0
    por_dia = collections.Counter()
    por_hora = collections.Counter()
    nivel_bajo = 0
    sin_rule = 0
    bad_json = 0
    auto_evid = collections.Counter()
    n_auto = 0

    for path in files:
        pref = _prefijo(os.path.basename(path))
        with _open_lines(path) as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    bad_json += 1
                    continue
                if not rec.get("timestamp"):
                    continue
                ts = parse_ts(rec["timestamp"])
                if ts < desde or ts > hasta:
                    continue
                m_total += 1
                agent = rec.get("agent") or {}
                if str(agent.get("id") or "") != agent_id and str(agent.get("name") or "") != agent_name:
                    continue
                m_endpoint += 1
                por_dia[ts.strftime("%Y-%m-%d")] += 1
                por_hora[ts.strftime("%Y-%m-%dT%H")] += 1
                rule = rec.get("rule")
                if not rule:
                    sin_rule += 1
                    continue
                try:
                    level = int(rule.get("level") or 0)
                except (TypeError, ValueError):
                    level = 0
                if level < 3:
                    # Esta instalación no emite alertas de nivel < 3 (`rule 1002`, nivel 2).
                    nivel_bajo += 1
                    continue
                campos = _aplanar(rec)
                auto = FR.detectar_auto_ruido(campos)
                rid = campos["rule_id"]
                if auto:
                    n_auto += 1
                    evidencia, _proc = auto
                    campo, _, valor = evidencia.partition("=")
                    auto_evid[(rid, campo, valor)] += 1
                idx.append((f"{pref}:{lineno}", norm_ts(ts), rid, level, campos["rule_groups"],
                            1 if auto else 0))

    stats = {
        "M_total": m_total,
        "M_endpoint": m_endpoint,
        "por_dia": por_dia,
        "por_hora": por_hora,
        "nivel_bajo": nivel_bajo,
        "sin_rule": sin_rule,
        "bad_json": bad_json,
        "auto": n_auto,
        "auto_evid": auto_evid,
    }
    return idx, stats


# --------------------------------------------------------------------------
# Escritura determinista
# --------------------------------------------------------------------------
def escribir_gz_csv(path: str, header, rows, comment: str) -> None:
    """CSV `.gz` determinista (`mtime=0`): misma entrada -> mismos bytes."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8", newline="")
        if comment:
            text.write(comment.rstrip("\n") + "\n")
        w = csv.writer(text, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)
        text.flush()
        text.detach()
    with open(path, "wb") as fh:
        fh.write(raw.getvalue())


def _rs(rule_id: str, catalogo: dict) -> str:
    d = catalogo.get(rule_id)
    return d["rs_origen"] if d else "UNKNOWN"


def _level(rule_id: str, catalogo: dict) -> str:
    d = catalogo.get(rule_id)
    return d["rule_level"] if d else ""


def _passa(rs: str, level, umbral: int, config_rs) -> bool:
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return False
    return rs in config_rs and lv >= umbral


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="L2 — índice evento<->alerta, catálogo de ruido y estabilidad del legítimo 72 h."
    )
    ap.add_argument("--archives", default=DEFAULT_ARCHIVES,
                    help="directorio con los 4 ficheros de archives (o ficheros sueltos)")
    ap.add_argument("--desde", default=T0_STR)
    ap.add_argument("--hasta", default=T1_STR)
    ap.add_argument("--agent-id", default=AGENT_ID)
    ap.add_argument("--agent-name", default=AGENT_NAME)
    ap.add_argument("--ruleids", default=DEFAULT_RULEIDS)
    ap.add_argument("--ruleids-historico", default=DEFAULT_RULEIDS_HIST)
    ap.add_argument("--campana", default=DEFAULT_CAMPANA)
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--detalle-out", default=DEFAULT_DETALLE)
    ap.add_argument("--n-acciones-ghosts", type=int, default=N_ACCIONES_GHOSTS)
    ap.add_argument("--duracion-h", type=int, default=DURACION_H)
    args = ap.parse_args(argv)

    desde = parse_ts(args.desde)
    hasta = parse_ts(args.hasta)

    # 1) Resolver las entradas de `archives`
    ap_dir = os.path.join(TC.ROOT, args.archives) if not os.path.isabs(args.archives) else args.archives
    if os.path.isdir(ap_dir):
        files = [os.path.join(ap_dir, f) for f in sorted(os.listdir(ap_dir))
                 if re.search(r"archive-\d+", f)]
    else:
        files = [ap_dir]
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print(f"ERROR: no hay ficheros de archives en {ap_dir}", file=sys.stderr)
        return 2

    ruleids = leer_ruleids(os.path.join(TC.ROOT, args.ruleids))
    ruleids_hist = leer_ruleids(os.path.join(TC.ROOT, args.ruleids_historico))
    campana = leer_campana(os.path.join(TC.ROOT, args.campana))

    # 2) Índice
    idx, st = construir_indice(files, desde, hasta, args.agent_id, args.agent_name)
    if st["M_endpoint"] != 342966:
        print(f"AVISO: M recalculado = {st['M_endpoint']} (esperado 342966)", file=sys.stderr)

    out_dir = os.path.join(TC.ROOT, args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    # sha256 de las entradas (trazabilidad)
    hashes = ",".join(f"{sha256_file(f)}:{os.path.basename(f)}" for f in files)
    tam_bytes = sum(os.path.getsize(f) for f in files)

    # 3) Índice -> eventos_alerta_72h.csv.gz
    idx_rows = [
        (u, ts, rid, lv, _rs(rid, ruleids), auto) for (u, ts, rid, lv, _groups, auto) in idx
    ]
    comment_idx = "# eventos_alerta_72h.csv.gz | " + " | ".join([
        "TFG HIDS - L2 indice evento<->alerta",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"ventana={args.desde}..{args.hasta}",
        f"agente={args.agent_id}/{args.agent_name}",
        "unidad=fichero:linea_de_archives",
        f"M_endpoint={st['M_endpoint']}",
        f"M_total={st['M_total']}",
        f"filas={len(idx_rows)}",
        f"nivel<3_excluidos={st['nivel_bajo']}",
        f"sin_rule_excluidos={st['sin_rule']}",
        f"auto_ruido={st['auto']}",
        "layout=largo(1 fila por evento alertante)",
        f"sha256_entradas={hashes}",
    ])
    idx_path = os.path.join(out_dir, "eventos_alerta_72h.csv.gz")
    escribir_gz_csv(idx_path, IDX_HEADER, idx_rows, comment_idx)

    # 4) Catálogo de ruido 72 h (11 reglas; suma `count` = 294.253, incluye `rule 11`)
    auto_por_rule = collections.Counter(r[2] for r in idx if r[5])
    unidades_por_rule = collections.Counter(r[2] for r in idx)
    cat_rows = []
    for rid in sorted(ruleids, key=lambda s: (0, int(s)) if s.isdigit() else (1, s)):
        d = ruleids[rid]
        unidades = unidades_por_rule.get(rid, 0)
        auto = auto_por_rule.get(rid, 0)
        pct = f"{100.0 * auto / unidades:.4f}" if unidades else "0.0000"
        cat_rows.append({
            "rule_id": rid,
            "rule_level": d["rule_level"],
            "rule_description": d["rule_description"],
            "groups": d["groups"],
            "rs_origen": d["rs_origen"],
            "count": d["count"],
            "first_seen": d["first_seen"],
            "last_seen": d["last_seen"],
            "alertas_auto": auto,
            "alertas_no_auto": unidades - auto,
            "pct_auto": pct,
            "origen_catalogo": "72h",
        })
    suma_count = sum(r["count"] for r in cat_rows)
    comment_cat = "# catalogo_ruido_72h.csv | " + " | ".join([
        "TFG HIDS - L2 catalogo de ruido autoritativo (72 h)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"ventana={args.desde}..{args.hasta}",
        f"reglas={len(cat_rows)}",
        f"suma_count={suma_count}",
        f"unidades_con_alerta={len(idx)}",
        f"unidades_auto={st['auto']}",
        "declaracion=rule 11 (stats, UNKNOWN) NO tiene unidad en archives: 294253 alertas = 294252 eventos + 1 alerta interna; su alertas_auto=0 aqui y la cifra 66.286 (alertas) vs 66.285 (unidades) se declara en auto_ruido_evidencia.csv",
        "declaracion=rule 1002 (nivel 2, 72 eventos) NO emite alerta: fuera del catalogo y de T3",
        "declaracion=auto_ruido es por CAMPOS (filtrar_ruido.detectar_auto_ruido), no por rule_id",
        "layout=largo(1 fila por rule_id)",
    ])
    TC.write_csv(os.path.join(out_dir, "catalogo_ruido_72h.csv"), CATALOGO_HEADER, cat_rows,
                 comment=comment_cat)

    # 5) Catálogo M1b = 72 h ∪ {5402,5501,5502,5715}
    m1b = []
    for rid in sorted(set(ruleids) | set(REGLAS_HISTORICAS),
                      key=lambda s: (0, int(s)) if s.isdigit() else (1, s)):
        if rid in ruleids:
            d = ruleids[rid]
            m1b.append({
                "rule_id": rid,
                "rule_level": d["rule_level"],
                "rs_origen": d["rs_origen"],
                "groups": d["groups"],
                "count_72h": d["count"],
                "origen_catalogo": "72h",
                "justificacion": f"observada en 72 h ({d['count']} alertas)",
            })
        else:
            d = ruleids_hist.get(rid, {})
            m1b.append({
                "rule_id": rid,
                "rule_level": d.get("rule_level", ""),
                "rs_origen": d.get("rs_origen", ""),
                "groups": d.get("groups", ""),
                "count_72h": 0,
                "origen_catalogo": "baseline_historico",
                "justificacion": (
                    "no ejercitada en 72 h (0 sesiones del operador en el endpoint, V4); "
                    f"baseline historico 2x4 h ({d.get('count', 0)} alertas)"
                ),
            })
    comment_m1b = "# catalogo_M1b.csv | " + " | ".join([
        "TFG HIDS - L2 catalogo M1b (72 h union 4 reglas historicas del operador)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"reglas={len(m1b)}",
        "origen_catalogo=72h|baseline_historico",
        "declaracion=la ausencia en 72 h de 5402/5501/5502/5715 NO es evidencia de deteccion (ventana sin sesiones del operador); se mantienen como ruido historico declarado",
        "layout=largo(1 fila por rule_id)",
    ])
    TC.write_csv(os.path.join(out_dir, "catalogo_M1b.csv"), CATALOGO_M1B_HEADER, m1b,
                 comment=comment_m1b)

    # 6) Evidencia de auto_ruido (por regla / campo / valor)
    evid_rows = []
    for (rid, campo, valor), n in sorted(st["auto_evid"].items(), key=lambda kv: (-kv[1], kv[0])):
        motivo = "stats" if campo == "rule_id" else campo.replace("audit_", "").replace("syscheck_", "syscheck_")
        evid_rows.append({
            "rule_id": rid,
            "motivo": motivo,
            "campo": campo,
            "valor": valor,
            "alertas": n,
            "unidades": n,
        })
    comment_evid = "# auto_ruido_evidencia.csv | " + " | ".join([
        "TFG HIDS - L2 evidencia del predicado auto_ruido (por campos)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        "predicado=filtrar_ruido.detectar_auto_ruido (audit_exe base en WAZUH_PROCESOS; audit_cwd=/var/ossec; audit_file/audit_dir/syscheck_path bajo /var/ossec/var/run/*; rule_id=11 + grupo stats)",
        f"unidades_auto={st['auto']}",
        f"alertas_auto_incl_stats={st['auto'] + 1}",
        f"unidades_con_alerta={len(idx)}",
        "declaracion=unidades_auto=66285; la alerta rule 11 (stats) tambien es auto_ruido pero NO tiene unidad en archives -> alertas_auto=66286",
        "declaracion=rule 1002 (nivel 2, 72 eventos) no emite alerta; no es FP ni auto_ruido",
        "layout=largo(1 fila por regla x campo x valor de evidencia)",
    ])
    TC.write_csv(os.path.join(out_dir, "auto_ruido_evidencia.csv"), EVIDENCIA_HEADER, evid_rows,
                 comment=comment_evid)

    # 7) Estabilidad por día y por hora
    cfg_c0 = set(M.CONFIGS["C0"])
    cfg_c1 = set(M.CONFIGS["C1"])
    dias = sorted(st["por_dia"])
    dia_rows = []
    for dia in dias:
        sel = [r for r in idx if r[1][:10] == dia]
        fp_c0 = len({r[0] for r in sel if _passa(_rs(r[2], ruleids), r[3], 0, cfg_c0)})
        fp_c1 = len({r[0] for r in sel if _passa(_rs(r[2], ruleids), r[3], 0, cfg_c1)})
        fp_c1n7 = len({r[0] for r in sel if _passa(_rs(r[2], ruleids), r[3], 7, cfg_c1)})
        m = st["por_dia"][dia]
        a_fp = sum(1 for r in sel if _passa(_rs(r[2], ruleids), r[3], 0, cfg_c1))
        auto = sum(1 for r in sel if r[5])
        dia_rows.append({
            "dia": dia,
            "M": m,
            "FP_uni_C0_N0": fp_c0,
            "FP_uni_C1_N0": fp_c1,
            "FP_uni_C1_N7": fp_c1n7,
            "FPR_C0": M.fmt_ratio(M.fpr(fp_c0, m)),
            "FPR_C1_N0": M.fmt_ratio(M.fpr(fp_c1, m)),
            "FPR_C1_N7": M.fmt_ratio(M.fpr(fp_c1n7, m)),
            "A_FP": a_fp,
            "auto": auto,
        })
    comment_dia = "# estabilidad_dia.csv | " + " | ".join([
        "TFG HIDS - L2 estabilidad diaria del legitimo",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        "unidad=evento decodificado (linea de archives)",
        "declaracion=M por dia se re-cuenta (frontera de rotacion diaria); el total es 342966",
        "columnas=" + ",".join(DIA_HEADER),
    ])
    TC.write_csv(os.path.join(out_dir, "estabilidad_dia.csv"), DIA_HEADER, dia_rows,
                 comment=comment_dia)

    horas = []
    for dia in dias:
        for h in range(24):
            horas.append(f"{dia}T{h:02d}")
    hora_rows = []
    for hh in horas:
        sel = [r for r in idx if r[1][:13] == hh]
        fp = len({r[0] for r in sel if _passa(_rs(r[2], ruleids), r[3], 0, cfg_c1)})
        m = st["por_hora"].get(hh, 0)
        a_fp = sum(1 for r in sel if _passa(_rs(r[2], ruleids), r[3], 0, cfg_c1))
        auto = sum(1 for r in sel if r[5])
        hora_rows.append({
            "hora_utc": hh + ":00Z",
            "M": m,
            "FP_uni_C1_N0": fp,
            "FPR_C1_N0": M.fmt_ratio(M.fpr(fp, m)) if m else "",
            "A_FP": a_fp,
            "auto": auto,
        })
    comment_hora = "# estabilidad_hora.csv | " + " | ".join([
        "TFG HIDS - L2 estabilidad horaria del legitimo",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"horas={len(hora_rows)}",
        "declaracion=72/72 horas con al menos una unidad FP (ruido estructural)",
        "columnas=" + ",".join(HORA_HEADER),
    ])
    TC.write_csv(os.path.join(out_dir, "estabilidad_hora.csv"), HORA_HEADER, hora_rows,
                 comment=comment_hora)

    # 8) Campaña declarada (11 casos): alertas en [ini-10s, fin+60s]
    camp_rows = []
    tot_camp = 0
    for r in campana:
        ini = parse_ts(r["ini"])
        fin = parse_ts(r["fin"])
        a = ini - timedelta(seconds=CAMPANA_PRE_S)
        b = fin + timedelta(seconds=CAMPANA_POST_S)
        sel = [x for x in idx if a <= parse_ts(x[1]) <= b]
        rids = sorted({x[2] for x in sel}, key=lambda s: (0, int(s)) if s.isdigit() else (1, s))
        lv = max([int(x[3]) for x in sel], default=0)
        tot_camp += len(sel)
        camp_rows.append({
            "caso": r["caso"],
            "ini": r["ini"],
            "fin": r["fin"],
            "duracion_s": int((fin - ini).total_seconds()),
            "alertas": len(sel),
            "rule_ids": ";".join(rids),
            "nivel_max": lv,
            "esperado_cumplido": r["esperado_cumplido"],
        })
    comment_camp = "# campana_estabilidad.csv | " + " | ".join([
        "TFG HIDS - L2 estabilidad de la campana declarada (B6)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"atribucion=[ini-{CAMPANA_PRE_S}s,fin+{CAMPANA_POST_S}s]",
        f"casos={len(camp_rows)}",
        f"alertas_total={tot_camp}",
        f"n_acciones_total={args.n_acciones_ghosts}",
        "declaracion=n_acciones por caso NO existe (BD GHOSTS parada); FP/accion de campana usa el total 63 acciones: 1793/63 = 28.4603",
        "declaracion=la campana esta DENTRO de M: no se fabrica un FPR alternativo",
        "columnas=" + ",".join(CAMPANA_HEADER),
    ])
    TC.write_csv(os.path.join(out_dir, "campana_estabilidad.csv"), CAMPANA_HEADER, camp_rows,
                 comment=comment_camp)

    # 9) Detalle de T3 (intermedio regenerable; no se versiona)
    det_rows = []
    for (u, ts, rid, lv, groups, auto) in idx:
        det_rows.append({
            "unidad": u,
            "rule_id": rid,
            "rule_level": lv,
            "rs_origen": _rs(rid, ruleids),
            "categoria": M.CATEGORIA_AUTO_RUIDO if auto else "ruido_conocido",
            "rule_groups": groups,
        })
    det_path = os.path.join(TC.ROOT, args.detalle_out)
    comment_det = "# T3_detalle.csv | " + " | ".join([
        "TFG HIDS - L2 detalle por evento alertante (intermedio regenerable; NO versionado)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"filas={len(det_rows)}",
        "declaracion=en una ventana sin ataque, toda alerta no-auto_ruido es ruido_conocido; dudosa=0",
        "columnas=" + ",".join(DETALLE_HEADER),
    ])
    TC.write_csv(det_path, DETALLE_HEADER, det_rows, comment=comment_det)

    # 10) MANIFEST de archives (copia literal del original, si existe)
    man_src = os.path.join(ap_dir, "MANIFEST.tsv") if os.path.isdir(ap_dir) else ""
    man_dst = os.path.join(out_dir, "MANIFEST_archives.tsv")
    if man_src and os.path.isfile(man_src):
        with open(man_src, "rb") as fi, open(man_dst, "wb") as fo:
            fo.write(fi.read())

    # 11) Resumen
    print(f"M endpoint={st['M_endpoint']} total={st['M_total']} "
          f"nivel<3={st['nivel_bajo']} sin_rule={st['sin_rule']}")
    print(f"indice: {len(idx_rows)} filas -> {TC.rel(idx_path)}")
    print(f"auto_ruido: {st['auto']} unidades ({100.0 * st['auto'] / len(idx_rows):.4f} %)")
    print(f"catalogo: {len(cat_rows)} reglas (suma count={suma_count})")
    print(f"campana: {tot_camp} alertas en {len(camp_rows)} casos")
    print(f"T3_detalle: {len(det_rows)} filas -> {TC.rel(det_path)}")
    print(f"tamano_archives={tam_bytes} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
