#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_campana_windows.py — tabla por caso de la campaña `B6` de Windows.

**No ejecuta nada**: lee las **marcas** de la campaña (`W-XX/{inicio,fin}.txt`) y las
alertas del agente **`002`** (`victima-windows`) y escribe `campana_fp_windows.csv`
con **las mismas 9 columnas** que Linux (`extraer_campana.py`, plan §10, CA-W14):

```
caso · ini · fin · n_acciones · n_eventos · alertas · rule_id · level · esperado_cumplido
```

| Columna | Fuente | Ventana |
|---|---|---|
| `ini`, `fin` | `…/campana/W-XX/{inicio,fin}.txt` (22 marcas) | — |
| `n_acciones` | export **por acción** de `history_timeline` (`--acciones`) | `[ini, fin]` |
| `n_eventos` | copia de los `archives` de Wazuh, **agente `002`** | `[ini, fin]` |
| `alertas` | CSV de alertas (`extraer_alertas_windows.py`) | `[ini − 10 s, fin + 60 s]` |
| `rule_id` / `level` | del mismo cruce de alertas | idem |
| `esperado_cumplido` | `SI` si `67027` aparece y `level < 7`; `NO` si no; `NO_EJECUTADO` **solo** si no hay ninguna marca; `NO_EVALUABLE` con motivo si hay marcas que no se pueden leer/convertir (p. ej. locales sin `--desfase-local`), si faltan marcas o `hecho.txt`, o si no se pasan alertas | — |

**Marcas de Windows.** La receta sella `echo %DATE%_%TIME%`: es **hora local del
invitado** (`dd/mm/aaaa_hh:mm:ss.cc`), no ISO/UTC. El extractor **no adivina**:

- si la marca es ISO (`2026-11-09T17:06:00Z`), se usa tal cual;
- si es local, **exige** `--desfase-local +01:00` (o el que corresponda). Sin desfase
  deja la ventana **vacía**, avisa y el caso queda **`NO_EVALUABLE` con el motivo**
  (`marca local sin --desfase-local declarado`). **Nunca** se marca `NO_EJECUTADO` si
  el fichero de la marca existe: `NO_EJECUTADO` es **solo** ausencia de marcas.

**Filtro por agente.** Se exige el agente **`002`** por `agent_id`; si el CSV no trae
columna de id, se acepta `agent_name == victima-windows` y se declara. **Nunca** se
mezclan agentes: una fila del `001` no entra (ni se cuenta ni se descarta en silencio:
se informa del número de filas ajenas).

**Dedupe por `MANIFEST`.** Si la copia de `archives` (o la carpeta de alertas) trae
`MANIFEST.tsv` en el formato de `exportar_denominador.sh`
(`fichero · bytes · sha256 · origen`), se leen **solo** las filas cuyo `origen` no sea
`DUPLICADO…`. Sin manifiesto, se deduplica por `sha256`. No se colapsan filas de
alerta: dos eventos idénticos del mismo segundo son dos eventos.

**Campos de Windows.** Se reconocen los nombres de Sysmon/Wazuh
(`win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.currentDirectory`,
`win.eventdata.user`, `win.system.eventID`) y los alias planos (`win_image`,
`win_command_line`, `win_cwd`, `win_user`, `event_id`). Si faltan, **no se inventan**:
se informa de cuántas filas los traen y la tabla común no cambia.

Uso:
    python extraer_campana_windows.py --solo-ventanas --evidencia <cosecha> \\
        --desfase-local +01:00 --out campana_ventanas_windows.tsv
    python extraer_campana_windows.py --ventanas campana_ventanas_windows.tsv \\
        --alertas <carpeta o CSV> --acciones ghosts_acciones_detalle.csv \\
        --evidencia <cosecha> --out campana_fp_windows.csv
    python extraer_campana_windows.py --test
"""

from __future__ import annotations

import argparse
import bisect
import csv
import glob
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campana_windows as cw  # noqa: E402
import contar_denominador as cd  # noqa: E402  (parse_ts / sha256 / lectura .gz)

CSV_HEADER = ["caso", "ini", "fin", "n_acciones", "n_eventos", "alertas",
              "rule_id", "level", "esperado_cumplido"]
#: El motivo viaja en el TSV intermedio (y en el `#` del CSV); las 9 columnas de datos
#: se mantienen idénticas a Linux (CA-W14).
TSV_HEADER = ["caso", "ini", "fin", "motivo"]

AGENTE = "victima-windows"
AGENTE_ID = "002"
RE_EXPR = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RE_LOCAL = re.compile(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})[ _]+"
                      r"(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?$")
COLS_TS_ACCIONES = ("createdutc", "created_utc", "timestamp", "ts", "fecha", "utc")

#: Alias de columnas: primero los nombres de Sysmon/Wazuh, luego los planos.
ALIAS_TS = ("timestamp_utc", "timestamp", "ts", "@timestamp", "fecha", "win_timestamp")
ALIAS_AGENT_ID = ("agent_id", "agent.id", "id_agente", "agente_id")
ALIAS_AGENT_NAME = ("agent_name", "agent.name", "agente")
ALIAS_RULE = ("rule_id", "rule.id", "ruleid")
ALIAS_LEVEL = ("rule_level", "rule.level", "level", "nivel")
ALIAS_IMAGE = ("win_image", "win.eventdata.image", "data.win.eventdata.image", "image",
               "image_path")
ALIAS_CMDLINE = ("win_command_line", "win.eventdata.commandline",
                 "data.win.eventdata.commandline", "command_line", "commandline")
ALIAS_CWD = ("win_cwd", "win.eventdata.currentdirectory",
             "data.win.eventdata.currentdirectory", "cwd")
ALIAS_USER = ("win_user", "win.eventdata.user", "data.win.eventdata.user", "user")
ALIAS_EVENT_ID = ("event_id", "win.system.eventid", "data.win.system.eventid", "eventid")


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    s = s.strip()
    if not s:
        raise ValueError("vacío")
    return cd.parse_ts(s)


def _leer_lineas(path):
    return cd._open_lines(path)


def sha256_file(path: str) -> str:
    return cd.sha256_file(path)


def parse_offset(txt: str) -> timedelta:
    """`+01:00`, `-05:00` o `+60`/`-300` (minutos) → `timedelta`."""
    s = (txt or "").strip()
    if not s:
        raise ValueError("desfase vacío")
    m = re.match(r"^([+-])(\d{1,2}):(\d{2})$", s)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    if re.match(r"^[+-]?\d+$", s):
        return timedelta(minutes=int(s))
    raise ValueError(f"desfase no reconocido: {txt!r}")


def parse_marca(txt: str, desfase: timedelta | None = None,
                formato: str = "dmy") -> datetime:
    """Marca de Windows → `datetime` UTC.

    Acepta ISO UTC (`…Z`/`+0000`) o la forma de `cmd` (`%DATE%_%TIME%`, hora local).
    Si la marca es local y no hay `desfase`, **falla**: no se adivina la zona.
    """
    s = (txt or "").strip().replace("\x00", "")
    if not s:
        raise ValueError("vacía")
    try:
        return cd.parse_ts(s)
    except ValueError:
        pass
    m = RE_LOCAL.match(s)
    if not m:
        raise ValueError(f"formato no reconocido: {txt!r}")
    a, b, yyyy = int(m.group(1)), int(m.group(2)), int(m.group(3))
    dia, mes = (a, b) if formato == "dmy" else (b, a)
    micro = int((m.group(7) or "0")[:6].ljust(6, "0"))
    naive = datetime(yyyy, mes, dia, int(m.group(4)), int(m.group(5)),
                     int(m.group(6)), micro)
    if desfase is None:
        raise ValueError("marca local sin `--desfase-local` declarado")
    return (naive - desfase).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# 1) Ventanas: marcas `inicio.txt` / `fin.txt`
# --------------------------------------------------------------------------
def leer_marcas(evidencia: str, desfase: timedelta | None = None,
                formato: str = "dmy"):
    """Devuelve ({caso: {"ini": dt|None, "fin": dt|None}}, [avisos])."""
    if not os.path.isdir(evidencia):
        raise SystemExit(f"ERROR: no existe la carpeta de evidencia {evidencia}")
    out, avisos = {}, []
    presentes, motivos = set(), {}

    def _anota(caso, clave, txt, origen):
        presentes.add(caso)
        try:
            dt = parse_marca(txt, desfase, formato)
        except ValueError as exc:
            msg = f"{origen} no utilizable ({exc})"
            avisos.append(f"{caso}: {msg}")
            motivos.setdefault(caso, []).append(msg)
            return
        reg = out.setdefault(caso, {"ini": None, "fin": None})
        if reg[clave] is not None and reg[clave] != dt:
            avisos.append(f"{caso}: {clave} repetido con distinto valor "
                          f"({fmt_ts(reg[clave])} vs {fmt_ts(dt)})")
        reg[clave] = dt

    for raiz, dirs, files in os.walk(evidencia):
        dirs.sort()
        for d in dirs:
            if re.fullmatch(r"W-\d{2}", d):
                carpeta = os.path.join(raiz, d)
                for clave, nombre in (("ini", "inicio.txt"), ("fin", "fin.txt")):
                    p = os.path.join(carpeta, nombre)
                    if os.path.isfile(p):
                        _anota(d, clave, open(p, encoding="utf-8",
                                             errors="replace").read(), nombre)
        for f in sorted(files):
            m = re.fullmatch(r"(W-\d{2})[_-](inicio|fin)\.txt", f)
            if m:
                _anota(m.group(1), "ini" if m.group(2) == "inicio" else "fin",
                       open(os.path.join(raiz, f), encoding="utf-8",
                            errors="replace").read(), f)

    vistos = 0
    for caso in list(out):
        reg = out[caso]
        for clave, nombre in (("ini", "inicio.txt"), ("fin", "fin.txt")):
            if reg[clave] is None:
                avisos.append(f"{caso}: falta {nombre}")
        if reg["ini"] and reg["fin"] and reg["fin"] < reg["ini"]:
            avisos.append(f"{caso}: fin anterior a inicio")
            motivos.setdefault(caso, []).append("fin anterior a inicio")
        if reg["ini"] or reg["fin"]:
            vistos += 1
        else:
            out.pop(caso)
    avisos.append(f"marcas encontradas: {vistos} casos (se esperan {len(cw.IDS)})")
    # Los 11 casos siempre existen en la tabla. `NO_EJECUTADO` = **no hay ninguna marca**;
    # si el fichero existe pero no se puede convertir, el caso es `NO_EVALUABLE` con motivo.
    for cid in cw.IDS:
        reg = out.setdefault(cid, {"ini": None, "fin": None})
        reg.setdefault("motivo", "")
        if motivos.get(cid):
            reg["motivo"] = "; ".join(motivos[cid])
            avisos.append(f"{cid}: marcas no utilizables (NO_EVALUABLE: {reg['motivo']})")
        elif cid in presentes and (not reg["ini"] or not reg["fin"]):
            reg["motivo"] = "marca presente pero incompleta"
            avisos.append(f"{cid}: marcas presentes no utilizables "
                          f"(NO_EVALUABLE: {reg['motivo']})")
        elif cid not in presentes and not reg["ini"] and not reg["fin"]:
            avisos.append(f"{cid}: sin marcas (NO_EJECUTADO)")
    return dict(sorted(out.items())), avisos


def escribir_ventanas(ventanas, out, avisos=()):
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    n_marcas = sum(1 for r in ventanas.values() for k in ("ini", "fin") if r[k])
    cab = (f"# campana_ventanas_windows.tsv | {n_marcas} marcas | "
           f"fuente=evidencia/campana/W-*/{{inicio,fin}}.txt | "
           f"casos={len(ventanas)} | plataforma=windows | agente={AGENTE_ID}/{AGENTE}")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(TSV_HEADER)
        for cid, r in ventanas.items():
            w.writerow([cid, fmt_ts(r["ini"]) if r["ini"] else "",
                        fmt_ts(r["fin"]) if r["fin"] else "", r.get("motivo", "")])
    print(f"-> {out} ({len(ventanas)} casos, {n_marcas} marcas)")
    for a in avisos:
        print(f"  AVISO: {a}")


def cargar_ventanas(path: str):
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: no existe {path}")
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    rd = csv.DictReader(lineas, delimiter="\t")
    if not rd.fieldnames or not {"caso", "ini", "fin"} <= set(rd.fieldnames):
        raise SystemExit("ERROR: campana_ventanas_windows.tsv debe tener caso/ini/fin")
    out = {}
    for r in rd:
        cid = (r["caso"] or "").strip()
        if not cid:
            continue
        ini = parse_iso(r["ini"]) if (r["ini"] or "").strip() else None
        fin = parse_iso(r["fin"]) if (r["fin"] or "").strip() else None
        if ini and fin and fin < ini:
            raise SystemExit(f"ERROR: {cid}: fin anterior a inicio")
        out[cid] = {"ini": ini, "fin": fin, "motivo": (r.get("motivo") or "").strip()}
    return dict(sorted(out.items()))


def comprobar_ventanas(ventanas):
    fallos, completas = [], []
    for cid, r in ventanas.items():
        if r["ini"] and r["fin"]:
            completas.append((r["ini"], r["fin"], cid))
        else:
            fallos.append(f"{cid}: marcas incompletas (NO_EVALUABLE)")
    completas.sort()
    for (ini1, fin1, c1), (ini2, _fin2, c2) in zip(completas, completas[1:]):
        a1 = ini1 - timedelta(seconds=cw.ATRIB_PRE_S)
        b1 = fin1 + timedelta(seconds=cw.ATRIB_POST_S)
        a2 = ini2 - timedelta(seconds=cw.ATRIB_PRE_S)
        if a2 <= b1:
            fallos.append(f"ventanas de atribución solapadas: {c1} y {c2}")
        if ini2 - fin1 < timedelta(seconds=cw.SEPARACION_MIN_S):
            fallos.append(f"separación < {cw.SEPARACION_MIN_S} s entre {c1} y {c2}")
        if a1 > b1:
            fallos.append(f"{c1}: ventana de atribución invertida")
    return fallos


# --------------------------------------------------------------------------
# 2) Ficheros: dedupe por MANIFEST / sha256
# --------------------------------------------------------------------------
def _leer_manifest(path: str):
    filas = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        rd = csv.DictReader(fh, delimiter="\t")
        if not rd.fieldnames:
            return filas
        for r in rd:
            filas.append({k.strip(): (v or "").strip() for k, v in r.items() if k})
    return filas


def ficheros_unicos(entradas, manifest=None, extensiones=(".json", ".json.gz")):
    """Ficheros a leer, **sin duplicados** (MANIFEST manda; si no, `sha256`)."""
    paths, notas = [], []
    entradas = list(entradas or [])
    if len(entradas) == 1 and os.path.isdir(entradas[0]):
        d = entradas[0]
        man = manifest or os.path.join(d, "MANIFEST.tsv")
        if os.path.isfile(man):
            manifest = man
        else:
            entradas = sorted(f for f in glob.glob(os.path.join(d, "*"))
                              if f.endswith(extensiones)
                              and not os.path.basename(f).upper().startswith("MANIFEST"))
    if manifest:
        if not os.path.isfile(manifest):
            raise SystemExit(f"ERROR: no existe el manifiesto {manifest}")
        base = os.path.dirname(os.path.abspath(manifest))
        for r in _leer_manifest(manifest):
            f = r.get("fichero") or r.get("ruta") or ""
            origen = (r.get("origen") or "").lower()
            if not f or origen.startswith("duplicado"):
                continue
            p = f if os.path.isabs(f) else os.path.join(base, f)
            if not p.endswith(extensiones):
                notas.append(f"manifiesto: {f} no es {'/'.join(extensiones)} (omitido)")
                continue
            if not os.path.isfile(p):
                notas.append(f"manifiesto: no existe {p}")
                continue
            paths.append(p)
        notas.append(f"MANIFEST: {len(paths)} ficheros únicos")
    else:
        unicos, vistos = [], {}
        for p in entradas:
            if not os.path.isfile(p):
                notas.append(f"no existe {p}")
                continue
            h = sha256_file(p)
            if h in vistos:
                notas.append(f"duplicado por sha256: {os.path.basename(p)} == "
                             f"{os.path.basename(vistos[h])} (descartado)")
                continue
            vistos[h] = p
            unicos.append(p)
        paths = unicos
    if not paths:
        raise SystemExit("ERROR: no hay ficheros que leer")
    return paths, notas


# --------------------------------------------------------------------------
# 3) Eventos de `archives` (agente 002)
# --------------------------------------------------------------------------
def contar_eventos(paths, ventanas, agent_id=AGENTE_ID, agent_name=AGENTE):
    pares = sorted((r["ini"], r["fin"], cid) for cid, r in ventanas.items()
                   if r["ini"] and r["fin"])
    inicios = [p[0] for p in pares]
    cuenta = {cid: 0 for cid, _r in ventanas.items()}
    no_ts = bad = 0
    for path in paths:
        for linea in _leer_lineas(path):
            linea = linea.strip() if isinstance(linea, str) else \
                linea.decode("utf-8", "replace").strip()
            if not linea:
                continue
            try:
                rec = json.loads(linea)
            except json.JSONDecodeError:
                bad += 1
                continue
            ts_raw = rec.get("timestamp")
            if not ts_raw:
                no_ts += 1
                continue
            try:
                ts = cd.parse_ts(str(ts_raw))
            except ValueError:
                no_ts += 1
                continue
            i = bisect.bisect_right(inicios, ts) - 1
            if i < 0:
                continue
            ini, fin, cid = pares[i]
            if ts > fin:
                continue
            ag = rec.get("agent", {}) or {}
            aid = str(ag.get("id", "") or "").strip()
            if aid:
                if aid != agent_id:
                    continue
            elif str(ag.get("name", "") or "").strip() != agent_name:
                continue
            cuenta[cid] += 1
    return cuenta, {"sin_timestamp": no_ts, "json_invalido": bad}


# --------------------------------------------------------------------------
# 4) Acciones de `history_timeline` (export POR ACCIÓN)
# --------------------------------------------------------------------------
def _sniff_delimitador(path: str) -> str:
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for linea in fh:
            if linea.startswith("#") or not linea.strip():
                continue
            return "\t" if linea.count("\t") > linea.count(",") else ","
    return ","


def contar_acciones(path, ventanas):
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: no existe {path}")
    delim = _sniff_delimitador(path)
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    rd = csv.DictReader(lineas, delimiter=delim)
    campos = [c.strip().lower() for c in (rd.fieldnames or [])]
    col = next((c for c in COLS_TS_ACCIONES if c in campos), None)
    if col is None:
        raise SystemExit(
            f"ERROR: {path} no tiene columna de tiempo por acción ({campos}). "
            f"El `ghosts_acciones.csv` agregado NO sirve: hace falta el export por "
            f"acción de `history_timeline`.")
    idx = campos.index(col)
    pares = sorted((r["ini"], r["fin"], cid) for cid, r in ventanas.items()
                   if r["ini"] and r["fin"])
    inicios = [p[0] for p in pares]
    cuenta = {cid: 0 for cid, _r in ventanas.items()}
    malas = 0
    for r in rd:
        vals = list(r.values())
        if idx >= len(vals):
            continue
        raw = (vals[idx] or "").strip()
        if not raw:
            malas += 1
            continue
        try:
            ts = cd.parse_ts(raw)
        except ValueError:
            malas += 1
            continue
        i = bisect.bisect_right(inicios, ts) - 1
        if i < 0:
            continue
        ini, fin, cid = pares[i]
        if ts <= fin:
            cuenta[cid] += 1
    return cuenta, {"sin_timestamp": malas, "columna": col}


# --------------------------------------------------------------------------
# 5) Alertas de Windows (campos Sysmon/win.eventdata.*)
# --------------------------------------------------------------------------
def _resolver(campos, alias):
    """Índice de la primera columna que case con un alias (sin distinguir mayúsculas)."""
    lower = [c.strip().lower() for c in campos]
    for a in alias:
        if a in lower:
            return lower.index(a)
    return None


def leer_alertas(path: str):
    """Devuelve (campos, filas) de un CSV/TSV de alertas (UTF-8 con o sin BOM)."""
    delim = _sniff_delimitador(path)
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    rd = csv.DictReader(lineas, delimiter=delim)
    return list(rd.fieldnames or []), [r for r in rd]


def contar_alertas(paths, ventanas, agent_id=AGENTE_ID, agent_name=AGENTE,
                   pre_s=cw.ATRIB_PRE_S, post_s=cw.ATRIB_POST_S):
    """Cuenta alertas por caso. Devuelve (res, meta).

    `meta` incluye cuántas filas se leyeron, cuántas eran de otro agente y cuántas
    traían cada campo de Windows (`win_image`…). Nada se inventa: si falta la columna
    de agente, **falla**; si falta un campo opcional, se informa con 0.
    """
    pares = sorted((r["ini"] - timedelta(seconds=pre_s),
                    r["fin"] + timedelta(seconds=post_s), cid)
                   for cid, r in ventanas.items() if r["ini"] and r["fin"])
    inicios = [p[0] for p in pares]
    res = {cid: {"alertas": 0, "rules": set(), "levels": []}
           for cid, _r in ventanas.items()}
    meta = {"filas": 0, "otros_agentes": 0, "sin_timestamp": 0,
            "campos": {k: 0 for k in ("win_image", "win_command_line", "win_cwd",
                                      "win_user", "event_id")},
            "columna_agente": None}
    for path in paths:
        campos, filas = leer_alertas(path)
        i_ts = _resolver(campos, ALIAS_TS)
        i_id = _resolver(campos, ALIAS_AGENT_ID)
        i_nm = _resolver(campos, ALIAS_AGENT_NAME)
        i_rule = _resolver(campos, ALIAS_RULE)
        i_lvl = _resolver(campos, ALIAS_LEVEL)
        if i_ts is None:
            raise SystemExit(f"ERROR: {path} no tiene columna de tiempo ({campos})")
        if i_id is None and i_nm is None:
            raise SystemExit(f"ERROR: {path} no tiene columna de agente; no se puede "
                             f"filtrar el {agent_id} sin inventar")
        if i_rule is None or i_lvl is None:
            raise SystemExit(f"ERROR: {path} no tiene rule_id/rule_level ({campos})")
        meta["columna_agente"] = "agent_id" if i_id is not None else "agent_name"
        idx_win = {k: _resolver(campos, alias) for k, alias in
                   (("win_image", ALIAS_IMAGE), ("win_command_line", ALIAS_CMDLINE),
                    ("win_cwd", ALIAS_CWD), ("win_user", ALIAS_USER),
                    ("event_id", ALIAS_EVENT_ID))}
        for r in filas:
            meta["filas"] += 1
            vals = list(r.values())
            if i_id is not None:
                propio = (vals[i_id] or "").strip() == agent_id
            else:
                propio = (vals[i_nm] or "").strip() == agent_name
            if not propio:
                meta["otros_agentes"] += 1
                continue
            raw = (vals[i_ts] or "").strip()
            if not raw:
                meta["sin_timestamp"] += 1
                continue
            try:
                ts = cd.parse_ts(raw)
            except ValueError:
                meta["sin_timestamp"] += 1
                continue
            for k, i in idx_win.items():
                if i is not None and (vals[i] or "").strip():
                    meta["campos"][k] += 1
            i = bisect.bisect_right(inicios, ts) - 1
            if i < 0:
                continue
            ini, fin, cid = pares[i]
            if ts > fin:
                continue
            try:
                lvl = int(float((vals[i_lvl] or "0").strip() or 0))
            except ValueError:
                lvl = 0
            res[cid]["alertas"] += 1
            res[cid]["rules"].add((vals[i_rule] or "").strip())
            res[cid]["levels"].append(lvl)
    return res, meta


# --------------------------------------------------------------------------
# 6) Tabla final
# --------------------------------------------------------------------------
def _evidencia_ok(evidencia, cid):
    if not evidencia:
        return None
    if os.path.isfile(os.path.join(evidencia, "campana", cid, "hecho.txt")):
        return True
    for raiz, _dirs, files in os.walk(evidencia):
        if os.path.basename(raiz) == cid and "hecho.txt" in files:
            return True
        if f"{cid}_hecho.txt" in files:
            return True
    return False


def construir_tabla(ventanas, acciones=None, eventos=None, alertas=None,
                    evidencia=None, umbral_n7=cw.UMBRAL_N7, rule_exec=cw.RULE_EXEC):
    filas = []
    for cid, r in ventanas.items():
        ini, fin = r["ini"], r["fin"]
        al = (alertas or {}).get(cid, {"alertas": 0, "rules": set(), "levels": []})
        rules = sorted(x for x in al["rules"] if x)
        levels = al["levels"]
        level = max(levels) if levels else 0
        hecho = _evidencia_ok(evidencia, cid)
        motivo = (r.get("motivo") or "").strip()
        if not ini and not fin:
            # Sin ninguna marca ⇒ NO_EJECUTADO. Con marca presente pero ilegible ⇒
            # NO_EVALUABLE con motivo (nunca NO_EJECUTADO: el caso se intentó).
            estado = "NO_EVALUABLE" if motivo else "NO_EJECUTADO"
        elif not ini or not fin:
            estado = "NO_EVALUABLE"
            motivo = motivo or "marcas incompletas"
        elif motivo:
            estado = "NO_EVALUABLE"
        elif hecho is False:
            estado = "NO_EVALUABLE"
            motivo = "marcas presentes pero sin hecho.txt (efecto no evidenciado)"
        elif alertas is None:
            estado = "NO_EVALUABLE"
            motivo = "sin fichero de alertas"
        elif rule_exec in rules and level < umbral_n7:
            estado = "SI"
        else:
            estado = "NO"
        filas.append({
            "caso": cid,
            "ini": fmt_ts(ini) if ini else "",
            "fin": fmt_ts(fin) if fin else "",
            "n_acciones": "" if acciones is None else str(acciones.get(cid, 0)),
            "n_eventos": "" if eventos is None else str(eventos.get(cid, 0)),
            # Sin fichero de alertas no se escribe un 0: no hay dato (`NO_EVALUABLE`).
            "alertas": "" if alertas is None else str(al["alertas"]),
            "rule_id": ";".join(rules),
            "level": "" if alertas is None else str(level),
            "esperado_cumplido": estado,
            # El motivo NO se añade a las 9 columnas (paridad con Linux): va al TSV y al
            # comentario `#` del CSV.
            "motivo": motivo if estado == "NO_EVALUABLE" else "",
        })
    return filas


def escribir_csv(filas, out, meta=None):
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    meta = meta or {}
    motivos = defaultdict(int)
    for f in filas:
        if f.get("motivo"):
            motivos[f["motivo"]] += 1
    cab = ("# campana_fp_windows.csv | campaña B6-W (windows-legit-prep, W2) | "
           f"{len(filas)} casos | atribucion=[ini-{cw.ATRIB_PRE_S}s,fin+"
           f"{cw.ATRIB_POST_S}s] | eventos=[ini,fin] | agente={AGENTE_ID}/{AGENTE} | "
           f"plataforma=windows | boveda_version=3 | "
           f"acciones={meta.get('acciones', '—')} | eventos_fuente="
           f"{meta.get('eventos', '—')} | sha256_casos_md={meta.get('sha_md', '—')}")
    if motivos:
        cab += " | no_evaluable_motivos=" + "; ".join(
            f"{n}x {m}" for m, n in sorted(motivos.items()))
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CSV_HEADER)
        for f in filas:
            w.writerow([f[c] for c in CSV_HEADER])
    print(f"-> {out} ({len(filas)} filas)")


# --------------------------------------------------------------------------
# 7) Autotest
# --------------------------------------------------------------------------
def _autotest():
    """Prueba de humo con datos sintéticos (sin VMs, sin red)."""
    with tempfile.TemporaryDirectory() as tmp:
        ev = os.path.join(tmp, "evidencia")
        ini = datetime(2026, 11, 2, 17, 6, 0, tzinfo=timezone.utc)
        casos = [("W-01", ini, ini + timedelta(seconds=60)),
                 ("W-02", ini + timedelta(minutes=9), ini + timedelta(minutes=9, seconds=40))]
        for cid, t0, t1 in casos:
            d = os.path.join(ev, "campana", cid)
            os.makedirs(d)
            open(os.path.join(d, "inicio.txt"), "w").write(fmt_ts(t0) + "\n")
            open(os.path.join(d, "fin.txt"), "w").write(fmt_ts(t1) + "\n")
            open(os.path.join(d, "hecho.txt"), "w").write("RESULTADO=OK\n")
        vent, avisos = leer_marcas(ev)
        assert len(vent) == len(cw.IDS), avisos
        assert vent["W-01"]["ini"] == ini and vent["W-02"]["ini"] == casos[1][1]
        assert vent["W-11"]["ini"] is None
        # marca local (`%DATE%_%TIME%`) con desfase declarado: 18:06 local == 17:06Z
        d = os.path.join(ev, "campana", "W-03")
        os.makedirs(d)
        open(os.path.join(d, "inicio.txt"), "w").write("02/11/2026_18:06:00.12\n")
        open(os.path.join(d, "fin.txt"), "w").write("02/11/2026_18:06:40.12\n")
        open(os.path.join(d, "hecho.txt"), "w").write("RESULTADO=OK\n")
        with_m3, avisos = leer_marcas(ev, parse_offset("+01:00"))
        assert fmt_ts(with_m3["W-03"]["ini"]) == fmt_ts(ini), (with_m3["W-03"], ini)
        sin_off, avisos = leer_marcas(ev)
        assert "W-03" not in sin_off or sin_off["W-03"]["ini"] is None, avisos
        assert any("desfase" in a for a in avisos), avisos

        # archives: dentro / fuera / agente ajeno, y dos ficheros idénticos (dedupe)
        def _ar(path, filas):
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                for rec in filas:
                    fh.write(json.dumps(rec) + "\n")
        a1 = os.path.join(tmp, "archives-02.json")
        a2 = os.path.join(tmp, "archives-copia.json")
        filas = [
            {"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
             "agent": {"id": "002", "name": AGENTE}},
            {"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.500+0000"),
             "agent": {"id": "001", "name": "victima-linux"}},
            {"timestamp": (ini + timedelta(minutes=30)).strftime(
                "%Y-%m-%dT%H:%M:%S.000+0000"),
             "agent": {"id": "002", "name": AGENTE}},
        ]
        _ar(a1, filas)
        _ar(a2, filas)
        paths, notas = ficheros_unicos([a1, a2])
        assert len(paths) == 1, notas
        evc, _ = contar_eventos(paths, vent)
        assert evc["W-01"] == 1 and evc["W-02"] == 0, evc
        # MANIFEST: el duplicado se descarta por `origen`
        man = os.path.join(tmp, "MANIFEST.tsv")
        with open(man, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("fichero\tbytes\tsha256\torigen\n")
            fh.write(f"{os.path.basename(a1)}\t1\tx\tendpoint-002\n")
            fh.write(f"{os.path.basename(a2)}\t1\tx\tDUPLICADO de 1\n")
        paths, notas = ficheros_unicos([tmp], manifest=man)
        assert paths == [a1], (paths, notas)

        # alertas: alias de Sysmon, agente 001 fuera, bordes inclusivos
        al = os.path.join(tmp, "alertas_detalle.csv")
        with open(al, "w", encoding="utf-8", newline="\n") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["timestamp_utc", "agent_id", "agent_name", "rule_id",
                        "rule_level", "win.eventdata.image",
                        "win.eventdata.commandLine", "win.eventdata.currentDirectory",
                        "win.eventdata.user", "win.system.eventID"])
            def _fila(ts, aid, lvl="3"):
                w.writerow([fmt_ts(ts), aid, AGENTE if aid == "002" else "victima-linux",
                            "67027", lvl, r"C:\Windows\System32\cmd.exe",
                            "cmd /c systeminfo", r"C:\Users\angel", "angel", "1"])
            _fila(ini + timedelta(seconds=2), "002")                 # dentro
            _fila(ini + timedelta(seconds=2), "001")                 # otro agente
            _fila(ini - timedelta(seconds=10), "002")                # borde pre: dentro
            _fila(ini - timedelta(seconds=11), "002")                # fuera
            _fila(casos[0][2] + timedelta(seconds=60), "002")        # borde post: dentro
            _fila(casos[0][2] + timedelta(seconds=61), "002")        # fuera
            _fila(casos[1][1] + timedelta(seconds=2), "002", "10")   # nivel 10
        res, meta = contar_alertas([al], vent)
        assert res["W-01"]["alertas"] == 3, res
        assert meta["otros_agentes"] == 1, meta
        assert meta["campos"]["win_command_line"] == 6, meta

        # tabla: SI, NO (nivel >= 7) y NO_EVALUABLE sin alertas
        nacc = {"W-01": 2, "W-02": 1}
        filas = construir_tabla(vent, nacc, evc, res, evidencia=ev)
        assert filas[0]["esperado_cumplido"] == "SI", filas[0]
        assert filas[1]["esperado_cumplido"] == "NO", filas[1]
        filas_sin = construir_tabla(vent, None, None, None, evidencia=ev)
        assert filas_sin[0]["esperado_cumplido"] == "NO_EVALUABLE", filas_sin[0]
        assert filas_sin[0]["n_acciones"] == "" and filas_sin[0]["n_eventos"] == ""
        out = os.path.join(tmp, "campana_fp_windows.csv")
        escribir_csv(filas, out, {"sha_md": "x"})
        assert os.path.isfile(out)
        print("autotest: OK")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Tabla por caso de la campaña B6 de Windows (por marcas).")
    ap.add_argument("--solo-ventanas", action="store_true",
                    help="solo lee las marcas y escribe campana_ventanas_windows.tsv")
    ap.add_argument("--evidencia", default=None,
                    help="carpeta cosechada (contiene campana/W-XX/{inicio,fin,hecho}.txt)")
    ap.add_argument("--ventanas", default=None, help="campana_ventanas_windows.tsv")
    ap.add_argument("--archives", nargs="*", default=None,
                    help="copia de archives (dir con MANIFEST.tsv, o ficheros)")
    ap.add_argument("--manifest", default=None, help="MANIFEST.tsv explícito")
    ap.add_argument("--acciones", default=None,
                    help="export POR ACCIÓN de history_timeline")
    ap.add_argument("--alertas", nargs="*", default=None,
                    help="CSV de alertas, o carpeta con MANIFEST.tsv")
    ap.add_argument("--manifest-alertas", default=None,
                    help="MANIFEST.tsv de los ficheros de alertas")
    ap.add_argument("--desfase-local", default=None,
                    help="desfase de la hora local del invitado (+01:00, -05:00, minutos)")
    ap.add_argument("--formato-fecha", default="dmy", choices=("dmy", "mdy"),
                    help="orden de %DATE% en el invitado (por defecto dd/mm/aaaa)")
    ap.add_argument("--out", default=None, help="fichero de salida")
    ap.add_argument("--agente", default=AGENTE)
    ap.add_argument("--agente-id", default=AGENTE_ID)
    ap.add_argument("--test", action="store_true", help="prueba de humo sintética")
    args = ap.parse_args(argv)

    if args.test:
        return _autotest()

    desfase = None
    if args.desfase_local:
        try:
            desfase = parse_offset(args.desfase_local)
        except ValueError as exc:
            ap.error(str(exc))

    if args.solo_ventanas:
        ev = args.evidencia
        if not ev:
            ap.error("--solo-ventanas necesita --evidencia")
        ventanas, avisos = leer_marcas(ev, desfase, args.formato_fecha)
        out = args.out or os.path.join(cw.dir_campana(), "campana_ventanas_windows.tsv")
        escribir_ventanas(ventanas, out, avisos)
        for f in comprobar_ventanas(ventanas):
            print(f"AVISO: {f}")
        return 0

    vent_path = args.ventanas or os.path.join(cw.dir_campana(),
                                              "campana_ventanas_windows.tsv")
    ventanas = cargar_ventanas(vent_path)
    for f in comprobar_ventanas(ventanas):
        print(f"AVISO: {f}")

    eventos = acciones = alertas = None
    if args.archives:
        paths, notas = ficheros_unicos(args.archives, args.manifest,
                                       (".json", ".json.gz"))
        for n in notas:
            print(f"  {n}")
        eventos, meta_ev = contar_eventos(paths, ventanas, args.agente_id, args.agente)
        print(f"archives: {len(paths)} ficheros únicos · eventos por caso {eventos} · "
              f"{meta_ev}")
    if args.acciones:
        acciones, meta_acc = contar_acciones(args.acciones, ventanas)
        print(f"acciones: columna '{meta_acc['columna']}' · {acciones} "
              f"(sin_timestamp={meta_acc['sin_timestamp']})")
    if args.alertas:
        paths, notas = ficheros_unicos(args.alertas, args.manifest_alertas,
                                       (".csv", ".tsv"))
        for n in notas:
            print(f"  {n}")
        alertas, meta_al = contar_alertas(paths, ventanas, args.agente_id, args.agente)
        print(f"alertas: {len(paths)} ficheros únicos · {meta_al['filas']} filas · "
              f"otros_agentes={meta_al['otros_agentes']} · "
              f"campos_win={meta_al['campos']}")
        print("alertas por caso: " + ", ".join(
            f"{c}={v['alertas']}" for c, v in alertas.items()))

    filas = construir_tabla(ventanas, acciones, eventos, alertas, args.evidencia)
    out = args.out or os.path.join(cw.dir_campana(), "campana_fp_windows.csv")
    md = cw.ruta_md()
    escribir_csv(filas, out, {
        "acciones": os.path.basename(args.acciones) if args.acciones else "—",
        "eventos": "MANIFEST" if (args.manifest or args.manifest_alertas) else (
            ",".join(os.path.basename(p) for p in (args.archives or [])) or "—"),
        "sha_md": cw.sha256_file(md) if os.path.isfile(md) else "—",
    })
    no_ejec = [f["caso"] for f in filas if f["esperado_cumplido"] == "NO_EJECUTADO"]
    no_eval = [f["caso"] for f in filas if f["esperado_cumplido"] == "NO_EVALUABLE"]
    no_cumpl = [f["caso"] for f in filas if f["esperado_cumplido"] == "NO"]
    motivos = defaultdict(int)
    for f in filas:
        if f["esperado_cumplido"] == "NO_EVALUABLE" and f.get("motivo"):
            motivos[f["motivo"]] += 1
    print(f"casos={len(filas)} · NO_EJECUTADO={len(no_ejec)} {no_ejec} · "
          f"NO_EVALUABLE={len(no_eval)} {no_eval} · "
          f"esperado_no={len(no_cumpl)} {no_cumpl}")
    for m, n in sorted(motivos.items()):
        print(f"  motivo NO_EVALUABLE ({n}x): {m}")
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
