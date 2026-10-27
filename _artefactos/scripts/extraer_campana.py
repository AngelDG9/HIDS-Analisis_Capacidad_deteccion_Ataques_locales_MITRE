#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_campana.py — tabla por caso de la campaña `B6` (bloque `legitimo-v3`, T2).

**No ejecuta nada**: lee las **marcas** de la campaña y los productos de la extracción
y escribe `campana_fp.csv` con **9 columnas** (plan §5.2.6, §8, CA-16):

```
caso · ini · fin · nº acciones · nº eventos en la ventana · alertas · rule_id · level · esperado_cumplido
```

Cómo se cuenta cada columna (mismas reglas que el plan §8):

| Columna | Fuente | Ventana |
|---|---|---|
| `ini`, `fin` | `campana_fp/C-XX/{inicio,fin}.txt` (22 marcas UTC) | — |
| `nº acciones` | export **por acción** de `history_timeline` (`--acciones`, `createdutc`) | `[ini, fin]` |
| `nº eventos` | copia de `archives` de Wazuh, **agente `001`** | `[ini, fin]` |
| `alertas` | `alertas_detalle.csv` (`extraer_alertas.py`) | `[ini − 10 s, fin + 60 s]` |
| `rule_id` / `level` | del mismo cruce de alertas | idem |
| `esperado_cumplido` | `SI` si `80792` aparece y `level < 7`; `NO` si no; `NO_EJECUTADO` sin marcas o sin `hecho.txt` | — |

**Dedupe:** si la copia de `archives` trae `MANIFEST.tsv` (formato de
`exportar_denominador.sh`: `fichero · bytes · sha256 · origen`), se leen **solo** las
filas cuyo `origen` no sea `DUPLICADO…` (los hardlinks de `archives.json` comparten
`sha256`). Sin manifiesto, se deduplica por `sha256` en memoria.

**Acciones:** el export por acción se obtiene del PostgreSQL del host (una fila por
acción), p. ej.:

```sql
\\copy (select to_char(createdutc,'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') as createdutc,
               coalesce(handler,'') as handler, coalesce(command,'') as command
        from history_timeline
        where createdutc >= '<t0>' and createdutc < '<t1>'
        order by createdutc) to 'ghosts_acciones_detalle.csv' csv header
```

El `ghosts_acciones.csv` **agregado** (por handler y por hora) **no sirve** aquí: no
tiene marcas de tiempo por acción. Si se pasa, el runner lo dice y deja `nº acciones`
vacío (no inventa la cifra).

Uso:
    python extraer_campana.py --solo-ventanas --evidencia <cosecha> --out campana_ventanas.tsv
    python extraer_campana.py --ventanas campana_ventanas.tsv --archives <copia> \\
        --acciones ghosts_acciones_detalle.csv --alertas alertas_detalle.csv \\
        --evidencia <cosecha> --out campana_fp.csv
    python extraer_campana.py --test
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
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campana  # noqa: E402
import contar_denominador as cd  # noqa: E402  (parse_ts / sha256 / lectura .gz)

CSV_HEADER = ["caso", "ini", "fin", "n_acciones", "n_eventos", "alertas",
              "rule_id", "level", "esperado_cumplido"]
TSV_HEADER = ["caso", "ini", "fin"]

AGENTE = "victima-linux"
AGENTE_ID = "001"
RE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COLS_TS_ACCIONES = ("createdutc", "created_utc", "timestamp", "ts", "fecha", "utc")
COLS_TS_ALERTAS = ("timestamp_utc", "timestamp", "ts")


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


# --------------------------------------------------------------------------
# 1) Ventanas: marcas `inicio.txt` / `fin.txt`
# --------------------------------------------------------------------------
def leer_marcas(evidencia: str):
    """Devuelve ({caso: {"ini": dt|None, "fin": dt|None}}, [avisos]).

    Acepta las dos formas en que la cosecha puede dejar las marcas:
    `…/campana_fp/C-01/inicio.txt` (carpeta por caso) y `…/C-01_inicio.txt`
    (plana), que es como las lista el plan §8 (`evidencia/*.txt`).
    """
    if not os.path.isdir(evidencia):
        raise SystemExit(f"ERROR: no existe la carpeta de evidencia {evidencia}")
    out, avisos = {}, []

    def _anota(caso, clave, txt, origen):
        try:
            dt = parse_iso(txt)
        except ValueError:
            avisos.append(f"{caso}: {origen} no es UTC ISO8601 ({txt!r})")
            return
        reg = out.setdefault(caso, {"ini": None, "fin": None})
        if reg[clave] is not None and reg[clave] != dt:
            avisos.append(f"{caso}: {clave} repetido con distinto valor "
                          f"({fmt_ts(reg[clave])} vs {fmt_ts(dt)})")
        reg[clave] = dt

    for raiz, dirs, files in os.walk(evidencia):
        dirs.sort()
        for d in dirs:
            if re.fullmatch(r"C-\d{2}", d):
                carpeta = os.path.join(raiz, d)
                for clave, nombre in (("ini", "inicio.txt"), ("fin", "fin.txt")):
                    p = os.path.join(carpeta, nombre)
                    if os.path.isfile(p):
                        _anota(d, clave, open(p, encoding="utf-8",
                                             errors="replace").read().strip(), nombre)
        for f in sorted(files):
            m = re.fullmatch(r"(C-\d{2})[_-](inicio|fin)\.txt", f)
            if m:
                _anota(m.group(1), "ini" if m.group(2) == "inicio" else "fin",
                       open(os.path.join(raiz, f), encoding="utf-8",
                            errors="replace").read().strip(), f)

    vistos = 0
    for caso in list(out):
        reg = out[caso]
        for clave, nombre in (("ini", "inicio.txt"), ("fin", "fin.txt")):
            if reg[clave] is None:
                avisos.append(f"{caso}: falta {nombre}")
        if reg["ini"] and reg["fin"] and reg["fin"] < reg["ini"]:
            avisos.append(f"{caso}: fin anterior a inicio")
        if reg["ini"] or reg["fin"]:
            vistos += 1
        else:
            out.pop(caso)
    if not out:
        raise SystemExit(f"ERROR: no hay marcas C-XX en {evidencia}")
    avisos.append(f"marcas encontradas: {vistos} casos (se esperan {len(campana.IDS)})")
    for cid in campana.IDS:
        if cid not in out:
            avisos.append(f"{cid}: sin marcas (NO_EJECUTADO)")
    return dict(sorted(out.items())), avisos


def escribir_ventanas(ventanas, out, avisos=()):
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    n_marcas = sum(1 for r in ventanas.values() for k in ("ini", "fin") if r[k])
    cab = (f"# campana_ventanas.tsv | {n_marcas} marcas | "
           f"fuente=evidencia/campana_fp/C-*/{{inicio,fin}}.txt | "
           f"casos={len(ventanas)} | plan=5.2.6,8")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(TSV_HEADER)
        for cid, r in ventanas.items():
            w.writerow([cid, fmt_ts(r["ini"]) if r["ini"] else "",
                        fmt_ts(r["fin"]) if r["fin"] else ""])
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
        raise SystemExit("ERROR: campana_ventanas.tsv debe tener caso/ini/fin")
    out = {}
    for r in rd:
        cid = (r["caso"] or "").strip()
        if not cid:
            continue
        ini = parse_iso(r["ini"]) if (r["ini"] or "").strip() else None
        fin = parse_iso(r["fin"]) if (r["fin"] or "").strip() else None
        if ini and fin and fin < ini:
            raise SystemExit(f"ERROR: {cid}: fin anterior a inicio")
        out[cid] = {"ini": ini, "fin": fin}
    return dict(sorted(out.items()))


def comprobar_ventanas(ventanas):
    """Fallos de coherencia: 22 marcas, sin solapes de atribución, orden correcto."""
    fallos, completas = [], []
    for cid, r in ventanas.items():
        if r["ini"] and r["fin"]:
            completas.append((r["ini"], r["fin"], cid))
        else:
            fallos.append(f"{cid}: marcas incompletas (NO_EJECUTADO)")
    completas.sort()
    for (ini1, fin1, c1), (ini2, _fin2, c2) in zip(completas, completas[1:]):
        a1 = ini1 - timedelta(seconds=campana.ATRIB_PRE_S)
        b1 = fin1 + timedelta(seconds=campana.ATRIB_POST_S)
        a2 = ini2 - timedelta(seconds=campana.ATRIB_PRE_S)
        if a2 <= b1:
            fallos.append(f"ventanas de atribución solapadas: {c1} y {c2}")
        if ini2 - fin1 < timedelta(seconds=campana.SEPARACION_MIN_S):
            fallos.append(f"separación < {campana.SEPARACION_MIN_S} s entre {c1} y {c2}")
        if a1 > b1:
            fallos.append(f"{c1}: ventana de atribución invertida")
    return fallos


# --------------------------------------------------------------------------
# 2) Eventos de `archives` (agente 001) con dedupe por MANIFEST
# --------------------------------------------------------------------------
def _leer_manifest(path: str):
    """Filas del MANIFEST de `exportar_denominador.sh` (TSV). Devuelve [dict]."""
    filas = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        rd = csv.DictReader(fh, delimiter="\t")
        if not rd.fieldnames:
            return filas
        for r in rd:
            filas.append({k.strip(): (v or "").strip() for k, v in r.items() if k})
    return filas


def ficheros_archivo(archives, manifest=None):
    """Ficheros de `archives` a leer, **sin duplicados**.

    Si hay `MANIFEST.tsv` (o se pasa `--manifest`), manda el manifiesto: se descartan
    las filas cuyo `origen` empieza por `DUPLICADO` (hardlinks de `archives.json`).
    Si no, se deduplica por `sha256`.
    """
    paths, notas = [], []
    entradas = list(archives or [])
    if len(entradas) == 1 and os.path.isdir(entradas[0]):
        d = entradas[0]
        man = manifest or os.path.join(d, "MANIFEST.tsv")
        if os.path.isfile(man):
            manifest = man
        else:
            entradas = sorted(glob.glob(os.path.join(d, "*.json")) +
                              glob.glob(os.path.join(d, "*.json.gz")))
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
            if not (p.endswith(".json") or p.endswith(".json.gz")):
                notas.append(f"manifiesto: {f} no es JSON (omitido)")
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
        raise SystemExit("ERROR: no hay ficheros de archives que leer")
    return paths, notas


def contar_eventos(paths, ventanas, agent_id=AGENTE_ID, agent_name=AGENTE):
    """Cuenta eventos de `archives` por caso, en una sola pasada."""
    pares = sorted((r["ini"], r["fin"], cid) for cid, r in ventanas.items()
                   if r["ini"] and r["fin"])
    inicios = [p[0] for p in pares]
    cuenta = {cid: 0 for cid, _r in ventanas.items()}
    no_ts = bad = 0
    for path in paths:
        for linea in _leer_lineas(path):
            linea = linea.strip() if isinstance(linea, str) else linea.decode("utf-8", "replace").strip()
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
            if str(ag.get("id", "") or "") != agent_id and \
                    str(ag.get("name", "") or "") != agent_name:
                continue
            cuenta[cid] += 1
    return cuenta, {"sin_timestamp": no_ts, "json_invalido": bad}


# --------------------------------------------------------------------------
# 3) Acciones de `history_timeline` (export POR ACCIÓN)
# --------------------------------------------------------------------------
def _sniff_delimitador(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for linea in fh:
            if linea.startswith("#") or not linea.strip():
                continue
            return "\t" if linea.count("\t") > linea.count(",") else ","
    return ","


def contar_acciones(path, ventanas):
    """Cuenta acciones por caso. `None` si el fichero no es un export por acción."""
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: no existe {path}")
    delim = _sniff_delimitador(path)
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    rd = csv.DictReader(lineas, delimiter=delim)
    campos = [c.strip().lower() for c in (rd.fieldnames or [])]
    col = next((c for c in COLS_TS_ACCIONES if c in campos), None)
    if col is None:
        raise SystemExit(
            f"ERROR: {path} no tiene columna de tiempo por acción "
            f"({campos}). El `ghosts_acciones.csv` agregado (tipo/clave/acciones) NO sirve: "
            f"hace falta el export por acción de `history_timeline` (ver docstring).")
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
# 4) Alertas (`alertas_detalle.csv`) con atribución [ini−10 s, fin+60 s]
# --------------------------------------------------------------------------
def contar_alertas(path, ventanas, agent_name=AGENTE,
                   pre_s=campana.ATRIB_PRE_S, post_s=campana.ATRIB_POST_S):
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: no existe {path}")
    delim = _sniff_delimitador(path)
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    rd = csv.DictReader(lineas, delimiter=delim)
    campos = [c.strip() for c in (rd.fieldnames or [])]
    lower = [c.lower() for c in campos]
    col_ts = next((c for c in COLS_TS_ALERTAS if c in lower), None)
    if col_ts is None:
        raise SystemExit(f"ERROR: {path} no tiene columna de tiempo ({campos})")
    col_ag = next((c for c in ("agent_name", "agente") if c in lower), None)
    col_rule = next((c for c in ("rule_id", "ruleid") if c in lower), None)
    col_lvl = next((c for c in ("rule_level", "level", "nivel") if c in lower), None)
    if col_rule is None or col_lvl is None:
        raise SystemExit(f"ERROR: {path} no tiene rule_id/rule_level ({campos})")
    i_ts, i_ag = lower.index(col_ts), (lower.index(col_ag) if col_ag else None)
    i_rule, i_lvl = lower.index(col_rule), lower.index(col_lvl)
    pares = sorted((r["ini"] - timedelta(seconds=pre_s),
                    r["fin"] + timedelta(seconds=post_s), cid)
                   for cid, r in ventanas.items() if r["ini"] and r["fin"])
    inicios = [p[0] for p in pares]
    res = {cid: {"alertas": 0, "rules": set(), "levels": []} for cid, _r in ventanas.items()}
    for r in rd:
        vals = list(r.values())
        if i_ag is not None and (vals[i_ag] or "").strip() != agent_name:
            continue
        raw = (vals[i_ts] or "").strip()
        if not raw:
            continue
        try:
            ts = cd.parse_ts(raw)
        except ValueError:
            continue
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
    return res


# --------------------------------------------------------------------------
# 5) Tabla final
# --------------------------------------------------------------------------
def _evidencia_ok(evidencia, cid):
    if not evidencia:
        return None
    if os.path.isfile(os.path.join(evidencia, "campana_fp", cid, "hecho.txt")):
        return True
    for raiz, _dirs, files in os.walk(evidencia):
        if os.path.basename(raiz) == cid and "hecho.txt" in files:
            return True
        if f"{cid}_hecho.txt" in files:
            return True
    return False


def construir_tabla(ventanas, acciones=None, eventos=None, alertas=None,
                    evidencia=None, umbral_n7=campana.UMBRAL_N7, rule_exec=campana.RULE_EXEC):
    filas = []
    for cid, r in ventanas.items():
        ini, fin = r["ini"], r["fin"]
        al = (alertas or {}).get(cid, {"alertas": 0, "rules": set(), "levels": []})
        rules = sorted(x for x in al["rules"] if x)
        levels = al["levels"]
        level = max(levels) if levels else 0
        hecho = _evidencia_ok(evidencia, cid)
        if not ini or not fin:
            estado = "NO_EJECUTADO"
        elif hecho is False:
            estado = "NO_EJECUTADO"
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
            "alertas": str(al["alertas"]),
            "rule_id": ";".join(rules),
            "level": str(level),
            "esperado_cumplido": estado,
        })
    return filas


def escribir_csv(filas, out, meta=None):
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    meta = meta or {}
    cab = ("# campana_fp.csv | campaña B6 | "
           f"{len(filas)} casos | atribucion=[ini-{campana.ATRIB_PRE_S}s,fin+"
           f"{campana.ATRIB_POST_S}s] | eventos=[ini,fin] | agente={AGENTE_ID}/{AGENTE} | "
           f"acciones={meta.get('acciones', '—')} | eventos_fuente={meta.get('eventos', '—')} | "
           f"sha256_casos_md={meta.get('sha_md', '—')}")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CSV_HEADER)
        for f in filas:
            w.writerow([f[c] for c in CSV_HEADER])
    print(f"-> {out} ({len(filas)} filas)")


# --------------------------------------------------------------------------
# 6) Autotest
# --------------------------------------------------------------------------
def _autotest():
    """Prueba de humo con datos sintéticos (sin VMs, sin red)."""
    with tempfile.TemporaryDirectory() as tmp:
        ev = os.path.join(tmp, "evidencia")
        base = os.path.join(ev, "campana_fp")
        ini = datetime(2026, 11, 2, 17, 6, 0, tzinfo=timezone.utc)
        for k, cid in enumerate(("C-01", "C-02")):
            d = os.path.join(base, cid)
            os.makedirs(d)
            t0 = ini + timedelta(minutes=9 * k)
            open(os.path.join(d, "inicio.txt"), "w").write(fmt_ts(t0) + "\n")
            open(os.path.join(d, "fin.txt"), "w").write(fmt_ts(t0 + timedelta(seconds=30)) + "\n")
            open(os.path.join(d, "hecho.txt"), "w").write("RESULTADO=OK\n")
        vent, avisos = leer_marcas(ev)
        assert len(vent) == 2, avisos
        # archives: uno dentro, otro fuera y un duplicado por sha256
        a1 = os.path.join(tmp, "ossec-archive-02.json")
        a2 = os.path.join(tmp, "archives.json")
        linea = json.dumps({"timestamp": ini.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                            "agent": {"id": "001", "name": AGENTE}})
        open(a1, "w").write(linea + "\n")
        open(a2, "w").write(linea + "\n")          # mismo contenido => mismo sha256
        paths, notas = ficheros_archivo([a1, a2])
        assert len(paths) == 1, notas
        evc, _ = contar_eventos(paths, vent)
        assert evc["C-01"] == 1 and evc["C-02"] == 0, evc
        # acciones por acción
        acc = os.path.join(tmp, "acciones.csv")
        with open(acc, "w", encoding="utf-8", newline="\n") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["createdutc", "handler", "command"])
            w.writerow([fmt_ts(ini + timedelta(seconds=5)), "h", "c"])
            w.writerow([fmt_ts(ini + timedelta(seconds=40)), "h", "c"])
        nacc, _ = contar_acciones(acc, vent)
        assert nacc["C-01"] == 1 and nacc["C-02"] == 0, nacc
        # alertas
        al = os.path.join(tmp, "alertas_detalle.csv")
        with open(al, "w", encoding="utf-8", newline="\n") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["timestamp_utc", "agent_name", "rule_id", "rule_level"])
            w.writerow([fmt_ts(ini + timedelta(seconds=2)), AGENTE, "80792", "3"])
            w.writerow([fmt_ts(ini + timedelta(seconds=2)), "otro", "80792", "3"])
            w.writerow([fmt_ts(ini + timedelta(minutes=9, seconds=2)), AGENTE, "80792", "3"])
        res = contar_alertas(al, vent)
        assert res["C-01"]["alertas"] == 1, res
        assert res["C-02"]["alertas"] == 1, res
        filas = construir_tabla(vent, nacc, evc, res, evidencia=ev)
        assert filas[0]["esperado_cumplido"] == "SI", filas[0]
        assert filas[1]["esperado_cumplido"] == "SI", filas[1]
        out = os.path.join(tmp, "campana_fp.csv")
        escribir_csv(filas, out, {"sha_md": campana.sha256_file(campana.ruta_md())})
        assert os.path.isfile(out)
        print("autotest: OK")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Tabla por caso de la campaña B6 (por marcas).")
    ap.add_argument("--solo-ventanas", action="store_true",
                    help="solo lee las marcas y escribe campana_ventanas.tsv")
    ap.add_argument("--evidencia", default=None,
                    help="carpeta cosechada (contiene campana_fp/C-XX/{inicio,fin,hecho}.txt)")
    ap.add_argument("--ventanas", default=None, help="campana_ventanas.tsv")
    ap.add_argument("--archives", nargs="*", default=None,
                    help="copia de archives (dir con MANIFEST.tsv, o ficheros)")
    ap.add_argument("--manifest", default=None, help="MANIFEST.tsv explícito")
    ap.add_argument("--acciones", default=None, help="export POR ACCIÓN de history_timeline")
    ap.add_argument("--alertas", default=None, help="alertas_detalle.csv")
    ap.add_argument("--out", default=None, help="fichero de salida")
    ap.add_argument("--agente", default=AGENTE)
    ap.add_argument("--agente-id", default=AGENTE_ID)
    ap.add_argument("--test", action="store_true", help="prueba de humo con datos sintéticos")
    args = ap.parse_args(argv)

    if args.test:
        return _autotest()

    vent_path = args.ventanas
    if args.solo_ventanas:
        ev = args.evidencia
        if not ev:
            ap.error("--solo-ventanas necesita --evidencia")
        ventanas, avisos = leer_marcas(ev)
        out = args.out or os.path.join(campana.dir_campana(), "campana_ventanas.tsv")
        escribir_ventanas(ventanas, out, avisos)
        for f in comprobar_ventanas(ventanas):
            print(f"AVISO: {f}")
        return 0

    if not vent_path:
        vent_path = os.path.join(campana.dir_campana(), "campana_ventanas.tsv")
    ventanas = cargar_ventanas(vent_path)
    fallos = comprobar_ventanas(ventanas)
    for f in fallos:
        print(f"AVISO: {f}")

    eventos = acciones = alertas = None
    if args.archives:
        paths, notas = ficheros_archivo(args.archives, args.manifest)
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
        alertas = contar_alertas(args.alertas, ventanas, args.agente)
        print("alertas: " + ", ".join(f"{c}={v['alertas']}" for c, v in alertas.items()))

    filas = construir_tabla(ventanas, acciones, eventos, alertas, args.evidencia)
    out = args.out or os.path.join(campana.dir_campana(), "campana_fp.csv")
    escribir_csv(filas, out, {
        "acciones": os.path.basename(args.acciones) if args.acciones else "—",
        "eventos": "MANIFEST" if args.manifest else (",".join(
            os.path.basename(p) for p in (args.archives or [])) or "—"),
        "sha_md": campana.sha256_file(campana.ruta_md()) if os.path.isfile(
            campana.ruta_md()) else "—",
    })
    no_ejec = [f["caso"] for f in filas if f["esperado_cumplido"] == "NO_EJECUTADO"]
    no_cumpl = [f["caso"] for f in filas if f["esperado_cumplido"] == "NO"]
    print(f"casos={len(filas)} · NO_EJECUTADO={len(no_ejec)} {no_ejec} · "
          f"esperado_no={len(no_cumpl)} {no_cumpl}")
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
