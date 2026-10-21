#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""contar_denominador.py — cuenta el denominador `M` (eventos decodificados) desde
`archives.json` del manager de Wazuh. Bloque `legitimo-72h` (L1).

**Especificación congelada:** `Soporte/Metrica/metrica_hids.md` §2 — la unidad del
legítimo es **una entrada decodificada** (una línea de `archives.json`), instrumentada
con `<logall_json>yes</logall_json>`. Esta herramienta es **determinista** y de **solo
lectura**; **NO** modifica `extraer_alertas.py` (huella congelada).

Cuenta, para `timestamp ∈ [--desde, --hasta]` (UTC, extremos inclusivos):
  - `total`    : TODAS las líneas decodificadas (incluye el propio manager).
  - `endpoint` : líneas del agente medido (`agent.id == --agent-id` **o**
                 `agent.name == --agent-name`) — el **titular** del denominador.

Acepta uno o varios ficheros (por si `archives.json` rota a ficheros diarios) y
ficheros `.gz`. La cabecera del CSV lleva `metrica_version` / `boveda_version` y el
`sha256` de cada entrada (regla R2 §6.7).

Bloque `legitimo-fix` (aditivo, §8.3):
  · imprime el **rango** `primer_ts .. ultimo_ts` de cada fichero;
  · **DEDUPE por `sha256`** (H-D: `archives.json` es hardlink del día) — `--no-dedupe` lo desactiva;
  · `--estricto` → **exit 3** si dos ficheros ÚNICOS solapan en tiempo;
  · `--manifest FILE` → `fichero<TAB>bytes<TAB>sha256<TAB>primer<TAB>ultimo`.

Uso:
    python3 contar_denominador.py --desde 2026-10-19T00:00:00Z --hasta 2026-10-22T00:00:00Z \
        --out Dataset/Legitimo/legitimo_72h/denominador_M.csv \
        archives.json [archives.json-2 ...]

Modo de prueba trivial (datos sintéticos embebidos, sin ficheros):
    python3 contar_denominador.py --test
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

VERSION_METRICA = 1
VERSION_BOVEDA = 1

CSV_HEADER = [
    "metrica_version",
    "boveda_version",
    "ambito",
    "eventos",
    "primer_ts",
    "ultimo_ts",
]


# --------------------------------------------------------------------------
# Tiempo (mismo criterio que extraer_alertas.py: acepta `Z` y `+0000`)
# --------------------------------------------------------------------------
def parse_ts(value: str) -> datetime:
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
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
# Lectura (soporta .gz) y sha256
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_lines(path):
    """Genera las líneas de una fuente: ruta de fichero (o `.gz`) o lista de líneas."""
    if isinstance(path, (list, tuple)):
        yield from path
        return
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            yield from fh
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            yield from fh


# --------------------------------------------------------------------------
# Conteo
# --------------------------------------------------------------------------
def contar(paths, desde, hasta, agent_id: str, agent_name: str):
    """Devuelve (res, per_file).

    `res` = dict con total/endpoint (eventos, primer_ts, ultimo_ts) y contadores de
    líneas descartadas. `per_file` = lista de (path, m_total, m_endpoint).
    """
    tot = {"eventos": 0, "first": None, "last": None}
    end = {"eventos": 0, "first": None, "last": None}
    no_ts = 0
    bad_json = 0
    vacias = 0
    per_file = []

    def _acc(bucket, ts):
        bucket["eventos"] += 1
        if bucket["first"] is None or ts < bucket["first"]:
            bucket["first"] = ts
        if bucket["last"] is None or ts > bucket["last"]:
            bucket["last"] = ts

    for path in paths:
        ft = fe = 0
        ffirst = flast = None
        for line in _open_lines(path):
            line = line.strip() if isinstance(line, str) else line.decode("utf-8", "replace").strip()
            if not line:
                vacias += 1
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad_json += 1
                continue
            ts_raw = rec.get("timestamp")
            if not ts_raw:
                no_ts += 1
                continue
            try:
                ts = parse_ts(str(ts_raw))
            except ValueError:
                no_ts += 1
                continue
            if desde is not None and ts < desde:
                continue
            if hasta is not None and ts > hasta:
                continue
            _acc(tot, ts)
            ft += 1
            if ffirst is None or ts < ffirst:
                ffirst = ts
            if flast is None or ts > flast:
                flast = ts
            agent = rec.get("agent", {}) or {}
            aid = str(agent.get("id", "") or "")
            anm = str(agent.get("name", "") or "")
            if aid == agent_id or (agent_name and anm == agent_name):
                _acc(end, ts)
                fe += 1
        per_file.append({"path": path, "total": ft, "endpoint": fe, "first": ffirst, "last": flast})

    return {
        "total": tot,
        "endpoint": end,
        "no_ts": no_ts,
        "bad_json": bad_json,
        "vacias": vacias,
    }, per_file


# --------------------------------------------------------------------------
# Dedupe, solapes y manifiesto (bloque `legitimo-fix`, §8.2/§8.3)
# --------------------------------------------------------------------------
def deduplicar(paths):
    """Quita duplicados por `sha256` (H-D: `archives.json` es hardlink del día)."""
    vistos, unicos, dups = {}, [], []
    for p in paths:
        h = sha256_file(p)
        if h in vistos:
            dups.append((p, vistos[h], h))
        else:
            vistos[h] = p
            unicos.append(p)
    return unicos, dups


def solapes(per_file):
    """Pares de ficheros cuyos rangos [primer, ultimo] se solapan (extremos inclusive)."""
    con = [pf for pf in per_file if pf["first"] and pf["last"]]
    out = []
    for i in range(len(con)):
        for j in range(i + 1, len(con)):
            a, b = con[i], con[j]
            if not (a["last"] < b["first"] or b["last"] < a["first"]):
                out.append((a, b))
    return out


def escribir_manifest(per_file, out_path):
    """`manifest.tsv`: fichero, bytes, sha256, primer_ts, ultimo_ts (uno por fichero único)."""
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        fh.write("fichero\tbytes\tsha256\tprimer\tultimo\n")
        for pf in per_file:
            fh.write("{}\t{}\t{}\t{}\t{}\n".format(
                os.path.basename(pf["path"]),
                os.path.getsize(pf["path"]),
                sha256_file(pf["path"]),
                fmt_ts(pf["first"]) if pf["first"] else "",
                fmt_ts(pf["last"]) if pf["last"] else "",
            ))


# --------------------------------------------------------------------------
# Salida
# --------------------------------------------------------------------------
def escribir_csv(res, per_file, paths, out_path, desde, hasta, agent_id, agent_name,
                 metrica_version=VERSION_METRICA, boveda_version=VERSION_BOVEDA):
    hashes = ",".join(f"{sha256_file(p)}:{os.path.basename(p)}" for p in paths)
    comment = (
        f"# contar_denominador.py | metrica_version={metrica_version} "
        f"boveda_version={boveda_version} | "
        f"desde={fmt_ts(desde) if desde else 'n/a'} hasta={fmt_ts(hasta) if hasta else 'n/a'} | "
        f"agente={agent_id}/{agent_name} | ficheros={len(paths)} | sha256_entradas={hashes}"
    )
    rows = [
        [metrica_version, boveda_version, "total",
         res["total"]["eventos"],
         fmt_ts(res["total"]["first"]) if res["total"]["first"] else "",
         fmt_ts(res["total"]["last"]) if res["total"]["last"] else ""],
        [metrica_version, boveda_version, "endpoint",
         res["endpoint"]["eventos"],
         fmt_ts(res["endpoint"]["first"]) if res["endpoint"]["first"] else "",
         fmt_ts(res["endpoint"]["last"]) if res["endpoint"]["last"] else ""],
    ]
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(comment + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CSV_HEADER)
        w.writerows(rows)
    return comment


# --------------------------------------------------------------------------
# Modo de prueba trivial (datos sintéticos embebidos)
# --------------------------------------------------------------------------
def run_test() -> int:
    sample = [
        '{"timestamp":"2026-10-19T00:00:01.000+0000","agent":{"id":"001","name":"victima-linux"},"full_log":"a"}',   # total+endpoint
        '{"timestamp":"2026-10-19T01:30:00.000+0000","agent":{"id":"000","name":"wazuh-server"},"full_log":"b"}',    # total
        '{"timestamp":"2026-10-22T00:00:00.000+0000","agent":{"id":"001","name":"victima-linux"},"full_log":"c"}',   # borde t1 (inclusive)
        '{"timestamp":"2026-10-22T00:00:01.000+0000","agent":{"id":"001","name":"victima-linux"},"full_log":"d"}',   # fuera (después de t1)
        '{"timestamp":"2026-10-18T23:59:59.000+0000","agent":{"id":"001","name":"victima-linux"},"full_log":"e"}',  # fuera (antes de t0)
        '{"timestamp":"2026-10-19T02:00:00.000+0000","agent":{"id":"001","name":"victima-linux"},"full_log":"f"}',
        '{"agent":{"id":"001"},"full_log":"sin_ts"}',                                                                # sin timestamp
        'no es json',                                                                                                # no-json
    ]
    desde = parse_ts("2026-10-19T00:00:00Z")
    hasta = parse_ts("2026-10-22T00:00:00Z")
    res, _ = contar([sample], desde, hasta, "001", "victima-linux")
    ok = (
        res["total"]["eventos"] == 4
        and res["endpoint"]["eventos"] == 3
        and res["no_ts"] == 1
        and res["bad_json"] == 1
        and fmt_ts(res["endpoint"]["first"]) == "2026-10-19T00:00:01Z"
        and fmt_ts(res["endpoint"]["last"]) == "2026-10-22T00:00:00Z"
    )
    print("# MODO TEST (sintético; no lee ficheros)")
    print(f"# total={res['total']['eventos']} endpoint={res['endpoint']['eventos']} "
          f"no_ts={res['no_ts']} bad_json={res['bad_json']}")
    print(f"# test: {'OK' if ok else 'FALLO'}", file=sys.stderr)
    return 0 if ok else 1


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cuenta el denominador M desde archives.json (Wazuh).")
    ap.add_argument("files", nargs="*", help="archives.json (y rotaciones); acepta .gz")
    ap.add_argument("--desde", help="inicio de ventana UTC ISO8601 (inclusive)")
    ap.add_argument("--hasta", help="fin de ventana UTC ISO8601 (inclusive)")
    ap.add_argument("--agent-id", default="001")
    ap.add_argument("--agent-name", default="victima-linux")
    ap.add_argument("--metrica-version", type=int, default=VERSION_METRICA)
    ap.add_argument("--boveda-version", type=int, default=VERSION_BOVEDA)
    ap.add_argument("--out", default=None, help="CSV de salida")
    ap.add_argument("--manifest", default=None, help="TSV con fichero/bytes/sha256/primer/ultimo")
    ap.add_argument("--estricto", action="store_true",
                    help="falla (exit 3) si dos ficheros ÚNICOS solapan en tiempo")
    ap.add_argument("--no-dedupe", action="store_true", help="no descartar duplicados por sha256")
    ap.add_argument("--test", action="store_true", help="modo de prueba trivial")
    args = ap.parse_args(argv)

    if args.test:
        return run_test()
    if not args.files:
        ap.error("faltan ficheros (o usa --test)")
    for p in args.files:
        if not os.path.isfile(p):
            print(f"ERROR: no existe {p}", file=sys.stderr)
            return 2

    desde = parse_ts(args.desde) if args.desde else None
    hasta = parse_ts(args.hasta) if args.hasta else None
    if desde and hasta and hasta < desde:
        ap.error("--hasta es anterior a --desde")

    # 1) DEDUPE por sha256 (H-D): el mismo contenido (hardlink) se cuenta UNA vez
    if args.no_dedupe:
        unicos, dups = list(args.files), []
    else:
        unicos, dups = deduplicar(args.files)
    for p, orig, h in dups:
        print(f"  DUPLICADO descartado: {os.path.basename(p)} (sha256={h[:12]} == {os.path.basename(orig)})")

    res, per_file = contar(unicos, desde, hasta, args.agent_id, args.agent_name)

    # 2) rango por fichero (para ver de un vistazo la cobertura y los bordes)
    for pf in per_file:
        r = (f"{fmt_ts(pf['first'])} .. {fmt_ts(pf['last'])}") if pf["first"] else "sin eventos en ventana"
        print(f"  {os.path.basename(pf['path'])}: total={pf['total']} endpoint={pf['endpoint']} rango={r}")
    print(f"M total={res['total']['eventos']} endpoint={res['endpoint']['eventos']} "
          f"no_ts={res['no_ts']} bad_json={res['bad_json']} ficheros={len(unicos)} duplicados={len(dups)}")
    if res["endpoint"]["first"]:
        print(f"cobertura endpoint: {fmt_ts(res['endpoint']['first'])} .. {fmt_ts(res['endpoint']['last'])}")

    # 3) --estricto: cero solapes entre ficheros únicos (regla de borde §8.2)
    if args.estricto:
        malos = solapes(per_file)
        if malos:
            print("ERROR --estricto: hay ficheros que SOLAPAN en tiempo:", file=sys.stderr)
            for a, b in malos:
                print(f"  {os.path.basename(a['path'])} [{fmt_ts(a['first'])}..{fmt_ts(a['last'])}] "
                      f"x {os.path.basename(b['path'])} [{fmt_ts(b['first'])}..{fmt_ts(b['last'])}]",
                      file=sys.stderr)
            return 3
        print("--estricto: sin solapes entre ficheros únicos")

    if args.manifest:
        escribir_manifest(per_file, args.manifest)
        print(f"-> {args.manifest}")

    if args.out:
        escribir_csv(res, per_file, unicos, args.out, desde, hasta, args.agent_id, args.agent_name,
                     args.metrica_version, args.boveda_version)
        print(f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
