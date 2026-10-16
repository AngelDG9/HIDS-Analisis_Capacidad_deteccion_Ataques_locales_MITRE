#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tabla2_ataques.py — T2 (plano ATAQUE) del TFG HIDS (bloque `reencuadre-metrica`).

**Recorte determinista** del corpus congelado (R2 §1.1): los `-Audited.csv` ya traen
`rule_level` + `rs_origen` + `categoria`; T2 **no re-mide**, solo cuenta.

Unidad = **caso** = **ventana canónica** `ATA<NNN>` (decisión D3, R2 §2.7):
`_rev1` si el ATA está en `Hojas/repeticiones.csv`, si no `_iter1`.

Por cada (config × umbral) y cada caso, cuenta las alertas `categoria=deteccion`
del caso con `rs_origen ∈ config` y `rule_level >= umbral` (R2 §2.3, §2.6).
La métrica (fórmulas) vive en `metrica_hids.py`; aquí solo hay recuento.

Salida (formato **largo**, una fila por caso × config × umbral): `Hojas/T2_ataques.csv`
con cabecera `#` (versión de métrica + bóveda + `sha256` de las entradas + config/umbral).

Determinismo (RNF-01): sin reloj, orden estable `(n, config, umbral)`, LF, UTF-8 sin BOM.

Invoca solo lectura del repo; **no** toca el laboratorio.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

DEFAULT_AUDITADO = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_ATA_INDEX = "Hojas/ATA_index.csv"
DEFAULT_REPETICIONES = "Hojas/repeticiones.csv"
DEFAULT_BITACORA = "Bitacora"
DEFAULT_OUT = "Hojas/T2_ataques.csv"
RS_CON_REGLAS_VIRGEN = ("RS1", "RS2")  # RS3=RS4=0 en virgen (active_ruleset.txt)

# META (una por caso; denormalizada en el formato largo) + clave + bloque.
HEADER = [
    "n",
    "ata_id",
    "id_tecnica",
    "subtecnica",
    "tactica",
    "plataforma",
    "paquete_pcap",
    "herramienta",
    "n_acciones_k",
    "n_acciones_m",
    "t0_utc",
    "t1_utc",
    "duracion_s",
    "ventana_canonica",
    "doble_iteracion",
    "analisis_manual",
    "config",
    "umbral",
    "#Alertas",
    "#rule.id_distintos",
    "#Alertas_correlacionadas",
    "#Alertas_correlacionadas_total",
    "#acciones_cubiertas",
    "t_hasta_1a_deteccion_s",
    "primera_evidencia_rule_id",
    "%Deteccion",
    "Detection",
]
BLOQUE_COLS = HEADER[18:]


def _parse_ts(ts: str):
    if not ts:
        return None
    t = ts.strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _pcap_ata_index(path):
    _, rows = TC.read_csv_rows(path, required=["ata_id", "tactica", "tecnica", "artefacto"])
    out = {}
    for r in rows:
        out[r["ata_id"]] = r
    return out


def _repeticiones(path):
    _, rows = TC.read_csv_rows(path, required=["ata_id"])
    return {r["ata_id"].strip() for r in rows}


def _bitacora(ata_id: str, bitacora_dir: str):
    p = os.path.join(bitacora_dir, f"{ata_id}.json")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _iter_de(bita: dict, audited_name: str):
    """Iteración de la bitácora cuyo `audited` casa con `audited_name`."""
    for it in (bita or {}).get("iteraciones", []):
        if os.path.basename(str(it.get("audited", ""))) == audited_name:
            return it
    return None


def _k_m(iter_obj):
    """`n_acciones_k/m` a partir de `metrico_o2` (p. ej. '1/1', '6/7', 'n/a (0/0)')."""
    if not iter_obj:
        return "", ""
    v = str(iter_obj.get("metrico_o2", "") or "")
    if "/" not in v:
        return "", ""
    parts = v.replace("n/a", "").replace("(", "").replace(")", "").strip().split("/")
    if len(parts) != 2:
        return "", ""
    k = parts[0].strip()
    m = parts[1].strip()
    return (k if k.isdigit() else ""), (m if m.isdigit() else "")


def _herramienta(bita: dict) -> str:
    atomic = (bita or {}).get("atomic") or {}
    if str(atomic.get("fuente", "")).upper() == "ART":
        return str(atomic.get("prueba", "") or "")
    return "propio"


def _num(x, default=0.0):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return default


def _bloque(rows, config_rs, umbral):
    """Cuenta el bloque (config × umbral) para un caso."""
    det = []
    for r in rows:
        if r.get("categoria") != M.CATEGORIA_DETECCION:
            continue
        if r.get("rs_origen") not in config_rs:
            continue
        if _num(r.get("rule_level"), -1.0) < umbral:
            continue
        det.append(r)
    rids = sorted({r.get("rule_id", "") for r in det})
    n_det = len(det)
    return {
        "#Alertas": n_det,
        "#rule.id_distintos": len(rids),
        "#Alertas_correlacionadas": len(rids),  # plano ataque: unidad = caso (D2)
        "#Alertas_correlacionadas_total": n_det,  # H (G) = corr (raw)
        "_rids": rids,
        "_det": det,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T2 (ataques) — recorte determinista del corpus.")
    ap.add_argument("--auditado", default=DEFAULT_AUDITADO)
    ap.add_argument("--ata-index", default=DEFAULT_ATA_INDEX)
    ap.add_argument("--repeticiones", default=DEFAULT_REPETICIONES)
    ap.add_argument("--bitacora", default=DEFAULT_BITACORA)
    ap.add_argument("--config", nargs="+", default=list(M.CONFIGS_VIRGEN))
    ap.add_argument("--umbral", nargs="+", type=int, default=list(M.UMBRALES))
    ap.add_argument("--rs-con-reglas", default=",".join(RS_CON_REGLAS_VIRGEN))
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    for c in args.config:
        if c not in M.CONFIGS:
            print(f"ERROR: config desconocida '{c}' (esperado {list(M.CONFIGS)})", file=sys.stderr)
            return 2
    for u in args.umbral:
        if u not in M.UMBRALES:
            print(f"ERROR: umbral no congelado '{u}' (esperado {list(M.UMBRALES)})", file=sys.stderr)
            return 2

    idx = _pcap_ata_index(args.ata_index)
    rep = _repeticiones(args.repeticiones)
    rs_con_reglas = {s.strip() for s in args.rs_con_reglas.split(",") if s.strip()}

    ata_ids = sorted(idx.keys())
    filas = []
    ficheros_cadena = []
    resumen = {}
    for n0, ata in enumerate(ata_ids, start=1):
        win = M.ventana_canonica(ata, rep)
        audited_name = f"{ata}_{win}-Audited.csv"
        audited_path = os.path.join(args.auditado, audited_name)
        if not os.path.isfile(audited_path):
            print(f"ERROR: falta el fichero canónico {audited_path}", file=sys.stderr)
            return 3
        ficheros_cadena.append(audited_path)
        _, rows = TC.read_csv_rows(audited_path)

        bita = _bitacora(ata, args.bitacora) or {}
        it = _iter_de(bita, audited_name) or {}
        k, m = _k_m(it)
        t0 = _parse_ts(it.get("t0", ""))
        t1 = _parse_ts(it.get("t1", ""))
        dur = it.get("duracion_s", "")
        meta = idx[ata]
        tecnica = str(meta.get("tecnica", ""))
        ficha = f"Dataset/Ataques/Resultados/Wazuh/linux/{ata}_meta.md"
        analisis = ficha if os.path.isfile(os.path.join(TC.ROOT, ficha)) else ""
        meta_row = {
            "n": n0,
            "ata_id": ata,
            "id_tecnica": tecnica,
            "subtecnica": str(meta.get("descripcion", "")) if "." in tecnica else "",
            "tactica": str(meta.get("tactica", "")),
            "plataforma": str(bita.get("sistema", "linux")),
            "paquete_pcap": str(meta.get("artefacto", "")),
            "herramienta": _herramienta(bita),
            "n_acciones_k": k,
            "n_acciones_m": m,
            "t0_utc": it.get("t0", ""),
            "t1_utc": it.get("t1", ""),
            "duracion_s": dur,
            "ventana_canonica": win,
            "doble_iteracion": str(bita.get("doble_iteracion", "")),
            "analisis_manual": analisis,
        }

        for cfg in args.config:
            cfg_rs = set(M.CONFIGS[cfg])
            if not cfg_rs.issubset(rs_con_reglas):
                # L8: config con ruleset vacío (RS3/RS4=0 en virgen) -> bloque vacío.
                for u in args.umbral:
                    fila = dict(meta_row, config=cfg, umbral=u)
                    for c in BLOQUE_COLS:
                        fila[c] = ""
                    filas.append(fila)
                    resumen[(cfg, u)] = resumen.get((cfg, u), {"tp": 0, "fn": 0, "vacio": True})
                continue
            for u in args.umbral:
                blk = _bloque(rows, cfg_rs, u)
                tp = 1 if blk["#rule.id_distintos"] > 0 else 0
                det = blk["_det"]
                t_hasta = ""
                primera = ""
                if det:
                    prim = sorted(det, key=lambda r: (r.get("timestamp_utc", ""), r.get("rule_id", "")))[0]
                    primera = prim.get("rule_id", "")
                    ts = _parse_ts(prim.get("timestamp_utc", ""))
                    if ts is not None and t0 is not None:
                        t_hasta = f"{(ts - t0).total_seconds():.3f}"
                fila = dict(meta_row, config=cfg, umbral=u)
                fila.update(
                    {
                        "#Alertas": blk["#Alertas"],
                        "#rule.id_distintos": blk["#rule.id_distintos"],
                        "#Alertas_correlacionadas": blk["#Alertas_correlacionadas"],
                        "#Alertas_correlacionadas_total": blk["#Alertas_correlacionadas_total"],
                        "#acciones_cubiertas": k,
                        "t_hasta_1a_deteccion_s": t_hasta,
                        "primera_evidencia_rule_id": primera,
                        "%Deteccion": M.fmt_det(100.0 if tp else 0.0),
                        "Detection": "SÍ" if tp else "NO",
                    }
                )
                filas.append(fila)
                rr = resumen.setdefault((cfg, u), {"tp": 0, "fn": 0, "vacio": False})
                rr["tp"] += tp
                rr["fn"] += (1 - tp)

    filas.sort(key=lambda f: (int(f["n"]), f["config"], int(f["umbral"])))

    # --- cabecera `#` (sin reloj) ---
    partes = [
        os.path.basename(args.out),
        "TFG HIDS - R2 T2 (plano ataque; ventana canonica; recorte del corpus)",
        f"metrica_version={M.VERSION_METRICA}",
        f"boveda_version={M.VERSION_BOVEDA}",
        f"N_casos={len(ata_ids)}",
        f"config={','.join(args.config)}",
        f"umbral={','.join(str(u) for u in args.umbral)}",
        f"rs_con_reglas={','.join(sorted(rs_con_reglas))}",
        f"ventana_canonica=rev1_si_repeticiones_else_iter1",
        "layout=largo(1 fila por caso x config x umbral; META denormalizada)",
        f"auditado={args.auditado}",
        f"cadena_auditado_sha256={TC.sha256_cadena(ficheros_cadena)}",
        f"ata_index_sha256={TC.sha256_file(os.path.join(TC.ROOT, args.ata_index))}",
        f"repeticiones_sha256={TC.sha256_file(os.path.join(TC.ROOT, args.repeticiones))}",
    ]
    for (cfg, u) in sorted(resumen):
        rr = resumen[(cfg, u)]
        etiqueta = "vacio(L8)" if rr.get("vacio") else f"TP={rr['tp']}/FN={rr['fn']}"
        partes.append(f"{cfg}_N{u}: {etiqueta}")
    partes.append("columnas=" + ",".join(HEADER))
    comment = "# " + " | ".join(partes)

    TC.write_csv(os.path.join(TC.ROOT, args.out), HEADER, filas, comment=comment)
    print(
        f"T2: {len(filas)} filas -> {args.out} | "
        + " ".join(
            f"{cfg}N{u}={resumen[(cfg, u)].get('tp', 0)}/{rr_}"
            for (cfg, u) in sorted(resumen)
            for rr_ in [resumen[(cfg, u)].get("tp", 0) + resumen[(cfg, u)].get("fn", 0)]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
