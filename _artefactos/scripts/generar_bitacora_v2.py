#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generar_bitacora_v2.py - Bitacora de la campana v2 (lanzador local) para `tabla2_ataques.py --bitacora`.

`tabla2_ataques.py` saca t0/t1/duracion/herramienta/doble_iteracion de `Bitacora/ATA*.json` casando por el nombre del
`-Audited.csv`. Solo existia la bitacora v1: apuntar T2 a `*_v2` sin esto da tiempos de la v1. Aqui se parte de la bitacora
v1 (metadatos ESTATICOS del caso: tecnica, tactica, fuente, esperado...) y se SUSTITUYEN las iteraciones por las reales de la
v2 (t0/t1 del indice de la campana). `metrico_o2` (k/m de señales declaradas) NO se recalcula: queda vacio y se declara.

Uso: python generar_bitacora_v2.py --so linux|windows
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import copy
import csv
import datetime as dt
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", choices=("linux", "windows"), required=True)
    ap.add_argument("--base", default="", help="carpeta de la campana v2 (por defecto Dataset/.../<so>_v2)")
    ap.add_argument("--v1-dir", default="", help="carpeta con la Bitacora v1 (por defecto <repo>/Bitacora)")
    a = ap.parse_args()
    base = a.base or os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", a.so + "_v2")
    ultimo = {}
    for r in csv.DictReader(open(os.path.join(base, "windows_index.csv"), encoding="utf-8")):
        ultimo[r["tag"]] = r
    por_ata = {}
    for tag, r in ultimo.items():
        if r["estado"] == "OK":
            por_ata.setdefault(r["ata"], []).append(r)
    out = os.path.join(base, "Bitacora")
    os.makedirs(out, exist_ok=True)
    n = 0
    for ata, filas in sorted(por_ata.items()):
        p1 = os.path.join(a.v1_dir or os.path.join(REPO, "Bitacora"), ata + ".json")
        j = copy.deepcopy(json.load(open(p1, encoding="utf-8"))) if os.path.isfile(p1) else {"ata_id": ata, "sistema": a.so}
        its = []
        for r in sorted(filas, key=lambda x: (x["variante"] == "rev", int(x["iter"]))):
            t0 = dt.datetime.strptime(r["t0"], "%Y-%m-%dT%H:%M:%SZ")
            t1 = dt.datetime.strptime(r["t1"], "%Y-%m-%dT%H:%M:%SZ")
            its.append({
                "iter": int(r["iter"]), "variante": r["variante"], "t0": r["t0"], "t1": r["t1"],
                "duracion_s": int((t1 - t0).total_seconds()),
                "snapshot": "lab-listo" if a.so == "linux" else "lab-listo-windows-ataques-gui",
                "detalle": "Dataset/Ataques/Resultados/Wazuh/%s_v2/CSV/%s-Detalle.csv" % (a.so, r["tag"]),
                "audited": "Dataset/Ataques/Resultados/Wazuh/%s_v2/Auditado/%s-Audited.csv" % (a.so, r["tag"]),
                "metrico_o2": "",
                "lanzador": "local (systemd-run)" if a.so == "linux" else "local (tarea programada)",
                "version_datos": 2,
            })
        j["iteraciones"] = its
        j["bitacora_origen"] = "generada por generar_bitacora_v2.py a partir de Bitacora/%s.json (metadatos) y del indice v2 (iteraciones)" % ata
        with open(os.path.join(out, ata + ".json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(j, fh, ensure_ascii=False, indent=1)
        n += 1
    print("bitacoras v2 escritas: %d en %s" % (n, out))


if __name__ == "__main__":
    main()
