#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""reextraer_detalle_windows_v2.py - regenera los `-Detalle.csv` de la campana Windows v2 con `rs_origen` correcto.

La extraccion original corrio en el host SIN `--ruleset-dir`, asi que `rs_origen` salio `UNKNOWN` y ninguna fila contaba para
C0/C1 (la v1 trae `RS1`). Aqui se vuelve a extraer desde las alertas CRUDAS guardadas (`<raw>/<tag>_alerts_002.jsonl.gz`) usando
una COPIA del ruleset del manager (`ruleset/rules` y `etc/rules`, sha256 en `ruleset_manager/rules.tgz`).
Uso: python reextraer_detalle_windows_v2.py --ruleset-dir <dir>/ruleset/rules --etc-rules-dir <dir>/etc/rules
"""
import argparse
import csv
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "windows_v2"))
    ap.add_argument("--raw", default=r"D:\TFG-VMs\ataques-windows-v2-2026-11-20\raw")
    ap.add_argument("--ruleset-dir", required=True)
    ap.add_argument("--etc-rules-dir", required=True)
    a = ap.parse_args()
    ultimo = {}
    for r in csv.DictReader(open(os.path.join(a.base, "windows_index.csv"), encoding="utf-8")):
        ultimo[r["tag"]] = r
    ext = os.path.join(REPO, "_artefactos", "scripts", "extraer_alertas_windows.py")
    n = mal = 0
    for tag, r in sorted(ultimo.items()):
        if r["estado"] != "OK":
            continue
        det = os.path.join(a.base, "CSV", tag + "-Detalle.csv")
        alerts = os.path.join(a.raw, "%s_alerts_002.jsonl.gz" % tag)
        p = subprocess.run([sys.executable, "-I", ext, "--alerts", alerts, "--desde", r["t0"], "--hasta", r["t1"], "--agent-id", "002",
                            "--agent-name", "victima-windows", "--detail", det, "--ruleset-dir", a.ruleset_dir,
                            "--etc-rules-dir", a.etc_rules_dir], capture_output=True, text=True, encoding="utf-8", errors="replace")
        n += 1
        if p.returncode != 0:
            mal += 1
            print("FALLO", tag, p.stderr[-200:])
    print("reextraidas=%d fallos=%d" % (n, mal))
    return 1 if mal else 0


if __name__ == "__main__":
    sys.exit(main())
