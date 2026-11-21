#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ataques_linux_v2.py - aplica `filtrar_ruido.py` a cada ventana OK del indice v2.

Entrada : <out>/windows_index.csv y <out>/CSV/<tag>-Detalle.csv  (los deja orquestar_ataques_linux.py)
Salida  : <out>/Auditado/<tag>-Audited.csv y <tag>-Revision.csv  (mismo nombre que en la version 1:
          ATA014_iter1-..., ATA014_rev1-...) y <out>/filtrado_resumen.csv.
NO resuelve las filas `dudosa`: eso es revision humana (queda en `-Revision.csv`).
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import csv
import glob
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
FILTRO = os.path.join(REPO, "_artefactos", "scripts", "filtrar_ruido.py")
CMD = os.path.join(REPO, "Dataset", "Ataques", "Comandos")


def esperado(ata, rev):
    pat = "ATA%s_esperado%s.csv" % (ata[3:], "_rev" if rev else "")
    h = glob.glob(os.path.join(CMD, "T*", pat))
    return h[0] if h else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "linux_v2"))
    ap.add_argument("--catalogo", default="", help="catalogo de ruido (por defecto el de fabrica del filtro)")
    ap.add_argument("--revision-dir", default="", help="carpeta con <tag>-Revision.csv ya rellenados (veredicto) para plegar")
    ap.add_argument("--aud-dir", default="Auditado", help="subcarpeta de salida dentro de --out")
    args = ap.parse_args()
    idx = os.path.join(args.out, "windows_index.csv")
    aud = os.path.join(args.out, args.aud_dir)
    os.makedirs(aud, exist_ok=True)
    filas = [["tag", "estado_filtro", "rc", "nota"]]
    ultimo = {}
    for r in csv.DictReader(open(idx, encoding="utf-8")):      # si un tag se repite, manda la ULTIMA fila
        ultimo[r["tag"]] = r
    for r in ultimo.values():
        if r["estado"] not in ("OK", "REVISAR"):
            continue
        tag, ata, rev, it = r["tag"], r["ata"], r["variante"] == "rev", int(r["iter"])
        det = os.path.join(args.out, "CSV", "%s-Detalle.csv" % tag)
        esp = esperado(ata, rev)
        if not os.path.isfile(det) or not esp:
            filas.append([tag, "SIN_ENTRADA", "", "detalle=%s esperado=%s" % (os.path.isfile(det), bool(esp))])
            continue
        cmd = [sys.executable, "-I", FILTRO, "--alerta", det, "--ata", ata, "--iter", str(it), "--esperado", esp,
               "--out", os.path.join(aud, "%s-Audited.csv" % tag),
               "--rev-out", os.path.join(aud, "%s-Revision.csv" % tag)]
        if args.catalogo:
            cmd += ["--catalogo", args.catalogo]
        if args.revision_dir and os.path.isfile(os.path.join(args.revision_dir, "%s-Revision.csv" % tag)):
            cmd += ["--revision", os.path.join(args.revision_dir, "%s-Revision.csv" % tag)]
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        filas.append([tag, "OK" if p.returncode == 0 else "FALLO", p.returncode,
                      (p.stdout.strip().splitlines() or [""])[-1][:160] if p.returncode == 0 else p.stderr.strip()[-160:]])
    with open(os.path.join(args.out, "filtrado_resumen.csv"), "w", encoding="utf-8", newline="") as fh:
        csv.writer(fh, lineterminator="\n").writerows(filas)
    print("filtradas=%d" % (len(filas) - 1))


if __name__ == "__main__":
    main()
