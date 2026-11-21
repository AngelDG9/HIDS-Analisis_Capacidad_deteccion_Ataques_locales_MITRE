#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ataques_windows_v2.py - aplica `filtrar_ruido_windows.py` a cada ventana OK del indice v2 (Windows).

Entrada : <out>/windows_index.csv y <out>/CSV/<tag>-Detalle.csv  (los deja orquestar_ataques_windows.py)
Salida  : <out>/Auditado/<tag>-Audited.csv y -Revision.csv, mas la sensibilidad `--sin-operador`
          (<tag>-Audited_sin_operador.csv), y <out>/filtrado_resumen.csv.
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
FILTRO = os.path.join(REPO, "_artefactos", "scripts", "filtrar_ruido_windows.py")
CMD = os.path.join(REPO, "Dataset", "Ataques", "Comandos", "windows")


def esperado(ata):
    h = glob.glob(os.path.join(CMD, "T*", "%s_esperado.csv" % ata))
    return h[0] if h else ""


def correr(det, ata, it, esp, out, rev, extra=()):
    cmd = [sys.executable, "-I", FILTRO, "--alerta", det, "--ata", ata, "--iter", str(it), "--esperado", esp,
           "--out", out, "--rev-out", rev] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    nota = (p.stdout.strip().splitlines() or [""])[0][:160] if p.returncode == 0 else p.stderr.strip()[-160:]
    return p.returncode, nota


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "windows_v2"))
    ap.add_argument("--catalogo", default="", help="catalogo de ruido (por defecto el de fabrica del filtro)")
    ap.add_argument("--revision-dir", default="", help="carpeta con <tag>-Revision.csv ya rellenados (veredicto) para plegar")
    ap.add_argument("--aud-dir", default="Auditado", help="subcarpeta de salida dentro de --out")
    args = ap.parse_args()
    aud = os.path.join(args.out, args.aud_dir)
    os.makedirs(aud, exist_ok=True)
    ultimo = {}
    for r in csv.DictReader(open(os.path.join(args.out, "windows_index.csv"), encoding="utf-8")):
        ultimo[r["tag"]] = r                                   # si un tag se repite, manda la ULTIMA fila
    filas = [["tag", "estado_filtro", "rc", "nota", "rc_sin_operador"]]
    for r in ultimo.values():
        if r["estado"] not in ("OK", "REVISAR"):
            continue
        tag, ata, it = r["tag"], r["ata"], int(r["iter"])
        det = os.path.join(args.out, "CSV", "%s-Detalle.csv" % tag)
        esp = esperado(ata)
        if not os.path.isfile(det) or not esp:
            filas.append([tag, "SIN_ENTRADA", "", "detalle=%s esperado=%s" % (os.path.isfile(det), bool(esp)), ""])
            continue
        extra = []
        if args.catalogo:
            extra += ["--catalogo", args.catalogo]
        if args.revision_dir and os.path.isfile(os.path.join(args.revision_dir, "%s-Revision.csv" % tag)):
            extra += ["--revision", os.path.join(args.revision_dir, "%s-Revision.csv" % tag)]
        rc, nota = correr(det, ata, it, esp, os.path.join(aud, "%s-Audited.csv" % tag), os.path.join(aud, "%s-Revision.csv" % tag), extra)
        rc2, _ = correr(det, ata, it, esp, os.path.join(aud, "%s-Audited_sin_operador.csv" % tag),
                        os.path.join(aud, "%s-Revision_sin_operador.csv" % tag), ["--sin-operador"] + extra)
        filas.append([tag, "OK" if rc == 0 else "FALLO", rc, nota, rc2])
    with open(os.path.join(args.out, "filtrado_resumen.csv"), "w", encoding="utf-8", newline="") as fh:
        csv.writer(fh, lineterminator="\n").writerows(filas)
    print("filtradas=%d" % (len(filas) - 1))


if __name__ == "__main__":
    main()
