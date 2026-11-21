#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""corregir_t0_windows_v2.py - t0 de las ventanas Windows v2 = momento del LANZAMIENTO (no la marca del propio script).

El orquestador tomo `t0` de `times.log` del ataque (la marca que escribe el .ps1 al arrancar). PowerShell tarda 1-3 s en
arrancar, asi que la creacion de `cmd.exe /c run.cmd` y de `powershell -File ATA<N>_ataque.ps1` (los procesos DEL ATAQUE)
quedaba ANTES de t0 y fuera de la ventana: el ataque perdia sus propias deteccion de proceso (p.ej. ATA060 0 detecciones;
ATA073/ATA097 sin las de nivel >=7 de la v1). En la v1 `t0` se sellaba ANTES de lanzar. Aqui se corrige a
`LANZADO_MANAGER` (reloj del manager justo antes de `schtasks /run`, en `Logs/<tag>/times.log.orquestador`).
Anade filas corregidas al indice (la ultima fila por tag manda) y conserva el t0 original en la columna `error` (nota).
"""
import csv
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def main():
    base = os.path.join(REPO, "Dataset", "Ataques", "Resultados", "Wazuh", "windows_v2")
    p = os.path.join(base, "windows_index.csv")
    rd = list(csv.DictReader(open(p, encoding="utf-8")))
    cols = list(rd[0].keys())
    ultimo = {}
    for r in rd:
        ultimo[r["tag"]] = r
    nuevas = []
    for tag, r in sorted(ultimo.items()):
        if r["estado"] != "OK" or "t0 corregido" in (r.get("error") or ""):
            continue
        tl = os.path.join(base, "Logs", tag, "times.log.orquestador")
        lanz = ""
        for ln in open(tl, encoding="utf-8"):
            if ln.startswith("LANZADO_MANAGER="):
                lanz = ln.split("=", 1)[1].strip()
        if not lanz:
            print("sin LANZADO_MANAGER:", tag)
            continue
        n = dict(r)
        n["error"] = "t0 corregido a LANZADO_MANAGER (t0 del script=%s)" % r["t0"]
        n["t0"] = lanz
        nuevas.append(n)
    with open(p, "a", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, lineterminator="\n")
        for n in nuevas:
            w.writerow(n)
    print("filas corregidas anadidas: %d" % len(nuevas))


if __name__ == "__main__":
    sys.exit(main())
