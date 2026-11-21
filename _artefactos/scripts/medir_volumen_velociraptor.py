#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""medir_volumen_velociraptor.py - cuenta filas y bytes REALES de un flujo de Velociraptor en el datastore del servidor.

Los ficheros `datastore/clients/<id>/artifacts/<Artifact>/<flujo>.json` son una CONCATENACION de varios flujos zlib:
hay que descomprimir todos (si se lee solo el primero o se mira el tamano en disco, se infravalora: error cometido el 2026-11-21).
Uso: python medir_volumen_velociraptor.py --datastore D:\\TFG-VMs\\velociraptor-server\\datastore --cliente C.xxxx --flujo F.xxxx --segundos 900 --out salida.csv
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import glob
import os
import zlib


def leer(path):
    b = open(path, "rb").read()
    out = b""
    while b:
        o = zlib.decompressobj()
        out += o.decompress(b)
        b = o.unused_data
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datastore", required=True)
    ap.add_argument("--cliente", required=True)
    ap.add_argument("--flujo", required=True)
    ap.add_argument("--segundos", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    base = os.path.join(a.datastore, "clients", a.cliente, "artifacts")
    filas = []
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d, a.flujo + ".json")
        if not os.path.isfile(p):
            continue
        o = leer(p)
        n = sum(1 for l in o.splitlines() if l.startswith(b"{"))
        f = 3600.0 / a.segundos
        filas.append((d, n, len(o), os.path.getsize(p), round(n * f), round(len(o) * f / 1e3, 1), round(os.path.getsize(p) * f / 1e3, 1)))
    with open(a.out, "w", encoding="utf-8", newline="") as fh:
        fh.write("# volumen medido con medir_volumen_velociraptor.py (descomprime TODOS los flujos zlib) | cliente %s | flujo %s | %d s\n" % (a.cliente, a.flujo, a.segundos))
        fh.write("artifact,filas,bytes_sin_comprimir,bytes_en_disco,filas_por_hora,KB_sin_comprimir_por_hora,KB_en_disco_por_hora\n")
        for r in filas:
            fh.write(",".join(str(x) for x in r) + "\n")
    for r in filas:
        print("%-28s filas=%6d  sin_comprimir=%.2f MB  en_disco=%.2f MB" % (r[0], r[1], r[2] / 1e6, r[3] / 1e6))


if __name__ == "__main__":
    main()
