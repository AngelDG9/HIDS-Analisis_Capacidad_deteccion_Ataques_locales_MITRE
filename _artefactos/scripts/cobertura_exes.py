#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cobertura_exes.py — cobertura del corpus de ataques por los binarios de la actividad legítima.

Criterio de aceptación **CA-04** (plan §5.2.1 y §12): la receta v2 debe ejecutar **≥ 22 de los
50 `basenames`** que el corpus de ataques hace aparecer en `audit_command`; el objetivo medido
es **23/50 = 46 %** (T2 añadirá `systemctl`/`crontab` en la campaña ⇒ **25/50**).

Cómo se cuenta (y por qué así):

1. **Denominador** = conjunto de `basenames` distintos de las filas `categoria=deteccion` cuya
   `rule_description` es `Audit: Command: <ruta>` en
   `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*-Audited.csv`. Son **51 rutas / 50
   basenames** (§17.13: el denominador correcto es 50, no 49). Se lee **en frío**: este script
   no reejecuta nada ni escribe en `Dataset/`.
2. **Numerador** = binarios que ejecutan de verdad las tres recetas (`d1/d2/d3.json`), extraídos
   con el **mismo** `binarios_de()` del generador (para que validador y contador no discrepen).
   Se ignoran los *builtins* (`cd`) y los nombres de fichero.
3. **Conjunto** = receta + campaña (opcional, `--campana <csv>`): la campaña de T2 aporta
   `systemctl` y `crontab` (solo lectura) y ya está pre-registrada en `campana_casos.csv`.

Uso:
    python _artefactos/scripts/cobertura_exes.py
    python _artefactos/scripts/cobertura_exes.py --campana Soporte/Laboratorio/legitimo_72h/campana/campana_casos.csv
    python _artefactos/scripts/cobertura_exes.py --min 22          # umbral (CA-04)

Salida: `cobertura_exes = n/50` y `RESULT=PASS|FAIL`. Sin secretos, sin escrituras.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import construir_receta_legitima as rec  # noqa: E402  (misma función binarios_de)

PATRON_CMD = re.compile(r"^Audit:\s*Command:\s*(.+?)\.?$")


def basenames_corpus(raiz: str):
    """Devuelve (basenames ordenados, nº de rutas, nº de filas de detección)."""
    ficheros = sorted(glob.glob(os.path.join(
        raiz, "Dataset", "Ataques", "Resultados", "Wazuh", "linux", "Auditado", "*-Audited.csv")))
    if not ficheros:
        raise SystemExit("ERROR: no se encuentra el corpus en Dataset/Ataques/.../Auditado/")
    rutas, filas = {}, 0
    for f in ficheros:
        with open(f, encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(linea for linea in fh if not linea.startswith("#")):
                if row.get("categoria") != "deteccion":
                    continue
                m = PATRON_CMD.match(row.get("rule_description", ""))
                if not m:
                    continue
                filas += 1
                ruta = m.group(1).strip()
                rutas[ruta] = rutas.get(ruta, 0) + 1
    return sorted({r.split("/")[-1] for r in rutas}), len(rutas), filas


def binarios_receta(recetas: str):
    """Binarios de las tres recetas, con el mismo `binarios_de` del generador."""
    out = set()
    for day in (1, 2, 3):
        path = os.path.join(recetas, f"d{day}.json")
        if not os.path.isfile(path):
            raise SystemExit(f"ERROR: falta {path}")
        tl = json.load(open(path, encoding="utf-8"))
        for h in tl.get("TimeLineHandlers", []):
            for ev in h.get("TimeLineEvents", []):
                out.update(rec.binarios_de(ev["Command"]))
    return out


def binarios_campana(path: str):
    """Binarios de la campaña. Acepta cualquier CSV y se queda con los tokens conocidos.

    Es deliberadamente tolerante: la campaña (T2) aún no tiene esquema cerrado y lo que
    interesa es **no** contar dos veces ni inventar binarios. Solo se aceptan tokens de la
    lista blanca del generador (`systemctl`/`crontab` incluidos aquí: son de la campaña).
    """
    validos = set(rec.BINARIOS_OK) | {"systemctl", "crontab"}
    out = set()
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            for celda in row:
                for tok in rec.binarios_de(celda) if celda.strip() else []:
                    if tok in validos:
                        out.add(tok)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cobertura de binarios del corpus (CA-04).")
    ap.add_argument("--raiz", default=None, help="raíz del repo (por defecto, dos niveles arriba)")
    ap.add_argument("--recetas", default=None, help="carpeta de las recetas")
    ap.add_argument("--campana", default=None, help="CSV de la campaña (T2), opcional")
    ap.add_argument("--min", type=int, default=22, help="umbral mínimo de binarios cubiertos")
    args = ap.parse_args(argv)

    raiz = args.raiz or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    recetas = args.recetas or os.path.join(raiz, "Soporte", "Laboratorio", "legitimo_72h", "recetas")

    corpus, n_rutas, n_filas = basenames_corpus(raiz)
    total = len(corpus)
    rec_set = binarios_receta(recetas)
    cub = sorted(rec_set & set(corpus))
    faltan = [b for b in corpus if b not in rec_set]

    print(f"corpus: {total} basenames distintos ({n_rutas} rutas; {n_filas} filas de detección)")
    print(f"receta v2 ({os.path.basename(recetas)}/d1-d3.json): {len(rec_set)} binarios")
    print(f"  cubiertos ({len(cub)}): " + " ".join(cub))
    extra = sorted(rec_set - set(corpus))
    print(f"  fuera del corpus ({len(extra)}): " + (" ".join(extra) if extra else "—"))
    print(f"  faltan ({len(faltan)}): " + " ".join(faltan))
    print(f"cobertura_exes = {len(cub)}/{total} = {100.0 * len(cub) / total:.1f} %")

    conjunto = set(cub)
    if args.campana:
        if not os.path.isfile(args.campana):
            raise SystemExit(f"ERROR: no existe {args.campana}")
        camp = binarios_campana(args.campana) & set(corpus)
        nuevas = sorted(camp - rec_set)
        conjunto |= camp
        print(f"campaña: {len(camp)} binarios del corpus; aporta {len(nuevas)} nuevos: "
              + (" ".join(nuevas) if nuevas else "—"))
        print(f"conjunto (receta + campaña) = {len(conjunto)}/{total} = "
              f"{100.0 * len(conjunto) / total:.1f} %")

    ok = len(cub) >= args.min
    print(f"umbral = {args.min}/{total} -> " + ("OK" if ok else "NO CUMPLE"))
    print("RESULT=" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
