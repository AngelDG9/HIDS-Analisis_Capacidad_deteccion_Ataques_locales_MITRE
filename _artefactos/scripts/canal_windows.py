#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""canal_windows.py — huella del canal del operador (Windows) para B1.0-SSH.1.

Lee el **detalle** que produce `extraer_alertas_windows.py` (`--detail`) y escribe la
huella del canal con **exactamente** las columnas que pide el plan (§5.2):

    rule_id,level,event_id,srcip,win_user,logon_type,win_parent_image

Qué entra (y qué **no**):

- **Sí**: los eventos de **identidad/sesión** del canal
  (`60106`, `60137`, `67024`, `67023`, `67028`, `67022`) y las filas de proceso cuya
  **imagen es `sshd.exe`** (el servicio; sus subprocesos `-R`/`-y`/`-z` también).
- **No**: los hijos de `sshd.exe` (`cmd.exe`, `powershell.exe`…). El ataque corre dentro
  de esa sesión y se atribuye por carpeta (`C:\\lab-attack\\ATA<NNN>`), no es canal
  (plan §5.2, regla 2). Tampoco el ruido de fondo ajeno al canal.

No inventa nada: si un campo no está, queda vacío. Cabecera `#` con la ventana, el
recuento, el `sha256` de la entrada y el `sha256` del propio CSV (sin reloj).

Uso:
    python canal_windows.py --alerta detalle.csv --out canal_ssh.csv --canal ssh
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ntpath
import os
import sys

#: Reglas de identidad/sesión que genera una sesión SSH (medidas en B1.0-SSH.1).
REGLAS_CANAL = {"60106", "60137", "67024", "67023", "67028", "67022"}

#: Imagen del servicio del canal (solo la imagen; nunca sus hijos).
IMAGEN_SERVICIO = "sshd.exe"

SALIDA = ["rule_id", "level", "event_id", "srcip", "win_user", "logon_type",
          "win_parent_image"]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _leer(path: str):
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return list(csv.DictReader(lineas))


def _basename(valor: str) -> str:
    v = (valor or "").strip().strip('"')
    return ntpath.basename(v).lower() if v else ""


def es_canal(fila: dict) -> bool:
    rid = (fila.get("rule_id") or "").strip()
    return rid in REGLAS_CANAL or _basename(fila.get("win_image")) == IMAGEN_SERVICIO


def construir(filas):
    salida = []
    for f in filas:
        if not es_canal(f):
            continue
        salida.append([
            (f.get("rule_id") or "").strip(),
            str(f.get("rule_level") or "").strip(),
            str(f.get("event_id") or "").strip(),
            (f.get("srcip") or "").strip(),
            (f.get("win_target_user") or "").strip() or (f.get("win_user") or "").strip(),
            str(f.get("logon_type") or "").strip(),
            (f.get("win_parent_image") or "").strip(),
        ])
    salida.sort(key=lambda r: (r[0], r[2], r[4], r[5], r[6], r[3]))
    return salida


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Huella del canal Windows (SSH).")
    ap.add_argument("--alerta", required=True, help="detalle de extraer_alertas_windows.py")
    ap.add_argument("--out", required=True, help="CSV de huella del canal")
    ap.add_argument("--detalle-out", default=None,
                    help="opcional: subconjunto del detalle (todas las columnas) del canal")
    ap.add_argument("--canal", default="ssh", choices=("ssh", "vmrun"))
    ap.add_argument("--ventana", default="", help="texto informativo de la ventana UTC")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.alerta):
        print(f"ERROR: no existe {args.alerta}", file=sys.stderr)
        return 2
    filas = _leer(args.alerta)
    canal = construir(filas)
    if not canal:
        print("ERROR: el detalle no contiene ninguna fila del canal", file=sys.stderr)
        return 1

    if args.detalle_out:
        campos = list(filas[0].keys()) if filas else []
        with open(args.detalle_out, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=campos, lineterminator="\n")
            w.writeheader()
            for f in filas:
                if es_canal(f):
                    w.writerow(f)
        print(f"detalle_canal={args.detalle_out}")

    reglas = sorted({r[0] for r in canal})
    eventos = sorted({r[2] for r in canal})
    cab = (
        f"# {os.path.basename(args.out)} | TFG HIDS - huella del canal "
        f"({args.canal}) | B1.0-SSH.1 | ventana={args.ventana} | filas={len(canal)} | "
        f"reglas={','.join(reglas)} | event_id={','.join(eventos)} | "
        f"fuente={os.path.basename(args.alerta)} sha256={sha256_file(args.alerta)} | "
        f"columnas: " + ",".join(SALIDA)
    )
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(SALIDA)
        w.writerows(canal)

    print(f"canal={args.canal} filas={len(canal)} reglas={reglas} -> {args.out}")
    print(f"sha256={sha256_file(args.out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
