#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""orquestar_velociraptor_v1.py - V1 de Velociraptor en Linux: los 55 casos (variante base) x 2 iteraciones, plan _fases/velociraptor-v1/plan.md.

Es la misma configuracion que la pasada de ojos (cfg S: EBPF con todos los eventos + subida de audit.log*), con los 55 casos por defecto.
Salida: Dataset/Ataques/Resultados/Velociraptor/linux_v1/cfgS ; crudo fuera del repo: D:\\TFG-VMs\\ataques-velociraptor-linux-v1\\{raw,crudo}.
Uso:  TFG_MANAGER_PW=... python orquestar_velociraptor_v1.py [--only ATA038,ATA039] [--iters 1] [--fase run|post]
Sin secretos (la contrasena solo viaja por la variable de entorno).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import orquestar_velociraptor_linux as vr        # noqa: E402
import orquestar_velociraptor_ojos as oj         # noqa: E402
import probar_ojos_velociraptor as po            # noqa: E402

BASE = os.path.join(olx.REPO, "Dataset", "Ataques", "Resultados", "Velociraptor", "linux_v1")
LAB = r"D:\TFG-VMs\ataques-velociraptor-linux-v1"


def todos_los_casos():
    vistos, out = set(), []
    for s in olx.cargar_especificaciones():
        if s["variante"] == "base" and s["ata"] not in vistos:
            vistos.add(s["ata"])
            out.append(s["ata"])
    return sorted(out)


def main():
    vr.FIJAR["S"] = oj.fijar_S
    vr.POST["S"] = oj.post_S
    vr.SUBS_EXTRA = ("collections",)
    defecto = {"--cfg": "S", "--only": ",".join(todos_los_casos()), "--iters": "1,2", "--out": BASE, "--raw": os.path.join(LAB, "raw"),
               "--crudo": os.path.join(LAB, "crudo"), "--log": r"D:\TFG-VMs\lab-logs\velociraptor_v1.txt"}
    for k, v in defecto.items():
        if k not in sys.argv:
            sys.argv += [k, v]
    po.cargar_custom = lambda: None
    try:
        vr.main()
    finally:
        if "--fase" not in sys.argv or "run" in sys.argv:
            try:
                vr.manager_off()                  # la VM manager solo se enciende para ATA039/ATA040
            except Exception:                     # noqa: BLE001
                pass


if __name__ == "__main__":
    main()
