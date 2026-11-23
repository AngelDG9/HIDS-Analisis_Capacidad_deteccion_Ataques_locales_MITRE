#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""orquestar_velociraptor_ojos.py - pasada E2/E3 del plan _fases/velociraptor-ojos/plan.md (cfg S = «todos los ojos de fabrica a la vez»).

Reutiliza el orquestador del piloto (orquestar_velociraptor_linux.py) y le anade dos ganchos:
  * tabla del servidor = Linux.Events.EBPF con TODOS los eventos (los de fabrica + `security_inode_rename` + `mkdir`; el parametro `Events` es oficial);
    las vistas «EBPF de fabrica» y «EBPF afinado» se obtienen DESPUES filtrando por EventName;
  * tras la marca de FIN: subir `audit.log*` con Generic.Collectors.File (artifact estandar; = los mismos bytes que lee Wazuh), comprobar que las marcas
    de inicio y fin estan dentro, recortar [t0-60 s, t1+120 s] por la hora de auditd y contar las anclas (`audit_exe`, `audit_cwd`) por evento de comando.
Si algo de eso falla, la ventana FALLA (no se cuenta vacia). La contrasena de las VMs SOLO por TFG_MANAGER_PW (entorno).
Uso:  python orquestar_velociraptor_ojos.py [--fase run|post] [--iters 1,2] [--only ATA001,...]   (los valores por defecto son los del plan)
"""
from __future__ import annotations

import glob
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import orquestar_velociraptor_linux as vr        # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402
import probar_ojos_velociraptor as po            # noqa: E402

CASOS = ["ATA001", "ATA002", "ATA008", "ATA009", "ATA011", "ATA012", "ATA003", "ATA035", "ATA026"]   # 6 del piloto + 3 de ampliacion (regla objetiva, plan §11)
BASE = os.path.join(olx.REPO, "Dataset", "Ataques", "Resultados", "Velociraptor", "linux_ojos")
LAB = r"D:\TFG-VMs\ataques-velociraptor-linux-ojos"


def fijar_S(cfg):
    """Tabla del servidor: solo EBPF con todos los eventos (+ Generic.Client.Stats de serie)."""
    return po.poner_tabla([po.OPCIONES["SUPER"]["tabla"][0]])


def post_S(meta, ldir, rdir, a0, a1):
    """Sube audit.log*, comprueba marcas, recorta por hora de auditd y cuenta anclas (estrictas) por evento de comando."""
    c = po.coleccionar_audit(rdir)
    meta["coleccion_audit"] = {"flow_id": c.get("flow_id"), "flow_estado": c.get("flow_estado"),
                               "ficheros": {f: {k: v for k, v in d.items() if k in ("bytes", "bytes_zlib", "bytes_en_disco")} for f, d in c.get("ficheros", {}).items()}}
    if c.get("flow_estado") != "FINISHED":
        raise RuntimeError("la subida de audit.log no termino (%s)" % c.get("flow_estado"))
    lineas = []
    for f in sorted(glob.glob(os.path.join(rdir, "audit.log*.gz"))):
        lineas += gzip.open(f).read().splitlines()
    if not lineas:
        raise RuntimeError("audit.log subido vacio")
    texto = b"\n".join(lineas)
    for k in ("marca_ini", "marca_fin"):
        if meta[k].encode() not in texto:
            raise RuntimeError("la %s no esta en el audit.log subido (auditd no la registro o falta un fichero rotado)" % k)
    dentro, sin_hora = ext.recortar_audit(lineas, a0, a1)
    ext.escribir_gz(os.path.join(rdir, "auditd_ventana.log.gz"), dentro)
    anclas = []
    for f in glob.glob(os.path.join(olx.CMD_DIR, "T*", "%s_esperado.csv" % meta["ata"])):
        anclas = ext.cargar_anclas(f)
    meta["audit"] = {"lineas_totales": len(lineas), "lineas_ventana": len(dentro), "sin_hora": sin_hora,
                     "anclas_audit_estricto": ext.contar_anclas_audit(dentro, anclas)}


def main():
    vr.FIJAR["S"] = fijar_S
    vr.POST["S"] = post_S
    vr.SUBS_EXTRA = ("collections",)
    defecto = {"--cfg": "S", "--only": ",".join(CASOS), "--iters": "1,2", "--out": BASE, "--raw": os.path.join(LAB, "raw"),
               "--crudo": os.path.join(LAB, "crudo"), "--log": r"D:\TFG-VMs\lab-logs\velociraptor_ojos.txt"}
    for k, v in defecto.items():
        if k not in sys.argv:
            sys.argv += [k, v]
    po.cargar_custom = lambda: None                 # no hace falta cargar los artifacts propios (solo se usan de fabrica)
    vr.main()


if __name__ == "__main__":
    main()
