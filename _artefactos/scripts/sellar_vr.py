#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sellar_vr.py - sellado de huellas de V1-L (equivalente a `sha256sums.txt` de Wazuh): fichero propio `sha256sums_vr.txt`.
Incluye los scripts y la receta de V1-L y TAMBIEN los ficheros de Wazuh que se reutilizan (guest, deploy, generador de receta...) para demostrar
que no cambiaron. NO modifica ningun fichero de Wazuh.
  python sellar_vr.py sellar    escribe Soporte/Laboratorio/legitimo_72h_vr/sha256sums_vr.txt (antes de t0)
  python sellar_vr.py check     recalcula y compara (V7: despues de t1); sale con 1 si algo cambio
Formato `sha256  ruta/relativa` como el de Wazuh. Sin secretos.
"""
import hashlib
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VR = "Soporte/Laboratorio/legitimo_72h_vr"
W = "Soporte/Laboratorio/legitimo_72h"
FICHEROS = [
    # propios de V1-L
    VR + "/legitimo_host_control_vr.ps1", VR + "/registrar_tareas_vr.ps1", VR + "/pausar_windows_update.ps1", VR + "/generar_control_vr.py",
    VR + "/legit_vr_config.json", VR + "/recetas_vr/d1.json", VR + "/recetas_vr/d2.json", VR + "/recetas_vr/d3.json",
    VR + "/recetas_vr/bloques.env", VR + "/recetas_vr/calendario.json", VR + "/recetas_vr/tabla_cfgS.sha256", VR + "/recetas_vr/vm_config.sha256",
    "_artefactos/scripts/legit_vr.py", "_artefactos/scripts/cosecha_vr.py", "_artefactos/scripts/exportar_denominador_vr.py",
    "_artefactos/scripts/verificar_validez_ventana_vr.py", "_artefactos/scripts/sellar_vr.py", "_artefactos/scripts/construir_snapshot_legit_vr.py",
    "Soporte/Laboratorio/ghosts/deploy_client_vr.ps1", "Soporte/Laboratorio/velociraptor/arrancar_servidor.ps1",
    # de Wazuh, reutilizados tal cual (se sellan para probar que no cambian)
    W + "/guest/tfg_keepalive.sh", W + "/guest/verificar_arreglos.sh", W + "/guest/instalar_tarea_invitado.sh",
    W + "/guest/tfg-ghosts-legit.service", W + "/guest/tfg-ghosts-legit.timer", W + "/exportar_acciones.sh",
    W + "/recetas/d1.json", W + "/recetas/d2.json", W + "/recetas/d3.json",
    "Soporte/Laboratorio/ghosts/client_ctl.sh", "Soporte/Laboratorio/ghosts/client_config/nlog.config", "Soporte/Laboratorio/ghosts/client_config/application.json",
    "Soporte/Laboratorio/ghosts/deploy_client.ps1", "_artefactos/scripts/construir_receta_legitima.py",
]
SUMAS = os.path.join(REPO, VR, "sha256sums_vr.txt")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    modo = sys.argv[1] if len(sys.argv) > 1 else "check"
    ahora = {}
    faltan = []
    for f in FICHEROS:
        p = os.path.join(REPO, f)
        (ahora.__setitem__(f, sha(p)) if os.path.isfile(p) else faltan.append(f))
    if modo == "sellar":
        if faltan:
            sys.exit("faltan ficheros: %s" % faltan)
        open(SUMAS, "w", encoding="utf-8", newline="\n").write("".join("%s  %s\n" % (h, f) for f, h in ahora.items()))
        print("sellados %d ficheros en %s" % (len(ahora), SUMAS))
        return
    esperado = dict((l.split("  ", 1)[1].strip(), l.split("  ", 1)[0]) for l in open(SUMAS, encoding="utf-8") if "  " in l)
    cambian = [f for f in esperado if ahora.get(f) != esperado[f]]
    print("ficheros sellados: %d | cambiados o ausentes: %d %s" % (len(esperado), len(cambian), cambian))
    print("RESULT=" + ("PASS" if not cambian and not faltan else "FAIL"))
    sys.exit(0 if not cambian and not faltan else 1)


if __name__ == "__main__":
    main()
