#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prueba_subida_grande_vr.py - E0 (d): comprueba que Velociraptor sube un fichero de ~300 MB (el orden de magnitud de audit.log* en la ventana real).
Crea un fichero aleatorio en /var/tmp de la VM, lo sube con Generic.Collectors.File, mide el tiempo, compara el sha256 y lo BORRA. Solo ensayo. Contrasena por entorno."""
import hashlib
import os
import re
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_ataques_linux as olx            # noqa: E402
import legit_vr                                  # noqa: E402
import orquestar_velociraptor_linux as vr        # noqa: E402
import extraer_ventana_velociraptor as ext       # noqa: E402

MB = int(sys.argv[1]) if len(sys.argv) > 1 else 300
c = legit_vr.fijar_cliente()
f = "/var/tmp/e0_prueba_%dMB.bin" % MB
rc, o, e = olx.ssh(olx.IP_V, "dd if=/dev/urandom of=%s bs=1M count=%d status=none && sha256sum %s && df -h / | tail -1" % (f, MB, f), timeout=300)
print(o.strip())
sha_vm = o.split()[0]
t = time.time()
rc, o, e = legit_vr.q("SELECT collect_client(client_id='%s', artifacts='Generic.Collectors.File', env=dict(Root='/', collectionSpec=\"Glob\n%s\")) AS f FROM scope()" % (c, f), 120)
fid = re.search(r"F\.[A-Z0-9]+", o).group(0)
estado = None
while time.time() - t < 1800:
    rc, o2, e2 = legit_vr.q("SELECT state FROM flows(client_id='%s', flow_id='%s')" % (c, fid), 60)
    if '"FINISHED"' in o2 or '"ERROR"' in o2:
        estado = "FINISHED" if "FINISHED" in o2 else "ERROR"
        break
    time.sleep(5)
seg = round(time.time() - t)
print("flujo", fid, estado, "en", seg, "s")
ok = None
for d, _, fs in os.walk(os.path.join(vr.SRV, "datastore", "clients", c, "collections", fid, "uploads")):
    for x in fs:
        if x.endswith(".bin"):
            p = os.path.join(d, x)
            b = open(p, "rb").read()
            try:
                b = ext._flujos(b)
            except Exception:                        # noqa: BLE001
                pass
            ok = hashlib.sha256(b).hexdigest() == sha_vm
            print("subido: %d bytes en disco, %d descomprimidos, sha256 coincide: %s" % (os.path.getsize(p), len(b), ok))
rc, o, e = olx.ssh(olx.IP_V, "rm -f %s; ls %s 2>&1 | head -1; df -h / | tail -1" % (f, f), timeout=60)
print("borrado en la VM:", o.strip().replace("\n", " | "))
print("RESULT=" + ("PASS" if estado == "FINISHED" and ok else "FAIL"))
