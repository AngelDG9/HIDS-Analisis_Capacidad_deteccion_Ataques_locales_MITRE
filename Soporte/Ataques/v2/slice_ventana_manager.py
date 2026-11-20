#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""slice_ventana_manager.py - corta una ventana [desde, hasta] de alerts o archives de Wazuh.

Se ejecuta EN EL MANAGER (con sudo: /var/ossec/logs es 750 wazuh:wazuh) y escribe por stdout
las lineas JSON CRUDAS (tal cual estan en el fichero) del agente pedido. Es solo lectura.

  sudo python3 slice_ventana_manager.py alerts   001 2026-11-20T01:06:00Z 2026-11-20T01:12:00Z
  sudo python3 slice_ventana_manager.py archives 001 2026-11-20T01:06:00Z 2026-11-20T01:12:00Z

Lee los ficheros DIARIOS por dia UTC (`ossec-alerts-DD.json` / `ossec-archive-DD.json`, o su
`.json.gz` si el dia ya roto). Sin dependencias fuera de la biblioteca estandar. Sin secretos.
"""
import datetime
import gzip
import os
import re
import sys

MES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
TS = re.compile(r'^\{"timestamp":"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)')


def _dt(s):
    return datetime.datetime.strptime(s.replace("Z", "")[:19], "%Y-%m-%dT%H:%M:%S")


def main(argv):
    if len(argv) != 5 or argv[1] not in ("alerts", "archives"):
        sys.stderr.write(__doc__)
        return 2
    kind, agent, desde, hasta = argv[1], argv[2], argv[3], argv[4]
    d0, d1 = _dt(desde), _dt(hasta)
    base = "ossec-alerts" if kind == "alerts" else "ossec-archive"
    marca = '"agent":{"id":"%s"' % agent
    dia = d0.date()
    ficheros = []
    while dia <= d1.date():
        d = "/var/ossec/logs/%s/%d/%s/%s-%02d.json" % (kind, dia.year, MES[dia.month - 1], base, dia.day)
        ficheros.append(d if os.path.isfile(d) else d + ".gz")
        dia += datetime.timedelta(days=1)
    out = sys.stdout.buffer
    n = 0
    f0 = desde.replace("Z", "")[:19]
    f1 = hasta.replace("Z", "")[:19]
    for p in ficheros:
        if not os.path.isfile(p):
            sys.stderr.write("AVISO ausente %s\n" % p)
            continue
        op = gzip.open if p.endswith(".gz") else open
        with op(p, "rb") as fh:
            for raw in fh:
                line = raw.decode("utf-8", "replace")
                if marca not in line:
                    continue
                m = TS.match(line)
                if not m:
                    continue
                ts = m.group(1)
                if f0 <= ts <= f1:
                    out.write(raw if raw.endswith(b"\n") else raw + b"\n")
                    n += 1
    sys.stderr.write("lineas=%d\n" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
