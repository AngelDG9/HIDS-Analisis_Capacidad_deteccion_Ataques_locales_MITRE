#!/usr/bin/env python3
"""E0 v5: cuenta eventos audit (cwd/exe) en archives.json dentro de una ventana UTC.
Uso (en el manager wazuh-server, con sudo): sudo python3 e0_audit_cwd.py T0 T1
T0/T1 con formato 2026-10-28T22:05:00 (prefijo lexicografico del timestamp).
Solo lectura. No escribe nada.
"""
import json
import sys

ARCH = "/var/ossec/logs/archives/archives.json"
t0, t1 = sys.argv[1], sys.argv[2]
cwd, exe = {}, {}
n = malos = 0
with open(ARCH, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if '"audit"' not in line:
            continue
        ts = line[line.find('"timestamp":"') + 13:][:19]
        if not (t0 <= ts <= t1):
            continue
        try:
            j = json.loads(line)
        except Exception:
            malos += 1
            continue
        au = (j.get("data") or {}).get("audit") or {}
        c = au.get("cwd")
        if not c:
            continue
        n += 1
        cwd[c] = cwd.get(c, 0) + 1
        e = au.get("exe") or "?"
        exe[e] = exe.get(e, 0) + 1
print("eventos_audit_con_cwd=%d" % n)
print("lineas_no_json=%d" % malos)
print("cwd_distintos=%d" % len(cwd))
for c, k in sorted(cwd.items(), key=lambda x: -x[1]):
    print("  cwd=%s n=%d" % (c, k))
print("cwd_ghosts_client=%d" % sum(v for c, v in cwd.items() if "ghosts-client" in c))
print("binarios:")
for e, k in sorted(exe.items(), key=lambda x: -x[1])[:40]:
    print("  %s:%d" % (e, k))
