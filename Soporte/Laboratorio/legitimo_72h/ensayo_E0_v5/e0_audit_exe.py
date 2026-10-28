#!/usr/bin/env python3
"""E0 v5: inspecciona eventos audit de un exe concreto en una ventana (diagnostico)."""
import json
import sys

ARCH = "/var/ossec/logs/archives/archives.json"
t0, t1, exe = sys.argv[1], sys.argv[2], sys.argv[3]
n = 0
with open(ARCH, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if exe not in line:
            continue
        ts = line[line.find('"timestamp":"') + 13:][:19]
        if not (t0 <= ts <= t1):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        au = (j.get("data") or {}).get("audit") or {}
        if au.get("exe") != exe:
            continue
        n += 1
        if n <= 8:
            print("%s | audit_ts=%s | cwd=%s | cmd=%s" % (
                j.get("timestamp"), au.get("timestamp"), au.get("cwd"),
                (au.get("command") or "")[:90]))
print("total_exe=%d" % n)
