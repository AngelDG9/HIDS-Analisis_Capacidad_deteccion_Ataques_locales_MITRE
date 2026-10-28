#!/usr/bin/env python3
"""E0 v5: compara multiconjunto de comandos de una timeline JSON con los de la BD."""
import collections
import json
import sys

tl_path, tsv_path = sys.argv[1], sys.argv[2]
with open(tl_path, encoding="utf-8") as fh:
    tl = json.load(fh)
cmds = [e["Command"] for h in tl["TimeLineHandlers"] for e in h["TimeLineEvents"]]
with open(tsv_path, encoding="utf-8-sig") as fh:
    db = [l.rstrip("\n") for l in fh if l.strip()]
a, b = collections.Counter(cmds), collections.Counter(db)
faltan = a - b
sobran = b - a
print("timeline %d db %d faltan %d sobran %d" % (len(cmds), len(db), sum(faltan.values()), sum(sobran.values())))
for c, n in list(faltan.items())[:5]:
    print("  FALTA x%d: %s" % (n, c[:120]))
for c, n in list(sobran.items())[:5]:
    print("  SOBRA x%d: %s" % (n, c[:120]))
print("db_con_pipe=%d" % sum(1 for c in db if "|" in c))
