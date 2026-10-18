#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ghosts_api.py — utilidades de control del servidor GHOSTS (TFG HIDS, bloque L0).

Solo **biblioteca estándar** (urllib). Subcomandos:

  list                Lista las máquinas registradas (GET /api/machines).
  wait MACHINE        Espera a que aparezca la máquina MACHINE (por nombre).
  send-timeline M    Envía al servidor la timeline `--timeline FILE` para la máquina M
                     (POST /api/machineupdates, Type=Timeline).
  send-updates M     Pide al agente que suba su timeline actual (Type=RequestForTimeline).
  count               Cuenta las acciones registradas (historia de timeline) por máquina.

No contiene secretos. La URL base por defecto es el host en VMnet1.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "http://192.168.65.1:5000/api"


def _get(url: str):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read().decode("utf-8")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def cmd_list(base: str, _args) -> int:
    machines = _get(f"{base}/machines?q=")
    if not machines:
        print("(sin máquinas registradas)")
        return 0
    for m in machines:
        print(f"{m.get('name'):24s} id={m.get('id')} up={m.get('statusUp')} "
              f"last={m.get('lastReportedUtc')} user={m.get('currentUsername')}")
    return 0


def _find_machine(base: str, name: str):
    for m in _get(f"{base}/machines?q="):
        if (m.get("name") or "").lower() == name.lower():
            return m
    return None


def cmd_wait(base: str, args) -> int:
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        m = _find_machine(base, args.machine)
        if m:
            print(m.get("id"))
            return 0
        time.sleep(3)
    print(f"ERROR: la máquina {args.machine} no apareció en {args.timeout}s", file=sys.stderr)
    return 1


def cmd_send_timeline(base: str, args) -> int:
    m = _find_machine(base, args.machine)
    if not m:
        print(f"ERROR: máquina {args.machine} no registrada", file=sys.stderr)
        return 1
    with open(args.timeline, "r", encoding="utf-8") as fh:
        timeline = json.load(fh)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "MachineId": m["id"],
        "Username": m.get("currentUsername") or "",
        "Type": "Timeline",
        "Status": "Active",
        "ActiveUtc": now,
        "CreatedUtc": now,
        "Update": timeline,
    }
    res = _post(f"{base}/machineupdates", payload)
    print(json.dumps(res) if isinstance(res, (dict, list)) else res)
    return 0


def cmd_send_updates(base: str, args) -> int:
    m = _find_machine(base, args.machine)
    if not m:
        print(f"ERROR: máquina {args.machine} no registrada", file=sys.stderr)
        return 1
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "MachineId": m["id"],
        "Username": m.get("currentUsername") or "",
        "Type": "RequestForTimeline",
        "Status": "Active",
        "ActiveUtc": now,
        "CreatedUtc": now,
    }
    res = _post(f"{base}/machineupdates", payload)
    print(json.dumps(res) if isinstance(res, (dict, list)) else res)
    return 0


def cmd_count(base: str, args) -> int:
    """Cuenta acciones a partir de la actividad reportada por el servidor.

    La actividad histórica se consulta vía el endpoint de máquina
    (history_timeline). Se hace un sondeo por máquina.
    """
    machines = _get(f"{base}/machines?q=")
    total = 0
    for m in machines:
        if args.machine and (m.get("name") or "").lower() != args.machine.lower():
            continue
        try:
            act = _get(f"{base}/machines/{m['id']}/activity?skip=0&take=1")
        except urllib.error.HTTPError:
            act = []
        n = len(act) if isinstance(act, list) else 0
        print(f"{m.get('name')}: muestra={n}")
        total += n
    print(f"total_muestra={total}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Control del servidor GHOSTS (TFG HIDS).")
    ap.add_argument("--base", default=DEFAULT_BASE, help="URL base de la API (…/api)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list"); p.set_defaults(func=cmd_list)

    p = sub.add_parser("wait"); p.add_argument("machine"); p.add_argument("--timeout", type=int, default=180)
    p.set_defaults(func=cmd_wait)

    p = sub.add_parser("send-timeline"); p.add_argument("machine"); p.add_argument("--timeline", required=True)
    p.set_defaults(func=cmd_send_timeline)

    p = sub.add_parser("send-updates"); p.add_argument("machine")
    p.set_defaults(func=cmd_send_updates)

    p = sub.add_parser("count"); p.add_argument("--machine", default=None)
    p.set_defaults(func=cmd_count)

    args = ap.parse_args(argv)
    return args.func(args.base, args)


if __name__ == "__main__":
    raise SystemExit(main())
