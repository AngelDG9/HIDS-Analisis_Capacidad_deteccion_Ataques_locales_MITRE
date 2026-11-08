#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arrancar_servicios_host.py — “internet local” del laboratorio (HOST, B-2).

Arranca/para de forma **idempotente** los servicios que suplen a internet en el
laboratorio aislado, **enlazados a `192.168.65.1`** (VMnet1) y **acotados** a
`192.168.65.0/24` por firewall:

| Puerto | Servicio | Script |
|---|---|---|
| 8080 | web estática | `Soporte/Laboratorio/internet_local/serve_site.py` |
| 9090 | sink HTTP | `Soporte/Ataques/receiver/sink_http.py` |
| 9091 | sink TCP crudo | el mismo `sink_http.py --tcp-port 9091` |
| 9092 | nube WebDAV | `Soporte/Ataques/receiver/sink_webdav.py` |

**Nunca** toca `443/1514/1515/55000` (manager). **Sin secretos.** Los PID se guardan
fuera del repo (`D:\\TFG-VMs\\lab-logs\\servicios_host.pids.json`); `stop` solo mata
los procesos que arrancó este script.

Uso:
    python _artefactos/scripts/arrancar_servicios_host.py start
    python _artefactos/scripts/arrancar_servicios_host.py status
    python _artefactos/scripts/arrancar_servicios_host.py stop
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

BIND = "192.168.65.1"
REMOTE = "192.168.65.0/24"
BASE = r"D:\TFG-VMs\lab-logs"
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SITE = os.path.join(REPO, "Soporte", "Laboratorio", "internet_local", "site")
SERVE = os.path.join(REPO, "Soporte", "Laboratorio", "internet_local", "serve_site.py")
SINK_HTTP = os.path.join(REPO, "Soporte", "Ataques", "receiver", "sink_http.py")
SINK_WEBDAV = os.path.join(REPO, "Soporte", "Ataques", "receiver", "sink_webdav.py")
PIDFILE = os.path.join(BASE, "servicios_host.pids.json")

#: (nombre, puerto(s), argv).  `argv` sin el ejecutable `python`.
SERVICIOS = [
    ("web8080", (8080,), [SERVE, "--bind", BIND, "--port", "8080",
                          "--root", SITE, "--log", os.path.join(BASE, "web_access.log")]),
    ("sink9090", (9090, 9091), [SINK_HTTP, "--bind", BIND, "--port", "9090",
                                "--tcp-port", "9091",
                                "--log", os.path.join(BASE, "sink_http.log")]),
    ("webdav9092", (9092,), [SINK_WEBDAV, "--bind", BIND, "--port", "9092",
                             "--root", os.path.join(BASE, "cloud_bucket"),
                             "--log", os.path.join(BASE, "sink_webdav.log")]),
]

#: Reglas de firewall: (nombre, puerto). Todas acotadas a `REMOTE`.
REGLAS = [
    ("TFG-web-8080", 8080),
    ("TFG-sink-9090", 9090),
    ("TFG-sink-9091", 9091),
    ("TFG-webdav-9092", 9092),
]


def puerto_abierto(host: str, puerto: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=timeout):
            return True
    except OSError:
        return False


def _leer_pids() -> dict:
    try:
        with open(PIDFILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _guardar_pids(pids: dict) -> None:
    os.makedirs(os.path.dirname(PIDFILE), exist_ok=True)
    with open(PIDFILE, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(pids, fh, indent=2, sort_keys=True)


def _netsh(args: list[str]) -> int:
    if os.name != "nt":
        return 1
    return subprocess.run(["netsh"] + args, capture_output=True, text=True).returncode


def regla_existe(nombre: str) -> bool:
    return _netsh(["advfirewall", "firewall", "show", "rule", f"name={nombre}"]) == 0


def crear_regla(nombre: str, puerto: int) -> bool:
    if regla_existe(nombre):
        return False
    rc = _netsh([
        "advfirewall", "firewall", "add", "rule", f"name={nombre}",
        "dir=in", "action=allow", "protocol=TCP", f"localport={puerto}",
        f"remoteip={REMOTE}",
    ])
    if rc != 0:
        raise RuntimeError(f"no se pudo crear la regla {nombre} (rc={rc})")
    return True


def borrar_regla(nombre: str) -> bool:
    if not regla_existe(nombre):
        return False
    _netsh(["advfirewall", "firewall", "delete", "rule", f"name={nombre}"])
    return True


def _lanzar(nombre: str, argv: list[str]):
    os.makedirs(BASE, exist_ok=True)
    out = open(os.path.join(BASE, f"{nombre}.out.log"), "a", encoding="utf-8")
    err = open(os.path.join(BASE, f"{nombre}.err.log"), "a", encoding="utf-8")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    proc = subprocess.Popen([sys.executable] + argv, stdout=out, stderr=err,
                            creationflags=flags)
    return proc


def cmd_start(espera: float = 10.0) -> int:
    os.makedirs(BASE, exist_ok=True)
    os.makedirs(os.path.join(BASE, "cloud_bucket"), exist_ok=True)
    pids = _leer_pids()
    fallos = 0
    for nombre, puertos, argv in SERVICIOS:
        abiertos = [p for p in puertos if puerto_abierto(BIND, p)]
        if len(abiertos) == len(puertos):
            print(f"{nombre}: ya escuchando {puertos} (no se duplica)")
            continue
        if abiertos:
            print(f"{nombre}: AVISO puertos parcialmente abiertos {abiertos}; no se duplica")
            continue
        proc = _lanzar(nombre, argv)
        pids[nombre] = proc.pid
        for _ in range(int(espera * 10)):
            if all(puerto_abierto(BIND, p) for p in puertos):
                break
            time.sleep(0.1)
        ok = all(puerto_abierto(BIND, p) for p in puertos)
        print(f"{nombre}: pid={proc.pid} puertos={puertos} -> {'OK' if ok else 'FALLO'}")
        if not ok:
            fallos += 1
    _guardar_pids(pids)
    for nombre, puerto in REGLAS:
        creada = crear_regla(nombre, puerto)
        print(f"firewall {nombre}: {'creada' if creada else 'ya existente'} (TCP {puerto} desde {REMOTE})")
    return 0 if fallos == 0 else 1


def cmd_stop() -> int:
    pids = _leer_pids()
    for nombre, pid in sorted(pids.items()):
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                               capture_output=True, text=True)
            else:
                os.kill(int(pid), 15)
            print(f"{nombre}: parado (pid={pid})")
        except Exception as exc:  # noqa: BLE001 - se informa, no se oculta
            print(f"{nombre}: no se pudo parar pid={pid}: {exc}")
    if os.path.exists(PIDFILE):
        os.remove(PIDFILE)
    for nombre, _puerto in REGLAS:
        borrada = borrar_regla(nombre)
        print(f"firewall {nombre}: {'retirada' if borrada else 'no existía'}")
    return cmd_status()


def cmd_status() -> int:
    cerrados = 0
    for nombre, puertos, _argv in SERVICIOS:
        for p in puertos:
            abierto = puerto_abierto(BIND, p)
            print(f"{p}: {'ABIERTO' if abierto else 'cerrado'}")
            cerrados += 0 if abierto else 1
    total = sum(len(p) for _n, p, _a in SERVICIOS)
    print(f"resumen: {total - cerrados}/{total} abiertos")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Internet local del laboratorio (host).")
    ap.add_argument("accion", choices=("start", "stop", "status"))
    args = ap.parse_args(argv)
    if args.accion == "start":
        return cmd_start()
    if args.accion == "stop":
        return cmd_stop()
    return cmd_status()


if __name__ == "__main__":
    raise SystemExit(main())
