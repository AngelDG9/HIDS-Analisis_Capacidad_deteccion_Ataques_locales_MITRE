#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""serve_site.py — servidor web estático de la "internet local" del TFG (bloque L0).

Parte de la **"internet local"** (laboratorio aislado): sirve un sitio pequeño y creíble
(intranet/portal/noticias) y una carpeta de **descargas** de juguete para que GHOSTS (u otro
cliente) tenga webs que visitar y ficheros que descargar **sin salir a internet**.

Vive en el **HOST** (`192.168.65.1`, VMnet1), fuera de las VMs medidas. Es **solo biblioteca
estándar** de Python 3 (cero dependencias) — la idea del plan es `python -m http.server`, aquí
envuelto en un script para: fijar el puerto, registrar accesos en un log y no exponer el listado
de directorios.

Registra **una línea por petición** en `--log`:

    <UTC> <IP> "<METHOD> <ruta> HTTP/x" <código> <bytes> "<user-agent>"

Uso (HOST):

    python serve_site.py --bind 192.168.65.1 --port 8080 \
        --root "Soporte/Laboratorio/internet_local/site" \
        --log  "…/internet_local/web_access.log"
"""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SiteHandler(http.server.SimpleHTTPRequestHandler):
    """Sirve el sitio y registra cada acceso (sin listar directorios)."""

    server_version = "TFG-Intranet/1.0"

    def list_directory(self, path):  # noqa: D401  (evita el índice automático)
        self.send_error(403, "Directory listing is disabled")
        return None

    def log_message(self, fmt: str, *args) -> None:  # sobrescribe el log de stderr
        line = "%s %s %s" % (utc_now(), self.client_address[0], fmt % args)
        try:
            with open(self.server.log_path, "a", encoding="utf-8") as fh:  # type: ignore[attr-defined]
                fh.write(line + "\n")
        except OSError:
            pass


class SiteServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, log_path: str):
        super().__init__(addr, handler)
        self.log_path = log_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Servidor web estático de la internet local (TFG HIDS).")
    ap.add_argument("--bind", default="192.168.65.1", help="IP del host en VMnet1")
    ap.add_argument("--port", type=int, default=8080, help="puerto HTTP")
    ap.add_argument("--root", required=True, help="raíz del sitio a servir")
    ap.add_argument("--log", default="web_access.log", help="fichero de log (append)")
    args = ap.parse_args(argv)

    handler = lambda *a, **kw: SiteHandler(*a, directory=args.root, **kw)  # noqa: E731
    try:
        server = SiteServer((args.bind, args.port), handler, args.log)
    except OSError as exc:
        print(f"ERROR: no se pudo escuchar en {args.bind}:{args.port} -> {exc}", file=sys.stderr)
        return 2

    with open(args.log, "a", encoding="utf-8") as fh:
        fh.write(f"# serve_site arrancado {utc_now()} bind={args.bind} port={args.port} root={args.root}\n")

    print(f"# serve_site escuchando en http://{args.bind}:{args.port}/ (root={args.root})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n# serve_site detenido por teclado", flush=True)
    finally:
        server.server_close()
        with open(args.log, "a", encoding="utf-8") as fh:
            fh.write(f"# serve_site detenido {utc_now()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
