#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sink_http.py — receptor HTTP efímero para la exfiltración de ATA008 (T1048.002).

Vive en el **HOST / sobremesa** (no en las VMs): el manager es el *detector* y no
debe ejecutar nada durante el ataque; el receptor escucha en la **IP del host en
VMnet1** (`192.168.65.0/24`, normalmente `192.168.65.1`).

Por cada petición, escribe **una línea** en `--log` (por defecto `sink.log`):

    <UTC> <método> <ruta> from=<IP> len=<N> sha256=<hash> content_type=<...>

- Registra **método, ruta, IP de origen, longitud, Content-Type y sha256 del
  cuerpo**: esa línea es la **evidencia primaria** de que el dato salió de la
  víctima (el cuerpo en sí **no** se guarda en disco, solo su hash).
- Responde `200 OK` a `POST`/`PUT` para que el `POST` de la víctima tenga éxito.
- `GET` responde un texto mínimo para usarlo como *health check*.

Solo **biblioteca estándar** de Python 3. Sin secretos. Uso (en el sobremesa):

    python sink_http.py --bind 192.168.65.1 --port 9090 --log "…/Logs/ATA008_iterN/sink.log"

Arrancarlo **antes de `t0`** y pararlo **después de `t1`** (runbook:
`Soporte/Ataques/piloto_procedimiento.md` §3).
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import sys
from datetime import datetime, timezone

DEFAULT_PORT = 9090
DEFAULT_LOG = "sink.log"


def utc_now() -> str:
    """Marca UTC en el mismo formato que los t0/t1 del piloto."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SinkHandler(http.server.BaseHTTPRequestHandler):
    """Handler que registra metadatos + sha256 del cuerpo y responde 200."""

    server_version = "TFG-Sink/1.0"

    # ---- utilidades -------------------------------------------------------
    def _log_path(self) -> str:
        return self.server.log_path  # type: ignore[attr-defined]

    def _append(self, line: str) -> None:
        with open(self._log_path(), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        n = int(length) if length and length.isdigit() else 0
        return self.rfile.read(n) if n > 0 else b""

    def _register(self, method: str, body: bytes) -> None:
        sha = hashlib.sha256(body).hexdigest() if body else "-"
        ctype = self.headers.get("Content-Type", "-")
        self._append(
            f"{utc_now()} {method} {self.path} from={self.client_address[0]} "
            f"len={len(body)} sha256={sha} content_type={ctype}"
        )

    def _reply_200(self, text: bytes = b"OK\n") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text)

    # ---- métodos HTTP -----------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802 (nombre impuesto por http.server)
        body = self._read_body()
        self._register("POST", body)
        self._reply_200()

    def do_PUT(self) -> None:  # noqa: N802
        body = self._read_body()
        self._register("PUT", body)
        self._reply_200()

    def do_GET(self) -> None:  # noqa: N802
        self._register("GET", b"")
        self._reply_200(b"TFG sink OK\n")

    def log_message(self, fmt: str, *args) -> None:  # silencio en stderr
        pass


class SinkServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, log_path: str):
        super().__init__(addr, handler)
        self.log_path = log_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Receptor HTTP efímero de exfiltración (TFG HIDS, ATA008/T1048.002)."
    )
    ap.add_argument("--bind", default="192.168.65.1", help="IP del host en VMnet1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="puerto TCP")
    ap.add_argument("--log", default=DEFAULT_LOG, help="fichero de log (append)")
    args = ap.parse_args(argv)

    try:
        server = SinkServer((args.bind, args.port), SinkHandler, args.log)
    except OSError as exc:
        print(f"ERROR: no se pudo escuchar en {args.bind}:{args.port} -> {exc}", file=sys.stderr)
        return 2

    with open(args.log, "a", encoding="utf-8") as fh:
        fh.write(f"# sink_http arrancado {utc_now()} bind={args.bind} port={args.port}\n")

    print(f"# sink_http escuchando en http://{args.bind}:{args.port}/ (log={args.log})",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n# sink_http detenido por teclado", flush=True)
    finally:
        server.server_close()
        with open(args.log, "a", encoding="utf-8") as fh:
            fh.write(f"# sink_http detenido {utc_now()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())