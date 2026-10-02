#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATA046_app.py — APP local DESECHABLE (T1499.003 Application Exhaustion Flood).

App HTTP mono-hilo en loopback (127.0.0.1) cuyo endpoint `/compute` realiza un
calculo ACOTADO pero CARO (PBKDF2-HMAC-SHA256). Se levanta en el PRE-STAGING
(antes de t0) y se para tras t1: la ventana mide SOLO el flood de peticiones
caras que lanza el cliente (`curl`), no el arranque de la app.

Uso:  python3 ATA046_app.py <puerto> <fichero_log>
Solo biblioteca estandar. Sin secretos. No escucha fuera de loopback.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9093
LOG = sys.argv[2] if len(sys.argv) > 2 else "app.log"
ITER = 300_000


def expensive() -> str:
    """Calculo voluntariamente caro en CPU (acotado por ITER)."""
    return hashlib.pbkdf2_hmac("sha256", b"tfg-hids", b"ata046-salt", ITER).hex()


class AppHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TFG-App/1.0"

    def do_GET(self) -> None:  # noqa: N802
        t0 = time.time()
        if self.path.startswith("/compute"):
            digest = expensive()
        else:
            digest = "-"
        dt = time.time() - t0
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{ts} GET {self.path} compute_s={dt:.3f}\n")
        body = (json.dumps({"digest": digest[:16], "compute_s": round(dt, 3)}) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silencio
        pass


class AppServer(http.server.HTTPServer):
    # Mono-hilo a proposito: las peticiones concurrentes se serializan -> se puede
    # observar el agotamiento por cola (latencia creciente) del servicio.
    daemon_threads = False
    allow_reuse_address = True


if __name__ == "__main__":
    AppServer(("127.0.0.1", PORT), AppHandler).serve_forever()
