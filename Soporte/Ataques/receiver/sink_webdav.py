#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sink_webdav.py — receptor WebDAV mínimo (solo stdlib) para ATA049/T1567.002.

Vive en el **HOST** (no en las VMs): es el *servicio de almacenamiento en la nube
montado en el laboratorio*. El atacante (víctima) sube ficheros con un cliente de
nube real (`rclone`, backend WebDAV). El receptor:

- guarda cada cuerpo subido bajo `--root`;
- registra **una línea por PUT** en `--log`:

      <UTC> PUT <ruta> from=<IP> len=<N> sha256=<hash>

La línea con el `sha256` es la **evidencia primaria** de la exfiltración (el
fichero llegó y su hash coincide con el enviado). No guarda secretos.

Cubre lo mínimo que usa el cliente `rclone` (backend WebDAV): `OPTIONS`,
`PROPFIND` (Depth 0/1), `MKCOL`, `PUT`, `GET`, `HEAD`, `DELETE`.

Uso (HOST):
    python sink_webdav.py --bind 192.168.65.1 --port 9090 \
        --root ".../cloud_bucket" --log ".../Logs/ATA049_iterN/sink.log"
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WebDavHandler(BaseHTTPRequestHandler):
    server_version = "TFG-WebDav/1.0"

    # ---- utilidades -------------------------------------------------------
    def _root(self) -> str:
        return self.server.root  # type: ignore[attr-defined]

    def _log_path(self) -> str:
        return self.server.log_path  # type: ignore[attr-defined]

    def _append(self, line: str) -> None:
        with open(self._log_path(), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)

    def _local_path(self, fs_path: str) -> str:
        rel = urllib.parse.unquote(fs_path).lstrip("/")
        # neutraliza traversal
        parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
        return os.path.join(self._root(), *parts)

    def _read_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        n = int(length) if length and length.isdigit() else 0
        return self.rfile.read(n) if n > 0 else b""

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # silencio
        pass

    # ---- WebDAV -----------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("DAV", "1, 2")
        self.send_header("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _propstat(self, href: str, is_dir: bool, size: int) -> str:
        rtype = "<D:collection/>" if is_dir else ""
        return (
            "<D:response>"
            f"<D:href>{href}</D:href>"
            "<D:propstat><D:prop>"
            "<D:displayname>%s</D:displayname>"
            "<D:resourcetype>%s</D:resourcetype>"
            "<D:getcontentlength>%d</D:getcontentlength>"
            "<D:getcontenttype>application/octet-stream</D:getcontenttype>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
            "</D:response>"
        ) % (os.path.basename(href.rstrip("/")) or "/", rtype, size)

    def do_PROPFIND(self) -> None:  # noqa: N802
        depth = self.headers.get("Depth", "1")
        local = self._local_path(self.path)
        parts = ["<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                 "<D:multistatus xmlns:D=\"DAV:\">"]
        if os.path.isdir(local):
            parts.append(self._propstat(self.path.rstrip("/") + "/", True, 0))
            if depth != "0":
                for name in sorted(os.listdir(local)):
                    p = os.path.join(local, name)
                    href = self.path.rstrip("/") + "/" + urllib.parse.quote(name)
                    parts.append(self._propstat(href, os.path.isdir(p),
                                                os.path.getsize(p)))
        elif os.path.exists(local):
            parts.append(self._propstat(self.path, False, os.path.getsize(local)))
        else:
            self._send(404)
            return
        parts.append("</D:multistatus>")
        body = "".join(parts).encode("utf-8")
        self.send_response(207)
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_MKCOL(self) -> None:  # noqa: N802
        local = self._local_path(self.path)
        if os.path.exists(local):
            self._send(405)
            return
        os.makedirs(local, exist_ok=True)
        self._send(201)

    def do_PUT(self) -> None:  # noqa: N802
        body = self._read_body()
        local = self._local_path(self.path)
        os.makedirs(os.path.dirname(local), exist_ok=True)
        with open(local, "wb") as fh:
            fh.write(body)
        sha = hashlib.sha256(body).hexdigest() if body else "-"
        self._append(
            f"{utc_now()} PUT {self.path} from={self.client_address[0]} "
            f"len={len(body)} sha256={sha}"
        )
        self._send(201)

    def do_GET(self) -> None:  # noqa: N802
        local = self._local_path(self.path)
        if os.path.isfile(local):
            with open(local, "rb") as fh:
                body = fh.read()
            self._send(200, body, "application/octet-stream")
        else:
            self._send(404)

    def do_HEAD(self) -> None:  # noqa: N802
        local = self._local_path(self.path)
        if os.path.isfile(local):
            self.send_response(200)
            self.send_header("Content-Length", str(os.path.getsize(local)))
            self.end_headers()
        else:
            self._send(404)

    def do_DELETE(self) -> None:  # noqa: N802
        local = self._local_path(self.path)
        if os.path.isfile(local):
            os.remove(local)
            self._send(204)
        elif os.path.isdir(local):
            try:
                os.rmdir(local)
                self._send(204)
            except OSError:
                self._send(409)
        else:
            self._send(404)


class WebDavServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, root: str, log_path: str):
        super().__init__(addr, handler)
        self.root = root
        self.log_path = log_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Receptor WebDAV mínimo (TFG HIDS).")
    ap.add_argument("--bind", default="192.168.65.1")
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--root", required=True, help="directorio del 'bucket'")
    ap.add_argument("--log", default="sink.log")
    args = ap.parse_args(argv)

    os.makedirs(args.root, exist_ok=True)
    try:
        server = WebDavServer((args.bind, args.port), WebDavHandler, args.root, args.log)
    except OSError as exc:
        print(f"ERROR: no se pudo escuchar en {args.bind}:{args.port} -> {exc}",
              file=sys.stderr)
        return 2
    with open(args.log, "a", encoding="utf-8") as fh:
        fh.write(f"# sink_webdav arrancado {utc_now()} bind={args.bind} port={args.port}\n")
    print(f"# sink_webdav escuchando en http://{args.bind}:{args.port}/ root={args.root}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n# sink_webdav detenido por teclado", flush=True)
    finally:
        server.server_close()
        with open(args.log, "a", encoding="utf-8") as fh:
            fh.write(f"# sink_webdav detenido {utc_now()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
