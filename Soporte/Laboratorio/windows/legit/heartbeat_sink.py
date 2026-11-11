#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""heartbeat_sink.py — receptor del chivato (latido) de la ventana legítima Windows.

Vive en el **HOST** (no en la VM). Escucha en `192.168.65.1:9095` (VMnet1) y acepta
`POST /heartbeat` con un JSON de **<= 1 KB**. Por cada latido escribe **una línea**
en `heartbeat.jsonl` (append) y una línea en el log del sink (append).

Campos que **añade** el sink a cada línea (además de los que manda el invitado):

    recv_utc      hora UTC de recepción (reloj del host)
    delta_s       recv_utc - ts_envio (o ts_utc si el emisor es antiguo)
    delta_ref     campo usado para `delta_s` (`ts_envio` en el contrato v4)
    body_sha256   sha256 del cuerpo CRUDO recibido
    cadena        OK | INICIO | REINICIO_BUCLE | ROTA | ROTA_SEQ
    seq_ok        true/false (seq > último seq visto)

**Cadena de integridad.** El invitado manda `sha256_prev` = sha256 del cuerpo que
envió en el latido anterior. El sink comprueba `sha256_prev == body_sha256` de la
línea anterior. Un proceso nuevo del invitado no conoce el hash previo (manda cadena
vacía) ⇒ `REINICIO_BUCLE` (declarado, no manipulación). Una edición de una línea del
JSONL rompe el `sha256_prev` de la siguiente ⇒ `ROTA`.

**Puerto ocupado ⇒ `exit 48`** (sin fallback silencioso). Para que Windows no permita
dos binds al mismo puerto se desactiva `SO_REUSEADDR` (`allow_reuse_address = False`).

`POST /test` valida el contrato (JSON <= 1 KB) y responde `{"ok":true,"test":true}`
**sin escribir** en `heartbeat.jsonl`: es el POST de prueba de `prep` y no rompe ni
`seq` ni la cadena `sha256_prev`.

Solo biblioteca estándar. **Sin secretos.**

Uso (HOST):

    python heartbeat_sink.py --bind 192.168.65.1 --port 9095 \
        --out ".../legit/evidencia/t2a/heartbeat.jsonl" \
        --log ".../legit/evidencia/t2a/heartbeat_sink.log"

No sustituye a `Soporte/Ataques/receiver/sink_http.py` (puertos 9090/9091/9092).
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import sys
import threading
from datetime import datetime, timezone

DEFAULT_BIND = "192.168.65.1"
DEFAULT_PORT = 9095
DEFAULT_OUT = "heartbeat.jsonl"
DEFAULT_LOG = "heartbeat_sink.log"
MAX_BODY = 1024          # 1 KB (contrato del plan)
MAX_OUT_BYTES = 5 * 1024 * 1024  # rotación defensiva a 5 MB


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts: str):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


class Estado:
    """Estado compartido (cadena + seq) y escritura serializada."""

    def __init__(self, out_path: str, log_path: str):
        self.out_path = out_path
        self.log_path = log_path
        self.lock = threading.Lock()
        self.expected = None   # body_sha256 de la última línea
        self.last_seq = None
        self.n = 0
        self._seed()

    def _seed(self) -> None:
        if not os.path.exists(self.out_path):
            return
        try:
            with open(self.out_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 65536))
                lineas = fh.read().decode("utf-8", "replace").strip().splitlines()
            if lineas:
                last = json.loads(lineas[-1])
                self.expected = last.get("body_sha256")
                self.last_seq = last.get("seq")
                self.n = len(lineas)
        except Exception:
            pass

    def log(self, linea: str) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(linea + "\n")
        except OSError:
            pass

    def _rotar(self) -> None:
        try:
            if os.path.getsize(self.out_path) >= MAX_OUT_BYTES:
                os.replace(self.out_path, self.out_path + ".1")
                self.expected = None
                self.last_seq = None
                self.log(f"{utc_now()} rotacion out={self.out_path} -> .1")
        except OSError:
            pass

    def registrar(self, body: dict, raw: bytes, ip: str) -> dict:
        recv = utc_now()
        sha = hashlib.sha256(raw).hexdigest()
        prev = body.get("sha256_prev") or ""
        with self.lock:
            if self.expected is None:
                cadena = "INICIO" if not prev else "OK"
            elif prev == self.expected:
                cadena = "OK"
            elif prev == "":
                cadena = "REINICIO_BUCLE"
            else:
                cadena = "ROTA"

            seq_ok = True
            try:
                seq_ok = (self.last_seq is None) or (int(body.get("seq")) > int(self.last_seq))
            except (TypeError, ValueError):
                seq_ok = False
            if not seq_ok:
                cadena = "ROTA_SEQ"

            t0 = None
            delta_ref = None
            for campo in ("ts_envio", "ts_utc"):
                t0 = parse_ts(body.get(campo))
                if t0 is not None:
                    delta_ref = campo
                    break
            delta = None
            if t0 is not None:
                delta = round((datetime.now(timezone.utc) - t0).total_seconds(), 3)

            linea = dict(body)  # conserva el orden del invitado
            linea["recv_utc"] = recv
            linea["delta_s"] = delta
            linea["delta_ref"] = delta_ref
            linea["body_sha256"] = sha
            linea["cadena"] = cadena
            linea["seq_ok"] = seq_ok

            self._rotar()
            with open(self.out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(linea, ensure_ascii=False, separators=(",", ":")) + "\n")

            self.expected = sha
            try:
                self.last_seq = int(body.get("seq"))
            except (TypeError, ValueError):
                pass
            self.n += 1
            self.log(
                f"{recv} POST /heartbeat from={ip} len={len(raw)} "
                f"seq={body.get('seq')} cadena={cadena} delta={delta}"
            )
            return {"ok": True, "cadena": cadena, "seq": body.get("seq")}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "TFG-HeartbeatSink/1.0"

    def _estado(self) -> Estado:
        return self.server.estado  # type: ignore[attr-defined]

    def _json(self, code: int, obj: dict) -> None:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        ruta = self.path.split("?")[0]
        if ruta not in ("/heartbeat", "/test"):
            self._json(404, {"ok": False, "error": "ruta"})
            return
        length = self.headers.get("Content-Length")
        n = int(length) if length and length.isdigit() else 0
        if n > MAX_BODY:
            self.rfile.read(n)
            self._estado().log(
                f"{utc_now()} RECHAZO from={self.client_address[0]} len={n} motivo=gt_1KB"
            )
            self._json(413, {"ok": False, "error": "cuerpo > 1 KB"})
            return
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            body = json.loads(raw.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("no es objeto")
        except (UnicodeDecodeError, ValueError):
            self._estado().log(
                f"{utc_now()} RECHAZO from={self.client_address[0]} len={len(raw)} motivo=json"
            )
            self._json(400, {"ok": False, "error": "JSON inválido"})
            return
        if ruta == "/test":
            # POST de prueba de `prep`: valida el contrato (JSON <= 1 KB) SIN escribir
            # en `heartbeat.jsonl` (no rompe `seq` ni la cadena `sha256_prev`).
            self._estado().log(
                f"{utc_now()} TEST from={self.client_address[0]} len={len(raw)} ok"
            )
            self._json(200, {"ok": True, "test": True, "len": len(raw)})
            return
        res = self._estado().registrar(body, raw, self.client_address[0])
        self._json(200, res)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] == "/health":
            self._json(200, {"ok": True, "n": self._estado().n})
            return
        self._json(404, {"ok": False, "error": "ruta"})

    def log_message(self, fmt: str, *args) -> None:
        pass


class Sink(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # En Windows SO_REUSEADDR permite re-bindear un puerto ya escuchado: lo apagamos
    # para que "puerto ocupado" sea un error real (exit 48).
    allow_reuse_address = False

    def __init__(self, addr, handler, estado: Estado):
        super().__init__(addr, handler)
        self.estado = estado


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sink del latido (TFG HIDS, ventana legítima Windows).")
    ap.add_argument("--bind", default=DEFAULT_BIND, help="IP del host en VMnet1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="puerto TCP (9095)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="JSONL de latidos (append)")
    ap.add_argument("--log", default=DEFAULT_LOG, help="log del sink (append)")
    args = ap.parse_args(argv)

    estado = Estado(args.out, args.log)
    try:
        server = Sink((args.bind, args.port), Handler, estado)
    except OSError as exc:
        msg = f"{utc_now()} ERROR no se pudo escuchar en {args.bind}:{args.port} -> {exc}"
        print(msg, file=sys.stderr, flush=True)
        estado.log(msg)
        return 48  # contrato del plan: puerto ocupado ⇒ exit 48

    estado.log(
        f"# heartbeat_sink arrancado {utc_now()} bind={args.bind} port={args.port} "
        f"pid={os.getpid()} out={args.out}"
    )
    print(f"# heartbeat_sink escuchando en http://{args.bind}:{args.port}/heartbeat", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n# heartbeat_sink detenido por teclado", flush=True)
    finally:
        server.server_close()
        estado.log(f"# heartbeat_sink detenido {utc_now()} latidos={estado.n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
