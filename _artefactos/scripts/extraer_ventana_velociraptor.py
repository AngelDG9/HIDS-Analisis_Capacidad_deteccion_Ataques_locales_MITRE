#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_ventana_velociraptor.py - lee los resultados de monitorizacion de Velociraptor y recorta una ventana.

Los ficheros del servidor (`datastore/clients/<id>/monitoring/<Artifact>/<YYYY-MM-DD>.json`) son JSON por lineas; segun la
version/origen pueden ser texto plano o VARIOS flujos zlib concatenados (error cometido el 2026-11-21: leer solo el primero).
`leer_filas` acepta ambos. Funciones puras y deterministas (misma entrada -> mismos bytes de salida) para poder probarlas.

Uso como libreria desde orquestar_velociraptor_linux.py; como script:
  python extraer_ventana_velociraptor.py --monitoring <dir monitoring> --t0 ISO --t1 ISO [--antes 60 --despues 120] --out dir
Sin secretos. Solo biblioteca estandar.
"""
import argparse
import csv
import datetime as dt
import glob
import gzip
import hashlib
import json
import os
import re
import zlib

# artifacts de eventos de Linux de los que se guarda todo
ARTIFACTS = ["Linux.Events.ProcessExecutions", "Linux.Events.EBPF", "Linux.Events.TrackProcesses", "Linux.Events.Journal",
             "Linux.Events.DNS", "Linux.Events.HTTPConnections", "Linux.Events.SSHLogin", "Linux.Events.SSHBruteforce"]


def _flujos(b):
    """Descomprime TODOS los flujos zlib concatenados (o devuelve tal cual si es texto)."""
    if b[:1] in (b"{", b"[", b"\n", b""):
        return b
    out = b""
    while b:
        o = zlib.decompressobj()
        out += o.decompress(b)
        b = o.unused_data
    return out


def leer_filas(path):
    """Lista de (linea_bytes, dict) en el orden del fichero; las lineas que no son JSON se ignoran."""
    if not os.path.isfile(path):
        return []
    res = []
    for linea in _flujos(open(path, "rb").read()).splitlines():
        linea = linea.strip()
        if not linea.startswith(b"{"):
            continue
        try:
            res.append((linea, json.loads(linea)))
        except ValueError:
            continue
    return res


def _iso(s):
    s = s.strip().replace("Z", "+00:00")
    if "." in s:                       # recorta nanosegundos a microsegundos
        cab, resto = s.split(".", 1)
        m = re.match(r"(\d+)(.*)", resto)
        s = cab + "." + m.group(1)[:6].ljust(6, "0") + m.group(2)
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def hora_evento(row):
    """Hora (UTC) del evento: la del propio evento si existe; si no, la de recepcion en el servidor (`_ts`, epoch s)."""
    for k in ("Time", "Timestamp", "timestamp", "EventTime"):
        v = row.get(k)
        if isinstance(v, str):
            try:
                return _iso(v)
            except ValueError:
                pass
    s = row.get("System")
    if isinstance(s, dict) and isinstance(s.get("Timestamp"), str):
        try:
            return _iso(s["Timestamp"])
        except ValueError:
            pass
    v = row.get("_ts")
    if isinstance(v, (int, float)):
        return dt.datetime.fromtimestamp(v, tz=dt.timezone.utc)
    return None


def recortar(filas, t0, t1):
    """Filas con t0 <= hora <= t1 (datetime con zona). Las filas sin hora legible se cuentan aparte (no se descartan en silencio)."""
    dentro, sin_hora = [], 0
    for linea, row in filas:
        h = hora_evento(row)
        if h is None:
            sin_hora += 1
        elif t0 <= h <= t1:
            dentro.append(linea)
    return dentro, sin_hora


def dias(t0, t1):
    d, out = t0.date(), []
    while d <= t1.date():
        out.append(d.isoformat())
        d += dt.timedelta(days=1)
    return out


def recortar_artifact(monitoring_dir, artifact, t0, t1, margen_lectura=600):
    """Se leen tambien los ficheros de los dias siguientes (hasta `margen_lectura` s tras t1): el servidor los clasifica por hora de RECEPCION."""
    filas = []
    for dia in dias(t0, t1 + dt.timedelta(seconds=margen_lectura)):
        filas += leer_filas(os.path.join(monitoring_dir, artifact, dia + ".json"))
    return recortar(filas, t0, t1)


def escribir_gz(path, lineas):
    """gzip determinista (mtime=0): la misma entrada da los mismos bytes."""
    with open(path, "wb") as fh, gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:   # sin nombre ni fecha en la cabecera
        for l in lineas:
            gz.write(l + b"\n")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ------------------------------------------------------------------ anclas (ground truth `*_esperado.csv`)
def cargar_anclas(esperado_csv):
    """Señales `tipo=deteccion` del fichero esperado: [(senal_id, campo, patron)]."""
    out = []
    with open(esperado_csv, encoding="utf-8") as fh:
        lineas = [l for l in fh if not l.startswith("#") and l.strip()]
    for r in csv.DictReader(lineas):
        if r.get("tipo") == "deteccion":
            out.append((r["senal_id"], r["campo"], r["patron"]))
    return out


def _base_cwd(patron):
    """`/ruta/ATA011/*` -> `/ruta/ATA011` (sin barra final: el directorio de trabajo real no la lleva)."""
    return patron.rstrip("*").rstrip("/")


def regex_ancla(campo, patron):
    """audit_exe: ejecutable como palabra completa (`dd` no casa con `add`); audit_cwd: la ruta (el `*` final = prefijo)."""
    if campo == "audit_cwd":
        return re.compile(re.escape(_base_cwd(patron)) + r"(?![A-Za-z0-9_])")
    return re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(patron) + r"(?![A-Za-z0-9_-])")


def contar_anclas(lineas, anclas):
    """{senal_id: n_filas_que_contienen_el_ancla} sobre las lineas JSON crudas de una ventana."""
    res = {}
    textos = [l.decode("utf-8", "replace") for l in lineas]
    for sid, campo, patron in anclas:
        rx = regex_ancla(campo, patron)
        res[sid] = sum(1 for t in textos if rx.search(t))
    return res


def contar_anclas_exec_ebpf(lineas, anclas):
    """Comprobacion ESTRICTA sobre eventos `sched_process_exec` de Linux.Events.EBPF (los unicos que son «arranque de proceso»):
    audit_exe  -> basename de `pathname`, de `cmdpath` o de `argv[0]` == patron (no subcadenas);
    audit_cwd  -> `pwd` empieza por la ruta (el `*` final = prefijo).  {senal_id: n_eventos}."""
    ev = []
    for l in lineas:
        try:
            r = json.loads(l)
        except ValueError:
            continue
        if (r.get("System") or {}).get("EventName") == "sched_process_exec":
            ev.append(r.get("EventData") or {})
    res = {}
    for sid, campo, patron in anclas:
        n = 0
        for d in ev:
            if campo == "audit_cwd":
                base, pwd = _base_cwd(patron), str(d.get("pwd", ""))
                if pwd == base or pwd.startswith(base + "/"):
                    n += 1
            else:
                nombres = {os.path.basename(str(d.get("pathname", ""))), os.path.basename(str(d.get("cmdpath", "")))}
                av = d.get("argv") or []
                if av:
                    nombres.add(os.path.basename(str(av[0])))
                if patron in nombres:
                    n += 1
        res[sid] = n
    return res


# ------------------------------------------------------------------ lineas de auditd (audit.log subido tal cual por Generic.Collectors.File)
_RX_AUDIT = re.compile(rb"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
_RX_CAMPO = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def hora_audit(linea):
    """Hora (UTC) de una linea de auditd (`msg=audit(EPOCH.ms:SEQ)`); None si no es una linea de auditd."""
    m = _RX_AUDIT.search(linea)
    return dt.datetime.fromtimestamp(float(m.group(1)), tz=dt.timezone.utc) if m else None


def recortar_audit(lineas, t0, t1):
    """Lineas de auditd con t0 <= hora <= t1 (las de un mismo evento comparten hora). Devuelve (dentro, n_sin_hora); lineas vacias se ignoran."""
    dentro, sin_hora = [], 0
    for l in lineas:
        if not l.strip():
            continue
        h = hora_audit(l)
        if h is None:
            sin_hora += 1
        elif t0 <= h <= t1:
            dentro.append(l)
    return dentro, sin_hora


def _valor_audit(v, entrecomillado):
    """auditd escribe en hexadecimal (sin comillas) los valores con espacios o caracteres raros."""
    if entrecomillado is not None:
        return entrecomillado
    if len(v) >= 2 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def contar_anclas_audit(lineas, anclas):
    """Anclas ESTRICTAS sobre auditd, por EVENTO (misma marca `msg=audit(ts:seq)`), solo eventos de comando (`key=audit-wazuh-c`, como la regla 80792 de Wazuh):
    audit_exe -> basename de `exe=` == patron;  audit_cwd -> `cwd=` (registro CWD del mismo evento) empieza por la ruta (el `*` final = prefijo).  {senal_id: n_eventos}."""
    ev = {}
    for l in lineas:
        m = _RX_AUDIT.search(l)
        if not m:
            continue
        t = l.decode("utf-8", "replace")
        d = ev.setdefault((m.group(1), m.group(2)), {"cmd": False, "exe": None, "cwd": None})
        campos = {k: _valor_audit(v, q if q != "" or v.startswith('"') else None) for k, v, q in _RX_CAMPO.findall(t)}
        if t.lstrip().startswith("type=SYSCALL"):
            if "audit-wazuh-c" in campos.get("key", ""):
                d["cmd"] = True
            d["exe"] = campos.get("exe")
        elif t.lstrip().startswith("type=CWD"):
            d["cwd"] = campos.get("cwd")
    res = {}
    for sid, campo, patron in anclas:
        n = 0
        for d in ev.values():
            if not d["cmd"]:
                continue
            if campo == "audit_cwd":
                base = _base_cwd(patron)
                if d["cwd"] is not None and (d["cwd"] == base or d["cwd"].startswith(base + "/")):
                    n += 1
            elif d["exe"] is not None and os.path.basename(d["exe"]) == patron:
                n += 1
        res[sid] = n
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--monitoring", required=True)
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--antes", type=int, default=60)
    ap.add_argument("--despues", type=int, default=120)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    t0 = _iso(a.t0) - dt.timedelta(seconds=a.antes)
    t1 = _iso(a.t1) + dt.timedelta(seconds=a.despues)
    os.makedirs(a.out, exist_ok=True)
    for art in ARTIFACTS:
        lineas, sin_hora = recortar_artifact(a.monitoring, art, t0, t1)
        escribir_gz(os.path.join(a.out, art + ".jsonl.gz"), lineas)
        print("%-34s filas=%6d sin_hora=%d" % (art, len(lineas), sin_hora))


if __name__ == "__main__":
    main()
