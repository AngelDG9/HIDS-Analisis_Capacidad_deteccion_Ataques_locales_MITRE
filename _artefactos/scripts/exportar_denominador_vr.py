#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exportar_denominador_vr.py - denominador `M` de la ventana de 72 h con Velociraptor (V1-L). Sustituye a `exportar_denominador.sh` + `contar_denominador.py` de Wazuh.

M NO se define como en Wazuh (no hay `archives.json` ni agente): se cuenta POR OJO, por hora del EVENTO (no por fichero ni por hora de recepcion):
  ebpf     = filas de Linux.Events.EBPF con System.Timestamp en [t0,t1]   (de crudo_servidor/monitoring; recorta por la hora del evento)
  auditd   = EVENTOS de auditd (marca msg=audit(ts:seq)) con ts en [t0,t1] (de la subida de audit.log* por Velociraptor; lineas = registros sueltos)
Borde: [t0,t1] inclusivo, como en Wazuh. Comprueba ademas que la copia por `tar` (cosecha) y la subida por Velociraptor contienen los MISMOS eventos de auditd.
Productos (mismos nombres y columnas que Wazuh, con un ambito por ojo): denominador_M.csv, estabilidad_hora.csv, estabilidad_dia.csv.
Uso: python exportar_denominador_vr.py --cosecha D:\\TFG-VMs\\legitimo-vr-AAAA-MM-DD --t0 ... --t1 ... --out DIR [--boveda 2]
Sin secretos. Solo biblioteca estandar + el extractor del repo.
"""
import argparse
import collections
import datetime as dt
import glob
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extraer_ventana_velociraptor as ext       # noqa: E402

RX_TS = re.compile(rb'"Timestamp":\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)')
RX_AUD = re.compile(rb"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")


def iso(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def epoch(d):
    return d.replace(tzinfo=dt.timezone.utc).timestamp()


def _lineas_fichero(p):
    """Lineas JSON de un fichero del datastore (JSONL plano o varias corrientes zlib concatenadas), SIN cargarlo entero en memoria."""
    with open(p, "rb") as fh:
        ini = fh.read(1)
        fh.seek(0)
        if ini == b"{":
            for l in fh:
                if l.startswith(b"{"):
                    yield l
            return
        pend = b""
        d = zlib.decompressobj()
        while True:
            blk = fh.read(1 << 20)
            if not blk:
                break
            while blk:
                try:
                    out = d.decompress(blk)
                except zlib.error:
                    return
                pend += out
                *lineas, pend = pend.split(b"\n")
                for l in lineas:
                    if l.startswith(b"{"):
                        yield l
                if d.eof:
                    blk = d.unused_data
                    d = zlib.decompressobj()
                else:
                    blk = b""
        if pend.startswith(b"{"):
            yield pend


def lineas_ebpf(cosecha):
    for p in sorted(glob.glob(os.path.join(cosecha, "crudo_servidor", "monitoring", "Linux.Events.EBPF", "*.json"))):
        yield from _lineas_fichero(p)


def bytes_audit_vr(cosecha):
    """Contenido (descomprimido) de cada audit.log* subido por Velociraptor: {nombre: bytes}."""
    r = {}
    for p in glob.glob(os.path.join(cosecha, "crudo_servidor", "collections", "*", "uploads", "auto", "var", "log", "audit", "audit.log*")):
        if p.endswith(".chunk"):
            continue
        b = open(p, "rb").read()
        try:
            b = ext._flujos(b)
        except Exception:                                                   # noqa: BLE001 - fichero no zlib
            pass
        r[os.path.basename(p)] = b
    return r


def bytes_audit_tar(cosecha):
    r = {}
    p = os.path.join(cosecha, "evidencia", "root_audit.tar.gz")
    if not os.path.isfile(p):
        return r
    with tarfile.open(p, "r:gz") as t:
        for m in t.getmembers():
            if m.isfile() and os.path.basename(m.name).startswith("audit.log"):
                r[os.path.basename(m.name)] = t.extractfile(m).read()
    return r


def eventos_audit(blobs, t0, t1):
    """{(ts,seq)} de eventos dentro de [t0,t1] y recuento de lineas."""
    ev, lineas = set(), 0
    a, b = epoch(t0), epoch(t1)
    for nombre, blob in blobs.items():
        for l in blob.splitlines():
            m = RX_AUD.search(l)
            if not m:
                continue
            ts = float(m.group(1))
            if a <= ts <= b:
                ev.add((m.group(1), m.group(2)))
                lineas += 1
    return ev, lineas


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cosecha", required=True)
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--boveda", default="2")
    a = ap.parse_args()
    t0, t1 = iso(a.t0), iso(a.t1)
    os.makedirs(a.out, exist_ok=True)
    hora_eb, dia_eb, primero, ultimo, n_eb = collections.Counter(), collections.Counter(), None, None, 0
    ini, fin = epoch(t0), epoch(t1)
    for l in lineas_ebpf(a.cosecha):
        m = RX_TS.search(l)
        if not m:
            continue
        d = dt.datetime.strptime(m.group(1).decode(), "%Y-%m-%dT%H:%M:%S")
        e = epoch(d)
        if not (ini <= e <= fin):
            continue
        n_eb += 1
        hora_eb[d.strftime("%Y-%m-%dT%H:00Z")] += 1
        dia_eb[d.strftime("%Y-%m-%d")] += 1
        primero = d if primero is None or d < primero else primero
        ultimo = d if ultimo is None or d > ultimo else ultimo
    vr_blobs, tar_blobs = bytes_audit_vr(a.cosecha), bytes_audit_tar(a.cosecha)
    ev_vr, lin_vr = eventos_audit(vr_blobs, t0, t1)
    ev_tar, lin_tar = eventos_audit(tar_blobs, t0, t1)
    hora_au, dia_au = collections.Counter(), collections.Counter()
    for ts, _ in ev_vr:
        d = dt.datetime.fromtimestamp(float(ts), tz=dt.timezone.utc)
        hora_au[d.strftime("%Y-%m-%dT%H:00Z")] += 1
        dia_au[d.strftime("%Y-%m-%d")] += 1
    iguales = (ev_vr == ev_tar) if tar_blobs else None
    cab = "# denominador_M.csv | Velociraptor V1-L | metrica_version=1 boveda_version=%s | desde=%s hasta=%s | ebpf=Linux.Events.EBPF (filas por hora del evento) auditd=subida de audit.log* por Velociraptor (eventos por msg=audit(ts:seq)) | borde=[t0,t1] inclusivo" % (a.boveda, a.t0, a.t1)
    f = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""      # noqa: E731
    pa = min((float(t) for t, _ in ev_vr), default=None)
    ua = max((float(t) for t, _ in ev_vr), default=None)
    fa = lambda x: dt.datetime.fromtimestamp(x, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if x else ""  # noqa: E731
    with open(os.path.join(a.out, "denominador_M.csv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cab + "\nmetrica_version,boveda_version,ambito,eventos,primer_ts,ultimo_ts\n")
        fh.write("1,%s,ebpf,%d,%s,%s\n" % (a.boveda, n_eb, f(primero), f(ultimo)))
        fh.write("1,%s,auditd_eventos,%d,%s,%s\n" % (a.boveda, len(ev_vr), fa(pa), fa(ua)))
        fh.write("1,%s,auditd_lineas,%d,,\n" % (a.boveda, lin_vr))
    horas = sorted(set(hora_eb) | set(hora_au))
    with open(os.path.join(a.out, "estabilidad_hora.csv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# estabilidad_hora.csv | Velociraptor V1-L | filas EBPF y eventos de auditd por hora UTC del evento (sin FP: aun no hay reglas C2/C3)\nhora_utc,M_ebpf,M_auditd\n")
        for h in horas:
            fh.write("%s,%d,%d\n" % (h, hora_eb[h], hora_au[h]))
    with open(os.path.join(a.out, "estabilidad_dia.csv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# estabilidad_dia.csv | Velociraptor V1-L | por dia UTC del evento\ndia,M_ebpf,M_auditd\n")
        for d in sorted(set(dia_eb) | set(dia_au)):
            fh.write("%s,%d,%d\n" % (d, dia_eb[d], dia_au[d]))
    res = {"ebpf_filas": n_eb, "auditd_eventos_vr": len(ev_vr), "auditd_lineas_vr": lin_vr, "auditd_eventos_tar": len(ev_tar),
           "auditd_vr_igual_tar": iguales, "ficheros_audit_vr": sorted(vr_blobs), "ficheros_audit_tar": sorted(tar_blobs),
           "horas": len(horas)}
    json.dump(res, open(os.path.join(a.out, "denominador_resumen.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))
    if iguales is False:
        print("AVISO: la subida de Velociraptor y la copia por tar NO tienen los mismos eventos de auditd")
        sys.exit(2)


if __name__ == "__main__":
    main()
