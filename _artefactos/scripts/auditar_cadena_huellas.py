#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auditar_cadena_huellas.py — Auditoría de la cadena de huellas (TV8 / CA-B8).

Comprueba que **cada `sha256` citado** sobre un fichero del repositorio coincide
con el `sha256` **real** de ese fichero. Cobertura (solo lectura):

  * `Bitacora/ATA<NNN>.json`   -> campos `*_sha256` cuyo valor cita un **fichero**
    (se excluyen los hashes de **contenido**, p. ej. `sha256_cuerpo`).
  * `Dataset/Ataques/Resultados/Wazuh/linux/ATA<NNN>_meta.md` -> `sha256=<hex>`
    (se asocia al nombre de fichero más cercano hacia atrás).
  * Cabeceras de `-Audited.csv` / `-Revision.csv` -> `etiqueta=<ruta> sha256=<hex>`.
  * `Dataset/Ataques/Comandos/*/ATA<NNN>_esperado.csv` (cabeceras, por si citan).

No modifica nada. Exit 0 = cadena coherente; exit 1 = desincronías (las lista).

Uso:  python _artefactos/scripts/auditar_cadena_huellas.py [--repo RAIZ]
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX64_ANY = re.compile(r"[0-9a-f]{64}")
# Nombre de fichero "citable" dentro de una ficha (para asociar el sha256).
FNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]*\.(?:sh|csv|txt|md|log|py|html|json)\b")

# Campos de `Bitacora/*.json` que citan un **fichero** (los de contenido se omiten).
JSON_FILE_KEYS = {
    "esperado_sha256",
    "ataque_sha256",
    "cron_job_sha256",
    "logtest_sha256",
    "preflight_sha256",
    "detalle_sha256",
    "detalle_raw_sha256",
    "audited_sha256",
    "revision_sha256",
    "sink_log_sha256",
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(ref: str) -> str:
    return (ref or "").strip().strip('"').replace("\\", "/").lstrip("./")


def ataque_id(path: str) -> str | None:
    m = re.search(r"(ATA\d{3})", os.path.basename(path))
    return m.group(1) if m else None


class Auditor:
    def __init__(self, root: str):
        self.root = root
        self.findings: list[str] = []
        self.observaciones: list[str] = []
        self.checked = 0
        self.skipped = 0

    # ---- utilidades -----------------------------------------------------
    def real(self, ref: str) -> str | None:
        p = os.path.join(self.root, norm(ref))
        return p if os.path.isfile(p) else None

    def check(self, where: str, ref: str, cited: str) -> None:
        """Verifica una cita `sha256` sobre el fichero `ref`."""
        cited = (cited or "").strip().lower()
        if not HEX64.match(cited):
            return
        if ref is None:
            self.skipped += 1
            return
        p = self.real(ref)
        if p is None:
            self.skipped += 1
            return
        self.checked += 1
        real = sha256_file(p)
        if real != cited:
            self.findings.append(
                f"[{where}] {norm(ref)}\n"
                f"    citado = {cited}\n"
                f"    real   = {real}"
            )

    # ---- Bitacora -------------------------------------------------------
    def audit_bitacora(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        ata = data.get("ata_id") or ataque_id(path)
        artefacto = norm(data.get("artefacto", ""))
        rel = lambda name: (artefacto + ("" if artefacto.endswith("/") else "/") + name)  # noqa: E731

        # nivel raíz
        self.check(f"{ata}/bitacora:esperado_sha256", rel(f"{ata}_esperado.csv"),
                   data.get("esperado_sha256"))
        self.check(f"{ata}/bitacora:ataque_sha256", rel(f"{ata}_ataque.sh"),
                   data.get("ataque_sha256"))
        if data.get("cron_job_sha256"):
            self.check(f"{ata}/bitacora:cron_job_sha256", rel("cron_job.sh"),
                       data.get("cron_job_sha256"))
        c0 = data.get("c0") or {}
        self.check(f"{ata}/bitacora:logtest_sha256", c0.get("logtest"),
                   c0.get("logtest_sha256"))
        self.check(f"{ata}/bitacora:preflight_sha256", c0.get("preflight"),
                   c0.get("preflight_sha256"))

        for it in data.get("iteraciones", []) or []:
            n = it.get("iter", "?")
            self.check(f"{ata}/bitacora:iter{n}.detalle_sha256", it.get("detalle"),
                       it.get("detalle_sha256"))
            if it.get("detalle_raw_sha256"):
                raw_ref = re.sub(r"-Detalle\.csv$", "-Detalle_raw.csv",
                                 norm(it.get("detalle", "")))
                self.check(f"{ata}/bitacora:iter{n}.detalle_raw_sha256", raw_ref,
                           it.get("detalle_raw_sha256"))
            self.check(f"{ata}/bitacora:iter{n}.audited_sha256", it.get("audited"),
                       it.get("audited_sha256"))
            self.check(f"{ata}/bitacora:iter{n}.revision_sha256", it.get("revision"),
                       it.get("revision_sha256"))
            efecto = it.get("efecto") or {}
            if efecto.get("sink_log_sha256"):
                self.check(f"{ata}/bitacora:iter{n}.sink_log_sha256", efecto.get("sink_log"),
                           efecto.get("sink_log_sha256"))

    # ---- Fichas (meta.md) ----------------------------------------------
    def _resolve_basename(self, ata: str, basename: str, artefacto: str) -> str | None:
        c0dir = "Soporte/Ataques/c0"
        if basename == f"{ata}_ataque.sh":
            return artefacto + basename
        if basename == f"{ata}_esperado.csv":
            return artefacto + basename
        if basename == "cron_job.sh":
            return artefacto + basename
        if basename.endswith("_logtest.txt"):
            return f"{c0dir}/{basename}"
        if basename.endswith("_preflight.md"):
            return f"{c0dir}/{basename}"
        # glob único por nombre en el repo
        hits = glob.glob(os.path.join(self.root, "**", basename), recursive=True)
        hits = [h for h in hits if os.path.isfile(h)]
        if len(hits) == 1:
            return os.path.relpath(hits[0], self.root).replace("\\", "/")
        return None

    def audit_meta(self, path: str) -> None:
        ata = ataque_id(path)
        artefacto = None
        for m in re.finditer(r"`?\.\.\./([A-Za-z0-9_.\-]+)/ATA\d{3}_ataque\.sh`?", open(path, encoding="utf-8").read()):
            artefacto = "Dataset/Ataques/Comandos/" + m.group(1) + "/"
            break
        if artefacto is None:
            hits = glob.glob(os.path.join(
                self.root, "Dataset", "Ataques", "Comandos", "*", f"{ata}_ataque.sh"))
            if len(hits) == 1:
                artefacto = os.path.relpath(os.path.dirname(hits[0]), self.root).replace("\\", "/") + "/"

        text = open(path, encoding="utf-8").read()
        # Nombres que SÍ forman parte de la "cadena de huellas" de la técnica. Los
        # `sha256` de **contenido** (artifact, sink.log, passwd.gz...) no lo son y se
        # omiten: su nombre más cercano no está en esta lista blanca.
        def es_cadena(basename: str) -> bool:
            return (
                basename in (f"{ata}_ataque.sh", f"{ata}_esperado.csv", "cron_job.sh")
                or basename.endswith("_logtest.txt")
                or basename.endswith("_preflight.md")
            )

        prev_end = 0
        for m in HEX64_ANY.finditer(text):
            cited = m.group(0)
            span = text[prev_end:m.start()]
            prev_end = m.end()
            names = FNAME.findall(span)
            if not names or not es_cadena(names[-1]):
                self.skipped += 1
                continue
            ref = self._resolve_basename(ata, names[-1], artefacto or "")
            if ref is None:
                self.skipped += 1
                continue
            self.check(f"{ata}/meta", ref, cited)

    # ---- Cabeceras CSV --------------------------------------------------
    CSV_CITE = re.compile(r"([A-Za-z_]+)=(\S+)\s+sha256=([0-9a-f]{64})")

    def audit_csv(self, path: str) -> None:
        if not (path.endswith("-Audited.csv") or path.endswith("-Revision.csv")):
            return
        ata = ataque_id(path)
        self_ref = os.path.relpath(path, self.root).replace("\\", "/")
        with open(path, "r", encoding="utf-8") as fh:
            for _ in range(3):
                line = fh.readline()
                if not line or not line.lstrip().startswith("#"):
                    break
                for m in self.CSV_CITE.finditer(line):
                    label, ref, cited = m.group(1), m.group(2), m.group(3)
                    if label == "catalogo":
                        ref = "Dataset/Legitimo/ruleids_legitimos.csv"
                    # Autocita en un `-Revision.csv`: el `revision=` de su cabecera apunta
                    # al propio fichero (huella de linaje del plegado, no verificable:
                    # un fichero no puede contener su propio sha256). Se declara, no es
                    # una desincronía corregible.
                    if path.endswith("-Revision.csv") and label == "revision" \
                            and norm(ref) == norm(self_ref):
                        self.observaciones.append(
                            f"[{ata}/{os.path.basename(path)}] autocita `revision=` "
                            f"(huella de linaje, no verificable): citado={cited}")
                        self.skipped += 1
                        continue
                    self.check(f"{ata}/{os.path.basename(path)}:{label}", norm(ref), cited)

    # ---- Esperado -------------------------------------------------------
    def audit_esperado(self, path: str) -> None:
        ata = ataque_id(path)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.lstrip().startswith("#"):
                    break
                for m in self.CSV_CITE.finditer(line):
                    label, ref, cited = m.group(1), m.group(2), m.group(3)
                    self.check(f"{ata}/esperado:{label}", norm(ref), cited)

    # ---- Preflight C0 (metadatos del examen) ----------------------------
    PRE_CITE = re.compile(r"(\S+)\s+sha256=([0-9a-f]{64})")

    def audit_preflight(self, path: str) -> None:
        ata = ataque_id(path)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                for m in self.PRE_CITE.finditer(line):
                    ref, cited = m.group(1), m.group(2)
                    self.check(f"{ata}/preflight", norm(ref), cited)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Auditoría de la cadena de huellas (TV8).")
    ap.add_argument("--repo", default=None, help="raíz del repositorio")
    args = ap.parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    root = args.repo or os.path.abspath(os.path.join(here, "..", ".."))
    os.chdir(root)
    au = Auditor(root)

    for path in sorted(glob.glob(os.path.join(root, "Bitacora", "ATA*.json"))):
        au.audit_bitacora(path)
    for path in sorted(glob.glob(os.path.join(
            root, "Dataset", "Ataques", "Resultados", "Wazuh", "linux", "ATA*_meta.md"))):
        au.audit_meta(path)
    for path in sorted(glob.glob(os.path.join(
            root, "Dataset", "Ataques", "Resultados", "Wazuh", "linux", "Auditado", "ATA*-*.csv"))):
        au.audit_csv(path)
    for path in sorted(glob.glob(os.path.join(
            root, "Dataset", "Ataques", "Comandos", "*", "ATA*_esperado.csv"))):
        au.audit_esperado(path)
    for path in sorted(glob.glob(os.path.join(
            root, "Soporte", "Ataques", "c0", "ATA*_preflight.md"))):
        au.audit_preflight(path)

    print(f"citas verificadas={au.checked}  omitidas(no-fichero/no-resueltas)={au.skipped}")
    if au.observaciones:
        print("\nOBSERVACIONES (no son desincronías corregibles):")
        for o in au.observaciones:
            print("  - " + o)
    if au.findings:
        print(f"\nDESINCRONIAS={len(au.findings)}", file=sys.stderr)
        for f in au.findings:
            print(f, file=sys.stderr)
        return 1
    print("cadena de huellas COHERENTE (0 desincronías)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
