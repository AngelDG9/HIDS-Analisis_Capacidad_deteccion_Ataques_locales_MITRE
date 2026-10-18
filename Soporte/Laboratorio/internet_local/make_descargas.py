#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_descargas.py — genera los ficheros de descarga de juguete de la internet local.

Determinista (sin aleatoriedad) para que el material sea reproducible: crea un **PDF mínimo
válido**, un **CSV** y un **ZIP** de ejemplo bajo `site/descargas/`. Solo biblioteca estándar.

Uso:
    python make_descargas.py --out Soporte/Laboratorio/internet_local/site/descargas
"""

from __future__ import annotations

import argparse
import io
import os
import zipfile


def _minimal_pdf(text: str) -> bytes:
    """Construye un PDF 1.4 mínimo con una línea de texto (válido y abrible)."""
    lines = ["BT /F1 16 Tf 72 700 Td (" + text + ") Tj ET"]
    content = "\n".join(lines).encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i)
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_pos = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objects) + 1))
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1))
    out.write(b"startxref\n%d\n%%%%EOF\n" % xref_pos)
    return out.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Genera descargas de juguete de la internet local.")
    ap.add_argument("--out", required=True, help="carpeta site/descargas")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    with open(os.path.join(args.out, "manual_empleado.pdf"), "wb") as fh:
        fh.write(_minimal_pdf("Manual del empleado - edicion de ejemplo (laboratorio TFG)"))

    csv = (
        "mes,departamento,responsable,horas,incidencias\n"
        "enero,Recursos Humanos,Ana Ruiz,160,2\n"
        "febrero,Informatica,Luis Gomez,158,1\n"
        "marzo,Compras,Marta Diaz,162,0\n"
    )
    with open(os.path.join(args.out, "plantilla_informe.csv"), "w", encoding="utf-8", newline="") as fh:
        fh.write(csv)

    # ZIP determinista (mismas marcas de tiempo → mismo sha256).
    zip_path = os.path.join(args.out, "paquete_datos.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in [
            ("datos/ventas.csv", b"id,importe\n1,120.50\n2,89.99\n"),
            ("datos/leeme.txt", b"Paquete de datos de ejemplo del portal interno.\n"),
        ]:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)

    for n in ("manual_empleado.pdf", "plantilla_informe.csv", "paquete_datos.zip"):
        p = os.path.join(args.out, n)
        print(f"{n}\t{os.path.getsize(p)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
