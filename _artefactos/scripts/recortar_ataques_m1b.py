#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recortar_ataques_m1b.py — M1b · re-corte determinista de las 128 ventanas de ataque.

**No re-ejecuta ataques**: re-clasifica las alertas ya extraídas (`-Detalle.csv`) con el
catálogo de ruido **M1b** (`catalogo_M1b.csv`, 15 reglas) y deja los nuevos
`-Audited.csv` en `Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado/`.

Reglas del plan (`plan.md` §6.2):
  1. La fuente de cada ventana se toma de la **cabecera** del `-Audited.csv` original
     (`alerta`, `esperado`, `revision` y sus `sha256`). Si un `sha256` no coincide con el
     fichero actual -> **PARAR** (no aproximar).
  2. Se invoca `filtrar_ruido.py` con el catálogo M1b y las mismas entradas. El original
     es **solo lectura**.
  3. Se compara el **contenido de datos** (sin líneas de comentario `#`) del original y
     del nuevo. Cualquier diferencia se registra en `diff.csv` y hace fallar la
     herramienta (`exit != 0`) para que no se acepte sin revisión humana.
  4. La **sensibilidad** (catálogo 72 h puro, 11 reglas) se ejecuta aparte en
     `M1b/sensibilidad_72h/` y **no** es canónica.

Salidas (deterministas, sin reloj):
  - `M1b/Auditado/<ventana>-Audited.csv` (128)
  - `M1b/Auditado/<ventana>-Revision.csv` (solo si quedan `dudosa`)
  - `M1b/diff.csv` (0 filas esperadas)
  - `M1b/resumen_recorte.csv`
  - `M1b/MANIFEST_sha256.tsv`
  - `M1b/sensibilidad_72h/{Auditado,diff.csv,resumen_recorte.csv,MANIFEST_sha256.tsv}`
"""

from __future__ import annotations

import argparse
import csv
import difflib
import glob
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tabla_comun as TC  # noqa: E402

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
FILTRAR = os.path.join(SCRIPTS_DIR, "filtrar_ruido.py")

DEFAULT_AUDITADO_ORIGEN = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_CATALOGO = "Dataset/Legitimo/legitimo_72h/analisis/catalogo_M1b.csv"
DEFAULT_CATALOGO_SENS = "Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv"
DEFAULT_OUT_DIR = "Dataset/Ataques/Resultados/Wazuh/linux/M1b"

RE_ENTRADA = re.compile(
    r"^(alerta|esperado|revision|catalogo)=(.+?) sha256=([0-9a-f]{64})$"
)
RE_ATA_ITER = re.compile(r"\bata=(\S+)\s+iter=(\d+)\b")
RE_NOMBRE = re.compile(r"^(ATA\d+)_(?:iter|rev)(\d+)-Audited\.csv$")


def _sha256(path: str) -> str:
    return TC.sha256_file(path)


def _leer_cabecera(path: str) -> tuple[str, dict]:
    """Devuelve `(cabecera, entradas)` de un `-Audited.csv` original."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        cabecera = fh.readline().rstrip("\r\n")
    entradas = {}
    for parte in cabecera.split(" | "):
        m = RE_ENTRADA.match(parte.strip())
        if m:
            entradas[m.group(1)] = (m.group(2).strip(), m.group(3))
    return cabecera, entradas


def _data_lines(path: str) -> list[str]:
    """Líneas de datos (sin comentarios `#` ni la cabecera CSV), normalizando CRLF."""
    out = []
    primera = True
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for ln in fh:
            ln = ln.rstrip("\r\n")
            if TC.es_comentario(ln):
                continue
            if primera:
                primera = False  # cabecera de columnas, idéntica en ambos ficheros
                continue
            out.append(ln)
    return out


def _diff_lineas(a: list[str], b: list[str]) -> list[tuple[str, str, str]]:
    """Lista `(tipo, linea_a, linea_b)` con las diferencias de datos."""
    diffs = []
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace":
            for k in range(max(i2 - i1, j2 - j1)):
                la = a[i1 + k] if i1 + k < i2 else ""
                lb = b[j1 + k] if j1 + k < j2 else ""
                diffs.append(("replace", la, lb))
        elif tag == "delete":
            for k in range(i1, i2):
                diffs.append(("delete", a[k], ""))
        elif tag == "insert":
            for k in range(j1, j2):
                diffs.append(("insert", "", b[k]))
    return diffs


def _escribir_csv(path: str, header: list[str], rows: list[dict], comment: str | None = None) -> None:
    TC.write_csv(path, header, rows, comment=comment)


def _verificar_entradas(nombre: str, entradas: dict) -> list[str]:
    errores = []
    for etiqueta in ("alerta", "esperado", "revision"):
        if etiqueta not in entradas:
            if etiqueta == "revision":
                continue
            errores.append(f"{nombre}: falta '{etiqueta}' en la cabecera")
            continue
        ruta, sha = entradas[etiqueta]
        if not os.path.isfile(ruta):
            errores.append(f"{nombre}: {etiqueta} no existe: {ruta}")
            continue
        real = _sha256(ruta)
        if real != sha:
            errores.append(f"{nombre}: {etiqueta} sha256 no coincide ({real} != {sha})")
    return errores


def _procesar(
    auditado_origen: str, out_dir: str, catalogo: str, etiqueta: str, canonica: bool
) -> dict:
    """Re-ejecuta todas las ventanas y escribe diff + resumen + manifest."""
    catalogo_abs = os.path.join(TC.ROOT, catalogo)
    if not os.path.isfile(catalogo_abs):
        raise SystemExit(f"ERROR: no existe el catálogo: {catalogo_abs}")

    origen_abs = os.path.join(TC.ROOT, auditado_origen)
    out_abs = os.path.join(TC.ROOT, out_dir)
    auditado_out = os.path.join(out_abs, "Auditado")
    os.makedirs(auditado_out, exist_ok=True)

    ficheros = sorted(glob.glob(os.path.join(origen_abs, "*-Audited.csv")))
    if not ficheros:
        raise SystemExit(f"ERROR: no hay '-Audited.csv' en {origen_abs}")

    resumen = []
    diferencias = []
    manifest = []
    errores_globales = []

    for i, original in enumerate(ficheros, start=1):
        nombre = os.path.basename(original)
        m_nombre = RE_NOMBRE.match(nombre)
        if not m_nombre:
            errores_globales.append(f"{nombre}: nombre no reconocido")
            continue
        ata = m_nombre.group(1)
        _, entradas = _leer_cabecera(original)
        m_ata = RE_ATA_ITER.search(_leer_cabecera(original)[0])
        it = int(m_ata.group(2)) if m_ata else int(m_nombre.group(2))

        errores = _verificar_entradas(nombre, entradas)
        if errores:
            errores_globales.extend(errores)
            continue

        alerta = entradas["alerta"][0]
        esperado = entradas["esperado"][0]
        revision = entradas.get("revision", (None, None))[0]

        salida = os.path.join(auditado_out, nombre)
        rev_salida = os.path.join(auditado_out, nombre.replace("-Audited.csv", "-Revision.csv"))
        cmd = [
            sys.executable,
            FILTRAR,
            "--alerta",
            alerta,
            "--ata",
            ata,
            "--iter",
            str(it),
            "--catalogo",
            catalogo,
            "--esperado",
            esperado,
            "--out",
            salida,
            "--rev-out",
            rev_salida,
        ]
        if revision:
            cmd.extend(["--revision", revision])

        proc = subprocess.run(
            cmd,
            cwd=TC.ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            errores_globales.append(
                f"{nombre}: filtrar_ruido exit={proc.returncode}\n{proc.stderr.strip()}"
            )
            continue

        a = _data_lines(original)
        b = _data_lines(salida)
        diffs = _diff_lineas(a, b)
        for tipo, la, lb in diffs:
            diferencias.append(
                {
                    "fichero": nombre,
                    "tipo": tipo,
                    "linea_original": la,
                    "linea_m1b": lb,
                }
            )
        resumen.append(
            {
                "fichero": nombre,
                "filas_original": len(a),
                "filas_m1b": len(b),
                "lineas_distintas": len(diffs),
                "exit_code": proc.returncode,
                "sha256_original": _sha256(original),
                "sha256_m1b": _sha256(salida),
            }
        )
        manifest.append({"fichero": nombre, "sha256": _sha256(salida)})
        print(
            f"[{etiqueta}] {i:3d}/{len(ficheros)} {nombre}: filas={len(b)} "
            f"distintas={len(diffs)}"
        )

    diff_path = os.path.join(out_abs, "diff.csv")
    _escribir_csv(
        diff_path,
        ["fichero", "tipo", "linea_original", "linea_m1b"],
        diferencias,
        comment=(
            "# diff.csv | M1b | comparacion de DATOS (sin lineas '#') entre "
            f"{auditado_origen} y {out_dir}/Auditado | diferencias={len(diferencias)}"
        ),
    )
    resumen_path = os.path.join(out_abs, "resumen_recorte.csv")
    _escribir_csv(
        resumen_path,
        [
            "fichero",
            "filas_original",
            "filas_m1b",
            "lineas_distintas",
            "exit_code",
            "sha256_original",
            "sha256_m1b",
        ],
        resumen,
        comment=(
            f"# resumen_recorte.csv | M1b | ventanas={len(ficheros)} | "
            f"procesadas={len(resumen)} | catalogo={catalogo} | out={out_dir}"
        ),
    )
    manifest_path = os.path.join(out_abs, "MANIFEST_sha256.tsv")
    with open(manifest_path, "w", encoding="utf-8", newline="") as fh:
        fh.write("# MANIFEST_sha256.tsv | M1b | sha256 de los -Audited.csv generados\n")
        for r in manifest:
            fh.write(f"{r['fichero']}\t{r['sha256']}\n")

    return {
        "ventanas": len(ficheros),
        "procesadas": len(resumen),
        "diferencias": len(diferencias),
        "errores": errores_globales,
        "out_dir": out_dir,
        "catalogo": catalogo,
        "canonica": canonica,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="M1b — re-corte determinista de las 128 ventanas de ataque."
    )
    ap.add_argument("--auditado-origen", default=DEFAULT_AUDITADO_ORIGEN)
    ap.add_argument("--catalogo", default=DEFAULT_CATALOGO)
    ap.add_argument("--catalogo-sensibilidad", default=DEFAULT_CATALOGO_SENS)
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--filtro", default="filtrar_ruido.py",
                    help="script de filtrado en _artefactos/scripts (Windows: filtrar_ruido_windows.py)")
    ap.add_argument("--permitir-diferencias", action="store_true",
                    help="en la tanda canonica, las lineas distintas vs el origen NO son error (Windows: el catalogo M1b-W si cambia categorias)")
    ap.add_argument(
        "--solo",
        choices=("canonica", "sensibilidad", "ambas"),
        default="ambas",
        help="qué tanda ejecutar (por defecto ambas)",
    )
    args = ap.parse_args(argv)
    global FILTRAR
    FILTRAR = os.path.join(SCRIPTS_DIR, args.filtro)

    resultados = []
    if args.solo in ("canonica", "ambas"):
        resultados.append(
            _procesar(
                args.auditado_origen,
                args.out_dir,
                args.catalogo,
                "M1b",
                True,
            )
        )
    if args.solo in ("sensibilidad", "ambas"):
        resultados.append(
            _procesar(
                args.auditado_origen,
                os.path.join(args.out_dir, "sensibilidad_72h"),
                args.catalogo_sensibilidad,
                "sens72h",
                False,
            )
        )

    fallo = False
    for r in resultados:
        print(
            f"RESUMEN {r['out_dir']}: ventanas={r['ventanas']} "
            f"procesadas={r['procesadas']} diferencias={r['diferencias']} "
            f"errores={len(r['errores'])}"
        )
        if r["errores"]:
            fallo = True
            for e in r["errores"]:
                print(f"ERROR: {e}", file=sys.stderr)
        if r["diferencias"] and r["canonica"] and not args.permitir_diferencias:
            fallo = True
            print(
                f"ERROR: {r['diferencias']} lineas de datos distintas en {r['out_dir']}/diff.csv",
                file=sys.stderr,
            )
        elif r["diferencias"]:
            print(
                f"AVISO: {r['diferencias']} lineas distintas en {r['out_dir']}/diff.csv "
                "(sensibilidad NO canonica; se documenta, no invalida M1b)"
            )
    return 1 if fallo else 0


if __name__ == "__main__":
    raise SystemExit(main())
