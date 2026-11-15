#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_sellos_windows.py — gate de sellos de Windows (C8, D-08).

Equivalente a `sha256sum -c` **sobre las rutas Windows** del sello global
`Soporte/Laboratorio/legitimo_72h/sha256sums.txt`, más la comprobación de
**cobertura** que `sha256sum -c` no hace:

1. **Formato**: cada línea es `<sha256>  <ruta>`; sin líneas malformadas.
2. **Duplicadas**: ninguna ruta aparece dos veces.
3. **Integridad** (`sha256sum -c`): toda entrada Windows declarada existe y su
   sha256 coincide con el fichero real.
4. **Cobertura**: toda ruta crítica de Windows está en el sello y existe. La lista
   `RUTAS_CRITICAS` es la lista blanca del plan §5.1 (recetas, campaña, control,
   invitado, sink, configuración, herramientas y tests) más los artefactos que
   ejecutan `prep`/`arm`/`crudo`/`cleanup` y los que calculan `M`/FPR.
5. **`sha256sum -c` real**: el sello no puede llevar CRLF; GNU `sha256sum -c`
   interpretaría `\\r` como parte del nombre y fallaría en todas las líneas.

Uso:
    python _artefactos/scripts/verificar_sellos_windows.py
    python _artefactos/scripts/verificar_sellos_windows.py --sello RUTA --raiz RUTA
    python _artefactos/scripts/verificar_sellos_windows.py --listar

Salida: una línea por comprobación, la lista de fallos y `RESULT=PASS|FAIL`.
Sin VMs, sin red, sin secretos. Devuelve 0 si PASS y 1 si FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SELLO = os.path.join(RAIZ, "Soporte", "Laboratorio", "legitimo_72h", "sha256sums.txt")

#: Lista blanca de artefactos Windows críticos (plan §5.1 + C8). Si uno no está en
#: el sello, la cobertura falla aunque `sha256sum -c` pase.
RUTAS_CRITICAS = (
    # recetas y campaña
    "Soporte/Laboratorio/windows/recetas/w1.json",
    "Soporte/Laboratorio/windows/recetas/w2.json",
    "Soporte/Laboratorio/windows/recetas/w3.json",
    "Soporte/Laboratorio/windows/recetas/calendario_windows.json",
    "Soporte/Laboratorio/windows/recetas/bloques_windows.env",
    "Soporte/Laboratorio/windows/recetas/receta_windows_resumen.md",
    "Soporte/Laboratorio/windows/campana/campana_windows.csv",
    "Soporte/Laboratorio/windows/campana/casos_windows.md",
    # control del host y del invitado
    "Soporte/Laboratorio/windows/windows_legit_host_control.ps1",
    "Soporte/Laboratorio/windows/deploy_windows.ps1",
    "Soporte/Laboratorio/windows/manifiesto_snapshot.ps1",
    "Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1",
    "Soporte/Laboratorio/windows/guest/preparar_invitado_windows.ps1",
    "Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1",
    "Soporte/Laboratorio/windows/guest/verificar_windows.ps1",
    # sink del latido y procedencia del cliente
    "Soporte/Laboratorio/windows/legit/heartbeat_sink.py",
    "Soporte/Laboratorio/windows/legit/heartbeat_sink_ctl.ps1",
    # auditoria 2026-11-13: vigilante del host (R-01) y cosecha del invitado (R-02)
    "Soporte/Laboratorio/windows/legit/watch_loop.ps1",
    "Soporte/Laboratorio/windows/legit/cosecha_invitado.ps1",
    "Soporte/Laboratorio/windows/legit/BUILD.md",
    "Soporte/Laboratorio/windows/legit/comparabilidad_windows.md",
    "Soporte/Laboratorio/windows/legit/snapshot_windows_legit.md",
    # configuración del cliente
    "Soporte/Laboratorio/windows/client_config/application.json",
    "Soporte/Laboratorio/windows/client_config/nlog.config",
    # herramientas
    "_artefactos/scripts/construir_receta_legitima_windows.py",
    "_artefactos/scripts/campana_windows.py",
    "_artefactos/scripts/extraer_alertas_windows.py",
    "_artefactos/scripts/extraer_campana_windows.py",
    "_artefactos/scripts/cobertura_herramientas_windows.py",
    "_artefactos/scripts/verificar_espejo.py",
    "_artefactos/scripts/verificar_paridad_windows.py",
    "_artefactos/scripts/verificar_sellos_windows.py",
    "_artefactos/scripts/etiquetar_operador_legit.py",
    "_artefactos/scripts/analizar_ensayo_windows.py",
    "_artefactos/scripts/filtrar_ruido_windows.py",
    "_artefactos/scripts/contar_denominador.py",
    # tests
    "_artefactos/scripts/tests/test_construir_receta_legitima_windows.py",
    "_artefactos/scripts/tests/test_verificar_paridad_windows.py",
    "_artefactos/scripts/tests/test_verificar_sellos_windows.py",
    "_artefactos/scripts/tests/test_campana_windows.py",
    "_artefactos/scripts/tests/test_verificar_espejo.py",
    "_artefactos/scripts/tests/test_extraer_alertas_windows.py",
    "_artefactos/scripts/tests/test_extraer_campana_windows.py",
    "_artefactos/scripts/tests/test_cobertura_herramientas_windows.py",
    "_artefactos/scripts/tests/test_ejecucion_windows.py",
    "_artefactos/scripts/tests/test_etiquetar_operador_legit.py",
    "_artefactos/scripts/tests/test_filtrar_ruido_windows.py",
    "_artefactos/scripts/tests/test_contar_denominador.py",
    "_artefactos/scripts/tests/test_watch_cosecha_windows.py",
    "_artefactos/scripts/tests/test_analizar_ensayo_windows.py",
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def es_ruta_windows(ruta: str) -> bool:
    """Rutas Windows del sello: el árbol del bloque o una herramienta/test crítico."""
    r = ruta.replace("\\", "/")
    return r.startswith("Soporte/Laboratorio/windows/") or r in RUTAS_CRITICAS


def leer_entradas(path: str):
    """Lee el sello conservando el `\\r` para detectar CRLF (sha256sum -c fallaría)."""
    entradas, crlf, malformadas = [], False, []
    with open(path, "rb") as fh:
        datos = fh.read()
    if b"\r\n" in datos:
        crlf = True
    for i, linea in enumerate(datos.decode("utf-8-sig", errors="replace").split("\n"), 1):
        crudo = linea
        if crudo.endswith("\r"):
            crudo = crudo[:-1]
        if not crudo.strip() or crudo.lstrip().startswith("#"):
            continue
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", crudo)
        if not m:
            malformadas.append({"linea": i, "texto": crudo[:120]})
            continue
        entradas.append({"linea": i, "hash": m.group(1).lower(),
                         "ruta": m.group(2).strip()})
    return entradas, crlf, malformadas


def _estado(ident: str, ok: bool, detalle: str):
    return {"id": ident, "estado": "OK" if ok else "FALLO", "detalle": detalle}


def comprobar(path: str = SELLO, raiz: str = RAIZ):
    """Devuelve (entradas, fallos). No escribe nada."""
    if not os.path.isfile(path):
        return [], [f"no existe el sello: {path}"]
    entradas, crlf, malformadas = leer_entradas(path)
    out, fallos = [], []

    out.append(_estado("SELLO-01", bool(entradas) and not malformadas,
                       f"{len(entradas)} entradas; malformadas={len(malformadas)}"))
    if malformadas:
        fallos.append(f"SELLO-01: líneas malformadas: "
                      f"{[m['linea'] for m in malformadas[:5]]}")

    rutas = [e["ruta"] for e in entradas]
    dup = sorted({r for r in rutas if rutas.count(r) > 1})
    out.append(_estado("SELLO-02", not dup,
                       f"duplicadas={len(dup)}" + (f": {dup[:5]}" if dup else "")))
    if dup:
        fallos.append(f"SELLO-02: rutas duplicadas: {dup[:5]}")

    obsoletas, ausentes = [], []
    for e in entradas:
        if not es_ruta_windows(e["ruta"]):
            continue
        p = os.path.join(raiz, e["ruta"])
        if not os.path.isfile(p):
            ausentes.append(e["ruta"])
            continue
        if sha256_file(p) != e["hash"]:
            obsoletas.append(e["ruta"])
    detalle = []
    if obsoletas:
        detalle.append(f"{len(obsoletas)} obsoletas: {obsoletas[:8]}")
    if ausentes:
        detalle.append(f"{len(ausentes)} ausentes: {ausentes[:8]}")
    out.append(_estado("SELLO-03", not obsoletas and not ausentes,
                       "; ".join(detalle) if detalle else
                       "todas las entradas Windows cuadran con el fichero real"))
    if obsoletas:
        fallos.append(f"SELLO-03: {len(obsoletas)} entradas obsoletas: {obsoletas}")
    if ausentes:
        fallos.append(f"SELLO-03: {len(ausentes)} entradas ausentes: {ausentes}")

    declaradas = set(rutas)
    faltan = [p for p in RUTAS_CRITICAS if p not in declaradas]
    sin_fichero = [p for p in RUTAS_CRITICAS if not os.path.isfile(os.path.join(raiz, p))]
    out.append(_estado("SELLO-04", not faltan and not sin_fichero,
                       "cobertura completa" if not faltan and not sin_fichero else
                       f"faltan del sello: {faltan}; sin fichero: {sin_fichero}"))
    if faltan:
        fallos.append(f"SELLO-04: {len(faltan)} rutas críticas sin sellar: {faltan}")
    if sin_fichero:
        fallos.append(f"SELLO-04: {len(sin_fichero)} rutas críticas sin fichero: {sin_fichero}")

    out.append(_estado("SELLO-05", not crlf,
                       "sello en LF (compatible con `sha256sum -c`)" if not crlf else
                       "sello con CRLF: `sha256sum -c` interpretaría `\\r` como parte "
                       "del nombre y fallaría"))
    if crlf:
        fallos.append("SELLO-05: el sello tiene CRLF; reescribirlo en LF")
    return out, fallos


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="Gate de sellos Windows (C8)")
    ap.add_argument("--sello", default=SELLO, help="sha256sums.txt global")
    ap.add_argument("--raiz", default=RAIZ, help="raíz del repositorio")
    ap.add_argument("--listar", action="store_true",
                    help="imprime la lista blanca de rutas críticas y sale")
    args = ap.parse_args(argv)

    if args.listar:
        for p in RUTAS_CRITICAS:
            print(p)
        return 0

    entradas, fallos = comprobar(args.sello, args.raiz)
    print(f"== SELLOS WINDOWS — {os.path.relpath(args.sello, args.raiz)} ==")
    for e in entradas:
        print(f"[{e['estado']}] {e['id']}: {e['detalle']}")
    if fallos:
        print("FALLOS:")
        for f in fallos:
            print(f"  - {f}")
    print("RESULT=" + ("PASS" if not fallos else "FAIL"))
    return 0 if not fallos else 1


if __name__ == "__main__":
    raise SystemExit(main())
