#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""construir_receta_legitima.py — receta de actividad legítima del TFG (bloque `legitimo-fix`).

Genera **tres timelines GHOSTS** (un día de oficina cada una, `d1/d2/d3`), su **calendario**
(`calendario.json` + `bloques.env`, la misma fuente para la vigilancia y el keepalive) y un
**resumen** legible (`receta_resumen.md`). Incluye un **validador** (`--check`) con todos los
invariantes del plan (§5.5, §5.7, DT10) y un modo **dry** (`--dry --base HH:MMZ`) que comprime
la jornada ×40 para la prueba en seco DT9.

Principios (plan §5.1) — todos verificados por `--check`:

1. **Jornada de oficina** 09:00–18:00 local (08:00–17:00 UTC), con café (20 min) y comida (60 min).
2. **Ráfagas y pausas**: ráfagas de acciones a 40–60 s separadas por huecos; **hueco máximo
   intra-bloque ≤ 12 min** (validado; el plan admite hasta 20).
3. **Determinismo**: solo `Command` (bash). **Cero** `"Command":"random"`, **cero** delays
   aleatorios (`delay-jitter`), **cero** handler `Curl` (inyecta UA aleatoria) y **cero**
   handlers de navegador (`Browser*`).
4. **Bloques disjuntos** (una ventana UTC por bloque, sin solape) ⇒ sin concurrencia.
5. **Legítimo por construcción**: lista blanca de binarios; rutas solo bajo `/home/angel`
   (más `/dev/null`); sin `sudo`; sin dobles comillas en los comandos.
6. **Sesión web *browser-like* con `curl`** (§5.7): UA fija y honesta, cookie jar, `Referer`,
   `Accept`/`Accept-Encoding`, requisitos de página (CSS/JS/SVG) y descarga real del PDF.
   Ocupa **8 posiciones que ya existían** ⇒ **no cambia el recuento** (111/117/105).

Uso:
    python _artefactos/scripts/construir_receta_legitima.py            # genera
    python _artefactos/scripts/construir_receta_legitima.py --check    # valida lo versionado
    python _artefactos/scripts/construir_receta_legitima.py --dry --base 10:00Z --out /tmp/dry.json

Salida por defecto: `Soporte/Laboratorio/legitimo_72h/recetas/`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Constantes de la receta (una sola fuente de verdad)
# --------------------------------------------------------------------------
VERSION_RECETA = 1

DOC = "/home/angel/Documentos"
DOWN = "/home/angel/Descargas"
CACHE = "/home/angel/.cache/tfg-web"
COOKIES = CACHE + "/cookies.txt"
WEB = "http://intranet.local:8080"
PASTE = "http://intranet.local:9090"
CLOUD = "http://nube.local:9092"
UA = "TFG-Legit/1.0 (Linux; x86_64; sesion-web)"

# Bloques del día (UTC). Local = UTC+1 (Europe/Madrid, tras el DST del 2026-10-25).
BLOQUES = [
    {"id": "B1", "on": "08:00:00", "off": "08:12:00", "tipo": "trabajo",
     "nombre": "Llegada", "local": "09:00-09:12"},
    {"id": "B2", "on": "08:12:00", "off": "10:00:00", "tipo": "trabajo",
     "nombre": "Correo y mañana", "local": "09:12-11:00"},
    {"id": "P1", "on": "10:00:00", "off": "10:20:00", "tipo": "pausa",
     "nombre": "Café", "local": "11:00-11:20"},
    {"id": "B3", "on": "10:20:00", "off": "13:00:00", "tipo": "trabajo",
     "nombre": "Documentos", "local": "11:20-14:00"},
    {"id": "P2", "on": "13:00:00", "off": "14:00:00", "tipo": "pausa",
     "nombre": "Comida", "local": "14:00-15:00"},
    {"id": "B4", "on": "14:00:00", "off": "16:15:00", "tipo": "trabajo",
     "nombre": "Reuniones y tarde", "local": "15:00-17:15"},
    {"id": "B5", "on": "16:15:00", "off": "17:00:00", "tipo": "trabajo",
     "nombre": "Cierre", "local": "17:15-18:00"},
]
JORNADA = ("08:00:00", "17:00:00")

# Recuento por día (plan §5.3/§5.4)
CUENTAS = {
    1: {"B1": 9, "B2": 26, "B3": 42, "B4": 22, "B5": 12},   # 111
    2: {"B1": 9, "B2": 32, "B3": 34, "B4": 30, "B5": 12},   # 117
    3: {"B1": 9, "B2": 22, "B3": 46, "B4": 16, "B5": 12},   # 105
}
TEMAS = {1: "cierre de informes", 2: "reuniones y portal", 3: "revisión y copias"}

# Mapeo de días de la ventana propuesta (26/10 lunes → d1)
MAPA_DIAS = {"2026-10-26": 1, "2026-10-27": 2, "2026-10-28": 3}

# Plan de tiempos: ráfagas mínimas por bloque y separación intra-ráfaga (s)
PLAN_TIMES = {
    "B1": {"min_rafagas": 3, "intra": 45},
    "B2": {"min_rafagas": 10, "intra": 50},
    "B3": {"min_rafagas": 13, "intra": 50},
    "B4": {"min_rafagas": 12, "intra": 50},
    "B5": {"min_rafagas": 6, "intra": 50},
}
CAP_HUECO_S = 720          # 12 min (plan §5.2)
COLA_FIN_S = 120           # la última acción cae 2 min antes de UtcTimeOff
GUARDIAN_S = 60            # el último DelayAfter acaba 1 min DESPUÉS de UtcTimeOff

# Lista blanca (plan §5.1-6)
BINARIOS_OK = {
    "mkdir", "echo", "cat", "cp", "mv", "tar", "gzip", "md5sum", "sha256sum",
    "ls", "find", "du", "df", "wc", "date", "curl", "grep", "head", "tail",
    "stat", "rm", "true",
}

HANDLERS_PROHIBIDOS = {"BrowserFirefox", "BrowserChrome", "Curl", "NpcSystem"}
PLACEHOLDERS = ("{uuid}", "{n}", "{c}", "{now}")

# Posiciones globales de la sesión web (¶5.7): B1-6..8 y B3-36..40
WEB_POS_B1 = (6, 7, 8)
WEB_POS_B3 = (36, 37, 38, 39, 40)


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def hms_to_s(h: str) -> int:
    hh, mm, ss = (int(x) for x in h.split(":"))
    return hh * 3600 + mm * 60 + ss


def bloque_por_id(bid: str):
    return next(b for b in BLOQUES if b["id"] == bid)


def dur_bloque(bid: str) -> int:
    b = bloque_por_id(bid)
    return hms_to_s(b["off"]) - hms_to_s(b["on"])


def repartir(n: int, c: int):
    """Reparte `n` acciones en `c` ráfagas lo más iguales posible (determinista)."""
    base, extra = divmod(n, c)
    return [base + 1] * extra + [base] * (c - extra)


def plan_tiempos(n: int, dur_s: int, min_rafagas: int, intra_s: int,
                 cap_s: int = CAP_HUECO_S, cola_s: int = COLA_FIN_S):
    """Desplazamientos (s, desde el inicio del bloque) de las `n` acciones.

    Estructura: `c` ráfagas de 2–6 acciones separadas `intra_s`; huecos entre ráfagas
    calculados para que la última acción caiga `cola_s` antes de `UtcTimeOff`.
    """
    if n <= 1:
        return [0]
    objetivo = dur_s - cola_s
    c = None
    for cand in range(max(2, min_rafagas), n + 1):
        intra_total = (n - cand) * intra_s
        inter = (objetivo - intra_total) / (cand - 1)
        if 120 <= inter <= cap_s:
            c = cand
            break
    if c is None:                     # no cabe: usa el máximo de ráfagas
        c = n
        intra_total = 0
        inter = 0
    intra_total = (n - c) * intra_s
    inter = (objetivo - intra_total) / (c - 1) if c > 1 else 0
    tiempos = [0]
    for tam in repartir(n, c):
        for _ in range(tam - 1):
            tiempos.append(tiempos[-1] + intra_s)
        if len(tiempos) < n:
            tiempos.append(tiempos[-1] + int(round(inter)))
    assert len(tiempos) == n, (len(tiempos), n)
    return tiempos


def delays_desde_tiempos(tiempos, dur_s):
    """Convierte desplazamientos en `DelayAfter` (ms), con guardián de fin de bloque."""
    out = []
    for i, t in enumerate(tiempos):
        if i + 1 < len(tiempos):
            out.append((tiempos[i + 1] - t) * 1000)
        else:
            out.append((dur_s - t + GUARDIAN_S) * 1000)
    return out


# --------------------------------------------------------------------------
# Plantillas de comandos (sin comillas dobles, sin sudo, rutas /home/angel)
# --------------------------------------------------------------------------
def curl_get(url, out, referer=None, escribe_cookies=False):
    partes = ["curl -sS", f"-A '{UA}'"]
    partes.append(f"-c {COOKIES}" if escribe_cookies else f"-b {COOKIES}")
    if referer:
        partes.append(f"-e {referer}")
    partes.append("-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'")
    partes.append("-H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5'")
    partes.append("--compressed")
    partes.append(f"-o {out}")
    partes.append("-w '%{http_code}'")
    partes.append(url)
    return " ".join(partes)


def curl_post(url, datos, out):
    return (f"curl -sS -A '{UA}' -b {COOKIES} -H 'Accept: text/plain;q=0.9,*/*;q=0.8' "
            f"-X POST --data '{datos}' -o {out} -w '%{{http_code}}' {url}")


def curl_put(local, url):
    return f"curl -sS -A '{UA}' -b {COOKIES} -T {local} -o /dev/null -w '%{{http_code}}' {url}"


def curl_propfind(url, out):
    return (f"curl -sS -A '{UA}' -b {COOKIES} -X PROPFIND -H 'Depth: 1' "
            f"-o {out} -w '%{{http_code}}' {url}")


# --------------------------------------------------------------------------
# Bloques: acciones de cada día
# --------------------------------------------------------------------------
def b1(day: int):
    tema = {1: "estado del informe mensual",
            2: "confirmacion de la reunion de area",
            3: "revision de las copias de seguridad"}[day]
    return [
        ("llegada", f"date -u +%FT%TZ > {DOC}/llegada_$(date -u +%F).txt"),
        ("listar", f"ls -la {DOC}"),
        ("estructura", f"mkdir -p {DOC}/informes {DOC}/actas {DOC}/copias {DOC}/correo {DOWN} {CACHE}"),
        ("agenda", f"echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > {DOC}/agenda_$(date -u +%F).txt"),
        ("agenda", f"cat {DOC}/agenda_$(date -u +%F).txt"),
        # --- sesión web browser-like: abrir portal (cookie jar) ---
        ("web-sesion", curl_get(WEB + "/", f"{CACHE}/index.html", escribe_cookies=True)),
        # --- requisitos de la página: CSS + JS + SVG (3 peticiones) ---
        ("web-requisitos", " && ".join([
            curl_get(WEB + "/styles.css", f"{CACHE}/styles.css", referer=WEB + "/"),
            curl_get(WEB + "/portal.js", f"{CACHE}/portal.js", referer=WEB + "/"),
            curl_get(WEB + "/assets/logo.svg", f"{CACHE}/logo.svg", referer=WEB + "/"),
        ])),
        # --- tamaño + huella de lo descargado ---
        ("web-huella", f"wc -c {CACHE}/index.html && sha256sum {CACHE}/styles.css"),
        ("correo", f"echo 're: {tema}' > {DOC}/correo/borrador_1.txt"),
    ]


def b2_correo(day: int):
    out = []
    for r in range(1, 5):
        out.append(("correo-buzon",
                    curl_post(PASTE + "/paste", f"consulta_buzon_d{day}_r{r}", f"{CACHE}/buzon_{r}.txt")))
        out.append(("correo-escribir",
                    f"echo 'ronda {r}: pendiente de revisar el informe del area' >> {DOC}/correo/borrador_{r}.txt"))
        out.append(("correo-leer", f"cat {DOC}/correo/borrador_{r}.txt"))
    return out


def b2_adjuntos(day: int):
    out = [("informe", f"echo 'informe del area - jornada {day}' > {DOC}/informes/informe.txt")]
    for i in (1, 2):
        out.append(("adjunto",
                    f"tar -czf {DOC}/informes/adjunto_{i}_$(date -u +%F).tar.gz -C {DOC}/informes informe.txt"))
        out.append(("huella", f"sha256sum {DOC}/informes/adjunto_{i}_$(date -u +%F).tar.gz"))
        out.append(("tamano", f"du -sh {DOC}/informes/adjunto_{i}_$(date -u +%F).tar.gz"))
        out.append(("listar", f"ls -la {DOC}/informes"))
    return out


def b2_ordenar(day: int):
    return [
        ("copia", f"cp -f {DOC}/informes/informe.txt {DOC}/informes/informe.bak"),
        ("renombrar", f"mv -f {DOC}/correo/borrador_1.txt {DOC}/correo/enviado_1.txt"),
        ("contar", f"find {DOC} -type f > {CACHE}/lista_ficheros.txt"),
        ("listar", f"ls -la {DOC}/correo"),
        ("contar", f"wc -l {DOC}/informes/informe.txt"),
        ("leer", f"cat {DOC}/correo/enviado_1.txt"),
        ("tamano", f"du -sh {DOC}/correo"),
        ("copia", f"cp -f {DOC}/informes/informe.txt {DOWN}/informe_copia_{day}.txt"),
        ("limpiar", f"rm -f {DOWN}/tmp_borradores.csv"),
        ("agenda", f"echo 'revisado el buzon de la manana' >> {DOC}/agenda_$(date -u +%F).txt"),
        ("huella", f"md5sum {DOC}/informes/informe.bak"),
        ("listar", f"ls -la {DOC}"),
    ]


POOL_B2 = {"correo": b2_correo, "adjuntos": b2_adjuntos, "ordenar": b2_ordenar}
ORDEN_B2 = {1: ["correo", "adjuntos", "ordenar"],
            2: ["correo", "ordenar", "adjuntos"],
            3: ["ordenar", "correo", "adjuntos"]}


def b3_web(day: int):
    return [
        ("web-navegar", curl_get(WEB + "/noticias.html", f"{DOWN}/noticias.html",
                                 referer=f"{CACHE}/index.html")),
        ("web-navegar", curl_get(WEB + "/ayuda.html", "/dev/null",
                                 referer=f"{DOWN}/noticias.html")),
        ("web-descarga", curl_get(WEB + "/descargas/plantilla_informe.csv",
                                  f"{CACHE}/plantilla_informe.csv", referer=WEB + "/ayuda.html")),
        ("web-pdf", curl_get(WEB + "/descargas/manual_empleado.pdf",
                             f"{DOWN}/manual_empleado.pdf", referer=f"{DOWN}/noticias.html")),
        ("web-huella", f"wc -c {DOWN}/manual_empleado.pdf && sha256sum {DOWN}/manual_empleado.pdf"),
    ]


def b3_redactar(day: int):
    temas = [
        "alcance del informe", "actividades del area", "incidencias de la semana",
        "indicadores del mes", "riesgos identificados", "plan de accion",
        "conclusiones", "anexo de datos",
    ]
    out = []
    for i, tema in enumerate(temas, start=1):
        out.append(("redactar", f"echo '{i}. {tema} (dia {day})' >> {DOC}/informes/informe.txt"))
        out.append(("leer", f"cat {DOC}/informes/informe.txt"))
        out.append(("contar", f"wc -l {DOC}/informes/informe.txt"))
    return out


def b3_comprimir(day: int):
    return [
        ("comprimir", f"gzip -kf {DOC}/informes/informe.txt"),
        ("huella", f"md5sum {DOC}/informes/informe.txt.gz"),
        ("huella", f"sha256sum {DOC}/informes/informe.txt.gz"),
        ("listar", f"ls -la {DOC}/informes"),
        ("tamano", f"du -sh {DOC}/informes"),
        ("contar", f"wc -l {DOC}/informes/informe.txt.gz"),
    ]


def b3_consolidar(day: int):
    return [
        ("consolidar", f"tar -czf {DOWN}/informes.tar.gz -C {DOC} informes"),
        ("copia", f"cp -f {DOWN}/informes.tar.gz {DOWN}/informes_copia_{day}.tar.gz"),
        ("huella", f"sha256sum {DOWN}/informes.tar.gz"),
        ("contar", f"find {DOC} -type f > {CACHE}/lista_ficheros_d{day}.txt"),
        ("tamano", f"du -sh {DOWN}"),
        ("listar", f"ls -la {DOWN}"),
    ]


def b3_repaso(day: int):
    return [
        ("revisar", f"grep -c 'informe' {DOC}/informes/informe.txt"),
        ("revisar", f"head -n 5 {DOC}/informes/informe.txt"),
        ("revisar", f"tail -n 5 {DOC}/informes/informe.txt"),
        ("revisar", f"wc -l {DOC}/informes/informe.txt"),
        ("listar", f"ls -la {DOC}/informes"),
        ("disco", "df -h /"),
        ("estado", f"stat {DOC}/informes/informe.txt"),
        ("leer", f"cat {DOC}/informes/informe.bak"),
    ]


POOL_B3 = {"web": b3_web, "redactar": b3_redactar, "comprimir": b3_comprimir,
           "consolidar": b3_consolidar, "repaso": b3_repaso}
ORDEN_B3 = {1: ["redactar", "comprimir", "consolidar", "repaso"],
            2: ["comprimir", "redactar", "consolidar", "repaso"],
            3: ["repaso", "redactar", "consolidar", "comprimir"]}
# La sesión web va SIEMPRE primero en B3 (posiciones 36..40), como en §5.7.


def b4_acta(day: int, n: int = 1):
    out = []
    for k in range(1, n + 1):
        out += [
            ("acta", f"echo 'acta de reunion {k} del area (dia {day})' > {DOC}/actas/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"cat {DOC}/actas/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"wc -c {DOC}/actas/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"cp -f {DOC}/actas/acta_{k}_$(date -u +%F).txt {DOC}/actas/compartida_{k}.txt"),
            ("acta", f"sha256sum {DOC}/actas/compartida_{k}.txt"),
            ("acta", f"ls -la {DOC}/actas"),
        ]
    return out


def b4_nube(day: int):
    return [
        ("nube", curl_put(f"{DOC}/actas/acta_1_$(date -u +%F).txt", CLOUD + "/nube/actas/")),
        ("nube", curl_propfind(CLOUD + "/nube/", f"{CACHE}/nube_listado.txt")),
        ("nube", curl_put(f"{DOC}/informes/informe.txt", CLOUD + "/nube/informes/")),
        ("nube", curl_propfind(CLOUD + "/nube/actas/", f"{CACHE}/nube_actas.txt")),
        ("portal", curl_get(WEB + "/", f"{CACHE}/portal_tarde.html", referer=WEB + "/ayuda.html")),
        ("portal", curl_get(WEB + "/noticias.html", f"{CACHE}/noticias_tarde.html",
                            referer=f"{CACHE}/portal_tarde.html")),
    ]


def b4_descargas(day: int):
    return [
        ("descarga", curl_get(WEB + "/descargas/plantilla_informe.csv", f"{DOWN}/plantilla_dia{day}.csv",
                              referer=f"{CACHE}/portal_tarde.html")),
        ("descarga", f"wc -c {DOWN}/plantilla_dia{day}.csv"),
        ("descarga", f"sha256sum {DOWN}/plantilla_dia{day}.csv"),
        ("portal", curl_get(WEB + "/ayuda.html", f"{CACHE}/ayuda_tarde.html", referer=WEB + "/")),
        ("portal", curl_get(WEB + "/styles.css", f"{CACHE}/styles_tarde.css", referer=WEB + "/ayuda.html")),
        ("portal", f"wc -l {CACHE}/ayuda_tarde.html"),
    ]


def b4_informe(day: int):
    return [
        ("informe", f"tar -czf {DOWN}/informe_dia{day}.tar.gz -C {DOC}/informes informe.txt"),
        ("huella", f"sha256sum {DOWN}/informe_dia{day}.tar.gz"),
        ("tamano", f"du -sh {DOWN}/informe_dia{day}.tar.gz"),
        ("listar", f"ls -la {DOWN}"),
    ]


POOL_B4 = {"acta1": lambda d: b4_acta(d, 1), "nube": b4_nube,
           "acta2": lambda d: b4_acta(d, 2), "descargas": b4_descargas,
           "informe": b4_informe}
ORDEN_B4 = {1: ["acta1", "nube", "informe", "descargas"],
            2: ["acta1", "acta2", "nube", "informe", "descargas"],
            3: ["acta1", "nube", "informe", "descargas"]}


def b5(day: int):
    return [
        ("copia", f"tar -czf {DOC}/copias/copia_$(date -u +%F).tar.gz -C {DOC} informes actas"),
        ("huella", f"sha256sum {DOC}/copias/copia_$(date -u +%F).tar.gz"),
        ("huella", f"cat {DOC}/copias/copia_$(date -u +%F).tar.gz.sha256"),
        ("nube", curl_put(f"{DOC}/copias/copia_$(date -u +%F).tar.gz", CLOUD + "/nube/copias/")),
        ("nube", curl_propfind(CLOUD + "/nube/copias/", f"{CACHE}/copias_nube.txt")),
        ("tamano", f"du -sh {DOC}"),
        ("disco", "df -h /"),
        ("copia", f"cp -f {DOC}/copias/copia_$(date -u +%F).tar.gz {DOWN}/copia_final_{day}.tar.gz"),
        ("tamano", f"wc -c {DOWN}/copia_final_{day}.tar.gz"),
        ("limpiar", f"rm -f {DOWN}/tmp_*.csv"),
        ("cierre", "date -u +%FT%TZ"),
        ("cierre", f"ls -la {DOC} {DOWN}"),
    ]


# --------------------------------------------------------------------------
# Composición de un día
# --------------------------------------------------------------------------
def componer_dia(day: int):
    """Devuelve [(bloque, familia, comando)] con el recuento exacto del plan."""
    acciones = []
    for bid in ("B1", "B2", "B3", "B4", "B5"):
        n = CUENTAS[day][bid]
        if bid == "B1":
            lista = b1(day)
        elif bid == "B2":
            pool = []
            for cat in ORDEN_B2[day]:
                pool += POOL_B2[cat](day)
            lista = pool
        elif bid == "B3":
            pool = list(POOL_B3["web"](day))          # sesión web primero (§5.7)
            for cat in ORDEN_B3[day]:
                pool += POOL_B3[cat](day)
            lista = pool
        elif bid == "B4":
            pool = []
            for cat in ORDEN_B4[day]:
                pool += POOL_B4[cat](day)
            lista = pool
        else:
            lista = b5(day)
        if len(lista) < n:
            raise SystemExit(f"ERROR: pool {bid} dia {day} tiene {len(lista)} acciones, faltan {n}")
        lista = lista[:n]
        acciones += [(bid, fam, cmd) for fam, cmd in lista]
    return acciones


def construir_timeline(day: int, dry: bool = False, base_s: int = 10 * 3600,
                        factor: int = 40, pausa_dry_s: int = 30):
    acciones = componer_dia(day)
    handlers = []
    for b in BLOQUES:
        if b["tipo"] != "trabajo":
            continue
        n = CUENTAS[day][b["id"]]
        dur = dur_bloque(b["id"])
        cfg = PLAN_TIMES[b["id"]]
        if dry:
            # La ventana del bloque (dur_d) es MAYOR que el hueco que ocupan las acciones
            # (dur_span): asi el desfase de ejecucion (~0,1 s/accion) no empuja eventos fuera
            # de la ventana (WorkingHours.Is los mandaria al dia siguiente y se perderian).
            dur_span = max(8, dur // 90)
            dur_d = max(dur_span + 6, dur // 55)
            tiempos = plan_tiempos(n, dur_span, cfg["min_rafagas"], max(1, cfg["intra"] // 2),
                                   cap_s=max(3, CAP_HUECO_S // 90),
                                   cola_s=max(2, COLA_FIN_S // 60))
            base_s += dur_d + pausa_dry_s
            on_s = base_s - dur_d - pausa_dry_s
            on, off = on_s, on_s + dur_d
            delays = []
            for i, t in enumerate(tiempos):
                if i + 1 < len(tiempos):
                    delays.append(max(500, (tiempos[i + 1] - t) * 1000))
                else:
                    delays.append(max(500, (dur_d - t) * 1000 + 500))
        else:
            on, off = hms_to_s(b["on"]), hms_to_s(b["off"])
            tiempos = plan_tiempos(n, dur, cfg["min_rafagas"], cfg["intra"])
            delays = delays_desde_tiempos(tiempos, dur)
        eventos = [{"Command": cmd, "DelayAfter": int(dl)}
                   for (bb, _fam, cmd), dl in zip([a for a in acciones if a[0] == b["id"]], delays)]
        assert len(eventos) == n
        handlers.append({
            "HandlerType": "Command",
            "Initial": "",
            "UtcTimeOn": _fmt_hms(on),
            "UtcTimeOff": _fmt_hms(off),
            "Loop": True,
            "HandlerArgs": {},
            "TimeLineEvents": eventos,
        })
    return {"Status": "Run", "TimeLineHandlers": handlers}, acciones


def _fmt_hms(s: int) -> str:
    s %= 24 * 3600
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def escribir_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def escribir_calendario(outdir):
    cal = {
        "receta_version": VERSION_RECETA,
        "zona": "Europe/Madrid (CET=UTC+1 desde 2026-10-25)",
        "dia_local": "09:00-18:00",
        "jornada_utc": {"on": JORNADA[0], "off": JORNADA[1]},
        "bloques": BLOQUES,
        "cuentas": {str(k): v for k, v in CUENTAS.items()},
        "total_ventana": sum(sum(v.values()) for v in CUENTAS.values()),
        "mapa_dias": MAPA_DIAS,
        "regla_dia": "k = 1 + ((fecha_utc - fecha_t0) mod 3)",
        "hueco_max_intra_bloque_s": CAP_HUECO_S,
        "fuente": "_artefactos/scripts/construir_receta_legitima.py",
    }
    escribir_json(os.path.join(outdir, "calendario.json"), cal)

    lineas = [
        "# bloques y pausas de la receta legitima (UTC). Generado; NO editar a mano.",
        f"# jornada {JORNADA[0]} - {JORNADA[1]} UTC (09:00-18:00 local)",
        "TFG_RECETA_VERSION=1",
        f"TFG_JORNADA={JORNADA[0]}-{JORNADA[1]}",
    ]
    for b in BLOQUES:
        lineas.append(f"{b['id']}={b['on'][:5]}-{b['off'][:5]} {b['tipo']}")
    lineas += [
        "# mapeo de dias de la ventana (fecha_utc del dia -> fichero de receta)",
        "TFG_MAPA_DIAS=2026-10-26:1,2026-10-27:2,2026-10-28:3",
    ]
    with open(os.path.join(outdir, "bloques.env"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


def escribir_resumen(outdir, timelines):
    lineas = [
        "# `receta_resumen.md` — receta de actividad legítima (3 días)",
        "",
        "> Generado por `_artefactos/scripts/construir_receta_legitima.py` (receta v1).",
        "> Jornada **09:00–18:00 local** (08:00–17:00 UTC), con **café** (20 min) y **comida** (60 min).",
        "> Solo handler `Command`; **cero** `random`, **cero** `Curl`, **cero** navegador.",
        "",
        "| Bloque | UTC | Local | Tipo | D1 | D2 | D3 |",
        "|---|---|---|---|---|---|---|",
    ]
    for b in BLOQUES:
        c = CUENTAS
        vals = [str(c[d][b["id"]]) if b["tipo"] == "trabajo" else "0" for d in (1, 2, 3)]
        lineas.append(f"| {b['id']} {b['nombre']} | {b['on'][:5]}–{b['off'][:5]} | {b['local']} | "
                      f"{b['tipo']} | {vals[0]} | {vals[1]} | {vals[2]} |")
    tot = {d: sum(CUENTAS[d].values()) for d in (1, 2, 3)}
    lineas.append(f"| **Total** | 08:00–17:00 | 09:00–18:00 | — | **{tot[1]}** | **{tot[2]}** | **{tot[3]}** |")
    lineas += ["", f"**Total ventana (3 días): {sum(tot.values())} acciones.**", ""]
    for day in (1, 2, 3):
        lineas.append(f"## Día {day} — «{TEMAS[day]}» ({tot[day]} acciones)")
        lineas.append("")
        lineas.append("| # | UTC | Bloque | Familia | Comando |")
        lineas.append("|---|---|---|---|---|")
        tl, acciones = construir_timeline(day)
        idx = 0
        for h, b in zip(tl["TimeLineHandlers"], [x for x in BLOQUES if x["tipo"] == "trabajo"]):
            t = hms_to_s(b["on"])
            for ev in h["TimeLineEvents"]:
                _, fam, cmd = acciones[idx]
                idx += 1
                lineas.append(f"| {idx} | {_fmt_hms(t)[:5]} | {b['id']} | {fam} | `{cmd}` |")
                t += ev["DelayAfter"] // 1000
        lineas.append("")
    with open(os.path.join(outdir, "receta_resumen.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


# --------------------------------------------------------------------------
# Validador
# --------------------------------------------------------------------------
def binarios_de(cmd: str):
    """Primer token de cada segmento encadenado con `&&`."""
    out = []
    for seg in cmd.split(" && "):
        tok = seg.strip().split()[0] if seg.strip() else ""
        out.append(tok)
    return out


def validar(outdir, verbose=True):
    fallos = []
    avisos = []
    datos = {}
    for day in (1, 2, 3):
        path = os.path.join(outdir, f"d{day}.json")
        if not os.path.isfile(path):
            fallos.append(f"falta {path}")
            continue
        tl = json.load(open(path, encoding="utf-8"))
        datos[day] = tl
        if tl.get("Status") != "Run":
            fallos.append(f"d{day}: Status != Run")
        hs = tl.get("TimeLineHandlers", [])
        trabajo = [b for b in BLOQUES if b["tipo"] == "trabajo"]
        if len(hs) != len(trabajo):
            fallos.append(f"d{day}: {len(hs)} handlers (se esperan {len(trabajo)})")
            continue
        total = 0
        for h, b in zip(hs, trabajo):
            if h.get("HandlerType") != "Command":
                fallos.append(f"d{day}/{b['id']}: HandlerType={h.get('HandlerType')}")
            if h.get("HandlerType") in HANDLERS_PROHIBIDOS:
                fallos.append(f"d{day}/{b['id']}: handler prohibido {h.get('HandlerType')}")
            if not h.get("Loop"):
                fallos.append(f"d{day}/{b['id']}: Loop != true")
            if h.get("HandlerArgs"):
                fallos.append(f"d{day}/{b['id']}: HandlerArgs no vacío")
            if h.get("UtcTimeOn") != b["on"] or h.get("UtcTimeOff") != b["off"]:
                fallos.append(f"d{day}/{b['id']}: ventana {h.get('UtcTimeOn')}-{h.get('UtcTimeOff')} != {b['on']}-{b['off']}")
            evs = h.get("TimeLineEvents", [])
            total += len(evs)
            if len(evs) != CUENTAS[day][b["id"]]:
                fallos.append(f"d{day}/{b['id']}: {len(evs)} eventos != {CUENTAS[day][b['id']]}")
            # huecos
            dur = dur_bloque(b["id"])
            t = 0
            for i, ev in enumerate(evs):
                if i == 0:
                    t = 0
                else:
                    t += evs[i - 1]["DelayAfter"] / 1000.0
            gap_max = max([evs[i]["DelayAfter"] / 1000.0 for i in range(len(evs) - 1)] or [0])
            if gap_max > 20 * 60:
                fallos.append(f"d{day}/{b['id']}: hueco {gap_max/60:.1f} min > 20 min")
            elif gap_max > CAP_HUECO_S:
                fallos.append(f"d{day}/{b['id']}: hueco {gap_max/60:.1f} min > 12 min (regla interna)")
            suma = sum(ev["DelayAfter"] for ev in evs) / 1000.0
            if suma < dur:
                fallos.append(f"d{day}/{b['id']}: suma(delays)={suma:.0f}s < duración {dur}s")
            for ev in evs:
                cmd = ev["Command"]
                if '"' in cmd:
                    fallos.append(f"d{day}/{b['id']}: comillas dobles en: {cmd[:60]}")
                if cmd.strip() == "random" or "random" == cmd.strip():
                    fallos.append(f"d{day}/{b['id']}: comando random prohibido")
                if "|" in cmd:
                    fallos.append(f"d{day}/{b['id']}: comando con PIPE (GHOSTS pierde el reporte): {cmd[:60]}")
                for tok in binarios_de(cmd):
                    if tok not in BINARIOS_OK:
                        fallos.append(f"d{day}/{b['id']}: binario no permitido '{tok}' en {cmd[:60]}")
                if "sudo" in cmd.split():
                    fallos.append(f"d{day}/{b['id']}: sudo prohibido")
                for ruta in re.findall(r"(?<![\w.])/[A-Za-z0-9_./$()-]+", re.sub(r"https?://\S+", "", cmd)):
                    if ruta.startswith("/dev/null"):
                        continue
                    if not ruta.startswith("/home/angel"):
                        fallos.append(f"d{day}/{b['id']}: ruta fuera de /home/angel: {ruta}")
                for ph in PLACEHOLDERS:
                    if ph in cmd:
                        fallos.append(f"d{day}/{b['id']}: placeholder {ph} en {cmd[:60]}")
                if "-A 'Mozilla" in cmd or "-A 'curl" in cmd:
                    fallos.append(f"d{day}/{b['id']}: UA que suplanta un navegador")
        if total != sum(CUENTAS[day].values()):
            fallos.append(f"d{day}: total {total} != {sum(CUENTAS[day].values())}")

    # sesión web (8 posiciones, siempre las mismas)
    for day, tl in datos.items():
        if len(tl.get("TimeLineHandlers", [])) != 5:
            continue
        cmds_b1 = [ev["Command"] for ev in tl["TimeLineHandlers"][0]["TimeLineEvents"]]
        cmds_b3 = [ev["Command"] for ev in tl["TimeLineHandlers"][2]["TimeLineEvents"]]
        # globales 6..8 = B1[5:8]; globales 36..40 = B3[0:5] (B1=9 + B2=26 = 35 previas)
        web = cmds_b1[WEB_POS_B1[0] - 1:WEB_POS_B1[-1]] + cmds_b3[:WEB_POS_B3[-1] - WEB_POS_B3[0] + 1]
        if len(web) != 8:
            fallos.append(f"d{day}: sesión web con {len(web)} acciones (se esperan 8)")
        for i, c in enumerate(web):
            if "curl " in c:
                if UA not in c:
                    fallos.append(f"d{day}: acción web sin UA fija: {c[:60]}")
                if COOKIES not in c:
                    fallos.append(f"d{day}: acción web sin cookie jar: {c[:60]}")
            if i > 0 and "cookies.txt" in c and "-e " not in c:
                fallos.append(f"d{day}: acción web sin Referer: {c[:60]}")
        if web[1].count("curl ") != 3:
            fallos.append(f"d{day}: los requisitos no son 3 peticiones")
        if "manual_empleado.pdf" not in web[6]:
            fallos.append(f"d{day}: falta la descarga del PDF")
        if "sha256sum" not in web[7]:
            fallos.append(f"d{day}: falta la huella de la descarga")

    # calendario / bloques.env
    cal_path = os.path.join(outdir, "calendario.json")
    env_path = os.path.join(outdir, "bloques.env")
    if not os.path.isfile(cal_path):
        fallos.append("falta calendario.json")
    else:
        cal = json.load(open(cal_path, encoding="utf-8"))
        if cal.get("mapa_dias") != MAPA_DIAS:
            fallos.append("calendario.json: mapa de días incorrecto")
        if cal.get("total_ventana") != sum(sum(v.values()) for v in CUENTAS.values()):
            fallos.append("calendario.json: total de la ventana incorrecto")
    if not os.path.isfile(env_path):
        fallos.append("falta bloques.env")

    resumen = {
        "dias": {d: sum(CUENTAS[d].values()) for d in (1, 2, 3)},
        "total": sum(sum(v.values()) for v in CUENTAS.values()),
        "web_session": 1,
        "handlers_browser": 0,
        "fallos": fallos,
        "avisos": avisos,
    }
    if verbose:
        print(f"receta v{VERSION_RECETA}: dias={resumen['dias']} total={resumen['total']} "
              f"web_session=1 handlers_browser=0")
        for a in avisos:
            print(f"AVISO: {a}")
        for f in fallos:
            print(f"FALLO: {f}")
        print("RESULT=" + ("PASS" if not fallos else "FAIL"))
    return resumen


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Genera/valida la receta legítima (3 días).")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--dry", action="store_true", help="timeline comprimida ×40 para la prueba en seco")
    ap.add_argument("--base", default="10:00Z", help="hora UTC de inicio del día comprimido (HH:MMZ)")
    ap.add_argument("--out", default=None, help="fichero de salida del modo dry")
    ap.add_argument("--day", type=int, default=1, choices=(1, 2, 3))
    args = ap.parse_args(argv)

    raiz = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    outdir = args.out_dir or os.path.join(raiz, "Soporte", "Laboratorio", "legitimo_72h", "recetas")

    if args.check:
        res = validar(outdir)
        return 0 if not res["fallos"] else 1

    if args.dry:
        m = re.match(r"^(\d{1,2}):(\d{2})Z?$", args.base.strip())
        if not m:
            ap.error("--base debe ser HH:MMZ")
        base_s = int(m.group(1)) * 3600 + int(m.group(2)) * 60
        tl, acciones = construir_timeline(args.day, dry=True, base_s=base_s)
        out = args.out or os.path.join(outdir, f"d{args.day}.dry.json")
        escribir_json(out, tl)
        print(f"dry: {out} ({len(acciones)} acciones, dia {args.day}, base {args.base})")
        return 0

    timelines = {}
    for day in (1, 2, 3):
        tl, acciones = construir_timeline(day)
        timelines[day] = (tl, acciones)
        escribir_json(os.path.join(outdir, f"d{day}.json"), tl)
    escribir_calendario(outdir)
    escribir_resumen(outdir, timelines)
    for day in (1, 2, 3):
        p = os.path.join(outdir, f"d{day}.json")
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        print(f"d{day}.json  {sum(CUENTAS[day].values())} acciones  sha256={h}")
    res = validar(outdir)
    return 0 if not res["fallos"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
