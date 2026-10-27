#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""construir_receta_legitima.py — receta de actividad legítima del TFG (bloque `legitimo-v3`, receta v2).

Genera **tres timelines GHOSTS** (un día de oficina cada una, `d1/d2/d3`), su **calendario**
(`calendario.json` + `bloques.env`, la misma fuente para la vigilancia y el keepalive) y un
**resumen** legible (`receta_resumen.md`). Incluye un **validador** (`--check`) con todos los
invariantes del plan (§5.1, §5.2.1, CA-01…CA-03) y un modo **dry** (`--dry --base HH:MMZ`) que
comprime la jornada para la prueba en seco DT9.

Novedades de la **v2** (plan §5.1, T1) sobre la v1:

1. **`cwd` realista (M1, §5.1 y §1.4)** — cada acción se ejecuta como
   `cd <carpeta coherente> && <comando>`. La carpeta es la del primer fichero que el comando
   toca (regla `cwd_de`), con dos excepciones declaradas (`mkdir -p` y los `xargs`). Resultado:
   **ninguna** acción se ejecuta en `~/ghosts-client` (el plan B de §1.9.2, aplicado en la
   receta). `cd` es un *builtin*: no añade `execve`; sí cambia el `audit_cwd` del hijo. Sin
   pipes (DT9: GHOSTS pierde el reporte).
2. **Ritmo irregular determinista (M2, §5.1 y §1.4)** — **tabla de jitter literal** (`INTRA`,
   `RAFAGAS`, `HUECOS`, `PAUSA_LARGA`): ráfagas de **1–6** acciones, huecos intra de
   **41–62 s**, huecos entre ráfagas de **80 s–22 min** y **dos pausas largas** (20–22 min),
   una en `B3` y otra en `B4`. **Cero `random`**: dos generaciones son byte-idénticas.
   Regla dura: **ningún hueco > `CAP_HUECO_S` = 1320 s**.
3. **Errores humanos con reintento (M3, §5.1 y §1.4)** — **10/día**, de 6 familias (ruta mal
   escrita, `cp` a carpeta inexistente, `gzip` repetido, `rm` inexistente, `cat` de una
   carpeta, opción inválida). Cada error va **seguido del reintento correcto** y deja
   **dos líneas** en `~/Documentos/errores.log` (`ts · tipo · familia · comando · rc`): el
   `rc` se captura con `$?`, **no** se escribe a mano.
4. **Herramientas del corpus (M4, §5.2)** — 12 binarios nuevos **elegidos por el corpus**
   (`xargs`, `timeout`, `sed`, `ip`, `openssl`, `tee`, `free`, `logger`, `seq`, `rsync`,
   `shred`, `wget`), cada uno con una acción con sentido de oficina. Lista blanca: **34**.
5. **Sin fechas (v5, §17.9)** — `MAPA_DIAS` deja de estar hardcodeado: se pasa con `--t0`
   (o `--mapa-dias`), y `--check` lo acepta como entrada. Sin fecha, el mapa queda **vacío**
   y se fija al cerrar T4.

**No** incluye el bloque de campaña `B6` (es T2).

Uso:
    python _artefactos/scripts/construir_receta_legitima.py                     # genera (sin fecha)
    python _artefactos/scripts/construir_receta_legitima.py --t0 2026-11-02      # genera con la ventana
    python _artefactos/scripts/construir_receta_legitima.py --check             # valida lo versionado
    python _artefactos/scripts/construir_receta_legitima.py --check --t0 2026-11-02
    python _artefactos/scripts/construir_receta_legitima.py --dry --base 10:00Z --out /tmp/dry.json

Salida por defecto: `Soporte/Laboratorio/legitimo_72h/recetas/`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import campana

# --------------------------------------------------------------------------
# Constantes de la receta (una sola fuente de verdad)
# --------------------------------------------------------------------------
VERSION_RECETA = 2

HOME = "/home/angel"
DOC = HOME + "/Documentos"
DOWN = HOME + "/Descargas"
CACHE = HOME + "/.cache/tfg-web"
COOKIES = CACHE + "/cookies.txt"
INFORMES = DOC + "/informes"
ACTAS = DOC + "/actas"
CORREO = DOC + "/correo"
COPIAS = DOC + "/copias"
REGISTRO = DOC + "/errores.log"          # registro de errores humanos (M3)
WEB = "http://intranet.local:8080"
PASTE = "http://intranet.local:9090"
CLOUD = "http://nube.local:9092"
UA = "TFG-Legit/1.0 (Linux; x86_64; sesion-web)"

# Carpetas de trabajo admitidas en el prefijo `cd <carpeta> && ` (M1).
DIRS_CWD = (HOME, DOC, DOWN, CACHE, INFORMES, ACTAS, CORREO, COPIAS)

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
    # B6 = campaña de falsos positivos (T2). NO es jornada de trabajo: es un bloque
    # **declarado** de 45 min al final del día (plan §3.1 y §3.1.1).
    dict(campana.B6),
]
BLOQUES_TRABAJO = [b for b in BLOQUES if b["tipo"] == "trabajo"]
IDS_TRABAJO = [b["id"] for b in BLOQUES_TRABAJO]
JORNADA = ("08:00:00", "17:00:00")

# Recuento BASE por día (v1, sin las adiciones de la v2). Las adiciones se suman aparte y el
# total se **calcula** (no se escribe a mano) para que no haya dos verdades.
BASE_CUENTAS = {
    1: {"B1": 9, "B2": 26, "B3": 42, "B4": 22, "B5": 12},
    2: {"B1": 9, "B2": 32, "B3": 34, "B4": 30, "B5": 12},
    3: {"B1": 9, "B2": 22, "B3": 46, "B4": 16, "B5": 12},
}
TEMAS = {1: "cierre de informes", 2: "reuniones y portal", 3: "revisión y copias"}

# --------------------------------------------------------------------------
# Tabla de jitter FIJA (M2). Todo son constantes literales: no hay `random`.
# --------------------------------------------------------------------------
# Hueco dentro de ráfaga (s). 41–62 s ⇒ mínimo del plan ≥ 40 s.
INTRA = (41, 57, 43, 62, 48, 55, 44, 59)
# Acciones por ráfaga (1–6), patrón literal que se recorre en ciclo.
RAFAGAS = {
    "B1": (3, 2, 4, 2),
    "B2": (3, 1, 4, 2, 3, 1, 5, 2, 4, 1, 3, 2, 5, 1, 2, 4, 1, 3, 2, 6, 1, 4, 2, 3),
    "B3": (2, 4, 1, 3, 5, 2, 1, 4, 3, 2, 6, 1, 3, 2, 4, 1, 5, 2, 3, 1, 4, 2, 6, 1, 3, 2, 4),
    "B4": (3, 1, 2, 4, 1, 3, 2, 5, 1, 2, 4, 3, 1, 6, 2, 1, 4, 2, 3, 1, 5, 2),
    "B5": (2, 3, 1, 4, 2, 3, 1, 4),
}
# Hueco entre ráfagas (s): **forma** literal. Se ajusta de forma proporcional a la duración
# del bloque (misma forma en los 3 días, escala distinta porque el nº de acciones cambia).
HUECOS = {
    "B1": (100, 115, 105, 120, 95, 130, 110),
    "B2": (110, 150, 450, 190, 250, 100, 380, 140, 115, 310, 160, 95, 250, 120, 340, 135, 105),
    "B3": (120, 220, 380, 95, 450, 180, 260, 140, 90, 320, 150, 110, 430, 130, 210, 95,
           170, 260, 120, 140, 90, 200, 130, 160, 110, 250, 95),
    "B4": (520, 110, 780, 610, 340, 900, 480, 700, 260, 560, 400, 880, 640, 300, 750, 210,
           580, 460),
    "B5": (450, 700, 500, 640, 480, 620, 530),
}
# Pausa larga declarada (s): una por día en B3 y otra en B4 (20–22 min). Es literal.
PAUSA_LARGA = {"B3": 1250, "B4": 1210, "B1": 0, "B2": 0, "B5": 0}   # 20:50 y 20:10
PAUSA_POS = {"B3": 0.50, "B4": 0.34}                                 # dónde cae (fracción)
CAP_HUECO_S = 1320          # 22 min (una sola regla; sustituye a los 720/1200 de la v1)
MIN_HUECO_S = 40            # 40 s
MIN_HUECO_INTER_S = 80      # separación mínima ráfaga↔ráfaga (deja inequívoco el corte)
COLA_FIN_S = 60             # la última acción cae 1 min antes de UtcTimeOff
GUARDIAN_S = 60             # el último DelayAfter acaba 1 min DESPUÉS de UtcTimeOff

# --------------------------------------------------------------------------
# Lista blanca (M4). 34 binarios. Justificación (plan §5.2 / corpus: 50 basenames):
#   · 22 de la v1: ofimática básica (mkdir, echo, cat, cp, mv, tar, gzip, md5sum, sha256sum,
#     ls, find, du, df, wc, date, curl, grep, head, tail, stat, rm, true).
#   · 12 nuevos ELEGIDOS POR EL CORPUS (aparecen en `audit_command` de alguna detección):
#     xargs (2497 filas), curl (852, ya estaba), timeout (96), ip (73), openssl (16),
#     sed (14), rsync (10), seq (4), tee (4), wget (4), free (5), logger (2), shred (2).
#   · NO entran (a propósito): systemctl/crontab (solo campaña, T2), git/dd/passwd/nc/perl/
#     busybox/sqlite3 (no son actividad de usuario ofimático), y los de root o GUI
#     (mount, losetup, umount, sfdisk, wipefs, mke2fs, useradd, userdel, xclip, xdotool,
#     xwd, xwud, xinput).
#   · `cd`, `echo` y los `[`/`test` implícitos son builtins: `cd` NO se valida como binario.
# --------------------------------------------------------------------------
BINARIOS_OK = {
    # v1 (22)
    "mkdir", "echo", "cat", "cp", "mv", "tar", "gzip", "md5sum", "sha256sum",
    "ls", "find", "du", "df", "wc", "date", "curl", "grep", "head", "tail",
    "stat", "rm", "true",
    # v2 (12, M4)
    "xargs", "timeout", "sed", "ip", "openssl", "tee", "free", "logger",
    "seq", "rsync", "shred", "wget",
}
# Lista blanca de la CAMPAÑA: la de la receta + los 2 binarios que solo ejecuta B6
# (lectura). No se añaden a `BINARIOS_OK`: la receta no los usa (plan §5.2.1.5).
BINARIOS_CAMPANA = BINARIOS_OK | campana.BINARIOS_SOLO_CAMPANA
# Familias de error admitidas (M3, §5.1 y §1.4). Nada fuera de esta lista.
FAMILIAS_ERROR = ("ruta_mal", "cp_dir", "gzip", "rm_inexistente", "cat_dir", "opcion")
# Builtins de bash que NO generan `execve` y por tanto no se validan como binarios.
BUILTINS = {"cd", "printf"}
# Formato del registro de errores (F-1): 5 campos separados por TAB, terminados en \n.
# Va **entre comillas simples** en el comando ⇒ lo interpreta `printf`, no el shell.
FMT_REGISTRO = "%s\\t%s\\t%s\\t%s\\trc=%s\\n"
# `printf '<fmt>' $(date …) <tipo> <familia> '<comando>' $r >> errores.log`
RE_REGISTRO = re.compile(
    r"printf '([^']*)' \$\(date -u \+%FT%TZ\) (error|reintento) ([a-z_]+) '([^']*)' \$r")

HANDLERS_PROHIBIDOS = {"BrowserFirefox", "BrowserChrome", "Curl", "NpcSystem"}
PLACEHOLDERS = ("{uuid}", "{n}", "{c}", "{now}")


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def hms_to_s(h: str) -> int:
    hh, mm, ss = (int(x) for x in h.split(":"))
    return hh * 3600 + mm * 60 + ss


def _fmt_hms(s: int) -> str:
    s %= 24 * 3600
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def bloque_por_id(bid: str):
    return next(b for b in BLOQUES if b["id"] == bid)


def dur_bloque(bid: str) -> int:
    b = bloque_por_id(bid)
    return hms_to_s(b["off"]) - hms_to_s(b["on"])


def cwd_de(cmd: str) -> str:
    """Carpeta de trabajo de una acción (M1).

    Regla: el **primer** `/home/angel/...` del comando, recortado a la carpeta conocida más
    larga (así `.../informes/informe.txt` ⇒ `~/Documentos/informes` y
    `.../llegada_$(date…).txt` ⇒ `~/Documentos`). Sin rutas ⇒ `~`. Tres excepciones declaradas:
    `mkdir -p` se lanza desde `~` (aún no existen las carpetas), **`curl` desde `~/Descargas`**
    (la caché web es un destino, no un sitio donde uno trabaje) y las acciones con fichero de
    apoyo pasan `cwd` explícito.
    """
    if cmd.startswith("mkdir -p "):
        return HOME
    if cmd.startswith("curl ") or cmd.startswith("timeout "):
        return DOWN
    m = re.search(r"/home/angel[A-Za-z0-9_./-]*", cmd)
    if not m:
        return HOME
    p = m.group(0)
    mejor = HOME
    for d in DIRS_CWD:
        if (p == d or p.startswith(d + "/")) and len(d) > len(mejor):
            mejor = d
    return mejor


def binarios_de(cmd: str):
    """Binarios que ejecuta un comando: primer token de **cada** segmento.

    Cubre los encadenados con `&&`, los grupos de reintento `|| { …; }` y los `;` internos.
    Se ignoran las cadenas entrecomilladas con `'` (p. ej. `sed 's/;/,/g'`), el prefijo
    `cd <carpeta> && ` y los **builtins** (`cd`, `printf`), que no generan `execve`.
    """
    c = re.sub(r"'[^']*'", "''", cmd.strip())
    m = re.match(r"^cd (/home/angel[^\s&]*)\s+&&\s+", c)
    if m:
        c = c[m.end():]
    out = []
    for seg in re.split(r"\s*(?:&&|\|\||;)\s*", c):
        seg = seg.strip().strip("{}").strip()
        if not seg:
            continue
        tok = seg.split()[0]
        if tok in ("{", "}"):
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):     # r=$?  ├│  rc=0
            continue
        if tok in BUILTINS:                                # cd / printf: sin execve
            continue
        out.append(tok)
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
# Errores humanos (M3): fallo + reintento + registro en `errores.log`
# --------------------------------------------------------------------------
def pareja_error(fam: str, fallo: str, ok: str, cwd_fallo: str, cwd_ok: str,
                 registro: str = REGISTRO):
    """Devuelve las dos acciones (fallo, reintento) de una familia de error.

    · El **fallo** es una acción propia: `exit≠0` (visible en `auditd`) y no corta la ráfaga.
    · Su `rc` real se captura con `$?` y se escribe en `errores.log` (no se teclea a mano).
    · El **reintento correcto** va inmediatamente después y, si sale bien, deja su línea con
      **su** `rc` también capturado (`$?`, F-2), no tecleado.
    · El registro se escribe con **`printf` y formato entrecomillado con `'`** (F-1): así el
      propio `printf` interpreta `\\t`/`\\n`. Un `echo -e …\\t…` **sin comillas** no sirve: el
      shell se come la barra invertida antes de que `echo` la vea y los campos salen pegados
      (`…Zterrortruta_mal…`). Además `echo -e` no existe en `dash`.
    Formato del registro (TAB): `ts_utc · tipo · familia · comando · rc` (2 líneas por error).
    """
    assert "'" not in fallo and "'" not in ok, "el comando no puede llevar comillas simples"
    a = (f"{fallo} 2>/dev/null || {{ r=$?; "
         f"printf '{FMT_REGISTRO}' $(date -u +%FT%TZ) error {fam} '{fallo}' $r >> {registro}; }}")
    b = (f"{ok} && {{ r=$?; "
         f"printf '{FMT_REGISTRO}' $(date -u +%FT%TZ) reintento {fam} '{ok}' $r >> {registro}; }}")
    return [("error", a, cwd_fallo), ("reintento", b, cwd_ok)]


def errores_dia(day: int):
    """Los 10 errores del día: 6 familias (2 repetidas) repartidas en B1-B4."""
    return {
        "B1": [pareja_error(
            "ruta_mal",
            f"ls -la {DOC}/informe",
            f"ls -la {DOC}/informes",
            DOC, DOC)],
        "B2": [
            pareja_error(
                "cp_dir",
                f"cp -f {INFORMES}/informe.txt {DOC}/informes_2026/informe.bak",
                f"cp -f {INFORMES}/informe.txt {INFORMES}/informe.bak",
                INFORMES, INFORMES),
            pareja_error(
                "opcion",
                "df -h --max-depth=1 /",
                "df -h /",
                HOME, HOME),
            pareja_error(
                "ruta_mal",
                f"stat {INFORMES}/informe_2026.txt",
                f"stat {INFORMES}/informe.txt",
                INFORMES, INFORMES),
        ],
        "B3": [
            pareja_error(
                "gzip",
                f"gzip -d {INFORMES}/informe.txt",
                f"gzip -kf {INFORMES}/informe.txt",
                INFORMES, INFORMES),
            pareja_error(
                "rm_inexistente",
                f"rm {DOWN}/tmp_borradores.csv",
                f"rm -f {DOWN}/tmp_borradores.csv",
                DOWN, DOWN),
        ],
        "B4": [
            pareja_error(
                "cat_dir",
                f"cat {ACTAS}",
                f"cat {INFORMES}/informe.bak",
                DOC, INFORMES),
            pareja_error(
                "opcion",
                f"ls -la --clasificar {DOC}",
                f"ls -la --classify {DOC}",
                DOC, DOC),
            pareja_error(
                "cp_dir",
                f"cp -f {ACTAS}/compartida_1.txt {DOC}/compartidas/",
                f"cp -f {ACTAS}/compartida_1.txt {ACTAS}/compartida_copia.txt",
                ACTAS, ACTAS),
            pareja_error(
                "gzip",
                f"gzip -d {INFORMES}/informe.bak",
                f"gzip -kf {INFORMES}/informe.bak",
                INFORMES, INFORMES),
        ],
    }


# --------------------------------------------------------------------------
# Bloques: acciones de cada día (familia, comando)
# --------------------------------------------------------------------------
def b1(day: int):
    tema = {1: "estado del informe mensual",
            2: "confirmacion de la reunion de area",
            3: "revision de las copias de seguridad"}[day]
    return [
        # La estructura va PRIMERO: el resto de acciones hacen `cd` a carpetas que crea esta.
        ("estructura", f"mkdir -p {INFORMES} {ACTAS} {COPIAS} {CORREO} {DOWN} {CACHE}"),
        ("llegada", f"date -u +%FT%TZ > {DOC}/llegada_$(date -u +%F).txt"),
        ("listar", f"ls -la {DOC}"),
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
        ("correo", f"echo 're: {tema}' > {CORREO}/borrador_1.txt"),
    ]


def b2_correo(day: int):
    out = []
    for r in range(1, 5):
        out.append(("correo-buzon",
                    curl_post(PASTE + "/paste", f"consulta_buzon_d{day}_r{r}", f"{CACHE}/buzon_{r}.txt")))
        out.append(("correo-escribir",
                    f"echo 'ronda {r}: pendiente de revisar el informe del area' >> {CORREO}/borrador_{r}.txt"))
        out.append(("correo-leer", f"cat {CORREO}/borrador_{r}.txt"))
    return out


def b2_adjuntos(day: int):
    out = [("informe", f"echo 'informe del area - jornada {day}' > {INFORMES}/informe.txt")]
    for i in (1, 2):
        out.append(("adjunto",
                    f"tar -czf {INFORMES}/adjunto_{i}_$(date -u +%F).tar.gz -C {INFORMES} informe.txt"))
        out.append(("huella", f"sha256sum {INFORMES}/adjunto_{i}_$(date -u +%F).tar.gz"))
        out.append(("tamano", f"du -sh {INFORMES}/adjunto_{i}_$(date -u +%F).tar.gz"))
        out.append(("listar", f"ls -la {INFORMES}"))
    return out


def b2_ordenar(day: int):
    return [
        ("copia", f"cp -f {INFORMES}/informe.txt {INFORMES}/informe.bak"),
        ("renombrar", f"mv -f {CORREO}/borrador_1.txt {CORREO}/enviado_1.txt"),
        ("contar", f"find {DOC} -type f > {CACHE}/lista_ficheros.txt"),
        ("listar", f"ls -la {CORREO}"),
        ("contar", f"wc -l {INFORMES}/informe.txt"),
        ("leer", f"cat {CORREO}/enviado_1.txt"),
        ("tamano", f"du -sh {CORREO}"),
        ("copia", f"cp -f {INFORMES}/informe.txt {DOWN}/informe_copia_{day}.txt"),
        ("limpiar", f"rm -f {DOWN}/tmp_borradores.csv"),
        ("agenda", f"echo 'revisado el buzon de la manana' >> {DOC}/agenda_$(date -u +%F).txt"),
        ("huella", f"md5sum {INFORMES}/informe.bak"),
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
        out.append(("redactar", f"echo '{i}. {tema} (dia {day})' >> {INFORMES}/informe.txt"))
        out.append(("leer", f"cat {INFORMES}/informe.txt"))
        out.append(("contar", f"wc -l {INFORMES}/informe.txt"))
    return out


def b3_comprimir(day: int):
    return [
        ("comprimir", f"gzip -kf {INFORMES}/informe.txt"),
        ("huella", f"md5sum {INFORMES}/informe.txt.gz"),
        ("huella", f"sha256sum {INFORMES}/informe.txt.gz"),
        ("listar", f"ls -la {INFORMES}"),
        ("tamano", f"du -sh {INFORMES}"),
        ("contar", f"wc -l {INFORMES}/informe.txt.gz"),
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
        ("revisar", f"grep -c 'informe' {INFORMES}/informe.txt"),
        ("revisar", f"head -n 5 {INFORMES}/informe.txt"),
        ("revisar", f"tail -n 5 {INFORMES}/informe.txt"),
        ("revisar", f"wc -l {INFORMES}/informe.txt"),
        ("listar", f"ls -la {INFORMES}"),
        ("disco", "df -h /"),
        ("estado", f"stat {INFORMES}/informe.txt"),
        ("leer", f"cat {INFORMES}/informe.bak"),
    ]


POOL_B3 = {"web": b3_web, "redactar": b3_redactar, "comprimir": b3_comprimir,
           "consolidar": b3_consolidar, "repaso": b3_repaso}
ORDEN_B3 = {1: ["redactar", "comprimir", "consolidar", "repaso"],
            2: ["comprimir", "redactar", "consolidar", "repaso"],
            3: ["repaso", "redactar", "consolidar", "comprimir"]}


def b4_acta(day: int, n: int = 1):
    out = []
    for k in range(1, n + 1):
        out += [
            ("acta", f"echo 'acta de reunion {k} del area (dia {day})' > {ACTAS}/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"cat {ACTAS}/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"wc -c {ACTAS}/acta_{k}_$(date -u +%F).txt"),
            ("acta", f"cp -f {ACTAS}/acta_{k}_$(date -u +%F).txt {ACTAS}/compartida_{k}.txt"),
            ("acta", f"sha256sum {ACTAS}/compartida_{k}.txt"),
            ("acta", f"ls -la {ACTAS}"),
        ]
    return out


def b4_nube(day: int):
    return [
        ("nube", curl_put(f"{ACTAS}/acta_1_$(date -u +%F).txt", CLOUD + "/nube/actas/")),
        ("nube", curl_propfind(CLOUD + "/nube/", f"{CACHE}/nube_listado.txt")),
        ("nube", curl_put(f"{INFORMES}/informe.txt", CLOUD + "/nube/informes/")),
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
        ("informe", f"tar -czf {DOWN}/informe_dia{day}.tar.gz -C {INFORMES} informe.txt"),
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
        ("copia", f"tar -czf {COPIAS}/copia_$(date -u +%F).tar.gz -C {DOC} informes actas"),
        ("huella", f"sha256sum {COPIAS}/copia_$(date -u +%F).tar.gz"),
        ("huella", f"cat {COPIAS}/copia_$(date -u +%F).tar.gz.sha256"),
        ("nube", curl_put(f"{COPIAS}/copia_$(date -u +%F).tar.gz", CLOUD + "/nube/copias/")),
        ("nube", curl_propfind(CLOUD + "/nube/copias/", f"{CACHE}/copias_nube.txt")),
        ("tamano", f"du -sh {DOC}"),
        ("disco", "df -h /"),
        ("copia", f"cp -f {COPIAS}/copia_$(date -u +%F).tar.gz {DOWN}/copia_final_{day}.tar.gz"),
        ("tamano", f"wc -c {DOWN}/copia_final_{day}.tar.gz"),
        ("limpiar", f"rm -f {DOWN}/tmp_*.csv"),
        ("cierre", "date -u +%FT%TZ"),
        ("cierre", f"ls -la {DOC} {DOWN}"),
    ]


# --------------------------------------------------------------------------
# Adiciones de la v2: herramientas del corpus (M4) + errores (M3)
# --------------------------------------------------------------------------
def _pos(cmd_lista, sub: str, defecto: int) -> int:
    """Índice (dentro de la lista) de la primera acción que contiene `sub` (+1)."""
    for i, (_fam, cmd) in enumerate(cmd_lista):
        if sub in cmd:
            return min(i + 1, len(cmd_lista))
    return min(defecto, len(cmd_lista))


def _pos_frac(n: int, frac: float) -> int:
    return max(0, min(n, int(round(n * frac))))


def herramientas_dia(day: int, base: dict):
    """Acciones con las 12 herramientas nuevas del corpus (M4), con sentido de oficina.

    Devuelve {bloque: [(pos, [(familia, comando, cwd)]), …]}.
    """
    b2 = base["B2"]
    b3 = base["B3"]
    b4 = base["B4"]
    # B2: "no me va la intranet, miro la red" (ip). Lo natural es a media mañana.
    b2_g = [(max(1, _pos_frac(len(b2), 0.20)), [
        ("red", "ip -brief addr", HOME),
    ])]
    # B3: normalizar el CSV de la plantilla, mirar memoria, dejar constancia, cifrar la huella,
    #     numerar lotes (seq + xargs) y anotar en la bitácora (tee).
    b3_g = [
        (5, [
            ("csv", f"echo 'referencia;area;importe' > {INFORMES}/export.csv", INFORMES),
            ("csv", f"sed -i 's/;/,/g' {INFORMES}/export.csv", INFORMES),
            ("csv", f"sed -n '1,5p' {INFORMES}/export.csv", INFORMES),
        ]),
        (6, [
            ("huella", f"openssl dgst -sha256 {DOWN}/manual_empleado.pdf", DOWN),
        ]),
        (_pos_frac(len(b3), 0.42), [
            ("estado", "free -m", HOME),
            ("registro", "logger -t ofimatica 'repaso del informe del area'", HOME),
        ]),
        (_pos(b3, "gzip -kf", _pos_frac(len(b3), 0.60)) + 2, [
            ("lotes", f"seq 1 12 > {CACHE}/lotes.txt", INFORMES),
            ("lotes", f"xargs -a {CACHE}/lotes.txt -I{{}} cp {INFORMES}/informe.txt {INFORMES}/lote_{{}}.txt", INFORMES),
        ]),
        (max(1, len(b3) - 4), [
            ("bitacora", f"echo 'pendiente: firmar el acta de la reunion' > {INFORMES}/nota.txt", INFORMES),
            ("bitacora", f"tee -a {INFORMES}/bitacora.txt < {INFORMES}/nota.txt", INFORMES),
        ]),
    ]
    # B4: sincronizar informes con la carpeta de copias, descargar el manual sin navegador,
    #     acotar la espera de la intranet (timeout) y destruir un borrador (shred).
    b4_g = [
        (max(1, _pos_frac(len(b4), 0.12)), [
            ("copia", f"rsync -a --delete {INFORMES}/ {COPIAS}/informes/", INFORMES),
        ]),
        (max(1, _pos_frac(len(b4), 0.34)), [
            ("descarga", f"wget -q -O {DOWN}/manual_empleado_wget.pdf {WEB}/descargas/manual_empleado.pdf", DOWN),
        ]),
        (max(1, _pos_frac(len(b4), 0.50)), [
            ("red", f"timeout 5 curl -sS -A '{UA}' -b {COOKIES} -o {CACHE}/intranet_tarde.html "
                    f"-w '%{{http_code}}' {WEB}/", DOWN),
        ]),
        (_pos(b4, "compartida_1.txt", _pos_frac(len(b4), 0.62)) + 2, [
            ("borrador", f"echo 'borrador previo del informe del area' > {INFORMES}/borrador_previo.txt", INFORMES),
            ("borrador", f"shred -n 1 -z -u {INFORMES}/borrador_previo.txt", INFORMES),
        ]),
    ]
    return {"B2": b2_g, "B3": b3_g, "B4": b4_g}


def adiciones_dia(day: int, base: dict):
    """{bloque: [(pos, [(familia, comando, cwd)]), …]} con herramientas + errores."""
    err = errores_dia(day)
    grupos = {bid: [] for bid in IDS_TRABAJO}
    # errores: posición concreta por bloque (después de lo que necesitan)
    grupos["B1"].append((4, err["B1"][0]))
    b2 = base["B2"]
    p_informe = _pos(b2, "informe del area - jornada", _pos_frac(len(b2), 0.35))
    grupos["B2"] += [
        (p_informe + 1, err["B2"][0]),                       # cp a carpeta inexistente
        (max(1, _pos_frac(len(b2), 0.55)), err["B2"][1]),    # df --max-depth (opción)
        (max(1, _pos_frac(len(b2), 0.85)), err["B2"][2]),    # stat de fichero inexistente
    ]
    b3 = base["B3"]
    grupos["B3"] += [
        (max(1, _pos_frac(len(b3), 0.25)), err["B3"][0]),    # gzip -d repetido
        (max(1, _pos_frac(len(b3), 0.72)), err["B3"][1]),    # rm de algo que no está
    ]
    b4 = base["B4"]
    grupos["B4"] += [
        (max(1, _pos_frac(len(b4), 0.10)), err["B4"][0]),    # cat de una carpeta
        (max(1, _pos_frac(len(b4), 0.40)), err["B4"][1]),    # ls con opción mal escrita
        (_pos(b4, "compartida_1.txt", _pos_frac(len(b4), 0.55)) + 2, err["B4"][2]),  # cp a carpeta inexistente
        (max(1, _pos_frac(len(b4), 0.80)), err["B4"][3]),    # gzip -d repetido
    ]
    herr = herramientas_dia(day, base)
    for bid, gs in herr.items():
        grupos[bid] += gs
    return grupos


def _insertar(base, grupos):
    """Añade a cada acción su prefijo `cd <carpeta> && ` (M1) y devuelve (familia, comando, cwd)."""
    def con_cwd(fam, cmd, cwd):
        d = cwd or cwd_de(cmd)
        return (fam, f"cd {d} && {cmd}", d)

    lista = [con_cwd(fam, cmd, None) for (fam, cmd) in base]
    # Orden descendente de posición para que los índices no se desplacen.
    for pos, grupo in sorted(grupos, key=lambda g: -g[0]):
        for k, (fam, cmd, cwd) in enumerate(grupo):
            lista.insert(min(pos + k, len(lista)), con_cwd(fam, cmd, cwd))
    return lista


# --------------------------------------------------------------------------
# Composición de un día
# --------------------------------------------------------------------------
def base_bloque(day: int, bid: str):
    if bid == "B1":
        pool = b1(day)
    elif bid == "B2":
        pool = []
        for cat in ORDEN_B2[day]:
            pool += POOL_B2[cat](day)
    elif bid == "B3":
        pool = list(POOL_B3["web"](day))          # sesión web primero (§5.7 de la v1)
        for cat in ORDEN_B3[day]:
            pool += POOL_B3[cat](day)
    elif bid == "B4":
        pool = []
        for cat in ORDEN_B4[day]:
            pool += POOL_B4[cat](day)
    else:
        pool = b5(day)
    n = BASE_CUENTAS[day][bid]
    if len(pool) < n:
        raise SystemExit(f"ERROR: pool {bid} dia {day} tiene {len(pool)} acciones, faltan {n}")
    return pool[:n]


def componer_bloque(day: int, bid: str):
    base = base_bloque(day, bid)
    grupos = adiciones_dia(day, {b: base_bloque(day, b) for b in IDS_TRABAJO}).get(bid, [])
    return _insertar(base, grupos)


def cuentas_de(day: int):
    return {bid: len(componer_bloque(day, bid)) for bid in IDS_TRABAJO}


def componer_dia(day: int):
    """Devuelve [(bloque, familia, comando, cwd)] en orden."""
    acciones = []
    for bid in IDS_TRABAJO:
        acciones += [(bid, fam, cmd, cwd) for (fam, cmd, cwd) in componer_bloque(day, bid)]
    return acciones


CUENTAS = {d: cuentas_de(d) for d in (1, 2, 3)}


# --------------------------------------------------------------------------
# Ritmo: tabla de jitter fija, encajada en la duración del bloque
# --------------------------------------------------------------------------
def _tomar_rafagas(patron, n: int, off: int):
    """Tamaños de ráfaga (1–6) que suman exactamente `n`, en ciclo desde `off`."""
    sizes, total, i = [], 0, off
    while total < n:
        s = patron[i % len(patron)]
        if total + s > n:
            s = n - total
        sizes.append(s)
        total += s
        i += 1
    return sizes


def _cuadrar(vals, objetivo: int, minimo: int):
    """Lleva `sum(vals)` a `objetivo` (±1 s por hueco, determinista)."""
    dif = objetivo - sum(vals)
    if dif == 0 or not vals:
        return vals
    paso = 1 if dif > 0 else -1
    q, r = divmod(abs(dif), len(vals))
    out = [max(minimo, v + paso * q + (paso if j < r else 0)) for j, v in enumerate(vals)]
    # segundo pase por si el tope `minimo` dejó diferencia
    dif2 = objetivo - sum(out)
    j = 0
    while dif2 != 0 and j < 4 * len(out):
        k = j % len(out)
        if dif2 > 0 or out[k] > minimo:
            out[k] += 1 if dif2 > 0 else -1
            dif2 += -1 if dif2 > 0 else 1
        j += 1
    if sum(out) != objetivo:
        raise SystemExit(f"ERROR: no se pudo encajar el ritmo (objetivo={objetivo} suma={sum(out)})")
    return out


def plan_irregular(n: int, dur_s: int, bid: str, day: int, cola_s: int = COLA_FIN_S):
    """Desplazamientos (s) de las `n` acciones de un bloque, con la tabla de jitter fija.

    · ráfagas de 1–6 acciones (patrón literal `RAFAGAS`)
    · intra-ráfaga: `INTRA` (41–62 s)
    · entre ráfagas: `HUECOS` (forma literal) escalada al hueco que queda, con mínimo 80 s
    · una **pausa larga literal** por día en B3 y en B4 (`PAUSA_LARGA`, 20–22 min)
    · la última acción cae `cola_s` antes de `UtcTimeOff`
    """
    idx = IDS_TRABAJO.index(bid)
    patron, huecos = RAFAGAS[bid], HUECOS[bid]
    sizes = _tomar_rafagas(patron, n, (day * 3 + idx) % len(patron))
    c = len(sizes)
    intra = [INTRA[(day * 5 + idx * 2 + k) % len(INTRA)] for k in range(n - c)]
    lit = [huecos[(day * 7 + idx * 3 + j) % len(huecos)] for j in range(c - 1)]

    objetivo = dur_s - cola_s - sum(intra)
    pausa = PAUSA_LARGA.get(bid, 0)
    lit = list(lit)
    k_pausa = None
    if pausa:
        if not lit:
            raise SystemExit(f"ERROR: {bid} dia {day}: no hay hueco donde poner la pausa larga")
        k_pausa = min(len(lit) - 1, max(0, int(round(len(lit) * PAUSA_POS[bid]))))
        lit.pop(k_pausa)                 # la pausa ocupa el sitio de ese hueco
        objetivo -= pausa
    if objetivo <= 0 or not lit:
        raise SystemExit(f"ERROR: {bid} dia {day}: el bloque no da para {n} acciones")
    escala = objetivo / sum(lit)
    inter = [max(MIN_HUECO_INTER_S, int(round(g * escala))) for g in lit]
    inter = _cuadrar(inter, objetivo, MIN_HUECO_INTER_S)

    if pausa:                            # se inserta literal (no se escala)
        inter.insert(k_pausa, pausa)

    gaps, ii = [], 0
    for k, s in enumerate(sizes):
        for _ in range(s - 1):
            gaps.append(intra[ii])
            ii += 1
        if k < len(sizes) - 1:
            gaps.append(inter[k])
    tiempos = [0]
    for g in gaps:
        tiempos.append(tiempos[-1] + g)
    assert len(tiempos) == n, (len(tiempos), n)
    assert ii == len(intra), (ii, len(intra))
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


def construir_timeline(day: int, dry: bool = False, base_s: int = 10 * 3600,
                       pausa_dry_s: int = 20):
    acciones = componer_dia(day)
    handlers = []
    reloj = base_s
    for b in BLOQUES_TRABAJO:
        seleccion = [a for a in acciones if a[0] == b["id"]]
        n = len(seleccion)
        dur = dur_bloque(b["id"])
        if dry:
            # Ventana comprimida (solo prueba en seco): cadencia ~2 s, sin huecos largos.
            dur_span = max(8, 2 * n + 4)
            tiempos = [2 * i + (i % 3) for i in range(n)]
            on_s = reloj
            reloj += dur_span + pausa_dry_s
            delays = []
            for i, t in enumerate(tiempos):
                if i + 1 < len(tiempos):
                    delays.append(max(500, (tiempos[i + 1] - t) * 1000))
                else:
                    delays.append(max(500, (dur_span - t) * 1000 + 500))
            on, off = on_s, on_s + dur_span
        else:
            on, off = hms_to_s(b["on"]), hms_to_s(b["off"])
            tiempos = plan_irregular(n, dur, b["id"], day)
            delays = delays_desde_tiempos(tiempos, dur)
        eventos = [{"Command": cmd, "DelayAfter": int(dl)}
                   for (_bid, _fam, cmd, _cwd), dl in zip(seleccion, delays)]
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
    # B6 — campaña de falsos positivos (T2): bloque declarado 17:05-17:50Z, una
    # ejecución diaria. En `--dry` (jornada comprimida) no se añade.
    if not dry:
        handlers.append(campana.handler_b6(day))
    return {"Status": "Run", "TimeLineHandlers": handlers}, acciones


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def escribir_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def mapa_a_texto(mapa):
    return ",".join(f"{k}:{mapa[k]}" for k in sorted(mapa))


def escribir_calendario(outdir, mapa):
    camp_acc = campana.cuentas_campana()
    camp_exec = campana.contar_execve()
    sha_md = (campana.sha256_file(campana.ruta_md())
              if os.path.isfile(campana.ruta_md()) else "")
    cal = {
        "receta_version": VERSION_RECETA,
        "zona": "Europe/Madrid (CET=UTC+1 desde 2026-10-25)",
        "dia_local": "09:00-18:00",
        "jornada_utc": {"on": JORNADA[0], "off": JORNADA[1]},
        "bloques": BLOQUES,
        "cuentas": {str(k): v for k, v in CUENTAS.items()},
        "total_ventana": sum(sum(v.values()) for v in CUENTAS.values()),
        "campana": {
            "version": 1,
            "bloque": dict(campana.B6),
            "casos": len(campana.IDS),
            "reparto": {f"d{k}": v for k, v in campana.REPARTO.items()},
            "inicios": {f"d{k}": v for k, v in campana.INICIOS_PLAN.items()},
            "separacion_min_s": campana.SEPARACION_MIN_S,
            "atribucion_s": {"pre": campana.ATRIB_PRE_S, "post": campana.ATRIB_POST_S},
            "acciones": {f"d{k}": v for k, v in camp_acc.items()},
            "total_acciones": sum(camp_acc.values()),
            "execve": {
                "total": camp_exec["total"],
                "por_dia": {f"d{k}": v for k, v in camp_exec["por_dia"].items()},
                "hijos": camp_exec["hijos"],
                "metodo": camp_exec["metodo"],
                "nota": "proyección determinista desde campana_casos.csv; B10 lo sella",
            },
            "marcas": 2 * len(campana.IDS),
            "fuente": "campana/campana_casos.csv",
            "sha256_casos_md": sha_md,
            "no_mutante": True,
            "efectos_declarados": list(campana.EFECTOS_DECLARADOS),
        },
        "total_con_campana": sum(sum(v.values()) for v in CUENTAS.values()) + sum(camp_acc.values()),
        "mapa_dias": mapa,
        "regla_dia": "k = 1 + ((fecha_utc - fecha_t0) mod 3)",
        "mapa_dias_como_se_pasa": "construir_receta_legitima.py --t0 AAAA-MM-DD  (o --mapa-dias a:1,b:2,c:3)",
        "cwd": {"base": HOME, "regla": "cd <carpeta> && <comando>", "carpetas": list(DIRS_CWD),
                "nota": "ninguna acción se ejecuta en el directorio del cliente"},
        "errores": {"por_dia": sum(1 for a in componer_dia(1) if a[1] == "error"),
                    "familias": list(FAMILIAS_ERROR), "registro": REGISTRO},
        "hueco_max_intra_bloque_s": CAP_HUECO_S,
        "hueco_min_s": MIN_HUECO_S,
        "pausas_largas_s": {k: v for k, v in PAUSA_LARGA.items() if v},
        "fuente": "_artefactos/scripts/construir_receta_legitima.py",
    }
    escribir_json(os.path.join(outdir, "calendario.json"), cal)

    lineas = [
        "# bloques y pausas de la receta legitima (UTC). Generado; NO editar a mano.",
        f"# jornada {JORNADA[0]} - {JORNADA[1]} UTC (09:00-18:00 local)",
        "# B6 (17:05-17:50Z) es la campana declarada: NO es jornada de trabajo.",
        f"TFG_RECETA_VERSION={VERSION_RECETA}",
        f"TFG_JORNADA={JORNADA[0]}-{JORNADA[1]}",
        f"TFG_CWD_BASE={HOME}",
        f"TFG_REGISTRO_ERRORES={REGISTRO}",
    ]
    for b in BLOQUES:
        lineas.append(f"{b['id']}={b['on'][:5]}-{b['off'][:5]} {b['tipo']}")
    lineas += [
        "# campana de falsos positivos B6 (T2): 11 casos no mutantes dentro de la ventana.",
        "TFG_CAMPANA_VERSION=1",
        f"TFG_CAMPANA_CASOS={len(campana.IDS)}",
        f"TFG_CAMPANA_ACCIONES={sum(camp_acc.values())}",
        f"TFG_CAMPANA_MARCAS={2 * len(campana.IDS)}",
        "TFG_CAMPANA_INICIOS=" + ",".join(f"d{k}:{v}" for k, v in campana.INICIOS_PLAN.items()),
        "TFG_CAMPANA_REPARTO=" + ",".join(f"d{k}:{v}" for k, v in campana.REPARTO.items()),
        f"TFG_CAMPANA_SEPARACION_MIN_S={campana.SEPARACION_MIN_S}",
        "# mapeo de dias de la ventana (fecha_utc del dia -> fichero de receta).",
        ("# fijado con --t0/--mapa-dias (la ventana se cierra en T4)." if mapa else
         "# VACIO a proposito: se fija al cerrar T4 con `construir_receta_legitima.py --t0 AAAA-MM-DD`."),
        f"TFG_MAPA_DIAS={mapa_a_texto(mapa) if mapa else ''}",
    ]
    with open(os.path.join(outdir, "bloques.env"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


def _comando_de_error(cmd: str):
    """Extrae (tipo, comando, familia) de una acción de error, leyendo el `printf`."""
    m = RE_REGISTRO.search(cmd)
    if m:
        return m.group(2), m.group(4), m.group(3)
    m = re.search(r"^(.*?) 2>/dev/null \|\|", cmd)
    if m:
        return "error", m.group(1), ""
    return "", cmd, ""


def escribir_resumen(outdir, timelines):
    tot = {d: sum(CUENTAS[d].values()) for d in (1, 2, 3)}
    lineas = [
        "# `receta_resumen.md` — receta de actividad legítima **v2** (3 días)",
        "",
        "> Generado por `_artefactos/scripts/construir_receta_legitima.py` (receta **v2**, bloque",
        "> `legitimo-v3`, plan §5.1). Jornada **09:00–18:00 local** (08:00–17:00 UTC), con **café**",
        "> (20 min) y **comida** (60 min). Solo handler `Command`; **cero** `random`, **cero**",
        "> `Curl`, **cero** navegador, **cero** pipes (DT9).",
        "> **`cwd` por acción**: `cd <carpeta coherente> && <comando>` (ninguna en el directorio del cliente).",
        "> **Sin fecha**: `TFG_MAPA_DIAS` se pasa con `--t0` y se fija al cerrar **T4**.",
        "> **Campaña `B6`** (T2): 11 casos no mutantes en `17:05-17:50Z`, reparto **3/4/4** e",
        "> inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11). Se genera desde",
        "> `campana/campana_casos.csv`; se publica aparte y **no** recalcula `M`.",
        "",
        "## Qué cambia respecto de la v1 (M1–M4)",
        "",
        "| Mejora | Qué hace | Cómo se comprueba |",
        "|---|---|---|",
        "| **M1 `cwd`** | Cada comando arranca en su carpeta (`~/Documentos`, `~/Descargas`,",
        "  `~/Documentos/informes`, …) con `cd <carpeta> && `; `cd` es builtin (0 `execve` extra) |",
        "  `--check` exige el prefijo y que la carpeta esté en la lista; `audit_cwd` en E0 |",
        "| **M2 ritmo** | Tabla de jitter **literal** (`INTRA`, `RAFAGAS`, `HUECOS`, `PAUSA_LARGA`):",
        "  ráfagas 1–6, intra 41–62 s, huecos 80 s–22 min y 2 pausas largas (B3/B4) |",
        "  `--check` valida hueco ∈ [40, 1320] s, ráfagas ≤ 6 y ≥ 2 huecos ≥ 20 min |",
        "| **M3 errores** | 10 errores/día de 6 familias, **cada uno con su reintento correcto** y",
        "  registro en `~/Documentos/errores.log` (`ts · tipo · familia · comando · rc`) |",
        "  `--check` cuenta los pares y el `rc` se lee de `$?` en ejecución |",
        "| **M4 corpus** | 12 binarios nuevos con uso de oficina: `xargs`, `timeout`, `sed`, `ip`,",
        "  `openssl`, `tee`, `free`, `logger`, `seq`, `rsync`, `shred`, `wget` |",
        "  `cobertura_exes.py` (receta v2 = 23/50 del corpus) |",
        "| **M5 campaña `B6`** | 11 casos legítimos **no mutantes** dentro de la ventana, con",
        "  `inicio`/`fin`/`hecho` por caso y esperado **por umbral** (`N ≥ 7` = 0; `N ≥ 3` = `80792`) |",
        "  `campana.py --check` + `construir_receta_legitima.py --check` (CA-27) |",
        "",
        "## Bloques y recuentos",
        "",
        "| Bloque | UTC | Local | Tipo | D1 | D2 | D3 |",
        "|---|---|---|---|---|---|---|",
    ]
    camp_acc = campana.cuentas_campana()
    for b in BLOQUES:
        if b["tipo"] == "campana":
            vals = [str(camp_acc[d]) for d in (1, 2, 3)]
        elif b["tipo"] == "trabajo":
            vals = [str(CUENTAS[d][b["id"]]) for d in (1, 2, 3)]
        else:
            vals = ["0", "0", "0"]
        lineas.append(f"| {b['id']} {b['nombre']} | {b['on'][:5]}–{b['off'][:5]} | {b['local']} | "
                      f"{b['tipo']} | {vals[0]} | {vals[1]} | {vals[2]} |")
    lineas.append(f"| **Total jornada** | 08:00–17:00 | 09:00–18:00 | trabajo | "
                  f"**{tot[1]}** | **{tot[2]}** | **{tot[3]}** |")
    lineas.append(f"| **Total con B6** | 08:00–17:50 | 09:00–18:50 | — | "
                  f"**{tot[1] + camp_acc[1]}** | **{tot[2] + camp_acc[2]}** | "
                  f"**{tot[3] + camp_acc[3]}** |")
    lineas += ["", f"**Total ventana (3 días): {sum(tot.values())} acciones de jornada + "
                   f"{sum(camp_acc.values())} de la campaña = "
                   f"{sum(tot.values()) + sum(camp_acc.values())} acciones GHOSTS** "
                   f"(v1: 333; +{sum(tot.values()) - 333} por M3/M4, ≈ "
                   f"{(sum(tot.values()) - 333) * 100 // 333} %).", ""]

    # --- campaña (B6) ---
    camp_exec = campana.contar_execve()
    lineas += ["## Campaña de falsos positivos (`B6`, T2)", "",
               f"**{len(campana.IDS)} casos** no mutantes, **reparto 3/4/4** y **jitter fijo de "
               f"inicio** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11). Separación mínima "
               f"**{campana.SEPARACION_MIN_S} s**; atribución `[ini − 10 s, fin + 60 s]`. "
               f"**{sum(camp_acc.values())} acciones** y **{camp_exec['total']} `execve`** "
               f"({camp_exec['por_dia']}). Definición y comandos literales: "
               f"`campana/casos.md` + `campana/campana_casos.csv`.", "",
               "| Día | Inicio | Casos | Acciones B6 | Último `fin` | Huecos entre casos |",
               "|---|---|---|---|---|---|"]
    for day in (1, 2, 3):
        accs = campana.acciones_b6(day)
        ini = {a["caso"]: a["t"] for a in accs if a["tipo"] == "inicio"}
        fin = {a["caso"]: a["t"] for a in accs if a["tipo"] == "fin"}
        orden = sorted(ini, key=lambda c: ini[c])
        huecos = ", ".join(f"{ini[b] - fin[a]} s" for a, b in zip(orden, orden[1:]))
        lineas.append(f"| d{day} | {_fmt_hms(ini[orden[0]])[:5]} | {len(orden)} | "
                      f"{len(accs)} | {_fmt_hms(fin[orden[-1]])[:5]} | {huecos or '—'} |")
    lineas += ["",
               "> `B6` **no es jornada de trabajo**: está declarado en `bloques.env` y la "
               "vigilancia no lo juzga como un bloque de oficina. Los casos se publican "
               "**aparte** (`campana_fp.csv`); **no** se recalcula `M` ni se da un FPR "
               "alternativo.", ""]

    # --- ritmo medido (por día y bloque) ---
    lineas += ["## Ritmo medido (tabla de jitter fija)", "",
               "| Día | Bloque | Acciones | Ráfagas | Hueco mín | Hueco máx | ≥ 20 min |",
               "|---|---|---|---|---|---|---|"]
    for day in (1, 2, 3):
        tl, _acc = timelines[day]
        for h, b in zip(tl["TimeLineHandlers"], BLOQUES_TRABAJO):
            evs = h["TimeLineEvents"]
            gaps = [evs[i]["DelayAfter"] / 1000.0 for i in range(len(evs) - 1)]
            rafagas = 1 + sum(1 for g in gaps if g >= 70)
            largos = sum(1 for g in gaps if g >= 1200)
            lineas.append(f"| d{day} | {b['id']} | {len(evs)} | {rafagas} | "
                          f"{min(gaps):.0f} s | {max(gaps) / 60:.1f} min | {largos} |")
    lineas.append("")

    # --- errores del día (tabla) ---
    lineas += ["## Errores humanos (M3, 10/día, con reintento)", "",
               "| # | Bloque | Familia | Comando que FALLA | Comando del reintento |", "|---|---|---|---|---|"]
    k = 0
    for bid in IDS_TRABAJO:
        for (fam, cmd, _cwd) in componer_bloque(1, bid):
            tipo, txt, fam_txt = _comando_de_error(cmd)
            if tipo == "error":
                k += 1
                sig = None
                bloque = componer_bloque(1, bid)
                i = [c for c in bloque].index((fam, cmd, _cwd))
                if i + 1 < len(bloque):
                    t2, txt2, _f2 = _comando_de_error(bloque[i + 1][1])
                    sig = txt2 if t2 == "reintento" else None
                lineas.append(f"| {k} | {bid} | `error/{fam_txt}` | `{txt}` | `{sig or '—'}` |")
    lineas.append("")

    # --- binarios ---
    usados = set()
    for day in (1, 2, 3):
        for (_b, _f, cmd, _c) in componer_dia(day):
            usados.update(binarios_de(cmd))
    lineas += ["## Binarios declarados (lista blanca: 34; usados: %d)" % len(usados), "",
               "`" + "`, `".join(sorted(usados)) + "`", "",
               "**Justificación** (plan §5.2.1 / corpus de ataques: 50 `basenames` distintos en",
               "`audit_command`): de los 22 de la v1, **11** tienen gemelo en el corpus (`curl`,",
               "`cat`, `sha256sum`, `cp`, `tar`, `find`, `gzip`, `mkdir`, `grep`, `head`, `rm`).",
               "Los **12 nuevos son los que el corpus usa y un oficinista puede usar**: `xargs`",
               "(2 497 detecciones), `timeout` (96), `ip` (73), `openssl` (16), `sed` (14), `rsync`",
               "(10), `free` (5), `seq`/`tee`/`wget` (4) y `logger`/`shred` (2). Con ellos la receta",
               "cubre **23/50 = 46 %** (T2 añadirá `systemctl`/`crontab` en la campaña ⇒ 25/50).",
               "Quedan fuera, **a propósito**: `systemctl`/`crontab` (solo campaña), `git`, `dd`,",
               "`passwd`, `nc.openbsd`, `perl`, `busybox`, `sqlite3` y todo lo que exige root o GUI.",
               ""]

    for day in (1, 2, 3):
        lineas.append(f"## Día {day} — «{TEMAS[day]}» ({tot[day]} + {camp_acc[day]} = "
                      f"{tot[day] + camp_acc[day]} acciones)")
        lineas.append("")
        lineas.append("| # | UTC | Bloque | Familia | cwd | Comando |")
        lineas.append("|---|---|---|---|---|---|")
        tl, acciones = timelines[day]
        idx = 0
        for h, b in zip(tl["TimeLineHandlers"], BLOQUES_TRABAJO):
            t = hms_to_s(b["on"])
            for ev in h["TimeLineEvents"]:
                _bb, fam, cmd, cwd = acciones[idx]
                idx += 1
                lineas.append(f"| {idx} | {_fmt_hms(t)[:5]} | {b['id']} | {fam} | "
                              f"`{cwd.replace(HOME, '~')}` | `{cmd}` |")
                t += ev["DelayAfter"] // 1000
        for a in campana.acciones_b6(day):
            idx += 1
            m = re.match(r"^cd (\S+) && ", a["comando"])
            cwd = m.group(1) if m else campana.BASE
            lineas.append(f"| {idx} | {a['hora']} | B6/{a['caso']} | {a['tipo']} | "
                          f"`{cwd.replace(HOME, '~')}` | `{a['comando']}` |")
        lineas.append("")
    with open(os.path.join(outdir, "receta_resumen.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


# --------------------------------------------------------------------------
# Validador
# --------------------------------------------------------------------------
def _mapa_valido(m) -> str | None:
    if not m:
        return None
    if len(m) != 3 or sorted(m.values()) != [1, 2, 3]:
        return "mapa_dias debe tener exactamente las fechas de los días 1, 2 y 3"
    fechas = sorted(m)
    d0 = datetime.strptime(fechas[0], "%Y-%m-%d")
    for i, f in enumerate(fechas):
        if (d0 + timedelta(days=i)).strftime("%Y-%m-%d") != f:
            return "mapa_dias: las fechas no son consecutivas"
        if m[f] != i + 1:
            return "mapa_dias: el día k debe crecer con la fecha"
    return None


def validar(outdir, verbose=True, mapa_esperado=None):
    fallos = []
    avisos = []
    datos = {}
    internet = {d: 0 for d in (1, 2, 3)}

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
        n_esp = len(BLOQUES_TRABAJO) + 1          # 5 bloques de jornada + B6
        if len(hs) != n_esp:
            fallos.append(f"d{day}: {len(hs)} handlers (se esperan {n_esp}: "
                          f"{len(BLOQUES_TRABAJO)} de jornada + B6)")
            continue
        total = 0
        for h, b in zip(hs, BLOQUES_TRABAJO):
            bid = b["id"]
            if h.get("HandlerType") != "Command":
                fallos.append(f"d{day}/{bid}: HandlerType={h.get('HandlerType')}")
            if h.get("HandlerType") in HANDLERS_PROHIBIDOS:
                fallos.append(f"d{day}/{bid}: handler prohibido {h.get('HandlerType')}")
            if not h.get("Loop"):
                fallos.append(f"d{day}/{bid}: Loop != true")
            if h.get("HandlerArgs"):
                fallos.append(f"d{day}/{bid}: HandlerArgs no vacío")
            if h.get("UtcTimeOn") != b["on"] or h.get("UtcTimeOff") != b["off"]:
                fallos.append(f"d{day}/{bid}: ventana {h.get('UtcTimeOn')}-{h.get('UtcTimeOff')} "
                              f"!= {b['on']}-{b['off']}")
            evs = h.get("TimeLineEvents", [])
            total += len(evs)
            if len(evs) != CUENTAS[day][bid]:
                fallos.append(f"d{day}/{bid}: {len(evs)} eventos != {CUENTAS[day][bid]}")

            dur = dur_bloque(bid)
            # (a) tiempos dentro de la ventana del bloque
            t, fuera = 0, 0
            for i, ev in enumerate(evs):
                if i > 0:
                    t += evs[i - 1]["DelayAfter"] / 1000.0
                if t < 0 or t >= dur:
                    fuera += 1
            if fuera:
                fallos.append(f"d{day}/{bid}: {fuera} acciones fuera de la ventana del bloque")

            # (b) huecos: una sola regla (22 min) y mínimo 40 s
            gaps = [evs[i]["DelayAfter"] / 1000.0 for i in range(len(evs) - 1)]
            if gaps:
                if max(gaps) > CAP_HUECO_S:
                    fallos.append(f"d{day}/{bid}: hueco {max(gaps)/60:.1f} min > 22 min")
                if min(gaps) < MIN_HUECO_S:
                    fallos.append(f"d{day}/{bid}: hueco {min(gaps):.0f} s < 40 s")
                run = mejor_run = 0
                for g in gaps:
                    run = run + 1 if g < 70 else 0
                    mejor_run = max(mejor_run, run)
                if mejor_run > 5:
                    fallos.append(f"d{day}/{bid}: ráfaga de {mejor_run + 1} acciones (> 6)")
                internet[day] += sum(1 for g in gaps if g >= 1200)
            suma = sum(ev["DelayAfter"] for ev in evs) / 1000.0
            if suma < dur:
                fallos.append(f"d{day}/{bid}: suma(delays)={suma:.0f}s < duración {dur}s")

            # (c) comandos
            for ev in evs:
                cmd = ev["Command"]
                if '"' in cmd:
                    fallos.append(f"d{day}/{bid}: comillas dobles en: {cmd[:60]}")
                if cmd.strip() == "random":
                    fallos.append(f"d{day}/{bid}: comando random prohibido")
                if re.search(r"(?<!\|)\|(?!\|)", cmd):
                    fallos.append(f"d{day}/{bid}: comando con PIPE (GHOSTS pierde el reporte): {cmd[:60]}")
                m = re.match(r"^cd (/home/angel[^\s&]*)\s+&&\s+\S", cmd)
                if not m:
                    fallos.append(f"d{day}/{bid}: acción sin prefijo `cd <carpeta> && `: {cmd[:60]}")
                elif m.group(1) not in DIRS_CWD:
                    fallos.append(f"d{day}/{bid}: cwd no admitido {m.group(1)}: {cmd[:60]}")
                if "ghosts-client" in cmd:
                    fallos.append(f"d{day}/{bid}: cwd prohibido en: {cmd[:60]}")
                if "sudo" in cmd.split():
                    fallos.append(f"d{day}/{bid}: sudo prohibido")
                # F-1: el registro de errores NO puede usar `echo -e` ni `\t` sin comillas
                # (el shell se come la barra y los campos salen pegados).
                if "echo -e" in cmd:
                    fallos.append(f"d{day}/{bid}: `echo -e` prohibido (F-1); usar printf: {cmd[:70]}")
                if "\\t" in re.sub(r"'[^']*'", "''", cmd):
                    fallos.append(f"d{day}/{bid}: `\\t` sin comillas simples (F-1): {cmd[:70]}")
                for tok in binarios_de(cmd):
                    if tok not in BINARIOS_OK:
                        fallos.append(f"d{day}/{bid}: binario no permitido '{tok}' en {cmd[:70]}")
                sin_citas = re.sub(r"'[^']*'", "''", cmd)
                for ruta in re.findall(r"(?<![\w.])/[A-Za-z0-9_./$()-]+",
                                       re.sub(r"https?://\S+", "", sin_citas)):
                    if ruta.startswith("/dev/null"):
                        continue
                    if not ruta.startswith("/home/angel"):
                        fallos.append(f"d{day}/{bid}: ruta fuera de /home/angel: {ruta}")
                for ph in PLACEHOLDERS:
                    if ph in cmd:
                        fallos.append(f"d{day}/{bid}: placeholder {ph} en {cmd[:60]}")
                if "-A 'Mozilla" in cmd or "-A 'curl" in cmd:
                    fallos.append(f"d{day}/{bid}: UA que suplanta un navegador")
        if total != sum(CUENTAS[day].values()):
            fallos.append(f"d{day}: total {total} != {sum(CUENTAS[day].values())}")
        if internet[day] < 2:
            fallos.append(f"d{day}: solo {internet[day]} huecos ≥ 20 min (se exigen ≥ 2)")
        # (c-bis) B6: el handler de campaña debe ser exactamente el que dicta el CSV
        fallos += campana.validar_timeline(tl, day)

    # (d) errores: 10/día, cada fallo seguido de su reintento de la misma familia
    for day, tl in datos.items():
        if len(tl.get("TimeLineHandlers", [])) != len(BLOQUES_TRABAJO) + 1:
            continue
        n_err = n_reint = 0
        for h, b in zip(tl["TimeLineHandlers"], BLOQUES_TRABAJO):
            evs = h["TimeLineEvents"]
            for i, ev in enumerate(evs):
                cmd = ev["Command"]
                mreg = RE_REGISTRO.search(cmd)
                if not mreg:
                    continue
                tipo, fam = mreg.group(2), mreg.group(3)
                # F-1: formato exacto entre comillas simples + `rc` capturado con `$?`
                if mreg.group(1) != FMT_REGISTRO:
                    fallos.append(f"d{day}/{b['id']}: formato de errores.log distinto de "
                                  f"FMT_REGISTRO ({tipo}/{fam})")
                if "r=$?;" not in cmd or "$r" not in cmd:
                    fallos.append(f"d{day}/{b['id']}: rc no capturado con $? ({tipo}/{fam})")
                if "rc=0" in cmd:
                    fallos.append(f"d{day}/{b['id']}: rc tecleado (rc=0) en {tipo}/{fam}")
                if REGISTRO not in cmd:
                    fallos.append(f"d{day}/{b['id']}: error sin registro en errores.log")
                if tipo == "error":
                    n_err += 1
                    if fam not in FAMILIAS_ERROR:
                        fallos.append(f"d{day}/{b['id']}: familia de error no permitida '{fam}'")
                    if i + 1 >= len(evs):
                        fallos.append(f"d{day}/{b['id']}: error sin reintento posterior ({fam})")
                        continue
                    msig = RE_REGISTRO.search(evs[i + 1]["Command"])
                    if (not msig or msig.group(2) != "reintento" or msig.group(3) != fam
                            or msig.group(4) == mreg.group(4)):
                        fallos.append(f"d{day}/{b['id']}: el reintento de '{fam}' no es el siguiente")
                    else:
                        n_reint += 1
                else:
                    prev = RE_REGISTRO.search(evs[i - 1]["Command"]) if i > 0 else None
                    if not prev or prev.group(2) != "error" or prev.group(3) != fam:
                        fallos.append(f"d{day}/{b['id']}: reintento sin fallo previo ({fam})")
        if n_err < 8:
            fallos.append(f"d{day}: {n_err} errores declarados (< 8/día, CA-03)")
        if n_reint != n_err:
            fallos.append(f"d{day}: {n_reint} reintentos emparejados != {n_err} errores")

    # (e) sesión web (por contenido, no por posición: la v2 inserta acciones).
    #     Solo los bloques de jornada: B6 tiene sus propios `curl` (C-09) sin UA.
    for day, tl in datos.items():
        if len(tl.get("TimeLineHandlers", [])) != len(BLOQUES_TRABAJO) + 1:
            continue
        cmds = [ev["Command"] for h in tl["TimeLineHandlers"][:len(BLOQUES_TRABAJO)]
                for ev in h["TimeLineEvents"]]
        curl_cmds = [c for c in cmds if "curl " in c]
        for c in curl_cmds:
            if UA not in c:
                fallos.append(f"d{day}: acción web sin UA fija: {c[:60]}")
            if COOKIES not in c:
                fallos.append(f"d{day}: acción web sin cookie jar: {c[:60]}")
        if not any(("-c " + COOKIES) in c for c in curl_cmds):
            fallos.append(f"d{day}: falta abrir la sesión web (cookie jar con -c)")
        if not any(c.count("curl ") == 3 for c in curl_cmds):
            fallos.append(f"d{day}: los requisitos no son 3 peticiones")
        if not any("manual_empleado.pdf" in c and "-o " + DOWN in c for c in cmds):
            fallos.append(f"d{day}: falta la descarga del PDF")
        if not any(("sha256sum " + DOWN + "/manual_empleado.pdf") in c for c in cmds):
            fallos.append(f"d{day}: falta la huella de la descarga")

    # (f) calendario / bloques.env
    cal_path = os.path.join(outdir, "calendario.json")
    env_path = os.path.join(outdir, "bloques.env")
    cal = None
    if not os.path.isfile(cal_path):
        fallos.append("falta calendario.json")
    else:
        cal = json.load(open(cal_path, encoding="utf-8"))
        if cal.get("receta_version") != VERSION_RECETA:
            fallos.append(f"calendario.json: receta_version {cal.get('receta_version')} != {VERSION_RECETA}")
        if cal.get("cuentas") != {str(k): v for k, v in CUENTAS.items()}:
            fallos.append("calendario.json: cuentas distintas de las del generador")
        if cal.get("total_ventana") != sum(sum(v.values()) for v in CUENTAS.values()):
            fallos.append("calendario.json: total de la ventana incorrecto")
        if cal.get("hueco_max_intra_bloque_s") != CAP_HUECO_S:
            fallos.append(f"calendario.json: hueco_max_intra_bloque_s != {CAP_HUECO_S}")
        camp_cal = cal.get("campana") or {}
        camp_acc = campana.cuentas_campana()
        if camp_cal.get("casos") != len(campana.IDS):
            fallos.append("calendario.json: campana.casos incorrecto")
        if camp_cal.get("acciones") != {f"d{k}": v for k, v in camp_acc.items()}:
            fallos.append("calendario.json: campana.acciones no coincide con el CSV")
        if camp_cal.get("inicios") != {f"d{k}": v for k, v in campana.INICIOS_PLAN.items()}:
            fallos.append("calendario.json: campana.inicios incorrecto")
        if camp_cal.get("reparto") != {f"d{k}": v for k, v in campana.REPARTO.items()}:
            fallos.append("calendario.json: campana.reparto incorrecto")
        if camp_cal.get("separacion_min_s") != campana.SEPARACION_MIN_S:
            fallos.append("calendario.json: campana.separacion_min_s incorrecto")
        if camp_cal.get("efectos_declarados") != list(campana.EFECTOS_DECLARADOS):
            fallos.append("calendario.json: campana.efectos_declarados no coincide con la "
                          "estructura del módulo")
        camp_exec = campana.contar_execve()
        if (camp_cal.get("execve") or {}).get("total") != camp_exec["total"]:
            fallos.append("calendario.json: campana.execve.total no coincide con el CSV")
        if (camp_cal.get("execve") or {}).get("por_dia") != {
                f"d{k}": v for k, v in camp_exec["por_dia"].items()}:
            fallos.append("calendario.json: campana.execve.por_dia no coincide con el CSV")
        if os.path.isfile(campana.ruta_md()) and \
                camp_cal.get("sha256_casos_md") != campana.sha256_file(campana.ruta_md()):
            fallos.append("calendario.json: sha256_casos_md no coincide con casos.md")
        if cal.get("total_con_campana") != (sum(sum(v.values()) for v in CUENTAS.values())
                                           + sum(camp_acc.values())):
            fallos.append("calendario.json: total_con_campana incorrecto")
        err = _mapa_valido(cal.get("mapa_dias") or {})
        if err:
            fallos.append("calendario.json: " + err)
        if mapa_esperado is not None and (cal.get("mapa_dias") or {}) != mapa_esperado:
            fallos.append("calendario.json: mapa_dias no coincide con el que se pasa por parámetro")
        if not cal.get("mapa_dias") and mapa_esperado is None:
            avisos.append("sin fecha: mapa_dias vacío (se fija al cerrar T4 con --t0)")
    if not os.path.isfile(env_path):
        fallos.append("falta bloques.env")
    else:
        env = {}
        for linea in open(env_path, encoding="utf-8"):
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            k, v = linea.split("=", 1)
            env[k.strip()] = v.strip()
        if env.get("TFG_RECETA_VERSION") != str(VERSION_RECETA):
            fallos.append(f"bloques.env: TFG_RECETA_VERSION != {VERSION_RECETA}")
        if env.get("TFG_JORNADA") != f"{JORNADA[0]}-{JORNADA[1]}":
            fallos.append("bloques.env: TFG_JORNADA incorrecta")
        for b in BLOQUES:
            if env.get(b["id"]) != f"{b['on'][:5]}-{b['off'][:5]} {b['tipo']}":
                fallos.append(f"bloques.env: línea {b['id']} incorrecta")
        if env.get("TFG_CWD_BASE") != HOME:
            fallos.append("bloques.env: TFG_CWD_BASE incorrecto")
        mapa_env = {}
        if env.get("TFG_MAPA_DIAS"):
            try:
                for par in env["TFG_MAPA_DIAS"].split(","):
                    f, kk = par.split(":")
                    mapa_env[f.strip()] = int(kk)
            except ValueError:
                fallos.append("bloques.env: TFG_MAPA_DIAS con formato inválido")
        if cal is not None and mapa_env != (cal.get("mapa_dias") or {}):
            fallos.append("bloques.env: TFG_MAPA_DIAS no coincide con calendario.json")
        if mapa_esperado is not None and mapa_env != mapa_esperado:
            fallos.append("bloques.env: TFG_MAPA_DIAS no coincide con el parámetro")
        if env.get("B6") != f"{campana.B6['on'][:5]}-{campana.B6['off'][:5]} campana":
            fallos.append("bloques.env: línea B6 incorrecta")
        camp_env = {
            "TFG_CAMPANA_CASOS": str(len(campana.IDS)),
            "TFG_CAMPANA_ACCIONES": str(sum(camp_acc.values())),
            "TFG_CAMPANA_MARCAS": str(2 * len(campana.IDS)),
            "TFG_CAMPANA_INICIOS": ",".join(f"d{k}:{v}" for k, v in campana.INICIOS_PLAN.items()),
            "TFG_CAMPANA_REPARTO": ",".join(f"d{k}:{v}" for k, v in campana.REPARTO.items()),
            "TFG_CAMPANA_SEPARACION_MIN_S": str(campana.SEPARACION_MIN_S),
        }
        for k, v in camp_env.items():
            if env.get(k) != v:
                fallos.append(f"bloques.env: {k} incorrecto ({env.get(k)!r} != {v!r})")

    if not os.path.isfile(os.path.join(outdir, "receta_resumen.md")):
        fallos.append("falta receta_resumen.md")

    # (g) campaña B6 (CA-27): 11 casos no mutantes, 22 marcas, evidencia y pre-registro
    camp_res = campana.validar()
    fallos += [f"campaña: {f}" for f in camp_res["fallos"]]
    avisos += [f"campaña: {a}" for a in camp_res["avisos"]]

    resumen = {
        "version": VERSION_RECETA,
        "dias": {d: sum(CUENTAS[d].values()) for d in (1, 2, 3)},
        "total": sum(sum(v.values()) for v in CUENTAS.values()),
        "binarios_blanco": len(BINARIOS_OK),
        "errores": {d: sum(1 for a in componer_dia(d) if a[1] == "error") for d in (1, 2, 3)},
        "campana": {"casos": camp_res["casos"], "marcas": camp_res["marcas"],
                    "acciones": camp_res["acciones_total"],
                    "binarios": camp_res["binarios"], "ata": camp_res["ata"]},
        "fallos": fallos,
        "avisos": avisos,
    }
    if verbose:
        print(f"receta v{VERSION_RECETA}: dias={resumen['dias']} total={resumen['total']} "
              f"errores={resumen['errores']} binarios_ok={resumen['binarios_blanco']} "
              f"hueco_max={CAP_HUECO_S}s cwd=cd-por-accion handlers_browser=0")
        print(f"campana B6: {resumen['campana']['casos']} casos, "
              f"{resumen['campana']['acciones']} acciones, "
              f"{resumen['campana']['marcas']} marcas, "
              f"{len(resumen['campana']['binarios'])} binarios, "
              f"{len(resumen['campana']['ata'])} ATA")
        for a in avisos:
            print(f"AVISO: {a}")
        for f in fallos:
            print(f"FALLO: {f}")
        print("RESULT=" + ("PASS" if not fallos else "FAIL"))
    return resumen


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def mapa_desde(t0, mapa):
    """Construye el mapeo fecha→día desde `--t0` (3 días consecutivos) o `--mapa-dias`."""
    if mapa:
        out = {}
        for par in mapa.split(","):
            f, kk = par.split(":")
            out[f.strip()] = int(kk)
        return out
    if t0:
        d0 = datetime.strptime(t0, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return {(d0 + timedelta(days=i)).strftime("%Y-%m-%d"): i + 1 for i in range(3)}
    return {}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Genera/valida la receta legítima v2 (3 días).")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--dry", action="store_true", help="timeline comprimida para la prueba en seco")
    ap.add_argument("--base", default="10:00Z", help="hora UTC de inicio del día comprimido (HH:MMZ)")
    ap.add_argument("--out", default=None, help="fichero de salida del modo dry")
    ap.add_argument("--day", type=int, default=1, choices=(1, 2, 3))
    ap.add_argument("--t0", default=None,
                    help="primer día de la ventana (AAAA-MM-DD): deriva el mapa de los 3 días")
    ap.add_argument("--mapa-dias", default=None,
                    help="mapeo explícito fecha:k (p. ej. 2026-11-02:1,2026-11-03:2,2026-11-04:3)")
    args = ap.parse_args(argv)

    raiz = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    outdir = args.out_dir or os.path.join(raiz, "Soporte", "Laboratorio", "legitimo_72h", "recetas")

    try:
        mapa = mapa_desde(args.t0, args.mapa_dias)
    except (ValueError, IndexError):
        ap.error("--t0 debe ser AAAA-MM-DD y --mapa-dias 'fecha:k,...'")
    err = _mapa_valido(mapa)
    if err:
        ap.error(err)

    if args.check:
        res = validar(outdir, mapa_esperado=mapa if mapa else None)
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
    escribir_calendario(outdir, mapa)
    escribir_resumen(outdir, timelines)
    for day in (1, 2, 3):
        p = os.path.join(outdir, f"d{day}.json")
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        tl, _a = timelines[day]
        gaps = [ev["DelayAfter"] / 1000.0 for hh in tl["TimeLineHandlers"]
                for ev in hh["TimeLineEvents"][:-1]]
        print(f"d{day}.json  {sum(CUENTAS[day].values())} acciones de jornada + "
              f"{len(campana.acciones_b6(day))} de B6  "
              f"hueco={min(gaps):.0f}-{max(gaps):.0f}s ({max(gaps)/60:.1f} min)  sha256={h}")
    print(f"mapa_dias={mapa_a_texto(mapa) if mapa else '(vacio: se fija en T4 con --t0)'}")
    res = validar(outdir, mapa_esperado=mapa if mapa else None)
    return 0 if not res["fallos"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
