#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""campana.py — campaña de falsos positivos `B6` (bloque `legitimo-v3`, T2).

La campaña son **11 casos legítimos no mutantes** (C-01…C-12 **sin C-04**) que se
ejecutan **dentro** de la ventana de 72 h, en el bloque declarado **`B6` =
17:05-17:50Z** (plan §3.1, §5.2.6), con **jitter fijo de inicio** (`d1` 17:06,
`d2` 17:17, `d3` 17:11), reparto **3/4/4** y separación **≥ 3 min** entre casos.

**Fuente única de verdad:** `Soporte/Laboratorio/legitimo_72h/campana/campana_casos.csv`
(**una fila por caso**, 11; la lista literal de comandos va en la columna `comandos`,
separada por saltos de línea, y su tipo en `tipos`). Este módulo:

1. **carga** el CSV y comprueba que la estructura es coherente;
2. **valida** los 11 casos con el **mismo** `binarios_de()` / `BINARIOS_OK` del
   generador de la receta (0 `|`, 0 `sudo`, 0 `random`, 0 comillas dobles,
   **0 mutación** fuera de `~/Documentos/campana_fp/`, 22 marcas, evidencia…);
3. **construye** el handler `B6` de `d1/d2/d3.json` (lo consume
   `construir_receta_legitima.py`);
4. **genera** `campana/casos.md` (fichas legibles) y **sella** en la cabecera del
   CSV el `sha256` de `casos.md` (§5.2.6: pre-registro anterior a `t0`).

Uso:
    python _artefactos/scripts/campana.py --docs     # (re)genera casos.md + sella el CSV
    python _artefactos/scripts/campana.py --check    # valida CSV, docs y sha
    python _artefactos/scripts/campana.py --no-mutacion   # salida literal de la auditoría
    python _artefactos/scripts/campana.py --reparto  # imprime el reparto por día y los huecos

`--docs` es **idempotente**: dos ejecuciones dejan los mismos bytes (no hay fecha,
ni orden no determinista). `--check` NO escribe nada.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import re

# --------------------------------------------------------------------------
# Constantes (una sola fuente; el CSV manda sobre comandos y metadatos)
# --------------------------------------------------------------------------
CAMPANA_REL = ("Soporte", "Laboratorio", "legitimo_72h", "campana")
CSV_NAME = "campana_casos.csv"
MD_NAME = "casos.md"

BASE = "/home/angel/Documentos/campana_fp"

#: Bloque declarado de la campaña (NO es jornada de trabajo; plan §3.1 y §3.1.1).
B6 = {
    "id": "B6",
    "on": "17:05:00",
    "off": "17:50:00",
    "tipo": "campana",
    "nombre": "Repaso del sistema",
    "local": "18:05-18:50",
}

#: Jitter fijo de inicio por día (§3.1.1, decisión (c)).
INICIOS_PLAN = {1: "17:06:00", 2: "17:17:00", 3: "17:11:00"}
#: Reparto 3/4/4 (§5.2.6).
REPARTO = {1: 3, 2: 4, 3: 4}
#: Separación mínima entre el fin de un caso y el inicio del siguiente (§5.2.4.3).
SEPARACION_MIN_S = 180
#: Ventana de atribución de alertas: `[ini - 10 s, fin + 60 s]` (§5.2.4.2).
ATRIB_PRE_S = 10
ATRIB_POST_S = 60
#: Cadencia interna de un caso (s): literal, sin `random`.
GAP_INTRA = (5, 8, 6, 10, 7, 9, 5, 8, 7, 9)
#: Regla de `execve` que delata la ejecución (H-A, §5.2.2).
RULE_EXEC = "80792"
#: Umbral de «FP de verdad» y umbral de «se ejecutó» (§5.2.2).
UMBRAL_N7 = 7
UMBRAL_N3 = 3

#: Identificadores pre-registrados (11; C-04 retirada en v4 por no mutación).
IDS = ("C-01", "C-02", "C-03", "C-05", "C-06", "C-07",
       "C-08", "C-09", "C-10", "C-11", "C-12")

#: Columnas del CSV (orden estable). Una fila por **caso** (11); los comandos van en
#: `comandos`, separados por saltos de línea dentro del campo entrecomillado, y su tipo
#: en `tipos`, en el mismo orden (plan §5.2.6: «11 filas … con la lista literal»).
COLS = [
    "caso", "nombre", "dia", "hora_inicio", "muta", "binarios", "ata", "tecnica",
    "rule_ids", "esperado_n7", "esperado_n3", "evidencia", "coste", "por_que",
    "tipos", "comandos",
]
#: Columnas de metadatos (las que no son la lista de acciones).
COLS_META = [c for c in COLS if c not in ("caso", "tipos", "comandos")]

TIPOS = ("inicio", "comando", "evidencia", "fin")

#: Binarios que solo aparecen en la campaña (lectura); el generador los añade a su
#: lista blanca para validar la campaña, nunca para la receta (§5.2.1.5).
BINARIOS_SOLO_CAMPANA = {"systemctl", "crontab"}

#: Escrituras de `systemctl` prohibidas (la campaña solo lee).
SYSTEMCTL_ESCRITURA = {
    "start", "stop", "restart", "reload", "try-restart", "reload-or-restart",
    "force-reload", "enable", "disable", "reenable", "preset", "preset-all",
    "mask", "unmask", "isolate", "kill", "clean", "freeze", "thaw",
    "set-property", "set-environment", "unset-environment", "daemon-reload",
    "daemon-reexec", "edit", "link", "revert", "reset-failed", "switch-root",
    "import-environment", "default", "rescue", "emergency", "halt", "poweroff",
    "reboot", "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate",
    "kexec", "add-wants", "add-requires",
}
#: Instaladores / gestores de paquetes prohibidos.
INSTALADORES = ("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "snap", "pip", "pip3")
#: Cuentas de usuario / credenciales prohibidas.
CUENTAS = {"useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd",
           "chpasswd", "chsh", "chfn", "su", "newgrp"}
#: Efectos laterales **declarados**: lo único que la campaña produce fuera de
#: `~/Documentos/campana_fp/`. La clave es el nombre del efecto; `verbos` son los
#: binarios que lo producen (se validan contra la lista blanca) y `descripcion` es
#: lo que se publica en `casos.md` y `calendario.json`.
EFECTOS_DECLARADOS = {
    "logger": {
        "descripcion": "una línea en el journal del sistema (C-11); no se borra "
                       "(borrarla sería otra mutación)",
        "verbos": ("logger",),
    },
    "descargas_http": {
        "descripcion": "cuatro peticiones HTTP a la intranet local (C-09: dos a `:8080` y un "
                       "intento a `:8081`; C-12: una a `:8080`); las **tres** que llegan al "
                       "8080 dejan rastro en el `web_access.log` del **servidor**, fuera de "
                       "la víctima",
        "verbos": ("curl", "wget"),
    },
}
#: Binarios conocidos por producir un efecto **fuera** de la carpeta del caso. Si uno
#: aparece en un comando y no está declarado en `EFECTOS_DECLARADOS`, es un fallo.
PRODUCTORES_EFECTO_EXTERNO = {"logger", "curl", "wget", "mail", "sendmail", "ssh",
                              "scp", "sftp", "nc", "nc.openbsd", "ncat", "socat",
                              "ftp", "tftp"}
#: Builtins del shell: NO generan `execve` (se excluyen del recuento declarado).
BUILTINS_SIN_EXECVE = {"cd", "echo", "printf", "true", ":", "["}
#: Hijos que un `execve` lanza por diseño en la campaña (se declaran aparte):
#: `xargs` ⇒ 1 `cp` por línea de su fichero (12) y `timeout` ⇒ 1 hijo (1 `curl`).
HIJOS_POR_ACCION = {"xargs": "cp", "timeout": "curl"}
#: Binarios de apoyo de la evidencia/limpieza: pueden aparecer sin declararse en
#: la columna `binarios` (no son el mecanismo que se mide).
AYUDAS = {"echo", "printf", "cat", "wc", "grep", "head", "tail", "stat", "ls",
          "du", "rm", "date", "mkdir", "true", "sha256sum"}

# H-1 (T3): se proh?be CUALQUIER `|`; la API parte por `|` y pierde la acci?n.
RE_PIPE = re.compile(r"\|")
RE_ATA = re.compile(r"^ATA\d{3}$")
RE_TEC = re.compile(r"^T\d{4}(?:\.\d{3})?$")
RE_HORA = re.compile(r"^\d{2}:\d{2}:\d{2}$")


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def raiz_repo(raiz=None) -> str:
    if raiz:
        return os.path.abspath(raiz)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def dir_campana(raiz=None) -> str:
    return os.path.join(raiz_repo(raiz), *CAMPANA_REL)


def ruta_csv(raiz=None) -> str:
    return os.path.join(dir_campana(raiz), CSV_NAME)


def ruta_md(raiz=None) -> str:
    return os.path.join(dir_campana(raiz), MD_NAME)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hms_to_s(h: str) -> int:
    hh, mm, ss = (int(x) for x in h.split(":"))
    return hh * 3600 + mm * 60 + ss


def s_to_hms(s: int) -> str:
    s %= 24 * 3600
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _binarios_de(cmd: str):
    """`binarios_de` del generador (import perezoso: evita el ciclo de imports)."""
    import construir_receta_legitima as rec
    return rec.binarios_de(cmd)


def _binarios_ok():
    import construir_receta_legitima as rec
    return set(getattr(rec, "BINARIOS_CAMPANA",
                       set(rec.BINARIOS_OK) | BINARIOS_SOLO_CAMPANA))


def _cwd_ok():
    import construir_receta_legitima as rec
    return set(rec.DIRS_CWD)


# --------------------------------------------------------------------------
# Lectura del CSV (fuente única)
# --------------------------------------------------------------------------
def leer_cabecera(path: str):
    """Devuelve las líneas `#` iniciales."""
    comentarios = []
    with open(path, encoding="utf-8", newline="") as fh:
        for linea in fh:
            if linea.startswith("#"):
                comentarios.append(linea.rstrip("\n"))
            else:
                break
    return comentarios


def _filas_csv(path: str):
    """Filas del CSV, ignorando **solo** las líneas `#` iniciales (no las de dentro)."""
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = fh.readlines()
    i = 0
    while i < len(lineas) and lineas[i].startswith("#"):
        i += 1
    return list(csv.DictReader(io.StringIO("".join(lineas[i:]))))


def cargar(raiz=None):
    """Carga el CSV y devuelve `casos` (dict ordenado) + `filas` (una por caso).

    `casos[caso] = {"meta": {...}, "acciones": [ {...}, … ]}`. Las acciones se expanden
    del campo `comandos` (una por línea) y su `tipo` sale de `tipos` (mismo orden).
    """
    path = ruta_csv(raiz)
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: falta {path}")
    rd = _filas_csv(path)
    if rd and rd[0].keys() != set(COLS):
        raise SystemExit(f"ERROR: cabecera del CSV distinta de la esperada.\n"
                         f"  esperada: {COLS}\n  leída:    {list(rd[0].keys())}")
    filas = [dict(r) for r in rd]
    casos = {}
    for r in filas:
        cid = (r["caso"] or "").strip()
        if not cid:
            raise SystemExit("ERROR: fila sin `caso`")
        if cid in casos:
            raise SystemExit(f"ERROR: caso duplicado en el CSV: {cid}")
        tipos = [t.strip() for t in (r["tipos"] or "").split("\n") if t.strip()]
        cmds = (r["comandos"] or "").split("\n")
        if len(tipos) != len(cmds):
            raise SystemExit(f"ERROR: {cid}: {len(tipos)} tipos != {len(cmds)} comandos")
        casos[cid] = {
            "meta": {k: (r[k] or "").strip() for k in COLS_META},
            "acciones": [{"orden": i + 1, "tipo": t, "comando": c}
                         for i, (t, c) in enumerate(zip(tipos, cmds))],
        }
    return casos, filas


# --------------------------------------------------------------------------
# Construcción de B6 (tiempos absolutos y handler GHOSTS)
# --------------------------------------------------------------------------
def acciones_b6(dia: int, raiz=None):
    """Acciones del bloque B6 de un día, con su hora absoluta (s desde medianoche UTC).

    Devuelve `[{"caso", "orden", "tipo", "comando", "t", "hora"}, …]` en orden.
    El primer evento de cada caso cae **exactamente** en su `hora_inicio` (CSV);
    los siguientes, con la cadencia literal `GAP_INTRA` (sin `random`).
    """
    casos, _ = cargar(raiz)
    seleccion = [c for c in casos if str(casos[c]["meta"]["dia"]) == str(dia)]
    seleccion.sort(key=lambda c: casos[c]["meta"]["hora_inicio"])
    out = []
    for idx, cid in enumerate(seleccion):
        acciones = sorted(casos[cid]["acciones"], key=lambda a: a["orden"])
        t = hms_to_s(casos[cid]["meta"]["hora_inicio"])
        for k, a in enumerate(acciones):
            if k:
                t += GAP_INTRA[(idx * 3 + k) % len(GAP_INTRA)]
            out.append({"caso": cid, "orden": a["orden"], "tipo": a["tipo"],
                        "comando": a["comando"], "t": t, "hora": s_to_hms(t)})
    return out


def handler_b6(dia: int, raiz=None):
    """Handler `Command` de GHOSTS para el bloque B6 del día (una ejecución diaria).

    `UtcTimeOn` es la hora del **primer caso** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11):
    el bloque declarado empieza a las 17:05, pero GHOSTS no ejecuta nada hasta la
    primera acción. `UtcTimeOff` = 17:50 (fin del bloque).
    """
    import construir_receta_legitima as rec
    accs = acciones_b6(dia, raiz)
    if not accs:
        raise SystemExit(f"ERROR: B6 del día {dia} sin acciones")
    on, off = accs[0]["t"], hms_to_s(B6["off"])
    eventos = []
    for i, a in enumerate(accs):
        if i + 1 < len(accs):
            dl = accs[i + 1]["t"] - a["t"]
        else:
            # Guardián de fin de bloque: se duerme 1 min más allá de UtcTimeOff; el
            # handler, al volver, se encuentra fuera de ventana y espera al día siguiente.
            dl = off + rec.GUARDIAN_S - a["t"]
        eventos.append({"Command": a["comando"], "DelayAfter": int(dl) * 1000})
    return {
        "HandlerType": "Command",
        "Initial": "",
        "UtcTimeOn": s_to_hms(on),
        "UtcTimeOff": B6["off"],
        "Loop": True,
        "HandlerArgs": {},
        "TimeLineEvents": eventos,
    }


def cuentas_campana(raiz=None):
    """{día: nº de acciones de B6}."""
    return {d: len(acciones_b6(d, raiz)) for d in (1, 2, 3)}


# --------------------------------------------------------------------------
# Validación estática (comandos) — CA-27
# --------------------------------------------------------------------------
def _sin_comillas(cmd: str) -> str:
    return re.sub(r"'[^']*'", "''", cmd)


def rutas_absolutas(cmd: str):
    s = re.sub(r"https?://\S+", "", _sin_comillas(cmd))
    return re.findall(r"(?<![\w.])(/[A-Za-z0-9_./$(){}-]+)", s)


def _segmentos(cmd: str):
    """Segmentos del comando (tras quitar el prefijo `cd <dir> && `)."""
    c = _sin_comillas(cmd.strip())
    m = re.match(r"^cd\s+(/\S+)\s+&&\s+", c)
    if m:
        c = c[m.end():]
    out = []
    for seg in re.split(r"\s*(?:&&|\|\||;)\s*", c):
        seg = seg.strip().strip("{}").strip()
        if seg:
            out.append(seg)
    return out


def _tokens(seg: str):
    """Tokens de un segmento hasta la primera redirección (`>`, `>>`, `<`)."""
    out = []
    for t in seg.split():
        if ">" in t or "<" in t:
            break
        out.append(t)
    return out


def destinos_escritura(cmd: str):
    """`[(verbo, destino)]` de los destinos de escritura del comando.

    No pretende ser un intérprete de shell: cubre **las formas que usa la campaña**
    (redirecciones, `-o`/`-O`/`-out`, `tee`, `rm`, `mkdir`, `shred`, `sed -i`, `cp`).
    Lo que no esté aquí lo cubre la regla «toda ruta absoluta vive bajo `campana_fp`».
    """
    out = []
    s = _sin_comillas(cmd)
    for m in re.finditer(r">>?\s*([^\s;&|]+)", s):
        t = m.group(1)
        if not t.startswith("&"):
            out.append(("redireccion", t))
    for seg in _segmentos(cmd):
        tok = _tokens(seg)
        if not tok:
            continue
        prog, args = tok[0], tok[1:]
        def _no_flags(xs):
            return [a for a in xs if not a.startswith("-")]
        if prog == "rm" or prog == "mkdir":
            out += [(prog, a) for a in _no_flags(args)]
        elif prog == "shred":
            out += [(prog, a) for a in _no_flags(args)]
        elif prog == "tee":
            out += [("tee", a) for a in _no_flags(args)]
        elif prog == "sed" and any(a.startswith("-i") for a in args):
            out.append(("sed -i", args[-1]))
        elif prog == "cp" and len(args) >= 2:
            out.append(("cp", args[-1]))
        elif prog == "xargs":
            if "cp" in args:
                i = args.index("cp")
                if args[i + 1:]:
                    out.append(("xargs cp", args[-1]))
        elif prog in ("curl", "openssl", "wget"):
            for flag in ("-o", "-out", "-O"):
                if flag in args:
                    i = args.index(flag)
                    if i + 1 < len(args):
                        out.append((f"{prog} {flag}", args[i + 1]))
    return out


def _destino_ok(dest: str) -> bool:
    d = dest.strip()
    if d in ("/dev/null", "/dev/stdout", "/dev/stderr"):
        return True
    if d.startswith("&"):
        return True
    if d.startswith(BASE + "/") or d == BASE:
        return True
    # Ruta relativa: se resuelve bajo el `cwd`, que es una carpeta de la campaña.
    return not d.startswith("/") and ".." not in d.split("/")


def verbo_efecto(declarados=None):
    """{binario: efecto} de la estructura de efectos declarados."""
    decl = EFECTOS_DECLARADOS if declarados is None else declarados
    out = {}
    for nombre, e in decl.items():
        for v in e["verbos"]:
            out[v] = nombre
    return out


def validar_comando(cmd: str, binarios_ok=None, declarados=None):
    """Fallos de un comando suelto (mismas reglas que la receta + no mutación).

    Incluye la comprobación de **efectos externos**: si el comando usa un binario
    que produce un efecto fuera de la carpeta del caso (`logger`, `curl`, `wget`…) y
    ese efecto no está en la estructura declarada, es un fallo. Nada de tautologías.
    """
    fallos = []
    ok = binarios_ok or _binarios_ok()
    decl_verbo = verbo_efecto(declarados)
    if not isinstance(cmd, str) or not cmd.strip():
        return ["comando vacío"]
    if '"' in cmd:
        fallos.append(f"comillas dobles: {cmd[:70]}")
    # H-1 (T3): ningún `|` (ni simple ni `||`): la API parte la línea por `|`.
    if "|" in cmd:
        fallos.append(f"'|' (GHOSTS pierde el reporte): {cmd[:70]}")
    if re.search(r"(?:^|\s)sudo(?:\s|$)", cmd):
        fallos.append(f"sudo prohibido: {cmd[:70]}")
    if re.search(r"(?:^|[\s;&|])random(?:$|[\s;&|])", cmd):
        fallos.append(f"random prohibido: {cmd[:70]}")
    if "echo -e" in cmd:
        fallos.append(f"echo -e prohibido (F-1): {cmd[:70]}")
    if "\\t" in _sin_comillas(cmd):
        fallos.append(f"\\t sin comillas simples (F-1): {cmd[:70]}")

    m = re.match(r"^cd\s+(/\S+)\s+&&\s+\S", cmd)
    if not m:
        fallos.append(f"sin prefijo `cd <carpeta> && `: {cmd[:70]}")
    else:
        d = m.group(1)
        if not (d == BASE or d.startswith(BASE + "/") or d in _cwd_ok()):
            fallos.append(f"cwd fuera de la campaña: {d}")

    for tok in _binarios_de(cmd):
        if tok not in ok:
            fallos.append(f"binario no permitido '{tok}': {cmd[:70]}")
        if tok in PRODUCTORES_EFECTO_EXTERNO and tok not in decl_verbo:
            fallos.append(f"efecto externo NO declarado por '{tok}': {cmd[:70]}")

    for ruta in rutas_absolutas(cmd):
        if ruta in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            continue
        if not (ruta == BASE or ruta.startswith(BASE + "/")):
            fallos.append(f"ruta absoluta fuera de campana_fp: {ruta}")

    for _verbo, dest in destinos_escritura(cmd):
        if not _destino_ok(dest):
            fallos.append(f"escritura fuera de campana_fp: {dest}")

    # --- verbos que mutan el sistema (0 en toda la campaña) ---
    for seg in _segmentos(cmd):
        tok = _tokens(seg)
        if not tok:
            continue
        prog, args = tok[0], tok[1:]
        if prog == "crontab" and args != ["-l"]:
            fallos.append(f"crontab de escritura/otro uso: {seg[:70]}")
        if prog == "systemctl":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in SYSTEMCTL_ESCRITURA:
                fallos.append(f"systemctl de escritura '{sub}': {seg[:70]}")
        if prog in INSTALADORES:
            fallos.append(f"instalación prohibida '{prog}': {seg[:70]}")
        if prog in CUENTAS:
            fallos.append(f"cuentas/credenciales prohibidas '{prog}': {seg[:70]}")
    return fallos


def validar_efectos(raiz=None, declarados=None):
    """Valida la **estructura** de efectos declarados y su uso real.

    1. Cada efecto tiene `descripcion` no vacía y `verbos` no vacíos.
    2. Cada verbo existe en la lista blanca y no está repetido en dos efectos.
    3. Todo efecto declarado se usa al menos una vez en la campaña (no hay
       declaraciones muertas).
    4. Todo productor de efecto externo que aparece en la campaña está declarado.
    """
    decl = EFECTOS_DECLARADOS if declarados is None else declarados
    fallos = []
    if not isinstance(decl, dict) or not decl:
        return ["EFECTOS_DECLARADOS vacío o mal formado"]
    ok = _binarios_ok()
    vistos = {}
    for nombre, e in decl.items():
        if not isinstance(e, dict):
            fallos.append(f"efecto '{nombre}': la entrada no es un dict")
            continue
        if not (e.get("descripcion") or "").strip():
            fallos.append(f"efecto '{nombre}': sin descripción")
        verbos = tuple(e.get("verbos") or ())
        if not verbos:
            fallos.append(f"efecto '{nombre}': sin verbos")
        for v in verbos:
            if v not in ok:
                fallos.append(f"efecto '{nombre}': verbo '{v}' fuera de la lista blanca")
            if v in vistos:
                fallos.append(f"verbo '{v}' declarado en '{vistos[v]}' y en '{nombre}'")
            vistos[v] = nombre

    casos, _ = cargar(raiz)
    usados = set()
    for c in casos.values():
        for a in c["acciones"]:
            usados.update(_binarios_de(a["comando"]))
    for nombre, e in decl.items():
        if not (set(e.get("verbos") or ()) & usados):
            fallos.append(f"efecto '{nombre}' declarado pero no se usa en la campaña")
    for tok in sorted(usados & PRODUCTORES_EFECTO_EXTERNO):
        if tok not in vistos:
            fallos.append(f"'{tok}' produce un efecto externo y no está declarado")
    return fallos


# --------------------------------------------------------------------------
# Validación completa (CA-27)
# --------------------------------------------------------------------------
def validar(raiz=None, comprobar_docs=True):
    """Valida los 11 casos. Devuelve `{"fallos", "avisos", "resumen"}`."""
    fallos, avisos = [], []
    casos, filas = cargar(raiz)

    # --- (a) composición ---
    ids = tuple(casos)
    if ids != IDS:
        fallos.append(f"casos {ids} != {IDS}")
    if "C-04" in casos:
        fallos.append("C-04 no debe existir (retirada en v4: no mutación)")
    if len(filas) != len(casos):
        fallos.append("el CSV tiene filas duplicadas o inconsistentes")

    total_marcas = 0
    for dia in (1, 2, 3):
        del_dia = [c for c in casos if casos[c]["meta"]["dia"] == str(dia)]
        if len(del_dia) != REPARTO[dia]:
            fallos.append(f"d{dia}: {len(del_dia)} casos != {REPARTO[dia]}")
        if del_dia:
            primera = casos[del_dia[0]]["meta"]["hora_inicio"]
            if primera != INICIOS_PLAN[dia]:
                fallos.append(f"d{dia}: primer inicio {primera} != {INICIOS_PLAN[dia]}")

    for cid in casos:
        c = casos[cid]
        meta, accs = c["meta"], sorted(c["acciones"], key=lambda a: a["orden"])
        # --- (b) estructura de acciones ---
        ordenes = [a["orden"] for a in accs]
        if ordenes != list(range(1, len(accs) + 1)):
            fallos.append(f"{cid}: `orden` no es 1..n ({ordenes})")
        tipos = [a["tipo"] for a in accs]
        if tipos[0] != "inicio" or tipos[-1] != "fin":
            fallos.append(f"{cid}: el caso debe abrir con `inicio` y cerrar con `fin`")
        if tipos.count("inicio") != 1 or tipos.count("fin") != 1:
            fallos.append(f"{cid}: marcas inicio/fin repetidas")
        if "evidencia" not in tipos:
            fallos.append(f"{cid}: sin acción de evidencia")
        if "comando" not in tipos:
            fallos.append(f"{cid}: sin comandos propios")
        if tipos.index("fin") < max(i for i, t in enumerate(tipos) if t == "evidencia"):
            fallos.append(f"{cid}: `fin` anterior a la evidencia")
        for t in tipos:
            if t not in TIPOS:
                fallos.append(f"{cid}: tipo desconocido '{t}'")
        total_marcas += tipos.count("inicio") + tipos.count("fin")

        # --- (c) marcas UTC con la forma exacta ---
        ini = accs[0]["comando"]
        fin = accs[-1]["comando"]
        carpeta = f"{BASE}/{cid}"
        if "mkdir -p" not in ini or f"date -u +%FT%TZ > {carpeta}/inicio.txt" not in ini:
            fallos.append(f"{cid}: la marca de inicio no crea la carpeta y sella inicio.txt")
        if f"date -u +%FT%TZ > {carpeta}/fin.txt" not in fin:
            fallos.append(f"{cid}: la marca de fin no sella fin.txt")
        if not RE_HORA.match(meta["hora_inicio"]):
            fallos.append(f"{cid}: hora mal formada ({meta['hora_inicio']!r})")

        # --- (d) metadatos obligatorios ---
        if meta.get("muta") != "No":
            fallos.append(f"{cid}: `muta` debe ser No (campaña no mutante)")
        if meta.get("esperado_n7") != "0":
            fallos.append(f"{cid}: el esperado N>=7 pre-registrado debe ser 0")
        if RULE_EXEC not in meta.get("esperado_n3", ""):
            fallos.append(f"{cid}: el esperado N>=3 debe citar {RULE_EXEC}")
        if RULE_EXEC not in meta.get("rule_ids", ""):
            fallos.append(f"{cid}: `rule_ids` debe incluir {RULE_EXEC}")
        atas = [x for x in meta.get("ata", "").split(";") if x]
        tecs = [x for x in meta.get("tecnica", "").split(";") if x]
        if not atas or not all(RE_ATA.match(a) for a in atas):
            fallos.append(f"{cid}: `ata` mal formado: {meta.get('ata')!r}")
        if len(atas) != len(tecs) or not all(RE_TEC.match(t) for t in tecs):
            fallos.append(f"{cid}: `tecnica` no casa 1:1 con `ata`: {meta.get('tecnica')!r}")
        if not meta.get("evidencia"):
            fallos.append(f"{cid}: sin evidencia de efecto declarada")
        if not meta.get("coste"):
            fallos.append(f"{cid}: sin coste declarado")
        if not meta.get("por_que"):
            fallos.append(f"{cid}: sin justificación (`por_que`)")

        # --- (e) comandos: reglas duras y no mutación ---
        usados = set()
        for a in accs:
            fallos += [f"{cid}: {f}" for f in validar_comando(a["comando"])]
            usados.update(_binarios_de(a["comando"]))
            if a["tipo"] == "evidencia":
                if f"{carpeta}/hecho.txt" not in a["comando"]:
                    fallos.append(f"{cid}: la evidencia no escribe hecho.txt")
                if "RESULTADO=OK" not in a["comando"]:
                    fallos.append(f"{cid}: la evidencia no sella RESULTADO=OK")
        declarados = [x for x in meta.get("binarios", "").split(";") if x]
        texto = " ".join(a["comando"] for a in accs)
        sobran = sorted(usados - set(declarados) - AYUDAS)
        if sobran:
            fallos.append(f"{cid}: binarios sin declarar en `binarios`: {sobran}")
        faltan = [b for b in declarados if b not in usados
                  and not re.search(rf"(?<![\w./-]){re.escape(b)}(?![\w./-])", texto)]
        if faltan:
            fallos.append(f"{cid}: declarados y no usados: {faltan}")

        # --- (f) duplicado exacto de comando dentro del caso ---
        vistos = set()
        for a in accs:
            if a["comando"] in vistos:
                fallos.append(f"{cid}: comando repetido literalmente: {a['comando'][:60]}")
            vistos.add(a["comando"])

    if total_marcas != 22:
        fallos.append(f"marcas inicio+fin = {total_marcas} (se exigen 22)")

    # --- (g) tiempos: ventana, jitter, separación y ventanas de atribución ---
    for dia in (1, 2, 3):
        accs = acciones_b6(dia, raiz)
        if not accs:
            fallos.append(f"d{dia}: B6 sin acciones")
            continue
        on, off = hms_to_s(B6["on"]), hms_to_s(B6["off"])
        for a in accs:
            if not (on <= a["t"] < off):
                fallos.append(f"d{dia}: {a['caso']} fuera de B6 ({a['hora']})")
        fin = {}
        ini = {}
        for a in accs:
            if a["tipo"] == "inicio":
                ini[a["caso"]] = a["t"]
            if a["tipo"] == "fin":
                fin[a["caso"]] = a["t"]
        orden = [c for c in casos if casos[c]["meta"]["dia"] == str(dia)]
        orden.sort(key=lambda c: ini[c])
        for prev, nxt in zip(orden, orden[1:]):
            if ini[nxt] - fin[prev] < SEPARACION_MIN_S:
                fallos.append(f"d{dia}: separación {ini[nxt] - fin[prev]} s entre {prev} y "
                              f"{nxt} (< {SEPARACION_MIN_S} s)")
            if ini[nxt] - ATRIB_PRE_S <= fin[prev] + ATRIB_POST_S:
                fallos.append(f"d{dia}: ventanas de atribución solapadas {prev}/{nxt}")
        if fin[orden[-1]] > off:
            fallos.append(f"d{dia}: el último fin ({s_to_hms(fin[orden[-1]])}) pasa de "
                          f"{B6['off']}")
        if max(ini.values()) >= off:
            fallos.append(f"d{dia}: algún inicio cae después del cierre de B6")

    # --- (h) pre-registro: sha256 de casos.md en la cabecera del CSV ---
    # --- (i) efectos externos declarados (estructura + uso real, O-5) ---
    fallos += validar_efectos(raiz)

    if comprobar_docs:
        md = ruta_md(raiz)
        if not os.path.isfile(md):
            fallos.append("falta casos.md (genera con `campana.py --docs`)")
        else:
            cab = leer_cabecera(ruta_csv(raiz))
            esperado = sha256_file(md)
            m = next((re.search(r"sha256_casos_md=([0-9a-f]{64})", c) for c in cab
                      if "sha256_casos_md" in c), None)
            if not m:
                fallos.append("la cabecera del CSV no sella sha256_casos_md")
            elif m.group(1) != esperado:
                fallos.append(f"sha256_casos_md de la cabecera ({m.group(1)[:12]}…) no "
                              f"coincide con casos.md ({esperado[:12]}…); ejecuta --docs")
            # el CSV completo debe ser estable (una sola forma de escribirlo)
            try:
                texto = render_csv(casos, sha_md=esperado)
            except Exception as exc:  # pragma: no cover - defensivo
                fallos.append(f"no se pudo re-renderizar el CSV: {exc}")
            else:
                with open(ruta_csv(raiz), encoding="utf-8", newline="") as fh:
                    actual = fh.read()
                if texto != actual:
                    fallos.append("campana_casos.csv no es canónico; ejecuta --docs")
            texto_md = render_md(casos)
            with open(md, encoding="utf-8", newline="") as fh:
                if texto_md != fh.read():
                    fallos.append("casos.md no coincide con el CSV; ejecuta --docs")

    execve = contar_execve(raiz)
    resumen = {
        "casos": len(casos),
        "marcas": total_marcas,
        "acciones": {d: len(acciones_b6(d, raiz)) for d in (1, 2, 3)},
        "acciones_total": sum(len(acciones_b6(d, raiz)) for d in (1, 2, 3)),
        "execve": execve,
        "binarios": sorted({b for c in casos.values() for b in
                            (x for x in c["meta"].get("binarios", "").split(";") if x)}),
        "ata": sorted({a for c in casos.values() for a in
                       (x for x in c["meta"].get("ata", "").split(";") if x)}),
        "fallos": fallos,
        "avisos": avisos,
    }
    return resumen


def validar_timeline(tl, dia: int, raiz=None):
    """Comprueba que el handler B6 de `d{dia}.json` es el que dicta el CSV."""
    fallos = []
    hs = tl.get("TimeLineHandlers", [])
    esp = acciones_b6(dia, raiz)
    if not esp:
        return [f"d{dia}: el CSV no define acciones para este día"]
    cand = [h for h in hs if h.get("UtcTimeOn") == s_to_hms(esp[0]["t"])
            and h.get("UtcTimeOff") == B6["off"]]
    if len(cand) != 1:
        return [f"d{dia}: se esperaba 1 handler B6 ({s_to_hms(esp[0]['t'])}-{B6['off']}) "
                f"y hay {len(cand)}"]
    h = cand[0]
    if h.get("HandlerType") != "Command":
        fallos.append(f"d{dia}/B6: HandlerType={h.get('HandlerType')}")
    if not h.get("Loop"):
        fallos.append(f"d{dia}/B6: Loop != true")
    if h.get("HandlerArgs"):
        fallos.append(f"d{dia}/B6: HandlerArgs no vacío")
    evs = h.get("TimeLineEvents", [])
    if len(evs) != len(esp):
        fallos.append(f"d{dia}/B6: {len(evs)} eventos != {len(esp)} del CSV")
        return fallos
    on = esp[0]["t"]
    t = 0
    for i, (ev, a) in enumerate(zip(evs, esp)):
        if i:
            t += evs[i - 1]["DelayAfter"] / 1000.0
        if ev["Command"] != a["comando"]:
            fallos.append(f"d{dia}/B6/{a['caso']}: comando {i} no coincide con el CSV")
        if abs(t - (a["t"] - on)) > 0.001:
            fallos.append(f"d{dia}/B6/{a['caso']}: hora {s_to_hms(on + int(t))} != "
                          f"{a['hora']} (CSV)")
    if on + t + evs[-1]["DelayAfter"] / 1000.0 <= hms_to_s(B6["off"]):
        fallos.append(f"d{dia}/B6: el guardián no pasa de UtcTimeOff")
    return fallos


# --------------------------------------------------------------------------
# Render: CSV canónico y `casos.md`
# --------------------------------------------------------------------------
CABECERA_CSV = ("# campana_casos.csv · campana B6 (bloque legitimo-v3, T2) · "
                "{n} casos · {m} marcas · {a} acciones · sha256_casos_md={sha} · "
                "fuente=casos.md · plan=5.2.6")


def _cabecera_comentarios(sha_md: str, casos) -> str:
    acciones = sum(len(c["acciones"]) for c in casos.values())
    marcas = sum(1 for c in casos.values() for a in c["acciones"]
                 if a["tipo"] in ("inicio", "fin"))
    return CABECERA_CSV.format(n=len(casos), m=marcas, a=acciones, sha=sha_md)


def render_csv(casos, sha_md: str) -> str:
    """CSV completo (cabecera `#` + columnas + **una fila por caso**), LF y determinista."""
    buf = io.StringIO()
    buf.write(_cabecera_comentarios(sha_md, casos) + "\n")
    w = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(COLS)
    for cid, c in casos.items():
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        fila = {"caso": cid, **c["meta"],
                "tipos": "\n".join(a["tipo"] for a in accs),
                "comandos": "\n".join(a["comando"] for a in accs)}
        w.writerow([fila.get(c, "") for c in COLS])
    return buf.getvalue()


def _ficha_md(cid, caso) -> list:
    meta = caso["meta"]
    accs = sorted(caso["acciones"], key=lambda a: a["orden"])
    atas = [x for x in meta["ata"].split(";") if x]
    tecs = [x for x in meta["tecnica"].split(";") if x]
    confunde = "; ".join(f"{a} ({t})" for a, t in zip(atas, tecs))
    out = [
        f"### {cid} · {meta['nombre']}",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| Día · hora (UTC) | `d{meta['dia']}` · **{meta['hora_inicio']}** |",
        f"| Binarios | `{'`, `'.join(x for x in meta['binarios'].split(';') if x)}` |",
        f"| Se confunde con | {confunde} |",
        f"| `rule_id` pre-registrados | `{'`, `'.join(x for x in meta['rule_ids'].split(';') if x)}` |",
        f"| **Esperado `N ≥ 7`** | **{meta['esperado_n7']} alertas** (ningún FP «de verdad») |",
        f"| **Esperado `N ≥ 3`** | **{meta['esperado_n3']}** (todo `execve` alerta: H-A) |",
        f"| ¿Cambia la máquina? | **{meta['muta']}** (solo escribe bajo `{BASE}/{cid}/`) |",
        f"| Evidencia de efecto | {meta['evidencia']} |",
        f"| Coste · disco | {meta['coste']} |",
        f"| Por qué es legítimo | {meta['por_que']} |",
        "",
        "**Comandos literales** (en este orden; las marcas van **primero** y **última**):",
        "",
    ]
    for a in accs:
        out.append(f"{a['orden']}. `{a['tipo']}` — `{a['comando']}`")
    out += ["", "**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de "
            "la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, "
            "no un 0-alerta.", ""]
    return out


def render_md(casos) -> str:
    """`casos.md` completo (determinista, a partir del CSV)."""
    total = sum(len(c["acciones"]) for c in casos.values())
    ex = contar_execve()
    hijos_txt = ", ".join(f"`{k}` ×{v}" for k, v in ex["hijos"].items() if v)
    lineas = [
        "# `casos.md` — campaña de falsos positivos (`B6`, 11 casos)",
        "",
        "> **Pre-registro firmado antes de `t0`** (plan §5.2.6, §10). Este fichero se **genera**",
        "> desde `campana_casos.csv` (fuente única: comandos literales y metadatos); su",
        "> `sha256` se **sella en la cabecera del CSV**. No se edita a mano.",
        "> Bloque **`B6` «repaso del sistema» = 17:05–17:50Z** (18:05–18:50 local), **11 casos**",
        "> en **3/4/4** días, inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11) y",
        "> separación **≥ 3 min** entre casos. Atribución: `timestamp ∈ [ini − 10 s, fin + 60 s]`.",
        f"> **{total} acciones GHOSTS** (22 de ellas son las marcas `inicio`/`fin`).",
        "",
        "## Qué mide y por qué está dentro de la ventana",
        "",
        "La campaña **no** fabrica ataques: hace **11 tareas de oficina corrientes** que un",
        "empleado ejecutaría en el mismo portátil, con las **mismas herramientas** que el corpus",
        "usa en sus ataques. Se ejecuta **dentro** de `[t0, t1]`, en un bloque **declarado**,",
        "y se publica **aparte** (`campana_fp.csv`), sin recalcular `M` ni un FPR alternativo.",
        "",
        "**No mutante** (definición operativa, §5.2.1.4): todo lo que se crea vive bajo",
        f"`{BASE}/C-XX/` y **se borra dentro del propio caso**; no se toca `crontab`, `/etc`,",
        "servicios, unidades, repositorios, credenciales ni rutas del sistema.",
        "",
        "**Efectos declarados fuera de la carpeta** (son los **dos únicos**; los sella",
        "`calendario.json` → `campana.efectos_declarados`):",
        "",
    ]
    for nombre, e in EFECTOS_DECLARADOS.items():
        lineas.append(f"- **`{nombre}`** — {e['descripcion']}.")
    lineas += ["",
        "## Resumen (11 casos · `N ≥ 7` = 0 en todos)",
        "",
        "| # | Caso | Día | Hora (UTC) | Binarios | Se confunde con | `N ≥ 7` | `N ≥ 3` | ¿Muta? | Coste |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for cid in casos:
        c = casos[cid]
        meta = c["meta"]
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        atas = [x for x in meta["ata"].split(";") if x]
        tecs = [x for x in meta["tecnica"].split(";") if x]
        confunde = ", ".join(f"{a} {t}" for a, t in zip(atas, tecs))
        bins = ", ".join(f"`{x}`" for x in meta["binarios"].split(";") if x)
        n3 = meta["esperado_n3"].replace(";", ",")
        lineas.append(f"| **{cid}** | {meta['nombre']} | d{meta['dia']} | "
                      f"**{meta['hora_inicio']}** | {bins} | {confunde} | "
                      f"**{meta['esperado_n7']}** | {n3} | **{meta['muta']}** | {meta['coste']} |")
    lineas += [
        "",
        "> **Cómo leer los umbrales.** `N ≥ 7` decide si el caso es un FP «de verdad»",
        "> (`P2` o superior); `N ≥ 3` es donde **todo** `execve` alerta por `80792` (hipótesis",
        "> H-A). Se pre-registran los dos. **No** se promete el número exacto de filas (el corpus",
        "> muestra 1–3 por `execve`); lo falsable es el **conjunto de `rule_id`** y el `level`.",
        "> Si un caso alerta a `N ≥ 7`, **es un hallazgo** y se publica; no se re-ejecuta.",
        "> Si un caso **no** alerta ni a `N ≥ 3`, el `80792` no llegó: **no se ejecutó**.",
        "",
        "## Fichas",
        "",
    ]
    for cid in casos:
        lineas += _ficha_md(cid, casos[cid])
    lineas += [
        "## Orden, marcas y atribución",
        "",
        "- **Por caso (rígido):** `inicio.txt` → preparación y comandos → **evidencia** "
        "(`hecho.txt`) → limpieza → `fin.txt`. Nada del caso se ejecuta después de `fin`.",
        "- **Marcas:** `date -u +%FT%TZ > …/inicio.txt` y `…/fin.txt`; **11 × 2 = 22** marcas "
        "(22 `execve` de `date`). La acción de inicio crea además la carpeta (`mkdir -p`, "
        "11 `execve` más, declarados).",
        "- **Atribución:** alerta del agente `001` (`victima-linux`) con `timestamp ∈ "
        "[ini − 10 s, fin + 60 s]`. Se cuenta **todo** lo que caiga dentro (incluido el "
        "keepalive, declarado) y se distingue `audit_exe`/`rule_id` esperados.",
        "- **Evidencia de efecto (obligatoria):** cada caso termina dejando `hecho.txt` con "
        "`RESULTADO=OK` y el predicado de su ficha. Sin `hecho.txt` el caso es "
        "`NO_EJECUTADO`, no un 0-alerta.",
        "- **Limpieza:** los temporales del caso se borran **antes** de `fin.txt` (van en la "
        "misma acción que la marca de fin); solo sobreviven `inicio.txt`, `hecho.txt` y "
        "`fin.txt`.",
        "",
        "## Volumen declarado (acciones y `execve`)",
        "",
        f"- **Acciones GHOSTS:** **{total}** (**22** son marcas `inicio`/`fin`; las otras "
        f"**{total - 22}** son preparación de insumos, comandos propios, evidencia y limpieza).",
        f"- **`execve` reales (proyección determinista):** **{ex['total']}** "
        f"(d1 **{ex['por_dia'][1]}** · d2 **{ex['por_dia'][2]}** · d3 **{ex['por_dia'][3]}**).",
        f"  Cómo se cuenta: {ex['metodo']}. Los *builtins* del shell (`cd`, `echo`, `printf`, "
        "`true`) **no** generan `execve`.",
        f"- **Hijos declarados:** {hijos_txt}.",
        f"- **Desglose por binario:** `" + "`, `".join(
            f"{k} {v}" for k, v in ex["por_binario"].items()) + "`.",
        "- **B10 lo sella:** esta previsión se compara con lo observado (`nº acciones` y "
        "`nº eventos` de `campana_fp.csv`) y se fija en el sello. **No** es una cifra "
        "copiada de fuera: sale de los comandos literales del CSV.",
        "",
        "## Prerrequisitos en el invitado (T3/E0)",
        "",
        "> **Bloqueante:** `~/Documentos/campana_fp/` debe **existir y ser escribible** por",
        "> `angel` **antes de B6**. Todas las acciones empiezan por `cd …/campana_fp…`; si la",
        "> carpeta no existe, el `cd` falla, **no se escribe ninguna marca** y los **11 casos",
        "> se pierden** (`NO_EJECUTADO`). El **deploy (T3)** la crea (`mkdir -p` + propietario",
        "> `angel:angel`) y **E0** lo comprueba. No se borra entre días: las marcas y",
        "> `hecho.txt` viven ahí.",
        "",
        "| Comprobación (E0) | Comando | Criterio |",
        "|---|---|---|",
        "| Carpeta de campaña | `test -w /home/angel/Documentos/campana_fp` | rc=0 |",
        "| Binarios (17) | `command -v free systemctl ip crontab openssl rm shred rsync sed "
        "curl timeout seq xargs cp logger tee wget` | todos resuelven |",
        "| `crontab` vacío | `crontab -l` | rc=1 («no crontab for angel») |",
        "| Red | `ip -brief addr` · `ip route` | IPv4 `192.168.65.x` · ruta no vacía |",
        "| Intranet | `curl -sS -o /dev/null -w '%{http_code}' http://intranet.local:8080/` "
        "| `200` |",
        "| Puerto cerrado | `curl -sS --max-time 2 http://intranet.local:8081/` | rc=7 o 28 (filtrado) |",
        "| `logger` | `logger -t ofimatica prueba` + `journalctl -t ofimatica -n 1` | "
        "aparece la línea |",
        "| `shred` | `shred --version` | coreutils ≥ 8 |",
        "| `openssl` | `openssl version` | ≥ 1.1.1 (`-pbkdf2`) |",
        "| PDF del manual | `wget -q -O /dev/null http://intranet.local:8080/descargas/"
        "manual_empleado.pdf` | descarga > 500 bytes |",
        "| Disco | `df -Pk /home/angel/Documentos` | ≥ 40 MB libres (tope declarado) |",
        "",
        "> Si falla la carpeta o un binario, **no se arranca B6**: los casos se marcarían",
        "> `NO_EJECUTADO`. Se corrige el deploy y se repite E0.",
        "",
        "## Desviaciones respecto del plan (declaradas)",
        "",
        "| # | Plan | Artefacto | Por qué |",
        "|---|---|---|---|",
        f"| D-1 | «~47-55 acciones» (§5.2.6) | **{total}** | 11 evidencias + 11 limpiezas + "
        "6 preparaciones, todas declaradas; el número exacto lo fija el CSV y lo sella B10 |",
        f"| D-2 | «~59-65 `execve`» (§5.2.6) | **{ex['total']}** | mismos motivos + los 12 `cp` "
        "de `xargs` y el `curl` de `timeout`; sigue siendo < 0,01 % de `M`; B10 lo sella |",
        "| D-3 | «`BINARIOS_OK` = 36» (§15.2) | **34** | errata: §5.2.1.5 **prohíbe** "
        "`systemctl`/`crontab` en la lista de la receta. Son **34**; **36** es "
        "`BINARIOS_CAMPANA` (34 + los 2 de B6), que solo valida la campaña |",
        "| D-4 | no figura en §15.1 | **`campana.py`** (nuevo) | el plan pide «validador de "
        "campaña» y generar B6 desde el CSV; se aísla en un módulo para no engordar el "
        "generador de la receta |",
        "| D-5 | C-10 copia `informes/informe.txt` | **plantilla propia** "
        "(`C-10/plantilla.txt`) | un caso no debe depender de un fichero que crea la receta: "
        "prepara su insumo y lo borra |",
        "| D-6 | C-05 con `sha256sum` ×2 | **un solo `sha256sum f1 f2`** | una acción deja "
        "las dos huellas; el predicado (iguales) se ve en `hecho.txt` |",
        "",
        "> Ninguna desviación cambia el diseño: no añade mutación, ni `sudo`, ni `|`, ni red",
        "> fuera de la intranet local; solo declara el volumen real y dos decisiones de",
        "> implementación.",
        "",
        "## Qué NO entra (y por qué)",
        "",
        "- **C-04 — «programo mi copia mensual y la quito»** (`crontab` + `crontab -r`): "
        "**retirada en v4** por decisión humana. Escribe estado en el `crontab` del usuario, "
        "fuera de `campana_fp/`, y la campaña es **no mutante**. Se pierde la única medición "
        "legítima de **`2832` (L5)**; se declara como límite (§1.9.4, §17.4). **No se "
        "sustituye** por otra escritura de sistema.",
        "- `ps`, `id`, `whoami`, `uname`, `journalctl`: **no aparecen** en el corpus de "
        "ataques (no hay ataque con el que confundirlos).",
        "- `passwd`, `useradd`, `mount`, `losetup`, `dd`: exigen root, cambian credenciales "
        "o no son actividad de oficina.",
        "",
        "## Cómo se comprueba",
        "",
        "```bash",
        "python _artefactos/scripts/campana.py --check      # 11 casos, 0 mutación, 22 marcas",
        "python _artefactos/scripts/construir_receta_legitima.py --check   # receta + B6",
        "python _artefactos/scripts/cobertura_exes.py --campana "
        "Soporte/Laboratorio/legitimo_72h/campana/campana_casos.csv",
        "```",
        "",
        "---",
        "",
        "> **Sellado.** El `sha256` de este fichero está en la **primera línea** de",
        "> `campana_casos.csv`. Cualquier cambio en el pre-registro obliga a regenerar ambos",
        "> (`campana.py --docs`) **y a firmarlos otra vez antes de `t0`**.",
        "",
    ]
    return "\n".join(lineas)


# --------------------------------------------------------------------------
# Escritura de docs y sellado
# --------------------------------------------------------------------------
def escribir_docs(raiz=None, verbose=True):
    casos, _filas = cargar(raiz)
    md_texto = render_md(casos)
    md = ruta_md(raiz)
    os.makedirs(os.path.dirname(md), exist_ok=True)
    with open(md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(md_texto)
    sha = sha256_file(md)
    csv_texto = render_csv(casos, sha)
    with open(ruta_csv(raiz), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(csv_texto)
    if verbose:
        print(f"casos.md          {len(md_texto)} bytes  sha256={sha}")
        print(f"campana_casos.csv {len(csv_texto)} bytes  filas={len(casos)}  "
              f"acciones={sum(len(c['acciones']) for c in casos.values())}")
    return sha


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Auditoría de no mutación (salida literal para el tester, CA-27)
# --------------------------------------------------------------------------
REGLAS_MUTACION = {
    "systemctl de escritura": r"\bsystemctl\s+(start|stop|restart|reload|try-restart|"
                              r"enable|disable|reenable|mask|unmask|isolate|kill|clean|"
                              r"set-property|daemon-reload|edit|link|revert|reset-failed|"
                              r"reboot|poweroff|halt|suspend|hibernate|kexec)\b",
    "crontab de escritura": r"\bcrontab\s+(?!-l\b)\S+",
    "cuentas (useradd/userdel/passwd...)": r"\b(useradd|userdel|usermod|groupadd|groupdel|"
                                           r"passwd|chpasswd|chsh|chfn)\b",
    "instalación (apt/dpkg/yum/...)": r"\b(apt|apt-get|dpkg|yum|dnf|rpm|snap|pip|pip3)\b",
    "root/GUI (mount/losetup/dd/...)": r"\b(mount|umount|losetup|mke2fs|wipefs|sfdisk|dd)\b",
    "pipes": r"\|",
    "sudo": r"(?:^|\s)sudo(?:\s|$)",
    "random": r"(?:^|[\s;&|])random(?:$|[\s;&|])",
    "comillas dobles": r'"',
}


def auditar_no_mutacion(raiz=None):
    """Cuenta (literal) cada patrón prohibido sobre los 63 comandos de la campaña."""
    casos, _ = cargar(raiz)
    cmds = [a["comando"] for c in casos.values() for a in c["acciones"]]
    texto = "\n".join(cmds)
    counts = {k: len(re.findall(p, texto)) for k, p in REGLAS_MUTACION.items()}
    fuera = []
    for cmd in cmds:
        for _verbo, dest in destinos_escritura(cmd):
            if not _destino_ok(dest):
                fuera.append((dest, cmd[:70]))
        for ruta in rutas_absolutas(cmd):
            if ruta in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                continue
            if not (ruta == BASE or ruta.startswith(BASE + "/")):
                fuera.append((ruta, cmd[:70]))
    counts["escritura fuera de campana_fp"] = len(fuera)
    efectos = {}
    for nombre, e in EFECTOS_DECLARADOS.items():
        patron = re.compile(r"(?:^|[\s;&|])(?:" +
                            "|".join(re.escape(v) for v in e["verbos"]) + r")(?:\s|$)")
        efectos[nombre] = sum(1 for c in cmds if patron.search(c))
    counts["efectos declarados"] = efectos
    fallos = [f"{k} = {v} (se exige 0)" for k, v in counts.items()
              if v and k not in ("efectos declarados",)]
    for nombre, n in efectos.items():
        if n < 1:
            fallos.append(f"efecto declarado '{nombre}' sin ningún uso")
    return {"comandos": len(cmds), "counts": counts, "fuera": fuera, "fallos": fallos}


def contar_execve(raiz=None):
    """`execve` reales que ejecutará la campaña (proyección determinista del CSV).

    Se cuenta el **primer token de cada segmento** (`binarios_de`), se excluyen los
    *builtins* del shell (`cd`, `echo`, `printf`, `true`) y se añaden los **hijos**
    declarados: `xargs` lanza un `cp` por línea de su fichero (12, de `seq 1 12`) y
    `timeout` lanza el comando envuelto (`curl`, 1). No se copia ninguna cifra
    externa: sale de los comandos literales del CSV. **B10 lo sella.**
    """
    casos, _ = cargar(raiz)
    por_dia = {1: 0, 2: 0, 3: 0}
    detalle = {}
    hijos = {"cp": 0, "curl": 0}
    for cid, c in casos.items():
        dia = int(c["meta"]["dia"])
        n_caso = 0
        texto_caso = " ".join(a["comando"] for a in c["acciones"])
        n_hijos_cp = 0
        m = re.search(r"\bseq\s+1\s+(\d+)\b", texto_caso)
        for a in c["acciones"]:
            toks = _binarios_de(a["comando"])
            for tok in toks:
                if tok in BUILTINS_SIN_EXECVE:
                    continue
                n_caso += 1
                detalle[tok] = detalle.get(tok, 0) + 1
            if "xargs" in toks:
                n_hijos_cp = int(m.group(1)) if m else 0
                n_caso += n_hijos_cp
                hijos["cp"] += n_hijos_cp
            if "timeout" in toks:
                n_caso += 1
                hijos["curl"] += 1
        por_dia[dia] += n_caso
    detalle["cp"] = detalle.get("cp", 0) + hijos["cp"]
    detalle["curl"] = detalle.get("curl", 0) + hijos["curl"]
    return {"total": sum(por_dia.values()), "por_dia": por_dia,
            "hijos": hijos, "por_binario": dict(sorted(detalle.items())),
            "metodo": "primer token por segmento, sin builtins (cd/echo/printf/true), "
                      "+12 cp de xargs y +1 curl de timeout"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Campaña B6 (11 casos no mutantes).")
    ap.add_argument("--raiz", default=None, help="raíz del repo (por defecto, 3 niveles arriba)")
    ap.add_argument("--docs", action="store_true", help="regenera casos.md y sella el CSV")
    ap.add_argument("--check", action="store_true", help="valida campaña, docs y sha")
    ap.add_argument("--no-mutacion", action="store_true",
                    help="auditoría literal de no mutación (0 en todo salvo logger)")
    ap.add_argument("--reparto", action="store_true", help="imprime reparto y huecos")
    args = ap.parse_args(argv)

    if args.no_mutacion:
        res = auditar_no_mutacion(args.raiz)
        print(f"comandos auditados = {res['comandos']}")
        for k, v in res["counts"].items():
            print(f"{k} = {v}")
        for f in res["fallos"]:
            print(f"FALLO: {f}")
        print("RESULT=" + ("PASS" if not res["fallos"] else "FAIL"))
        return 0 if not res["fallos"] else 1

    if args.docs:
        escribir_docs(args.raiz)
        res = validar(args.raiz)
        for f in res["fallos"]:
            print(f"FALLO: {f}")
        print("RESULT=" + ("PASS" if not res["fallos"] else "FAIL"))
        return 0 if not res["fallos"] else 1

    res = validar(args.raiz)
    for f in res["fallos"]:
        print(f"FALLO: {f}")
    print(f"campana: {res['casos']} casos | {res['marcas']} marcas | "
          f"{res['acciones_total']} acciones {res['acciones']} | "
          f"{res['execve']['total']} execve {res['execve']['por_dia']} | "
          f"{len(res['binarios'])} binarios | {len(res['ata'])} ATA")
    if args.reparto or not args.check:
        casos, _ = cargar(args.raiz)
        for dia in (1, 2, 3):
            accs = acciones_b6(dia, args.raiz)
            ini = {a["caso"]: a["t"] for a in accs if a["tipo"] == "inicio"}
            fin = {a["caso"]: a["t"] for a in accs if a["tipo"] == "fin"}
            orden = sorted(ini, key=lambda c: ini[c])
            print(f"  d{dia}: {len(orden)} casos | {len(accs)} acciones | "
                  f"{s_to_hms(ini[orden[0]])}-{s_to_hms(fin[orden[-1]])} | "
                  f"gaps=" + ",".join(f"{ini[b] - fin[a]}s" for a, b in zip(orden, orden[1:])))
        print("  binarios: " + " ".join(res["binarios"]))
        print("  ATA: " + " ".join(res["ata"]))
    print("RESULT=" + ("PASS" if not res["fallos"] else "FAIL"))
    return 0 if not res["fallos"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
