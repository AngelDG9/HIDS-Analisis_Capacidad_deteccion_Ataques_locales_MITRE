#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""construir_receta_legitima_windows.py — receta Windows **espejo** de la de Linux (W1).

Genera las tres timelines GHOSTS de Windows (`w1/w2/w3.json`), su calendario
(`calendario_windows.json` + `bloques_windows.env`) y un resumen legible
(`receta_windows_resumen.md`), **sin inventar ritmo**: el vector de `DelayAfter`, el número
de eventos y las ventanas `UtcTimeOn/UtcTimeOff` se **copian tal cual** de las recetas
Linux versionadas (`Soporte/Laboratorio/legitimo_72h/recetas/d{1,2,3}.json`) y solo se
**traduce el texto del comando**. Es el «traslado por ranuras» del plan §D2.

Por qué un módulo aparte y no un `--plataforma` en el generador Linux: ese fichero está en
la lista de **prohibidos** (plan §16.3) y su `--check` codifica invariantes POSIX
(`cd /home/angel && …`, comillas dobles prohibidas, `printf` con `$?`…). Añadirle una rama
de plataforma obligaría a editarlo y a relajar sus invariantes. Este módulo lo **importa**
(`import construir_receta_legitima`) y reutiliza sus tablas de ritmo (`INTRA`, `RAFAGAS`,
`HUECOS`, `PAUSA_LARGA`), sus cuentas y la campaña (`campana.py`), sin tocar nada.

Decisiones de traducción (todas declaradas en `receta_windows_resumen.md`):

1. **Una entrada = un `cmd /c`.** El handler `Command` de GHOSTS ya lanza
   `cmd /c <Command>` (`Handlers/Cmd.cs:106`), así que el `Command` de la receta **no**
   lleva el envoltorio: ponerlo daría `cmd /c cmd /c …`, un proceso de más por acción. La
   única excepción es el **fan-out** (`for … do @cmd /c copy`), donde el `cmd` hijo **es**
   el proceso que sustituye al `cp` de Linux (12 hijos, espejo del `xargs`+`cp`).
2. **`cwd` realista**: toda acción empieza por `cd /d C:\\Users\\angel… && ` (misma regla
   que el `cd <carpeta> && ` de Linux). La campaña vive en `C:\\lab-legit\\campana\\W-XX`.
3. **Sin `|` en ninguna parte** (lección H-1, `state.md:10`; auditoría D-01): el servidor
   GHOSTS parte la línea de resultado por `|` (`QueueSyncService.cs:178`) y pierde el
   reporte. La regla es **0 pipes en todo el texto**, también dentro de
   `powershell -NoProfile -Command "…"` (nota de corrección C7, anula el W0 §4.5).
4. **Errores** con `if errorlevel` (nunca `%ERRORLEVEL%`, que se expande al analizar la
   línea) y registro TSV de **5 campos** en `C:\\Users\\angel\\Documentos\\errores.log`.
5. **PowerShell solo donde no hay nativo**: cifrado (W-04/C-05) y borrado seguro
   (W-05/C-06) escritos a mano, más la normalización de CSV de la campaña (W-07/C-08), que
   el plan §5.2 ya define en PowerShell. El **mismo** guion de borrado seguro aparece
   también en la jornada (B4, herramienta `shred` del corpus, 1/día); es el **único** uso
   de PowerShell fuera de la campaña.

Uso:
    python _artefactos/scripts/construir_receta_legitima_windows.py            # genera
    python _artefactos/scripts/construir_receta_legitima_windows.py --check    # valida
    python _artefactos/scripts/construir_receta_legitima_windows.py --out DIR  # otro destino
    python ... --t0 2026-11-09                                                 # fija el mapa

Salida por defecto: `Soporte/Laboratorio/windows/recetas/`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import campana                        # noqa: E402  (campaña B6: fuente de tiempos)
import construir_receta_legitima as L  # noqa: E402  (generador Linux: solo lectura)

# --------------------------------------------------------------------------
# Constantes (una sola fuente de verdad)
# --------------------------------------------------------------------------
VERSION_RECETA_W = 1
PLATAFORMA = "windows"
BOVEDA_VERSION = 3

HOME_W = r"C:\Users\angel"
DOC_W = HOME_W + r"\Documentos"
DOWN_W = HOME_W + r"\Descargas"
CACHE_W = HOME_W + r"\.cache\tfg-web"
INFORMES_W = DOC_W + r"\informes"
ACTAS_W = DOC_W + r"\actas"
CORREO_W = DOC_W + r"\correo"
COPIAS_W = DOC_W + r"\copias"
REGISTRO_W = DOC_W + r"\errores.log"

UA_W = "TFG-Legit/1.0 (Windows; x86_64; sesion-web)"

#: Base de la campaña Windows (plan §5.2: `C:\lab-legit\campana\W-XX\`).
BASE_CAMP_W = r"C:\lab-legit\campana"
#: Ruta Linux de la campaña (para traducirla a `BASE_CAMP_W`).
CAMP_LX = "/home/angel/Documentos/campana_fp"
#: C-01…C-12 → W-01…W-11 (C-04 no existe: decisión de no mutación).
MAPEO_CASOS = {
    "C-01": "W-01", "C-02": "W-02", "C-03": "W-03", "C-05": "W-04",
    "C-06": "W-05", "C-07": "W-06", "C-08": "W-07", "C-09": "W-08",
    "C-10": "W-09", "C-11": "W-10", "C-12": "W-11",
}

#: Carpetas de trabajo admitidas tras `cd /d` (espejo de `L.DIRS_CWD` + campaña).
CARPETAS_PERFIL = (HOME_W, DOC_W, DOWN_W, CACHE_W, INFORMES_W, ACTAS_W, CORREO_W, COPIAS_W)
DIRS_CWD_W = CARPETAS_PERFIL + (BASE_CAMP_W,)

#: Separador de campos del registro de errores (TAB literal).
TAB = "\t"
#: Marca de tiempo **local** del invitado: `cmd` no formatea ISO/UTC sin PowerShell.
#: La hora UTC de cada acción se ancla con el `timestamp` de Wazuh (W-V9). Declarado.
TS_W = "%DATE%_%TIME%"

#: Registro de errores: 5 campos TSV (`ts · tipo · familia · comando · rc`).
RE_ERRLOG = re.compile(
    r">> (?P<log>\S*errores\.log) echo (?P<ts>%DATE%_%TIME%)"
    r"\t(?P<tipo>error|reintento)\t(?P<fam>[a-z_]+)\t(?P<cmd>.+?)\t(?P<rc>rc=[a-z0-9]+)")

#: Verbos de mutación de sistema prohibidos en toda la receta (CA-W3 / plan §D2).
MUTANTES = (
    r"\bschtasks\s+/(create|delete|change)\b",
    r"\breg\s+(add|delete|import)\b",
    r"\bsc\s+(create|delete|config)\b",
    r"\bnet\s+user\s+\S+\s+/(add|delete)\b",
    r"\bbcdedit\b", r"\bvssadmin\b", r"\bcipher\s+/w", r"\bformat\b", r"\bdiskpart\b",
    r"\bicacls\b[^\n]*/(grant|deny)\b",
    r"\bwevtutil\s+cl\b", r"\bnet\s+stop\b", r"\bnet\s+start\b",
)

# --------------------------------------------------------------------------
# Traducción de rutas y utilidades
# --------------------------------------------------------------------------
def _p(path: str) -> str:
    """Ruta Linux (`/home/angel/...`) → ruta Windows (`C:\\Users\\angel\\...`).

    · `/dev/null` → `NUL`.
    · la campaña (`~/Documentos/campana_fp/C-XX`) → `C:\\lab-legit\\campana\\W-XX`.
    · se quita el sufijo de fecha `_$(date -u +%F)` de los nombres: `cmd` no da una fecha
      ISO y `%DATE%` lleva `/`, que no es válido en un nombre (declarado).
    """
    if path == "/dev/null":
        return "NUL"
    path = path.replace("_$(date -u +%F)", "")
    if path == CAMP_LX or path.startswith(CAMP_LX + "/"):
        resto = path[len(CAMP_LX):]
        for cid, wid in MAPEO_CASOS.items():
            resto = resto.replace("/" + cid, "/" + wid)
        return (BASE_CAMP_W + resto).replace("/", "\\")
    if path.startswith("/home/angel"):
        path = HOME_W + path[len("/home/angel"):]
    return path.replace("/", "\\")


def _pdir(path: str) -> str:
    """Carpeta contenedora de una ruta Linux (para `gzip`/`tar -C`)."""
    return _p(path).rsplit("\\", 1)[0]


def _base(path: str) -> str:
    return _p(path).rsplit("\\", 1)[-1]


def _q(texto: str) -> str:
    """Entrecomilla un valor que lleva espacios (regla R-W9: sin comillas internas)."""
    return '"%s"' % texto


def _split_amp(cmd: str):
    """Parte por ` && ` **fuera** de comillas simples (las de Linux)."""
    partes, buf, q = [], [], False
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if c == "'":
            q = not q
        if not q and cmd.startswith(" && ", i):
            partes.append("".join(buf))
            buf = []
            i += 4
            continue
        buf.append(c)
        i += 1
    partes.append("".join(buf))
    return partes


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Reglas de traducción de un comando simple (sin `cd` y sin ` && `)
# --------------------------------------------------------------------------
REGLAS_SIMPLES = []


def _regla(nombre, patron):
    def deco(fn):
        REGLAS_SIMPLES.append((nombre, re.compile(patron), fn))
        return fn
    return deco


def _curl(args: str) -> str:
    """Traduce una invocación de `curl` (Linux) a `curl.exe` (Windows).

    `curl.exe` viene en Windows 10 ≥ 1803 y acepta los mismos flags; cambian la UA
    (declarada), las rutas y las comillas (`"` es lo único que entiende `cmd`).
    """
    toks = shlex.split(args, posix=True)
    out = ["curl.exe"]
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "-A":
            out += ["-A", _q(UA_W)]
            i += 2
        elif t in ("-b", "-c", "-T", "-o"):
            out += [t, _p(toks[i + 1])]
            i += 2
        elif t == "-e":
            v = toks[i + 1]
            out += ["-e", _p(v) if v.startswith("/home/angel") else v]
            i += 2
        elif t == "-H":
            out += ["-H", _q(toks[i + 1])]
            i += 2
        elif t == "-w":
            out += ["-w", _q(toks[i + 1].replace("\n", "\\n"))]
            i += 2
        elif t == "--data":
            v = toks[i + 1]
            out += ["--data", _q(v) if " " in v else v]
            i += 2
        else:
            out.append(t)
            i += 1
    return " ".join(out)


@_regla("web-con-redireccion", r"^(curl .+?) > (\S+)$")
def _r_curl_redir(m):
    return "%s > %s" % (_curl(m.group(1)[5:]), _p(m.group(2)))


@_regla("web", r"^curl (.+)$")
def _r_curl(m):
    return _curl(m.group(1))


@_regla("web-timeout", r"^timeout (\d+) (curl .+)$")
def _r_timeout(m):
    return _curl("--max-time %s %s" % (m.group(1), m.group(2)[5:]))


@_regla("listar-opcion-mal", r"^ls -la --clasificar (\S+)$")
def _r_ls_bad(m):
    return "dir /clasificar %s" % _p(m.group(1))


@_regla("listar-opcion-bien", r"^ls -la --classify (\S+)$")
def _r_ls_ok(m):
    return "dir /a %s" % _p(m.group(1))


@_regla("estructura", r"^mkdir -p (.+)$")
def _r_mkdir(m):
    # W-4/W-3 (fix v3): `md` de una carpeta que ya existe devuelve **rc=1** (días 2 y 3) y,
    # al ir tras un `if`, se tragaría el resto de la línea. Se comprueba antes (`if not
    # exist`) y cada comprobación va **entre paréntesis**, de modo que la marca que venga
    # después (`inicio.txt`) se ejecute siempre.
    return " & ".join("(if not exist %s md %s)" % (_p(a), _p(a))
                      for a in m.group(1).split())


@_regla("fecha", r"^date -u \+%FT%TZ > (\S+)$")
def _r_fecha_out(m):
    return "> %s echo %s" % (_p(m.group(1)), TS_W)


@_regla("fecha", r"^date -u \+%FT%TZ$")
def _r_fecha(m):
    return "echo %s" % TS_W


@_regla("agenda-append", r"^echo '(.*)' >> (\S+)$")
def _r_echo_append(m):
    return ">> %s echo %s" % (_p(m.group(2)), m.group(1))


@_regla("agenda", r"^echo '(.*)' > (\S+)$")
def _r_echo_new(m):
    return "> %s echo %s" % (_p(m.group(2)), m.group(1))


@_regla("huella-doble", r"^sha256sum (\S+) (\S+) > (\S+)$")
def _r_sha2_out(m):
    out = _p(m.group(3))
    return ("certutil -hashfile %s SHA256 > %s 2>&1 & "
            "certutil -hashfile %s SHA256 >> %s 2>&1"
            % (_p(m.group(1)), out, _p(m.group(2)), out))


@_regla("huella", r"^sha256sum (\S+) > (\S+)$")
def _r_sha256_out(m):
    # L-1 (fix v3): la huella **se guarda en su fichero**; sin la redirección el `type`
    # posterior (.sha256) no encontraría nada. `2>&1` recoge también el pie de `certutil`.
    return "certutil -hashfile %s SHA256 > %s 2>&1" % (_p(m.group(1)), _p(m.group(2)))


@_regla("huella", r"^sha256sum (\S+)$")
def _r_sha256(m):
    return "certutil -hashfile %s SHA256" % _p(m.group(1))


@_regla("huella", r"^md5sum (\S+)$")
def _r_md5(m):
    return "certutil -hashfile %s MD5" % _p(m.group(1))


@_regla("huella", r"^openssl dgst -sha256 (\S+)$")
def _r_openssl(m):
    return "certutil -hashfile %s SHA256" % _p(m.group(1))


@_regla("contar", r"^wc -l (.+)$")
def _r_wcl(m):
    return 'find /c /v "" ' + " ".join(_p(a) for a in m.group(1).split())


@_regla("tamano", r"^wc -c (.+)$")
def _r_wcc(m):
    return "dir " + " ".join(_p(a) for a in m.group(1).split())


@_regla("listar", r"^ls -la (.+)$")
def _r_ls(m):
    return "dir " + " ".join(_p(a) for a in m.group(1).split())


@_regla("listar", r"^ls -l (.+)$")
def _r_ls1(m):
    return "dir " + " ".join(_p(a) for a in m.group(1).split())


@_regla("leer", r"^cat (.+)$")
def _r_cat(m):
    return "type " + " ".join(_p(a) for a in m.group(1).split())


@_regla("copiar", r"^cp -f (\S+) (\S+)$")
def _r_cp(m):
    return "copy /y %s %s" % (_p(m.group(1)), _p(m.group(2)))


@_regla("renombrar", r"^mv -f (\S+) (\S+)$")
def _r_mv(m):
    return "move /y %s %s" % (_p(m.group(1)), _p(m.group(2)))


@_regla("borrar-recursivo", r"^rm -rf (.+)$")
def _r_rmrf(m):
    # `rd` solo acepta **una** ruta: con dos da error de sintaxis y rc≠0 (y se llevaría por
    # delante la marca `fin.txt`). Una orden por ruta, separadas con `&` (W-3).
    return " & ".join("rd /s /q %s 2>nul" % _p(a) for a in m.group(1).split())


@_regla("borrar-forzado", r"^rm -f (.+)$")
def _r_rmf(m):
    # W-3 (fix v3): `rm -f` = «borra si está» ⇒ `del /f /q`, que **ya** devuelve rc=0 tanto
    # si el fichero existe como si no. El viejo `if exist X del X` se tragaba todo lo que
    # viniera detrás en la misma línea (registro de errores, `fin.txt`) cuando X no existía.
    parts = [_p(a) for a in m.group(1).split()]
    return " & ".join("del /f /q %s 2>nul" % p for p in parts)


@_regla("borrar-error", r"^rm (\S+)$")
def _r_rm(m):
    # W-2 (fix v3): `del` de un fichero ausente devuelve **rc=0** en Windows (a diferencia de
    # `rm`), así que la familia `rm_inexistente` no llegaba a registrar el fallo. Se
    # materializa como `type` del **mismo** temporal: abrir el fichero que ya no está sí
    # falla (rc=1) y el reintento (`del /f /q`) sí lo deja limpio.
    return "type %s" % _p(m.group(1))


@_regla("comprimir", r"^tar -czf (\S+) -C (\S+) (.+)$")
def _r_tar(m):
    return "tar -czf %s -C %s %s" % (_p(m.group(1)), _p(m.group(2)), m.group(3))


@_regla("comprimir", r"^gzip -kf (\S+)$")
def _r_gzip(m):
    return "tar -czf %s.gz -C %s %s" % (_p(m.group(1)), _pdir(m.group(1)), _base(m.group(1)))


@_regla("descomprimir-error", r"^gzip -d (\S+)$")
def _r_gunzip(m):
    return "tar -xzf %s -C %s" % (_p(m.group(1)), _pdir(m.group(1)))


@_regla("listar-ficheros", r"^find (\S+) -type f > (\S+)$")
def _r_find(m):
    return "dir /b /s /a-d %s > %s" % (_p(m.group(1)), _p(m.group(2)))


@_regla("contar-coincidencias", r"^grep -c '(.*)' (\S+)(?: >> (\S+))?$")
def _r_grepc(m):
    redir = (" >> " + _p(m.group(3))) if m.group(3) else ""
    return 'find /c "%s" %s%s' % (m.group(1), _p(m.group(2)), redir)


@_regla("filtrar", r"^grep '(.*)' (\S+) >> (\S+)$")
def _r_grep(m):
    return 'findstr /c:"%s" %s >> %s' % (m.group(1), _p(m.group(2)), _p(m.group(3)))


@_regla("cabecera", r"^head -(?:n )?(\d+) (\S+)(?: >> (\S+))?$")
def _r_head(m):
    redir = (" >> " + _p(m.group(3))) if m.group(3) else ""
    return "more +0 %s%s" % (_p(m.group(2)), redir)


@_regla("cola", r"^tail -(?:n )?(\d+) (\S+)(?: >> (\S+))?$")
def _r_tail(m):
    redir = (" >> " + _p(m.group(3))) if m.group(3) else ""
    return "more %s%s" % (_p(m.group(2)), redir)


@_regla("tamano-args", r"^du -sb (.+?) >> (\S+)$")
def _r_dusb(m):
    return "dir /s " + " ".join(_p(a) for a in m.group(1).split()) + " >> " + _p(m.group(2))


@_regla("tamano", r"^du -sh (.+)$")
def _r_du(m):
    return "dir /s " + " ".join(_p(a) for a in m.group(1).split())


@_regla("disco-opcion", r"^df -h --max-depth=1 /$")
def _r_df_bad(m):
    # `df` no tiene `--max-depth`: en Windows la opción mal escrita se prueba con `dir`
    # (builtin, sin elevación); el `rc` de un switch inválido lo confirma WE0-5.
    return "dir /max-depth=1 C:\\"


@_regla("disco", r"^df -h /$")
def _r_df(m):
    # `dir C:\` imprime los bytes libres en la última línea (sin `fsutil`, que puede
    # pedir elevación): es el equivalente más fiel de `df -h /`.
    return "dir C:\\"


@_regla("estado", r"^free -m(?: > (\S+))?$")
def _r_free(m):
    return "systeminfo" + ((" > " + _p(m.group(1))) if m.group(1) else "")


@_regla("red", r"^ip -brief addr(?: > (\S+))?$")
def _r_ip(m):
    return "ipconfig /all" + ((" > " + _p(m.group(1))) if m.group(1) else "")


@_regla("red", r"^ip route(?: > (\S+))?$")
def _r_route(m):
    return "route print" + ((" > " + _p(m.group(1))) if m.group(1) else "")


@_regla("registro", r"^logger -t (\S+) '(.*)'$")
def _r_logger(m):
    return ("eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO %s /D %s"
            % (m.group(1), _q(m.group(2))))


@_regla("bitacora", r"^tee -a (\S+) < (\S+)$")
def _r_tee(m):
    return "type %s >> %s" % (_p(m.group(2)), _p(m.group(1)))


@_regla("lotes", r"^seq (\d+) (\d+) > (\S+)$")
def _r_seq(m):
    return "for /L %%i in (%s,1,%s) do @echo %%i>>%s" % (m.group(1), m.group(2),
                                                         _p(m.group(3)))


@_regla("lotes", r"^xargs -a (\S+) -I\{\} cp (\S+) (\S*)\{\}(\S*)$")
def _r_xargs(m):
    # W-1 (fix v3): `xcopy` con un fichero suelto y un destino que **no existe** pregunta
    # «¿archivo o directorio?» y acaba con rc=2 sin copiar nada. `copy` sí renombra, pero es
    # builtin de `cmd`: hay que lanzarlo en un `cmd /c` hijo para que el abanico siga siendo
    # de **12 procesos** (los 12 `cp` de Linux).
    return ("for /f %%i in (%s) do @cmd /c copy /y %s %s%%i%s"
            % (_p(m.group(1)), _p(m.group(2)), _p(m.group(3)), m.group(4)))


@_regla("descarga", r"^wget -q -O (\S+) (\S+)$")
def _r_wget(m):
    return "curl.exe -sS -o %s %s" % (_p(m.group(1)), m.group(2))


@_regla("sincronizar", r"^rsync -a --delete (\S+) (\S+)$")
def _r_rsync(m):
    return ("robocopy %s %s /MIR /NFL /NDL /NJH /NJS /NP"
            % (_p(m.group(1)), _p(m.group(2))))


@_regla("csv-normalizar", r"^sed -i 's/;/,/g' (\S+)$")
def _r_sed_i(m):
    """Sin `sed` nativo y sin PowerShell en la jornada: se reescribe la cabecera."""
    return "> %s echo referencia,area,importe" % _p(m.group(1)).replace(".csv", "_comas.csv")


@_regla("csv-leer", r"^sed -n '1,5p' (\S+)(?: > (\S+))?$")
def _r_sed_n(m):
    redir = (" > " + _p(m.group(2))) if m.group(2) else ""
    return "more +0 %s%s" % (_p(m.group(1)), redir)


@_regla("estado-fichero", r"^stat -c %s (\S+)(?: (>|>>) (\S+))?$")
def _r_stat_bytes(m):
    redir = (" %s " % m.group(2) + _p(m.group(3))) if m.group(3) else ""
    return "for %%I in (%s) do @echo %%~zI%s" % (_p(m.group(1)), redir)


@_regla("estado-fichero", r"^stat (\S+)$")
def _r_stat(m):
    return "dir %s" % _p(m.group(1))


@_regla("servicios", r"^systemctl --failed --no-pager > (\S+)$")
def _r_scfailed(m):
    return "sc query state= all > %s" % _p(m.group(1))


@_regla("servicios", r"^systemctl list-units .* > (\S+)$")
def _r_tasklist(m):
    return "tasklist /svc > %s" % _p(m.group(1))


@_regla("servicios", r"^systemctl list-timers .* > (\S+)$")
def _r_schtasks(m):
    return "schtasks /query /fo LIST > %s" % _p(m.group(1))


@_regla("tareas-lectura", r"^crontab -l > (\S+) 2>/dev/null; r=\$\?; "
                          r"printf 'crontab_rc=%s\\n' \$r > (\S+)$")
def _r_crontab(m):
    out, rc = _p(m.group(1)), _p(m.group(2))
    reg = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    return ("reg query %s > %s 2>nul & if errorlevel 1 (> %s echo tarea_rc=ge1) "
            "else (> %s echo tarea_rc=0)" % (reg, out, rc, rc))


# --------------------------------------------------------------------------
# Reglas compuestas (prefijo completo de la acción, incluye los 3 casos PowerShell)
# --------------------------------------------------------------------------
REGLAS_COMPUESTAS = []


def _regla_c(nombre, patron):
    def deco(fn):
        REGLAS_COMPUESTAS.append((nombre, re.compile(patron, re.S), fn))
        return fn
    return deco


@_regla_c("caso_c05_cifrar",
          r"^openssl enc -aes-256-cbc -pbkdf2 -salt -in (\S+) -out (\S+) -pass pass:(\S+)$")
def _c_cifrar(m):
    """AES-256-CBC en PowerShell (plan N-4: no hay cifrado con contraseña nativo)."""
    src, dst = _p(m.group(1)), _p(m.group(2))
    return ("powershell -NoProfile -Command \""
            "$k=[byte[]](0..31); $v=[byte[]](0..15); "
            "$a=[IO.File]::ReadAllBytes('%s'); "
            "$s=[Security.Cryptography.Aes]::Create(); $s.Mode='CBC'; $s.Padding='PKCS7'; "
            "$s.Key=$k; $s.IV=$v; $e=$s.CreateEncryptor(); "
            "$b=$e.TransformFinalBlock($a,0,$a.Length); "
            "[IO.File]::WriteAllBytes('%s',$b)\"" % (src, dst))


@_regla_c("caso_c05_descifrar",
          r"^openssl enc -d -aes-256-cbc -pbkdf2 -in (\S+) -out (\S+) -pass pass:(\S+)$")
def _c_descifrar(m):
    src, dst = _p(m.group(1)), _p(m.group(2))
    return ("powershell -NoProfile -Command \""
            "$k=[byte[]](0..31); $v=[byte[]](0..15); "
            "$a=[IO.File]::ReadAllBytes('%s'); "
            "$s=[Security.Cryptography.Aes]::Create(); $s.Mode='CBC'; $s.Padding='PKCS7'; "
            "$s.Key=$k; $s.IV=$v; $d=$s.CreateDecryptor(); "
            "$b=$d.TransformFinalBlock($a,0,$a.Length); "
            "[IO.File]::WriteAllBytes('%s',$b)\"" % (src, dst))


@_regla_c("caso_c06_borrado", r"^shred -n (\d+) -z -u (\S+)$")
def _c_shred(m):
    """Sobrescritura determinista + borrado en PowerShell (plan N-5: `cipher /w` no)."""
    return ("powershell -NoProfile -Command \""
            "$p='%s'; $a=[IO.File]::ReadAllBytes($p); "
            "$z=New-Object byte[] $a.Length; [IO.File]::WriteAllBytes($p,$z); "
            "for($i=0;$i -lt $a.Length;$i++){$z[$i]=[byte](($i*37)%%251)}; "
            "[IO.File]::WriteAllBytes($p,$z); Remove-Item -LiteralPath $p -Force\"" % _p(m.group(2)))


@_regla_c("caso_c06_evidencia",
          r"^echo 'RESULTADO=OK' > (\S+) && cat (\S+) >> \1; "
          r"stat -c %s (\S+) > /dev/null 2>&1; \[ \$\? -ne 0 \] && "
          r"echo 'borrador_ausente=1' >> \1; true$")
def _c_c06_evid(m):
    ok, antes, borrador = _p(m.group(1)), _p(m.group(2)), _p(m.group(3))
    return ("echo RESULTADO=OK > %s && type %s >> %s && "
            "if not exist %s >> %s echo borrador_ausente=1"
            % (ok, antes, ok, borrador, ok))


@_regla_c("caso_c08_csv", r"^sed -i 's/;/,/g' (\S*campana_fp\S*)$")
def _c_sed_i(m):
    """Normalización de CSV en PowerShell (plan §5.2, W-07): **sin `|`** (D-01).

    La variable intermedia sustituye al pipe: `cmd` no expande `$`, PowerShell sí; el
    efecto y el número de procesos (1 `powershell.exe`) son los mismos.
    """
    return ("powershell -NoProfile -Command \""
            "$c = (Get-Content -LiteralPath '%s') -replace ';',','; "
            "Set-Content -LiteralPath '%s' -Value $c\"" % (_p(m.group(1)), _p(m.group(1))))


@_regla_c("caso_c09_fallo",
          r"^curl -sS --max-time (\d+) (\S+) 2>/dev/null; r=\$\?; "
          r"printf 'RC_FALLO=%s\\n' \$r > (\S+)$")
def _c_c09_fallo(m):
    out = _p(m.group(3))
    return ("curl.exe -sS --max-time %s %s >nul 2>&1 & "
            "if errorlevel 1 (> %s echo RC_FALLO=ge1) else (> %s echo RC_FALLO=0)"
            % (m.group(1), m.group(2), out, out))


@_regla_c("lotes-campana",
          r"^xargs -a (\S*campana_fp\S*) -I\{\} cp (\S+) (\S*)\{\}(\S*)$")
def _c_xargs_camp(m):
    """`xargs` → `for /L` + `cmd /c copy` (plan §5.2, W-09: mismo abanico de 12 procesos).

    W-1 (fix v3): `xcopy` preguntaba «¿archivo o directorio?» y no copiaba nada (rc=2). Se
    usa `copy` dentro de un `cmd /c` hijo: renombra bien y **mantiene los 12 procesos**.
    """
    dst = _p(m.group(3)) + "%i" + m.group(4)
    return "for /L %%i in (1,1,12) do @cmd /c copy /y %s %s" % (_p(m.group(2)), dst)


# --------------------------------------------------------------------------
# Traducción de una acción completa
# --------------------------------------------------------------------------
def _traducir_simple(seg: str) -> str:
    for _nombre, rx, fn in REGLAS_SIMPLES:
        m = rx.match(seg)
        if m:
            return fn(m)
    raise SystemExit(f"ERROR: sin regla de traducción para: {seg[:140]}")


#: Marca de cierre/apertura de un caso de la campaña (`inicio.txt` / `fin.txt`).
RE_MARCA_CASO = re.compile(r">\s*\S*\\(?:inicio|fin)\.txt\s+echo")


def traducir_rest(rest: str) -> str:
    """Traduce la parte derecha de una acción (lo que va tras el `cd`)."""
    for _nombre, rx, fn in REGLAS_COMPUESTAS:
        m = rx.match(rest)
        if m:
            return fn(m)
    if rest.endswith("; true"):
        rest = rest[: -len("; true")]
    if " && " in rest:
        # W-3 (fix v3): la marca `inicio.txt`/`fin.txt` de un caso se escribe **siempre**.
        # Encadenada con `&&` detrás de un borrado o de un `if` falso no se ejecutaba
        # (caso cerrado sin `fin.txt`) ⇒ se separa con `&`, como comando independiente.
        partes = [_traducir_simple(s) for s in _split_amp(rest)]
        out = partes[0]
        for p in partes[1:]:
            out += (" & " if RE_MARCA_CASO.search(p) else " && ") + p
        return out
    return _traducir_simple(rest)


def _linea_error(tipo: str, fam: str, cmd_w: str, rc: str) -> str:
    return TAB.join((TS_W, tipo, fam, cmd_w, rc))


#: Redirección de silencio que se añade a los fallos (`>nul 2>&1`) o que trae la
#: traducción (`del … 2>nul`). **No** puede ir dentro del `echo` del registro: `cmd`
#: la interpretaría otra vez y cortaría la línea del TSV.
RE_SILENCIO = re.compile(r"\s*2>nul\b|\s*>nul 2>&1\b")


def _cmd_registrable(cmd_w: str) -> str:
    """Comando tal y como se **registra** (sin las redirecciones de silencio)."""
    return RE_SILENCIO.sub("", cmd_w).strip()


def _registro(tipo: str, fam: str, cmd_w: str) -> str:
    """`if errorlevel` + TSV de 5 campos (no expande `%ERRORLEVEL%` antes de ejecutar)."""
    if tipo == "error":
        linea = _linea_error(tipo, fam, cmd_w, "rc=ge1")
        return "if errorlevel 1 (>> %s echo %s)" % (REGISTRO_W, linea)
    fallo = _linea_error(tipo, fam, cmd_w, "rc=ge1")
    bien = _linea_error(tipo, fam, cmd_w, "rc=0")
    return ("if errorlevel 1 (>> %s echo %s) else (>> %s echo %s)"
            % (REGISTRO_W, fallo, REGISTRO_W, bien))


def traducir(cmd_linux: str):
    """Traduce una acción completa de la receta Linux. Devuelve el comando Windows.

    Antes de nada se quita el sufijo `_$(date -u +%F)` de los nombres de fichero: en Linux
    es una sustitución del shell, pero aquí solo estorba (lleva `/` y espacios) y en
    Windows no hay una fecha ISO equivalente (declarado, T-13).
    """
    cmd_linux = cmd_linux.replace("_$(date -u +%F)", "")
    # Los textos de la campaña citan su caso: `C-11` (Linux) → `W-10` (Windows).
    cmd_linux = re.sub(r"\bC-(\d{2})\b",
                       lambda mm: MAPEO_CASOS.get("C-" + mm.group(1), mm.group(0)),
                       cmd_linux)
    m = re.match(r"^cd (\S+) && (.+)$", cmd_linux)
    if not m:
        raise SystemExit(f"ERROR: acción sin `cd <carpeta> && `: {cmd_linux[:140]}")
    cwd, rest = m.group(1), m.group(2)

    me = L.RE_REGISTRO.search(rest)
    if me:
        tipo, fam, fallo = me.group(2), me.group(3), me.group(4)
        cmd_w = traducir_rest(fallo)
        # El fallo no debe escribir su error por pantalla (va al registro): silencio de
        # salida salvo que la traducción ya lo traiga (`del … 2>nul`).
        silencio = "" if "2>nul" in cmd_w else " >nul 2>&1"
        return "cd /d %s && %s%s & %s" % (_p(cwd), cmd_w, silencio,
                                          _registro(tipo, fam,
                                                    _cmd_registrable(cmd_w)))
    return "cd /d %s && %s" % (_p(cwd), traducir_rest(rest))



# --------------------------------------------------------------------------
# Construcción de las timelines (por ranuras desde las recetas Linux)
# --------------------------------------------------------------------------
def _dir_recetas_linux(raiz: str) -> str:
    return os.path.join(raiz, "Soporte", "Laboratorio", "legitimo_72h", "recetas")


def cargar_linux(raiz: str = "."):
    """Carga `d1..d3.json` y comprueba que siguen coincidiendo con el generador."""
    dir_lx = _dir_recetas_linux(raiz)
    out = {}
    for day in (1, 2, 3):
        path = os.path.join(dir_lx, f"d{day}.json")
        if not os.path.isfile(path):
            raise SystemExit(f"ERROR: falta la receta Linux {path}")
        with open(path, encoding="utf-8") as fh:
            tl = json.load(fh)
        planas = [c for (_b, _f, c, _w) in L.componer_dia(day)]
        reales = [ev["Command"] for h in tl["TimeLineHandlers"][:len(L.BLOQUES_TRABAJO)]
                  for ev in h["TimeLineEvents"]]
        if planas != reales:
            raise SystemExit(f"ERROR: d{day}.json no coincide con construir_receta_legitima.py"
                             f" (regenera Linux antes de generar Windows)")
        camp = [a["comando"] for a in campana.acciones_b6(day)]
        reales_b6 = [ev["Command"] for h in tl["TimeLineHandlers"][len(L.BLOQUES_TRABAJO):]
                     for ev in h["TimeLineEvents"]]
        if camp != reales_b6:
            raise SystemExit(f"ERROR: el B6 de d{day}.json no coincide con campana.py")
        out[day] = tl
    return out


def construir_timeline(tl_linux):
    """Timeline Windows: mismos handlers, mismas ventanas, mismos `DelayAfter`."""
    handlers = []
    for h_lx in tl_linux["TimeLineHandlers"]:
        eventos = [{"Command": traducir(ev["Command"]), "DelayAfter": int(ev["DelayAfter"])}
                   for ev in h_lx["TimeLineEvents"]]
        handlers.append({
            "HandlerType": h_lx["HandlerType"],
            "Initial": h_lx["Initial"],
            "UtcTimeOn": h_lx["UtcTimeOn"],
            "UtcTimeOff": h_lx["UtcTimeOff"],
            "Loop": h_lx["Loop"],
            "HandlerArgs": h_lx["HandlerArgs"],
            "TimeLineEvents": eventos,
        })
    return {"Status": "Run", "TimeLineHandlers": handlers}


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def escribir_json(path: str, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def cuentas_w(timelines):
    """{día: {bloque: n}} de la jornada (sin B6)."""
    out = {}
    for day, tl in timelines.items():
        filas = {}
        for h, b in zip(tl["TimeLineHandlers"][:len(L.BLOQUES_TRABAJO)], L.BLOQUES_TRABAJO):
            filas[b["id"]] = len(h["TimeLineEvents"])
        out[day] = filas
    return out


def cuentas_b6_w(timelines):
    return {day: len(tl["TimeLineHandlers"][len(L.BLOQUES_TRABAJO)]["TimeLineEvents"])
            for day, tl in timelines.items()}


def mapa_a_texto(mapa):
    return ",".join(f"{k}:{mapa[k]}" for k in sorted(mapa))


def _mapa_desde_t0(t0: str):
    d0 = datetime.strptime(t0, "%Y-%m-%d")
    return {(d0 + timedelta(days=i)).strftime("%Y-%m-%d"): i + 1 for i in range(3)}


def escribir_calendario(outdir, timelines, mapa, raiz="."):
    dir_lx = _dir_recetas_linux(raiz)
    cuentas = cuentas_w(timelines)
    camp_acc = cuentas_b6_w(timelines)
    total = sum(sum(v.values()) for v in cuentas.values())
    cal = {
        "receta_version": VERSION_RECETA_W,
        "plataforma": PLATAFORMA,
        "boveda_version": BOVEDA_VERSION,
        "espejo_de": {
            "receta_linux": "Soporte/Laboratorio/legitimo_72h/recetas/d{1,2,3}.json",
            "sha256": {f"d{d}": sha256_file(os.path.join(dir_lx, f"d{d}.json"))
                       for d in (1, 2, 3)},
            "regla": "mismos handlers, mismos UtcTimeOn/Off, mismos DelayAfter",
        },
        "zona": "Europe/Madrid (CET=UTC+1 desde 2026-10-25)",
        "dia_local": "09:00-18:00",
        "jornada_utc": {"on": L.JORNADA[0], "off": L.JORNADA[1]},
        "bloques": L.BLOQUES,
        "cuentas": {str(k): v for k, v in cuentas.items()},
        "total_ventana": total,
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
            "marcas": 2 * len(campana.IDS),
            "fuente": "campana/campana_casos.csv (Linux) traducida a W-01…W-11",
            "base": BASE_CAMP_W,
            "mapeo_casos": MAPEO_CASOS,
            "no_mutante": True,
            "efectos_declarados": [
                "eventcreate: 1 evento en el registro de aplicaciones (W-10)",
                "curl.exe: peticiones HTTP a la intranet local (fuera de la víctima)",
            ],
        },
        "total_con_campana": total + sum(camp_acc.values()),
        "mapa_dias": mapa,
        "regla_dia": "k = 1 + ((fecha_utc - fecha_t0) mod 3)",
        "mapa_dias_como_se_pasa": ("construir_receta_legitima_windows.py --t0 AAAA-MM-DD "
                                   "(o --mapa-dias a:1,b:2,c:3)"),
        "cwd": {"base": HOME_W, "regla": "cd /d <carpeta> && <comando>",
                "carpetas": list(CARPETAS_PERFIL),
                "campana": BASE_CAMP_W,
                "nota": "0 acciones en C:\\Windows\\System32 ni en el directorio del cliente"},
        "errores": {"por_dia": 10, "familias": list(L.FAMILIAS_ERROR), "registro": REGISTRO_W,
                    "formato": "TSV de 5 campos: ts · tipo · familia · comando · rc",
                    "rc": "rc=ge1 (cmd solo da umbral); rc=0 en el reintento que funciona"},
        "hueco_max_intra_bloque_s": L.CAP_HUECO_S,
        "hueco_min_s": L.MIN_HUECO_S,
        "pausas_largas_s": {k: v for k, v in L.PAUSA_LARGA.items() if v},
        "fuente": "_artefactos/scripts/construir_receta_legitima_windows.py",
    }
    escribir_json(os.path.join(outdir, "calendario_windows.json"), cal)

    lineas = [
        "# bloques y pausas de la receta legitima Windows (UTC). Generado; NO editar a mano.",
        f"# jornada {L.JORNADA[0]} - {L.JORNADA[1]} UTC (09:00-18:00 local) - ESPEJO de Linux",
        "# B6 (17:05-17:50Z) es la campana declarada: NO es jornada de trabajo.",
        f"TFG_RECETA_VERSION={VERSION_RECETA_W}",
        f"TFG_PLATAFORMA={PLATAFORMA}",
        f"TFG_BOVEDA_VERSION={BOVEDA_VERSION}",
        f"TFG_JORNADA={L.JORNADA[0]}-{L.JORNADA[1]}",
        f"TFG_CWD_BASE={HOME_W}",
        f"TFG_REGISTRO_ERRORES={REGISTRO_W}",
        f"TFG_CAMPANA_BASE={BASE_CAMP_W}",
        "TFG_ESPEJO_DE=legitimo_72h/recetas",
    ]
    for b in L.BLOQUES:
        lineas.append(f"{b['id']}={b['on'][:5]}-{b['off'][:5]} {b['tipo']}")
    lineas += [
        "# campana de falsos positivos B6 (W-01..W-11): mismos conteos que Linux.",
        "TFG_CAMPANA_VERSION=1",
        f"TFG_CAMPANA_CASOS={len(campana.IDS)}",
        f"TFG_CAMPANA_ACCIONES={sum(camp_acc.values())}",
        f"TFG_CAMPANA_MARCAS={2 * len(campana.IDS)}",
        "TFG_CAMPANA_INICIOS=" + ",".join(f"d{k}:{v}" for k, v in campana.INICIOS_PLAN.items()),
        "TFG_CAMPANA_REPARTO=" + ",".join(f"d{k}:{v}" for k, v in campana.REPARTO.items()),
        f"TFG_CAMPANA_SEPARACION_MIN_S={campana.SEPARACION_MIN_S}",
        "# mapeo de dias de la ventana (fecha_utc del dia -> fichero de receta).",
        ("# fijado con --t0/--mapa-dias." if mapa else
         "# VACIO a proposito: se fija al armar la ventana con --t0 AAAA-MM-DD."),
        f"TFG_MAPA_DIAS={mapa_a_texto(mapa) if mapa else ''}",
    ]
    with open(os.path.join(outdir, "bloques_windows.env"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


# --------------------------------------------------------------------------
# Resumen legible
# --------------------------------------------------------------------------
TABLA_TRADUCCION = [
    ("estructura de carpetas", "`mkdir -p`",
     "`(if not exist <dir> md <dir>) & …` (idempotente: días 2 y 3 no fallan)"),
    ("fecha/hora", "`date -u +%FT%TZ`", "`echo %DATE% %TIME%` (local; sin ISO/UTC en `cmd`)"),
    ("listar", "`ls -la` / `ls -l`", "`dir`"),
    ("leer", "`cat`", "`type`"),
    ("copiar / mover / borrar", "`cp -f` / `mv -f` / `rm -f` / `rm -rf`",
     "`copy /y` / `move /y` / `del /f /q` / `rd /s /q` (una orden por ruta)"),
    ("contar", "`wc -l` / `wc -c`", '`find /c /v ""` / `dir`'),
    ("tamaño", "`du -sh` / `du -sb`", "`dir /s`"),
    ("disco", "`df -h /`", "`dir C:\\` (la última línea da los bytes libres)"),
    ("memoria / inventario", "`free -m` / `stat`", "`systeminfo` / `dir`"),
    ("red", "`ip -brief addr` / `ip route`", "`ipconfig /all` / `route print`"),
    ("huellas", "`sha256sum` / `md5sum` / `openssl dgst -sha256`",
     "`certutil -hashfile <f> SHA256|MD5` (`> <f>.sha256` cuando la huella se guarda)"),
    ("empaquetar", "`tar -czf` / `gzip -kf`", "`tar -czf` (bsdtar de Windows 10)"),
    ("desempaquetar (error)", "`gzip -d`", "`tar -xzf` de algo que no es un tar (falla)"),
    ("buscar", "`find -type f` / `grep -c` / `grep`",
     "`dir /b /s /a-d` / `find /c` / `findstr /c:`"),
    ("recortes de texto", "`head -n N` / `tail -n N`", "`more +0` / `more` (aproximado)"),
    ("sincronizar", "`rsync -a --delete`", "`robocopy /MIR /NFL /NDL /NJH /NJS /NP`"),
    ("web", "`curl` (`-A/-b/-c/-e/-H/-o/-w/-T/--data`)", "`curl.exe` (mismos flags)"),
    ("descarga", "`wget -q -O`", "`curl.exe -sS -o`"),
    ("acotar espera", "`timeout 5 curl …`", "`curl.exe --max-time 5 …`"),
    ("registro de aplicación", "`logger -t ofimatica`",
     "`eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO ofimatica /D \"…\"`"),
    ("bitácora", "`tee -a f < nota`", "`type nota >> f`"),
    ("generar lote", "`seq 1 12`", "`for /L %i in (1,1,12) do @echo %i`"),
    ("fan-out", "`xargs -I{} cp`",
     "`for /f %i in (lotes.txt) do @cmd /c copy /y` (12 hijos)"),
    ("servicios / tareas (lectura)", "`systemctl` / `crontab -l`",
     "`sc query state= all` / `tasklist /svc` / `schtasks /query` / `reg query`"),
]

TABLA_ERRORES = [
    ("`ruta_mal`", "`dir …\\informe`", "`dir …\\informes`"),
    ("`cp_dir`", "`copy /y f …\\informes_2026\\f.bak`", "`copy /y f …\\informes\\f.bak`"),
    ("`opcion`", "`dir /max-depth=1 C:\\`", "`dir C:\\`"),
    ("`opcion`", "`dir /clasificar …`", "`dir /a …`"),
    ("`gzip`", "`tar -xzf …\\informe.txt -C …`", "`tar -czf …\\informe.txt.gz -C … informe.txt`"),
    ("`rm_inexistente`", "`type …\\tmp_borradores.csv`",
     "`del /f /q …\\tmp_borradores.csv`"),
    ("`cat_dir`", "`type …\\actas`", "`type …\\informes\\informe.bak`"),
]
#: Nota obligatoria de la familia `rm_inexistente` (W-2): en Windows `del` de un fichero
#: ausente **no** falla (rc=0); el fallo se materializa con `type` del mismo temporal.
NOTA_RM_INEXISTENTE = (
    "`rm_inexistente`: `del` de un fichero que no existe devuelve **rc=0** en Windows (en "
    "Linux `rm` devuelve 1), así que el **fallo** se escribe con `type` del mismo temporal: "
    "abrir el fichero que ya no está sí falla (rc=1). El reintento (`del /f /q`) es el que "
    "deja limpio y devuelve rc=0.")


def escribir_resumen(outdir, timelines):
    cuentas = cuentas_w(timelines)
    camp_acc = cuentas_b6_w(timelines)
    tot = {d: sum(cuentas[d].values()) for d in (1, 2, 3)}
    total = sum(tot.values())
    total_camp = sum(camp_acc.values())
    lineas = [
        "# `receta_windows_resumen.md` — receta Windows **espejo** de la de Linux",
        "",
        "> Generado por `_artefactos/scripts/construir_receta_legitima_windows.py` (receta",
        f"> Windows v{VERSION_RECETA_W}, bloque `windows-legit-prep`, tanda **W1**). El ritmo **no**",
        "> se inventa: se copia del vector `DelayAfter` de `legitimo_72h/recetas/d{1,2,3}.json`",
        "> (**traslado por ranuras**, plan §D2). Solo cambian los **comandos**.",
        "",
        "## Tabla de espejo (medida, no declarada)",
        "",
        "| Día | Bloque | UTC | Acciones Linux | Acciones Windows | Huecos |",
        "|---|---|---|---|---|---|",
    ]
    for day in (1, 2, 3):
        tl = timelines[day]
        for i, b in enumerate(L.BLOQUES_TRABAJO):
            n = len(tl["TimeLineHandlers"][i]["TimeLineEvents"])
            lineas.append(f"| w{day} | {b['id']} | {b['on'][:5]}–{b['off'][:5]} | {n} | {n} | "
                          f"{max(0, n - 1)} (`DelayAfter` idéntico) |")
        lineas.append(f"| w{day} | B6 | 17:05–17:50 | {camp_acc[day]} | {camp_acc[day]} | "
                      "idéntico (campaña) |")
        lineas.append(f"| **w{day}** | **jornada** | 08:00–17:00 | **{tot[day]}** | "
                      f"**{tot[day]}** | **{max(0, tot[day] - 1)}** |")
    lineas += [
        "",
        f"**Total ventana (3 días):** **{total}** acciones de jornada + **{total_camp}** de "
        f"campaña = **{total + total_camp}** acciones GHOSTS (idéntico a Linux).",
        "",
        "## Qué cambia y qué no",
        "",
        "| Elemento | Linux | Windows | ¿Cambia? |",
        "|---|---|---|---|",
        "| Handler (`HandlerType`) | `Command` → `bash -c` | `Command` → `cmd /c` (`Cmd.cs:106`) "
        "| sí (shell) |",
        "| Ventanas `UtcTimeOn/Off` | 08:00–17:00Z + B6 17:05–17:50Z | **las mismas** | no |",
        "| Nº de acciones y `DelayAfter` | 147/153/141 + 16/25/22 | **los mismos** | no |",
        "| `cwd` | `cd /home/angel/… && ` | `cd /d C:\\Users\\angel\\… && ` | misma regla |",
        "| Errores | 10/día, `$?` exacto, `printf` TSV | 10/día, `if errorlevel`, `echo` TSV | "
        "sí (sintaxis y granularidad del `rc`) |",
        "| Herramientas | corpus de ataques Linux | ruleset + inventario P1-Windows | sí (fuente) |",
        "",
        "## Traducción aplicada (Linux → Windows)",
        "",
        "| Familia | Linux | Windows |",
        "|---|---|---|",
    ]
    for fam, lx, wx in TABLA_TRADUCCION:
        lineas.append(f"| {fam} | {lx} | {wx} |")

    lineas += [
        "",
        "## Comandos **sin equivalente exacto** (y qué se hizo)",
        "",
        "| # | Linux | Qué se hizo en Windows | Qué se pierde |",
        "|---|---|---|---|",
        "| T-1 | `date -u +%FT%TZ` | `echo %DATE% %TIME%` | hora **local** y sin formato ISO: "
        "`cmd` no tiene reloj UTC sin PowerShell. La hora UTC de cada acción se ancla con el "
        "`timestamp` de Wazuh (W-V9) |",
        "| T-2 | `head -n 5` / `tail -n 5` | `more +0` / `more` | no hay recorte exacto por "
        "número de líneas sin PowerShell: se muestran las primeras pantallas |",
        "| T-3 | `sed -i 's/;/,/g'` (jornada) | se reescribe la cabecera normalizada "
        "(`export_comas.csv`) | no se transforman las filas de datos (en la **campaña** W-07 sí "
        "se transforma, con PowerShell, como fija el plan §5.2) |",
        "| T-4 | `gzip -kf` / `gzip -d` | `tar -czf` / `tar -xzf` | el `.gz` lo produce `tar` |",
        "| T-5 | `openssl dgst -sha256` | `certutil -hashfile … SHA256` | mismo algoritmo, otra "
        "herramienta |",
        "| T-6 | `wget -q -O` | `curl.exe -sS -o` | sin `wget` nativo (plan N-9) |",
        "| T-7 | `timeout 5 curl` | `curl.exe --max-time 5` | mismo límite, otra vía |",
        "| T-8 | `rsync -a --delete` | `robocopy /MIR` | `robocopy` da 0–7 como éxito y ≥ 8 como "
        "fallo |",
        "| T-9 | `du -sh` / `du -sb` | `dir /s` | formato distinto (bytes + cabecera) |",
        "| T-10 | `logger -t` | `eventcreate … /D \"…\"` | escribe en el registro de "
        "**aplicaciones** (1 evento declarado, no se borra); puede exigir elevación (WE0-7) |",
        "| T-11 | `rm -f` | `del /f /q` | `del` no tiene `-f`, pero **sin `if exist`** ya "
        "devuelve rc=0 cuando el fichero no está (en Windows no es un error) |",
        "| T-12 | `cp` con destino directorio | `copy /y` con nombre de destino | `copy` no "
        "acepta un directorio como destino sin nombre |",
        "| T-13 | fecha en el nombre (`llegada_$(date).txt`) | sin fecha (`llegada.txt`) | "
        "`%DATE%` lleva `/`, inválido en un nombre de fichero |",
        "",
        "## Los casos escritos a mano en PowerShell",
        "",
        "PowerShell **solo** sustituye a lo que no existe en `cmd`: el cifrado, el borrado "
        "seguro y la normalización de CSV. El **borrado seguro** se usa además en la "
        "**jornada** (B4, `shred`, herramienta del corpus, 1/día) con el mismo guion: es el "
        "único uso de PowerShell fuera de la campaña. Total: **7 acciones** (3 de jornada + "
        "4 de campaña).",
        "",
        "| Caso | Qué hace el `-Command` | Proceso | Telemetría distinta esperada |",
        "|---|---|---|---|",
        "| **W-04** (`C-05`, cifrar) | AES-256-CBC con clave/IV fijos (`[byte[]](0..31)` y "
        "`(0..15)`), `TransformFinalBlock` y `WriteAllBytes` | 1 `powershell.exe` | **4104** "
        "(ScriptBlockLogging, reglas `91801-91846`) con el script en claro + Sysmon 1 "
        "(`powershell.exe` con `-Command`); Linux no tiene canal equivalente |",
        "| **W-04** (`C-05`, descifrar) | el mismo AES en modo descifrado → `informe.txt.rec` | "
        "1 `powershell.exe` | **4104** + `certutil -hashfile` posterior, que prueba que el "
        "descifrado devuelve el original |",
        "| **W-05** (`C-06`, borrado seguro) | sobrescribe con ceros, luego con un patrón "
        "determinista `(i*37)%251`, y **borra** | 1 `powershell.exe` | **4104** + Sysmon 11 "
        "(FileWrite) antes del borrado; `shred` no deja rastro equivalente en Windows |",
        "| W-07 (`C-08`, CSV) | `$c = (Get-Content) -replace ';',','; Set-Content -Value $c` "
        "(**sin pipe**, D-01) | 1 `powershell.exe` | **4104** (previsto en el "
        "plan §5.2) |",
        "",
        "> Clave/IV son **constantes de laboratorio** (no un secreto): el caso tiene que ser "
        "reproducible y determinista, como `-pass pass:demo-c05` en Linux.",
        "",
        "## Procesos: 1 acción = 1 `cmd.exe`",
        "",
        "El `Command` de la receta **no** lleva `cmd /c` porque el handler ya lo añade "
        "(`Cmd.cs:106`); ponerlo daría `cmd /c cmd /c …` y un proceso de más por acción. "
        "La única excepción declarada es el **fan-out** (`for … do @cmd /c copy`), donde el "
        "`cmd` hijo **es** el proceso que hace de `cp` (12 hijos, como en Linux). "
        f"**{total + total_camp}** entradas = **{total + total_camp}** `cmd.exe` (la misma "
        "unidad que «1 acción = 1 `bash -c`» en Linux).",
        "",
        "Acciones con **hijos** (las mismas que en Linux; no se multiplican):",
        "",
        "| Acción | Linux | Windows | Hijos |",
        "|---|---|---|---|",
        "| lote de 12 copias (B3 `xargs`, diario) | 1 `xargs` + 12 `cp` | 1 `cmd` + 12 "
        "`cmd /c copy` | 12 |",
        "| generación del lote (B3 `seq`) | 1 `seq` | bucle interno de `cmd` (`echo` es "
        "builtin) | 0 |",
        "| requisitos web (B1) | 1 acción con 3 `curl` | 1 acción con 3 `curl.exe` | 3 |",
        "| huellas dobles | 1 `sha256sum` con 2 ficheros | 1 acción con 2 `certutil` | 2 |",
        "| W-09 (`C-10`) | 1 `xargs` + 12 `cp` | 1 `cmd` + 12 `cmd /c copy` (plan §5.2) | 12 |",
        "",
        "**Acciones que cambian de número de procesos respecto de Linux: 0.** Lo que cambia "
        "es el **hijo**, no la unidad: en Windows `dir`, `type`, `copy`, `del`, `md`, `echo`, "
        "`if` y `for` son **builtins** (sin hijo); en Linux eran binarios. Afecta al recuento "
        "de eventos de proceso (`67027`), no al de acciones.",
        "",
        "## Errores humanos (10/día, con reintento)",
        "",
        "| Familia | Comando que FALLA | Reintento correcto |",
        "|---|---|---|",
    ]
    for fam, mal, bien in TABLA_ERRORES:
        lineas.append(f"| {fam} | {mal} | {bien} |")
    lineas += [
        "",
        "> " + NOTA_RM_INEXISTENTE,
        "",
        "Registro: `C:\\Users\\angel\\Documentos\\errores.log`, **5 campos TSV** "
        "(`ts · tipo · familia · comando · rc`). `ts` = `%DATE%_%TIME%` (local) y el `rc` es "
        "`rc=ge1` en el fallo y `rc=0`/`rc=ge1` en el reintento: `cmd` no da el número exacto "
        "sin una acción extra de PowerShell (plan §4.4, descartada para no añadir procesos).",
        "",
        "Patrón (no expande `%ERRORLEVEL%` antes de ejecutar):",
        "",
        "```bat",
        "cd /d C:\\Users\\angel\\Documentos && dir C:\\Users\\angel\\Documentos\\informe>nul "
        "2>&1 & if errorlevel 1 (>> C:\\Users\\angel\\Documentos\\errores.log echo "
        "%DATE%_%TIME%\terror\truta_mal\tdir C:\\Users\\angel\\Documentos\\informe\trc=ge1)",
        "```",
        "",
        "## Correcciones de la prueba en seco (W-1…W-4)",
        "",
        "| # | Síntoma medido | Causa | Arreglo |",
        "|---|---|---|---|",
        "| W-1 | 48 procesos fallidos, **0 ficheros** en el lote de 12 | `xcopy` con un "
        "fichero suelto y destino inexistente pregunta «¿archivo o directorio?» y sale rc=2 | "
        "`for … do @cmd /c copy /y …` (12 hijos, mismos ficheros que Linux) |",
        "| W-2 | **9** líneas `error`/día en vez de 10 | `del` de un fichero ausente devuelve "
        "**rc=0** en Windows | el fallo de `rm_inexistente` se hace con `type` del mismo "
        "temporal (rc=1) |",
        "| W-3 | el registro del reintento y el `fin.txt` de W-09 no se escribían | un `if` "
        "falso (o un `if exist` de un fichero ausente) **se traga el resto de la línea** | "
        "`rm -f` sin `if exist`; marcas `inicio.txt`/`fin.txt` separadas con `&`; `mkdir` con "
        "cada `if` entre paréntesis |",
        "| W-4 | **rc=1** en la estructura de los días 2 y 3 | `md` de una carpeta existente "
        "falla | `(if not exist <dir> md <dir>)` |",
        "",
        "> Comprobado **ejecutando** los comandos en un sandbox de Windows: "
        "`_artefactos/scripts/tests/test_ejecucion_windows.py` (12 ficheros del fan-out, "
        "10+10 líneas de error/reintento, `fin.txt` de los 11 casos).",
        "",
        "## Riesgos abiertos (se cierran en WE0, no aquí)",
        "",
        "| # | Qué | Qué se hace si falla |",
        "|---|---|---|",
        "| R1 | **`where` de las herramientas** (`curl`, `tar`, `robocopy`, `certutil`, "
        "`find`, `findstr`, `more`, `eventcreate`, `sc`, `tasklist`, `schtasks`, `reg`, "
        "`systeminfo`, `ipconfig`, `route`) como `angel` (WE0-2b) | se **cae esa "
        "herramienta** y su acción se sustituye por otra nativa; **no se instala** (plan P-2) |",
        "| R2 | **`rc` de los errores de builtin** (`dir /max-depth=1`, `dir /clasificar`, "
        "`del`, `type` de una carpeta) en WE0-5 | si un switch inválido devolviera `rc=0`, el "
        "par se sustituye por `certutil -hashfile … MD6` (fallo seguro) y se declara |",
        "| R3 | **`eventcreate` como `angel`** (WE0-7): puede exigir elevación | se degrada a "
        "**lectura** (`wevtutil qe Application /c:5 /rd:true /f:text`) y se declara: afecta a "
        "1 acción/día (`registro`) y al caso **W-10** |",
        "| R4 | **`C:\\Users\\angel` bajo FIM** (R-W8) | si está vigilado, el numerador se "
        "dispara: la actividad se mueve a `C:\\lab-legit` en W3 y se declara (sin tocar el FIM) |",
        "| R5 | **`more` con salida redirigida** | si falla, `head`/`tail` se sustituyen por "
        "`findstr /n` y se declara la pérdida del recorte exacto |",
        "",
        "## Cómo se comprueba",
        "",
        "```bash",
        "python _artefactos/scripts/construir_receta_legitima_windows.py          # genera",
        "python _artefactos/scripts/construir_receta_legitima_windows.py --check   # valida",
        "python _artefactos/scripts/verificar_espejo.py                            # espejo",
        "```",
        "",
        "## Desviaciones declaradas respecto del plan",
        "",
        "| # | Plan | Artefacto | Por qué |",
        "|---|---|---|---|",
        "| DW-1 | `Soporte/Laboratorio/windows_legit/recetas_windows/` (§16.1) | "
        "`Soporte/Laboratorio/windows/recetas/` | destino pedido en la tanda W1; el generador "
        "acepta `--out` para escribir en la ruta del plan sin tocar código |",
        "| DW-2 | `construir_receta_windows.py` (§16.1) | "
        "`construir_receta_legitima_windows.py` | nombre pedido en W1 y coherente con el "
        "generador Linux |",
        "| DW-3 | ficheros `d1/d2/d3.json` | `w1/w2/w3.json` | para no confundir la receta "
        "Windows con la Linux; el mapeo es 1:1 (w1↔d1) |",
        "| DW-4 | `t0` sin fijar | `mapa_dias` vacío | se fija al armar la ventana (`--t0`), "
        "igual que en Linux |",
        "",
    ]
    with open(os.path.join(outdir, "receta_windows_resumen.md"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")


# --------------------------------------------------------------------------
# Generación
# --------------------------------------------------------------------------
def generar(outdir: str, raiz: str = ".", mapa=None, verbose=True):
    datos = cargar_linux(raiz)
    timelines = {day: construir_timeline(datos[day]) for day in (1, 2, 3)}
    os.makedirs(outdir, exist_ok=True)
    for day in (1, 2, 3):
        escribir_json(os.path.join(outdir, f"w{day}.json"), timelines[day])
    escribir_calendario(outdir, timelines, mapa or {}, raiz)
    escribir_resumen(outdir, timelines)
    if verbose:
        c, cb = cuentas_w(timelines), cuentas_b6_w(timelines)
        for day in (1, 2, 3):
            print(f"w{day}.json  jornada={sum(c[day].values())}  B6={cb[day]}  "
                  f"total={sum(c[day].values()) + cb[day]}")
    return timelines


# --------------------------------------------------------------------------
# Validador
# --------------------------------------------------------------------------
def validar(outdir: str, mapa_esperado=None, verbose=True):
    fallos, avisos, datos = [], [], {}
    for day in (1, 2, 3):
        path = os.path.join(outdir, f"w{day}.json")
        if not os.path.isfile(path):
            fallos.append(f"falta {path}")
            continue
        tl = json.load(open(path, encoding="utf-8"))
        datos[day] = tl
        hs = tl.get("TimeLineHandlers", [])
        if tl.get("Status") != "Run":
            fallos.append(f"w{day}: Status != Run")
        extra = set(tl) - {"Status", "TimeLineHandlers"}
        if extra:
            fallos.append(f"w{day}: claves no admitidas en la timeline: {sorted(extra)}")
        if len(hs) != len(L.BLOQUES_TRABAJO) + 1:
            fallos.append(f"w{day}: {len(hs)} handlers (se esperan "
                          f"{len(L.BLOQUES_TRABAJO)} + B6)")
            continue
        total = 0
        for h, b in zip(hs[:len(L.BLOQUES_TRABAJO)], L.BLOQUES_TRABAJO):
            bid = b["id"]
            if h.get("HandlerType") != "Command":
                fallos.append(f"w{day}/{bid}: HandlerType={h.get('HandlerType')}")
            if not h.get("Loop"):
                fallos.append(f"w{day}/{bid}: Loop != true")
            if h.get("HandlerArgs"):
                fallos.append(f"w{day}/{bid}: HandlerArgs no vacío")
            if h.get("UtcTimeOn") != b["on"] or h.get("UtcTimeOff") != b["off"]:
                fallos.append(f"w{day}/{bid}: ventana {h.get('UtcTimeOn')}-{h.get('UtcTimeOff')}"
                              f" != {b['on']}-{b['off']}")
            total += len(h["TimeLineEvents"])
            for j, ev in enumerate(h["TimeLineEvents"]):
                fallos += [f"w{day}/{bid} #{j}: {f}" for f in validar_comando(ev["Command"])]
        if total != sum(L.CUENTAS[day].values()):
            fallos.append(f"w{day}: total {total} != {sum(L.CUENTAS[day].values())}")
        # B6
        h6 = hs[len(L.BLOQUES_TRABAJO)]
        esp = campana.acciones_b6(day)
        if h6["UtcTimeOn"] != campana.s_to_hms(esp[0]["t"]):
            fallos.append(f"w{day}/B6: UtcTimeOn no es el primer inicio de la campaña")
        if h6["UtcTimeOff"] != campana.B6["off"]:
            fallos.append(f"w{day}/B6: UtcTimeOff != {campana.B6['off']}")
        if len(h6["TimeLineEvents"]) != len(esp):
            fallos.append(f"w{day}/B6: {len(h6['TimeLineEvents'])} eventos != {len(esp)}")
        for j, ev in enumerate(h6["TimeLineEvents"]):
            fallos += [f"w{day}/B6 #{j}: {f}" for f in validar_comando(ev["Command"])]

    # errores: 10 fallos + 10 reintentos por día, emparejados y con 5 campos
    for day, tl in datos.items():
        if len(tl.get("TimeLineHandlers", [])) != len(L.BLOQUES_TRABAJO) + 1:
            continue
        n_err = n_reint = 0
        for h, b in zip(tl["TimeLineHandlers"][:len(L.BLOQUES_TRABAJO)], L.BLOQUES_TRABAJO):
            evs = h["TimeLineEvents"]
            for i, ev in enumerate(evs):
                m = RE_ERRLOG.search(ev["Command"])
                if not m:
                    continue
                tipo, fam = m.group("tipo"), m.group("fam")
                if fam not in L.FAMILIAS_ERROR:
                    fallos.append(f"w{day}/{b['id']}: familia '{fam}' no permitida")
                if "if errorlevel 1" not in ev["Command"]:
                    fallos.append(f"w{day}/{b['id']}: sin `if errorlevel` ({tipo}/{fam})")
                if "%ERRORLEVEL%" in ev["Command"]:
                    fallos.append(f"w{day}/{b['id']}: usa %ERRORLEVEL% (se expande antes)")
                if m.group("log") != REGISTRO_W:
                    fallos.append(f"w{day}/{b['id']}: registro fuera de errores.log")
                if m.group("rc") not in ("rc=ge1", "rc=0"):
                    fallos.append(f"w{day}/{b['id']}: rc mal formado ({m.group('rc')})")
                if tipo == "error":
                    n_err += 1
                    if i + 1 >= len(evs):
                        fallos.append(f"w{day}/{b['id']}: error sin reintento ({fam})")
                        continue
                    s = RE_ERRLOG.search(evs[i + 1]["Command"])
                    if not s or s.group("tipo") != "reintento" or s.group("fam") != fam:
                        fallos.append(f"w{day}/{b['id']}: el reintento de '{fam}' no va "
                                      f"después")
                    elif s.group("cmd") == m.group("cmd"):
                        fallos.append(f"w{day}/{b['id']}: el reintento repite el comando")
                    else:
                        n_reint += 1
                else:
                    p = RE_ERRLOG.search(evs[i - 1]["Command"]) if i else None
                    if not p or p.group("tipo") != "error" or p.group("fam") != fam:
                        fallos.append(f"w{day}/{b['id']}: reintento sin fallo previo")
        if n_err != 10:
            fallos.append(f"w{day}: {n_err} errores (se exigen 10/día)")
        if n_reint != n_err:
            fallos.append(f"w{day}: {n_reint} reintentos != {n_err} errores")

    # PowerShell: en la campaña (cifrado/borrado/CSV) y, en la jornada, **solo** el
    # borrado seguro (`shred`, mecanismo M4: no hay equivalente nativo).
    for day, tl in datos.items():
        for i, h in enumerate(tl.get("TimeLineHandlers", [])):
            for j, ev in enumerate(h["TimeLineEvents"]):
                if "powershell" not in ev["Command"]:
                    continue
                bloque = "B6" if i >= len(L.BLOQUES_TRABAJO) else L.BLOQUES_TRABAJO[i]["id"]
                if bloque != "B6" and "Remove-Item -LiteralPath" not in ev["Command"]:
                    fallos.append(f"w{day}/{bloque} #{j}: PowerShell fuera de los casos "
                                  f"declarados")
                if "-EncodedCommand" in ev["Command"] or "-WindowStyle" in ev["Command"]:
                    fallos.append(f"w{day}/{bloque} #{j}: opción de evasión")

    # calendario / env / resumen
    cal_path = os.path.join(outdir, "calendario_windows.json")
    if not os.path.isfile(cal_path):
        fallos.append("falta calendario_windows.json")
    else:
        cal = json.load(open(cal_path, encoding="utf-8"))
        if cal.get("plataforma") != PLATAFORMA:
            fallos.append("calendario_windows.json: plataforma != windows")
        if cal.get("boveda_version") != BOVEDA_VERSION:
            fallos.append("calendario_windows.json: boveda_version != 3")
        if datos:
            cuentas = cuentas_w(datos)
            if cal.get("cuentas") != {str(k): v for k, v in cuentas.items()}:
                fallos.append("calendario_windows.json: cuentas distintas de las generadas")
            if (cal.get("campana") or {}).get("acciones") != {
                    f"d{k}": v for k, v in cuentas_b6_w(datos).items()}:
                fallos.append("calendario_windows.json: campana.acciones incorrecta")
        if (cal.get("cwd") or {}).get("base") != HOME_W:
            fallos.append("calendario_windows.json: cwd.base incorrecto")
        if mapa_esperado is not None and (cal.get("mapa_dias") or {}) != mapa_esperado:
            fallos.append("calendario_windows.json: mapa_dias no coincide con el parámetro")
    env_path = os.path.join(outdir, "bloques_windows.env")
    if not os.path.isfile(env_path):
        fallos.append("falta bloques_windows.env")
    else:
        env = {}
        for linea in open(env_path, encoding="utf-8"):
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            k, v = linea.split("=", 1)
            env[k.strip()] = v.strip()
        esperado = {
            "TFG_RECETA_VERSION": str(VERSION_RECETA_W),
            "TFG_PLATAFORMA": PLATAFORMA,
            "TFG_BOVEDA_VERSION": str(BOVEDA_VERSION),
            "TFG_CWD_BASE": HOME_W,
            "TFG_REGISTRO_ERRORES": REGISTRO_W,
            "TFG_CAMPANA_BASE": BASE_CAMP_W,
            "TFG_CAMPANA_CASOS": str(len(campana.IDS)),
            "TFG_CAMPANA_MARCAS": str(2 * len(campana.IDS)),
        }
        for k, v in esperado.items():
            if env.get(k) != v:
                fallos.append(f"bloques_windows.env: {k} incorrecto ({env.get(k)!r} != {v!r})")
        for b in L.BLOQUES:
            if env.get(b["id"]) != f"{b['on'][:5]}-{b['off'][:5]} {b['tipo']}":
                fallos.append(f"bloques_windows.env: línea {b['id']} incorrecta")
        mapa_env = {}
        if env.get("TFG_MAPA_DIAS"):
            try:
                for par in env["TFG_MAPA_DIAS"].split(","):
                    f, kk = par.split(":")
                    mapa_env[f.strip()] = int(kk)
            except ValueError:
                fallos.append("bloques_windows.env: TFG_MAPA_DIAS con formato inválido")
        if mapa_esperado is not None and mapa_env != mapa_esperado:
            fallos.append("bloques_windows.env: TFG_MAPA_DIAS no coincide con el parámetro")
    if not os.path.isfile(os.path.join(outdir, "receta_windows_resumen.md")):
        fallos.append("falta receta_windows_resumen.md")

    resumen = {"dias": ({d: sum(cuentas_w(datos)[d].values()) for d in (1, 2, 3)}
                        if datos else {}),
               "campana": cuentas_b6_w(datos) if datos else {},
               "fallos": fallos, "avisos": avisos}
    if verbose:
        for f in fallos:
            print("FALLO:", f)
        for a in avisos:
            print("aviso:", a)
    return resumen


def validar_comando(cmd):
    """Invariantes de una acción Windows (CA-W1/CA-W3) y unidad de proceso."""
    fallos = []
    if not isinstance(cmd, str) or not cmd.strip():
        return ["comando vacío"]
    # El handler ya antepone `cmd /c`: un `cmd /c` **de primer nivel** sería un doble
    # envoltorio. Dentro de un bucle (`… do @cmd /c copy …`, fan-out de 12) es legítimo.
    if re.search(r"(?:^|&)\s*cmd /c\b", cmd, re.I):
        fallos.append(f"`cmd /c` de primer nivel (doble envoltorio): {cmd[:80]}")
    if cmd.count('"') % 2:
        fallos.append(f"comillas descompensadas: {cmd[:80]}")
    if "%RANDOM%" in cmd or "Get-Random" in cmd:
        fallos.append(f"aleatoriedad prohibida: {cmd[:80]}")
    if "-EncodedCommand" in cmd or "-WindowStyle" in cmd or "-ExecutionPolicy" in cmd:
        fallos.append(f"opción de evasión: {cmd[:80]}")
    if "^" in cmd:
        fallos.append(f"`^` prohibido (R-W9): {cmd[:80]}")
    if "`" in cmd:
        fallos.append(f"backtick prohibido: {cmd[:80]}")
    for pat in MUTANTES:
        if re.search(pat, cmd, re.I):
            fallos.append(f"comando mutante ({pat}): {cmd[:80]}")
    if "|" in cmd:
        fallos.append(f"`|` prohibido (GHOSTS pierde el reporte, D-01): {cmd[:80]}")
    if "%{" in cmd and ("%DATE%" in cmd or "%TIME%" in cmd):
        fallos.append(f"`%{{...}}` junto a `%VAR%` (expansión): {cmd[:80]}")
    m = re.match(r"^cd /d (\S+) && \S", cmd)
    if not m:
        fallos.append(f"sin prefijo `cd /d <carpeta> && `: {cmd[:80]}")
    else:
        d = m.group(1)
        if not (d in DIRS_CWD_W or d.startswith(BASE_CAMP_W + "\\")):
            fallos.append(f"cwd no admitido {d}: {cmd[:80]}")
        if "System32" in cmd or "ghosts-client" in cmd.lower():
            fallos.append(f"cwd/comando prohibido (System32/cliente): {cmd[:80]}")
    return fallos


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Receta legítima Windows (espejo de Linux)")
    ap.add_argument("--out", default=os.path.join(RAIZ, "Soporte", "Laboratorio", "windows",
                                                 "recetas"))
    ap.add_argument("--raiz", default=RAIZ, help="raíz del repositorio")
    ap.add_argument("--t0", default=None, help="fecha UTC del día 1 (AAAA-MM-DD)")
    ap.add_argument("--mapa-dias", default=None, help="a:1,b:2,c:3")
    ap.add_argument("--check", action="store_true", help="valida lo versionado (no escribe)")
    ap.add_argument("--silencio", action="store_true")
    args = ap.parse_args(argv)

    mapa = {}
    if args.t0:
        mapa = _mapa_desde_t0(args.t0)
    elif args.mapa_dias:
        try:
            for par in args.mapa_dias.split(","):
                f, k = par.split(":")
                mapa[f.strip()] = int(k)
        except ValueError:
            print("ERROR: --mapa-dias con formato inválido")
            return 2
        if sorted(mapa.values()) != [1, 2, 3]:
            print("ERROR: --mapa-dias debe tener los días 1, 2 y 3")
            return 2
    esperado = mapa or None

    if args.check:
        res = validar(args.out, mapa_esperado=esperado, verbose=not args.silencio)
        if res["fallos"]:
            print(f"FALLA — {len(res['fallos'])} fallo(s)")
            return 1
        print(f"PASA — w1/w2/w3 = {res['dias']} (jornada) + {res['campana']} (campaña)")
        return 0
    generar(args.out, raiz=args.raiz, mapa=mapa, verbose=not args.silencio)
    res = validar(args.out, mapa_esperado=esperado, verbose=False)
    if res["fallos"]:
        for f in res["fallos"]:
            print("FALLO:", f)
        return 1
    print(f"OK — {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
