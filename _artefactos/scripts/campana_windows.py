#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""campana_windows.py — campaña `B6` de Windows (bloque `windows-legit-prep`, W2).

**No ejecuta nada.** Documenta, valida y sella los **11 casos espejo** de la campaña
de Linux (`legitimo_72h/campana/campana_casos.csv`) en su versión Windows:

- **Comandos literales**: se leen de los **handlers B6** de las recetas ya generadas
  (`Soporte/Laboratorio/windows/recetas/w{1,2,3}.json`), que son las que ejecutará
  GHOSTS. No se copian a mano: la campaña documentada y la que corre son la misma.
- **Metadatos** (nombre, mecanismo, técnicas, esperado, evidencia, coste, por qué es
  legítimo): viven en este módulo y se publican en `campana_windows.csv` +
  `casos_windows.md` (este último con su `sha256` en la cabecera del CSV).

Qué se valida (`--check`):

1. **11 casos** (`W-01`…`W-11`), reparto **3/4/4** e inicios **17:06/17:17/17:11**.
2. **22 marcas** (`inicio`/`fin` en cada caso) y **63 acciones** (idénticas a Linux).
3. **0 mutación**: ni `schtasks /create`, ni `reg add`, ni `sc create/config`, ni
   `net user`, ni `msiexec`, ni instalación; **0 escrituras** fuera de la carpeta del caso.
4. **0 pipes** fuera de `powershell -Command` (regla H-1 del bloque Linux).
5. **Esperado por umbral**: `N ≥ 7` = 0 en todos; `N ≥ 3` cita `67027` (predicción).
6. **Evidencia** de efecto (`hecho.txt` con `RESULTADO=OK`) y efectos declarados.
7. **Coherencia con `w*.json`**: mismo comando, mismo orden, misma hora que el CSV; y
   mismas horas que la campaña de Linux (espejo por ranuras).

> **Naturaleza de la evidencia.** En Linux la campaña se derivó del **corpus de
> ataques** (4 107 detecciones `80792`). **No existe corpus Windows** (§N-1 del plan),
> así que aquí el «esperado» es una **predicción** por umbral, no una medida. Las
> reglas de Windows citadas (`67027`, `91801-91846`, `92200-92227`, `60600-61072`)
> son **hipótesis** salvo `67027`, que está observada en la baseline histórica.

Uso:
    python campana_windows.py --docs        # regenera casos_windows.md y sella el CSV
    python campana_windows.py --check       # valida campaña, docs, sha y recetas
    python campana_windows.py --no-mutacion # auditoría literal (0 en todo)
    python campana_windows.py --reparto     # reparto, huecos y ventanas
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re

# --------------------------------------------------------------------------
# Constantes (una sola fuente; el CSV manda sobre comandos y metadatos)
# --------------------------------------------------------------------------
CAMPANA_REL = ("Soporte", "Laboratorio", "windows", "campana")
RECETAS_REL = ("Soporte", "Laboratorio", "windows", "recetas")
CSV_NAME = "campana_windows.csv"
MD_NAME = "casos_windows.md"

BASE = r"C:\lab-legit\campana"

#: Bloque declarado de la campaña (NO es jornada de trabajo; plan §4.1 y §5.2).
B6 = {
    "id": "B6",
    "on": "17:05:00",
    "off": "17:50:00",
    "tipo": "campana",
    "nombre": "Repaso del sistema",
}

#: Jitter fijo de inicio por día (idéntico a Linux).
INICIOS_PLAN = {1: "17:06:00", 2: "17:17:00", 3: "17:11:00"}
#: Reparto 3/4/4.
REPARTO = {1: 3, 2: 4, 3: 4}
#: Separación mínima entre el fin de un caso y el inicio del siguiente.
SEPARACION_MIN_S = 180
#: Ventana de atribución de alertas: `[ini - 10 s, fin + 60 s]`.
ATRIB_PRE_S = 10
ATRIB_POST_S = 60

#: Regla de creación de proceso (L3) observada en la baseline del 08/10 (132 de 159).
#: Es el ancla funcional de `80792` en Linux, **no** una regla de detección (§18.6).
RULE_EXEC = "67027"
#: Umbral de «FP de verdad» y umbral de «se ejecutó».
UMBRAL_N7 = 7
UMBRAL_N3 = 3

#: Identificadores pre-registrados (11; C-04 no tiene espejo: no mutación).
IDS = ("W-01", "W-02", "W-03", "W-04", "W-05", "W-06",
       "W-07", "W-08", "W-09", "W-10", "W-11")

#: C-XX de Linux ↔ W-XX de Windows (C-04 retirada en Linux v4 y también aquí).
MAPEO = {
    "W-01": "C-01", "W-02": "C-02", "W-03": "C-03", "W-04": "C-05",
    "W-05": "C-06", "W-06": "C-07", "W-07": "C-08", "W-08": "C-09",
    "W-09": "C-10", "W-10": "C-11", "W-11": "C-12",
}

#: Columnas del CSV (orden estable). Una fila por **caso** (11); los comandos van en
#: `comandos`, separados por saltos de línea dentro del campo entrecomillado, y su tipo
#: en `tipos`, en el mismo orden.
COLS = [
    "caso", "nombre", "dia", "hora_inicio", "mecanismo", "muta", "binarios",
    "tecnica", "ata_linux", "rule_ids", "esperado_n7", "esperado_n3",
    "efecto_declarado", "evidencia", "coste", "por_que", "tipos", "comandos",
]
COLS_META = [c for c in COLS if c not in ("caso", "tipos", "comandos")]

TIPOS = ("inicio", "comando", "evidencia", "fin")

#: Metadatos por caso. **Predicción declarada**: nombres, técnicas y esperado salen
#: del plan §5.2 y del inventario P1-Windows, no de un corpus Windows (no existe).
META = {
    "W-01": {
        "nombre": "El equipo va lento: miro memoria y servicios",
        "binarios": "systeminfo;sc;tasklist",
        "tecnica": "T1057;T1082;T1007",
        "ata_linux": "ATA004;ATA045;ATA038",
        "rule_ids": "67027",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con «RESULTADO=OK», el recuento de servicios.txt "
                     "(> 10), free.txt (>= 3) y fallidos.txt",
        "coste": "3 min · <1 MB",
        "por_que": "Cualquier empleado mira el estado del equipo y sus servicios "
                   "cuando el portátil va lento, antes de abrir una incidencia. Solo "
                   "lectura: `systeminfo`, `sc query` y `tasklist` no cambian nada.",
    },
    "W-02": {
        "nombre": "No me va la intranet: miro la red",
        "binarios": "ipconfig;route",
        "tecnica": "T1016;T1018",
        "ata_linux": "ATA054;ATA055",
        "rule_ids": "67027",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con la IPv4 192.168.65.x (findstr) y la tabla de rutas",
        "coste": "2 min · <1 MB",
        "por_que": "Comprobar la IP y la puerta de enlace es el primer paso cuando una "
                   "web interna no carga. `ipconfig /all` y `route print` son de "
                   "lectura: no se usa `netsh` ni `route add`.",
    },
    "W-03": {
        "nombre": "Compruebo si la copia esta programada",
        "binarios": "schtasks;reg",
        "tecnica": "T1053.005;T1547.001",
        "ata_linux": "ATA021;ATA004",
        "rule_ids": "67027",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con el nº de tareas (find /c) y tarea_rc=0/ge1",
        "coste": "2 min · <1 MB",
        "por_que": "Comprobar si la copia automática está programada es una duda "
                   "corriente. `schtasks /query` y `reg query` solo leen; no hay "
                   "`/create`, ni `reg add`, ni `sc config`.",
    },
    "W-04": {
        "nombre": "Protejo el informe antes de enviarlo (cifrado, parcial)",
        "binarios": "powershell;certutil",
        "tecnica": "T1486",
        "ata_linux": "ATA001;ATA019;ATA041",
        "rule_ids": "67027;91801-91846",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con las dos huellas SHA256 (original == descifrado)",
        "coste": "4 min · <1 MB",
        "por_que": "Proteger un informe con datos de cliente antes de enviarlo es "
                   "práctica de oficina. El fichero es de juguete y la clave es fija y "
                   "simbólica. **Parcial**: Windows 10 Pro no trae cifrado simétrico "
                   "con contrasena por linea de comandos sin instalar (§N-4); se pierde "
                   "la variante `openssl enc -pass` de T1486.",
    },
    "W-05": {
        "nombre": "Limpio temporales y destruyo un borrador (parcial)",
        "binarios": "powershell",
        "tecnica": "T1070.004;T1485",
        "ata_linux": "ATA003;ATA005",
        "rule_ids": "67027;91801-91846",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con el tamaño previo y borrador_ausente=1",
        "coste": "2 min · <1 MB",
        "por_que": "Borrar temporales y destruir un borrador con datos personales es "
                   "lo que recomienda cualquier manual de protección de datos. Los dos "
                   "objetos los crea el propio caso. **Parcial**: `cipher /w:` reescribe "
                   "el espacio libre 3 veces (GB y horas de disco, §N-5); se sustituye "
                   "por sobrescritura del propio fichero en PowerShell.",
    },
    "W-06": {
        "nombre": "Sincronizo los informes con la carpeta de copias",
        "binarios": "robocopy",
        "tecnica": "T1039;T1074.001",
        "ata_linux": "ATA039;ATA040",
        "rule_ids": "67027;92200-92227",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con dir /s de origen y destino (mismo tamaño) y dir "
                     "del destino",
        "coste": "3 min · <1 MB",
        "por_que": "Sincronizar la carpeta de informes con la de copias es lo que hace "
                   "cualquiera que haya perdido un fichero una vez. Origen y destino son "
                   "del caso; `/MIR` solo afecta a `W-06\\destino\\`.",
    },
    "W-07": {
        "nombre": "Normalizo el CSV del informe",
        "binarios": "powershell",
        "tecnica": "T1565.001",
        "ata_linux": "ATA006;ATA032;ATA026;ATA017",
        "rule_ids": "67027;91801-91846",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con el CSV normalizado (more) y el recuento de `;`",
        "coste": "2 min · <1 MB",
        "por_que": "Cambiar el separador de un export para abrirlo en Excel es una "
                   "tarea de oficina diaria. El único fichero que se reescribe es el del "
                   "caso; el pipe vive **dentro** de `powershell -Command` (§4.5).",
    },
    "W-08": {
        "nombre": "La intranet no responde: acoto el tiempo y reintento",
        "binarios": "curl.exe",
        "tecnica": "T1071.001;T1048",
        "ata_linux": "ATA025;ATA009;ATA010;ATA020;ATA023;ATA028;ATA041;ATA050",
        "rule_ids": "67027",
        "efecto_declarado": "descargas_http",
        "evidencia": "hecho.txt con http_code, fallo_rc, reintento_rc y el tamaño de "
                     "intranet.html",
        "coste": "3 min · <1 MB",
        "por_que": "Cuando una web interna no responde, el usuario acota el tiempo de "
                   "espera y reintenta. Los puertos son de la intranet local: 8080 "
                   "(abierto) y 8081 (cerrado, el «no responde»).",
    },
    "W-09": {
        "nombre": "Preparo el lote de plantillas del mes",
        "binarios": "copy",
        "tecnica": "T1499.002;T1499.003",
        "ata_linux": "ATA046;ATA047",
        "rule_ids": "67027;92200-92227",
        "efecto_declarado": "",
        "evidencia": "hecho.txt con el tamaño de lote_12.txt y dir de lote_*.txt",
        "coste": "4 min · <1 MB",
        "por_que": "Preparar doce copias de una plantilla para el lote del mes es "
                   "mecánico y corriente. **Cambia de mecanismo**: Windows no tiene "
                   "`xargs`; se conserva el abanico de 12 con `for /L` + `cmd /c copy`.",
    },
    "W-10": {
        "nombre": "Dejo constancia de la incidencia en el registro",
        "binarios": "eventcreate",
        "tecnica": "T1056.001",
        "ata_linux": "ATA018",
        "rule_ids": "67027;60600-61072",
        "efecto_declarado": "registro_eventos",
        "evidencia": "hecho.txt con el contenido de registro.log",
        "coste": "2 min · <1 MB",
        "por_que": "Dejar constancia de una incidencia en el registro de la aplicación "
                   "es lo que pide cualquier procedimiento. Escribe **1 evento** "
                   "INFORMATION declarado que no se borra (borrarlo sería otra mutación).",
    },
    "W-11": {
        "nombre": "Descargo el manual de la intranet",
        "binarios": "curl.exe",
        "tecnica": "T1105",
        "ata_linux": "ATA008;ATA043",
        "rule_ids": "67027",
        "efecto_declarado": "descargas_http",
        "evidencia": "hecho.txt con el éxito y el tamaño de manual.pdf (> 500 bytes)",
        "coste": "2 min · <1 MB",
        "por_que": "Descargar el manual del empleado desde la intranet es lo que hace "
                   "cualquiera el primer día. **Desviación declarada**: el plan preveía "
                   "`certutil -urlcache`; la receta (W1) usa solo `curl.exe` porque "
                   "`certutil -urlcache` es un patrón clásico de detección y habría "
                   "mezclado la hipótesis con el mecanismo.",
    },
}

#: Efectos **declarados** fuera de la carpeta del caso (los dos únicos).
EFECTOS_DECLARADOS = {
    "descargas_http": {
        "descripcion": "cuatro peticiones HTTP a la intranet local (W-08: dos a `:8080` y "
                       "un intento a `:8081`; W-11: una a `:8080`); las **tres** que "
                       "llegan al 8080 dejan rastro en el `web_access.log` del "
                       "**servidor**, fuera de la víctima",
        "verbos": ("curl.exe",),
    },
    "registro_eventos": {
        "descripcion": "un evento INFORMATION (ID 100, origen `ofimatica`) en el registro "
                       "**Application** de la víctima (W-10); no se borra (borrarlo sería "
                       "otra mutación)",
        "verbos": ("eventcreate",),
    },
}

#: Tabla de equivalencia Linux ↔ Windows (se publica en `casos_windows.md`).
EQUIVALENCIA = [
    {"linux": "C-01", "win": "W-01",
     "mecanismo": "descubrimiento de procesos, memoria y servicios (`free` + `systemctl`)",
     "cambia": "`systeminfo` + `sc query state= all` + `tasklist /svc`",
     "comparable": "sí"},
    {"linux": "C-02", "win": "W-02",
     "mecanismo": "lectura de la configuración de red (`ip addr` + `ip route`)",
     "cambia": "`ipconfig /all` + `route print`",
     "comparable": "sí"},
    {"linux": "C-03", "win": "W-03",
     "mecanismo": "comprobar la copia programada (`systemctl list-timers` + `crontab -l`)",
     "cambia": "`schtasks /query` + `reg query …\\Run` (los dos de lectura)",
     "comparable": "sí (mismo mecanismo; la regla que puede saltar es otra)"},
    {"linux": "C-04", "win": "—",
     "mecanismo": "persistencia benigna (crear y quitar una tarea programada)",
     "cambia": "no existe: retirada en Linux (v4) y en Windows por la misma decisión",
     "comparable": "**no** (sin espejo: no mutación)"},
    {"linux": "C-05", "win": "W-04",
     "mecanismo": "cifrar un informe antes de enviarlo (`openssl enc -pass`)",
     "cambia": "AES en PowerShell con clave fija + `certutil -hashfile`",
     "comparable": "**parcial**: se pierde el cifrado con contraseña (T1486 legítimo)"},
    {"linux": "C-06", "win": "W-05",
     "mecanismo": "borrar temporales y destruir un borrador (`rm -rf` + `shred`)",
     "cambia": "`rd /s /q` + sobrescritura y borrado en PowerShell (sin `cipher /w:`)",
     "comparable": "**parcial**: se pierde el borrado seguro de espacio libre (T1561)"},
    {"linux": "C-07", "win": "W-06",
     "mecanismo": "sincronizar informes con la carpeta de copias (`rsync --delete`)",
     "cambia": "`robocopy … /MIR`",
     "comparable": "sí (mismo fan-in/fan-out local)"},
    {"linux": "C-08", "win": "W-07",
     "mecanismo": "normalizar un CSV (`sed -i 's/;/ /g'`)",
     "cambia": "`powershell -Command … -replace ';',',' \\| Set-Content` (4104 real)",
     "comparable": "sí (mismo fichero reescrito; Windows añade telemetría 4104)"},
    {"linux": "C-09", "win": "W-08",
     "mecanismo": "intranet que no responde: acotar tiempo y reintentar (`curl`+`timeout`)",
     "cambia": "`curl.exe --max-time` ×3 (8080, 8081, 8080) sin `timeout`",
     "comparable": "sí (mismas peticiones y mismo reintento)"},
    {"linux": "C-10", "win": "W-09",
     "mecanismo": "abanico de 12 copias de una plantilla (`seq`+`xargs`+`cp`)",
     "cambia": "`for /L %i in (1,1,12) do @cmd /c copy`",
     "comparable": "sí (mismo fan-out de 12; cambia el shell, no la forma)"},
    {"linux": "C-11", "win": "W-10",
     "mecanismo": "dejar constancia en el registro del sistema (`logger` + `tee`)",
     "cambia": "`eventcreate /T INFORMATION /L APPLICATION` + `type >>`",
     "comparable": "**parcial**: `eventcreate` puede exigir elevación (WE0-7); si falla "
                   "se degrada a lectura y se declara"},
    {"linux": "C-12", "win": "W-11",
     "mecanismo": "descargar el manual de la intranet (`wget`)",
     "cambia": "`curl.exe -o`",
     "comparable": "sí (misma descarga; `curl.exe` está en Windows 10 ≥ 1803)"},
]

#: Verbos que mutan el sistema: 0 en toda la campaña (se audita literalmente).
REGLAS_MUTACION = {
    "schtasks de escritura": r"\bschtasks(?:\.exe)?\s+/(create|delete|change|run|end)\b",
    "reg de escritura": r"\breg(?:\.exe)?\s+(add|delete|import|copy|restore|load|unload|save)\b",
    "sc de escritura": r"\bsc(?:\.exe)?\s+(create|delete|config|start|stop|pause|continue|"
                       r"failure|sdset)\b",
    "cuentas (net user/localgroup)": r"\bnet(?:\.exe)?\s+(user|localgroup|group)\b[^\n]*"
                                     r"/(add|delete)\b",
    "servicios (net start/stop)": r"\bnet(?:\.exe)?\s+(start|stop)\b",
    "instalación (msiexec/wusa/dism/winget/choco)": r"\b(msiexec|wusa|dism|winget|choco)\b",
    "arranque/volumen (bcdedit/vssadmin/cipher /w/format/diskpart)":
        r"\b(bcdedit|vssadmin|cipher\s+/w|format|diskpart)\b",
    "ACL (icacls /grant|/deny)": r"\bicacls(?:\.exe)?\b[^\n]*/(grant|deny|setowner|reset)\b",
    "registro de eventos (wevtutil cl/sl)": r"\bwevtutil(?:\.exe)?\s+(cl|sl)\b",
    "aleatoriedad": r"(%RANDOM%|Get-Random)",
    "evasión (-EncodedCommand/-WindowStyle/-ExecutionPolicy)":
        r"(-EncodedCommand|-WindowStyle|-ExecutionPolicy)",
}

RE_TEC = re.compile(r"^T\d{4}(?:\.\d{3})?$")
RE_ATA = re.compile(r"^ATA\d{3}$")
RE_HORA = re.compile(r"^\d{2}:\d{2}:\d{2}$")
RE_CARPETA = re.compile(r"\\W-(\d{2})\\")
RE_ABS = re.compile(r"[A-Za-z]:\\[^\s\"';&|)]+")


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


def dir_recetas(raiz=None) -> str:
    return os.path.join(raiz_repo(raiz), *RECETAS_REL)


def sha256_file(path: str) -> str:
    import hashlib
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


# --------------------------------------------------------------------------
# Recetas: comandos literales de B6 (fuente de la campaña que se ejecutará)
# --------------------------------------------------------------------------
def leer_b6(raiz=None):
    """Devuelve `{día: handler B6}` leído de `w{1,2,3}.json` (+ fallos)."""
    fallos, out = [], {}
    for dia in (1, 2, 3):
        path = os.path.join(dir_recetas(raiz), f"w{dia}.json")
        if not os.path.isfile(path):
            fallos.append(f"falta {path}")
            continue
        tl = json.load(open(path, encoding="utf-8"))
        hs = tl.get("TimeLineHandlers", [])
        if not hs:
            fallos.append(f"w{dia}.json sin TimeLineHandlers")
            continue
        h = hs[-1]
        if h.get("UtcTimeOff") != B6["off"]:
            fallos.append(f"w{dia}.json: el último handler no cierra a {B6['off']}")
        out[dia] = h
    return out, fallos


def construir_casos(raiz=None):
    """Construye `{W-XX: {"meta": {...}, "acciones": [...]}}` desde `w*.json` + META."""
    handlers, fallos = leer_b6(raiz)
    if fallos:
        raise SystemExit("ERROR: " + "; ".join(fallos))
    casos = {}
    for dia in (1, 2, 3):
        h = handlers[dia]
        t = hms_to_s(h["UtcTimeOn"])
        actual = None
        for ev in h["TimeLineEvents"]:
            cmd = ev["Command"]
            m = RE_CARPETA.search(cmd)
            cid = f"W-{m.group(1)}" if m else None
            if cid and re.search(r"\\inicio\.txt", cmd):
                if cid in casos:
                    raise SystemExit(f"ERROR: {cid} abre dos veces")
                actual = cid
                casos[cid] = {"meta": {"dia": str(dia), "hora_inicio": s_to_hms(t)},
                              "acciones": []}
            if actual is None:
                raise SystemExit(f"ERROR: w{dia}.json tiene eventos antes del primer "
                                 f"`inicio.txt`")
            if cid and cid != actual:
                raise SystemExit(f"ERROR: w{dia}.json mezcla {actual} y {cid}")
            if re.search(r"\\inicio\.txt", cmd):
                tipo = "inicio"
            elif re.search(r"\\fin\.txt", cmd):
                tipo = "fin"
            elif re.search(r"\\hecho\.txt", cmd) and "RESULTADO=OK" in cmd:
                tipo = "evidencia"
            else:
                tipo = "comando"
            casos[actual]["acciones"].append({
                "orden": len(casos[actual]["acciones"]) + 1,
                "tipo": tipo,
                "comando": cmd,
                "hora": s_to_hms(t),
            })
            t += int(ev.get("DelayAfter", 0)) // 1000
    if set(casos) != set(IDS):
        raise SystemExit(f"ERROR: casos en las recetas {sorted(casos)} != {list(IDS)}")
    for cid, c in casos.items():
        if cid not in META:
            raise SystemExit(f"ERROR: falta META de {cid}")
        meta = dict(META[cid])
        meta["mecanismo"] = MAPEO[cid]
        meta["muta"] = "No"
        meta["esperado_n7"] = "0"
        n = len(c["acciones"])
        if cid == "W-09":
            n += 12  # fan-out: 12 `cmd /c copy` hijos
        meta["esperado_n3"] = f"{RULE_EXEC} L3 >={n} (1 cmd.exe por acción; predicción)"
        c["meta"] = {**c["meta"], **meta}
    return dict(sorted(casos.items()))


# --------------------------------------------------------------------------
# Lectura / render del CSV canónico
# --------------------------------------------------------------------------
def _filas_csv(path: str):
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = fh.readlines()
    i = 0
    while i < len(lineas) and lineas[i].startswith("#"):
        i += 1
    return list(csv.DictReader(io.StringIO("".join(lineas[i:]))))


def cargar(raiz=None):
    path = ruta_csv(raiz)
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: falta {path} (genera con `--docs`)")
    rd = _filas_csv(path)
    if rd and list(rd[0].keys()) != COLS:
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


CABECERA_CSV = (
    "# campana_windows.csv · campana B6-W (bloque windows-legit-prep, W2) · "
    "{n} casos · {m} marcas · {a} acciones · sha256_casos_md={sha} · "
    "fuente=casos_windows.md · plataforma=windows · boveda_version=3 · "
    "corpus_windows=NO_EXISTE (prediccion) · plan=5.2")


def _cabecera_comentarios(sha_md: str, casos) -> str:
    acciones = sum(len(c["acciones"]) for c in casos.values())
    marcas = sum(1 for c in casos.values() for a in c["acciones"]
                 if a["tipo"] in ("inicio", "fin"))
    return CABECERA_CSV.format(n=len(casos), m=marcas, a=acciones, sha=sha_md)


def render_csv(casos, sha_md: str) -> str:
    buf = io.StringIO()
    buf.write(_cabecera_comentarios(sha_md, casos) + "\n")
    w = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(COLS)
    for cid, c in casos.items():
        accs = sorted(c["acciones"], key=lambda a: a["orden"])
        fila = {"caso": cid, **c["meta"],
                "tipos": "\n".join(a["tipo"] for a in accs),
                "comandos": "\n".join(a["comando"] for a in accs)}
        w.writerow([fila.get(k, "") for k in COLS])
    return buf.getvalue()


def _ficha_md(cid, caso) -> list:
    meta = caso["meta"]
    accs = sorted(caso["acciones"], key=lambda a: a["orden"])
    tecs = [x for x in meta["tecnica"].split(";") if x]
    atas = [x for x in meta["ata_linux"].split(";") if x]
    bins = ", ".join(f"`{x}`" for x in meta["binarios"].split(";") if x)
    efecto = meta["efecto_declarado"] or "ninguno fuera de su carpeta"
    return [
        f"### {cid} · {meta['nombre']}",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| Día · hora (UTC) | `d{meta['dia']}` · **{meta['hora_inicio']}** |",
        f"| Mecanismo (espejo de) | `{meta['mecanismo']}` |",
        f"| Herramientas | {bins} |",
        f"| Se confunde con (MITRE) | {'; '.join(f'`{t}`' for t in tecs)} |",
        f"| Corpus **Linux** con el mismo mecanismo | "
        f"{'; '.join(f'`{a}`' for a in atas)} — **no hay corpus Windows** |",
        f"| `rule_id` hipotéticos (predicción) | "
        f"`{'`, `'.join(x for x in meta['rule_ids'].split(';') if x)}` |",
        f"| **Esperado `N ≥ 7`** | **{meta['esperado_n7']} alertas** (predicción: ningún "
        f"FP «de verdad») |",
        f"| **Esperado `N ≥ 3`** | **{meta['esperado_n3']}** |",
        f"| ¿Cambia la máquina? | **{meta['muta']}** (solo escribe bajo `{BASE}\\{cid}\\`) |",
        f"| Efecto declarado | {efecto} |",
        f"| Evidencia de efecto | {meta['evidencia']} |",
        f"| Coste · disco | {meta['coste']} |",
        f"| Por qué es legítimo | {meta['por_que']} |",
        "",
        "**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):",
        "",
    ] + [f"{a['orden']}. `{a['tipo']}` — `{a['comando']}`" for a in accs] + [
        "",
        "**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la "
        "fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay "
        "marcas, pero no prueba de efecto), no un 0-alerta.",
        "",
    ]


def render_md(casos) -> str:
    total = sum(len(c["acciones"]) for c in casos.values())
    marcas = sum(1 for c in casos.values() for a in c["acciones"]
                 if a["tipo"] in ("inicio", "fin"))
    comparables = sum(1 for e in EQUIVALENCIA if e["comparable"].startswith("sí"))
    parciales = sum(1 for e in EQUIVALENCIA if e["comparable"].startswith("**parcial"))
    lineas = [
        "# `casos_windows.md` — campaña de falsos positivos de Windows (`B6`, 11 casos)",
        "",
        "> **Pre-registro; `sha256` en la cabecera de `campana_windows.csv`.** Este fichero",
        "> se **genera** desde los comandos literales de `recetas/w{1,2,3}.json` + los",
        "> metadatos de `campana_windows.py`. **No se edita a mano.**",
        ">",
        "> ⚠️ **Es una predicción, no una medida.** En Linux la campaña se derivó del corpus",
        "> de ataques (4 107 detecciones `80792`). **No existe corpus de ataques Windows**",
        "> (plan §N-1): las reglas citadas son **hipótesis** salvo `67027`, que es la regla de",
        "> creación de proceso observada en la baseline del 08/10 (132 de 159 alertas).",
        "",
        "> **Bloque `B6` «repaso del sistema» = 17:05–17:50Z**, **11 casos** en **3/4/4**",
        "> días, inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11) y",
        "> separación **≥ 3 min**. Atribución: `timestamp ∈ [ini − 10 s, fin + 60 s]`.",
        f"> **{total} acciones GHOSTS** ({marcas} de ellas son las marcas `inicio`/`fin`).",
        "",
        "## Qué mide y por qué está dentro de la ventana",
        "",
        "La campaña **no** fabrica ataques: hace **11 tareas de oficina corrientes** que un",
        "empleado ejecutaría en el mismo portátil, con las **mismas herramientas** que el",
        "ruleset y el inventario P1-Windows señalan como sospechosas. Se ejecuta **dentro**",
        "de `[t0, t1]`, en un bloque **declarado**, y se publica **aparte**",
        "(`campana_fp_windows.csv`), sin recalcular `M` ni un FPR alternativo.",
        "",
        "**No mutante** (misma definición que Linux): todo lo que se crea vive bajo",
        f"`{BASE}\\W-XX\\` y **se borra dentro del propio caso**; no se toca el Programador",
        "de tareas, **no se modifica la configuración del registro**, ni los servicios, las",
        "cuentas, el arranque o rutas del sistema. **W-10 escribe 1 evento declarado** en el",
        "registro de aplicaciones (`Application`): no se borra (borrarlo sería otra mutación).",
        "La comprobación literal está en `campana_windows.py --no-mutacion`.",
        "",
        "**Efectos declarados fuera de la carpeta** (son los **dos únicos**):",
        "",
    ]
    for nombre, e in EFECTOS_DECLARADOS.items():
        lineas.append(f"- **`{nombre}`** — {e['descripcion']}.")
    lineas += [
        "",
        "## Tabla de equivalencia Linux ↔ Windows",
        "",
        "> **Cómo leerla.** `mecanismo` es lo que se quiere medir; `cambia` es la diferencia",
        "> técnica; `comparable` dice si la fila se puede comparar **caso a caso** con Linux.",
        "> **No** se comparan recuentos crudos de alertas entre plataformas (§W-L2): se compara",
        "> «¿alertó?, ¿con qué regla?, ¿a qué nivel?».",
        "",
        "| Linux | Windows | Mecanismo compartido | Qué cambia | ¿Comparable por caso? |",
        "|---|---|---|---|---|",
    ]
    for e in EQUIVALENCIA:
        lineas.append(f"| `{e['linux']}` | {('`'+e['win']+'`') if e['win'] != '—' else '—'} "
                      f"| {e['mecanismo']} | {e['cambia']} | {e['comparable']} |")
    lineas += [
        "",
        f"**Recuento:** {comparables} casos comparables, {parciales} parciales y "
        f"**1 sin espejo** (`C-04`, persistencia benigna: retirada por no mutación).",
        "",
        "## Resumen (11 casos · `N ≥ 7` = 0 en todos: predicción)",
        "",
        "| # | Caso | Día | Hora (UTC) | Herramientas | Se confunde con | `N ≥ 7` | "
        "`N ≥ 3` | ¿Muta? | Coste |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for cid in casos:
        c = casos[cid]
        meta = c["meta"]
        tecs = ", ".join(meta["tecnica"].split(";"))
        bins = ", ".join(f"`{x}`" for x in meta["binarios"].split(";") if x)
        n3 = meta["esperado_n3"].split(" (")[0]
        lineas.append(f"| **{cid}** | {meta['nombre']} | d{meta['dia']} | "
                      f"**{meta['hora_inicio']}** | {bins} | {tecs} | "
                      f"**{meta['esperado_n7']}** | {n3} | **{meta['muta']}** | "
                      f"{meta['coste']} |")
    lineas += [
        "",
        "> **Cómo leer los umbrales.** `N ≥ 7` decide si el caso es un FP «de verdad»",
        "> (`P2` o superior); `N ≥ 3` es donde **todo proceso creado** alerta por `67027`",
        "> (hipótesis H-W1, predicción). **No** se promete el número exacto: la cota inferior",
        "> es **1 `cmd.exe` por acción** (el handler ejecuta `cmd /c <comando>`), más 12",
        "> `cmd /c` hijos en `W-09`. Lo exacto **se mide** y lo sella B10-W.",
        "> Si un caso alerta a `N ≥ 7`, **es un hallazgo** y se publica; no se re-ejecuta.",
        "> Si un caso **no** produce `67027`, **no se ejecutó** (no es «0 alertas»).",
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
        "- **Marcas:** `> …\\inicio.txt echo %DATE%_%TIME%` y `…\\fin.txt`. Son **22** "
        "(2 por caso). **Ojo:** `cmd` no formatea ISO/UTC, así que la marca es **hora "
        "local** (`%DATE%_%TIME%`); el extractor solo la convierte si se le pasa el "
        "**desfase declarado** (`--desfase-local`). Sin desfase **no adivina**: deja la "
        "ventana vacía y el caso queda `NO_EVALUABLE`.",
        "- **Atribución:** alerta del agente **`002` (`victima-windows`)** con "
        "`timestamp ∈ [ini − 10 s, fin + 60 s]`. Se cuenta **todo** lo que caiga dentro "
        "(incluido el keepalive, declarado) y se distingue `win_image`/`rule_id`.",
        "- **Evidencia de efecto (obligatoria):** cada caso deja `hecho.txt` con "
        "`RESULTADO=OK` y el predicado de su ficha. Sin `hecho.txt` el caso es "
        "`NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.",
        "- **Limpieza:** los temporales del caso se borran **antes** de `fin.txt`; solo "
        "sobreviven `inicio.txt`, `hecho.txt` y `fin.txt`.",
        "",
        "## Volumen declarado (acciones y procesos)",
        "",
        f"- **Acciones GHOSTS:** **{total}** (**{marcas}** son marcas `inicio`/`fin`; las "
        f"otras **{total - marcas}** son preparación de insumos, comandos propios, "
        "evidencia y limpieza). Idénticas a Linux (16/25/22).",
        "- **Procesos (cota inferior):** **75** = **63 `cmd.exe`** (uno por acción) + **12** "
        "`cmd /c` hijos del fan-out de `W-09`. El recuento real será mayor (herramientas "
        "hijas: `systeminfo`, `sc`, `certutil`, `curl.exe`…); **se mide**.",
        "- **B10-W lo sella:** esta previsión se compara con lo observado (`n_acciones` y "
        "`n_eventos` de `campana_fp_windows.csv`) y se fija en el sello.",
        "",
        "## Prerrequisitos en el invitado (WE0-2b)",
        "",
        "> **Bloqueante:** `C:\\lab-legit\\campana\\` debe existir y ser escribible por",
        "> `angel` **antes de B6**. Todas las acciones empiezan por `cd /d …`; si la carpeta",
        "> no existe, no se escribe ninguna marca y los **11 casos se pierden**",
        "> (`NO_EJECUTADO`).",
        "",
        "| Comprobación (WE0) | Comando | Criterio |",
        "|---|---|---|",
        "| Carpeta de campaña | `if exist C:\\lab-legit\\campana (echo OK)` | `OK` |",
        "| Herramientas | `where systeminfo sc tasklist ipconfig route schtasks reg "
        "powershell certutil robocopy curl.exe eventcreate find findstr more tar` | todas "
        "resuelven |",
        "| Builtins de `cmd` | `copy`, `del`, `rd`, `type`, `dir` | no necesitan `where` |",
        "| Intranet | `curl.exe -sS -o NUL -w \"%{http_code}\" http://intranet.local:8080/` "
        "| `200` |",
        "| Puerto cerrado | `curl.exe -sS --max-time 2 http://intranet.local:8081/` | "
        "rc≠0 (7 o 28) |",
        "| `eventcreate` como `angel` | el comando de W-10 | rc=0 (si no, WE0-7 lo degrada "
        "a lectura y se declara) |",
        "| Disco | `dir C:\\` (bytes libres) | ≥ 40 MB (presupuesto de la campaña) |",
        "",
        "> Si falla la carpeta o una herramienta, **no se arranca B6**: el caso se marca",
        "> `NO_EJECUTADO` y se corrige el deploy (nunca se instala, §P-2).",
        "",
        "## Desviaciones respecto del plan (declaradas)",
        "",
        "| # | Plan | Artefacto | Por qué |",
        "|---|---|---|---|",
        "| D-W1 | W-04 con `tar -a` + `certutil` | **AES en PowerShell + `certutil "
        "-hashfile`** | `tar -a` no cifra; el plan pedía «integridad + empaquetado» y eso "
        "no es T1486. Se conserva el mecanismo (cifrar) con clave fija, sin contraseña |",
        "| D-W2 | W-05 con `del` + `rd` | **`rd /s /q` + sobrescritura en PowerShell** | "
        "`del` de un fichero inexistente devuelve rc=0 en Windows (no es error); el "
        "borrado seguro se escribe a mano (no hay `shred` ni `cipher /w:` asumible) |",
        "| D-W3 | W-11 con `certutil -urlcache` y `curl` | **solo `curl.exe`** | "
        "`certutil -urlcache` es un patrón clásico de detección: usarlo habría mezclado "
        "la hipótesis abierta con el mecanismo. Se retira la hipótesis |",
        "| D-W4 | C-10 con `xargs` | **`for /L` + `cmd /c copy`** | Windows no tiene "
        "`xargs`; se conserva el abanico de 12 procesos |",
        "| D-W5 | «~40 comandos y ~55 procesos» (§5.2) | **63 acciones / 75 procesos "
        "(cota inferior)** | el número exacto lo fija el CSV y lo sella B10-W |",
        "| D-W6 | `campana_windows.md` | **`casos_windows.md`** | el nombre del artefacto "
        "sigue el del espejo de Linux (`casos.md`); el CSV mantiene `campana_windows` |",
        "| D-W7 | familia de error `rm_inexistente` con `del` | **`type` del temporal + "
        "`del` de reintento** | en Windows `del` de un fichero ausente devuelve **rc=0**: "
        "el fallo nunca se registraba. `type` del mismo temporal sí falla (rc=1); el "
        "reintento correcto sigue siendo `del /f /q` |",
        "",
        "> Ninguna desviación añade mutación, ni elevación, ni `|` fuera de PowerShell, ni",
        "> red fuera de la intranet local.",
        "",
        "## Qué es predicción y qué queda para WE0",
        "",
        "| Elemento | Estado |",
        "|---|---|",
        "| Comandos, horas, reparto, marcas y acciones | **medido** (salen de `w*.json`, "
        "que ya pasó `--check` en W1) |",
        "| «No muta», rutas y ausencia de pipes | **verificado** aquí (`--no-mutacion`) |",
        "| Técnicas MITRE y `ATA` Linux | **analogía declarada** (mismo mecanismo; no hay "
        "corpus Windows) |",
        "| `rule_id` esperados salvo `67027` | **hipótesis** (`91801-91846`, `92200-92227`, "
        "`60600-61072`) |",
        "| `N ≥ 7` = 0 y `N ≥ 3` con `67027` | **predicción**; WE0-3/WE0-4 confirman el "
        "mapeo evento→regla |",
        "| `eventcreate` como `angel` | **abierto** (WE0-7) |",
        "| Número exacto de alertas y niveles | **se mide** en la ventana; no se promete |",
        "",
        "## Cómo se comprueba",
        "",
        "```bat",
        "python _artefactos\\scripts\\campana_windows.py --check",
        "python _artefactos\\scripts\\campana_windows.py --no-mutacion",
        "python _artefactos\\scripts\\construir_receta_legitima_windows.py --check",
        "python _artefactos\\scripts\\extraer_campana_windows.py --test",
        "",
        "rem extraccion (fuera de la ventana, tras cosechar)",
        "python _artefactos\\scripts\\extraer_campana_windows.py --solo-ventanas "
        "--evidencia <cosecha> --desfase-local +01:00",
        "python _artefactos\\scripts\\extraer_campana_windows.py --ventanas "
        "campana_ventanas_windows.tsv --alertas <alertas> --acciones <export> "
        "--evidencia <cosecha>",
        "```",
        "",
        "---",
        "",
        "> **Sellado.** El `sha256` de este fichero está en la **primera línea** de",
        "> `campana_windows.csv`. Cualquier cambio en el pre-registro obliga a regenerar",
        "> ambos (`campana_windows.py --docs`) **y a firmarlos otra vez antes de `t0`**.",
        "",
    ]
    return "\n".join(lineas)


def escribir_docs(raiz=None, verbose=True):
    casos = construir_casos(raiz)
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
        print(f"casos_windows.md  {len(md_texto.encode('utf-8'))} bytes  sha256={sha}")
        print(f"campana_windows.csv {len(csv_texto.encode('utf-8'))} bytes  "
              f"filas={len(casos)}  "
              f"acciones={sum(len(c['acciones']) for c in casos.values())}")
    return sha


# --------------------------------------------------------------------------
# Validación estática de comandos (no mutación, H-1, rutas)
# --------------------------------------------------------------------------
def _sin_ps(cmd: str) -> str:
    """Quita el argumento de `powershell -Command "…"` (los pipes internos valen)."""
    return re.sub(r'powershell(?:\.exe)?\s+-NoProfile\s+-Command\s+"[^"]*"', "",
                  cmd, flags=re.S)


def destinos_escritura(cmd: str):
    return [m.group(1) for m in re.finditer(r">>?\s*([^\s&|>]+)", cmd)]


def _destino_ok(dest: str) -> bool:
    d = dest.strip('"')
    if d.lower() in ("nul", "&1", "&2"):
        return True
    if not re.match(r"^[A-Za-z]:\\", d):
        return False
    return d.lower() == BASE.lower() or d.lower().startswith(BASE.lower() + "\\")


def validar_comando(cmd: str):
    """Invariantes de una acción (CA-W3) y no mutación."""
    fallos = []
    if not isinstance(cmd, str) or not cmd.strip():
        return ["comando vacío"]
    # El handler ya antepone `cmd /c`: un `cmd /c` de primer nivel sería doble envoltorio.
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
    for pat in REGLAS_MUTACION.values():
        if re.search(pat, cmd, re.I):
            fallos.append(f"comando mutante ({pat}): {cmd[:80]}")
    # H-1: ningún `|` fuera de un argumento `powershell -Command "…"`.
    if "|" in _sin_ps(cmd):
        fallos.append(f"`|` fuera de PowerShell (GHOSTS pierde el reporte): {cmd[:80]}")
    if "%{" in cmd and ("%DATE%" in cmd or "%TIME%" in cmd):
        fallos.append(f"`%{{...}}` junto a `%VAR%` (expansión): {cmd[:80]}")
    m = re.match(r"^cd /d (\S+) && \S", cmd)
    if not m:
        fallos.append(f"sin prefijo `cd /d <carpeta> && `: {cmd[:80]}")
    else:
        d = m.group(1)
        if not (d.lower() == BASE.lower() or d.lower().startswith(BASE.lower() + "\\")):
            fallos.append(f"cwd fuera de la campaña: {d}")
        if "System32" in cmd or "ghosts-client" in cmd.lower():
            fallos.append(f"cwd/comando prohibido (System32/cliente): {cmd[:80]}")
    for ruta in RE_ABS.findall(cmd):
        if not _destino_ok(ruta):
            fallos.append(f"ruta absoluta fuera de la carpeta del caso: {ruta}")
    for dest in destinos_escritura(cmd):
        if not _destino_ok(dest):
            fallos.append(f"escritura fuera de la carpeta del caso: {dest}")
    return fallos


def validar_efectos(casos=None, declarados=None):
    decl = EFECTOS_DECLARADOS if declarados is None else declarados
    fallos = []
    if not isinstance(decl, dict) or not decl:
        return ["EFECTOS_DECLARADOS vacío o mal formado"]
    casos = casos if casos is not None else cargar()[0]
    texto = "\n".join(a["comando"] for c in casos.values() for a in c["acciones"])
    vistos = {}
    for nombre, e in decl.items():
        if not (e.get("descripcion") or "").strip():
            fallos.append(f"efecto '{nombre}': sin descripción")
        verbos = tuple(e.get("verbos") or ())
        if not verbos:
            fallos.append(f"efecto '{nombre}': sin verbos")
        for v in verbos:
            if v in vistos:
                fallos.append(f"verbo '{v}' declarado en '{vistos[v]}' y en '{nombre}'")
            vistos[v] = nombre
            if not re.search(rf"(?:^|[\s;&|(]){re.escape(v)}(?:$|[\s;&|)])", texto):
                fallos.append(f"efecto '{nombre}': el verbo '{v}' no se usa")
    for nombre, e in decl.items():
        marcados = {cid for cid, c in casos.items()
                    if c["meta"].get("efecto_declarado") == nombre}
        if not marcados:
            fallos.append(f"efecto '{nombre}' declarado pero ningún caso lo asume")
    for cid, c in casos.items():
        e = c["meta"].get("efecto_declarado") or ""
        if e and e not in decl:
            fallos.append(f"{cid}: efecto declarado '{e}' inexistente")
    return fallos


# --------------------------------------------------------------------------
# Validación completa
# --------------------------------------------------------------------------
def validar(raiz=None, comprobar_docs=True):
    fallos, avisos = [], []
    casos, filas = cargar(raiz)

    # --- (a) composición ---
    ids = tuple(casos)
    if ids != IDS:
        fallos.append(f"casos {ids} != {IDS}")
    if len(filas) != len(casos):
        fallos.append("el CSV tiene filas duplicadas o inconsistentes")
    if sorted(c["meta"]["mecanismo"] for c in casos.values()) != \
            sorted(set(MAPEO.values())):
        fallos.append("cada caso debe tener un mecanismo Linux distinto (C-01…C-12)")

    total_marcas = 0
    for dia in (1, 2, 3):
        del_dia = [c for c in casos if casos[c]["meta"]["dia"] == str(dia)]
        if len(del_dia) != REPARTO[dia]:
            fallos.append(f"d{dia}: {len(del_dia)} casos != {REPARTO[dia]}")
        if del_dia:
            primera = min(casos[c]["meta"]["hora_inicio"] for c in del_dia)
            if primera != INICIOS_PLAN[dia]:
                fallos.append(f"d{dia}: primer inicio {primera} != {INICIOS_PLAN[dia]}")

    for cid in casos:
        c = casos[cid]
        meta, accs = c["meta"], sorted(c["acciones"], key=lambda a: a["orden"])
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
        if tipos.count("comando") < 1:
            fallos.append(f"{cid}: sin comandos propios")
        if tipos.index("fin") < max(i for i, t in enumerate(tipos) if t == "evidencia"):
            fallos.append(f"{cid}: `fin` anterior a la evidencia")
        for t in tipos:
            if t not in TIPOS:
                fallos.append(f"{cid}: tipo desconocido '{t}'")
        total_marcas += tipos.count("inicio") + tipos.count("fin")

        # --- marcas locales (`%DATE%_%TIME%`) ---
        carpeta = rf"{BASE}\{cid}"
        ini, fin = accs[0]["comando"], accs[-1]["comando"]
        if f"{carpeta}\\inicio.txt" not in ini or "%DATE%_%TIME%" not in ini:
            fallos.append(f"{cid}: la marca de inicio no sella inicio.txt")
        if f"{carpeta}\\fin.txt" not in fin or "%DATE%_%TIME%" not in fin:
            fallos.append(f"{cid}: la marca de fin no sella fin.txt")
        if not RE_HORA.match(meta["hora_inicio"]):
            fallos.append(f"{cid}: hora mal formada ({meta['hora_inicio']!r})")

        # --- metadatos obligatorios ---
        if meta["mecanismo"] not in MAPEO.values():
            fallos.append(f"{cid}: mecanismo '{meta['mecanismo']}' no es C-XX válido")
        if meta["muta"] != "No":
            fallos.append(f"{cid}: `muta` debe ser No (campaña no mutante)")
        if meta["esperado_n7"] != "0":
            fallos.append(f"{cid}: el esperado N>=7 pre-registrado debe ser 0")
        if RULE_EXEC not in meta["esperado_n3"]:
            fallos.append(f"{cid}: el esperado N>=3 debe citar {RULE_EXEC}")
        if RULE_EXEC not in meta["rule_ids"]:
            fallos.append(f"{cid}: `rule_ids` debe incluir {RULE_EXEC}")
        tecs = [x for x in meta["tecnica"].split(";") if x]
        if not tecs or not all(RE_TEC.match(t) for t in tecs):
            fallos.append(f"{cid}: `tecnica` mal formada: {meta['tecnica']!r}")
        atas = [x for x in meta["ata_linux"].split(";") if x]
        if not atas or not all(RE_ATA.match(a) for a in atas):
            fallos.append(f"{cid}: `ata_linux` mal formado: {meta['ata_linux']!r}")
        if not meta["evidencia"]:
            fallos.append(f"{cid}: sin evidencia de efecto declarada")
        if not meta["coste"]:
            fallos.append(f"{cid}: sin coste declarado")
        if not meta["por_que"]:
            fallos.append(f"{cid}: sin justificación (`por_que`)")

        # --- comandos: reglas duras y no mutación ---
        usados = set()
        for a in accs:
            fallos += [f"{cid}: {f}" for f in validar_comando(a["comando"])]
            if a["tipo"] == "evidencia":
                if f"{carpeta}\\hecho.txt" not in a["comando"]:
                    fallos.append(f"{cid}: la evidencia no escribe hecho.txt")
                if "RESULTADO=OK" not in a["comando"]:
                    fallos.append(f"{cid}: la evidencia no sella RESULTADO=OK")
            if cid not in a["comando"]:
                fallos.append(f"{cid}: acción fuera de su carpeta: {a['comando'][:70]}")
            for tok in re.findall(r"\b([A-Za-z][\w.-]*\.exe)\b", a["comando"]):
                usados.add(tok)
            for tok in re.findall(r"\b(systeminfo|tasklist|certutil|robocopy|"
                                  r"eventcreate|schtasks|ipconfig)\b", a["comando"]):
                usados.add(tok)
        declarados = [x for x in meta["binarios"].split(";") if x]
        sobran = sorted(usados - set(declarados))
        if sobran:
            fallos.append(f"{cid}: binarios sin declarar en `binarios`: {sobran}")
        texto = " ".join(a["comando"] for a in accs)
        faltan = [b for b in declarados
                  if not re.search(rf"(?<![\w.-]){re.escape(b)}(?![\w.-])", texto)]
        if faltan:
            fallos.append(f"{cid}: declarados y no usados: {faltan}")
        vistos = set()
        for a in accs:
            if a["comando"] in vistos:
                fallos.append(f"{cid}: comando repetido literalmente: {a['comando'][:60]}")
            vistos.add(a["comando"])

    if total_marcas != 22:
        fallos.append(f"marcas inicio+fin = {total_marcas} (se exigen 22)")

    # --- (b) tiempos: B6, separación y ventanas de atribución (desde `w*.json`) ---
    handlers, err = leer_b6(raiz)
    if err:
        fallos += err
    else:
        on, off = hms_to_s(B6["on"]), hms_to_s(B6["off"])
        for dia in (1, 2, 3):
            h = handlers[dia]
            t = hms_to_s(h["UtcTimeOn"])
            ini, fin = {}, {}
            for ev in h["TimeLineEvents"]:
                cmd = ev["Command"]
                m = RE_CARPETA.search(cmd)
                cid = f"W-{m.group(1)}" if m else None
                if cid and re.search(r"\\inicio\.txt", cmd):
                    ini[cid] = t
                if cid and re.search(r"\\fin\.txt", cmd):
                    fin[cid] = t
                t += int(ev.get("DelayAfter", 0)) // 1000
            orden = sorted(ini, key=lambda c: ini[c])
            for cid in orden:
                if not (on <= ini[cid] < off):
                    fallos.append(f"d{dia}: {cid} fuera de B6 "
                                  f"({s_to_hms(ini[cid])})")
                if fin[cid] > off:
                    fallos.append(f"d{dia}: {cid} termina después de {B6['off']}")
            for prev, nxt in zip(orden, orden[1:]):
                if ini[nxt] - fin[prev] < SEPARACION_MIN_S:
                    fallos.append(f"d{dia}: separación {ini[nxt] - fin[prev]} s entre "
                                  f"{prev} y {nxt} (< {SEPARACION_MIN_S} s)")
                if ini[nxt] - ATRIB_PRE_S <= fin[prev] + ATRIB_POST_S:
                    fallos.append(f"d{dia}: ventanas de atribución solapadas {prev}/{nxt}")

    # --- (c) coherencia con las recetas (comando, orden, hora) y con Linux ---
    fallos += _validar_contra_recetas(raiz, casos)

    # --- (d) efectos declarados ---
    fallos += validar_efectos(casos)

    # --- (e) pre-registro: sha256 de casos_windows.md en la cabecera ---
    if comprobar_docs:
        md = ruta_md(raiz)
        if not os.path.isfile(md):
            fallos.append("falta casos_windows.md (genera con `--docs`)")
        else:
            cab = _leer_cabecera(ruta_csv(raiz))
            esperado = sha256_file(md)
            m = next((re.search(r"sha256_casos_md=([0-9a-f]{64})", c) for c in cab
                      if "sha256_casos_md" in c), None)
            if not m:
                fallos.append("la cabecera del CSV no sella sha256_casos_md")
            elif m.group(1) != esperado:
                fallos.append(f"sha256_casos_md de la cabecera ({m.group(1)[:12]}…) no "
                              f"coincide con casos_windows.md ({esperado[:12]}…); "
                              f"ejecuta --docs")
            with open(ruta_csv(raiz), encoding="utf-8", newline="") as fh:
                actual = fh.read()
            if render_csv(casos, esperado) != actual:
                fallos.append("campana_windows.csv no es canónico; ejecuta --docs")
            with open(md, encoding="utf-8", newline="") as fh:
                if render_md(casos) != fh.read():
                    fallos.append("casos_windows.md no coincide con el CSV; ejecuta --docs")

    resumen = {
        "casos": len(casos),
        "marcas": total_marcas,
        "acciones": {d: sum(len(casos[c]["acciones"]) for c in casos
                            if casos[c]["meta"]["dia"] == str(d)) for d in (1, 2, 3)},
        "acciones_total": sum(len(c["acciones"]) for c in casos.values()),
        "mecanismos": sorted(c["meta"]["mecanismo"] for c in casos.values()),
        "fallos": fallos,
        "avisos": avisos,
    }
    return resumen


def _leer_cabecera(path: str):
    with open(path, encoding="utf-8", newline="") as fh:
        return [l.rstrip("\n") for l in fh if l.startswith("#")]


def _validar_contra_recetas(raiz, casos):
    """El CSV debe ser exactamente el B6 de `w*.json`, y las horas las de Linux."""
    fallos = []
    handlers, err = leer_b6(raiz)
    fallos += err
    if err:
        return fallos
    for dia in (1, 2, 3):
        h = handlers[dia]
        t = hms_to_s(h["UtcTimeOn"])
        esperado = []  # (caso, tipo, cmd, hora)
        actual = None
        for ev in h["TimeLineEvents"]:
            cmd = ev["Command"]
            m = RE_CARPETA.search(cmd)
            cid = f"W-{m.group(1)}" if m else None
            if cid and re.search(r"\\inicio\.txt", cmd):
                actual = cid
            if re.search(r"\\inicio\.txt", cmd):
                tipo = "inicio"
            elif re.search(r"\\fin\.txt", cmd):
                tipo = "fin"
            elif re.search(r"\\hecho\.txt", cmd) and "RESULTADO=OK" in cmd:
                tipo = "evidencia"
            else:
                tipo = "comando"
            esperado.append((actual, tipo, cmd, s_to_hms(t)))
            t += int(ev.get("DelayAfter", 0)) // 1000
        planos = [(cid, a["tipo"], a["comando"], casos[cid]["meta"]["hora_inicio"]
                   if a["tipo"] == "inicio" else None)
                  for cid in [c for c in casos
                              if casos[c]["meta"]["dia"] == str(dia)]
                  for a in sorted(casos[cid]["acciones"], key=lambda x: x["orden"])]
        # hora exacta por acción: se reconstruye con el JSON, no con el CSV
        del_dia = sorted((c for c in casos if casos[c]["meta"]["dia"] == str(dia)),
                         key=lambda c: casos[c]["meta"]["hora_inicio"])
        csv_seq = [(c, a["tipo"], a["comando"]) for c in del_dia
                   for a in sorted(casos[c]["acciones"], key=lambda x: x["orden"])]
        json_seq = [(cid, tipo, cmd) for cid, tipo, cmd, _h in esperado]
        if csv_seq != json_seq:
            fallos.append(f"d{dia}: la secuencia del CSV no coincide con w{dia}.json "
                          f"(comando, orden o tipo)")
        if len(csv_seq) != len(json_seq):
            fallos.append(f"d{dia}: {len(csv_seq)} acciones CSV != {len(json_seq)} JSON")
        # espejo con Linux: mismas horas por acción
        import campana as lx
        esp_lx = lx.acciones_b6(dia)
        if len(esp_lx) != len(esperado):
            fallos.append(f"d{dia}: {len(esperado)} acciones Windows != {len(esp_lx)} Linux")
        for (cid_w, _tipo, _cmd, hora_w), a_lx in zip(esperado, esp_lx):
            if cid_w and hora_w != a_lx["hora"]:
                fallos.append(f"d{dia}/{cid_w}: hora {hora_w} != {a_lx['hora']} (Linux)")
                break
    return fallos


# --------------------------------------------------------------------------
# Auditoría de no mutación (salida literal)
# --------------------------------------------------------------------------
def _pipes_fuera_ps(cmd: str) -> int:
    return _sin_ps(cmd).count("|")


def auditar_no_mutacion(raiz=None):
    casos, _ = cargar(raiz)
    cmds = [a["comando"] for c in casos.values() for a in c["acciones"]]
    texto = "\n".join(cmds)
    counts = {k: len(re.findall(p, texto, re.I)) for k, p in REGLAS_MUTACION.items()}
    counts["pipes fuera de powershell -Command"] = sum(_pipes_fuera_ps(c) for c in cmds)
    fuera = []
    for cmd in cmds:
        for dest in destinos_escritura(cmd):
            if not _destino_ok(dest):
                fuera.append((dest, cmd[:70]))
        for ruta in RE_ABS.findall(cmd):
            if not _destino_ok(ruta):
                fuera.append((ruta, cmd[:70]))
    counts["escritura fuera de la carpeta del caso"] = len(fuera)
    efectos = {}
    for nombre, e in EFECTOS_DECLARADOS.items():
        patron = re.compile(r"(?:^|[\s;&|(])(?:" +
                            "|".join(re.escape(v) for v in e["verbos"]) + r")(?:$|[\s;&|)])")
        efectos[nombre] = sum(1 for c in cmds if patron.search(c))
    fallos = [f"{k} = {v} (se exige 0)" for k, v in counts.items() if v]
    for nombre, n in efectos.items():
        if n < 1:
            fallos.append(f"efecto declarado '{nombre}' sin ningún uso")
    return {"comandos": len(cmds), "counts": counts, "efectos": efectos,
            "fuera": fuera, "fallos": fallos}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Campaña B6 de Windows (11 casos espejo).")
    ap.add_argument("--raiz", default=None, help="raíz del repo (3 niveles arriba)")
    ap.add_argument("--docs", action="store_true",
                    help="regenera casos_windows.md y sella el CSV")
    ap.add_argument("--check", action="store_true", help="valida campaña, docs y sha")
    ap.add_argument("--no-mutacion", action="store_true", help="auditoría literal")
    ap.add_argument("--reparto", action="store_true", help="reparto, huecos y ventanas")
    args = ap.parse_args(argv)

    if args.no_mutacion:
        res = auditar_no_mutacion(args.raiz)
        print(f"comandos auditados = {res['comandos']}")
        for k, v in res["counts"].items():
            print(f"{k} = {v}")
        for k, v in res["efectos"].items():
            print(f"efecto declarado {k} = {v}")
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
    print(f"campana_windows: {res['casos']} casos | {res['marcas']} marcas | "
          f"{res['acciones_total']} acciones {res['acciones']} | "
          f"{len(res['mecanismos'])} mecanismos Linux")
    if args.reparto or not args.check:
        casos, _ = cargar(args.raiz)
        for dia in (1, 2, 3):
            del_dia = sorted((c for c in casos if casos[c]["meta"]["dia"] == str(dia)),
                             key=lambda c: casos[c]["meta"]["hora_inicio"])
            print(f"  d{dia}: {len(del_dia)} casos | "
                  f"{casos[del_dia[0]]['meta']['hora_inicio']}-"
                  f"{casos[del_dia[-1]]['meta']['hora_inicio']} | "
                  + ", ".join(f"{c}@{casos[c]['meta']['hora_inicio']}"
                              for c in del_dia))
        print("  mecanismos: " + " ".join(res["mecanismos"]))
    print("RESULT=" + ("PASS" if not res["fallos"] else "FAIL"))
    return 0 if not res["fallos"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
