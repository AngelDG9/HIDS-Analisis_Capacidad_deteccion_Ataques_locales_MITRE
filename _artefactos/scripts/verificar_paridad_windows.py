#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_paridad_windows.py — validador de **paridad Linux ↔ Windows** (C5, D-06/D-08/D-09/D-10/D-11).

Tres bloques independientes:

1. **Paridad diferencial de invariantes** (el que habría cazado el pipe, D-01).
   Ejecuta el **mismo corpus de mutaciones** contra los validadores de Linux
   (`construir_receta_legitima.py` / `campana.py`) y de Windows
   (`construir_receta_legitima_windows.py` / `campana_windows.py`). Si un invariante
   **falla en Linux y no en Windows**, el script **FALLA**, salvo que la diferencia esté
   en `DIVERGENCIAS_DECLARADAS` con `motivo`, `prueba` y `test`. También falla si el
   invariante no lo detecta **ninguno** de los dos: un corpus que no discrimina no vale.

2. **Sellos y metadatos** (el que habría cazado `boveda_version=2`, D-02/D-08).
   Comprueba la cabecera del `M` (`metrica_version=1`, `boveda_version=3`), la versión
   del cliente (`Domain 8.2.7.90`), el sello `sha256sums.txt` (coherencia + cobertura),
   `manifiesto_esperado.json` (sha256 por fichero) y `crudo.done.manifest_sha256`.

3. **Canary de reportabilidad** (el que caza un parser nuevo, D-01).
   Genera una timeline con **una acción por plantilla** de comando (~22 formas: `cmd`,
   `>`, `&&`, `if errorlevel`, `for /L`, PowerShell, `eventcreate`, `robocopy`, `curl`,
   `type`, `copy`, `del`, `md`, `start`…) y un verificador que exige
   `history_timeline == enviados`. **Falla cerrado**: si falta una plantilla, la lista.
   La ejecución real en la VM es de C6/T4; aquí se genera y se prueba **en seco**
   (positivo + control negativo con una plantilla omitida).

Uso:
    python _artefactos/scripts/verificar_paridad_windows.py
    python _artefactos/scripts/verificar_paridad_windows.py --bloque 1
    python _artefactos/scripts/verificar_paridad_windows.py --bloque 2 --m RUTA_M.csv
    python _artefactos/scripts/verificar_paridad_windows.py --bloque 3 --canary-out DIR
    python _artefactos/scripts/verificar_paridad_windows.py --sin-escribir

Salida: `RESULT=PASS|FAIL`, la tabla de invariantes y la lista de divergencias.
Sin VMs, sin red, sin secretos. Devuelve 0 si PASS y 1 si FAIL.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import campana                         # noqa: E402  (validador de la campaña Linux)
import campana_windows as CW          # noqa: E402  (campaña Windows)
import construir_receta_legitima as L  # noqa: E402
import construir_receta_legitima_windows as W  # noqa: E402

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR_LX = os.path.join(RAIZ, "Soporte", "Laboratorio", "legitimo_72h", "recetas")
DIR_WN = os.path.join(RAIZ, "Soporte", "Laboratorio", "windows", "recetas")
SELLOS = os.path.join(RAIZ, "Soporte", "Laboratorio", "legitimo_72h", "sha256sums.txt")
EVID = os.path.join(RAIZ, "Soporte", "Laboratorio", "windows", "legit", "evidencia")
MANIFIESTO = os.path.join(EVID, "manifiesto_esperado.json")
DESPLIEGUE = os.path.join(EVID, "despliegue_actual.json")
BUILD = os.path.join(RAIZ, "Soporte", "Laboratorio", "windows", "legit", "BUILD.md")
CANARY_DIR = os.path.join(EVID, "canary_windows")

#: Ficheros que el sello **debe** cubrir (D-08). Es la lista blanca del plan §5.1;
#: no incluye evidencias ni logs (crecen y no son código).
RUTAS_SELLO_OBLIGATORIAS = (
    "Soporte/Laboratorio/windows/recetas/w1.json",
    "Soporte/Laboratorio/windows/recetas/w2.json",
    "Soporte/Laboratorio/windows/recetas/w3.json",
    "Soporte/Laboratorio/windows/recetas/calendario_windows.json",
    "Soporte/Laboratorio/windows/recetas/bloques_windows.env",
    "Soporte/Laboratorio/windows/recetas/receta_windows_resumen.md",
    "Soporte/Laboratorio/windows/campana/campana_windows.csv",
    "Soporte/Laboratorio/windows/campana/casos_windows.md",
    "Soporte/Laboratorio/windows/windows_legit_host_control.ps1",
    "Soporte/Laboratorio/windows/deploy_windows.ps1",
    "Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1",
    "Soporte/Laboratorio/windows/guest/preparar_invitado_windows.ps1",
    "Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1",
    "Soporte/Laboratorio/windows/guest/verificar_windows.ps1",
    "Soporte/Laboratorio/windows/manifiesto_snapshot.ps1",
    "Soporte/Laboratorio/windows/legit/heartbeat_sink.py",
    "Soporte/Laboratorio/windows/legit/BUILD.md",
    "_artefactos/scripts/construir_receta_legitima_windows.py",
    "_artefactos/scripts/campana_windows.py",
    "_artefactos/scripts/extraer_alertas_windows.py",
    "_artefactos/scripts/extraer_campana_windows.py",
    "_artefactos/scripts/cobertura_herramientas_windows.py",
    "_artefactos/scripts/verificar_espejo.py",
    "_artefactos/scripts/verificar_paridad_windows.py",
    "_artefactos/scripts/etiquetar_operador_legit.py",
    "_artefactos/scripts/tests/test_construir_receta_legitima_windows.py",
    "_artefactos/scripts/tests/test_verificar_paridad_windows.py",
    "_artefactos/scripts/tests/test_campana_windows.py",
    "_artefactos/scripts/tests/test_verificar_espejo.py",
    "_artefactos/scripts/tests/test_extraer_alertas_windows.py",
    "_artefactos/scripts/tests/test_extraer_campana_windows.py",
    "_artefactos/scripts/tests/test_cobertura_herramientas_windows.py",
    "_artefactos/scripts/tests/test_ejecucion_windows.py",
)

#: Divergencias **deliberadas** (plan §5.2). Cada una exige las tres piezas:
#: (1) motivo, (2) prueba de que es segura, (3) test que la protege.
DIVERGENCIAS_DECLARADAS = {
    "EVASION": {
        "motivo": "Linux no tiene PowerShell ni `-EncodedCommand`: el invariante no es "
                  "aplicable al corpus Linux (no hay una forma equivalente que prohibir).",
        "prueba": "0 ocurrencias de `-EncodedCommand` en d1/d2/d3.json; Windows sí puede "
                  "recibirlo, así que allí se prohíbe explícitamente.",
        "test": "tests/test_verificar_paridad_windows.py::test_evasion_es_windows_only",
    },
    "UNIDAD": {
        "motivo": "Linux no tiene `cmd.exe`: su unidad es «1 acción = 1 execve» y la mide "
                  "`binarios_de`; Windows añade el handler `cmd /c`, así que el único "
                  "doble envoltorio posible es un `cmd /c` de primer nivel.",
        "prueba": "0 ocurrencias de `cmd /c` en d1/d2/d3.json; el validador Windows "
                  "rechaza el `cmd /c` de primer nivel y `verificar_espejo` lo comprueba.",
        "test": "tests/test_verificar_paridad_windows.py::test_unidad_cmd_es_windows_only",
    },
    "COMILLAS": {
        "motivo": "Linux prohíbe **todas** las comillas dobles; Windows las necesita para "
                  "PowerShell, `curl.exe -A/-H/-w`, `findstr /c:\"…\"` y `eventcreate /D \"…\"`.",
        "prueba": "0 comillas dobles en d1/d2/d3.json; en Windows son obligatorias por la "
                  "sintaxis de `cmd` y están limitadas a las plantillas declaradas.",
        "test": "tests/test_construir_receta_legitima_windows.py::test_comillas_compensadas",
    },
}


# --------------------------------------------------------------------------
# Utilidades comunes
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _leer_json(path: str, utf8_sig: bool = False):
    with open(path, encoding="utf-8-sig" if utf8_sig else "utf-8") as fh:
        return json.load(fh)


def _cargar_dias(directorio: str, prefijo: str):
    return {d: _leer_json(os.path.join(directorio, f"{prefijo}{d}.json"))
            for d in (1, 2, 3)}


def _escribir_dias(directorio: str, prefijo: str, datos):
    for d, tl in datos.items():
        with open(os.path.join(directorio, f"{prefijo}{d}.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(tl, fh, indent=1, ensure_ascii=False)
            fh.write("\n")


def _copiar_recetas(origen: str, prefijo: str) -> str:
    """Copia solo los ficheros que el validador necesita (no `superseded/`)."""
    tmp = tempfile.mkdtemp(prefix="paridad_")
    dst = os.path.join(tmp, "recetas")
    os.makedirs(dst)
    nombres = [f"{prefijo}{d}.json" for d in (1, 2, 3)]
    nombres += (["calendario.json", "bloques.env", "receta_resumen.md"] if prefijo == "d"
                else ["calendario_windows.json", "bloques_windows.env",
                      "receta_windows_resumen.md"])
    for n in nombres:
        src = os.path.join(origen, n)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(dst, n))
    return tmp


def _eventos(tl):
    return [e for h in tl.get("TimeLineHandlers", []) for e in h["TimeLineEvents"]]


def _primer_evento(tl):
    for h in tl.get("TimeLineHandlers", []):
        if h.get("TimeLineEvents"):
            return h["TimeLineEvents"][0]
    raise AssertionError("timeline sin eventos")


def _contiene(fallos, tokens):
    return [f for f in fallos if any(t.lower() in f.lower() for t in tokens)]


# --------------------------------------------------------------------------
# Bloque 1 — mutaciones de receta (mismo corpus contra los dos validadores)
# --------------------------------------------------------------------------
def _mut_pipe(tl):
    _primer_evento(tl)["Command"] += " | more"


def _mut_random_lx(tl):
    _primer_evento(tl)["Command"] = "random"


def _mut_random_wn(tl):
    _primer_evento(tl)["Command"] = r"cd /d C:\Users\angel && echo %RANDOM%"


def _mut_cd_lx(tl):
    e = _primer_evento(tl)
    e["Command"] = re.sub(r"^cd /home/angel[^\s&]*\s+&&\s+", "", e["Command"])


def _mut_cd_wn(tl):
    e = _primer_evento(tl)
    e["Command"] = re.sub(r"^cd /d \S+ && ", "", e["Command"])


def _mut_retry_lx(tl):
    for h in tl.get("TimeLineHandlers", [])[:len(L.BLOQUES_TRABAJO)]:
        evs = h["TimeLineEvents"]
        for i, ev in enumerate(evs):
            m = L.RE_REGISTRO.search(ev["Command"])
            if m and m.group(2) == "reintento":
                evs.pop(i)
                return
    raise AssertionError("Linux: no hay ningún reintento que quitar")


def _mut_retry_wn(tl):
    for h in tl.get("TimeLineHandlers", [])[:len(L.BLOQUES_TRABAJO)]:
        evs = h["TimeLineEvents"]
        for i, ev in enumerate(evs):
            m = W.RE_ERRLOG.search(ev["Command"])
            if m and m.group("tipo") == "reintento":
                evs.pop(i)
                return
    raise AssertionError("Windows: no hay ningún reintento que quitar")


def _mut_conteo(tl):
    _primer_evento(tl)  # asegura que hay eventos
    tl["TimeLineHandlers"][0]["TimeLineEvents"].pop()


def _mut_l1_lx(tl):
    for h in tl.get("TimeLineHandlers", [])[:len(L.BLOQUES_TRABAJO)]:
        for ev in h["TimeLineEvents"]:
            cmd = ev["Command"]
            # La ruta lleva `$(date -u +%F)` con espacios; para la mutación basta con
            # cortar la redirección final `> …\.sha256`.
            if "sha256sum" in cmd and ".sha256" in cmd and " > " in cmd:
                ev["Command"] = cmd.split(" > ")[0]
                return
    raise AssertionError("Linux: no hay ninguna huella escrita con `>`")


def _mut_l1_wn(tl):
    for h in tl.get("TimeLineHandlers", [])[:len(L.BLOQUES_TRABAJO)]:
        for ev in h["TimeLineEvents"]:
            cmd = ev["Command"]
            m = W.RE_ESCRITURA_HUELLA_W.search(cmd)
            if m:
                path = re.escape(m.group(1))
                ev["Command"] = re.sub(rf"\s*>\s*{path}(?:\s+2>&1)?", "", cmd)
                return
    raise AssertionError("Windows: no hay ninguna huella escrita con `>`")


def _mut_binario_lx(tl):
    e = _primer_evento(tl)
    e["Command"] = re.sub(r"^(cd [^&]+ && )", r"\1whoami2 && ", e["Command"])


def _mut_binario_wn(tl):
    e = _primer_evento(tl)
    e["Command"] = re.sub(r"^(cd /d [^&]+ && )", r"\1whoami2.exe && ", e["Command"])


def _mut_comillas_lx(tl):
    """Linux prohíbe comillas dobles; Windows las necesita (divergencia declarada)."""
    _primer_evento(tl)["Command"] += ' "x"'


def _validar_receta(plataforma: str, mutacion):
    """Copia, muta y valida una receta. Devuelve (fallos, detectados)."""
    if plataforma == "lx":
        origen, prefijo = DIR_LX, "d"
    else:
        origen, prefijo = DIR_WN, "w"
    tmp = _copiar_recetas(origen, prefijo)
    try:
        datos = _cargar_dias(os.path.join(tmp, "recetas"), prefijo)
        mutacion(datos[1])
        _escribir_dias(os.path.join(tmp, "recetas"), prefijo, datos)
        if plataforma == "lx":
            fallos = L.validar(os.path.join(tmp, "recetas"), verbose=False)["fallos"]
        else:
            fallos = W.validar(os.path.join(tmp, "recetas"), verbose=False)["fallos"]
        return fallos
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _baseline():
    lx = L.validar(DIR_LX, verbose=False)["fallos"]
    wn = W.validar(DIR_WN, verbose=False)["fallos"]
    return lx, wn


def _veredicto(inv_id, aplica_lx, aplica_wn, lx_detecta, wn_detecta):
    """Regla §5.2: si falla en Linux y no en Windows ⇒ FALLA, salvo declaración."""
    if not aplica_lx and not aplica_wn:
        return "FALLA", "el invariante no se aplica a ninguna plataforma"
    # Plataformas donde el invariante no existe: debe estar declarado **y** la otra
    # plataforma debe seguir detectando su mutación.
    if not aplica_lx:
        if inv_id not in DIVERGENCIAS_DECLARADAS:
            return "FALLA", "Linux no tiene el invariante y no está declarado"
        if not wn_detecta:
            return "FALLA", "Windows no detecta su propia mutación"
        return "N/A (declarada)", DIVERGENCIAS_DECLARADAS[inv_id]["motivo"]
    if not aplica_wn:
        if inv_id not in DIVERGENCIAS_DECLARADAS:
            return "FALLA", "Windows no tiene el invariante y no está declarado"
        if not lx_detecta:
            return "FALLA", "Linux no detecta su propia mutación"
        return "N/A (declarada)", DIVERGENCIAS_DECLARADAS[inv_id]["motivo"]
    if not lx_detecta:
        return "FALLA", "Linux no detecta la mutación"
    if not wn_detecta:
        return "FALLA", "Windows no detecta una mutación que Linux sí detecta"
    return "PASS", ""


def ejecutar_bloque1():
    """Corpus diferencial. Devuelve (filas, fallos, divergencias)."""
    filas, fallos, divergencias = [], [], []
    lx_base, wn_base = _baseline()
    if lx_base:
        fallos.append(f"baseline Linux ya falla ({len(lx_base)}): {lx_base[:2]}")
    if wn_base:
        fallos.append(f"baseline Windows ya falla ({len(wn_base)}): {wn_base[:2]}")

    def receta(inv_id, descripcion, mut_lx, mut_wn, tok_lx, tok_wn,
               aplica_lx=True, aplica_wn=True):
        flx = _validar_receta("lx", mut_lx) if aplica_lx else []
        fwn = _validar_receta("wn", mut_wn) if aplica_wn else []
        dlx = bool(_contiene(flx, tok_lx)) if aplica_lx else False
        dwn = bool(_contiene(fwn, tok_wn)) if aplica_wn else False
        est, motivo = _veredicto(inv_id, aplica_lx, aplica_wn, dlx, dwn)
        filas.append({
            "id": inv_id, "descripcion": descripcion,
            "aplica_lx": aplica_lx, "aplica_wn": aplica_wn,
            "lx_detecta": dlx, "wn_detecta": dwn,
            "estado": est, "motivo": motivo,
            "detalle_lx": _contiene(flx, tok_lx)[:1],
            "detalle_wn": _contiene(fwn, tok_wn)[:1],
        })
        if est == "FALLA":
            fallos.append(f"{inv_id}: {motivo}")
        if est == "N/A (declarada)":
            divergencias.append(inv_id)

    receta("PIPE", "0 pipes (ningún `|` en ningún sitio)",
           _mut_pipe, _mut_pipe, ["|"], ["|"])
    receta("RANDOM", "0 aleatoriedad (`random` / `%RANDOM%` / `Get-Random`)",
           _mut_random_lx, _mut_random_wn, ["random"], ["aleatoriedad"])
    receta("CD", "prefijo `cd` por acción",
           _mut_cd_lx, _mut_cd_wn, ["prefijo"], ["prefijo"])
    receta("PARES", "pares error/reintento emparejados",
           _mut_retry_lx, _mut_retry_wn, ["reintento"], ["reintento"])
    receta("CONTEOS", "conteos de acciones por bloque/día",
           _mut_conteo, _mut_conteo, ["eventos"], ["total"])
    receta("BINARIOS", "lista blanca de binarios (D-10)",
           _mut_binario_lx, _mut_binario_wn,
           ["binario no permitido"], ["binario no permitido"])
    receta("L1", "toda huella leída se escribe antes (L-1)",
           _mut_l1_lx, _mut_l1_wn, ["L-1"], ["L-1"])

    # Mutantes y evasión: se prueban en el validador de comandos de cada plataforma.
    cmd_lx_mut = "cd /home/angel/Documentos/campana_fp/C-01 && crontab -r"
    cmd_wn_mut = (r"cd /d C:\lab-legit\campana\W-01 && schtasks /create /tn x "
                  r"/tr calc.exe /sc once /st 00:00")
    flx = campana.validar_comando(cmd_lx_mut)
    fwn = W.validar_comando(cmd_wn_mut)
    dlx = bool(_contiene(flx, ["crontab"]))
    dwn = bool(_contiene(fwn, ["mutante"]))
    est, motivo = _veredicto("MUTANTE", True, True, dlx, dwn)
    filas.append({
        "id": "MUTANTE", "descripcion": "0 comandos mutantes (schtasks/reg/sc/crontab…)",
        "aplica_lx": True, "aplica_wn": True, "lx_detecta": dlx, "wn_detecta": dwn,
        "estado": est, "motivo": motivo, "detalle_lx": flx[:1], "detalle_wn": fwn[:1],
    })
    if est == "FALLA":
        fallos.append(f"MUTANTE: {motivo}")

    cmd_ev = (r"cd /d C:\Users\angel && powershell -NoProfile "
              r"-EncodedCommand AAAA")
    fwn = W.validar_comando(cmd_ev)
    dwn = bool(_contiene(fwn, ["evasión"]))
    est, motivo = _veredicto("EVASION", False, True, False, dwn)
    filas.append({
        "id": "EVASION", "descripcion": "0 opciones de evasión (`-EncodedCommand`…)",
        "aplica_lx": False, "aplica_wn": True, "lx_detecta": False, "wn_detecta": dwn,
        "estado": est, "motivo": motivo, "detalle_lx": [], "detalle_wn": fwn[:1],
    })
    if est == "FALLA":
        fallos.append(f"EVASION: {motivo}")
    if est == "N/A (declarada)":
        divergencias.append("EVASION")

    cmd_un = r"cmd /c cd /d C:\Users\angel && echo x"
    fwn = W.validar_comando(cmd_un)
    dwn = bool(_contiene(fwn, ["cmd /c"]))
    est, motivo = _veredicto("UNIDAD", False, True, False, dwn)
    filas.append({
        "id": "UNIDAD", "descripcion": "unidad `cmd.exe` (sin doble envoltorio)",
        "aplica_lx": False, "aplica_wn": True, "lx_detecta": False, "wn_detecta": dwn,
        "estado": est, "motivo": motivo, "detalle_lx": [], "detalle_wn": fwn[:1],
    })
    if est == "FALLA":
        fallos.append(f"UNIDAD: {motivo}")
    if est == "N/A (declarada)":
        divergencias.append("UNIDAD")

    # Comillas dobles: divergencia declarada (Linux las prohíbe; Windows las necesita).
    flx = _validar_receta("lx", _mut_comillas_lx)
    dlx = bool(_contiene(flx, ["comillas dobles"]))
    est, motivo = _veredicto("COMILLAS", True, False, dlx, False)
    filas.append({
        "id": "COMILLAS", "descripcion": "comillas dobles (Linux 0; Windows solo las "
                                         "plantillas declaradas)",
        "aplica_lx": True, "aplica_wn": False, "lx_detecta": dlx, "wn_detecta": False,
        "estado": est, "motivo": motivo, "detalle_lx": flx[:1], "detalle_wn": [],
    })
    if est == "N/A (declarada)":
        divergencias.append("COMILLAS")

    return filas, fallos, divergencias


# --------------------------------------------------------------------------
# Bloque 2 — sellos y metadatos
# --------------------------------------------------------------------------
def _estado(ident, ok, detalle, warn=False):
    return {"id": ident, "estado": "OK" if ok else ("SKIP" if warn else "FALLO"),
            "detalle": detalle}


def _crudo_auto():
    base = r"D:\TFG-VMs"
    if not os.path.isdir(base):
        return None
    cands = sorted(glob.glob(os.path.join(base, "legitimo-windows-*", "crudo")))
    return cands[-1] if cands else None


def _kv(path: str):
    out = {}
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for linea in fh:
            if "=" in linea:
                k, v = linea.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def comprobar_m(path: str):
    if not path or not os.path.isfile(path):
        return [_estado("M-01", False, f"no existe el M: {path}", warn=True)]
    out = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        lineas = [l.rstrip("\n") for l in fh if l.strip()]
    cab = lineas[0]
    m_mv = re.search(r"metrica_version=(\d+)", cab)
    m_bv = re.search(r"boveda_version=(\d+)", cab)
    out.append(_estado(
        "M-01", bool(m_mv and m_mv.group(1) == "1" and m_bv and m_bv.group(1) == "3"),
        f"cabecera: metrica_version={m_mv.group(1) if m_mv else '—'} "
        f"boveda_version={m_bv.group(1) if m_bv else '—'} ({path})"))
    datos = list(csv.DictReader(lineas[1:]))
    if not datos:
        out.append(_estado("M-02", False, "el M no tiene filas de datos"))
        return out
    mal_mv = [r for r in datos if str(r.get("metrica_version")) != "1"]
    mal_bv = [r for r in datos if str(r.get("boveda_version")) != "3"]
    out.append(_estado(
        "M-02", not mal_mv and not mal_bv,
        f"{len(datos)} filas; metrica_version!=1: {len(mal_mv)}; "
        f"boveda_version!=3: {len(mal_bv)}"))
    return out


def _leer_sellos(path: str):
    entradas = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for i, linea in enumerate(fh, 1):
            linea = linea.rstrip("\n")
            if not linea.strip() or linea.lstrip().startswith("#"):
                continue
            m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", linea)
            if not m:
                entradas.append({"linea": i, "hash": None, "ruta": linea,
                                 "error": "formato"})
                continue
            entradas.append({"linea": i, "hash": m.group(1).lower(),
                             "ruta": m.group(2).strip(), "error": None})
    return entradas


def comprobar_sellos(path: str = SELLOS):
    if not os.path.isfile(path):
        return [_estado("SELLO-01", False, f"no existe el sello: {path}")]
    entradas = _leer_sellos(path)
    out = []
    malformadas = [e for e in entradas if e["error"]]
    out.append(_estado("SELLO-01", bool(entradas) and not malformadas,
                       f"{len(entradas)} entradas; malformadas={len(malformadas)}"))
    rutas = [e["ruta"] for e in entradas if not e["error"]]
    dup = sorted({r for r in rutas if rutas.count(r) > 1})
    out.append(_estado("SELLO-02", not dup,
                       f"duplicadas={len(dup)}" + (f": {dup[:5]}" if dup else "")))

    obsoletas, ausentes = [], []
    for e in entradas:
        if e["error"]:
            continue
        p = e["ruta"]
        if not os.path.isfile(os.path.join(RAIZ, p)):
            ausentes.append(p)
            continue
        if sha256_file(os.path.join(RAIZ, p)) != e["hash"]:
            obsoletas.append(p)
    detalle = []
    if obsoletas:
        detalle.append(f"{len(obsoletas)} obsoletas: {obsoletas}")
    if ausentes:
        detalle.append(f"{len(ausentes)} ausentes: {ausentes}")
    out.append(_estado("SELLO-03", not obsoletas and not ausentes,
                       "; ".join(detalle) if detalle else
                       "todas las entradas cuadran con el fichero real"))

    faltan = [p for p in RUTAS_SELLO_OBLIGATORIAS if p not in set(rutas)]
    out.append(_estado("SELLO-04", not faltan,
                       "cobertura completa" if not faltan else
                       f"faltan {len(faltan)} rutas: {faltan}"))
    return out


def comprobar_manifiesto(path: str = MANIFIESTO):
    if not os.path.isfile(path):
        return [_estado("MANIF-01", False, f"no existe {path}")]
    try:
        d = _leer_json(path, utf8_sig=True)
    except (ValueError, OSError) as exc:
        return [_estado("MANIF-01", False, f"no se puede leer {path}: {exc}")]
    out = [_estado("MANIF-01", True, f"{os.path.basename(path)} presente y parseable")]
    ficheros = d.get("ficheros") or []
    sha = str(d.get("MANIFEST_SHA256") or "")
    malos = [f for f in ficheros
             if not re.match(r"^[0-9a-f]{64}$", str(f.get("sha256") or ""))]
    out.append(_estado(
        "MANIF-02",
        bool(ficheros) and bool(re.match(r"^[0-9a-f]{64}$", sha))
        and int(d.get("MANIFEST_FILES", -1)) == len(ficheros) and not malos,
        f"ficheros={len(ficheros)} MANIFEST_FILES={d.get('MANIFEST_FILES')} "
        f"MANIFEST_SHA256={sha[:12]}… sha256 malos={len(malos)}"))
    dominio = ((d.get("cliente") or {}).get("ghosts_domain_fileversion") or "")
    out.append(_estado("MANIF-03", dominio == "8.2.7.90",
                       f"Domain FileVersion={dominio!r} (se espera 8.2.7.90)"))
    if os.path.isfile(BUILD):
        texto = open(BUILD, encoding="utf-8", errors="replace").read()
        out.append(_estado("MANIF-04", "v8.3.1" in texto and "8.2.7.90" in texto,
                           "BUILD.md cita v8.3.1 y 8.2.7.90"))
    else:
        out.append(_estado("MANIF-04", False, f"no existe {BUILD}"))
    if os.path.isfile(DESPLIEGUE):
        try:
            dep = _leer_json(DESPLIEGUE, utf8_sig=True)
            out.append(_estado("MANIF-05",
                               str(dep.get("manifest_sha256")) == sha,
                               f"despliegue.manifest_sha256={str(dep.get('manifest_sha256'))[:12]}…"
                               f" == manifiesto {sha[:12]}…"))
        except (ValueError, OSError) as exc:
            out.append(_estado("MANIF-05", False, f"despliegue_actual.json ilegible: {exc}"))
    else:
        out.append(_estado("MANIF-05", False, f"no existe {DESPLIEGUE}"))
    sha_file = path + ".sha256"
    if os.path.isfile(sha_file):
        txt = open(sha_file, encoding="utf-8-sig", errors="replace").read().split()
        out.append(_estado("MANIF-06", bool(txt) and txt[0].lower() == sha256_file(path),
                           f"{os.path.basename(sha_file)} cuadra con el fichero"))
    else:
        out.append(_estado("MANIF-06", False, f"no existe {sha_file}", warn=True))
    return out


def comprobar_crudo(crudo_dir: str | None):
    if not crudo_dir:
        return [_estado("CRUDO-01", False, "no hay crudo de Windows: se omite", warn=True)]
    done = os.path.join(crudo_dir, "crudo.done")
    if not os.path.isfile(done):
        return [_estado("CRUDO-01", False, f"no existe {done}")]
    kv = _kv(done)
    out = [_estado("CRUDO-01", True, f"crudo.done presente ({crudo_dir})")]
    man = os.path.join(crudo_dir, "MANIFEST.tsv")
    if os.path.isfile(man) and kv.get("manifest_sha256"):
        out.append(_estado(
            "CRUDO-02", sha256_file(man) == kv["manifest_sha256"].lower(),
            f"manifest_sha256={kv['manifest_sha256'][:12]}… == sha256(MANIFEST.tsv)"))
        with open(man, encoding="utf-8-sig", errors="replace") as fh:
            filas = [l for l in fh if l.strip()]
        n = max(0, len(filas) - 1)
        out.append(_estado("CRUDO-03", str(n) == str(kv.get("ficheros")),
                           f"ficheros={kv.get('ficheros')} filas MANIFEST={n}"))
    else:
        out.append(_estado("CRUDO-02", False, "falta MANIFEST.tsv o manifest_sha256"))
    out.append(_estado("CRUDO-04", kv.get("M_rc") == "0" and os.path.isfile(
        kv.get("M_csv", "")), f"M_rc={kv.get('M_rc')} M_csv={kv.get('M_csv')}"))
    # Cruce ligero: el sha256 del archives en `denominador_manifest.tsv` debe ser el
    # mismo que el del MANIFEST.tsv (no se re-hashea el .json de 329 MB).
    den = os.path.join(crudo_dir, "denominador_manifest.tsv")
    if os.path.isfile(den) and os.path.isfile(man):
        with open(man, encoding="utf-8-sig", errors="replace") as fh:
            filas = list(csv.DictReader(fh, delimiter="\t"))
        with open(den, encoding="utf-8-sig", errors="replace") as fh:
            den_filas = list(csv.DictReader(fh, delimiter="\t"))
        sha_man = next((r.get("sha256") for r in filas
                        if os.path.basename(r.get("fichero", "")) == "archives.json"), None)
        sha_den = next((r.get("sha256") for r in den_filas
                        if r.get("fichero") == "archives.json"), None)
        out.append(_estado("CRUDO-05", bool(sha_man) and sha_man == sha_den,
                           f"archives.json: MANIFEST={str(sha_man)[:12]}… "
                           f"denominador={str(sha_den)[:12]}…"))
    else:
        out.append(_estado("CRUDO-05", False, "falta denominador_manifest.tsv",
                           warn=True))
    return out


def ejecutar_bloque2(m_path=None, crudo_dir=None):
    entradas = []
    crudo = crudo_dir if crudo_dir is not None else _crudo_auto()
    done = os.path.join(crudo, "crudo.done") if crudo else None
    kv = _kv(done) if done and os.path.isfile(done) else {}
    m = m_path or kv.get("M_csv")
    entradas += comprobar_m(m)
    entradas += comprobar_crudo(crudo)
    entradas += comprobar_manifiesto()
    entradas += comprobar_sellos()
    fallos = [e for e in entradas if e["estado"] == "FALLO"]
    return entradas, fallos


# --------------------------------------------------------------------------
# Bloque 3 — canary de reportabilidad
# --------------------------------------------------------------------------
#: 22 plantillas: una acción por forma sintáctica. El `prep` de C6 debe crear
#: `C:\lab-legit\canary` antes de enviar la timeline (no se ejecuta aquí).
PLANTILLAS_CANARY = [
    ("cmd_simple", "cmd /c", r"cd /d C:\lab-legit\canary && cmd /c echo CANARY-01"),
    ("redir_out", "redirección >",
     r"cd /d C:\lab-legit\canary && echo CANARY-02 > C:\lab-legit\canary\canary_02.txt"),
    ("redir_append", "redirección >>",
     r"cd /d C:\lab-legit\canary && echo CANARY-03 >> C:\lab-legit\canary\canary_02.txt"),
    ("and_and", "encadenado &&",
     r"cd /d C:\lab-legit\canary && echo CANARY-04 && echo CANARY-04b"),
    ("if_errorlevel", "if errorlevel",
     r"cd /d C:\lab-legit\canary && dir C:\lab-legit\canary\noexiste >nul 2>&1 & "
     r"if errorlevel 1 (>> C:\lab-legit\canary\errores.log echo CANARY-05)"),
    ("for_L", "for /L",
     r"cd /d C:\lab-legit\canary && for /L %i in (1,1,3) do @echo CANARY-06-%i"),
    ("powershell", "PowerShell simple",
     r'cd /d C:\lab-legit\canary && powershell -NoProfile -Command "Write-Output CANARY-07"'),
    ("powershell_var", "PowerShell con variable y comillas",
     'cd /d C:\\lab-legit\\canary && powershell -NoProfile -Command "$c = Get-Content '
     '-LiteralPath \'C:\\lab-legit\\canary\\canary_02.txt\'; Set-Content -LiteralPath '
     '\'C:\\lab-legit\\canary\\canary_08.txt\' -Value $c"'),
    ("eventcreate", "eventcreate",
     r'cd /d C:\lab-legit\canary && eventcreate /T INFORMATION /ID 100 /L APPLICATION '
     r'/SO canary /D "canary 09"'),
    ("robocopy", "robocopy",
     r"cd /d C:\lab-legit\canary && robocopy . copia canary_02.txt /NJH /NJS /NP"),
    ("curl", "curl.exe",
     r"cd /d C:\lab-legit\canary && curl.exe -sS --max-time 5 --version "
     r"> C:\lab-legit\canary\canary_10.txt"),
    ("certutil", "certutil > huella",
     r"cd /d C:\lab-legit\canary && certutil -hashfile C:\lab-legit\canary\canary_02.txt "
     r"SHA256 > C:\lab-legit\canary\canary_11.sha256 2>&1"),
    ("type", "type de huella",
     r"cd /d C:\lab-legit\canary && type C:\lab-legit\canary\canary_11.sha256"),
    ("copy", "copy",
     r"cd /d C:\lab-legit\canary && copy /y C:\lab-legit\canary\canary_02.txt "
     r"C:\lab-legit\canary\canary_13.txt"),
    ("del", "del",
     r"cd /d C:\lab-legit\canary && del /f /q C:\lab-legit\canary\canary_13.txt"),
    ("md", "md",
     r"cd /d C:\lab-legit\canary && md C:\lab-legit\canary\canary_dir"),
    ("rd", "rd",
     r"cd /d C:\lab-legit\canary && rd /s /q C:\lab-legit\canary\canary_dir"),
    ("start", "start",
     r"cd /d C:\lab-legit\canary && start /b cmd /c echo CANARY-18"),
    ("find", "find /c",
     r'cd /d C:\lab-legit\canary && find /c "CANARY" C:\lab-legit\canary\canary_02.txt'),
    ("findstr", "findstr",
     r'cd /d C:\lab-legit\canary && findstr /c:"CANARY" C:\lab-legit\canary\canary_02.txt'),
    ("more", "more",
     r"cd /d C:\lab-legit\canary && more +0 C:\lab-legit\canary\canary_02.txt"),
    ("tar", "tar",
     r"cd /d C:\lab-legit\canary && tar -czf C:\lab-legit\canary\canary_22.tar.gz "
     r"-C C:\lab-legit\canary canary_02.txt"),
]

_RE_CMD = re.compile(r"\bcommand\b", re.I)


def _plantillas(enviados=None):
    return [{"id": pid, "forma": forma, "comando": cmd}
            for pid, forma, cmd in (enviados or PLANTILLAS_CANARY)]


def escribir_timeline_canary(path: str, plantillas=None):
    pl = _plantillas(plantillas)
    tl = {
        "Status": "Run",
        "TimeLineHandlers": [{
            "HandlerType": "Command",
            "Initial": "",
            "UtcTimeOn": "00:00:00",
            "UtcTimeOff": "23:59:59",
            "Loop": False,
            "HandlerArgs": {},
            "TimeLineEvents": [{"Command": p["comando"], "DelayAfter": 2000}
                               for p in pl],
        }],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(tl, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    return path


def escribir_history_simulado(path: str, plantillas=None, omitir=()):
    pl = [p for p in _plantillas(plantillas) if p["id"] not in set(omitir)]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("id\tcreatedutc\thandler\tcommand\n")
        for i, p in enumerate(pl):
            fh.write(f"{p['id']}\t2026-11-11T00:00:{i:02d}Z\tCommand\t{p['comando']}\n")
    return path


def leer_history_timeline(path: str):
    """Lee un export de `history_timeline` (TSV/CSV) o una timeline JSON."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        texto = fh.read()
    if path.lower().endswith(".json"):
        d = json.loads(texto)
        if isinstance(d, list):
            eventos = d
        elif isinstance(d, dict) and "TimeLineEvents" in d:
            eventos = d["TimeLineEvents"]
        elif isinstance(d, dict) and "TimeLineHandlers" in d:
            eventos = [e for h in d["TimeLineHandlers"] for e in h["TimeLineEvents"]]
        else:
            raise ValueError(f"{path}: JSON sin TimeLineEvents")
        return [str(e.get("Command") or e.get("command") or "") for e in eventos]
    lineas = [l for l in texto.splitlines() if l.strip() and not l.startswith("#")]
    if not lineas:
        return []
    # Tabla de `psql` (`id | createdutc | handler | command`, con separador `---+---`):
    # es el formato del export de WE0-2 y no es TSV/CSV.
    if "|" in lineas[0] and _RE_CMD.search(lineas[0]):
        cab = [c.strip().lower() for c in lineas[0].split("|")]
        idx = next(i for i, c in enumerate(cab) if _RE_CMD.search(c))
        salida = []
        for linea in lineas[1:]:
            if set(linea.strip()) <= set("-+ "):
                continue
            partes = [p.strip() for p in linea.split("|")]
            if len(partes) > idx:
                salida.append(partes[idx])
        return salida
    sep = "\t" if lineas[0].count("\t") >= lineas[0].count(",") else ","
    rd = csv.DictReader(lineas, delimiter=sep)
    col = next((c for c in (rd.fieldnames or []) if _RE_CMD.search(c.strip())), None)
    if not col:
        raise ValueError(f"{path}: no hay columna `command`")
    return [str(r.get(col) or "") for r in rd]


def verificar_canary(enviados, history_path: str):
    """Compara la timeline enviada con `history_timeline`. Falla cerrado."""
    pl = _plantillas(enviados)
    fallo, hist = "", []
    try:
        hist = leer_history_timeline(history_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fallo = f"no se puede leer history_timeline: {exc}"
    restantes = Counter(hist)
    faltan = []
    for p in pl:
        if restantes[p["comando"]] > 0:
            restantes[p["comando"]] -= 1
        else:
            faltan.append(p)
    sobran = list(restantes.elements())
    return {
        "ok": not faltan and not fallo,
        "enviados": len(pl), "reportados": len(hist),
        "faltan": faltan, "sobran": sobran, "error": fallo,
    }


def ejecutar_bloque3(outdir: str = CANARY_DIR):
    os.makedirs(outdir, exist_ok=True)
    timeline = escribir_timeline_canary(os.path.join(outdir, "timeline_canary.json"))
    with open(os.path.join(outdir, "plantillas_canary.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        json.dump(_plantillas(), fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    hist_ok = escribir_history_simulado(
        os.path.join(outdir, "history_timeline_simulado.tsv"))
    hist_bad = escribir_history_simulado(
        os.path.join(outdir, "history_timeline_simulado_fallo.tsv"),
        omitir=("powershell",))
    res_ok = verificar_canary(None, hist_ok)
    res_bad = verificar_canary(None, hist_bad)
    lineas = [
        "# canary de reportabilidad (C5, en seco — sin VM)",
        f"timeline={timeline}",
        f"plantillas={len(PLANTILLAS_CANARY)}",
        f"positivo: enviados={res_ok['enviados']} reportados={res_ok['reportados']} "
        f"faltan={len(res_ok['faltan'])} RESULT="
        + ("PASS" if res_ok["ok"] else "FAIL"),
        f"negativo (sin powershell): enviados={res_bad['enviados']} "
        f"reportados={res_bad['reportados']} faltan={len(res_bad['faltan'])} RESULT="
        + ("PASS" if res_bad["ok"] else "FAIL"),
    ]
    for p in res_bad["faltan"]:
        lineas.append(f"  FALTA {p['id']}: {p['comando']}")
    with open(os.path.join(outdir, "canary_dryrun.txt"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lineas) + "\n")
    entradas = []
    entradas.append(_estado(
        "CANARY-01", all(os.path.isfile(p) for p in (timeline, hist_ok, hist_bad)),
        f"timeline + plantillas + historial simulado en {outdir}"))
    entradas.append(_estado(
        "CANARY-02", res_ok["ok"],
        f"positivo: {res_ok['reportados']}/{res_ok['enviados']} reportados"))
    entradas.append(_estado(
        "CANARY-03", (not res_bad["ok"]) and [p["id"] for p in res_bad["faltan"]] == ["powershell"],
        "control negativo: falta `powershell` y se detecta"))
    if res_bad["faltan"]:
        entradas.append(_estado(
            "CANARY-04", True,
            "control negativo (esperado): faltan " +
            ", ".join(p["id"] for p in res_bad["faltan"])))
    fallos = [e for e in entradas if e["estado"] == "FALLO"]
    return entradas, fallos, res_ok, res_bad


# --------------------------------------------------------------------------
# Impresión y CLI
# --------------------------------------------------------------------------
def _imprimir_bloque1(filas, fallos, divergencias):
    print("== BLOQUE 1 — PARIDAD DIFERENCIAL ==")
    print(f"{'invariante':<12} {'Linux':>8} {'Windows':>8}  estado")
    for f in filas:
        lx = "detecta" if f["lx_detecta"] else ("N/A" if not f["aplica_lx"] else "NO")
        wn = "detecta" if f["wn_detecta"] else ("N/A" if not f["aplica_wn"] else "NO")
        print(f"{f['id']:<12} {lx:>8} {wn:>8}  {f['estado']}")
        if f["estado"] != "PASS" and f["motivo"]:
            print(f"  -> {f['motivo']}")
    if divergencias:
        print("divergencias declaradas:")
        for inv in sorted(set(divergencias)):
            d = DIVERGENCIAS_DECLARADAS[inv]
            print(f"  {inv}: {d['motivo']}")
            print(f"    prueba: {d['prueba']}")
            print(f"    test:   {d['test']}")
    print(f"RESULT_BLOQUE1={'PASS' if not fallos else 'FAIL'}")


def _imprimir_bloque(entradas, nombre, fallos):
    print(f"== {nombre} ==")
    for e in entradas:
        print(f"[{e['estado']}] {e['id']}: {e['detalle']}")
    print(f"RESULT_{nombre.split('—')[0].strip().replace(' ', '_')}="
          f"{'PASS' if not fallos else 'FAIL'}")


def main(argv=None):
    # La consola de Windows puede ser cp1252: no dejar que un acento rompa el informe.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="Paridad Linux ↔ Windows (C5)")
    ap.add_argument("--bloque", choices=("1", "2", "3", "todos"), default="todos")
    ap.add_argument("--m", default=None, help="denominador_M.csv de Windows")
    ap.add_argument("--crudo", default=None,
                    help="carpeta del crudo de Windows (contiene crudo.done)")
    ap.add_argument("--sellos", default=SELLOS, help="sha256sums.txt global")
    ap.add_argument("--canary-out", default=CANARY_DIR,
                    help="carpeta de salida del canary")
    ap.add_argument("--sin-escribir", action="store_true",
                    help="canary en un directorio temporal (no escribe evidencia)")
    args = ap.parse_args(argv)

    resultados = {}
    if args.bloque in ("1", "todos"):
        filas, fallos, div = ejecutar_bloque1()
        _imprimir_bloque1(filas, fallos, div)
        resultados["BLOQUE1"] = not fallos
    if args.bloque in ("2", "todos"):
        entradas, fallos = ejecutar_bloque2(args.m, args.crudo)
        _imprimir_bloque(entradas, "BLOQUE 2 — SELLOS Y METADATOS", fallos)
        resultados["BLOQUE2"] = not fallos
    if args.bloque in ("3", "todos"):
        out = args.canary_out
        tmp = None
        if args.sin_escribir:
            tmp = tempfile.mkdtemp(prefix="canary_")
            out = tmp
        try:
            entradas, fallos, res_ok, res_bad = ejecutar_bloque3(out)
            _imprimir_bloque(entradas, "BLOQUE 3 — CANARY DE REPORTABILIDAD", fallos)
            print(f"canary: enviados={res_ok['enviados']} "
                  f"reportados={res_ok['reportados']} "
                  f"faltan={len(res_ok['faltan'])}")
            if res_bad["faltan"]:
                print("control negativo detecta: " +
                      ", ".join(p["id"] for p in res_bad["faltan"]))
            resultados["BLOQUE3"] = not fallos
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    ok = all(resultados.values()) and bool(resultados)
    print("RESULT=" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
