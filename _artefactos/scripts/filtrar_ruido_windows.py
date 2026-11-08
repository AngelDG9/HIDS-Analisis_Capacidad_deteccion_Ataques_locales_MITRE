#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ruido_windows.py — filtro de ruido y etiquetado auditado (Windows, B1.0).

**Mismo orden y categorías que `filtrar_ruido.py` (Linux).** Cambian los **datos**:

- `ATTACK_ROOT = C:\\lab-attack\\` (la carpeta del ataque se deriva de `--ata`).
- Campos de señal Windows: `win_image`, `win_command_line`, `win_cwd`, `win_target`,
  `syscheck_path`, `rule_id`, `rule_group` (esquema v5, aditivo).
- **H4-W**: una señal `win_image` de detección solo casa si (i) casa la imagen, (ii) casa
  al menos un ancla (`win_cwd`, `win_command_line`, `win_target` o `syscheck_path`) con
  `C:\\lab-attack\\ATA<NNN>` y (iii) la fila es un evento de ejecución (`event_id` 1 o 4688).
  Lo que casa la imagen y falla el ancla/evento -> `dudosa` (`sin_ancla`), nunca `deteccion`
  ni `ruido_conocido`.
- **Candado de pertenencia (B1.0-SSH.1, G-SSH.1)**: si la fila tiene evidencia de ataque
  (`C:\\lab-attack\\ATA<NNN>` en `win_cwd`/`win_command_line`/`win_target`/`syscheck_path`),
  se evalúa **antes** que `auto_ruido`/`operador` y **nunca** cae en `auto_ruido` ni
  `ruido_conocido`: o casa una detección declarada (`deteccion`) o es `artefacto_ataque`.
  Para el resto de filas se mantiene el orden Linux.
- **`auto_ruido` del canal (B1.0-SSH.1)**: solo la **imagen del servicio** `sshd.exe`
  (`auto_ruido:canal-ssh`); **nunca** sus hijos (`cmd.exe`/`powershell.exe` del ataque se
  atribuyen por carpeta como siempre). El resto del régimen lo absorbe el catálogo baseline.
- **`OPERADOR_WIN` (B1.0-SSH.1)**: el logon del canal **no es ataque**. Se excluye con un
  predicado **estrecho por `rule_id` + evidencia medida** (ver §9.6 de la política):
  `60106`/`60137` (4624/4634 tipo 3) por `win_user=angel ∧ logon_type=3`; `67024`/`67023`
  (4624/4634 tipo 5) por `win_user=sshd_<pid>`; `67028` (4672) por `win_user=angel` o
  `sshd_<pid>`; `67022`/`67023` por `srcip=192.168.65.1` (regla del plan; en este
  laboratorio el 4624 de SSH **no trae IP** y se declara). `--sin-operador` calcula la
  **sensibilidad** (T2-W sin el predicado).
- **Modo baseline** (`--modo baseline`): no exige señales; una novedad no cuenta como
  detección (se absorbe como `ruido_conocido`), igual que en Linux.
- **Replay de la baseline Windows** (`--replay-baseline`): v1 (72) con catálogo v1 -> 0
  detecciones; v2 (87) con catálogo v1+v2 -> 0. Es la comprobación CA-B1-08.

Salida: mismas **15 columnas** que el filtro Linux
(`ata_id,iter,timestamp_utc,agent_name,rule_id,rule_level,rule_groups,rs_origen,
rule_description,categoria,motivo,atribucion,revision,veredicto_humano,evidencia`).
Determinismo: sin reloj, orden estable `(timestamp_utc, rule_id, evidencia)`, LF, UTF-8.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import hashlib
import ntpath
import os
import re
import sys

# --------------------------------------------------------------------------
# Constantes (deben coincidir con `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §9)
# --------------------------------------------------------------------------
CATEGORIAS = ("deteccion", "ruido_conocido", "auto_ruido", "dudosa", "artefacto_ataque")

#: Raíz de las carpetas de ataque en Windows. La carpeta se deriva de `--ata`.
ATTACK_ROOT = "C:\\lab-attack\\"

#: B1.0-SSH.1: `auto_ruido` solo para la **imagen del servicio** del canal.
CANAL_SSH_IMAGENES = {"sshd.exe"}

#: Predicado `OPERADOR_WIN` (B1.0-SSH.1). Evidencia: `Soporte/Ataques/c0/windows/canal_ssh.csv`.
OPERADOR_SRCIPS = {"192.168.65.1"}
OPERADOR_REGLAS_IP = {"67022", "67023"}
OPERADOR_REGLAS_ANGEL = {"60106", "60137"}      # 4624/4634 de red (logon_type=3)
OPERADOR_REGLAS_PRIV = {"67028"}                # 4672 (sin logon_type)
OPERADOR_REGLAS_SSHD = {"67024", "67023"}       # 4624/4634 del servicio (tipo 5)
OPERADOR_USUARIO = "angel"
OPERADOR_USUARIO_SSHD = re.compile(r"^sshd_\d+$", re.IGNORECASE)

#: Todas las reglas que el predicado puede eximir (para el aviso `CONFLICTO`).
OPERADOR_REGLAS = (
    OPERADOR_REGLAS_IP | OPERADOR_REGLAS_ANGEL | OPERADOR_REGLAS_PRIV | OPERADOR_REGLAS_SSHD
)

#: Eventos de ejecución Windows (H4-W): Sysmon 1 y Seguridad 4688.
WIN_EXEC_EVENT_IDS = {"1", "4688"}
WIN_EXEC_GROUPS = {"sysmon_eid1", "sysmon_event1"}

SIGNAL_TIPOS = ("deteccion", "ambigua")
SIGNAL_CAMPOS = (
    "rule_id",
    "rule_group",
    "win_image",
    "win_command_line",
    "win_cwd",
    "win_target",
    "syscheck_path",
)
SIGNAL_HEADER = [
    "senal_id",
    "tipo",
    "campo",
    "patron",
    "dato_componente",
    "tecnica",
    "nota",
]

OUT_HEADER = [
    "ata_id",
    "iter",
    "timestamp_utc",
    "agent_name",
    "rule_id",
    "rule_level",
    "rule_groups",
    "rs_origen",
    "rule_description",
    "categoria",
    "motivo",
    "atribucion",
    "revision",
    "veredicto_humano",
    "evidencia",
]
REV_EXTRA = ["veredicto", "nota", "revisor", "fecha"]

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_SIGNALS = 3
EXIT_GUARDRAIL = 4

DEFAULT_CATALOGO = "Dataset/Legitimo/windows/ruleids_legitimos.csv"
DEFAULT_AUDITED_DIR = "Dataset/Ataques/Resultados/Wazuh/windows/Auditado"
DEFAULT_COMANDOS_DIR = "Dataset/Ataques/Comandos/windows"

#: Raíz del repo (para el replay, que debe funcionar desde cualquier cwd).
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

#: Replay CA-B1-08 (rutas relativas al repo).
BASELINE_V1 = "Dataset/Legitimo/windows/baseline_detalle_v1.csv"
BASELINE_V1_CAT = "Dataset/Legitimo/windows/ruleids_legitimos_v1.csv"
BASELINE_V2 = "Dataset/Legitimo/windows/baseline_detalle_v2.csv"
BASELINE_V2_CAT = "Dataset/Legitimo/windows/ruleids_legitimos.csv"  # union v1+v2


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv_rows(path: str, required: list[str] | None = None):
    """Lee un CSV ignorando líneas de comentario `#`. Devuelve (fieldnames, filas)."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    fieldnames = list(reader.fieldnames or [])
    rows = list(reader)
    if required:
        missing = [c for c in required if c not in fieldnames]
        if missing:
            raise ValueError(f"{path}: faltan columnas {missing}; tiene {fieldnames}")
    return fieldnames, rows


def _norm(value: str) -> str:
    """Normaliza para comparar rutas/command lines Windows (minúsculas + `\\`)."""
    v = (value or "").strip().strip('"').replace("/", "\\")
    return v.lower()


def glob_match(value: str, pattern: str) -> bool:
    """Glob case-insensitive para Windows (rutas y command lines)."""
    if not pattern:
        return False
    return fnmatch.fnmatchcase(_norm(value), _norm(pattern))


def basename_win(value: str) -> str:
    v = (value or "").strip().strip('"')
    return ntpath.basename(v) if v else ""


def _ruta_win_abs(value: str, cwd: str) -> str:
    """Resuelve una ruta Windows (absoluta o relativa al `cwd`). Devuelve `\\` normalizado."""
    v = (value or "").strip().strip('"').replace("/", "\\")
    if not v:
        return ""
    if ntpath.isabs(v):
        return ntpath.normpath(v)
    if cwd:
        return ntpath.normpath(ntpath.join(cwd.replace("/", "\\"), v))
    return ntpath.normpath(v)


def _bajo_carpeta(path: str, carpeta: str) -> bool:
    p = _norm(path).rstrip("\\")
    c = _norm(carpeta).rstrip("\\")
    return bool(p) and (p == c or p.startswith(c + "\\"))


# --------------------------------------------------------------------------
# Carga de entradas
# --------------------------------------------------------------------------
def load_catalogo(path: str) -> set[str]:
    _, rows = read_csv_rows(path, required=["rule_id"])
    return {str(r["rule_id"]).strip() for r in rows if str(r.get("rule_id", "")).strip()}


def load_signals(path: str):
    _, rows = read_csv_rows(path, required=SIGNAL_HEADER)
    signals = []
    errores = []
    for i, r in enumerate(rows, start=2):
        senal_id = (r.get("senal_id") or "").strip()
        tipo = (r.get("tipo") or "").strip()
        campo = (r.get("campo") or "").strip()
        patron = r.get("patron") or ""
        if not senal_id:
            errores.append(f"línea {i}: senal_id vacío")
            continue
        if tipo not in SIGNAL_TIPOS:
            errores.append(f"línea {i}: tipo '{tipo}' no válido (esperado {SIGNAL_TIPOS})")
            continue
        if campo not in SIGNAL_CAMPOS:
            errores.append(f"línea {i}: campo '{campo}' no válido (esperado {SIGNAL_CAMPOS})")
            continue
        signals.append(
            {
                "senal_id": senal_id,
                "tipo": tipo,
                "campo": campo,
                "patron": patron,
                "dato_componente": (r.get("dato_componente") or "").strip(),
                "tecnica": (r.get("tecnica") or "").strip(),
            }
        )
    if errores:
        raise ValueError("señales inválidas en " + path + ": " + "; ".join(errores))
    return signals


# --------------------------------------------------------------------------
# Auto-ruido (§3) — solo la imagen del servicio del canal
# --------------------------------------------------------------------------
def detectar_auto_ruido(row: dict):
    """`auto_ruido` del canal SSH: **solo** `sshd.exe` (imagen del servicio).

    Los hijos de `sshd.exe` (`cmd.exe`, `powershell.exe`…) **no** son canal: el ataque
    corre dentro de esa sesión y se atribuye por carpeta. Devuelve `(evidencia, motivo)`.
    """
    img = (row.get("win_image") or "").strip()
    if img and basename_win(img).lower() in CANAL_SSH_IMAGENES:
        return (f"win_image={img}", "canal-ssh")
    return None


# --------------------------------------------------------------------------
# Pertenencia al ataque (§3) — prueba DEMOSTRABLE por carpeta
# --------------------------------------------------------------------------
def es_del_ataque(row: dict, ata_id: str) -> str:
    """Devuelve `campo=valor` si la fila es DEL ATAQUE, o "".

    "Del ataque" = `win_cwd`, `win_command_line`, `win_target` o `syscheck_path` bajo
    `C:\\lab-attack\\ATA<NNN>`. La carpeta la crea y usa solo el ataque.
    """
    if not ata_id:
        return ""
    carpeta = (ATTACK_ROOT.rstrip("\\") + "\\" + ata_id).rstrip("\\")

    cwd = (row.get("win_cwd") or "").strip()
    if cwd and _bajo_carpeta(_ruta_win_abs(cwd, ""), carpeta):
        return f"win_cwd={cwd}"

    for field in ("syscheck_path", "win_target"):
        raw = row.get(field) or ""
        if raw and _bajo_carpeta(_ruta_win_abs(raw, cwd), carpeta):
            return f"{field}={raw}"

    cmd = (row.get("win_command_line") or "").strip()
    if cmd and _norm(carpeta) in _norm(cmd):
        return f"win_command_line={cmd}"

    return ""


# --------------------------------------------------------------------------
# Predicado OPERADOR_WIN (B1.0-SSH.1, §9.6 de la política)
# --------------------------------------------------------------------------
def detectar_operador(row: dict):
    """Devuelve `(rule_id, evidencia)` si la fila es el **logon del canal**; si no, None.

    Condiciones **estrechas** y con la evidencia medida en `canal_ssh.csv`:
    - `60106`/`60137` (4624/4634 de **red**): `win_user=angel` **y** `logon_type=3`.
    - `67024`/`67023` (4624/4634 del **servicio**): `win_user=sshd_<pid>`.
    - `67028` (4672): `win_user=angel` **o** `sshd_<pid>` (4672 no trae `logon_type`).
    - `67022`/`67023`: `srcip=192.168.65.1` (regla del plan; en este laboratorio el 4624
      de SSH **no trae IP** — se declara en `B1.0-SSH.md`).

    Si falta el campo que demuestra la condición, **no** se excluye (lado seguro).
    """
    rid = str(row.get("rule_id") or "").strip()
    srcip = (row.get("srcip") or "").strip()
    # `win_user` es la cuenta *subject* (equipo/SYSTEM) en 4624/4634/4688; el usuario
    # efectivo del logon está en `win_target_user` (columna aditiva).
    user = (row.get("win_target_user") or "").strip() or (row.get("win_user") or "").strip()
    logon = str(row.get("logon_type") or "").strip()

    if rid in OPERADOR_REGLAS_IP and srcip in OPERADOR_SRCIPS:
        return (rid, f"srcip={srcip}")
    if rid in OPERADOR_REGLAS_ANGEL and user.lower() == OPERADOR_USUARIO and logon == "3":
        return (rid, f"win_user={user}|logon_type={logon}")
    if rid == "67028" and (user.lower() == OPERADOR_USUARIO
                           or OPERADOR_USUARIO_SSHD.match(user)):
        return (rid, f"win_user={user}")
    if rid in OPERADOR_REGLAS_SSHD and OPERADOR_USUARIO_SSHD.match(user):
        return (rid, f"win_user={user}")
    return None


def conflictos_operador(signals) -> list[str]:
    """`CONFLICTO` si una señal `deteccion` casa una regla del predicado (anti-frágil).

    La detección va **antes** del predicado, así que prevalece; el aviso deja traza.
    """
    avisos = []
    for s in signals:
        if s["tipo"] != "deteccion" or s["campo"] != "rule_id":
            continue
        for rid in sorted(OPERADOR_REGLAS):
            if glob_match(rid, s["patron"]):
                avisos.append(
                    f"la señal {s['senal_id']} (deteccion, rule_id={s['patron']}) casa una "
                    f"regla del predicado OPERADOR_WIN ({rid}); prevalece la deteccion"
                )
                break
    return avisos


# --------------------------------------------------------------------------
# Señales esperadas
# --------------------------------------------------------------------------
def _valor_campo(row: dict, campo: str):
    if campo == "rule_group":
        grupos = [g for g in (row.get("rule_groups") or "").split("|") if g]
        return grupos or None
    val = (row.get(campo) or "").strip()
    return val or None


def _match_campo(row: dict, campo: str, patron: str):
    """(evaluable, casado, valor). evaluable=False si el campo está ausente."""
    val = _valor_campo(row, campo)
    if val is None:
        return False, False, ""
    if campo == "rule_group":
        for g in val:
            if glob_match(g, patron):
                return True, True, g
        return True, False, "|".join(val)
    if campo == "win_image":
        if glob_match(val, patron):
            return True, True, val
        if glob_match(basename_win(val), patron):
            return True, True, val
        return True, False, val
    if campo in ("win_cwd", "win_target", "syscheck_path"):
        return True, glob_match(_ruta_win_abs(val, ""), patron), val
    return True, glob_match(val, patron), val


def _grupos(row: dict) -> list[str]:
    return [g for g in (row.get("rule_groups") or "").split("|") if g]


def es_evento_ejecucion(row: dict) -> bool:
    """True si la fila es Sysmon 1 o Seguridad 4688 (H4-W)."""
    eid = str(row.get("event_id") or "").strip()
    if eid in WIN_EXEC_EVENT_IDS:
        return True
    if set(_grupos(row)) & WIN_EXEC_GROUPS:
        return True
    return str(row.get("rule_id") or "").strip() == "67027"


def _casa_ancla(row: dict, anchors) -> bool:
    """True si `win_cwd`, `win_command_line`, `win_target` o `syscheck_path` casan un ancla."""
    cwd = (row.get("win_cwd") or "").strip()
    valores = []
    for field in ("win_cwd", "win_command_line", "win_target", "syscheck_path"):
        raw = row.get(field) or ""
        if not raw:
            continue
        if field in ("win_cwd", "win_target", "syscheck_path"):
            p = _ruta_win_abs(raw, cwd)
            valores.extend([p, p + "\\"])
        else:
            valores.append(raw)
    for a in anchors:
        pat = a["patron"]
        if any(glob_match(v, pat) for v in valores):
            return True
    return False


def evaluar_senales(row: dict, signals):
    """Devuelve match_deteccion, match_ambigua, sin_ancla, alguna_evaluable (H4-W)."""
    tiene_win_image = any(
        s["tipo"] == "deteccion" and s["campo"] == "win_image" for s in signals
    )
    anchors = [
        s
        for s in signals
        if s["tipo"] == "deteccion"
        and (
            s["campo"] in ("win_cwd", "win_target", "syscheck_path")
            or (s["campo"] == "win_command_line" and tiene_win_image)
        )
    ]
    match_det = None
    match_amb = None
    sin_ancla = None
    alguna_evaluable = False
    for s in signals:
        campo = s["campo"]
        # Las anclas de detección no son detectoras por sí solas; solo cuentan para
        # `sin_campos` si el campo existe (salvo que no haya `win_image`: entonces
        # `win_command_line` sí puede detectar, comportamiento legado).
        es_ancla = s in anchors and not (campo == "win_command_line" and not tiene_win_image)
        if es_ancla:
            if _valor_campo(row, campo) is not None:
                alguna_evaluable = True
            continue
        evaluable, casa, valor = _match_campo(row, campo, s["patron"])
        if not evaluable:
            continue
        alguna_evaluable = True
        if not casa:
            continue
        if s["tipo"] == "deteccion":
            if campo == "win_image" and anchors:
                if not _casa_ancla(row, anchors):
                    if sin_ancla is None:
                        sin_ancla = (s, f"win_image={valor}")
                    continue
                if not es_evento_ejecucion(row):
                    if sin_ancla is None:
                        sin_ancla = (s, f"win_image={valor}")
                    continue
            if match_det is None:
                match_det = (s, valor)
        elif s["tipo"] == "ambigua" and match_amb is None:
            match_amb = (s, valor)
    return {
        "match_deteccion": match_det,
        "match_ambigua": match_amb,
        "sin_ancla": sin_ancla,
        "alguna_evaluable": alguna_evaluable,
    }


def avisos_ancla(signals) -> list[str]:
    """AVISO (stderr) por señales Windows sin el mecanismo H4-W completo."""
    tiene_win_image = any(
        s["tipo"] == "deteccion" and s["campo"] == "win_image" for s in signals
    )
    tiene_ancla = any(
        s["tipo"] == "deteccion"
        and s["campo"] in ("win_cwd", "win_command_line", "win_target", "syscheck_path")
        for s in signals
    )
    avisos = []
    if tiene_win_image and not tiene_ancla:
        for s in signals:
            if s["tipo"] == "deteccion" and s["campo"] == "win_image":
                avisos.append(
                    f"la señal {s['senal_id']} (deteccion, win_image={s['patron']}) no "
                    "declara ancla (win_cwd/win_command_line/win_target/syscheck_path): "
                    "el recuento puede ser ancho (H4-W); añadir un ancla"
                )
    if not tiene_win_image:
        for s in signals:
            if s["tipo"] == "deteccion" and s["campo"] == "win_command_line":
                avisos.append(
                    f"la señal {s['senal_id']} (deteccion, win_command_line={s['patron']}) "
                    "no declara win_image: se mantiene el comportamiento legado; para H4-W "
                    "declarar win_image + ancla"
                )
    return avisos


def _atribucion(sig: dict) -> str:
    tec = sig.get("tecnica", "")
    dc = sig.get("dato_componente", "")
    return "|".join(p for p in (tec, dc) if p)


# --------------------------------------------------------------------------
# Clasificación (§2) — orden Linux + candado de pertenencia (Windows)
# --------------------------------------------------------------------------
def clasificar(
    row: dict,
    catalogo: set[str],
    signals,
    modo_baseline: bool,
    conflictos: list,
    ata_id: str = "",
    operador: bool = True,
):
    rid = str(row.get("rule_id") or "").strip()
    pertenencia = "" if modo_baseline else es_del_ataque(row, ata_id)
    out = {
        "categoria": "",
        "motivo": "",
        "atribucion": "",
        "revision": "",
        "veredicto_humano": "",
        "evidencia": "",
        "_pertenencia": pertenencia,
    }

    auto = detectar_auto_ruido(row)
    ev = None
    if not modo_baseline and signals:
        ev = evaluar_senales(row, signals)

    # ------------------------------------------------------------------
    # CANDADO B1.0-SSH.1 (G-SSH.1): la pertenencia al ataque se evalúa ANTES
    # que `auto_ruido` y que `operador`. Una fila con evidencia de ataque
    # (`win_cwd`/`win_command_line`/`win_target`/`syscheck_path` bajo
    # `C:\lab-attack\ATA<NNN>`) NUNCA puede caer en `auto_ruido` ni en
    # `ruido_conocido`: o casa una detección declarada, o es `artefacto_ataque`.
    # ------------------------------------------------------------------
    if not modo_baseline and pertenencia:
        if ev is not None and ev["match_deteccion"] is not None:
            s, valor = ev["match_deteccion"]
            out["categoria"] = "deteccion"
            out["motivo"] = f"senal:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        # El resto del orden Linux se mantiene: lo dudoso se revisa, no se descarta.
        if ev is not None:
            if ev["match_ambigua"] is not None:
                s, valor = ev["match_ambigua"]
                out["categoria"] = "dudosa"
                out["motivo"] = f"ambigua:{s['senal_id']}"
                out["atribucion"] = _atribucion(s)
                out["revision"] = "pendiente"
                out["evidencia"] = f"{s['campo']}={valor}"
                return out
            if ev["sin_ancla"] is not None:
                s, eviden = ev["sin_ancla"]
                out["categoria"] = "dudosa"
                out["motivo"] = f"sin_ancla:{s['senal_id']}"
                out["atribucion"] = _atribucion(s)
                out["revision"] = "pendiente"
                out["evidencia"] = eviden
                return out
            if not ev["alguna_evaluable"]:
                out["categoria"] = "dudosa"
                out["motivo"] = "sin_campos"
                out["revision"] = "pendiente"
                out["evidencia"] = ""
                return out
        out["categoria"] = "artefacto_ataque"
        out["motivo"] = "del_ataque"
        out["evidencia"] = pertenencia
        return out

    # 1. auto_ruido (solo filas SIN evidencia de ataque)
    if auto:
        if ev is not None and ev["match_deteccion"] is not None:
            s, _ = ev["match_deteccion"]
            # Una señal por `rule_id`/`rule_group` no "apunta a un proceso": casaría
            # también las filas del servicio del canal y daría un CONFLICTO engañoso.
            if s["campo"] not in ("rule_id", "rule_group"):
                conflictos.append(
                    f"rule_id={rid} timestamp={row.get('timestamp_utc')}: la señal "
                    f"{s['senal_id']} (deteccion) apunta a un proceso de Wazuh "
                    f"({auto[1]}); prevalece auto_ruido (revisar la señal)"
                )
        out["categoria"] = "auto_ruido"
        out["motivo"] = f"auto_ruido:{auto[1]}"
        out["evidencia"] = auto[0]
        return out

    # 2-3. señales esperadas (solo en modo ataque)
    if ev is not None:
        if ev["match_deteccion"] is not None:
            s, valor = ev["match_deteccion"]
            out["categoria"] = "deteccion"
            out["motivo"] = f"senal:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        op = detectar_operador(row) if operador else None
        if op is not None:
            out["categoria"] = "ruido_conocido"
            out["motivo"] = f"operador:{op[0]}"
            out["evidencia"] = op[1]
            return out
        if ev["match_ambigua"] is not None:
            s, valor = ev["match_ambigua"]
            out["categoria"] = "dudosa"
            out["motivo"] = f"ambigua:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["revision"] = "pendiente"
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        if ev["sin_ancla"] is not None:
            s, eviden = ev["sin_ancla"]
            out["categoria"] = "dudosa"
            out["motivo"] = f"sin_ancla:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["revision"] = "pendiente"
            out["evidencia"] = eviden
            return out
        if not ev["alguna_evaluable"]:
            out["categoria"] = "dudosa"
            out["motivo"] = "sin_campos"
            out["revision"] = "pendiente"
            out["evidencia"] = ""
            return out

    # 3.5. artefacto_ataque: ya resuelto por el CANDADO de arriba (una fila con
    # evidencia de ataque retorna antes de `auto_ruido`/`operador`).

    # 4-5. catálogo
    if rid not in catalogo:
        if not modo_baseline:
            out["categoria"] = "deteccion"
            out["motivo"] = "novel"
            out["evidencia"] = f"rule_id={rid}"
            return out
    out["categoria"] = "ruido_conocido"
    out["motivo"] = "baseline"
    out["evidencia"] = f"rule_id={rid}"
    return out


def _clave_revision(row: dict) -> tuple:
    return (
        (row.get("timestamp_utc") or "").strip(),
        str(row.get("rule_id") or "").strip(),
        (row.get("agent_name") or "").strip(),
        (row.get("evidencia") or "").strip(),
    )


# --------------------------------------------------------------------------
# Escritura
# --------------------------------------------------------------------------
def write_csv(path: str, header: list[str], rows, comment: str | None = None) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        if comment:
            fh.write(comment.rstrip("\n") + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        for r in rows:
            writer.writerow([r.get(c, "") for c in header])


def construir_comentario(nombre, ata, it, modo, entradas, conteos, operador=True) -> str:
    parts = [
        f"{nombre} | TFG HIDS - B1.0 filtro Windows (H4-W) | ata={ata} iter={it}",
        f"modo={'baseline' if modo == 'baseline' else 'ataque'}",
        f"operador={'on' if operador else 'off (sensibilidad --sin-operador)'}",
    ]
    for etiqueta, path, sha in entradas:
        parts.append(f"{etiqueta}={path} sha256={sha}")
    parts.append(
        "conteos: filas={filas} deteccion={deteccion} auto_ruido={auto_ruido} "
        "ruido_conocido={ruido_conocido} dudosa={dudosa} "
        "artefacto_ataque={artefacto_ataque}".format(**conteos)
    )
    parts.append("columnas: " + ",".join(OUT_HEADER))
    return "# " + " | ".join(parts)


# --------------------------------------------------------------------------
# Replay de la baseline Windows (CA-B1-08)
# --------------------------------------------------------------------------
def _contar_baseline(alerta: str, catalogo: str) -> tuple[int, int]:
    if not os.path.isabs(alerta):
        alerta = os.path.join(REPO_ROOT, alerta)
    if not os.path.isabs(catalogo):
        catalogo = os.path.join(REPO_ROOT, catalogo)
    _, alertas = read_csv_rows(alerta)
    cats = load_catalogo(catalogo)
    n_det = 0
    for r in alertas:
        c = clasificar(r, cats, [], True, [], "baseline")
        if c["categoria"] == "deteccion":
            n_det += 1
    return len(alertas), n_det


def replay_baseline() -> int:
    print("== replay baseline Windows (CA-B1-08) ==")
    ok = True
    for etiqueta, alerta, catalogo in (
        ("v1", BASELINE_V1, BASELINE_V1_CAT),
        ("v2", BASELINE_V2, BASELINE_V2_CAT),
    ):
        n, det = _contar_baseline(alerta, catalogo)
        estado = "PASA" if det == 0 else "FALLA"
        if det != 0:
            ok = False
        print(f"{etiqueta}: filas={n} deteccion={det} -> {estado} ({alerta} + {catalogo})")
    return EXIT_OK if ok else 1


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def _descubrir_esperado(ata_id: str) -> str | None:
    patron = os.path.join(DEFAULT_COMANDOS_DIR, "*", f"{ata_id}_esperado.csv")
    hits = sorted(glob.glob(patron))
    return hits[0] if len(hits) == 1 else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Filtro de ruido y etiquetado auditado de alertas (Windows, B1.0)."
    )
    ap.add_argument("--alerta", help="CSV de detalle (una fila por alerta)")
    ap.add_argument("--ata", default="", help="identificador del ataque (ATA056...)")
    ap.add_argument("--iter", type=int, default=1, help="iteración (1 o 2)")
    ap.add_argument("--catalogo", default=DEFAULT_CATALOGO, help="catálogo baseline Windows")
    ap.add_argument("--esperado", help="ATA<NNN>_esperado.csv (obligatorio salvo --modo baseline)")
    ap.add_argument(
        "--modo",
        choices=("ataque", "baseline"),
        default="ataque",
        help="'baseline' = ventana sin ataque (no exige señales)",
    )
    ap.add_argument("--revision", help="CSV de revisión previo a plegar")
    ap.add_argument("--out", help="CSV audited de salida")
    ap.add_argument("--rev-out", help="CSV de revisión de salida")
    ap.add_argument(
        "--replay-baseline",
        action="store_true",
        help="ejecuta CA-B1-08 (v1 72 + catálogo v1; v2 87 + catálogo v1+v2) y sale",
    )
    ap.add_argument(
        "--sin-operador",
        action="store_true",
        help="sensibilidad: no aplica el predicado OPERADOR_WIN (el canal contaría como novel)",
    )
    args = ap.parse_args(argv)

    if args.replay_baseline:
        return replay_baseline()

    if not args.alerta:
        print("ERROR: --alerta es obligatorio (o usa --replay-baseline)", file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isfile(args.alerta):
        print(f"ERROR: no existe el fichero de alertas: {args.alerta}", file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isfile(args.catalogo):
        print(f"ERROR: no existe el catálogo: {args.catalogo}", file=sys.stderr)
        return EXIT_USAGE

    modo_baseline = args.modo == "baseline"
    ata = args.ata or ("baseline" if modo_baseline else "")
    if not ata:
        print("ERROR: --ata es obligatorio en modo ataque", file=sys.stderr)
        return EXIT_USAGE

    esperado = args.esperado
    if not modo_baseline:
        if not esperado:
            esperado = _descubrir_esperado(ata)
        if not esperado:
            print(
                f"ERROR: falta el fichero de señales esperadas para {ata} "
                f"(esperado {DEFAULT_COMANDOS_DIR}/*/{ata}_esperado.csv). "
                "Sin señales, el filtro no puede atribuir ataques; usa --esperado "
                "o --modo baseline si la ventana no contiene ataque.",
                file=sys.stderr,
            )
            return EXIT_NO_SIGNALS
        if not os.path.isfile(esperado):
            print(f"ERROR: no existe el fichero de señales: {esperado}", file=sys.stderr)
            return EXIT_NO_SIGNALS

    try:
        _, alertas = read_csv_rows(args.alerta)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        catalogo = load_catalogo(args.catalogo)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    signals = []
    conflictos: list[str] = []
    if not modo_baseline:
        try:
            signals = load_signals(esperado)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not signals:
            print(f"ERROR: {esperado} no contiene señales", file=sys.stderr)
            return EXIT_NO_SIGNALS
        conflictos.extend(conflictos_operador(signals))
        for aviso in avisos_ancla(signals):
            print(f"AVISO: {aviso}", file=sys.stderr)

    filas = []
    for r in alertas:
        c = clasificar(r, catalogo, signals, modo_baseline, conflictos, ata,
                       operador=not args.sin_operador)
        fila = {
            "ata_id": ata,
            "iter": args.iter,
            "timestamp_utc": r.get("timestamp_utc", ""),
            "agent_name": r.get("agent_name", ""),
            "rule_id": r.get("rule_id", ""),
            "rule_level": r.get("rule_level", ""),
            "rule_groups": r.get("rule_groups", ""),
            "rs_origen": r.get("rs_origen", ""),
            "rule_description": r.get("rule_description", ""),
            **c,
        }
        filas.append(fila)

    avisos_artefacto = [
        f"rule_id={f['rule_id']} timestamp={f['timestamp_utc']}: ejecucion no declarada "
        f"en {f['evidencia']} -> artefacto_ataque (posible señal de detección no declarada)"
        for f in filas
        if f["categoria"] == "artefacto_ataque" and f["motivo"] == "del_ataque"
    ]

    filas.sort(key=lambda x: (x["timestamp_utc"], x["rule_id"], x["evidencia"]))

    if args.revision:
        if not os.path.isfile(args.revision):
            print(f"ERROR: no existe el fichero de revisión: {args.revision}", file=sys.stderr)
            return EXIT_USAGE
        _, rev_rows = read_csv_rows(args.revision)
        rev_map = {}
        for rr in rev_rows:
            rev_map[_clave_revision(rr)] = rr
        usadas = set()
        violaciones = []
        for fila in filas:
            if fila["categoria"] != "dudosa":
                continue
            clave = _clave_revision(fila)
            rr = rev_map.get(clave)
            if rr is None:
                continue
            veredicto = (rr.get("veredicto") or "").strip().lower()
            if veredicto not in ("deteccion", "ruido", "artefacto"):
                continue
            if veredicto == "ruido":
                pertenencia = fila.get("_pertenencia", "")
                if pertenencia:
                    violaciones.append((clave, pertenencia))
                    continue
            usadas.add(clave)
            if veredicto == "deteccion":
                fila["categoria"] = "deteccion"
            elif veredicto == "ruido":
                fila["categoria"] = "ruido_conocido"
            else:
                fila["categoria"] = "artefacto_ataque"
                fila["motivo"] = "del_ataque"
                pertenencia = fila.get("_pertenencia", "")
                if pertenencia:
                    fila["evidencia"] = pertenencia
            fila["revision"] = "resuelta"
            fila["veredicto_humano"] = veredicto
            extras = []
            if (rr.get("revisor") or "").strip():
                extras.append(f"revisor={rr['revisor'].strip()}")
            if (rr.get("fecha") or "").strip():
                extras.append(f"fecha={rr['fecha'].strip()}")
            if (rr.get("nota") or "").strip():
                extras.append(f"nota={rr['nota'].strip()}")
            if extras:
                sep = ";" if fila["evidencia"] else ""
                fila["evidencia"] = fila["evidencia"] + sep + ";".join(extras)
        for clave, rr in rev_map.items():
            if clave in usadas:
                continue
            if (rr.get("veredicto") or "").strip():
                print(
                    f"AVISO: revisión con clave no encontrada en la ventana (ignorada): {clave}",
                    file=sys.stderr,
                )
        if violaciones:
            for clave, pertenencia in violaciones:
                print(
                    f"ERROR: veredicto=ruido PROHIBIDO sobre una fila DEL ATAQUE "
                    f"(§3.2): key={clave} pertenencia={pertenencia}; usar "
                    "'deteccion' o 'artefacto'.",
                    file=sys.stderr,
                )
            return EXIT_GUARDRAIL

    out = args.out or os.path.join(
        DEFAULT_AUDITED_DIR, f"{ata}_iter{args.iter}-Audited.csv"
    )
    if args.rev_out:
        rev_out = args.rev_out
    elif args.out:
        rev_out = os.path.join(
            os.path.dirname(out), f"{ata}_iter{args.iter}-Revision.csv"
        )
    else:
        rev_out = os.path.join(
            DEFAULT_AUDITED_DIR, f"{ata}_iter{args.iter}-Revision.csv"
        )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    os.makedirs(os.path.dirname(rev_out), exist_ok=True)

    conteos = {
        "filas": len(filas),
        "deteccion": sum(1 for f in filas if f["categoria"] == "deteccion"),
        "auto_ruido": sum(1 for f in filas if f["categoria"] == "auto_ruido"),
        "ruido_conocido": sum(1 for f in filas if f["categoria"] == "ruido_conocido"),
        "dudosa": sum(1 for f in filas if f["categoria"] == "dudosa"),
        "artefacto_ataque": sum(1 for f in filas if f["categoria"] == "artefacto_ataque"),
    }
    entradas = [("alerta", args.alerta, sha256_file(args.alerta))]
    entradas.append(("catalogo", args.catalogo, sha256_file(args.catalogo)))
    if not modo_baseline:
        entradas.append(("esperado", esperado, sha256_file(esperado)))
    if args.revision:
        entradas.append(("revision", args.revision, sha256_file(args.revision)))

    comment = construir_comentario(
        os.path.basename(out), ata, args.iter, args.modo, entradas, conteos,
        operador=not args.sin_operador,
    )
    write_csv(out, OUT_HEADER, filas, comment=comment)

    dudosas = [f for f in filas if f["categoria"] == "dudosa"]
    if dudosas:
        rev_rows = [dict(f, veredicto="", nota="", revisor="", fecha="") for f in dudosas]
        rev_comment = construir_comentario(
            os.path.basename(rev_out), ata, args.iter, args.modo, entradas, conteos,
            operador=not args.sin_operador,
        )
        write_csv(rev_out, OUT_HEADER + REV_EXTRA, rev_rows, comment=rev_comment)

    for c in conflictos:
        print(f"CONFLICTO: {c}", file=sys.stderr)
    for a in avisos_artefacto:
        print(f"AVISO: {a}", file=sys.stderr)

    print(
        f"filas={conteos['filas']} deteccion={conteos['deteccion']} "
        f"auto_ruido={conteos['auto_ruido']} "
        f"ruido_conocido={conteos['ruido_conocido']} dudosa={conteos['dudosa']} "
        f"artefacto_ataque={conteos['artefacto_ataque']} -> {out}"
    )
    if dudosas:
        print(f"revisión pendiente: {len(dudosas)} filas -> {rev_out}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
