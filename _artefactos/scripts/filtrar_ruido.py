#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""filtrar_ruido.py — Filtro de ruido y etiquetado auditado de alertas (Fase 3 · A2.1).

Toma la **ventana de alertas de un ataque** (una fila por alerta; salida de
`extraer_alertas.py --detail`) y el **catálogo baseline**
(`Dataset/Legitimo/ruleids_legitimos.csv`) y produce
`ATA<NNN>_iter{N}-Audited.csv`: cada alerta clasificada por capa (`rs_origen`
copiado sin alterar) y etiquetada con una de cuatro categorías.

Categorías y **orden exacto** de decisión (`plan.md` §2; gana el primero):

    1.   auto_ruido       si el ORIGEN es el propio Wazuh (por campos; incluye la
                         firma interna del manager `rule_id=11` + grupo `stats`)
    2.   deteccion        si casa una SEÑAL ESPERADA de tipo `deteccion` (ANCLADA,
                          §2.2: una señal `audit_exe` solo casa si `exe ∧ cwd-ancla/ruta
                          ∧` evento de ejecución `audit_command`)
    1.5  ruido_conocido   si casa el PREDICADO OPERADOR (H3 §4.1): `5715` con
                          `srcip ∈ OPERADOR_SRCIPS` o `19004` con grupo `sca`
                          (motivo `operador:<rule_id>`). `5501`/`5502` NO están en
                          el predicado -> caen a `dudosa`/`sin_campos` solo si el
                          `esperado` no declara ninguna señal de campo siempre
                          evaluable; si declara `rule_id`/`rule_group`, `sin_campos`
                          no dispara -> paso 6 -> `ruido_conocido`/`baseline`.
    3.   dudosa           si casa una SEÑAL ESPERADA de tipo `ambigua`, **o** si casa
                          un `audit_exe` de detección pero falla el ancla / el evento
                          de ejecución (motivo `sin_ancla:<senal_id>`), **o** si no es
                          evaluable ninguna señal (falta el campo; motivo `sin_campos`)
    3.5  artefacto_ataque si la fila es "DEL ATAQUE" (`audit_cwd` o ruta —`audit_file`/
                          `audit_dir`/`syscheck_path` resuelta contra el `cwd`— bajo
                          `ATTACK_ROOT/<ATA_id>`) y NO casó una detección declarada
                          (motivo `del_ataque`). **Nunca** `ruido_conocido`.
    4.   deteccion        si rule.id NO está en el catálogo (motivo `novel`)
    5.   ruido_conocido   si rule.id SÍ está en el catálogo (motivo `baseline`);
                          tras el arreglo, solo contiene filas que **no** son del ataque

Pertenencia al ataque (§3, bloque `fase-03-metrica`). `ATTACK_ROOT` =
`/home/angel/lab-attack/`; la carpeta del ataque se deriva del `--ata`
(`ATTACK_ROOT + ata_id`), de modo que **también cubre a los 3 del piloto**
(ATA002/008/013) **sin editar** su `esperado`. Es una prueba **demostrable**: esa
carpeta la crea y usa solo el ataque. La `evidencia` de una fila `artefacto_ataque`
es el campo que demostró la pertenencia (`audit_cwd=…` / `audit_file=…`).

Guardarraíl de plegado (§3.2). En `--revision`, un `veredicto=ruido` sobre una fila
**del ataque** hace **fallar** la herramienta (`exit != 0`, código 4) indicando la
fila: el humano debe elegir `deteccion` **o** el tercer veredicto **`artefacto`**
(que pliega a `artefacto_ataque`, `revision=resuelta`, `veredicto_humano=artefacto`).
Un `veredicto=artefacto` sobre una fila ajena también se admite (mapea igual).

`AVISO` (§3.2). Una fila `artefacto_ataque` con grupo `audit_command` (execve de un
binario **no declarado**) emite **`AVISO`** *"posible señal de detección no
declarada"* por `stderr` (transparencia; p. ej. las 6 filas `80792` de ATA013).

Ancla implícita (§2.2). Toda señal `tipo=deteccion, campo=audit_cwd` de un
`esperado` es un **ancla** (una condición AND), **no** un detector por sí sola.
Si el `esperado` declara ≥1 ancla, una señal `deteccion` con `campo=audit_exe`
casa la fila **solo si** se cumplen las tres: (i) el `audit_exe` casa el patrón
(`full` o `basename`), (ii) el `audit_cwd` de la fila casa el ancla — el match
prueba el `cwd` **y** `cwd + "/"`, de modo que el patrón `…/ATA<NNN>/*` casa el
`cwd` real `…/ATA<NNN>` (el `*` casa la cadena vacía) — **o** alguna ruta
(`audit_file`/`audit_dir`/`syscheck_path`, resuelta contra el `cwd`) casa el ancla
(mejora C, §3.2; así un `watch` del `.tar.gz` creado en la carpeta del ataque queda
anclado), y (iii) la fila es un evento de ejecución (`rule_groups` contiene
`audit_command`; en un evento `watch` el `audit_exe` es el causante de la escritura,
no "el proceso del ataque") — como (iii) no se cumple en un `watch`, este sigue
yendo a `dudosa` (`sin_ancla`; la escritura es `artefacto_ataque` si el humano no la
cuenta como detección).
Una fila que casa el `audit_exe` pero **falla** el ancla o el evento de ejecución
→ `dudosa` (motivo `sin_ancla:<senal_id>`; `evidencia` = el campo que falló),
**nunca** `deteccion` ni `ruido_conocido`: nada se descarta en silencio. Si el
`esperado` **no** declara ancla se mantiene el comportamiento **legado** (el
`audit_exe` casa solo) y se emite un **`AVISO`** por `stderr` invitando a declarar
el ancla (convención H4).

`auto_ruido` es **categoría propia** y **nunca** cuenta como detección. Si una
señal `deteccion` apuntara a un proceso de Wazuh se emite **CONFLICTO** por
stderr (no se resuelve en silencio).

Señales esperadas (`ATA<NNN>_esperado.csv`, plan §2):
    senal_id,tipo,campo,patron,dato_componente,tecnica,nota
    tipo  ∈ {deteccion, ambigua}
    campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key, syscheck_path}
    patron: literal o glob `*`/`?` (fnmatch)

Sin fichero de señales la herramienta **falla ruidosamente** (exit != 0); solo
el modo explícito `--modo baseline` permite pasar una ventana sin ataque.

El fichero de revisión (`ATA<NNN>_iter{N}-Revision.csv`) contiene las filas
dudosas + columnas `veredicto,nota,revisor,fecha` para el humano. Al re-ejecutar
con `--revision <fichero>` los veredictos se pliegan (`revision=resuelta`); el
`veredicto` admite `deteccion` (`→ deteccion`), `ruido` (`→ ruido_conocido`;
**prohibido** sobre una fila del ataque, §3.2) y `artefacto`
(`→ artefacto_ataque`).

Determinismo (R-13): la salida no contiene reloj y depende solo de las entradas;
misma entrada -> salida **byte a byte** idéntica.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import hashlib
import os
import posixpath
import sys

# --------------------------------------------------------------------------
# Constantes (deben coincidir con `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`)
# --------------------------------------------------------------------------
CATEGORIAS = ("deteccion", "ruido_conocido", "auto_ruido", "dudosa", "artefacto_ataque")

# §3 (fase-03-metrica) — raíz de las carpetas de ataque. La carpeta del ataque se
# deriva del `--ata` (`ATTACK_ROOT + ata_id`); prueba DEMOSTRABLE de pertenencia.
ATTACK_ROOT = "/home/angel/lab-attack/"

# §3 — procesos del propio Wazuh (se comparan por nombre base de `audit.exe`)
WAZUH_PROCESOS = {
    "wazuh-agentd",
    "wazuh-syscheckd",
    "wazuh-logcollector",
    "wazuh-modulesd",
    "wazuh-execd",
    "wazuh-db",
    "wazuh-analysisd",
}
WAZUH_CWD = "/var/ossec"
WAZUH_RUN_GLOB = "/var/ossec/var/run/*"

# §3.d (v7, fase-03-auditoria-metodologica) — alerta INTERNA del **manager**
# (`rule_id=11`, grupo `stats`): recuento periódico del propio Wazuh, no un
# proceso de la víctima. Se reconoce por la **firma de la regla** (`rule_id` +
# grupo), **nunca** por `agent_name` (todas las filas traen el mismo agente).
# Va **al final** de `detectar_auto_ruido` para no alterar el `motivo`/`evidencia`
# de ninguna fila que ya casara los pasos anteriores (p. ej. `rule_id=11` con
# `audit_cwd=/var/ossec`, que conserva su `motivo`/`evidencia` previos).
WAZUH_STATS_RULE_ID = "11"
WAZUH_STATS_GROUP = "stats"

# §2.2 — ancla implícita: una señal `deteccion` de proceso (`audit_exe`) solo
# casa si el `audit_cwd` de la fila casa el ancla `audit_cwd` del `esperado` Y
# la fila es un **evento de ejecución**. El grupo `audit_command` (execve) lo
# distingue del evento `watch` (`audit_watch_*`), donde `audit_exe` es el
# causante de la escritura, no el proceso del ataque.
AUDIT_CMD_GROUP = "audit_command"

# --------------------------------------------------------------------------
# H3 (fase-03-afinado §4.1) — predicado OPERADOR
#
# Principio rector: **solo se auto-excluye lo DEMOSTRABLE como propio**; lo que
# no se puede demostrar, se revisa (`dudosa`).
#
#   - `5715` (sshd: authentication success)  -> se auto-excluye SOLO si
#     `srcip ∈ OPERADOR_SRCIPS` (la IP del host/sobremesa en VMnet1). Otra IP
#     (atacante) -> NO se excluye. Si falta `srcip` -> condición NO satisfecha.
#   - `19004` (grupo `sca`) -> se auto-excluye (autoevaluación del HIDS; regla +
#     grupo, sin condición de origen).
#   - `5501`/`5502` (PAM) -> **NUNCA** se auto-excluyen: el `full_log` no trae IP
#     ni id. de sesión, así que la atribución al operador NO es demostrable. Su
#     resultado depende del `esperado`: caen a `dudosa`/`sin_campos` solo si este
#     no declara ninguna señal de campo siempre evaluable; si declara
#     `rule_id`/`rule_group`, `sin_campos` no dispara -> paso 6 ->
#     `ruido_conocido`/`baseline`. Limitación declarada, lado seguro.
# --------------------------------------------------------------------------
OPERADOR_SRCIPS = {"192.168.65.1"}
OPERADOR_5715_GRUPOS = {"sshd", "syslog", "authentication_success"}
OPERADOR_19004_GRUPOS = {"sca"}

# Reglas del predicado (rule_id -> grupos admisibles) para la garantía anti-frágil:
# si una señal declarada casa una de estas reglas, se avisa por stderr (CONFLICTO).
OPERADOR_REGLAS = {
    "5715": OPERADOR_5715_GRUPOS,
    "19004": OPERADOR_19004_GRUPOS,
}

SIGNAL_TIPOS = ("deteccion", "ambigua")
SIGNAL_CAMPOS = (
    "rule_id",
    "rule_group",
    "audit_exe",
    "audit_cwd",
    "audit_key",
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
EXIT_GUARDRAIL = 4  # §3.2: veredicto=ruido sobre una fila DEL ATAQUE (prohibido)

DEFAULT_CATALOGO = "Dataset/Legitimo/ruleids_legitimos.csv"
# Convención por SO (fase-03-afinado §5): los resultados viven bajo `.../Wazuh/linux/`.
# El default de `--out`/`--rev-out` cae dentro del árbol versionado por SO (cabo 1).
DEFAULT_AUDITED_DIR = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_COMANDOS_DIR = "Dataset/Ataques/Comandos"


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
    """Lee un CSV del repo ignorando líneas de comentario `#`.

    Devuelve (fieldnames, filas) donde filas es lista de dict.
    """
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


def glob_match(value: str, pattern: str) -> bool:
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch.fnmatchcase(value, pattern)
    return value == pattern


def basename(value: str) -> str:
    v = (value or "").strip().strip('"')
    return os.path.basename(v) if v else ""


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
# Auto-ruido (§3) — por campos, nunca por rule.id
# --------------------------------------------------------------------------
def _ruta_abs(value: str, cwd: str) -> str:
    v = (value or "").strip().strip('"')
    if not v:
        return ""
    if v.startswith("/"):
        return v
    if cwd:
        return os.path.normpath(cwd.rstrip("/") + "/" + v.lstrip("/"))
    return v


def detectar_auto_ruido(row: dict):
    """Devuelve (evidencia, proceso) si la alerta es del propio Wazuh, o None."""
    exe = (row.get("audit_exe") or "").strip()
    base = basename(exe)
    if base in WAZUH_PROCESOS:
        return f"audit_exe={exe}", base

    cwd = (row.get("audit_cwd") or "").strip()
    if cwd == WAZUH_CWD:
        proceso = base or f"cwd={WAZUH_CWD}"
        return f"audit_cwd={cwd}", proceso

    for field in ("audit_file", "audit_dir", "syscheck_path"):
        raw = row.get(field) or ""
        p = _ruta_abs(raw, cwd)
        if p and glob_match(p, WAZUH_RUN_GLOB):
            return f"{field}={raw}", (base or "ruta")

    # §3.d (v7) — firma interna del **manager** (`rule_id=11` ∧ grupo `stats`).
    # Al ir al FINAL, no cambia ninguna fila que ya casara los pasos anteriores.
    rid = str(row.get("rule_id") or "").strip()
    grupos = {g for g in (row.get("rule_groups") or "").split("|") if g}
    if rid == WAZUH_STATS_RULE_ID and WAZUH_STATS_GROUP in grupos:
        return f"rule_id={rid}", WAZUH_STATS_GROUP
    return None


# --------------------------------------------------------------------------
# Pertenencia al ataque (§3, fase-03-metrica) — prueba DEMOSTRABLE por carpeta
# --------------------------------------------------------------------------
def _ruta_posix_abs(value: str, cwd: str) -> str:
    """Resuelve una ruta POSIX (absoluta o relativa al `cwd`) **sin** `os.path`.

    No usa `os.path.normpath` a propósito: en Windows convertiría `/` en `\\` y
    rompería la comparación con `ATTACK_ROOT` (rutas POSIX de la víctima Linux).
    """
    v = (value or "").strip().strip('"')
    if not v:
        return ""
    if v.startswith("/"):
        return posixpath.normpath(v)
    if cwd:
        return posixpath.normpath(cwd.rstrip("/") + "/" + v.lstrip("/"))
    return posixpath.normpath(v)


def _bajo_carpeta(path: str, carpeta: str) -> bool:
    p = (path or "").rstrip("/")
    return bool(p) and (p == carpeta or p.startswith(carpeta + "/"))


def es_del_ataque(row: dict, ata_id: str) -> str:
    """Devuelve la evidencia (`campo=valor`) si la fila es DEL ATAQUE, o "".

    "Del ataque" = `audit_cwd` o ruta (`audit_file`/`audit_dir`/`syscheck_path`,
    resuelta contra el `cwd`) bajo `ATTACK_ROOT/<ata_id>`. La carpeta la crea y usa
    solo el ataque -> prueba demostrable (no depende de que el `esperado` declare ancla).
    """
    if not ata_id:
        return ""
    carpeta = (ATTACK_ROOT.rstrip("/") + "/" + ata_id).rstrip("/")
    cwd = (row.get("audit_cwd") or "").strip()
    if _bajo_carpeta(cwd, carpeta):
        return f"audit_cwd={cwd}"
    for field in ("audit_file", "audit_dir", "syscheck_path"):
        raw = row.get(field) or ""
        p = _ruta_posix_abs(raw, cwd)
        if p and _bajo_carpeta(p, carpeta):
            return f"{field}={raw}"
    return ""


# --------------------------------------------------------------------------
# Predicado OPERADOR (H3 §4.1) — regla ∧ contexto, solo lo demostrable
# --------------------------------------------------------------------------
def detectar_operador(row: dict):
    """Devuelve `(rule_id, evidencia)` si la alerta es del operador/SCA de forma
    **demostrable**, o `None` si no lo es (o si falta el campo de origen).

    - `5715`: exige grupo (`sshd|syslog|authentication_success`) **y**
      `srcip ∈ OPERADOR_SRCIPS`. Sin `srcip` -> no se cumple.
    - `19004`: exige grupo `sca` (sin condición de origen).
    - `5501`/`5502`: **no** pertenecen al predicado (nunca se auto-excluyen).
    """
    rid = str(row.get("rule_id") or "").strip()
    grupos = {g for g in (row.get("rule_groups") or "").split("|") if g}
    if rid == "5715":
        if not (grupos & OPERADOR_5715_GRUPOS):
            return None
        srcip = (row.get("srcip") or "").strip()
        if srcip in OPERADOR_SRCIPS:
            return ("5715", f"srcip={srcip}")
        return None
    if rid == "19004":
        if "sca" in grupos:
            return ("19004", "rule_group=sca")
        return None
    return None


def conflictos_operador(signals) -> list[str]:
    """Garantía anti-frágil (H3 §4.1): si una señal declarada (`rule_id` o
    `rule_group`) **casaría una regla del predicado**, se avisa. Evita que una
    señal declarada se excluya en silencio (la detección va antes del paso 1.5)."""
    out = []
    for s in signals:
        campo = s["campo"]
        pat = s["patron"]
        if campo == "rule_id":
            hits = [rid for rid in OPERADOR_REGLAS if glob_match(rid, pat)]
        elif campo == "rule_group":
            hits = [
                rid
                for rid, gs in OPERADOR_REGLAS.items()
                if any(glob_match(g, pat) for g in gs)
            ]
        else:
            continue
        for rid in hits:
            out.append(
                f"la señal {s['senal_id']} ({s['tipo']}, {campo}={pat}) casa la regla "
                f"{rid} del predicado OPERADOR: prevalece la detección (no se resuelve "
                "en silencio; revisar la señal)"
            )
    return out


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
    if campo == "audit_exe":
        if glob_match(val, patron):
            return True, True, val
        if glob_match(basename(val), patron):
            return True, True, val
        return True, False, val
    return True, glob_match(val, patron), val


def _grupos(row: dict) -> list[str]:
    return [g for g in (row.get("rule_groups") or "").split("|") if g]


def es_evento_ejecucion(row: dict) -> bool:
    """True si la fila es un `execve` (grupo `audit_command`), no un `watch`."""
    return AUDIT_CMD_GROUP in _grupos(row)


def _casa_ancla(row: dict, anchors) -> bool:
    """True si el `cwd` **o** una ruta de la fila casa un patrón de señal-ancla.

    Prueba el `cwd` **y** `cwd + "/"`, para que el patrón `…/ATA<NNN>/*` case el
    `cwd` real `…/ATA<NNN>` (el `*` casa la cadena vacía). **Mejora C (§3.2):**
    prueba además `audit_file`/`audit_dir`/`syscheck_path` resueltos contra el
    `cwd`, de modo que una ruta dentro de la carpeta del ataque también ancla
    (p. ej. el `.tar.gz` creado por el ataque).
    """
    cwd = (row.get("audit_cwd") or "").strip()
    valores = [cwd, cwd + "/"]
    for field in ("audit_file", "audit_dir", "syscheck_path"):
        p = _ruta_posix_abs(row.get(field) or "", cwd)
        if p:
            valores.append(p)
            valores.append(p + "/")
    for a in anchors:
        pat = a["patron"]
        if any(glob_match(v, pat) for v in valores):
            return True
    return False


def evaluar_senales(row: dict, signals):
    """Devuelve dict con match_deteccion, match_ambigua, sin_ancla, alguna_evaluable.

    - Las señales `tipo=deteccion, campo=audit_cwd` son el **ancla** (§2.2): se
      consumen como condición, no detectan por sí solas.
    - Una señal `deteccion` con `campo=audit_exe` solo casa si (i) el `exe` casa,
      (ii) el `audit_cwd` de la fila casa el ancla y (iii) la fila es un evento
      de ejecución. Si el `exe` casa pero falla (ii) o (iii) → `sin_ancla`.
    - Sin ancla declarada, la señal `audit_exe` mantiene el comportamiento legado.
    """
    anchors = [
        s for s in signals if s["tipo"] == "deteccion" and s["campo"] == "audit_cwd"
    ]
    match_det = None
    match_amb = None
    sin_ancla = None
    alguna_evaluable = False
    for s in signals:
        campo = s["campo"]
        if s["tipo"] == "deteccion" and campo == "audit_cwd":
            # señal-ancla: no es un detector por sí sola (es la condición AND del
            # `audit_exe`); solo cuenta para `sin_campos` si el campo existe.
            if _valor_campo(row, "audit_cwd") is not None:
                alguna_evaluable = True
            continue
        evaluable, casa, valor = _match_campo(row, campo, s["patron"])
        if not evaluable:
            continue
        alguna_evaluable = True
        if not casa:
            continue
        if s["tipo"] == "deteccion":
            if campo == "audit_exe" and anchors:
                cwd = (row.get("audit_cwd") or "").strip()
                if not _casa_ancla(row, anchors):
                    if sin_ancla is None:
                        sin_ancla = (s, f"audit_cwd={cwd}")
                    continue
                if not es_evento_ejecucion(row):
                    if sin_ancla is None:
                        sin_ancla = (s, f"audit_exe={valor}")
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
    """`AVISO` (stderr, no bloqueante) por señal `audit_exe` de detección sin ancla.

    Retrocompatibilidad: un `esperado` sin ancla mantiene el comportamiento legado
    (el `audit_exe` casa solo) pero el recuento puede ser **ancho** (convención H4).
    """
    tiene_ancla = any(
        s["tipo"] == "deteccion" and s["campo"] == "audit_cwd" for s in signals
    )
    if tiene_ancla:
        return []
    return [
        f"la señal {s['senal_id']} (deteccion, audit_exe={s['patron']}) no declara "
        "ancla audit_cwd: el recuento puede ser ancho (convención H4); añadir una "
        "señal deteccion audit_cwd de la carpeta del ataque"
        for s in signals
        if s["tipo"] == "deteccion" and s["campo"] == "audit_exe"
    ]


def _atribucion(sig: dict) -> str:
    tec = sig.get("tecnica", "")
    dc = sig.get("dato_componente", "")
    return "|".join(p for p in (tec, dc) if p)


# --------------------------------------------------------------------------
# Clasificación (§2)
# --------------------------------------------------------------------------
def clasificar(
    row: dict,
    catalogo: set[str],
    signals,
    modo_baseline: bool,
    conflictos: list,
    ata_id: str = "",
):
    rid = str(row.get("rule_id") or "").strip()
    # §3 pertenencia al ataque (prueba demostrable por carpeta); se arrastra en la
    # fila como clave privada `_pertenencia` para el guardarraíl de plegado.
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
    # Conflicto: señal deteccion que apunta a un proceso de Wazuh (se evalúa igual)
    if not modo_baseline and signals:
        ev = evaluar_senales(row, signals)
        if auto and ev["match_deteccion"] is not None:
            s, _ = ev["match_deteccion"]
            conflictos.append(
                f"rule_id={rid} timestamp={row.get('timestamp_utc')}: la señal "
                f"{s['senal_id']} (deteccion) apunta a un proceso de Wazuh "
                f"({auto[1]}); prevalece auto_ruido (revisar la señal)"
            )

    # 1. auto_ruido
    if auto:
        out["categoria"] = "auto_ruido"
        out["motivo"] = f"auto_ruido:{auto[1]}"
        out["evidencia"] = auto[0]
        return out

    # 2-3. señales esperadas (solo en modo ataque)
    if ev is not None:
        # 2. deteccion (gana a todo lo que sigue, incluido el paso 1.5)
        if ev["match_deteccion"] is not None:
            s, valor = ev["match_deteccion"]
            out["categoria"] = "deteccion"
            out["motivo"] = f"senal:{s['senal_id']}"
            out["atribucion"] = _atribucion(s)
            out["evidencia"] = f"{s['campo']}={valor}"
            return out
        # 1.5. OPERADOR (H3 §4.1) — solo lo DEMOSTRABLE
        op = detectar_operador(row)
        if op is not None:
            out["categoria"] = "ruido_conocido"
            out["motivo"] = f"operador:{op[0]}"
            out["evidencia"] = op[1]
            return out
        # 3. dudosa (ambigua / sin_ancla / sin_campos)
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

    # 3.5. artefacto_ataque (§3.2, fase-03-metrica) — fila DEL ATAQUE que NO casó
    # una detección declarada. Nunca cae en ruido_conocido. Es determinista.
    if not modo_baseline and out["_pertenencia"]:
        out["categoria"] = "artefacto_ataque"
        out["motivo"] = "del_ataque"
        out["evidencia"] = out["_pertenencia"]
        return out

    # 4-5. catálogo
    if rid not in catalogo:
        # En modo baseline la ventana se declara sin ataque: una novedad no puede
        # contar como detección y se absorbe como ruido conocido (plan §8-a).
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


def construir_comentario(nombre, ata, it, modo, entradas, conteos) -> str:
    parts = [
        f"{nombre} | TFG HIDS - Fase 3 A2.1 (R-09/R-13) | ata={ata} iter={it}",
        f"modo={'baseline' if modo == 'baseline' else 'ataque'}",
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
# main
# --------------------------------------------------------------------------
def _descubrir_esperado(ata_id: str) -> str | None:
    patron = os.path.join(DEFAULT_COMANDOS_DIR, "*", f"{ata_id}_esperado.csv")
    hits = sorted(glob.glob(patron))
    return hits[0] if len(hits) == 1 else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Filtro de ruido y etiquetado auditado de alertas (Fase 3, A2.1)."
    )
    ap.add_argument("--alerta", required=True, help="CSV de detalle (una fila por alerta)")
    ap.add_argument("--ata", required=True, help="identificador del ataque (ATA001...)")
    ap.add_argument("--iter", type=int, default=1, help="iteración (1 o 2)")
    ap.add_argument("--catalogo", default=DEFAULT_CATALOGO, help="catálogo baseline")
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
    args = ap.parse_args(argv)

    # --- entradas ---
    if not os.path.isfile(args.alerta):
        print(f"ERROR: no existe el fichero de alertas: {args.alerta}", file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isfile(args.catalogo):
        print(f"ERROR: no existe el catálogo: {args.catalogo}", file=sys.stderr)
        return EXIT_USAGE

    modo_baseline = args.modo == "baseline"
    esperado = args.esperado
    if not modo_baseline:
        if not esperado:
            esperado = _descubrir_esperado(args.ata)
        if not esperado:
            print(
                f"ERROR: falta el fichero de señales esperadas para {args.ata} "
                f"(esperado {DEFAULT_COMANDOS_DIR}/*/{args.ata}_esperado.csv). "
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
        # Garantía anti-frágil H3: señal declarada sobre una regla del predicado.
        conflictos.extend(conflictos_operador(signals))
        # §2.2 — AVISO (no bloqueante) por señal `audit_exe` sin ancla declarada.
        for aviso in avisos_ancla(signals):
            print(f"AVISO: {aviso}", file=sys.stderr)

    # --- clasificación ---
    filas = []
    for r in alertas:
        c = clasificar(r, catalogo, signals, modo_baseline, conflictos, args.ata)
        fila = {
            "ata_id": args.ata,
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

    # §3.2 — AVISO (stderr, no bloqueante): execve no declarado que solo es artefacto
    avisos_artefacto = [
        f"rule_id={f['rule_id']} timestamp={f['timestamp_utc']}: execve no declarado "
        f"en {f['evidencia']} -> artefacto_ataque (posible señal de detección no declarada)"
        for f in filas
        if f["categoria"] == "artefacto_ataque"
        and f["motivo"] == "del_ataque"
        and AUDIT_CMD_GROUP in [g for g in (f.get("rule_groups") or "").split("|") if g]
    ]

    filas.sort(key=lambda x: (x["timestamp_utc"], x["rule_id"], x["evidencia"]))

    # --- plegar revisión humana ---
    if args.revision:
        if not os.path.isfile(args.revision):
            print(f"ERROR: no existe el fichero de revisión: {args.revision}", file=sys.stderr)
            return EXIT_USAGE
        _, rev_rows = read_csv_rows(args.revision)
        rev_map = {}
        for rr in rev_rows:
            clave = (
                (rr.get("timestamp_utc") or "").strip(),
                str(rr.get("rule_id") or "").strip(),
                (rr.get("agent_name") or "").strip(),
                (rr.get("evidencia") or "").strip(),
            )
            rev_map[clave] = rr
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
            # §3.2 guardarraíl: prohibido plegar a `ruido` una fila DEL ATAQUE.
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
            else:  # artefacto
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

    # --- salidas ---
    out = args.out or os.path.join(
        DEFAULT_AUDITED_DIR, f"{args.ata}_iter{args.iter}-Audited.csv"
    )
    rev_out = args.rev_out or os.path.join(
        DEFAULT_AUDITED_DIR, f"{args.ata}_iter{args.iter}-Revision.csv"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)

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
        os.path.basename(out), args.ata, args.iter, args.modo, entradas, conteos
    )
    write_csv(out, OUT_HEADER, filas, comment=comment)

    dudosas = [f for f in filas if f["categoria"] == "dudosa"]
    if dudosas:
        rev_rows = [dict(f, veredicto="", nota="", revisor="", fecha="") for f in dudosas]
        rev_comment = construir_comentario(
            os.path.basename(rev_out), args.ata, args.iter, args.modo, entradas, conteos
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
