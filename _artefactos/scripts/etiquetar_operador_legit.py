#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""etiquetar_operador_legit.py — etiqueta `sin_operador` en una ventana legítima Windows.

**Bloque:** `windows-legit-prep` (W3-bis), tanda **T3** (plan §8.2 y §8.3).
**No modifica** `filtrar_ruido_windows.py` (canónico de B1/B2): lo **importa** para
reutilizar el predicado `OPERADOR_WIN` (`detectar_operador`), igual que
`analizar_legitimo_72h.py` reutiliza el predicado de Linux.

## Qué marca (y qué NO)

El operador de la ventana legítima Windows v2 es **mínimo por diseño**:

| `motivo_operador` | Evidencia (determinista, estrecha) |
|---|---|
| `keepalive` | `win_command_line` contiene `tfg_keepalive_windows.ps1` |
| `latido` | `win_target` es `192.168.65.1:9095` (sink del chivato) |
| `watch` | `win_command_line` contiene `windows_legit_host_control` o `verificar_windows.ps1` (**en v2 no debe existir**: se cuenta y se declara `alerta_diseno`) |
| `deploy` | `win_command_line` contiene `deploy_windows.ps1` o `manifiesto_snapshot.ps1` (solo `prep`) |
| `logs_operador` | `syscheck_path`/`win_target` bajo `\\ghosts-client\\logs\\` o con nombre `estado.json`, `keepalive.log`, `recovery.log`, `heartbeat.seq` |
| `vmware_tools` | `win_parent_image` = `vmtoolsd.exe` (acceso del operador por VMware Tools) |
| `logon_operador` | predicado canónico `OPERADOR_WIN` de `filtrar_ruido_windows.detectar_operador` (logon SSH/red del operador) **+** contexto de red/SSH propio de la fila: `logon_type=3`, `srcip=192.168.65.1` o cuenta `sshd_<pid>` |
| `horario` | **opcional** (`--intervalos` + `--reglas-horarias`): fila dentro de un intervalo declarado **y** con `rule_id` de la lista. Desactivado por defecto |

**Nunca** se marca por `win_user=angel` a secas: `angel` es el **usuario legítimo**.
Tampoco se marca un `powershell.exe` genérico, ni `cmd.exe`, ni rutas del usuario
(`Documentos`, `Desktop`, `lab-legit`). Los tests lo prueban con filas sintéticas.

### `67028` (4672): contexto de red obligatorio (T3b)

`67028` (4672, «Special privileges assigned to new logon») **no trae `logon_type`**.
El predicado canónico lo marca por `win_user=angel` **a secas**, y eso confunde el
**autologon de consola** (`logon_type=2`, del usuario legítimo) con la sesión SSH del
operador. Aquí se exige, además, **contexto de red o SSH en la propia fila**:

- `logon_type=3`, **o**
- `srcip=192.168.65.1` (host del operador), **o**
- cuenta `sshd_<pid>` (solo existe durante una sesión SSH).

Sin ese contexto, la fila **no** se marca (lado seguro: cuenta como ruido del sistema).

## Salida

El CSV de entrada (p. ej. `alertas_detalle.csv` del extractor de Windows) **más** 4
columnas aditivas al final:

    operador_legit   0/1
    sin_operador     1 - operador_legit      (la sensibilidad que se compara con Linux)
    motivo_operador  keepalive | latido | watch | deploy | logs_operador |
                     vmware_tools | logon_operador | horario | ""
    evidencia_operador  campo=valor que demuestra la etiqueta

Se conservan las líneas de comentario `#` de la entrada y se **añade** una cabecera
`#` con `sha256` de entrada/salida, recuentos por motivo y el aviso de `watch`.

Además escribe una **auditoría JSON** (determinista, claves ordenadas) con la lista
completa de filas marcadas y el porqué: *qué marcó y por qué*, sin depender del CSV.

## Doble FPR (misma unidad que Linux: **línea de `archives`**)

`metrica_hids.md:45-54, 86-96`: `FPR = FP_uni / M`, con `FP_uni` = unidades legítimas
(líneas de `archives`) con **≥ 1 alerta** y `M` = líneas decodificadas del endpoint.
El doble FPR **no cambia el denominador** (igual que la sensibilidad «sin auto-ruido»
de Linux, `0,664693 = 227.967 / 342.966`):

    FPR_canonico     = FP_uni / M
    FPR_sin_operador = (FP_uni - operador_uni) / M

`operador_uni` se cuenta **en líneas de `archives`** (`--archives`): se cruzan las
claves `(timestamp, rule_id)` de las alertas marcadas con el crudo. Sin `--archives`
el script lo declara `unidad=alerta_provisional` y **no** publica FPR.

> **No se calcula el FPR de la ventana en T3**: la ventana de 72 h no existe todavía.
> `--plantilla` imprime la fórmula y `--fpr M FP OP` la evalúa; los tests usan datos
> sintéticos.

## Uso

    python etiquetar_operador_legit.py --detalle alertas_detalle.csv \\
        --out alertas_detalle_operador.csv --auditoria operador_auditoria.json \\
        [--archives archives.json ...] [--intervalos intervalos.csv \\
         --reglas-horarias 67027,92201]

    python etiquetar_operador_legit.py --plantilla
    python etiquetar_operador_legit.py --fpr 342966 294252 4
    python etiquetar_operador_legit.py --test

Determinismo: sin reloj, sin orden dependiente del sistema de ficheros, LF, UTF-8 sin BOM.
Solo biblioteca estándar. **Sin secretos.**
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import ntpath
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contar_denominador as cd  # noqa: E402  (parse_ts / _open_lines: también .gz)
import filtrar_ruido_windows as FR  # noqa: E402  (predicado OPERADOR_WIN canónico)

#: Columnas aditivas al final del detalle (no se reordena nada de la entrada).
COLS_OPERADOR = ["operador_legit", "sin_operador", "motivo_operador", "evidencia_operador"]

MOTIVOS = (
    "keepalive",
    "latido",
    "watch",
    "deploy",
    "logs_operador",
    "vmware_tools",
    "logon_operador",
    "horario",
)

#: El `watch` v4 no debe tocar el invitado. Si aparece, es fallo de diseño.
MOTIVOS_ALERTA_DISENO = ("watch",)

#: Sink del chivato (plan §4.2): 192.168.65.1:9095.
SINK_IP = "192.168.65.1"
SINK_PORT = "9095"

#: Prefijos de línea de comandos del operador (normalizados a minúsculas).
CMD_KEEPALIVE = ("tfg_keepalive_windows.ps1",)
CMD_WATCH = ("windows_legit_host_control", "verificar_windows.ps1")
CMD_DEPLOY = ("deploy_windows.ps1", "manifiesto_snapshot.ps1")

#: Rutas que solo escribe el operador keepalive (plan §16.1).
RUTA_LOGS_OPERADOR = "\\ghosts-client\\logs\\"
FICHEROS_OPERADOR = ("estado.json", "keepalive.log", "recovery.log", "heartbeat.seq")

#: Nombre de la imagen del hypervisor que delata acceso del operador (G-W8).
VMTOOLS = "vmtoolsd.exe"

#: Contexto de red/SSH exigido a **cualquier** `logon_*` (T3b). `67028` (4672) no
#: trae `logon_type`: sin esta evidencia no se marca (el 4672 de `angel` en consola
#: lo produce el autologon legítimo, `logon_type=2`).
LOGON_RED_TIPOS = ("3",)
LOGON_RED_SRCIPS = frozenset({SINK_IP})
LOGON_SSH_USUARIO = re.compile(r"^sshd_\d+$", re.IGNORECASE)


# --------------------------------------------------------------------------
# Utilidades deterministas
# --------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _norm(value: str) -> str:
    """Minúsculas, barras `/`→`\\`, colapsa barras repetidas y quita comillas."""
    v = (value or "").strip().strip('"').replace("/", "\\").lower()
    return re.sub(r"\\{2,}", r"\\", v)


def _base(value: str) -> str:
    v = (value or "").strip().strip('"')
    return ntpath.basename(v).lower() if v else ""


def leer_detalle(path: str):
    """Devuelve (comentarios, fieldnames, filas) de un CSV con cabecera `#` opcional."""
    comentarios = []
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = []
        for ln in fh:
            if ln.lstrip().startswith("#"):
                comentarios.append(ln.rstrip("\r\n"))
            else:
                lineas.append(ln)
    reader = csv.DictReader(lineas)
    fieldnames = list(reader.fieldnames or [])
    if not fieldnames:
        raise ValueError(f"{path}: sin cabecera CSV")
    return comentarios, fieldnames, list(reader)


# --------------------------------------------------------------------------
# Reglas de etiquetado (estrechas y por evidencia)
# --------------------------------------------------------------------------
def _en_cmd(row: dict, agujas) -> str:
    cmd = _norm(row.get("win_command_line") or "")
    for a in agujas:
        if a in cmd:
            return (row.get("win_command_line") or "").strip()
    return ""


def _es_sink_9095(row: dict) -> str:
    objetivo = _norm(row.get("win_target") or "").strip()
    if not objetivo:
        return ""
    # `ip:puerto` o solo `puerto`
    if objetivo.endswith(":" + SINK_PORT):
        ip = objetivo[: -(len(SINK_PORT) + 1)].strip("[]")
        if ip in ("", SINK_IP):
            return (row.get("win_target") or "").strip()
    return ""


def _es_logs_operador(row: dict) -> str:
    for campo in ("syscheck_path", "win_target"):
        raw = (row.get(campo) or "").strip()
        if not raw:
            continue
        n = _norm(raw)
        if RUTA_LOGS_OPERADOR in n:
            return f"{campo}={raw}"
        base = _base(raw)
        if base in FICHEROS_OPERADOR and "ghosts-client" in n:
            return f"{campo}={raw}"
    return ""


def contexto_red_logon(row: dict) -> str:
    """Evidencia de red/SSH de un `logon_*`; `""` si la fila no la trae.

    Se exige siempre (T3b): `67028` (4672) **no** trae `logon_type`, así que un
    `win_user=angel` a secas **no** basta — el autologon de consola del usuario
    legítimo (`logon_type=2`) produce el mismo 4672.
    """
    logon = str(row.get("logon_type") or "").strip()
    if logon in LOGON_RED_TIPOS:
        return f"logon_type={logon}"
    srcip = (row.get("srcip") or "").strip()
    if srcip in LOGON_RED_SRCIPS:
        return f"srcip={srcip}"
    for campo in ("win_target_user", "win_user"):
        usuario = (row.get(campo) or "").strip()
        if usuario and LOGON_SSH_USUARIO.match(usuario):
            return f"{campo}={usuario}"
    return ""


def motivo_operador(row: dict, intervalos=None, reglas_horarias=()):
    """`(motivo, evidencia)` si la fila es del operador; `None` si es del usuario.

    El orden es deliberado: primero las evidencias de **proceso/fichero** (las más
    fuertes), después el predicado canónico de logon y, al final, el modo horario
    opcional. Una fila nunca se marca por `win_user=angel` a secas.
    """
    cmd = _en_cmd(row, CMD_KEEPALIVE)
    if cmd:
        return ("keepalive", f"win_command_line={cmd}")

    cmd = _en_cmd(row, CMD_WATCH)
    if cmd:
        return ("watch", f"win_command_line={cmd}")

    cmd = _en_cmd(row, CMD_DEPLOY)
    if cmd:
        return ("deploy", f"win_command_line={cmd}")

    sink = _es_sink_9095(row)
    if sink:
        return ("latido", f"win_target={sink}")

    logs = _es_logs_operador(row)
    if logs:
        return ("logs_operador", logs)

    if _base(row.get("win_parent_image") or "") == VMTOOLS:
        return ("vmware_tools", f"win_parent_image={row.get('win_parent_image')}")

    try:
        op = FR.detectar_operador(row)
    except Exception:  # noqa: BLE001 - el predicado canónico no debe romper el etiquetado
        op = None
    if op is not None:
        rid, evidencia = op
        ctx = contexto_red_logon(row)
        if not ctx:
            # `OPERADOR_WIN` marca `67028` por `win_user=angel` y aquí eso no basta.
            return None
        return ("logon_operador", f"rule_id={rid};{evidencia};contexto={ctx}")

    hit = motivo_horario(row, intervalos, reglas_horarias)
    if hit is not None:
        return hit
    return None


def cargar_intervalos(path: str):
    """CSV `motivo,desde,hasta` (UTC ISO8601) → lista de dicts ordenada por `desde`."""
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lineas)
    requeridas = ("desde", "hasta")
    faltan = [c for c in requeridas if c not in (reader.fieldnames or [])]
    if faltan:
        raise ValueError(f"{path}: faltan columnas {faltan}")
    out = []
    for r in reader:
        d = cd.parse_ts((r.get("desde") or "").strip())
        h = cd.parse_ts((r.get("hasta") or "").strip())
        if h < d:
            raise ValueError(f"{path}: intervalo con hasta < desde ({r})")
        out.append({"motivo": (r.get("motivo") or "horario").strip() or "horario",
                    "desde": d, "hasta": h})
    return sorted(out, key=lambda x: (x["desde"], x["hasta"], x["motivo"]))


def motivo_horario(row: dict, intervalos, reglas_horarias):
    """Modo horario **opcional**: exige intervalo declarado **y** `rule_id` listado."""
    if not intervalos or not reglas_horarias:
        return None
    rid = str(row.get("rule_id") or "").strip()
    if rid not in set(reglas_horarias):
        return None
    ts_raw = (row.get("timestamp_utc") or "").strip()
    if not ts_raw:
        return None
    try:
        ts = cd.parse_ts(ts_raw)
    except ValueError:
        return None
    for iv in intervalos:
        if iv["desde"] <= ts <= iv["hasta"]:
            return ("horario",
                    f"intervalo={iv['motivo']};rule_id={rid};"
                    f"ts={cd.fmt_ts(ts)}")
    return None


# --------------------------------------------------------------------------
# Etiquetado de un detalle completo
# --------------------------------------------------------------------------
def etiquetar(filas, intervalos=None, reglas_horarias=()):
    """Devuelve (filas_etiquetadas, resumen). No muta las filas de entrada."""
    salida = []
    por_motivo = {m: 0 for m in MOTIVOS}
    marcadas = []
    for r in filas:
        hit = motivo_operador(r, intervalos, reglas_horarias)
        nueva = dict(r)
        if hit is None:
            nueva["operador_legit"] = "0"
            nueva["sin_operador"] = "1"
            nueva["motivo_operador"] = ""
            nueva["evidencia_operador"] = ""
        else:
            motivo, evidencia = hit
            nueva["operador_legit"] = "1"
            nueva["sin_operador"] = "0"
            nueva["motivo_operador"] = motivo
            nueva["evidencia_operador"] = evidencia
            por_motivo[motivo] = por_motivo.get(motivo, 0) + 1
            marcadas.append({
                "timestamp_utc": (r.get("timestamp_utc") or "").strip(),
                "rule_id": str(r.get("rule_id") or "").strip(),
                "agent_id": str(r.get("agent_id") or "").strip(),
                "motivo": motivo,
                "evidencia": evidencia,
            })
        salida.append(nueva)
    resumen = {
        "filas": len(salida),
        "operador": len(marcadas),
        "sin_operador": len(salida) - len(marcadas),
        "por_motivo": {k: v for k, v in sorted(por_motivo.items()) if v},
        "watch": por_motivo.get("watch", 0),
        "alerta_diseno": por_motivo.get("watch", 0) > 0,
        "marcadas": marcadas,
    }
    return salida, resumen


# --------------------------------------------------------------------------
# Unidad de `FP_uni`: línea de `archives` (CA-W3b-23)
# --------------------------------------------------------------------------
def _clave_ts_rule(ts_raw: str, rule_id: str):
    """Clave (timestamp truncado a ms, rule_id) comparable entre alertas y archives."""
    try:
        ts = cd.parse_ts(ts_raw)
    except (TypeError, ValueError):
        return None
    ms = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)
    return (ms.isoformat(), str(rule_id or "").strip())


def contar_unidades_operador(marcadas, archives, agent_id: str = "002"):
    """Cuenta **líneas de `archives`** del agente que corresponden a alertas marcadas.

    `archives`: rutas (o lista de líneas) del crudo. Sin `archives` → modo
    `alerta_provisional` explícito (no se finge la unidad de Linux).
    """
    alertas = len(marcadas)
    if not archives:
        return {"unidad": "alerta_provisional", "alertas": alertas,
                "unidades": None, "claves": alertas}
    claves = set()
    for m in marcadas:
        k = _clave_ts_rule(m.get("timestamp_utc", ""), m.get("rule_id", ""))
        if k is not None:
            claves.add(k)
    unidades = 0
    lineas = 0
    for path in archives:
        for raw in cd._open_lines(path):
            raw = raw.strip()
            if not raw:
                continue
            lineas += 1
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ag = ev.get("agent") or {}
            aid = str(ag.get("id", "") or "").strip()
            aname = str(ag.get("name", "") or "").strip()
            if aid and aid != agent_id:
                continue
            if not aid and aname and aname != "victima-windows":
                continue
            rule = ev.get("rule") or {}
            k = _clave_ts_rule(str(ev.get("timestamp", "")), str(rule.get("id", "")))
            if k is not None and k in claves:
                unidades += 1
    return {"unidad": "linea_archives", "alertas": alertas,
            "unidades": unidades, "lineas_leidas": lineas, "claves": len(claves)}


# --------------------------------------------------------------------------
# Doble FPR (plantilla; NO se evalúa sobre una ventana inexistente)
# --------------------------------------------------------------------------
def doble_fpr(M: int, fp_uni: int, operador_uni: int = 0) -> dict:
    """FPR canónico y `sin_operador` en la unidad de Linux (línea de `archives`).

    ```text
    FPR_canonico     = FP_uni / M
    FPR_sin_operador = (FP_uni - operador_uni) / M
    ```

    El denominador **no cambia** (mismo criterio que «sin auto-ruido» de Linux).
    """
    if M <= 0:
        raise ValueError("M debe ser > 0 (líneas de archives del endpoint)")
    if fp_uni < 0 or fp_uni > M:
        raise ValueError(f"FP_uni fuera de [0, M]: {fp_uni}")
    if operador_uni < 0 or operador_uni > fp_uni:
        raise ValueError(f"operador_uni fuera de [0, FP_uni]: {operador_uni}")
    fp_sin = fp_uni - operador_uni
    return {
        "M": M,
        "FP_uni": fp_uni,
        "operador_uni": operador_uni,
        "FP_uni_sin_operador": fp_sin,
        "FPR_canonico": round(fp_uni / M, 6),
        "FPR_canonico_pct": round(100.0 * fp_uni / M, 4),
        "FPR_sin_operador": round(fp_sin / M, 6),
        "FPR_sin_operador_pct": round(100.0 * fp_sin / M, 4),
        "delta_abs": round(operador_uni / M, 6),
    }


PLANTILLA = {
    "unidad": "linea_archives (FP_uni = línea de archives con >=1 alerta; M = líneas del endpoint)",
    "FPR_canonico": "FP_uni / M",
    "FPR_sin_operador": "(FP_uni - operador_uni) / M",
    "operador_uni": ("líneas de archives del agente cuyas (timestamp, rule_id) están en "
                     "alertas marcadas operador_legit=1"),
    "denominador": "M no cambia (igual que la sensibilidad sin auto-ruido de Linux)",
    "no_calculado_en_T3": "la ventana de 72 h de Windows no existe todavía",
}


# --------------------------------------------------------------------------
# Salida
# --------------------------------------------------------------------------
def escribir_csv(path: str, comentarios, fieldnames, filas, extra_comentario=None) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        for c in comentarios:
            fh.write(c.rstrip("\n") + "\n")
        if extra_comentario:
            fh.write(extra_comentario.rstrip("\n") + "\n")
        w = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n",
                           extrasaction="ignore")
        w.writeheader()
        for r in filas:
            w.writerow(r)


def escribir_auditoria(path: str, datos: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(datos, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def _cabecera_salida(base: str, resumen: dict, sha_in: str) -> str:
    return (
        f"# {base} | etiquetado operador (T3 windows-legit-prep) | "
        f"filas={resumen['filas']} operador={resumen['operador']} "
        f"sin_operador={resumen['sin_operador']} | "
        f"por_motivo={json.dumps(resumen['por_motivo'], ensure_ascii=False, sort_keys=True)} | "
        f"watch={resumen['watch']} alerta_diseno={int(resumen['alerta_diseno'])} | "
        f"sha256_entrada={sha_in} sha256_salida=<en la auditoría> | "
        f"columnas: " + ",".join(list(COLS_OPERADOR))
    )


# --------------------------------------------------------------------------
# Autotest (humo sintético)
# --------------------------------------------------------------------------
def _autotest() -> int:
    filas = [
        # 1) keepalive: powershell del bucle
        {"timestamp_utc": "2026-11-11T15:07:42.000Z", "rule_id": "67027",
         "win_command_line": r'powershell.exe -NoProfile -File "C:\Users\angel\ghosts-client\tfg_keepalive_windows.ps1" -Loop',
         "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "win_user": "SYSTEM"},
        # 2) usuario legítimo: powershell propio de la receta
        {"timestamp_utc": "2026-11-11T15:20:00.000Z", "rule_id": "67027",
         "win_command_line": r'powershell.exe -NoProfile -File C:\lab-legit\campana\scripts\W-04_cifrar_aes.ps1',
         "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "win_user": "angel"},
        # 3) latido: Sysmon 3 al sink
        {"timestamp_utc": "2026-11-11T15:10:00.000Z", "rule_id": "185001",
         "win_target": "192.168.65.1:9095", "win_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
        # 4) logon del operador por SSH (predicado canónico)
        {"timestamp_utc": "2026-11-11T15:00:00.000Z", "rule_id": "60106",
         "win_user": "angel", "win_target_user": "angel", "logon_type": "3"},
        # 5) logon legítimo de angel en consola (tipo 2) -> NO
        {"timestamp_utc": "2026-11-11T08:00:00.000Z", "rule_id": "60106",
         "win_user": "angel", "win_target_user": "angel", "logon_type": "2"},
        # 6) FIM del log del keepalive
        {"timestamp_utc": "2026-11-11T15:15:00.000Z", "rule_id": "550",
         "syscheck_path": r"C:\Users\angel\ghosts-client\logs\keepalive.log"},
        # 7) FIM de un fichero del usuario -> NO
        {"timestamp_utc": "2026-11-11T15:16:00.000Z", "rule_id": "550",
         "syscheck_path": r"C:\Users\angel\Documentos\informe.docx"},
        # 8) hijo de VMware Tools (acceso del operador)
        {"timestamp_utc": "2026-11-11T15:00:05.000Z", "rule_id": "67027",
         "win_image": r"C:\Windows\System32\cmd.exe",
         "win_parent_image": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"},
        # 9) 4672 del usuario en consola (logon_type=2): autologon legítimo -> NO
        {"timestamp_utc": "2026-11-11T08:00:01.000Z", "rule_id": "67028",
         "win_user": "angel", "event_id": "4672", "logon_type": "2"},
        # 10) 4672 con contexto de red (logon_type=3) -> sí
        {"timestamp_utc": "2026-11-11T15:00:02.000Z", "rule_id": "67028",
         "win_user": "angel", "event_id": "4672", "logon_type": "3"},
    ]
    out, res = etiquetar(filas)
    idx = {i: out[i]["motivo_operador"] for i in range(len(out))}
    esperado = {0: "keepalive", 1: "", 2: "latido", 3: "logon_operador", 4: "",
                5: "logs_operador", 6: "", 7: "vmware_tools", 8: "",
                9: "logon_operador"}
    assert idx == esperado, idx
    assert res["operador"] == 6 and res["sin_operador"] == 4, res
    assert res["alerta_diseno"] is False, res
    f = doble_fpr(342966, 294252, 4)
    assert f["FPR_canonico"] == 0.857963, f
    assert f["FPR_sin_operador"] == round(294248 / 342966, 6), f
    print("autotest: OK (6 operador / 4 usuario; FPR canónico reproduce 0,857963)")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Etiqueta `sin_operador` en una ventana legítima Windows (T3).")
    ap.add_argument("--detalle", help="CSV por alerta del extractor de Windows")
    ap.add_argument("--out", help="CSV de salida con las 4 columnas del operador")
    ap.add_argument("--auditoria", help="JSON de auditoría (qué se marcó y por qué)")
    ap.add_argument("--archives", nargs="*", default=None,
                    help="crudo del manager (archives.json/.gz) para contar unidades")
    ap.add_argument("--agent-id", default="002")
    ap.add_argument("--intervalos", help="CSV motivo,desde,hasta (modo horario opcional)")
    ap.add_argument("--reglas-horarias", default="",
                    help="rule_id donde SÍ se aplica el modo horario (coma)")
    ap.add_argument("--plantilla", action="store_true", help="imprime la plantilla del doble FPR")
    ap.add_argument("--fpr", nargs=3, type=int, metavar=("M", "FP_UNI", "OPERADOR_UNI"),
                    help="evalúa la plantilla con cifras dadas")
    ap.add_argument("--test", action="store_true", help="autotest sintético")
    args = ap.parse_args(argv)

    if args.test:
        return _autotest()
    if args.plantilla:
        print(json.dumps(PLANTILLA, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.fpr:
        try:
            res = doble_fpr(*args.fpr)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if not args.detalle:
        ap.error("--detalle es obligatorio (o usa --plantilla / --fpr / --test)")

    intervalos = cargar_intervalos(args.intervalos) if args.intervalos else None
    reglas = tuple(r.strip() for r in (args.reglas_horarias or "").split(",") if r.strip())

    comentarios, fieldnames, filas = leer_detalle(args.detalle)
    salida, resumen = etiquetar(filas, intervalos, reglas)
    extra = [c for c in COLS_OPERADOR if c not in fieldnames]
    if extra != COLS_OPERADOR:
        print(f"AVISO: el detalle ya tiene columnas {set(COLS_OPERADOR) & set(fieldnames)}; "
              f"se sobrescriben", file=sys.stderr)
    fieldnames_out = list(fieldnames) + [c for c in COLS_OPERADOR if c not in fieldnames]

    out = args.out or (os.path.splitext(args.detalle)[0] + "_operador.csv")
    aud = args.auditoria or (os.path.splitext(out)[0] + "_auditoria.json")

    sha_in = sha256_file(args.detalle)
    # Se escribe una sola vez: la cabecera cita `sha256_entrada` y remite a la auditoría
    # para `sha256_salida` (así el hash de salida no es circular).
    escribir_csv(out, comentarios, fieldnames_out, salida,
                 extra_comentario=_cabecera_salida(os.path.basename(out), resumen, sha_in))
    sha_out = sha256_file(out)

    unidades = contar_unidades_operador(resumen["marcadas"], args.archives, args.agent_id)
    auditoria = {
        "version": 1,
        "bloque": "windows-legit-prep",
        "tanda": "T3",
        "entrada": os.path.basename(args.detalle),
        "sha256_entrada": sha_in,
        "salida": os.path.basename(out),
        "sha256_salida": sha_out,
        "filas": resumen["filas"],
        "operador_legit": resumen["operador"],
        "sin_operador": resumen["sin_operador"],
        "por_motivo": resumen["por_motivo"],
        "watch": resumen["watch"],
        "alerta_diseno": resumen["alerta_diseno"],
        "reglas": {
            "proceso": {
                "keepalive": list(CMD_KEEPALIVE),
                "watch": list(CMD_WATCH),
                "deploy": list(CMD_DEPLOY),
                "latido": f"{SINK_IP}:{SINK_PORT}",
                "logs_operador": [RUTA_LOGS_OPERADOR] + list(FICHEROS_OPERADOR),
                "vmware_tools": VMTOOLS,
                "logon_operador": "filtrar_ruido_windows.detectar_operador (OPERADOR_WIN)"
                                 " + contexto de red/SSH propio (logon_type=3 |"
                                 " srcip=192.168.65.1 | sshd_<pid>)"},
            "horario": {
                "activo": bool(intervalos and reglas),
                "intervalos": ([{"motivo": iv["motivo"],
                                 "desde": cd.fmt_ts(iv["desde"]),
                                 "hasta": cd.fmt_ts(iv["hasta"])} for iv in intervalos]
                               if intervalos else []),
                "reglas_horarias": list(reglas),
            },
            "no_marca": "win_user=angel a secas (incluido 67028/4672 sin contexto de "
                        "red o SSH); powershell.exe/cmd.exe genéricos; rutas del usuario",
        },
        "unidad": unidades,
        "marcadas": resumen["marcadas"],
    }
    escribir_auditoria(aud, auditoria)

    print(f"filas={resumen['filas']} operador={resumen['operador']} "
          f"sin_operador={resumen['sin_operador']} por_motivo={resumen['por_motivo']}")
    if resumen["alerta_diseno"]:
        print("ALERTA_DISENO: hay filas del `watch`; en v2 el watch NO debe tocar el invitado",
              file=sys.stderr)
    print(f"unidad={unidades['unidad']} alertas={unidades['alertas']} "
          f"unidades_operador={unidades['unidades']}")
    print(f"salida={out}")
    print(f"auditoria={aud}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
