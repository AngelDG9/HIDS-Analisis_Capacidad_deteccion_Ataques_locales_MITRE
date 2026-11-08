#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_alertas_windows.py — alertas de Wazuh de Windows, por alerta y por `rule.id`.

**No ejecuta nada y no inventa campos.** Lee los ficheros de alertas del **manager**
(`/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json[.gz]`, una alerta JSON por
línea), filtra por **agente** (`002` = `victima-windows` por defecto) y por ventana UTC
`[--desde, --hasta]` **inclusiva**, y produce:

- **detalle** (`--detail`): una fila por alerta con **las mismas columnas** que el
  extractor de Linux (`extraer_alertas.py`, `DETAIL_HEADER`) **más** el ancla de Windows
  (plan §7, W2): `agent_id`, `win_image`, `win_command_line`, `win_cwd`, `win_user`,
  `event_id`. Las columnas de Linux (`audit_*`, `syscheck_path`, `src*`) se conservan
  para que el filtro de ruido pueda reutilizarse; en Windows saldrán vacías salvo
  `syscheck_path` (FIM).
- **Extensión aditiva B1.0-SSH.1 (plan §5.4, D17)**: al final se **añaden** `win_target`
  (`targetFilename` o `destinationIp:destinationPort`), `logon_type`
  (`data.win.eventdata.logonType`) y `win_parent_image` (`parentImage`); además `srcip`
  (columna que ya existía) se **rellena** con `data.win.eventdata.ipAddress`. Las 23
  columnas anteriores **no cambian** de orden ni de contenido.
- **agregado** (`--out`): las mismas 8 columnas que el histórico
  (`ruleids_legitimos.csv`: `rule_id, rule_level, rule_description, groups, count,
  first_seen, last_seen, rs_origen`).
- **muestra** (`--muestra`): líneas JSON crudas representativas (mismo criterio que el
  extractor de Linux).

De dónde sale cada campo de Windows (nombres **observados** en Wazuh 4.14.7 con
`eventchannel`, y sus alias planos):

| Columna | Ruta JSON (se prueban en orden) |
|---|---|
| `win_image` | `data.win.eventdata.image`, `…newProcessName`, `win.eventdata.image`, `win.image`, `data.win_image`, `win_image` |
| `win_command_line` | `data.win.eventdata.commandLine`, `…commandline`, `win.eventdata.…`, `data.win_command_line`, `win_command_line` |
| `win_cwd` | `data.win.eventdata.currentDirectory`, `win.eventdata.…`, `data.win_cwd`, `win_cwd` |
| `win_user` | `data.win.eventdata.user`, `…subjectUserName`, `…targetUserName`, `win.eventdata.…`, `data.win_user`, `win_user` |
| `event_id` | `data.win.system.eventID`, `win.system.eventID`, `data.event_id`, `event_id` |
| `win_target` | `data.win.eventdata.targetFilename` → si no hay, `destinationIp:destinationPort` |
| `logon_type` | `data.win.eventdata.logonType` |
| `win_parent_image` | `data.win.eventdata.parentImage` |
| `win_target_user` | `data.win.eventdata.targetUserName` (usuario efectivo del logon) |
| `srcip` | `data.win.eventdata.ipAddress` → `data.srcip` (`-` se declara vacío) |

La búsqueda de claves es **insensible a mayúsculas** (Sysmon usa `Image`,
`CommandLine`; el perfil normalizado del proyecto usa `image`, `commandline`). Si un
campo no está, se deja **vacío** y se informa del recuento: nunca se rellena a mano.

**Regresión CA-W23** (`--regresion`). El fichero crudo del manager del 08/10 **no está
en el repositorio** (solo se conservaron los productos `baseline_detalle_v{1,2}.csv`).
Por eso la regresión se hace **contra esos dos productos congelados**, que son el
detalle del propio extractor de Linux: se re-cuentan con el mismo filtro de agente y se
exige **72 + 87 = 159** alertas y los **7 `rule_id`**. Lo que **no** puede probar esa
regresión (y se declara) es el mapeo JSON→columnas nuevas, que se prueba con fixtures
sintéticos en `tests/test_extraer_alertas_windows.py`.

Uso (en el manager, como root para leer `/var/ossec`):
    sudo python3 extraer_alertas_windows.py \\
        --desde 2026-11-09T00:00:00Z --hasta 2026-11-12T00:00:00Z \\
        --agent-id 002 --agent-name victima-windows \\
        --detail ventana/alertas_detalle.csv --out ventana/ruleids_legitimos.csv

    python3 extraer_alertas_windows.py --regresion        # CA-W23 (solo lectura)
    python3 extraer_alertas_windows.py --test             # humo sintético
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
from datetime import timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import contar_denominador as cd  # noqa: E402  (parse_ts / _open_lines: tambien .gz)
import extraer_alertas as ea  # noqa: E402  (parse_ts / clasificacion RS / escritura CSV)

#: Columnas del detalle: las 17 de Linux + el ancla de Windows (plan §7, W2) +
#: la extensión aditiva de B1.0-SSH.1 (plan §5.4, D17). Solo se **añaden** al final.
DETAIL_HEADER = list(ea.DETAIL_HEADER) + [
    "agent_id",
    "win_image",
    "win_command_line",
    "win_cwd",
    "win_user",
    "event_id",
    "win_target",
    "logon_type",
    "win_parent_image",
    # Extra justificada por la evidencia de B1.0-SSH.1: en 4624/4634/4688 `win_user`
    # trae la cuenta *subject* (equipo/SYSTEM); el usuario efectivo es `targetUserName`.
    "win_target_user",
]

#: Agregado idéntico al histórico de Windows (`Dataset/Legitimo/windows/ruleids_legitimos.csv`).
CSV_HEADER = list(ea.CSV_HEADER)

AGENTE_ID_DEFECTO = "002"
AGENTE_NOMBRE_DEFECTO = "victima-windows"

#: Ventanas de la baseline histórica del 08/10 (solo para `--regresion`).
VENTANAS_HISTORICAS = {
    "v1": "2026-10-08T00:45:00Z..2026-10-08T04:45:00Z",
    "v2": "2026-10-08T12:00:00Z..2026-10-08T16:00:00Z",
}
ESPERADO_REGRESION = {
    "v1": 72,
    "v2": 87,
    "total": 159,
    "reglas": {"594", "598", "750", "60642", "60702", "67027", "92201"},
}

# --------------------------------------------------------------------------
# Lectura tolerante de campos anidados (sin inventar)
# --------------------------------------------------------------------------
def _clave_ci(d, clave):
    """Valor de `d[clave]` ignorando mayúsculas; `None` si no está."""
    if not isinstance(d, dict):
        return None
    buscada = clave.lower()
    for k, v in d.items():
        if str(k).lower() == buscada:
            return v
    return None


def _ruta(obj, partes):
    """Recorre `partes` con búsqueda insensible a mayúsculas; '' si falta."""
    cur = obj
    for p in partes:
        cur = _clave_ci(cur, p)
        if cur is None:
            return ""
        if isinstance(cur, (dict, list)):
            continue
        return cur
    return ""


def _primero(alert, candidatos):
    for partes in candidatos:
        v = _ruta(alert, partes)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


CAMPOS_WINDOWS = {
    "win_image": (
        ("data", "win", "eventdata", "image"),
        ("data", "win", "eventdata", "newProcessName"),
        ("win", "eventdata", "image"),
        ("win", "eventdata", "newProcessName"),
        ("data", "win", "image"),
        ("win", "image"),
        ("data", "win_image"),
        ("win_image",),
    ),
    "win_command_line": (
        ("data", "win", "eventdata", "commandLine"),
        ("data", "win", "eventdata", "commandline"),
        ("win", "eventdata", "commandLine"),
        ("data", "win", "commandLine"),
        ("win", "commandLine"),
        ("data", "win_command_line"),
        ("win_command_line",),
    ),
    "win_cwd": (
        ("data", "win", "eventdata", "currentDirectory"),
        ("win", "eventdata", "currentDirectory"),
        ("data", "win", "currentDirectory"),
        ("win", "currentDirectory"),
        ("data", "win_cwd"),
        ("win_cwd",),
    ),
    "win_user": (
        ("data", "win", "eventdata", "user"),
        ("data", "win", "eventdata", "subjectUserName"),
        ("data", "win", "eventdata", "targetUserName"),
        ("win", "eventdata", "user"),
        ("data", "win", "user"),
        ("win", "user"),
        ("data", "win_user"),
        ("win_user",),
        ("data", "dstuser"),
    ),
    "event_id": (
        ("data", "win", "system", "eventID"),
        ("win", "system", "eventID"),
        ("data", "win", "eventID"),
        ("win", "eventID"),
        ("data", "event_id"),
        ("event_id",),
    ),
    # --- extensión aditiva B1.0-SSH.1 (plan §5.4) ---
    "win_target": (
        ("data", "win", "eventdata", "targetFilename"),
        ("win", "eventdata", "targetFilename"),
        ("data", "win_target"),
        ("win_target",),
    ),
    "logon_type": (
        ("data", "win", "eventdata", "logonType"),
        ("win", "eventdata", "logonType"),
        ("data", "logon_type"),
        ("logon_type",),
    ),
    "win_parent_image": (
        ("data", "win", "eventdata", "parentImage"),
        ("win", "eventdata", "parentImage"),
        ("data", "win_parent_image"),
        ("win_parent_image",),
    ),
    "win_target_user": (
        ("data", "win", "eventdata", "targetUserName"),
        ("win", "eventdata", "targetUserName"),
        ("data", "win_target_user"),
        ("win_target_user",),
    ),
}

#: Red (Sysmon 3): `win_target` = `destinationIp:destinationPort` si no hay fichero.
CAMPOS_RED = {
    "destination_ip": (
        ("data", "win", "eventdata", "destinationIp"),
        ("win", "eventdata", "destinationIp"),
    ),
    "destination_port": (
        ("data", "win", "eventdata", "destinationPort"),
        ("win", "eventdata", "destinationPort"),
    ),
}

#: `srcip` en Windows vive en `data.win.eventdata.ipAddress` (plan §5.4).
CAMPOS_SRCIP = (
    ("data", "win", "eventdata", "ipAddress"),
    ("win", "eventdata", "ipAddress"),
    ("data", "srcip"),
    ("srcip",),
)


def _win_target_red(alert: dict) -> str:
    ip = _primero(alert, CAMPOS_RED["destination_ip"])
    port = _primero(alert, CAMPOS_RED["destination_port"])
    if ip and port:
        return f"{ip}:{port}"
    return ip


def srcip_de(alert: dict) -> str:
    """IP de origen: `ipAddress` (Windows) o `data.srcip`; `-` se declara vacío."""
    v = _primero(alert, CAMPOS_SRCIP).strip()
    return "" if v in ("", "-") else v


def campos_windows(alert: dict) -> dict:
    campos = {k: _primero(alert, v) for k, v in CAMPOS_WINDOWS.items()}
    if not campos["win_target"]:
        campos["win_target"] = _win_target_red(alert)
    return campos


def agente_de(alert: dict):
    """(id, nombre) del agente de la alerta; ('', '') si no viene."""
    a = alert.get("agent") or {}
    return str(a.get("id", "") or "").strip(), str(a.get("name", "") or "").strip()


def pertenece_al_agente(alert: dict, agent_id: str, agent_name: str):
    """(propio, motivo). Un `agent.id` distinto excluye aunque el nombre coincida."""
    aid, aname = agente_de(alert)
    if aid:
        return aid == agent_id, "otro_agente" if aid != agent_id else ""
    if aname:
        return aname == agent_name, "" if aname == agent_name else "otro_agente"
    return False, "sin_agente"


# --------------------------------------------------------------------------
# Extracción
# --------------------------------------------------------------------------
def _iter_alertas(paths):
    """Líneas JSON de todos los ficheros (soporta .gz de los rotados)."""
    for path in paths:
        for line in cd._open_lines(path):
            raw = line.strip()
            if not raw:
                continue
            yield raw


def extraer(paths, desde, hasta, agent_id=AGENTE_ID_DEFECTO,
            agent_name=AGENTE_NOMBRE_DEFECTO, id_map=None):
    """Devuelve (detalle, agregado, meta).

    `detalle`: lista de filas con `DETAIL_HEADER`.
    `agregado`: lista de filas con `CSV_HEADER`.
    `meta`: contadores de lectura y de campos de Windows (no se inventa nada).
    """
    id_map = id_map or {}
    detalle = []
    agg = {}
    meta = {
        "leidas": 0, "no_json": 0, "sin_timestamp": 0, "fuera_ventana": 0,
        "otros_agentes": 0, "sin_agente": 0, "en_ventana": 0,
        "campos": {k: 0 for k in CAMPOS_WINDOWS},
    }
    for raw in _iter_alertas(paths):
        meta["leidas"] += 1
        try:
            alert = json.loads(raw)
        except json.JSONDecodeError:
            meta["no_json"] += 1
            continue
        ts_raw = alert.get("timestamp")
        if not ts_raw:
            meta["sin_timestamp"] += 1
            continue
        try:
            ts = ea.parse_ts(str(ts_raw))
        except ValueError:
            meta["sin_timestamp"] += 1
            continue
        propio, motivo = pertenece_al_agente(alert, agent_id, agent_name)
        if not propio:
            meta["sin_agente" if motivo == "sin_agente" else "otros_agentes"] += 1
            continue
        if not (desde <= ts <= hasta):
            meta["fuera_ventana"] += 1
            continue
        meta["en_ventana"] += 1

        rule = alert.get("rule") or {}
        data = alert.get("data") or {}
        audit = data.get("audit") or {}
        syscheck = alert.get("syscheck") or {}
        groups = rule.get("groups", []) or []
        if isinstance(groups, str):
            groups = [groups]
        rid = str(rule.get("id", "") or "").strip() or "?"
        win = campos_windows(alert)
        for k, v in win.items():
            if v:
                meta["campos"][k] += 1

        ts_z = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
            f"{ts.microsecond // 1000:03d}Z"
        )
        detalle.append([
            ts_z,
            (alert.get("agent") or {}).get("name", ""),
            rid,
            rule.get("level", ""),
            rule.get("description", ""),
            "|".join(str(g) for g in groups),
            id_map.get(rid, "UNKNOWN"),
            audit.get("exe", ""),
            audit.get("cwd", ""),
            audit.get("key", ""),
            audit.get("type", ""),
            (audit.get("file", {}) or {}).get("name", ""),
            (audit.get("directory", {}) or {}).get("name", ""),
            syscheck.get("path", ""),
            srcip_de(alert),
            str(data.get("srcuser", "") or ""),
            str(data.get("dstuser", "") or ""),
            agente_de(alert)[0],
            win["win_image"],
            win["win_command_line"],
            win["win_cwd"],
            win["win_user"],
            win["event_id"],
            win["win_target"],
            win["logon_type"],
            win["win_parent_image"],
            win["win_target_user"],
        ])

        e = agg.get(rid)
        if e is None:
            e = {"level": rule.get("level", ""), "description": rule.get("description", ""),
                 "groups": groups, "count": 0, "first": ts, "last": ts}
            agg[rid] = e
        e["count"] += 1
        if ts < e["first"]:
            e["first"] = ts
        if ts > e["last"]:
            e["last"] = ts

    detalle.sort(key=lambda r: (r[0], r[2], r[17], r[18], r[5]))
    filas = []
    for rid, e in agg.items():
        filas.append([
            rid, e["level"], e["description"],
            "|".join(str(g) for g in e["groups"]),
            e["count"], ea.fmt_ts(e["first"]), ea.fmt_ts(e["last"]),
            id_map.get(rid, "UNKNOWN"),
        ])
    filas.sort(key=lambda r: (int(r[0]) if r[0].isdigit() else 10**12, r[0]))
    return detalle, filas, meta


def escribir_detalle(detalle, out, meta, ventana, fuentes):
    cab = (
        f"# {os.path.basename(out)} | detalle por alerta (una fila/alerta) | "
        f"windows-legit-prep W2 | fuentes={','.join(os.path.basename(p) for p in fuentes)} | "
        f"ventana={ventana} | leidas={meta['leidas']} en_ventana={meta['en_ventana']} "
        f"otros_agentes={meta['otros_agentes']} sin_agente={meta['sin_agente']} "
        f"fuera_ventana={meta['fuera_ventana']} no_json={meta['no_json']} | "
        f"campos_win={meta['campos']} | columnas: " + ",".join(DETAIL_HEADER)
    )
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as fh:
        fh.write(cab + "\n")
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(DETAIL_HEADER)
        w.writerows(detalle)
    return out


# --------------------------------------------------------------------------
# Regresión CA-W23 contra los productos del 08/10
# --------------------------------------------------------------------------
def _leer_detalle_historico(path, agent_id, agent_name):
    """Filas del detalle congelado (CSV del extractor de Linux), filtradas por agente."""
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = [ln for ln in fh if not ln.lstrip().startswith("#")]
    rd = csv.DictReader(lineas)
    faltan = [c for c in ("timestamp_utc", "rule_id") if c not in (rd.fieldnames or [])]
    if faltan:
        raise SystemExit(f"ERROR: {path} no tiene {faltan}; no se puede recontar sin inventar")
    if not ({"agent_id", "agent_name"} & set(rd.fieldnames or [])):
        raise SystemExit(f"ERROR: {path} no tiene columna de agente; no se puede filtrar "
                         f"el {agent_id} sin inventar")
    filas = []
    for r in rd:
        if "agent_id" in (rd.fieldnames or []) and (r.get("agent_id") or "").strip():
            if (r["agent_id"] or "").strip() != agent_id:
                continue
        elif "agent_name" in (rd.fieldnames or []):
            if (r.get("agent_name") or "").strip() != agent_name:
                continue
        filas.append(r)
    return filas


def regresion(paths, etiquetas=None, agent_id=AGENTE_ID_DEFECTO,
              agent_name=AGENTE_NOMBRE_DEFECTO):
    """Re-cuenta los productos congelados. Devuelve (ok, informe, detalle_por_etiqueta).

    No escribe nada y no toca `Dataset/`: solo lee.
    """
    etiquetas = etiquetas or []
    informe = {"ventanas": {}, "total": 0, "reglas": set(), "rs_origen": set()}
    ok = True
    for i, path in enumerate(paths):
        if not os.path.isfile(path):
            return False, {"error": f"no existe {path}"}, {}
        etiqueta = etiquetas[i] if i < len(etiquetas) else f"f{i + 1}"
        filas = _leer_detalle_historico(path, agent_id, agent_name)
        reglas = sorted({(r.get("rule_id") or "").strip() for r in filas} - {""})
        rs = sorted({(r.get("rs_origen") or "").strip() for r in filas} - {""})
        informe["ventanas"][etiqueta] = {"filas": len(filas), "reglas": reglas, "rs": rs}
        informe["total"] += len(filas)
        informe["reglas"] |= set(reglas)
        informe["rs_origen"] |= set(rs)
    informe["reglas"] = sorted(informe["reglas"], key=lambda x: int(x) if x.isdigit() else 10**12)
    informe["rs_origen"] = sorted(informe["rs_origen"])

    for etiqueta, esperado in (("v1", ESPERADO_REGRESION["v1"]),
                               ("v2", ESPERADO_REGRESION["v2"])):
        if etiqueta not in informe["ventanas"]:
            continue
        if informe["ventanas"][etiqueta]["filas"] != esperado:
            ok = False
    if informe["total"] != ESPERADO_REGRESION["total"]:
        ok = False
    if set(informe["reglas"]) != ESPERADO_REGRESION["reglas"]:
        ok = False
    informe["esperado"] = {
        "v1": ESPERADO_REGRESION["v1"], "v2": ESPERADO_REGRESION["v2"],
        "total": ESPERADO_REGRESION["total"],
        "reglas": sorted(ESPERADO_REGRESION["reglas"],
                         key=lambda x: int(x) if x.isdigit() else 10**12),
    }
    return ok, informe, {k: v["filas"] for k, v in informe["ventanas"].items()}


# --------------------------------------------------------------------------
# Humo sintético
# --------------------------------------------------------------------------
def _autotest():
    import tempfile
    from datetime import datetime, timezone

    ini = datetime(2026, 11, 9, 17, 6, tzinfo=timezone.utc)
    fin = datetime(2026, 11, 9, 17, 10, tzinfo=timezone.utc)

    def _iso(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    alertas = [
        {"timestamp": _iso(ini), "agent": {"id": "002", "name": "victima-windows"},
         "rule": {"id": "67027", "level": 3, "description": "A process was created.",
                  "groups": ["windows", "WEF"]},
         "data": {"win": {"system": {"eventID": "1"},
                          "eventdata": {"Image": r"C:\Windows\System32\cmd.exe",
                                        "CommandLine": "cmd /c systeminfo",
                                        "CurrentDirectory": r"C:\Users\angel",
                                        "User": "angel"}}}},
        {"timestamp": _iso(ini), "agent": {"id": "001", "name": "victima-linux"},
         "rule": {"id": "999999", "level": 3, "description": "ajena", "groups": []}},
        {"timestamp": _iso(fin), "agent": {"id": "002", "name": "victima-windows"},
         "rule": {"id": "92201", "level": 9, "description": "scripting file",
                  "groups": ["sysmon"]}},
        {"timestamp": _iso(fin), "agent": {"id": "002", "name": "victima-windows"},
         "rule": {"id": "67027", "level": 3, "description": "A process was created.",
                  "groups": ["windows"]}},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ossec-alerts-09.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for a in alertas:
                fh.write(json.dumps(a) + "\n")
        det, agg, meta = extraer([path], ini, fin, id_map={"67027": "RS1", "92201": "RS1"})
        assert len(det) == 3, det
        assert meta["otros_agentes"] == 1, meta
        assert det[0][18] == r"C:\Windows\System32\cmd.exe", det[0]
        assert det[0][19] == "cmd /c systeminfo" and det[0][20] == r"C:\Users\angel"
        assert det[0][21] == "angel" and det[0][22] == "1"
        assert {r[0]: r[4] for r in agg}["67027"] == 2, agg
        print("autotest: OK (3 alertas del 002, 1 ajena, campos de Sysmon mapeados)")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Alertas de Wazuh de Windows por alerta y por rule.id (ventana UTC).")
    ap.add_argument("--alerts", nargs="*", default=None,
                    help="ficheros del manager (.json / .json.gz); admite varios")
    ap.add_argument("--desde", help="inicio de ventana (UTC ISO8601)")
    ap.add_argument("--hasta", help="fin de ventana (UTC ISO8601)")
    ap.add_argument("--agent-id", default=AGENTE_ID_DEFECTO)
    ap.add_argument("--agent-name", default=AGENTE_NOMBRE_DEFECTO)
    ap.add_argument("--detail", metavar="RUTA.csv", help="una fila por alerta")
    ap.add_argument("--out", default=None, help="CSV agregado por rule.id")
    ap.add_argument("--muestra", metavar="RUTA.jsonl", help="líneas JSON crudas")
    ap.add_argument("--max-por-regla", type=int, default=5)
    ap.add_argument("--ruleset-dir", default=ea.DEFAULT_RULESET_DIR)
    ap.add_argument("--etc-rules-dir", default=ea.DEFAULT_ETC_RULES_DIR)
    ap.add_argument("--regresion", action="store_true",
                    help="CA-W23: re-cuenta Dataset/Legitimo/windows/baseline_detalle_v{1,2}.csv")
    ap.add_argument("--regresion-detalle", nargs="*", default=None,
                    help="rutas alternativas para --regresion")
    ap.add_argument("--test", action="store_true", help="humo sintético")
    args = ap.parse_args(argv)

    if args.test:
        return _autotest()

    if args.regresion:
        raiz = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        paths = args.regresion_detalle or [
            os.path.join(raiz, "Dataset", "Legitimo", "windows", "baseline_detalle_v1.csv"),
            os.path.join(raiz, "Dataset", "Legitimo", "windows", "baseline_detalle_v2.csv"),
        ]
        ok, inf, _ = regresion(paths, etiquetas=["v1", "v2"],
                               agent_id=args.agent_id, agent_name=args.agent_name)
        if "error" in inf:
            print(f"ERROR: {inf['error']}", file=sys.stderr)
            return 2
        for et in ("v1", "v2"):
            if et in inf["ventanas"]:
                v = inf["ventanas"][et]
                print(f"{et}: {v['filas']} alertas · reglas={v['reglas']} · rs={v['rs']}")
        print(f"total={inf['total']} (esperado {ESPERADO_REGRESION['total']}) · "
              f"reglas={len(inf['reglas'])} {inf['reglas']}")
        print("CA-W23 " + ("PASA" if ok else "FALLA"))
        if not ok:
            print("  diferencia: " + json.dumps(inf["esperado"], ensure_ascii=False))
        print("NOTA: la regresión usa los productos congelados del 08/10; el JSON crudo del "
              "manager no está en el repositorio (el mapeo JSON->win_* se prueba aparte).")
        return 0 if ok else 1

    if not args.alerts:
        ap.error("--alerts es obligatorio (o usa --regresion / --test)")
    if not args.desde or not args.hasta:
        ap.error("--desde y --hasta son obligatorios (o usa --regresion / --test)")
    desde = ea.parse_ts(args.desde)
    hasta = ea.parse_ts(args.hasta)
    if hasta < desde:
        ap.error("--hasta es anterior a --desde")

    fuentes = []
    for pat in args.alerts:
        fuentes.extend(sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat])
    if not fuentes:
        print(f"ERROR: no hay ficheros de alertas: {args.alerts}", file=sys.stderr)
        return 2
    for f in fuentes:
        if not os.path.isfile(f):
            print(f"ERROR: no existe {f}", file=sys.stderr)
            return 2

    id_map, avisos = ea.build_id_map(args.ruleset_dir, args.etc_rules_dir)
    if not id_map:
        print("AVISO: ruleset no disponible; rs_origen quedará UNKNOWN (no se inventa)",
              file=sys.stderr)
    for w in avisos:
        print(f"AVISO: {w}", file=sys.stderr)

    detalle, filas, meta = extraer(fuentes, desde, hasta, args.agent_id,
                                   args.agent_name, id_map)
    ventana = f"{ea.fmt_ts(desde)}..{ea.fmt_ts(hasta)}"
    print(f"alertas leidas={meta['leidas']} en_ventana={meta['en_ventana']} "
          f"otros_agentes={meta['otros_agentes']} sin_agente={meta['sin_agente']} "
          f"fuera_ventana={meta['fuera_ventana']} no_json={meta['no_json']}")
    print(f"campos_win={meta['campos']}")

    if args.detail:
        escribir_detalle(detalle, args.detail, meta, ventana, fuentes)
        print(f"detalle: filas={len(detalle)} -> {args.detail}")
    if args.muestra:
        lineas = []
        for f in fuentes:
            for line in cd._open_lines(f):
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if pertenece_al_agente(alert, args.agent_id, args.agent_name)[0]:
                    lineas.append(line)
        muestras = ea.select_muestra(lineas, desde, hasta, args.max_por_regla)[0]
        with open(args.muestra, "w", encoding="utf-8", newline="\n") as fh:
            for raw in muestras:
                fh.write(raw + "\n")
        print(f"muestra: lineas={len(muestras)} -> {args.muestra}")
    if args.out or not (args.detail or args.muestra):
        out = args.out or "ruleids_legitimos.csv"
        os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(CSV_HEADER)
            w.writerows(filas)
        n_unknown = sum(1 for r in filas if r[7] == "UNKNOWN")
        print(f"agregado: rule_ids={len(filas)} unknown={n_unknown} -> {out}")

    # Semáforo honesto: si se pidió detalle y no hay ni una alerta, se dice (no es PASS).
    if meta["leidas"] == 0:
        print("RESULT=VACIO (0 lineas leidas)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
