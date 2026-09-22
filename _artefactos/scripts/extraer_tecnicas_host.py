#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extraer_tecnicas_host.py — Corpus host de MITRE ATT&CK Enterprise (TFG HIDS).

Implementa el **filtro inverso host** (R-03) sobre el bundle STIX/JSON de
MITRE ATT&CK Enterprise **v19.1**: se queda con las técnicas/subtécnicas que
tienen al menos un Data Component con telemetría **endpoint**, descartando las
exclusivamente de red. Además calcula una prioridad R/E/S (R-04).

Diseño (plan F-01 v2, §2.2):

1. Cargar el bundle e indexar objetos por id.
2. Resolver los Data Components (`x-mitre-data-component`).
3. Recoger los `attack-pattern` (técnicas y subtécnicas).
4. Excluir deprecated/revoked (no se escriben en el CSV).
5. **Cadena de detección v19 (paso principal):**
       technique ←detects— Detection Strategy (`x-mitre-detection-strategy`)
                        → Analytics (`x-mitre-analytic`)
                        → Data Components (`x-mitre-data-component`)
   - Los Analytics cuelgan de la estrategia por el campo interno
     `x_mitre_analytic_refs` (y, como respaldo, por relaciones).
   - Los Data Components cuelgan de cada Analytic por el campo interno
     `x_mitre_log_source_references[].x_mitre_data_component_ref`
     (y, como respaldo, por relaciones).
   5b. **Fallback directo:** relaciones `detects` entre Data Component y
       `attack-pattern` (unión sin duplicados; inerte en v19.1, donde no
       existen, pero robusto entre versiones).
6. Clasificar cada Data Component en RED_PURA / RED_DESCARTADA / HOST.
7. Regla amplia (decisión humana 2026-09-19): `host_eligible=YES` si y solo si
   existe ≥1 Data Component HOST; los DC de red no otorgan elegibilidad pero
   **no anulan** una técnica con telemetría endpoint. Sin DC → NO
   (`sin_datacomponents`).
8. Subtécnicas sin Data Components propios: heredan los del padre
   (`heredado_padre=si`, explícito).
9. Plataformas + `endpoint_lw` (Linux/Windows).
10. Tácticas vía `kill_chain_phases` (`mitre-attack`) y `x-mitre-tactic`.
11. Prioridad R/E/S determinista (ver `compute_priority`).
12. CSV ordenado por prioridad, elegibilidad y id.

--------------------------------------------------------------------------
AJUSTE DE ESQUEMA (plan §2.2, paso 5c) — inspección del bundle real v19.1
--------------------------------------------------------------------------
El STIX real descargado (`enterprise-attack-v19.1.json`, 25 843 objetos)
confirma el esquema de v19, que difiere del `Data Component --detects-->
technique` clásico:

* Relación `detects`: **source = `x-mitre-detection-strategy`**,
  **target = `attack-pattern`** (697 relaciones en el bundle).
* La Detection Strategy referencia sus Analytics **por campo interno**
  `x_mitre_analytic_refs` (lista de ids de `x-mitre-analytic`), no por
  relación.
* Cada Analytic referencia sus Data Components por campo interno
  `x_mitre_log_source_references` → `x_mitre_data_component_ref`.
* NO existen relaciones `relationship_type=="detects"` que toquen directamente
  un Data Component (0 en el bundle), por lo que el fallback 5b es inerte en
  v19.1 (se mantiene por robustez inter-versiones).
* Los Data Components v19.1 **no** exponen `x_mitre_data_source_ref` y los
  `x-mitre-data-source` están todos deprecados. Para `Response Content` /
  `Response Metadata` la desambiguación "Internet Scan" se hace por
  descripción (contienen "internet scan") y, si existiera, por
  `x_mitre_data_source_ref`; los nombres son únicos (sin colisiones).
* Ancla verificada en el bundle: **T1039 → DET0410 → AN1145/AN1146/AN1147 →
  DC0102 (Network Share Access) + DC0039 (File Creation) + DC0055 (File Access)
  + DC0054 (Drive Access)** → `host_eligible=YES`.

Uso:
    python _artefactos/scripts/extraer_tecnicas_host.py
    python _artefactos/scripts/extraer_tecnicas_host.py --csv-only
    python _artefactos/scripts/extraer_tecnicas_host.py --stix <ruta.json>
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Rutas por defecto (relativas a la raíz del repo).
# --------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STIX = REPO_ROOT / "_artefactos" / "mitre" / "enterprise-attack-v19.1.json"
DEFAULT_CSV = REPO_ROOT / "Hojas" / "corpus_host.csv"
DEFAULT_MD = REPO_ROOT / "Hojas" / "lista_tecnicas_validas.md"

# --------------------------------------------------------------------------
# Clasificación de Data Components (plan §2.2, paso 6).
# --------------------------------------------------------------------------
# Data Components de RED PURA (filtro inverso "clásico").
RED_PURA = {
    "Network Connection Creation",
    "Network Traffic Content",
    "Network Traffic Flow",
}
# Data Components de RED DESCARTAJADA ("descartadas del todo": Network Share
# Access e Internet Scan: Response Content/Metadata). No otorgan elegibilidad.
RED_DESCARTADA = {
    "Network Share Access",
    "Response Content",
    "Response Metadata",
}
# Nombres genéricos que exigen confirmar el Data Source "Internet Scan".
_INTERNET_SCAN_NAMES = {"Response Content", "Response Metadata"}

# --------------------------------------------------------------------------
# Prioridad R/E/S (R-04, plan §2.2, paso 11). Determinista y documentada.
# --------------------------------------------------------------------------
# Tácticas que hacen P1 directamente (foco del profesor: Ransomware /
# Exfiltración / Sabotaje). En v19.1 "Impact" cubre Ransomware y Sabotaje.
P1_TACTICS = {"Impact", "Exfiltration", "Collection"}

# Tácticas "habilitadoras directas" de R/E/S → P2 (con telemetría endpoint).
# Nota v19: "Defense Evasion" se sustituye por "Stealth" (y se añade
# "Defense Impairment"); no existe la táctica "Defense Evasion".
P2_TACTICS = {
    "Execution",
    "Stealth",
    "Defense Impairment",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Initial Access",
}

# Lista curada R/E/S: técnicas clave aunque su táctica no sea P1 por sí misma.
# (Ransomware, Destrucción/Sabotaje, Exfiltración, Staging/Collection.)
CURATED_RES = {
    # Ransomware / Impact
    "T1486",  # Data Encrypted for Impact
    "T1485",  # Data Destruction
    "T1489",  # Service Stop
    "T1490",  # Inhibit System Recovery
    "T1491",  # Defacement
    "T1565",  # Data Manipulation
    "T1561",  # Disk Wipe
    "T1529",  # System Shutdown/Reboot
    # Exfiltration
    "T1567",  # Exfiltration Over Web Service
    "T1041",  # Exfiltration Over C2 Channel
    "T1048",  # Exfiltration Over Alternative Protocol
    "T1011",  # Exfiltration Over Other Network Medium
    "T1052",  # Exfiltration Over Physical Medium
    # Collection / staging
    "T1074",  # Data Staged
    "T1560",  # Archive Collected Data
    "T1119",  # Automated Collection
    "T1114",  # Email Collection
}

# Esquema exacto de 17 columnas (plan §2.2).
HEADER_COLUMNS = [
    "tecnica_id",
    "nombre",
    "es_subtecnica",
    "padre_id",
    "tacticas",
    "plataformas",
    "endpoint_lw",
    "data_components",
    "num_dc",
    "dc_host",
    "dc_red",
    "host_eligible",
    "priority",
    "heredado_padre",
    "motivo",
    "stix_version",
    "fecha_generacion",
]

_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}
_YESNO_ORDER = {"YES": 0, "NO": 1}


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def external_id(obj: dict) -> str | None:
    """Devuelve el `external_id` de ATT&CK (p. ej. 'T1486' o 'DC0039')."""
    for ref in obj.get("external_references") or []:
        if ref.get("external_id"):
            return ref["external_id"]
    return None


def is_removed(obj: dict) -> bool:
    """True si el objeto está deprecated o revocado."""
    return bool(obj.get("x_mitre_deprecated") or obj.get("revoked"))


def load_bundle(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def collection_version(objects: list[dict]) -> str | None:
    """`x_mitre_version` del objeto `x-mitre-collection` del bundle."""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


def classify_dc(dc: dict) -> str:
    """Clasifica un Data Component en RED_PURA / RED_DESCARTADA / HOST."""
    name = dc.get("name") or ""
    if name in RED_PURA:
        return "RED_PURA"
    if name in RED_DESCARTADA:
        # Desambiguar "Response Content/Metadata" por Data Source Internet Scan
        # si el campo existe (best-effort); si no, por descripción. Los nombres
        # son únicos en el bundle v19.1, así que la coincidencia exacta basta.
        if name in _INTERNET_SCAN_NAMES:
            ds_ref = dc.get("x_mitre_data_source_ref") or ""
            desc = (dc.get("description") or "").lower()
            if ds_ref and "internet scan" in ds_ref.lower():
                return "RED_DESCARTADA"
            if "internet scan" in desc:
                return "RED_DESCARTADA"
            # Fallback documentado: nombres únicos → se mantiene la clasificación
            # literal de nombre (red).
            return "RED_DESCARTADA"
        return "RED_DESCARTADA"
    return "HOST"


def _dedup_preserve_order(items):
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# --------------------------------------------------------------------------
# Cadena de detección v19 (plan §2.2, paso 5 + 5b)
# --------------------------------------------------------------------------
def data_component_ids_for_pattern(
    pattern: dict, objects: list[dict], idx: dict[str, dict]
) -> set[str]:
    """Devuelve el conjunto de ids de Data Components asociados a un patrón.

    Camino principal: `detects` (Detection Strategy → attack-pattern) +
    `x_mitre_analytic_refs` (Strategy → Analytics) + `x_mitre_log_source_references`
    (Analytic → Data Components). Admite ambos sentidos de `detects` y refuerza
    con relaciones explícitas. Fallback directo DC↔patrón.
    """
    dc_ids: set[str] = set()
    pattern_id = pattern["id"]

    # --- 1) Detection Strategies que detectan el patrón -------------------
    strategy_ids: set[str] = set()
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
            continue
        src = idx.get(rel.get("source_ref"))
        tgt = idx.get(rel.get("target_ref"))
        if src is None or tgt is None:
            continue
        if tgt.get("type") == "attack-pattern" and tgt["id"] == pattern_id:
            if src.get("type") == "x-mitre-detection-strategy":
                strategy_ids.add(src["id"])
        elif src.get("type") == "attack-pattern" and src["id"] == pattern_id:
            if tgt.get("type") == "x-mitre-detection-strategy":
                strategy_ids.add(tgt["id"])

    # --- 2) Analytics de cada estrategia y sus Data Components ------------
    for ds_id in strategy_ids:
        strategy = idx[ds_id]
        if is_removed(strategy):
            continue
        analytic_ids: set[str] = set(strategy.get("x_mitre_analytic_refs") or [])
        # Respaldo: relaciones que toquen la estrategia y un Analytic.
        for rel in objects:
            if rel.get("type") != "relationship":
                continue
            if rel.get("source_ref") == ds_id:
                other = idx.get(rel.get("target_ref"))
                if other is not None and other.get("type") == "x-mitre-analytic":
                    analytic_ids.add(other["id"])
            elif rel.get("target_ref") == ds_id:
                other = idx.get(rel.get("source_ref"))
                if other is not None and other.get("type") == "x-mitre-analytic":
                    analytic_ids.add(other["id"])

        for an_id in analytic_ids:
            analytic = idx.get(an_id)
            if analytic is None or analytic.get("type") != "x-mitre-analytic":
                continue
            if is_removed(analytic):
                continue
            # Referencia interna: log source references → data component.
            for lsr in analytic.get("x_mitre_log_source_references") or []:
                dc_ref = lsr.get("x_mitre_data_component_ref")
                if dc_ref and dc_ref in idx and idx[dc_ref].get("type") == "x-mitre-data-component":
                    dc_ids.add(dc_ref)
            # Referencias explícitas (respaldo inter-versiones).
            for rel in objects:
                if rel.get("type") != "relationship":
                    continue
                if rel.get("source_ref") == an_id:
                    other = idx.get(rel.get("target_ref"))
                    if other is not None and other.get("type") == "x-mitre-data-component":
                        dc_ids.add(other["id"])
                elif rel.get("target_ref") == an_id:
                    other = idx.get(rel.get("source_ref"))
                    if other is not None and other.get("type") == "x-mitre-data-component":
                        dc_ids.add(other["id"])

    # --- 3) Fallback directo: detects DC ↔ attack-pattern -----------------
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
            continue
        src = idx.get(rel.get("source_ref"))
        tgt = idx.get(rel.get("target_ref"))
        if src is None or tgt is None:
            continue
        if src.get("type") == "x-mitre-data-component" and tgt.get("type") == "attack-pattern" and tgt["id"] == pattern_id:
            dc_ids.add(src["id"])
        if tgt.get("type") == "x-mitre-data-component" and src.get("type") == "attack-pattern" and src["id"] == pattern_id:
            dc_ids.add(tgt["id"])

    return dc_ids


# --------------------------------------------------------------------------
# Tácticas y prioridad
# --------------------------------------------------------------------------
def tactics_for_pattern(pattern: dict, tactic_map: dict[str, str]) -> list[str]:
    """Nombres de táctica (orden de aparición) desde `kill_chain_phases`."""
    names = []
    for phase in pattern.get("kill_chain_phases") or []:
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        shortname = phase.get("phase_name")
        names.append(tactic_map.get(shortname, shortname))
    return _dedup_preserve_order([n for n in names if n])


def compute_priority(
    tecnica_id: str,
    parent_id: str | None,
    tactics: list[str],
    host_eligible: bool,
) -> str:
    """Prioridad R/E/S determinista (P1 > P2 > P3).

    * **P1** — táctica ∈ {Impact, Exfiltration, Collection} o técnica/padre en la
      lista curada R/E/S.
    * **P2** — `host_eligible` y táctica habilitadora directa
      (Execution/Stealth/Defense Impairment/Persistence/... ). La telemetría
      "relevante" se interpreta como tener al menos un DC endpoint
      (`host_eligible`).
    * **P3** — resto.
    """
    root = (tecnica_id or "").split(".")[0]
    if (
        set(tactics) & P1_TACTICS
        or tecnica_id in CURATED_RES
        or root in CURATED_RES
        or (parent_id and parent_id in CURATED_RES)
    ):
        return "P1"
    if host_eligible and (set(tactics) & P2_TACTICS):
        return "P2"
    return "P3"


def _tecnica_sort_key(tecnica_id: str):
    match = re.match(r"T(\d+)(?:\.(\d+))?$", tecnica_id or "")
    if match:
        return (int(match.group(1)), int(match.group(2) or 0))
    return (10**9, 0)


# --------------------------------------------------------------------------
# Extracción principal
# --------------------------------------------------------------------------
def extract_corpus(stix_path: str | Path = DEFAULT_STIX) -> list[dict]:
    """Extrae el corpus host (lista de filas-dict) del bundle STIX."""
    bundle = load_bundle(stix_path)
    objects = bundle.get("objects") or []
    idx = {obj.get("id"): obj for obj in objects if obj.get("id")}

    version = collection_version(objects)
    if not version:
        raise RuntimeError("El bundle no contiene `x-mitre-collection` con versión.")

    tactic_map = {
        obj.get("x_mitre_shortname"): obj.get("name")
        for obj in objects
        if obj.get("type") == "x-mitre-tactic"
    }

    patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]
    active_patterns = [p for p in patterns if not is_removed(p)]

    # Padre de cada subtécnica.
    parent_of: dict[str, str] = {}
    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "subtechnique-of":
            if rel.get("source_ref") and rel.get("target_ref"):
                parent_of[rel["source_ref"]] = rel["target_ref"]

    # Data Components por patrón (cache, incluidos padres para herencia).
    dc_cache: dict[str, set[str]] = {}
    for pat in active_patterns:
        dc_cache[pat["id"]] = data_component_ids_for_pattern(pat, objects, idx)

    fecha = _dt.date.today().isoformat()
    rows: list[dict] = []

    for pat in active_patterns:
        is_sub = bool(pat.get("x_mitre_is_subtechnique"))
        parent_id = None
        heredado = "no"

        dc_ids = set(dc_cache.get(pat["id"]) or set())
        if is_sub and not dc_ids:
            parent_ref = parent_of.get(pat["id"])
            if parent_ref and parent_ref in idx:
                parent = idx[parent_ref]
                parent_id = external_id(parent)
                parent_dcs = dc_cache.get(parent_ref)
                if parent_dcs is None:
                    parent_dcs = data_component_ids_for_pattern(parent, objects, idx)
                    dc_cache[parent_ref] = parent_dcs
                dc_ids = set(parent_dcs)
                heredado = "si" if dc_ids else "no"
        elif is_sub:
            parent_ref = parent_of.get(pat["id"])
            if parent_ref and parent_ref in idx:
                parent_id = external_id(idx[parent_ref])

        # Clasificación de Data Components.
        host_names, red_names = [], []
        for dc_id in sorted(dc_ids):
            dc = idx.get(dc_id)
            if dc is None:
                continue
            bucket = classify_dc(dc)
            if bucket == "HOST":
                host_names.append(dc.get("name") or "")
            else:
                red_names.append(dc.get("name") or "")
        host_names = sorted(set(host_names))
        red_names = sorted(set(red_names))
        dc_names = sorted(set(host_names) | set(red_names))

        num_dc = len(dc_names)
        dc_host = len(host_names)
        dc_red = len(red_names)
        host_eligible = dc_host >= 1

        if num_dc == 0:
            motivo = "sin_datacomponents"
        elif not host_eligible:
            motivo = "solo_red"
        else:
            motivo = "ok"

        tactics = tactics_for_pattern(pat, tactic_map)
        platforms = pat.get("x_mitre_platforms") or []
        endpoint_lw = "si" if ({"Linux", "Windows"} & set(platforms)) else "no"

        tecnica_id = external_id(pat) or ""
        priority = compute_priority(
            tecnica_id, parent_id, tactics, host_eligible
        )

        rows.append(
            {
                "tecnica_id": tecnica_id,
                "nombre": pat.get("name") or "",
                "es_subtecnica": "si" if is_sub else "no",
                "padre_id": parent_id or "",
                "tacticas": ";".join(tactics),
                "plataformas": ";".join(platforms),
                "endpoint_lw": endpoint_lw,
                "data_components": ";".join(dc_names),
                "num_dc": num_dc,
                "dc_host": dc_host,
                "dc_red": dc_red,
                "host_eligible": "YES" if host_eligible else "NO",
                "priority": priority,
                "heredado_padre": heredado,
                "motivo": motivo,
                "stix_version": version,
                "fecha_generacion": fecha,
            }
        )

    rows.sort(
        key=lambda r: (
            _PRIORITY_ORDER.get(r["priority"], 9),
            _YESNO_ORDER.get(r["host_eligible"], 9),
            _tecnica_sort_key(r["tecnica_id"]),
        )
    )
    return rows


# --------------------------------------------------------------------------
# Salidas
# --------------------------------------------------------------------------
def write_csv(rows: list[dict], out_path: str | Path = DEFAULT_CSV, version: str = "19.1", fecha: str | None = None) -> Path:
    """Escribe `corpus_host.csv` con cabecera de versión + fecha."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fecha = fecha or _dt.date.today().isoformat()
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(
            f"# corpus_host.csv | MITRE ATT&CK Enterprise v{version} "
            f"(stix x_mitre_version={version}) | generado={fecha}\n"
        )
        writer = csv.DictWriter(fh, fieldnames=HEADER_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return out_path


def _res_justification(row: dict) -> str:
    tactics = set(filter(None, (row.get("tacticas") or "").split(";")))
    tags = []
    if "Impact" in tactics:
        tags.append("Ransomware/Sabotaje (Impact)")
    if "Exfiltration" in tactics:
        tags.append("Exfiltración")
    if "Collection" in tactics:
        tags.append("Recolección/preparación")
    if not tags:
        if row.get("priority") == "P2":
            tags.append("Habilitadora")
        else:
            tags.append("Otras técnicas host")
    return ", ".join(tags)


def _candidate_rank(row: dict):
    """Clave de orden para candidatas: prioridad > núcleo R/E/S > padre >
    Linux/Windows > nº de DC host."""
    root = (row.get("tecnica_id") or "").split(".")[0]
    is_core = 0 if (row.get("tecnica_id") in CURATED_RES or root in CURATED_RES) else 1
    return (
        _PRIORITY_ORDER.get(row["priority"], 9),
        is_core,
        1 if row["es_subtecnica"] == "si" else 0,
        0 if row["endpoint_lw"] == "si" else 1,
        -int(row["dc_host"]),
        _tecnica_sort_key(row["tecnica_id"]),
    )


def _recommended_corpus(rows: list[dict], target: int = 13) -> list[dict]:
    """Propuesta automática de corpus (apoyo; la decisión final es humana).

    Garantiza cobertura ≥1 por familia R/E/S (Impact, Exfiltration, Collection),
    prioriza técnicas núcleo R/E/S y evita duplicar padre + subtécnica.
    """
    eligible = [r for r in rows if r["host_eligible"] == "YES"]
    ordered = sorted(eligible, key=_candidate_rank)

    chosen: list[dict] = []
    chosen_ids: set[str] = set()

    def conflicts(row) -> bool:
        # No elegir una subtécnica si su padre ya está en el corpus (ni al revés).
        if row["es_subtecnica"] == "si" and row["padre_id"] in chosen_ids:
            return True
        if row["tecnica_id"] in {c["padre_id"] for c in chosen if c["es_subtecnica"] == "si"}:
            return True
        return False

    def add(row) -> bool:
        if row["tecnica_id"] in chosen_ids or conflicts(row):
            return False
        chosen.append(row)
        chosen_ids.add(row["tecnica_id"])
        return True

    # 1) Cobertura obligatoria por familia R/E/S (prefiriendo Linux/Windows).
    for tactic in ("Impact", "Exfiltration", "Collection"):
        for row in ordered:
            if tactic in (row.get("tacticas") or "").split(";") and row["endpoint_lw"] == "si":
                if add(row):
                    break

    # 2) Rellenar con las mejores candidatas restantes.
    for row in ordered:
        if len(chosen) >= target:
            break
        add(row)
    return chosen[:target]


def write_markdown(rows: list[dict], out_path: str | Path = DEFAULT_MD, version: str = "19.1", fecha: str | None = None) -> Path:
    """Genera `lista_tecnicas_validas.md` priorizada R/E/S."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fecha = fecha or _dt.date.today().isoformat()

    eligible = [r for r in rows if r["host_eligible"] == "YES"]
    no_eligible = [r for r in rows if r["host_eligible"] == "NO"]

    def table(rs):
        lines = [
            "| ID | Nombre | Subtéc. | Tácticas | Plataformas | DC host | DC red | Prio | Justificación R/E/S |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rs:
            names = [n for n in (r["data_components"] or "").split(";") if n]
            host_names = [n for n in names if n not in RED_PURA and n not in RED_DESCARTADA]
            lines.append(
                "| {id} | {nombre} | {sub} | {tac} | {plat} | {dh} | {dr} | {prio} | {just} |".format(
                    id=r["tecnica_id"],
                    nombre=r["nombre"],
                    sub="sí" if r["es_subtecnica"] == "si" else "no",
                    tac=r["tacticas"] or "—",
                    plat=r["plataformas"] or "—",
                    dh=", ".join(host_names) or "—",
                    dr=r["dc_red"],
                    prio=r["priority"],
                    just=_res_justification(r),
                )
            )
        return "\n".join(lines)

    # Desglose por prioridad/táctica.
    from collections import Counter  # local, evita import global innecesario

    by_prio = Counter(r["priority"] for r in eligible)
    by_tactic = Counter()
    for r in eligible:
        for t in (r["tacticas"] or "").split(";"):
            if t:
                by_tactic[t] += 1

    p1 = [r for r in eligible if r["priority"] == "P1"]
    p2 = [r for r in eligible if r["priority"] == "P2"]
    p3 = [r for r in eligible if r["priority"] == "P3"]

    rec = _recommended_corpus(eligible)

    out = []
    out.append("# Lista de técnicas válidas (host-eligible) — MITRE ATT&CK Enterprise v19.1")
    out.append("")
    out.append(f"> Generado automáticamente por `_artefactos/scripts/extraer_tecnicas_host.py` el **{fecha}**.")
    out.append(f"> Fuente: `_artefactos/mitre/enterprise-attack-v19.1.json` (STIX v{version}).")
    out.append("")
    out.append("## 1. Método (filtro inverso host, R-03)")
    out.append("")
    out.append("- Se recorre la cadena de detección de ATT&CK v19: `attack-pattern ←detects— Detection Strategy → Analytics → Data Components`.")
    out.append("- Los Data Components de red pura (`Network Connection Creation`, `Network Traffic Content`, `Network Traffic Flow`) y los descartados (`Network Share Access`, `Response Content`, `Response Metadata`) **no** otorgan elegibilidad.")
    out.append("- **Interpretación amplia (fijada):** una técnica es `host_eligible=YES` si tiene **≥1 Data Component endpoint**; los DC de red **no anulan** una técnica con telemetría host. Solo es `NO` si todos sus DC son de red.")
    out.append("- Las subtécnicas sin telemetría propia **heredan** la del padre (`heredado_padre=si`).")
    out.append("")
    out.append("## 2. Resumen del corpus")
    out.append("")
    out.append(f"- Técnicas/subtécnicas activas analizadas: **{len(rows)}** (excluidas deprecated/revoked).")
    out.append(f"- `host_eligible=YES`: **{len(eligible)}** · `NO`: **{len(no_eligible)}**.")
    out.append(f"- Prioridad (host-eligible): **P1={by_prio.get('P1', 0)}**, **P2={by_prio.get('P2', 0)}**, **P3={by_prio.get('P3', 0)}**.")
    out.append("")
    out.append("### Cobertura por táctica (host-eligible)")
    out.append("")
    out.append("| Táctica | Técnicas |")
    out.append("|---|---|")
    for t, c in sorted(by_tactic.items()):
        out.append(f"| {t} | {c} |")
    out.append("")
    out.append("## 3. Técnicas priorizadas (P1 → P3)")
    out.append("")
    out.append("### P1 — Ransomware / Exfiltración / Sabotaje")
    out.append("")
    out.append(table(p1))
    out.append("")
    out.append("### P2 — Habilitadoras directas")
    out.append("")
    out.append(table(p2))
    out.append("")
    out.append("### P3 — Resto host-eligible")
    out.append("")
    out.append(table(p3))
    out.append("")
    out.append("## 4. Top candidatas (apoyo a la selección)")
    out.append("")
    out.append("Top ~20 candidatas host-eligible ordenadas por prioridad y riqueza de telemetría:")
    out.append("")
    out.append("| # | ID | Nombre | Tácticas | Prio | DC host |")
    out.append("|---|---|---|---|---|---|")
    top = sorted(eligible, key=_candidate_rank)[:20]
    for i, r in enumerate(top, 1):
        out.append(f"| {i} | {r['tecnica_id']} | {r['nombre']} | {r['tacticas']} | {r['priority']} | {r['dc_host']} |")
    out.append("")
    out.append(f"## 5. Recomendación automática de corpus ({len(rec)} técnicas)")
    out.append("")
    out.append("> Propuesta de **apoyo**; la decisión final es humana (paso 1.5). Garantiza ≥1 técnica por familia R/E/S.")
    out.append("")
    out.append("| ID | Nombre | Tácticas | Prio | Justificación |")
    out.append("|---|---|---|---|---|")
    for r in rec:
        out.append(f"| {r['tecnica_id']} | {r['nombre']} | {r['tacticas']} | {r['priority']} | {_res_justification(r)} |")
    out.append("")

    out_path.write_text("\n".join(out), encoding="utf-8")
    return out_path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Extrae el corpus host de MITRE ATT&CK Enterprise v19.1.")
    parser.add_argument("--stix", default=str(DEFAULT_STIX), help="Ruta al bundle STIX/JSON.")
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help="Ruta de salida del CSV.")
    parser.add_argument("--md", default=str(DEFAULT_MD), help="Ruta de salida del Markdown.")
    parser.add_argument("--csv-only", action="store_true", help="No genera el Markdown.")
    args = parser.parse_args(argv)

    stix_path = Path(args.stix)
    if not stix_path.exists():
        print(f"[ERROR] No existe el STIX: {stix_path}", file=sys.stderr)
        return 2

    rows = extract_corpus(stix_path)
    version = rows[0]["stix_version"] if rows else collection_version(load_bundle(stix_path).get("objects") or [])
    fecha = rows[0]["fecha_generacion"] if rows else _dt.date.today().isoformat()

    csv_path = write_csv(rows, args.csv, version=version, fecha=fecha)
    print(f"[OK] CSV -> {csv_path} ({len(rows)} filas)")

    if not args.csv_only:
        md_path = write_markdown(rows, args.md, version=version, fecha=fecha)
        print(f"[OK] Markdown -> {md_path}")

    yes = sum(1 for r in rows if r["host_eligible"] == "YES")
    print(f"[INFO] version={version} | total={len(rows)} | host_eligible=YES {yes} | NO {len(rows) - yes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
