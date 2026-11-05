#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificador de validez de la ventana legitima (V1-V7 y V9) - bloque `legitimo-v3`.

Lee los productos ya extraidos (no toca la victima ni el manager) y emite un informe
literal por criterio. V8 (host estable) se comprueba aparte con WMI/Get-WinEvent.

Uso:
    python _artefactos/scripts/verificar_validez_ventana.py
    python _artefactos/scripts/verificar_validez_ventana.py --json

Salida: texto por stdout (o JSON con --json). Codigo de salida 0 siempre (es un informe);
el veredicto se lee de las lineas `Vn: PASA/NO`.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
T0 = "2026-11-02T00:00:00Z"
T1 = "2026-11-05T00:00:00Z"


def _dt(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def leer_csv_con_comentarios(path: Path):
    """Devuelve (lineas_comentario, lista_de_dicts). Ignora lineas que empiezan por '#'."""
    comentarios, filas = [], []
    with open(path, encoding="utf-8", newline="") as fh:
        lineas = [ln for ln in fh if not ln.startswith("#")]
    lector = csv.DictReader(lineas)
    for r in lector:
        filas.append(r)
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            if ln.startswith("#"):
                comentarios.append(ln.rstrip("\n"))
            else:
                break
    return comentarios, filas


# ---------------------------------------------------------------- V1
def v1(alertas: Path) -> dict:
    _, filas = leer_csv_con_comentarios(alertas)
    ts = [_dt(r["timestamp_utc"]) for r in filas]
    ts.sort()
    hueco = max(((b - a).total_seconds() for a, b in zip(ts, ts[1:])), default=0.0)
    dias = {}
    for t in ts:
        dias[t.date().isoformat()] = dias.get(t.date().isoformat(), 0) + 1
    t0, t1 = _dt(T0), _dt(T1)
    return {
        "filas": len(filas),
        "primera": ts[0].isoformat().replace("+00:00", "Z"),
        "ultima": ts[-1].isoformat().replace("+00:00", "Z"),
        "primera_menos_t0_min": round((ts[0] - t0).total_seconds() / 60, 2),
        "t1_menos_ultima_min": round((t1 - ts[-1]).total_seconds() / 60, 2),
        "hueco_max_s": round(hueco, 3),
        "por_dia": dias,
    }


# ---------------------------------------------------------------- V2
def _acciones_receta(path: Path) -> tuple[int, int]:
    d = json.loads(path.read_text(encoding="utf-8"))
    total = jornada = 0
    for h in d.get("TimeLineHandlers", []):
        n = len(h.get("TimeLineEvents") or [])
        total += n
        if str(h.get("UtcTimeOn", "")) < "17:00:00":
            jornada += n
    return total, jornada


def _bloques(path: Path) -> list[tuple[int, int, str]]:
    out = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(B\d)=(\d\d):(\d\d)-(\d\d):(\d\d)\b", ln.strip())
        if m:
            out.append((int(m.group(2)), int(m.group(4)), m.group(1)))
    return out


def v2(acciones: Path, recetas: Path) -> dict:
    _, filas = leer_csv_con_comentarios(acciones)
    total = next((int(r["acciones"]) for r in filas if r["tipo"] == "total"), None)
    por_dia: dict[str, int] = {}
    por_hora: dict[str, int] = {}
    for r in filas:
        if r["tipo"] == "hora":
            dia, hora = r["clave"].split("T")
            por_dia[dia] = por_dia.get(dia, 0) + int(r["acciones"])
            por_hora[r["clave"]] = int(r["acciones"])
    receta = {}
    for i, dia in enumerate(("2026-11-02", "2026-11-03", "2026-11-04"), start=1):
        tot, jor = _acciones_receta(recetas / f"d{i}.json")
        receta[dia] = {"total": tot, "jornada": jor, "campana": tot - jor}
    bloques = _bloques(recetas / "bloques.env")
    fuera = []
    for clave in por_hora:
        h = int(clave.split("T")[1][:2])
        if not any(a <= h <= b for a, b, _ in bloques):
            fuera.append(clave)
    return {
        "total_acciones": total,
        "por_dia": por_dia,
        "receta": receta,
        "cumplimiento_pct": {
            d: round(100.0 * por_dia.get(d, 0) / receta[d]["total"], 2) for d in receta
        },
        "horas_con_acciones": sorted(por_hora),
        "horas_fuera_de_bloques": fuera,
        "bloques": bloques,
    }


# ---------------------------------------------------------------- V3
def v3(vigilancia: Path, manifest: Path | None) -> dict:
    lineas = [
        ln for ln in vigilancia.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\[2026-11-0[2-4]T", ln) and "[watch] estado=" in ln
    ]
    estados = {}
    for ln in lineas:
        m = re.search(r"estado=(\w+)", ln)
        if m:
            estados[m.group(1)] = estados.get(m.group(1), 0) + 1
    diarios = {}
    if manifest and manifest.exists():
        for ln in manifest.read_text(encoding="utf-8-sig").splitlines():
            if not ln.strip():
                continue
            sha, nombre, bytes_ = ln.split()[:3]
            p = manifest.parent / nombre
            diarios[nombre] = {
                "bytes": int(bytes_),
                "existe": p.exists(),
                "sha_ok": p.exists() and sha256_file(p) == sha,
            }
    return {
        "chequeos": len(lineas),
        "estados": estados,
        "mgr_active_2": sum(1 for ln in lineas if "mgr=active/2" in ln),
        "ag_Active": sum(1 for ln in lineas if "ag=Active" in ln),
        "primero": lineas[0][1:21] if lineas else None,
        "ultimo": lineas[-1][1:21] if lineas else None,
        "diarios": diarios,
    }


# ---------------------------------------------------------------- V4
def v4(alertas: Path) -> dict:
    _, filas = leer_csv_con_comentarios(alertas)
    return {
        "srcip_192_168_65_1": sum(1 for r in filas if r.get("srcip") == "192.168.65.1"),
        "srcip_no_vacia": sum(1 for r in filas if (r.get("srcip") or "").strip()),
        "srcuser_no_vacio": sum(1 for r in filas if (r.get("srcuser") or "").strip()),
        "reglas_sesion": {
            rid: sum(1 for r in filas if r.get("rule_id") == rid)
            for rid in ("5715", "5501", "5502", "5402", "550")
        },
        "agent_name_distintos": sorted({r.get("agent_name") for r in filas}),
    }


# ---------------------------------------------------------------- V5
def v5(ip_route: Path) -> dict:
    txt = ip_route.read_text(encoding="utf-8-sig").strip()
    return {
        "lineas": [ln for ln in txt.splitlines() if ln.strip()],
        "tiene_default": any(re.search(r"\bdefault\b", ln) for ln in txt.splitlines()),
    }


# ---------------------------------------------------------------- V6
def v6(denominador: Path, manifest: Path) -> dict:
    comentarios, filas = leer_csv_con_comentarios(denominador)
    cab = comentarios[0] if comentarios else ""
    m = re.search(r"sha256_entradas=([^|]+)", cab)
    entradas = {}
    if m:
        for trozo in m.group(1).strip().split(","):
            sha, nombre = trozo.split(":", 1)
            entradas[nombre] = sha
    manifiesto = {}
    if manifest.exists():
        for ln in manifest.read_text(encoding="utf-8-sig").splitlines():
            if ln.strip():
                sha, nombre, bytes_ = ln.split()[:3]
                manifiesto[nombre] = {"sha256": sha, "bytes": int(bytes_)}
    filas_d = {r["ambito"]: r for r in filas}
    return {
        "endpoint": filas_d.get("endpoint", {}).get("eventos"),
        "total": filas_d.get("total", {}).get("eventos"),
        "cobertura": [
            filas_d.get("endpoint", {}).get("primer_ts"),
            filas_d.get("endpoint", {}).get("ultimo_ts"),
        ],
        "ficheros_declarados": len(entradas),
        "sha_coinciden_manifest": all(
            manifiesto.get(n, {}).get("sha256") == s for n, s in entradas.items()
        ),
        "bytes_coinciden": all(
            (manifest.parent / n).exists()
            and (manifest.parent / n).stat().st_size == manifiesto.get(n, {}).get("bytes", -1)
            for n in entradas
        ),
    }


# ---------------------------------------------------------------- V7
def v7(sha256sums: Path, ruleset: Path, control_log: Path) -> dict:
    ok = bad = missing = 0
    fallos = []
    for ln in sha256sums.read_text(encoding="utf-8").splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        sha, ruta = ln.split(None, 1)
        p = REPO / ruta.strip()
        if not p.exists():
            missing += 1
            fallos.append(("MISSING", ruta.strip()))
        elif sha256_file(p) != sha:
            bad += 1
            fallos.append(("BAD", ruta.strip()))
        else:
            ok += 1
    config_identica = None
    if control_log.exists():
        hits = [ln for ln in control_log.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() in ("CONFIG_IDENTICA", "CONFIG_DIFIERE")]
        config_identica = hits[-1] if hits else None
    return {
        "sha256sums_ok": ok,
        "sha256sums_bad": bad,
        "sha256sums_missing": missing,
        "fallos": fallos,
        "ruleset_sha256": sha256_file(ruleset) if ruleset.exists() else None,
        "config_identica_ultimo": config_identica,
        "git_status": _git_status(),
    }


def _git_status() -> list[str]:
    try:
        r = subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                           capture_output=True, text=True, timeout=60)
        return [ln for ln in r.stdout.splitlines() if ln.strip()]
    except Exception as exc:  # pragma: no cover - entorno sin git
        return [f"ERROR git: {exc}"]


# ---------------------------------------------------------------- V9
def v9(evidencia: Path) -> dict:
    rec = (evidencia / "recovery.txt").read_text(encoding="utf-8").splitlines()
    recuperaciones = sum(1 for ln in rec if "accion=recuperacion" in ln)
    rotaciones = sum(1 for ln in rec if "accion=rotacion" in ln)
    fallidas = sum(1 for ln in rec if "resultado=" in ln and "resultado=ok" not in ln)
    client = (evidencia / "client_out.txt").read_text(encoding="utf-8", errors="replace")
    arranques = client.count("running in production mode")
    rot = (evidencia / "rotacion_estado.txt").read_text(encoding="utf-8").strip()
    return {
        "recuperaciones": recuperaciones,
        "rotaciones": rotaciones,
        "rotaciones_fallidas": fallidas,
        "arranques_cliente": arranques,
        "rotacion_estado": rot,
        "lineas_recovery": rec,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ventana", default=str(REPO / "Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02"))
    ap.add_argument("--recetas", default=str(REPO / "Soporte/Laboratorio/legitimo_72h/recetas"))
    ap.add_argument("--vigilancia", default=str(REPO / "Soporte/Laboratorio/legitimo_72h/vigilancia_legitimo.log"))
    ap.add_argument("--sha256sums", default=str(REPO / "Soporte/Laboratorio/legitimo_72h/sha256sums.txt"))
    ap.add_argument("--ruleset", default=str(REPO / "Soporte/Wazuh/Configuracion/active_ruleset.txt"))
    ap.add_argument("--control-log", default=str(REPO / "Soporte/Laboratorio/legitimo_72h/legitimo_host_control.log"))
    ap.add_argument("--manifest-denominador", default=r"D:/TFG-VMs/legitimo-2026-11-02/denominador/MANIFEST.tsv")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    ventana = Path(a.ventana)
    ev = ventana / "evidencia"
    res = {
        "t0": T0,
        "t1": T1,
        "V1": v1(ventana / "alertas_detalle.csv"),
        "V2": v2(ventana / "ghosts_acciones.csv", Path(a.recetas)),
        "V3": v3(Path(a.vigilancia), Path(a.manifest_denominador)),
        "V4": v4(ventana / "alertas_detalle.csv"),
        "V5": v5(ev / "ip_route.txt"),
        "V6": v6(ventana / "denominador_M.csv", Path(a.manifest_denominador)),
        "V7": v7(Path(a.sha256sums), Path(a.ruleset), Path(a.control_log)),
        "V9": v9(ev),
    }
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    print(f"ventana {T0} .. {T1}\n")
    x = res["V1"]
    print(f"V1 filas={x['filas']} primera={x['primera']} (+{x['primera_menos_t0_min']} min de t0) "
          f"ultima={x['ultima']} ({x['t1_menos_ultima_min']} min antes de t1) hueco_max={x['hueco_max_s']}s")
    print(f"   por dia: {x['por_dia']}")
    x = res["V2"]
    print(f"V2 total_acciones={x['total_acciones']} por_dia={x['por_dia']} receta={x['receta']}")
    print(f"   cumplimiento_pct={x['cumplimiento_pct']}")
    print(f"   horas_con_acciones={x['horas_con_acciones']}")
    print(f"   horas_fuera_de_bloques={x['horas_fuera_de_bloques']}")
    x = res["V3"]
    print(f"V3 chequeos={x['chequeos']} estados={x['estados']} mgr_active_2={x['mgr_active_2']} "
          f"ag_Active={x['ag_Active']} primero={x['primero']} ultimo={x['ultimo']}")
    for n, d in x["diarios"].items():
        print(f"   diario {n}: bytes={d['bytes']} existe={d['existe']} sha_ok={d['sha_ok']}")
    x = res["V4"]
    print(f"V4 srcip_192.168.65.1={x['srcip_192_168_65_1']} srcip_no_vacia={x['srcip_no_vacia']} "
          f"srcuser_no_vacio={x['srcuser_no_vacio']} reglas_sesion={x['reglas_sesion']} "
          f"agentes={x['agent_name_distintos']}")
    x = res["V5"]
    print(f"V5 tiene_default={x['tiene_default']} rutas={x['lineas']}")
    x = res["V6"]
    print(f"V6 endpoint={x['endpoint']} total={x['total']} cobertura={x['cobertura']} "
          f"ficheros={x['ficheros_declarados']} sha_coinciden={x['sha_coinciden_manifest']} "
          f"bytes_coinciden={x['bytes_coinciden']}")
    x = res["V7"]
    print(f"V7 sha256sums ok={x['sha256sums_ok']} bad={x['sha256sums_bad']} missing={x['sha256sums_missing']}")
    print(f"   ruleset_sha256={x['ruleset_sha256']}")
    print(f"   CONFIG_IDENTICA(ultimo)={x['config_identica_ultimo']}")
    print("   git status:")
    for ln in x["git_status"]:
        print(f"     {ln}")
    x = res["V9"]
    print(f"V9 recuperaciones={x['recuperaciones']} rotaciones={x['rotaciones']} "
          f"rotaciones_fallidas={x['rotaciones_fallidas']} arranques_cliente={x['arranques_cliente']} "
          f"rotacion_estado={x['rotacion_estado']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
