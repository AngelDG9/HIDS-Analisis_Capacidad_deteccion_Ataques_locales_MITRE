#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analizar_legitimo_windows.py — T3-W: productos del plano LEGÍTIMO de la ventana Windows.

Es el **espejo de `analizar_legitimo_72h.py` (Linux)**: convierte la ventana ya capturada
(`archives` del manager) en los productos que consume `tabla3_legitimo.py`, **sin volver a
medir nada en el laboratorio**. Misma unidad, mismo índice, mismos formatos: lo único que
cambia es el agente (`002`), el predicado del operador y el `auto_ruido`.

## Qué produce (en `--out-dir`)

1. `eventos_alerta_windows.csv.gz` — **índice evento↔alerta**: una fila por línea de `archives`
   del endpoint **con alerta** (`rule.level ≥ 3`), `unidad = "<fichero>:<nº de línea>"`
   (única por construcción; mismo criterio que Linux). Lleva `auto_ruido` y `operador_legit`.
2. `T3_detalle_windows.csv` — lo que lee `tabla3_legitimo.py --detalle` (mismas columnas que
   Linux: `unidad, rule_id, rule_level, rs_origen, categoria, rule_groups`).
3. `fpr_doble_windows.csv` — **FPR canónico y `sin_operador`** por umbral N (0/3/7/10/12), con
   `FP/acción` y `FP/hora`. **El denominador `M` no cambia** (igual que la sensibilidad
   «sin auto-ruido» de Linux).
4. `catalogo_ruido_windows.csv` — reglas observadas en la ventana (nivel, grupos, nº de
   alertas, nº del operador). `catalogo_M1b_windows.csv` — catálogo para re-cortar los 54
   ataques: ventana ∪ operador ∪ artefactos (con `origen_catalogo`).
5. `estabilidad_hora_windows.csv` y `estabilidad_dia_windows.csv` — eventos, alertas y alertas
   del operador por hora (72) y por día (3).
6. `resumen_windows.json` — `M`, `FP_uni`, `operador_uni`, FPR, recuentos y declaraciones.

## Definiciones (coherentes con Linux y con `comparabilidad_windows.md`)

* `M` = líneas de `archives` del endpoint `002` en `[t0, t1]` (se **re-cuenta** aquí con
  `contar_denominador.contar`; no se copia de ninguna ficha).
* `FP_uni` = líneas de `archives` del endpoint con alerta (`rule.level ≥ 3`). Una línea
  produce a lo sumo una regla, así que `#alertas = #unidades`.
* `operador_legit` = `etiquetar_operador_legit.motivo_operador` (SSH, keepalive, latido,
  tareas del laboratorio…). **No** se marca por `win_user=angel`: es el usuario legítimo.
* `auto_ruido` (**ruido del propio HIDS**) = la imagen o el padre es el **agente Wazuh** o
  `Sysmon64.exe`. Es una **sensibilidad** declarada (como «sin auto-ruido» de Linux), no entra
  en el canónico.
* `FPR_canonico = FP_uni / M`; `FPR_sin_operador = (FP_uni − operador_uni) / M`.

## Uso

    python analizar_legitimo_windows.py --archives D:\\TFG-VMs\\legitimo-windows-2026-11-23\\crudo\\archives \\
        --t0 2026-11-23T00:00:00Z --t1 2026-11-26T00:00:00Z --out-dir RUTA [--acciones 504]
    python tabla3_legitimo.py --so windows --detalle RUTA/T3_detalle_windows.csv --unidades-count <M> ...

Determinismo: sin reloj, orden estable, LF, UTF-8 sin BOM; el `.gz` se escribe con `mtime=0`.
Solo biblioteca estándar. Sin red, sin VMs, sin secretos.
"""

from __future__ import annotations

import argparse
import collections
import csv
import glob
import gzip
import io
import json
import ntpath
import os
import sys
from datetime import timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contar_denominador as cd  # noqa: E402
import etiquetar_operador_legit as EL  # noqa: E402
import extraer_alertas_windows as EA  # noqa: E402
import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

AGENT_ID = "002"
AGENT_NAME = "victima-windows"
BOVEDA_VERSION_WINDOWS = 3          # Windows sella con bóveda v3 (Linux v2): ver plan §7.5
NIVEL_ALERTA_MIN = 3                # `alert_log_level` por defecto de Wazuh

IDX_HEADER = ["unidad", "timestamp_utc", "rule_id", "rule_level", "rule_groups",
              "auto_ruido", "operador_legit", "motivo_operador"]
DETALLE_HEADER = ["unidad", "rule_id", "rule_level", "rs_origen", "categoria", "rule_groups"]
FPR_HEADER = ["umbral_N", "FP_uni", "operador_uni", "M", "FPR_canonico", "FPR_sin_operador",
              "FP_por_accion", "FP_por_hora"]
CATALOGO_HEADER = ["rule_id", "rule_level", "rule_groups", "count_ventana", "count_operador",
                   "origen_catalogo", "justificacion"]
EST_HEADER = ["periodo", "eventos_M", "alertas", "alertas_operador", "alertas_auto_ruido"]

#: Reglas del operador (SSH/logon): se incluyen en el catálogo M1b aunque la ventana no las
#: ejercite, porque el corpus de ataques se lanzó por SSH (plan §7.3).
REGLAS_OPERADOR = ("60106", "60137", "67022", "67023", "67024", "67028")
#: Artefactos del ataque ya declarados (precedente ATA073/ATA097 y W-07).
REGLAS_ARTEFACTO_ATAQUE = ("92213", "91823")
#: Reglas que saltan por el **modo de entrega** (`sshd.exe → cmd /c`), no por la técnica
#: (M-23). Se clasifican por **alerta** (padre `sshd.exe`), no por regla entera.
REGLAS_ARTEFACTO_ENTREGA = ("92052", "92032")

#: Procesos del propio HIDS: su ruido no es del usuario ni del operador.
IMAGENES_AUTO_RUIDO = ("wazuh-agent.exe", "sysmon64.exe", "sysmon.exe")
CARPETA_AGENTE = "\\ossec-agent\\"


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def _es_auto_ruido(fila: dict) -> bool:
    """Imagen o padre = agente Wazuh o Sysmon (ruido del propio HIDS)."""
    for campo in ("win_image", "win_parent_image"):
        v = (fila.get(campo) or "").strip()
        if not v:
            continue
        if ntpath.basename(v).lower() in IMAGENES_AUTO_RUIDO or CARPETA_AGENTE in v.lower().replace("/", "\\"):
            return True
    return False


def _fila_desde_evento(rec: dict, ts_z: str) -> dict:
    """Fila con las columnas que consumen el etiquetador y el predicado de auto-ruido."""
    rule = rec.get("rule") or {}
    groups = rule.get("groups", []) or []
    if isinstance(groups, str):
        groups = [groups]
    fila = {
        "timestamp_utc": ts_z,
        "rule_id": str(rule.get("id", "") or "").strip() or "?",
        "rule_level": str(rule.get("level", "")),
        "rule_groups": "|".join(str(g) for g in groups),
        "syscheck_path": str((rec.get("syscheck") or {}).get("path", "") or ""),
        "srcip": EA.srcip_de(rec),
    }
    fila.update(EA.campos_windows(rec))
    return fila


def _listar_archives(ruta: str):
    """Ficheros de `archives` (`*.json` y `*.json.gz`) de un directorio, o un fichero suelto."""
    if os.path.isdir(ruta):
        fs = sorted(glob.glob(os.path.join(ruta, "ossec-archive-*.json.gz"))
                    + glob.glob(os.path.join(ruta, "archives.json")))
        return fs
    return [ruta]


def leer_indice(paths, t0, t1, agent_id=AGENT_ID, agent_name=AGENT_NAME):
    """Devuelve (filas_indice, M). Mismo criterio de agente y de ventana que `contar`."""
    filas = []
    m_endpoint = 0
    for path in paths:
        tag = os.path.basename(path)
        for nlin, line in enumerate(cd._open_lines(path), 1):
            line = line.strip() if isinstance(line, str) else line.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_raw = rec.get("timestamp")
            if not ts_raw:
                continue
            try:
                ts = cd.parse_ts(str(ts_raw))
            except ValueError:
                continue
            if ts < t0 or ts > t1:
                continue
            ag = rec.get("agent") or {}
            if not (str(ag.get("id", "") or "") == agent_id or (agent_name and str(ag.get("name", "") or "") == agent_name)):
                continue
            m_endpoint += 1
            rule = rec.get("rule")
            if not rule:
                continue
            try:
                lvl = int(rule.get("level", 0))
            except (TypeError, ValueError):
                lvl = 0
            if lvl < NIVEL_ALERTA_MIN:
                continue
            ts_z = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
            fila = _fila_desde_evento(rec, ts_z)
            hit = EL.motivo_operador(fila)
            filas.append({
                "unidad": f"{tag}:{nlin}",
                "timestamp_utc": ts_z,
                "rule_id": fila["rule_id"],
                "rule_level": fila["rule_level"],
                "rule_groups": fila["rule_groups"],
                "auto_ruido": 1 if _es_auto_ruido(fila) else 0,
                "operador_legit": 1 if hit else 0,
                "motivo_operador": hit[0] if hit else "",
                "_win_parent_image": fila.get("win_parent_image", ""),
            })
    return filas, m_endpoint


def _clave_regla(rid: str):
    return (0, int(rid)) if rid.isdigit() else (1, rid)


def tabla_fpr(filas, m, n_acciones, horas):
    """FPR canónico y sin operador por umbral N. `FP_por_*` usan alertas (= unidades)."""
    out = []
    for n in M.UMBRALES:
        sel = [f for f in filas if int(f["rule_level"] or 0) >= n]
        fp = len(sel)
        op = sum(1 for f in sel if f["operador_legit"] == 1)
        d = EL.doble_fpr(m, fp, op) if m else {"FPR_canonico": "", "FPR_sin_operador": ""}
        out.append({
            "umbral_N": n, "FP_uni": fp, "operador_uni": op, "M": m,
            "FPR_canonico": d["FPR_canonico"], "FPR_sin_operador": d["FPR_sin_operador"],
            "FP_por_accion": round(fp / n_acciones, 6) if n_acciones else "",
            "FP_por_hora": round(fp / horas, 6) if horas else "",
        })
    return out


def catalogos(filas):
    por_regla = {}
    for f in filas:
        e = por_regla.setdefault(f["rule_id"], {"rule_level": f["rule_level"], "rule_groups": f["rule_groups"],
                                                "n": 0, "op": 0})
        e["n"] += 1
        e["op"] += 1 if f["operador_legit"] == 1 else 0
    cat = []
    for rid in sorted(por_regla, key=_clave_regla):
        e = por_regla[rid]
        cat.append({"rule_id": rid, "rule_level": e["rule_level"], "rule_groups": e["rule_groups"],
                    "count_ventana": e["n"], "count_operador": e["op"], "origen_catalogo": "ventana",
                    "justificacion": "observada en la ventana legitima (ruido conocido)"})
    m1b = list(cat)
    vistas = set(por_regla)
    for rid in REGLAS_OPERADOR:
        if rid not in vistas:
            m1b.append({"rule_id": rid, "rule_level": "", "rule_groups": "", "count_ventana": 0,
                        "count_operador": 0, "origen_catalogo": "operador",
                        "justificacion": "regla de logon SSH del operador: el corpus de ataques se lanzo por SSH"})
    for rid in REGLAS_ARTEFACTO_ATAQUE:
        m1b.append({"rule_id": rid, "rule_level": "", "rule_groups": "", "count_ventana": por_regla.get(rid, {}).get("n", 0),
                    "count_operador": 0, "origen_catalogo": "artefacto_ataque",
                    "justificacion": "artefacto de la herramienta de ataque (precedente ATA073/ATA097 y W-07)"})
    for rid in REGLAS_ARTEFACTO_ENTREGA:
        m1b.append({"rule_id": rid, "rule_level": "", "rule_groups": "", "count_ventana": por_regla.get(rid, {}).get("n", 0),
                    "count_operador": 0, "origen_catalogo": "artefacto_entrega",
                    "justificacion": "salta por el modo de entrega (sshd.exe -> cmd /c), no por la tecnica; "
                                     "se clasifica POR ALERTA (92052 padre sshd.exe; 92032 padre cmd.exe anidado) (plan M-23), no la regla entera"})
    return cat, m1b


def estabilidad(filas, m_por_periodo, corte):
    """Agrega por `corte` caracteres del timestamp (13 = hora, 10 = día)."""
    ev = collections.Counter(m_por_periodo)
    al, op, au = collections.Counter(), collections.Counter(), collections.Counter()
    for f in filas:
        k = f["timestamp_utc"][:corte]
        al[k] += 1
        op[k] += f["operador_legit"]
        au[k] += f["auto_ruido"]
    claves = sorted(set(ev) | set(al))
    return [{"periodo": k, "eventos_M": ev.get(k, 0), "alertas": al.get(k, 0),
             "alertas_operador": op.get(k, 0), "alertas_auto_ruido": au.get(k, 0)} for k in claves]


def contar_eventos_por_periodo(paths, t0, t1, corte, agent_id=AGENT_ID, agent_name=AGENT_NAME):
    c = collections.Counter()
    for path in paths:
        for line in cd._open_lines(path):
            line = line.strip() if isinstance(line, str) else line.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                ts = cd.parse_ts(str(rec.get("timestamp", "")))
            except (json.JSONDecodeError, ValueError):
                continue
            if ts < t0 or ts > t1:
                continue
            ag = rec.get("agent") or {}
            if not (str(ag.get("id", "") or "") == agent_id or (agent_name and str(ag.get("name", "") or "") == agent_name)):
                continue
            c[ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")[:corte]] += 1
    return c


def _escribir_gz(path, header, filas):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    for r in filas:
        w.writerow([r.get(c, "") for c in header])
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(buf.getvalue().encode("utf-8"))


def _cabecera(nombre, extra):
    return f"# {nombre} | TFG HIDS - T3-W (ventana legitima Windows) | metrica_version={M.VERSION_METRICA} | " \
           f"boveda_version={BOVEDA_VERSION_WINDOWS} | plataforma=windows | " + " | ".join(extra)


def analizar(archives, t0, t1, out_dir, n_acciones=504, agent_id=AGENT_ID, agent_name=AGENT_NAME):
    paths = _listar_archives(archives) if isinstance(archives, str) else list(archives)
    if not paths:
        raise SystemExit("no hay ficheros de archives en " + str(archives))
    paths, duplicados = cd.deduplicar(paths)          # `archives.json` puede ser hardlink del dia (H-D)
    res, per_file = cd.contar(paths, t0, t1, agent_id, agent_name)
    m_ref = res["endpoint"]["eventos"]
    dup = cd.solapes(per_file)
    if dup:                                            # igual que `contar_denominador --estricto`
        a, b = dup[0]
        raise SystemExit("--estricto: ficheros de archives con rangos solapados: "
                         f"{os.path.basename(a['path'])} y {os.path.basename(b['path'])}")
    filas, m = leer_indice(paths, t0, t1, agent_id, agent_name)
    if m != m_ref:
        raise SystemExit(f"incoherencia: indice cuenta M={m} y contar_denominador M={m_ref}")
    horas = (t1 - t0).total_seconds() / 3600.0
    fpr = tabla_fpr(filas, m, n_acciones, horas)
    cat, m1b = catalogos(filas)
    est_h = estabilidad(filas, contar_eventos_por_periodo(paths, t0, t1, 13, agent_id, agent_name), 13)
    est_d = estabilidad(filas, contar_eventos_por_periodo(paths, t0, t1, 10, agent_id, agent_name), 10)

    os.makedirs(out_dir, exist_ok=True)
    _escribir_gz(os.path.join(out_dir, "eventos_alerta_windows.csv.gz"), IDX_HEADER, filas)
    det = [{"unidad": f["unidad"], "rule_id": f["rule_id"], "rule_level": f["rule_level"],
            "rs_origen": "RS1", "categoria": M.CATEGORIA_AUTO_RUIDO if f["auto_ruido"] else "ruido_conocido",
            "rule_groups": f["rule_groups"]} for f in filas]
    com = lambda n, e: _cabecera(n, e)  # noqa: E731
    TC.write_csv(os.path.join(out_dir, "T3_detalle_windows.csv"), DETALLE_HEADER, det,
                 comment=com("T3_detalle_windows.csv", [f"filas={len(det)}", "intermedio regenerable",
                                                          "rs_origen=RS1 (todas las reglas de Windows son del ruleset por defecto)"]))
    TC.write_csv(os.path.join(out_dir, "fpr_doble_windows.csv"), FPR_HEADER, fpr,
                 comment=com("fpr_doble_windows.csv", [f"M={m}", f"n_acciones={n_acciones}", f"horas={horas:.1f}",
                                                         "FPR_sin_operador=(FP_uni-operador_uni)/M (el denominador no cambia)"]))
    TC.write_csv(os.path.join(out_dir, "catalogo_ruido_windows.csv"), CATALOGO_HEADER, cat,
                 comment=com("catalogo_ruido_windows.csv", [f"reglas={len(cat)}"]))
    TC.write_csv(os.path.join(out_dir, "catalogo_M1b_windows.csv"), CATALOGO_HEADER, m1b,
                 comment=com("catalogo_M1b_windows.csv", [f"reglas={len(m1b)}",
                                                            "catalogo=ventana U operador U artefactos"]))
    TC.write_csv(os.path.join(out_dir, "estabilidad_hora_windows.csv"), EST_HEADER, est_h,
                 comment=com("estabilidad_hora_windows.csv", [f"horas={len(est_h)}"]))
    TC.write_csv(os.path.join(out_dir, "estabilidad_dia_windows.csv"), EST_HEADER, est_d,
                 comment=com("estabilidad_dia_windows.csv", [f"dias={len(est_d)}"]))
    n0 = fpr[0]
    resumen = {
        "ventana": {"t0": cd.fmt_ts(t0), "t1": cd.fmt_ts(t1), "horas": round(horas, 3)},
        "agente": {"id": agent_id, "nombre": agent_name},
        "M_endpoint": m, "M_total": res["total"]["eventos"],
        "fp_uni_N0": n0["FP_uni"], "operador_uni_N0": n0["operador_uni"],
        "FPR_canonico_N0": n0["FPR_canonico"], "FPR_sin_operador_N0": n0["FPR_sin_operador"],
        "auto_ruido_uni": sum(f["auto_ruido"] for f in filas),
        "reglas_distintas": len(cat), "n_acciones": n_acciones,
        "ficheros": [os.path.basename(p) for p in paths], "duplicados_descartados": len(duplicados), "solapes": 0,
        "declaraciones": [
            "M se re-cuenta aqui con contar_denominador; coincide con el indice (comprobado)",
            "FPR_sin_operador no cambia el denominador",
            "auto_ruido = agente Wazuh/Sysmon (sensibilidad, no entra en el canonico)",
            "92052/92032 con padre sshd.exe son artefacto de entrega: se tratan en M1b-W, por alerta",
        ],
    }
    with open(os.path.join(out_dir, "resumen_windows.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(resumen, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return resumen, fpr, filas


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="T3-W: productos del plano legitimo de la ventana Windows.")
    ap.add_argument("--archives", required=True, help="directorio de archives (o un fichero)")
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--acciones", type=int, default=504)
    ap.add_argument("--agent-id", default=AGENT_ID)
    ap.add_argument("--agent-name", default=AGENT_NAME)
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    t0, t1 = cd.parse_ts(a.t0), cd.parse_ts(a.t1)
    resumen, fpr, _ = analizar(a.archives, t0, t1, a.out_dir, a.acciones, a.agent_id, a.agent_name)
    print(f"M endpoint={resumen['M_endpoint']} | FP_uni(N0)={resumen['fp_uni_N0']} | "
          f"operador_uni={resumen['operador_uni_N0']}")
    print(f"FPR canonico={resumen['FPR_canonico_N0']} | sin_operador={resumen['FPR_sin_operador_N0']}")
    for r in fpr:
        print(f"  N={r['umbral_N']:>2}  FP_uni={r['FP_uni']:>6}  op={r['operador_uni']:>5}  "
              f"FP/accion={r['FP_por_accion']}  FP/hora={r['FP_por_hora']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
