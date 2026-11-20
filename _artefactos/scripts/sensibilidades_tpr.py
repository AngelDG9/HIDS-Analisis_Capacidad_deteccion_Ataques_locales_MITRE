#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sensibilidades_tpr.py — TPR comparado Linux↔Windows con las MISMAS definiciones.

Responde a la pregunta «¿qué parte del TPR es detección real y cuál es una regla genérica o
un efecto de cómo se lanzó el ataque?» con **cuatro variantes iguales en las dos plataformas**:

| variante | Qué descuenta |
|---|---|
| `canonico` | nada (es el resultado principal, el que pide la métrica del profesor) |
| `sin_entrega` | alertas que saltan por **cómo se lanzó el ataque** y no por la técnica. En Windows: `92052` con padre `sshd.exe` (el envoltorio `sshd.exe → cmd /c`) y `92032` con padre `cmd.exe` (el `cmd` anidado de las comprobaciones del montaje: `cmd /c echo SSH-OK`, `if exist … efecto_local.txt echo OK`, `sftp-server.exe`; medido en el crudo). En Linux no hay equivalente: el envoltorio (`dash`) ya cae como `ruido_conocido` al clasificar (también aparece en el legítimo) ⇒ la variante coincide con la canónica (declarado) |
| `sin_doble_uso` | alertas de reglas **de doble uso**: las que T5 marca `SÍ` (saltan también en lo legítimo). Lo decide el dato, no una lista a mano |
| `sin_entrega_ni_doble_uso` | las dos cosas a la vez |

Un caso cuenta como detectado a nivel `N` si tiene ≥1 alerta de categoría `deteccion` con
`rule.level ≥ N` que **no** esté descontada por la variante. Se usa la ventana **canónica** de cada caso, la misma que usa `tabla2_ataques.py`: `rev1` si el caso está en `Hojas/repeticiones.csv` (9 casos de Linux) y `iter1` si no. Con ella se reproduce `T4` (Linux 53/55 a N≥3 y 2/55 a N≥7; Windows 54/54 y 2/54). Salida: CSV largo, determinista.

Lo importante (se imprime al final): **el resultado principal es `canonico`**; el resto son
sensibilidades para el anexo. Si un descuento hunde el TPR, se ve aquí por qué.

Uso:
    python sensibilidades_tpr.py --out Hojas/T2_sensibilidades_comparadas.csv
Solo biblioteca estándar. Sin red, sin VMs, sin secretos.
"""

from __future__ import annotations

import argparse
import csv
import glob
import gzip
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402

csv.field_size_limit(10**9)

UMBRALES = (0, 3, 7, 10, 12)
VARIANTES = ("canonico", "sin_entrega", "sin_doble_uso", "sin_entrega_ni_doble_uso")
HEADER = ["plataforma", "variante", "umbral_N", "casos_detectados", "casos_total", "TPR"]

DEF_LINUX_AUDITED = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEF_WIN_AUDITED = "Dataset/Ataques/Resultados/Wazuh/windows/Auditado"
DEF_T5_LINUX = "Hojas/T5_doble_uso.csv"
DEF_REPETICIONES = "Hojas/repeticiones.csv"
DEF_T5_WIN = "Hojas/T5_doble_uso_windows_b2.csv"
DEF_ALERTAS_WIN = r"D:\TFG-VMs\crudo-ataques\alerts_ataques"

REGLAS_ENTREGA_WIN = ("92052", "92032")  # envoltorio de entrega SSH (plan M-23)
PADRES_ENTREGA_WIN = ("sshd.exe", "cmd.exe")  # 92052: padre sshd.exe; 92032: cmd anidado (`cmd /c "cmd /c ..."`)


def _leer(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        lineas = [l for l in fh if not l.startswith("#")]
    return list(csv.DictReader(io.StringIO("".join(lineas))))


def reglas_doble_uso(t5_path):
    """Reglas que T5 marca `SÍ` (tolera la tilde mal codificada)."""
    if not t5_path or not os.path.isfile(t5_path):
        return set()
    return {r["rule_id"] for r in _leer(t5_path) if (r.get("doble_uso") or "").strip().upper().startswith("S")}


def mapa_padres(alertas_dir, reglas=REGLAS_ENTREGA_WIN, agent_id="002"):
    """`(timestamp[:23], rule_id) -> nombre del proceso padre`, desde las alertas CRUDAS."""
    padres = {}
    if not alertas_dir or not os.path.isdir(alertas_dir):
        return None
    for f in sorted(glob.glob(os.path.join(alertas_dir, "*"))):
        op = gzip.open if f.endswith(".gz") else open
        with op(f, "rt", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                if not any(f'"{r}"' in linea for r in reglas):
                    continue
                try:
                    d = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                if (d.get("agent") or {}).get("id") != agent_id:
                    continue
                rid = (d.get("rule") or {}).get("id")
                if rid not in reglas:
                    continue
                ed = (((d.get("data") or {}).get("win") or {}).get("eventdata") or {})
                p = str(ed.get("parentImage") or "").replace("\\", "/").split("/")[-1].lower()
                padres[(str(d.get("timestamp", ""))[:23], rid)] = p
    return padres


def leer_repeticiones(path):
    """ATA que tienen repetición (`rev1` es su ventana canónica). Sin fichero: ninguno."""
    if not path or not os.path.isfile(path):
        return set()
    return {r["ata_id"].strip() for r in _leer(path) if r.get("ata_id")}


def _casos(audited_dir, repeticiones=frozenset()):
    """`ATA -> filas` de la ventana CANÓNICA (`rev1` si hay repetición; si no, `iter1`)."""
    out = {}
    for f in sorted(glob.glob(os.path.join(audited_dir, "*_iter1-Audited.csv"))):
        ata = os.path.basename(f)[:6]
        if ata.startswith("EJEMPL"):
            continue
        win = M.ventana_canonica(ata, repeticiones)
        cand = os.path.join(audited_dir, f"{ata}_{win}-Audited.csv")
        if not os.path.isfile(cand):
            raise SystemExit(f"{ata}: falta la ventana canonica {cand}")
        out[ata] = _leer(cand)
    return out


def _descontada(fila, variante, doble_uso, padres, plataforma):
    rid = fila.get("rule_id", "")
    if variante in ("sin_doble_uso", "sin_entrega_ni_doble_uso") and rid in doble_uso:
        return True
    if variante in ("sin_entrega", "sin_entrega_ni_doble_uso") and plataforma == "windows" \
            and rid in REGLAS_ENTREGA_WIN and padres is not None:
        p = padres.get(((fila.get("timestamp_utc") or "")[:23], rid))
        if p in PADRES_ENTREGA_WIN:
            return True
    return False


def calcular(plataforma, audited_dir, t5_path, alertas_dir=None, repeticiones=frozenset()):
    casos = _casos(audited_dir, repeticiones)
    doble = reglas_doble_uso(t5_path)
    padres = mapa_padres(alertas_dir) if plataforma == "windows" else None
    filas = []
    for var in VARIANTES:
        sin_dato = (plataforma == "windows" and var in ("sin_entrega", "sin_entrega_ni_doble_uso") and padres is None)
        for n in UMBRALES:
            det = 0
            for ata, rows in casos.items():
                ok = False
                for r in rows:
                    if r.get("categoria") != "deteccion":
                        continue
                    try:
                        lv = int(r.get("rule_level", ""))
                    except ValueError:
                        continue
                    if lv < n or _descontada(r, var, doble, padres, plataforma):
                        continue
                    ok = True
                    break
                det += ok
            tot = len(casos)
            filas.append({"plataforma": plataforma, "variante": var, "umbral_N": n,
                          "casos_detectados": "ND" if sin_dato else det, "casos_total": tot,
                          "TPR": "ND" if sin_dato or not tot else round(det / tot, 6)})
    return filas, sorted(doble)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TPR comparado Linux/Windows con variantes iguales.")
    ap.add_argument("--linux-audited", default=DEF_LINUX_AUDITED)
    ap.add_argument("--windows-audited", default=DEF_WIN_AUDITED)
    ap.add_argument("--t5-linux", default=DEF_T5_LINUX)
    ap.add_argument("--t5-windows", default=DEF_T5_WIN)
    ap.add_argument("--alertas-windows", default=DEF_ALERTAS_WIN)
    ap.add_argument("--repeticiones", default=DEF_REPETICIONES)
    ap.add_argument("--out", default="Hojas/T2_sensibilidades_comparadas.csv")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    rep = leer_repeticiones(a.repeticiones)
    fl, du_l = calcular("linux", a.linux_audited, a.t5_linux, None, rep)
    fw, du_w = calcular("windows", a.windows_audited, a.t5_windows, a.alertas_windows, rep)
    cab = ("# T2_sensibilidades_comparadas.csv | TFG HIDS - TPR comparado Linux/Windows con variantes iguales | "
           f"doble_uso_linux={';'.join(du_l)} | doble_uso_windows={';'.join(du_w)} | ventana_canonica=rev1_si_repeticiones_else_iter1 | repeticiones=" + str(len(rep)) + " | T5-windows=provisional (legitimo = baseline de 8 h; recalcular con la ventana de 72 h) | "
           "sin_entrega(linux)=canonico (el envoltorio dash ya es ruido_conocido) | "
           "sin_entrega(windows)=92052 padre sshd.exe y 92032 padre cmd.exe (plan M-23)")
    TC.write_csv(a.out, HEADER, fl + fw, comment=cab)
    print("TPR a N>=3 (casos detectados / total):")
    for plat, fs in (("linux", fl), ("windows", fw)):
        print(f"  {plat}:", "  ".join(f"{f['variante']}={f['casos_detectados']}/{f['casos_total']}"
                                       for f in fs if f["umbral_N"] == 3))
    print("TPR a N>=7:")
    for plat, fs in (("linux", fl), ("windows", fw)):
        print(f"  {plat}:", "  ".join(f"{f['variante']}={f['casos_detectados']}/{f['casos_total']}"
                                       for f in fs if f["umbral_N"] == 7))
    return 0


if __name__ == "__main__":
    sys.exit(main())
