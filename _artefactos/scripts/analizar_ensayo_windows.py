#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analizar_ensayo_windows.py — informe MECÁNICO de un ensayo o ventana legítima Windows.

**Para qué sirve.** El ensayo WE0 (y la propia ventana de 72 h) deja dos carpetas de
evidencia: `crudo\\` (manager: `archives`, `alerts`, `manager\\ossec.log`…) y `cosecha\\`
(invitado: `.evtx`, `ossec.log` del agente, estado del operador…). Este script convierte
esa evidencia en **criterios con PASS/FAIL**, para decidir con datos y no a ojo. Nace de la
auditoría del 13-nov-2026, que dejó tres dudas sin medir:

* ¿hay **huecos nocturnos** en Windows? (el criterio V1 de Linux —hueco de alertas ≤ 30 min—
  pasó porque auditd genera ruido toda la noche; un Windows en reposo tuvo 36 min sin alertas);
* ¿cuánta **huella del operador** (keepalive, latido, SSH) hay y la pilla el etiquetador?;
* ¿**llegó todo** a `archives`? (cuenta de eventos por tipo en el `.evtx` del invitado frente a
  `archives` del manager, más las pruebas de pérdidas del agente y del manager).

## Criterios (umbrales por defecto; se pueden cambiar por parámetro)

| id | Qué mide | Pasa si |
|---|---|---|
| `A1` | `M` endpoint en [t0,t1) | > 0 |
| `A2` | hueco máximo entre EVENTOS de `archives` (endpoint) | ≤ 10 min |
| `A3` | hueco máximo entre ALERTAS | **informativo** (Linux: 62 s; criterio V1 = 30 min) |
| `A4` | latido (Sysmon 3 → :9095) | ≥ 98 % de los esperados y hueco ≤ 10 min |
| `A5` | operador visible | ≤ 5 % de las alertas **y** 0 alertas con rastro del operador sin etiquetar |
| `A6` | completitud `.evtx` ↔ `archives` | todo (log, EventID) no excluido dentro de tolerancia |
| `A7` | pérdidas del manager | 0 `events_dropped` y 0 avisos de cola/paquete descartado en la ventana |
| `A8` | pérdidas del agente | 0 avisos `buffer`/`flood`/`dropped` en el `ossec.log` del agente |
| `A9` | cosecha | `cosecha.done` y todos los ficheros verificados por hash |
| `A10` | reinicios/suspensiones en la ventana | 0 |
| `A11` | reloj invitado↔host | \\|delta\\| ≤ 2 s |

Un criterio sin datos sale `ND` (no disponible), nunca `PASS`: **no se aprueba en silencio**.
El informe también da la tabla por hora (eventos y alertas), que es donde se ve la noche.

## Uso

    python analizar_ensayo_windows.py --crudo D:\\TFG-VMs\\legitimo-windows-AAAA-MM-DD\\crudo \\
        --cosecha D:\\TFG-VMs\\legitimo-windows-AAAA-MM-DD\\cosecha \\
        --t0 2026-11-21T00:00:00Z --t1 2026-11-21T09:00:00Z [--out informe.md] [--json r.json]

Sale 0 si no hay ningún FAIL (los `ND`/`INFO` no fallan) y 1 si hay alguno.
Solo biblioteca estándar. Sin red, sin VMs, sin secretos.
"""

from __future__ import annotations

import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contar_denominador as cd  # noqa: E402
import etiquetar_operador_legit as EL  # noqa: E402
import extraer_alertas_windows as EA  # noqa: E402

#: IDs del canal Security que el agente Wazuh EXCLUYE por defecto (`<query>` de ossec.conf).
SECURITY_EXCLUIDOS_DEFECTO = frozenset({
    5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690, 4703, 4907, 5152, 5157})

CANAL = {  # nombre del log en el invitado -> `data.win.system.channel` en archives
    "Security": "Security",
    "Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell/Operational",
    "System": "System",
    "Application": "Application",
}

AVISOS_PERDIDA = re.compile(
    r"(queue is full|buffer is full|events may be lost|flood|package dropped|"
    r"could not append data into buffer|dropped|discarding)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def _ts(s: str) -> datetime:
    return cd.parse_ts(s)


def _epoch(dt: datetime) -> float:
    return dt.timestamp()


def _ficheros(carpeta: str, patrones):
    out = []
    for pat in patrones:
        out.extend(glob.glob(os.path.join(carpeta, pat)))
    return sorted(set(out))


def _leer_texto(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def _hueco_max_min(epochs):
    e = sorted(epochs)
    if len(e) < 2:
        return None
    return max(b - a for a, b in zip(e, e[1:])) / 60.0


def _fmt(x, nd=1):
    return "n/d" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


# --------------------------------------------------------------------------
# Lectura de `archives`
# --------------------------------------------------------------------------
def leer_archives(paths, t0: datetime, t1: datetime, agent_id: str):
    """Pasada única. Devuelve dict con epochs, conteo por (canal,eventID), latido y horas."""
    epochs = []
    por_evento = Counter()
    latido = []
    por_hora = Counter()
    for path in paths:
        for line in cd._open_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str((rec.get("agent") or {}).get("id", "")) != agent_id:
                continue
            try:
                ts = _ts(str(rec.get("timestamp", "")))
            except ValueError:
                continue
            if not (t0 <= ts < t1):
                continue
            ep = _epoch(ts)
            epochs.append(ep)
            por_hora[ts.strftime("%Y-%m-%dT%H")] += 1
            win = ((rec.get("data") or {}).get("win") or {})
            sysd = win.get("system") or {}
            ed = win.get("eventdata") or {}
            try:
                eid = int(sysd.get("eventID"))
            except (TypeError, ValueError):
                eid = None
            canal = str(sysd.get("channel") or "")
            if eid is not None:
                por_evento[(canal, eid)] += 1
                if canal.endswith("Sysmon/Operational") and eid == 3 and str(ed.get("destinationPort", "")) == "9095":
                    latido.append(ep)
    return {"epochs": epochs, "por_evento": por_evento, "latido": latido, "por_hora": por_hora}


# --------------------------------------------------------------------------
# Criterios
# --------------------------------------------------------------------------
def c_a1(arch):
    n = len(arch["epochs"])
    return ("A1", "PASS" if n > 0 else "FAIL", f"M endpoint={n}")


def c_a2(arch, max_min):
    h = _hueco_max_min(arch["epochs"])
    if h is None:
        return ("A2", "ND", "menos de 2 eventos")
    return ("A2", "PASS" if h <= max_min else "FAIL", f"hueco máx eventos={h:.1f} min (umbral {max_min})")


def c_a3(alertas):
    ep = [_epoch(_ts(r["timestamp_utc"])) for r in alertas]
    h = _hueco_max_min(ep)
    if h is None:
        return ("A3", "INFO", f"alertas={len(ep)}; hueco n/d")
    return ("A3", "INFO", f"alertas={len(ep)}; hueco máx alertas={h:.1f} min "
                          f"(V1 de Linux: ≤30 min; Linux midió 1,04 min)")


def c_a4(arch, t0, t1, intervalo_min=5.0, ratio_min=0.98, max_hueco=10.0):
    esperados = int((t1 - t0).total_seconds() // (intervalo_min * 60))
    n = len(arch["latido"])
    if esperados == 0:
        return ("A4", "ND", "ventana más corta que un intervalo")
    ratio = n / esperados
    h = _hueco_max_min(arch["latido"])
    ok = ratio >= ratio_min and (h is None or h <= max_hueco)
    return ("A4", "PASS" if ok else "FAIL",
            f"latidos={n}/{esperados} ({ratio * 100:.1f} %); hueco máx={_fmt(h)} min")


def c_a5(alertas_etiquetadas, max_pct=5.0):
    n = len(alertas_etiquetadas)
    if n == 0:
        return ("A5", "ND", "sin alertas")
    op = sum(1 for r in alertas_etiquetadas if r.get("operador_legit") == "1")
    pct = 100.0 * op / n
    restos = 0
    ejemplos = Counter()
    for r in alertas_etiquetadas:
        if r.get("operador_legit") == "1":
            continue
        txt = " ".join(str(v) for v in r.values()).lower()
        if any(w in txt for w in ("sshd", "keepalive", "tfg-winlegit", "vmtoolsd", "9095")):
            restos += 1
            ejemplos[(r.get("rule_id"), (r.get("win_command_line") or r.get("win_image") or "")[:60])] += 1
    ok = pct <= max_pct and restos == 0
    det = f"operador={op}/{n} ({pct:.2f} %, umbral {max_pct} %); sin etiquetar con rastro={restos}"
    if ejemplos:
        det += " p.ej. " + "; ".join(f"{k}×{v}" for k, v in ejemplos.most_common(3))
    motivos = Counter(r.get("motivo_operador") for r in alertas_etiquetadas if r.get("operador_legit") == "1")
    if motivos:
        det += " | motivos: " + ", ".join(f"{k}={v}" for k, v in motivos.most_common())
    return ("A5", "PASS" if ok else "FAIL", det)


def _excluidos_desde_conf(cosecha: str):
    txt = _leer_texto(os.path.join(cosecha, "invitado", "agente", "ossec.conf")) if cosecha else ""
    if not txt:
        return SECURITY_EXCLUIDOS_DEFECTO, "defecto de Wazuh"
    m = re.search(r"<location>Security</location>.*?<query>(.*?)</query>", txt, re.S)
    if not m:
        return frozenset(), "ossec.conf sin <query> en Security (no se excluye nada)"
    ids = frozenset(int(x) for x in re.findall(r"EventID\s*!=\s*(\d+)", m.group(1)))
    return ids, "ossec.conf del agente"


def c_a6(arch, cosecha, tol_min=3, tol_pct=1.0):
    csvp = os.path.join(cosecha, "invitado", "evtx", "conteo_por_evento.csv") if cosecha else ""
    if not csvp or not os.path.isfile(csvp):
        return ("A6", "ND", "sin conteo_por_evento.csv (cosecha ausente)"), []
    excl, fuente = _excluidos_desde_conf(cosecha)
    mal, total_evtx, total_arch = [], 0, 0
    filas = []
    with open(csvp, encoding="ascii", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            log, eid, cnt = r["log"], int(r["eventid"]), int(r["count"])
            canal = CANAL.get(log, log)
            if canal == "Security" and eid in excl:
                continue
            a = arch["por_evento"].get((canal, eid), 0)
            tol = max(tol_min, int(cnt * tol_pct / 100.0))
            total_evtx += cnt
            total_arch += a
            filas.append((canal, eid, cnt, a))
            if abs(cnt - a) > tol:
                mal.append((canal, eid, cnt, a))
    mal.sort(key=lambda x: -abs(x[2] - x[3]))
    det = (f"tipos comparados={len(filas)}; evtx={total_evtx} archives={total_arch}; "
           f"fuera de tolerancia={len(mal)} (excluidos de Security: {fuente})")
    if mal:
        det += " p.ej. " + "; ".join(f"{c.split('/')[0][-12:]}:{e} evtx={x} arch={y}" for c, e, x, y in mal[:4])
    return ("A6", "PASS" if not mal else "FAIL", det), filas


def c_a7(crudo, t0, t1):
    d = os.path.join(crudo, "manager") if crudo else ""
    if not d or not os.path.isdir(d):
        return ("A7", "ND", "sin crudo\\manager (ossec.log/estados del manager)")
    avisos = []
    for f in _ficheros(d, ["ossec.log", "ossec-*.log.gz"]):
        for ln in _leer_texto(f).splitlines():
            m = re.match(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})", ln)
            if not m or not AVISOS_PERDIDA.search(ln):
                continue
            # el ossec.log del manager va en hora LOCAL del manager (CET): se compara con holgura
            ts = datetime(*map(int, m.groups()), tzinfo=timezone.utc)
            if t0.timestamp() - 7200 <= ts.timestamp() < t1.timestamp() + 7200:
                avisos.append(ln.strip()[:140])
    dropped = None
    for nom in ("wazuh-analysisd.state", "wazuh-remoted.state"):
        txt = _leer_texto(os.path.join(d, nom))
        for m in re.finditer(r"events_dropped='(\d+)'", txt):
            dropped = (dropped or 0) + int(m.group(1))
    ok = (dropped in (0, None)) and not avisos
    if dropped is None and not avisos:
        return ("A7", "ND", "sin contadores events_dropped (estados ausentes); 0 avisos en ossec.log")
    return ("A7", "PASS" if ok else "FAIL",
            f"events_dropped={_fmt(dropped)}; avisos de pérdida en ventana={len(avisos)}"
            + (f" p.ej. {avisos[0]}" if avisos else ""))


def _offset_invitado(cosecha):
    """Desfase UTC del invitado (de `guest_local=...+01:00` en `reloj.txt`); 0 si no consta."""
    txt = _leer_texto(os.path.join(cosecha, "invitado", "reloj.txt")) if cosecha else ""
    m = re.search(r"guest_local=\S*?([+-])(\d{2}):(\d{2})\s*$", txt, re.M)
    if not m:
        return timedelta(0)
    d = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return d if m.group(1) == "+" else -d


def c_a8(cosecha, t0=None, t1=None):
    """Pérdidas del agente DENTRO de la ventana. El `ossec.log` del invitado arrastra el historial
    de la imagen (reconexiones de días anteriores): solo cuentan las líneas con hora en [t0,t1]
    (la hora del log es LOCAL del invitado; se pasa a UTC con el desfase de `reloj.txt`)."""
    p = os.path.join(cosecha, "invitado", "agente", "ossec.log") if cosecha else ""
    if not p or not os.path.isfile(p):
        return ("A8", "ND", "sin agente\\ossec.log")
    off = _offset_invitado(cosecha)
    perd, desc, fuera = [], 0, 0
    for ln in _leer_texto(p).splitlines():
        m = re.match(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})", ln)
        if not m:
            continue
        ts = datetime(*map(int, m.groups()), tzinfo=timezone.utc) - off
        if t0 is not None and not (t0 <= ts <= t1):
            fuera += 1
            continue
        if AVISOS_PERDIDA.search(ln) and "Lost connection" not in ln:
            perd.append(ln.strip()[:140])
        if re.search(r"Lost connection|Unable to connect", ln):
            desc += 1
    return ("A8", "PASS" if not perd else "FAIL",
            f"avisos buffer/flood/dropped={len(perd)}; reconexiones en la ventana={desc} "
            f"(líneas del log fuera de la ventana, ignoradas: {fuera})"
            + (f" p.ej. {perd[0]}" if perd else ""))


def c_a9(cosecha):
    p = os.path.join(cosecha, "cosecha.done") if cosecha else ""
    if not p or not os.path.isfile(p):
        return ("A9", "ND", "sin cosecha.done")
    kv = dict(l.split("=", 1) for l in _leer_texto(p).splitlines() if "=" in l)
    ok = kv.get("ficheros_invitado") == kv.get("ficheros_verificados") and int(kv.get("evtx", "0") or 0) >= 1
    return ("A9", "PASS" if ok else "FAIL",
            f"ficheros={kv.get('ficheros_invitado')} verificados={kv.get('ficheros_verificados')} "
            f"evtx={kv.get('evtx')} avisos={kv.get('avisos_invitado')}"), kv


def c_a10(cosecha):
    p = os.path.join(cosecha, "invitado", "sistema", "reinicios.txt") if cosecha else ""
    if not p or not os.path.isfile(p):
        return ("A10", "ND", "sin sistema\\reinicios.txt")
    m = re.search(r"reinicios_o_suspensiones=(\d+)", _leer_texto(p))
    if not m:
        return ("A10", "ND", "reinicios.txt sin contador")
    n = int(m.group(1))
    return ("A10", "PASS" if n == 0 else "FAIL", f"reinicios/suspensiones desde t0={n}")


def c_a11(kv):
    if not kv or "delta_reloj_s" not in kv:
        return ("A11", "ND", "sin delta_reloj_s")
    try:
        d = float(kv["delta_reloj_s"])
    except ValueError:
        return ("A11", "ND", f"delta_reloj_s={kv['delta_reloj_s']}")
    return ("A11", "PASS" if abs(d) <= 2.0 else "FAIL", f"delta reloj={d:+.2f} s (umbral 2 s)")


# --------------------------------------------------------------------------
# Orquestación
# --------------------------------------------------------------------------
def analizar(crudo, cosecha, t0, t1, agent_id="002", agent_name="victima-windows",
             max_hueco_eventos=10.0, max_pct_operador=5.0):
    arch_paths = _ficheros(os.path.join(crudo, "archives"), ["archives.json", "ossec-archive-*.json.gz"])
    alerts_paths = _ficheros(os.path.join(crudo, "alerts"), ["alerts.json", "ossec-alerts-*.json.gz", "ossec-alert-*.json.gz"])
    arch = leer_archives(arch_paths, t0, t1, agent_id)
    filas, _agr, _meta = EA.extraer(alerts_paths, t0, t1, agent_id=agent_id, agent_name=agent_name)
    detalle = [dict(zip(EA.DETAIL_HEADER, f)) for f in filas]      # `extraer` devuelve listas
    etiquetadas, _res = EL.etiquetar(detalle)
    resultados = [c_a1(arch), c_a2(arch, max_hueco_eventos), c_a3(detalle), c_a4(arch, t0, t1),
                  c_a5(etiquetadas, max_pct_operador)]
    a6, filas6 = c_a6(arch, cosecha)
    resultados.append(a6)
    resultados.append(c_a7(crudo, t0, t1))
    resultados.append(c_a8(cosecha, t0, t1))
    a9 = c_a9(cosecha)
    kv = {}
    if len(a9) == 2 and isinstance(a9[1], dict):
        kv = a9[1]
        a9 = a9[0]
    resultados.append(a9)
    resultados.append(c_a10(cosecha))
    resultados.append(c_a11(kv))
    # tabla por hora (donde se ve la noche)
    ah = Counter()
    for r in detalle:
        ah[_ts(r["timestamp_utc"]).strftime("%Y-%m-%dT%H")] += 1
    horas = sorted(set(arch["por_hora"]) | set(ah))
    return {"resultados": resultados, "horas": [(h, arch["por_hora"].get(h, 0), ah.get(h, 0)) for h in horas],
            "n_archives": len(arch["epochs"]), "n_alertas": len(detalle), "filas_evtx": filas6}


def informe(res, t0, t1) -> str:
    L = [f"# Informe del ensayo Windows — {t0:%Y-%m-%dT%H:%M:%SZ} → {t1:%Y-%m-%dT%H:%M:%SZ}", "",
         f"`M` endpoint = **{res['n_archives']}** · alertas = **{res['n_alertas']}**", "",
         "| id | estado | detalle |", "|---|---|---|"]
    for i, est, det in res["resultados"]:
        L.append(f"| {i} | **{est}** | {det} |")
    L += ["", "## Por hora (UTC)", "", "| hora | eventos (M) | alertas |", "|---|---:|---:|"]
    for h, e, a in res["horas"]:
        L.append(f"| {h}:00 | {e} | {a} |")
    fallos = [i for i, est, _ in res["resultados"] if est == "FAIL"]
    nd = [i for i, est, _ in res["resultados"] if est == "ND"]
    L += ["", f"**RESULT={'FAIL' if fallos else 'PASS'}** · fallos={fallos or '—'} · sin datos={nd or '—'}"]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Informe mecánico de un ensayo/ventana Windows.")
    ap.add_argument("--crudo", required=True)
    ap.add_argument("--cosecha", default="")
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--agent-id", default="002")
    ap.add_argument("--agent-name", default="victima-windows")
    ap.add_argument("--max-hueco-eventos-min", type=float, default=10.0)
    ap.add_argument("--max-pct-operador", type=float, default=5.0)
    ap.add_argument("--out", default="")
    ap.add_argument("--json", default="")
    a = ap.parse_args(argv)
    try:                                   # la consola de Windows (cp1252) no sabe pintar → ≥ ≤ ×
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    t0, t1 = _ts(a.t0), _ts(a.t1)
    res = analizar(a.crudo, a.cosecha, t0, t1, a.agent_id, a.agent_name,
                   a.max_hueco_eventos_min, a.max_pct_operador)
    txt = informe(res, t0, t1)
    sys.stdout.write(txt)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(txt)
    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"resultados": res["resultados"], "horas": res["horas"]}, fh, ensure_ascii=False, indent=1)
    return 1 if any(est == "FAIL" for _, est, _ in res["resultados"]) else 0


if __name__ == "__main__":
    sys.exit(main())
