#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar_validez_ventana_vr.py - criterios V1..V9 de validez de la ventana de 72 h con Velociraptor (V1-L, plan §5). SOLO LEE; codigo propio.
Adaptado de `verificar_validez_ventana.py` (Wazuh, que no se modifica). Entradas: la carpeta de la cosecha (`cosecha_vr.py`), los productos de
`exportar_denominador_vr.py`, el log de vigilancia VR y los sellos. Escribe un informe Markdown con PASS/FAIL/NA por criterio y un veredicto.
Veredicto (mismas reglas que Wazuh): VALIDA | VALIDA CON INCIDENCIA (solo V3/V9 con incidencias declaradas) | INVALIDA (cualquier otra FAIL).
Uso: python verificar_validez_ventana_vr.py --cosecha DIR --copia2 DIR2 --t0 ... --t1 ... --informe SALIDA.md [--vig LOG]
"""
import argparse
import collections
import csv
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exportar_denominador_vr as den            # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BASE = os.path.join(REPO, "Soporte", "Laboratorio", "legitimo_72h_vr")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def hms(s):
    h, m, *x = [int(v) for v in s.split(":")]
    return h * 3600 + m * 60 + (x[0] if x else 0)


def bloques():
    """B1..B6 de recetas_vr/bloques.env: [(id, ini_s, fin_s, tipo)]."""
    out = []
    for l in open(os.path.join(BASE, "recetas_vr", "bloques.env"), encoding="utf-8"):
        m = re.match(r"^(B\d|P\d)=(\d\d:\d\d)-(\d\d:\d\d) (\w+)", l.strip())
        if m:
            out.append((m.group(1), hms(m.group(2)), hms(m.group(3)), m.group(4)))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cosecha", required=True)
    ap.add_argument("--copia2", default="")
    ap.add_argument("--t0", required=True)
    ap.add_argument("--t1", required=True)
    ap.add_argument("--informe", required=True)
    ap.add_argument("--vig", default=os.path.join(BASE, "vigilancia_legitimo_vr.log"))
    ap.add_argument("--tolerancia-bloque-s", type=int, default=150)
    a = ap.parse_args()
    t0, t1 = den.iso(a.t0), den.iso(a.t1)
    ini, fin = den.epoch(t0), den.epoch(t1)
    res = collections.OrderedDict()      # criterio -> (estado, detalle)

    # ---------------------------------------------------------------- V1 cobertura (EBPF y auditd)
    minutos, primero, ultimo, n = set(), None, None, 0
    for l in den.lineas_ebpf(a.cosecha):
        m = den.RX_TS.search(l)
        if not m:
            continue
        e = den.epoch(dt.datetime.strptime(m.group(1).decode(), "%Y-%m-%dT%H:%M:%S"))
        if ini - 600 <= e <= fin + 600:
            minutos.add(int(e // 60))
        if ini <= e <= fin:
            n += 1
            primero = e if primero is None or e < primero else primero
            ultimo = e if ultimo is None or e > ultimo else ultimo
    ms = sorted(minutos)
    hueco_eb = max([(b - a_) for a_, b in zip(ms, ms[1:])] + [0])
    ev_vr, _ = den.eventos_audit(den.bytes_audit_vr(a.cosecha), t0, t1)
    ts_au = sorted(float(t) for t, _ in ev_vr)
    hueco_au = max([(b - a_) / 60 for a_, b in zip(ts_au, ts_au[1:])] + [0])
    ok1 = bool(n) and primero <= ini + 600 and ultimo >= fin - 600 and hueco_eb <= 30 and bool(ts_au) and ts_au[0] <= ini + 600 and ts_au[-1] >= fin - 600 and hueco_au <= 30
    res["V1 Cobertura"] = ("PASS" if ok1 else "FAIL", "EBPF: %d filas, primera t0+%.0fs, ultima t1-%.0fs, hueco max %d min | auditd: %d eventos, hueco max %.1f min" % (
        n, (primero or 0) - ini, fin - (ultimo or 0), hueco_eb, len(ev_vr), hueco_au))

    # ---------------------------------------------------------------- V2 actividad (ledger por accion)
    led = os.path.join(a.cosecha, "acciones", "ghosts_acciones_por_accion.csv")
    bl = bloques()
    por_dia, fuera, tot = collections.Counter(), [], 0
    if os.path.isfile(led):
        rd = csv.DictReader(open(led, encoding="utf-8", errors="replace"))
        for r in rd:
            c = r.get("createdutc") or r.get("createdUtc") or ""
            try:
                d = dt.datetime.fromisoformat(c.replace("Z", "")[:26])
            except ValueError:
                continue
            if not (t0 <= d <= t1):
                continue
            tot += 1
            por_dia[d.strftime("%Y-%m-%d")] += 1
            s = d.hour * 3600 + d.minute * 60 + d.second
            if not any(i - 0 <= s <= f + a.tolerancia_bloque_s for _, i, f, tipo in bl if tipo in ("trabajo", "campana")):
                fuera.append(c)
    esperado = {}
    try:
        cal = json.load(open(os.path.join(BASE, "recetas_vr", "calendario.json"), encoding="utf-8"))
        rec = {1: 163, 2: 178, 3: 163}
        esperado = {f: rec[k] for f, k in cal["mapa_dias"].items()}
    except (OSError, KeyError, ValueError):
        pass
    cumplim = {d: round(100.0 * por_dia.get(d, 0) / v, 1) for d, v in esperado.items() if t0.strftime("%Y-%m-%d") <= d <= t1.strftime("%Y-%m-%d")}
    ok2 = bool(tot) and not fuera and all(v >= 90 for v in cumplim.values())
    res["V2 Actividad"] = ("PASS" if ok2 else "FAIL", "acciones=%d por dia=%s cumplimiento%%=%s fuera_de_bloque=%d %s" % (tot, dict(por_dia), cumplim, len(fuera), fuera[:3]))

    # ---------------------------------------------------------------- V3 servidor y cliente (log de vigilancia)
    # el watch escribe cada chequeo en el log de vigilancia Y en el de control: se leen los dos y se quitan duplicados (robusto si uno no se pudo escribir)
    fuentes = [a.vig, os.path.join(BASE, "legitimo_host_control_vr.log")]
    lin = sorted({l for f in fuentes if os.path.isfile(f) for l in open(f, encoding="utf-8-sig", errors="replace")})
    ts = []
    alarmas = servidor_caido = 0
    for l in lin:
        m = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\] \[watch\] estado=(\w+)", l)
        if not m:
            continue
        d = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ")
        if t0 <= d <= t1:
            ts.append(d)
            alarmas += 1 if m.group(2) == "ALARMA" else 0
            servidor_caido += 0 if "srv=active" in l else 1
    huecos = [(b - a_).total_seconds() / 60 for a_, b in zip(ts, ts[1:])]
    res["V3 Servidor y cliente"] = ("PASS" if (ts and alarmas == 0 and servidor_caido == 0 and max(huecos + [0]) <= 31) else "INCIDENCIA",
                                    "chequeos=%d alarmas=%d servidor_caido=%d hueco_max=%.1f min" % (len(ts), alarmas, servidor_caido, max(huecos + [0])))

    # ---------------------------------------------------------------- V4 0 contaminacion (sesiones del operador en auditd)
    sesiones = []
    blobs = den.bytes_audit_vr(a.cosecha)
    for nombre, b in blobs.items():
        for l in b.splitlines():
            if not (l.startswith(b"type=USER_LOGIN") or l.startswith(b"type=USER_START")):
                continue
            m = den.RX_AUD.search(l)
            if not m or not (ini <= float(m.group(1)) <= fin):
                continue
            tx = l.decode("utf-8", "replace")
            ex = re.search(r' exe="([^"]*)"', tx)
            base = os.path.basename(ex.group(1)) if ex else ""
            if base in ("sshd", "login", "gdm-session-wor", "su", "sudo"):
                sesiones.append("%s %s" % (m.group(1), tx[:140]))
    res["V4 0 contaminacion"] = ("PASS" if not sesiones else "FAIL", "sesiones del operador en [t0,t1]: %d %s" % (len(sesiones), sesiones[:2]))

    # ---------------------------------------------------------------- V5 aislamiento
    ruta = os.path.join(a.cosecha, "evidencia", "ip_route.txt")
    tx = open(ruta, encoding="utf-8", errors="replace").read() if os.path.isfile(ruta) else ""
    rutas = tx.split("---")[0]                      # solo `ip route` (la salida de `ip addr` lleva la palabra «default» en «group default qlen»)
    hay_default = any(l.strip().startswith("default") for l in rutas.splitlines())
    res["V5 Aislamiento"] = ("PASS" if (rutas.strip() and not hay_default) else "FAIL", "`ip route` sin ruta `default`: %s (%d rutas)" % ("si" if (rutas.strip() and not hay_default) else "NO/ausente", len([l for l in rutas.splitlines() if l.strip()])))

    # ---------------------------------------------------------------- V6 crudo completo (manifest + copia2)
    man = os.path.join(a.cosecha, "MANIFEST.tsv")
    mal, n_ok = [], 0
    if os.path.isfile(man):
        for l in open(man, encoding="utf-8").read().splitlines()[1:]:
            f, _, h = l.split("\t")
            p = os.path.join(a.cosecha, f)
            if not os.path.isfile(p) or sha(p) != h:
                mal.append(f)
            else:
                n_ok += 1
    cop = ""
    if a.copia2 and os.path.isfile(os.path.join(a.copia2, "MANIFEST.tsv")):
        cop = "copia2 MANIFEST %s" % ("== igual" if open(man, "rb").read() == open(os.path.join(a.copia2, "MANIFEST.tsv"), "rb").read() else "DISTINTO")
    ok6 = os.path.isfile(man) and not mal and os.path.isfile(os.path.join(a.cosecha, "cosecha.done")) and (not a.copia2 or "igual" in cop)
    res["V6 Crudo completo"] = ("PASS" if ok6 else "FAIL", "ficheros con sha256 OK=%d mal=%d cosecha.done=%s %s" % (n_ok, len(mal), os.path.isfile(os.path.join(a.cosecha, "cosecha.done")), cop))

    # ---------------------------------------------------------------- V7 sin cambios a mitad
    est = os.path.join(a.cosecha, "evidencia", "estado_vr_y_auditd.txt")
    esp = os.path.join(BASE, "recetas_vr", "vm_config.sha256")
    dif = []
    if os.path.isfile(est) and os.path.isfile(esp):
        ahora = dict(l.split()[:2] for l in open(est, encoding="utf-8", errors="replace") if re.match(r"^[0-9a-f]{64}\s+/", l))
        antes = dict(l.split()[:2] for l in open(esp, encoding="utf-8") if re.match(r"^[0-9a-f]{64}\s+/", l))
        dif = [f for f, h in antes.items() if ahora.get(f) != h]
        v7 = "sha256 de VM (cliente, config, auditd.conf, reglas) iguales: %s %s" % (not dif, dif)
        ok7 = not dif and bool(antes)
    else:
        v7, ok7 = "faltan evidencia/estado_vr_y_auditd.txt o recetas_vr/vm_config.sha256", False
    th = ""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import legit_vr
        legit_vr.fijar_cliente()
        h_act, h_esp = legit_vr.tabla_hash(), open(legit_vr.HUELLA, encoding="utf-8").read().strip()
        th = " | tabla cfg S %s" % ("igual" if h_act == h_esp else "DISTINTA")
        ok7 = ok7 and h_act == h_esp
    except Exception as ex:                                       # noqa: BLE001
        th = " | tabla no comprobable (%s)" % str(ex)[:60]
        ok7 = False
    sums = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sellar_vr.py"), "check"], capture_output=True)
    sl = sums.stdout.decode("utf-8", "replace").strip().splitlines()
    ok7 = ok7 and sums.returncode == 0
    th += " | sha256sums_vr: %s" % (sl[-1] if sl else "sin salida")
    res["V7 Sin cambios"] = ("PASS" if ok7 else "FAIL", v7 + th)

    # ---------------------------------------------------------------- V8 host estable
    ps = ("$b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('s'); "
          "$e=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=41,42,107;StartTime=[datetime]'%s'} -ErrorAction SilentlyContinue).Count; \"$b|$e\"" % a.t0.rstrip("Z"))
    try:
        o = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=120).stdout.decode("utf-8", "replace").strip()
        boot, ke = o.split("|")
        ok8 = dt.datetime.strptime(boot, "%Y-%m-%dT%H:%M:%S") < t0 and int(ke) == 0
        res["V8 Host estable"] = ("PASS" if ok8 else "FAIL", "ultimo arranque del PC %sZ (< t0: %s); eventos Kernel-Power 41/42/107 desde t0: %s" % (boot, boot < a.t0.rstrip("Z"), ke))
    except Exception as ex:                                       # noqa: BLE001
        res["V8 Host estable"] = ("NA", "no comprobable: %s" % str(ex)[:80])

    # ---------------------------------------------------------------- V9 recuperaciones y rotaciones
    rp = glob.glob(os.path.join(a.cosecha, "evidencia", "guest_user", "home", "angel", "ghosts-client", "recovery.log"))
    rec_lin = open(rp[0], encoding="utf-8", errors="replace").read().splitlines() if rp else []
    tipos = collections.Counter(re.sub(r"^.*?\b(rotacion|arranque|recuperacion|alarma_disco|alarma_ram)\b.*$", r"\1", l) for l in rec_lin if re.search(r"\b(rotacion|arranque|recuperacion|alarma_disco|alarma_ram)\b", l))
    graves = {k: v for k, v in tipos.items() if k.startswith("alarma") or k == "recuperacion"}
    res["V9 Recuperaciones"] = ("PASS" if not graves else "INCIDENCIA", "recovery.log: %d lineas %s" % (len(rec_lin), dict(tipos)))

    fallos = [k for k, (e, _) in res.items() if e == "FAIL"]
    inc = [k for k, (e, _) in res.items() if e == "INCIDENCIA"]
    veredicto = "INVALIDA (revisar: %s)" % ", ".join(fallos) if fallos else ("VALIDA CON INCIDENCIA (%s)" % ", ".join(inc) if inc else "VALIDA")
    out = ["# Veredicto de validez de la ventana V1-L (Velociraptor)", "", "Ventana: %s -> %s. Generado por `verificar_validez_ventana_vr.py`." % (a.t0, a.t1), "",
           "**Veredicto: %s**" % veredicto, "", "| Criterio | Estado | Detalle |", "|---|---|---|"]
    out += ["| %s | %s | %s |" % (k, e, d.replace("|", "/")) for k, (e, d) in res.items()]
    open(a.informe, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print("\n".join(out))
    sys.exit(0 if not fallos else 1)


if __name__ == "__main__":
    main()
