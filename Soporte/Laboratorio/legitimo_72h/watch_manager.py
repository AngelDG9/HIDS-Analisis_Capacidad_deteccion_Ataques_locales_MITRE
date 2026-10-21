#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_manager.py — señales de VIGILANCIA leídas del MANAGER (solo lectura).

Bloque `legitimo-fix`. Lo invoca `legitimo_host_control.ps1 -Phase watch` por SSH y devuelve
líneas `clave=valor`. **No toca la víctima y no cambia nada del manager**:

  2. `agent_control -i 001` -> `Status` y `Last keep alive` (epoch)  => edad del agente
  3. `systemctl is-active wazuh-manager` + nº de `wazuh-remoted|wazuh-analysisd`
  4. crecimiento de `archives.json` y del diario de alertas (vs. chequeo anterior; estado en /tmp)
  5. **disco de la víctima** a partir de las líneas `"location":"df -P"` del agente `001`
     en `archives.json` (H-H). Lectura **incremental por offset**; si el tamaño baja
     (rotación) se reinicia el offset. Se toma la línea cuyo punto de montaje es `/`.

Uso:  echo "<pw>" | ssh manager "python3 /tmp/watch_manager.py"
Contraseña de sudo por STDIN (nunca en fichero). Estado en `/tmp/tfg_watch_*.state`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

ARCH = "/var/ossec/logs/archives/archives.json"
STATE_DF = "/tmp/tfg_watch_df.state"
STATE_SZ = "/tmp/tfg_watch_sz.state"
AC = "/var/ossec/bin/agent_control"
AGENTE = "001"


def ts_utc(epoch=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch if epoch is not None else time.time()))


def sudo(cmd, pw):
    """Ejecuta con `sudo -S` (el ticket cacheado es intermitente en SSH sin TTY)."""
    try:
        r = subprocess.run(["sudo", "-S", "-p", ""] + cmd, input=pw + "\n",
                           capture_output=True, text=True, timeout=25)
        return r.stdout
    except Exception:
        return ""


def leer_json(path, defecto):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return defecto


def guardar_json(path, obj):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    except Exception:
        pass


def leer_agente(pw):
    out = sudo([AC, "-i", AGENTE], pw)
    est = re.search(r"Status:\s+(\S+)", out)
    ka = re.search(r"Last keep alive:\s+(\d+)", out)
    return (est.group(1) if est else "desconocido",
            int(ka.group(1)) if ka else 0)


def tam(path, pw):
    out = sudo(["stat", "-c", "%s", path], pw).strip()
    try:
        return int(out)
    except ValueError:
        return -1


def leer_df_incremental(pw):
    """Devuelve (muestras_nuevas, offset_nuevo, reiniciado)."""
    st = leer_json(STATE_DF, {"offset": 0, "muestras": []})
    off = int(st.get("offset", 0))
    size = tam(ARCH, pw)
    if size < 0:                       # no hay archives.json (logall_json off)
        return [], 0, False, []
    reinicio = False
    if size < off:                     # rotación: el fichero es otro
        off = 0
        reinicio = True
    if off == 0 and st.get("offset", 0) == 0 and not st.get("muestras"):
        # primera vez: no releer el pasado, empezar por el final
        off = size
    nuevas = []
    if size > off:
        try:
            with open(ARCH, "rb") as fh:
                fh.seek(off)
                datos = fh.read(size - off)
        except PermissionError:
            out = sudo(["tail", "-c", f"+{off + 1}", ARCH], pw)
            datos = out.encode("utf-8", "replace")
        corte = datos.rfind(b"\n")
        if corte >= 0:
            completo = datos[: corte + 1]
            off = off + len(completo)
            for linea in completo.decode("utf-8", "replace").splitlines():
                if '"df -P"' not in linea:
                    continue
                try:
                    rec = json.loads(linea)
                except Exception:
                    continue
                if str((rec.get("agent") or {}).get("id")) != AGENTE:
                    continue
                if rec.get("location") != "df -P":
                    continue
                fl = rec.get("full_log") or ""
                m = re.search(r"'df -P':\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(\S+)\s*$", fl)
                if not m or m.group(6) != "/":
                    continue
                nuevas.append({"ts": rec.get("timestamp"), "avail_kb": int(m.group(4)), "pct": int(m.group(5))})
    muestras = ([] if reinicio else (st.get("muestras") or [])) + nuevas
    guardar_json(STATE_DF, {"offset": off, "muestras": muestras[-4:]})
    return nuevas, off, reinicio, muestras[-4:]


def edad_muestras_min(muestras):
    if not muestras:
        return -1
    last = muestras[-1]["ts"]
    try:
        s = last.replace("Z", "+00:00")
        m = re.search(r"([+-]\d{2})(\d{2})$", s)
        if m:
            s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"
        from datetime import datetime
        dt = datetime.fromisoformat(s)
        return int((time.time() - dt.timestamp()) / 60)
    except Exception:
        return -1


def tasa_mb_h(muestras):
    if len(muestras) < 2:
        return None
    a, b = muestras[-2], muestras[-1]
    try:
        from datetime import datetime
        def p(x):
            s = x["ts"].replace("Z", "+00:00")
            m = re.search(r"([+-]\d{2})(\d{2})$", s)
            if m:
                s = s[: m.start()] + f"{m.group(1)}:{m.group(2)}"
            return datetime.fromisoformat(s).timestamp()
        dt = p(b) - p(a)
        if dt < 300:
            return None
        return (b["avail_kb"] - a["avail_kb"]) / 1024.0 / (dt / 3600.0)
    except Exception:
        return None


def main():
    pw = ""
    if not sys.stdin.isatty():
        try:
            pw = sys.stdin.readline().rstrip("\n")
        except Exception:
            pw = ""

    print(f"utc={ts_utc()}")

    # 3) daemons
    print(f"manager={subprocess.run(['systemctl', 'is-active', 'wazuh-manager'], capture_output=True, text=True).stdout.strip()}")
    try:
        n = subprocess.run(["pgrep", "-c", "-f", "wazuh-remoted|wazuh-analysisd"],
                           capture_output=True, text=True).stdout.strip()
    except Exception:
        n = "0"
    print(f"daemons={n or '0'}")

    # 2) agente
    est, ka = leer_agente(pw)
    print(f"agente_status={est}")
    print(f"agente_ka={ts_utc(ka) if ka else 'none'}")
    print(f"agente_ka_edad_s={int(time.time()) - ka if ka else -1}")

    # 4) crecimiento
    hoy = time.gmtime()
    alerts = f"/var/ossec/logs/alerts/{hoy.tm_year}/{time.strftime('%b', hoy)}/ossec-alerts-{hoy.tm_mday:02d}.json"
    a_arch = tam(ARCH, pw)
    a_alert = tam(alerts, pw)
    prev = leer_json(STATE_SZ, {})
    d_arch = (a_arch - prev.get("archives", a_arch)) if a_arch >= 0 and prev.get("archives", -1) >= 0 else -1
    d_alert = (a_alert - prev.get("alerts", a_alert)) if a_alert >= 0 and prev.get("alerts", -1) >= 0 else -1
    guardar_json(STATE_SZ, {"archives": a_arch, "alerts": a_alert, "ts": ts_utc()})
    print(f"archives_bytes={a_arch}")
    print(f"archives_delta={d_arch}")
    print(f"alerts_bytes={a_alert}")
    print(f"alerts_delta={d_alert}")

    # 5) disco de la víctima leído del agente
    nuevas, off, reinicio, muestras = leer_df_incremental(pw)
    if muestras:
        last = muestras[-1]
        print(f"df_ts={last['ts']}")
        print(f"df_avail_kb={last['avail_kb']}")
        print(f"df_pct={last['pct']}")
        print(f"df_nuevas={len(nuevas)}")
        print(f"df_offset={off}")
        print(f"df_reset={1 if reinicio else 0}")
        print(f"df_muestras_edad_min={edad_muestras_min(muestras)}")
        t = tasa_mb_h(muestras)
        print(f"df_tasa_mb_h={'none' if t is None else round(t, 1)}")
        print("df_fuente=agente")
    else:
        print("df_ts=none")
        print("df_avail_kb=-1")
        print("df_pct=-1")
        print("df_nuevas=0")
        print(f"df_offset={off}")
        print("df_reset=0")
        print("df_muestras_edad_min=-1")
        print("df_tasa_mb_h=none")
        print("df_fuente=ninguna")


if __name__ == "__main__":
    main()
