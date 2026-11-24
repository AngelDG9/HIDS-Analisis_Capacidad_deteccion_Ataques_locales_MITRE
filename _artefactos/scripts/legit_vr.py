#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""legit_vr.py - utilidades del HOST para la ventana de 72 h con Velociraptor (V1-L). Sustituye a `watch_manager.py` de Wazuh.

NUNCA entra en la victima (sin SSH): solo lee el servidor de Velociraptor y el datastore del PC.
Subcomandos (cada uno imprime lineas `clave=valor`, salvo indicacion):
  watch          senales para la vigilancia: servidor, edad del ultimo contacto del cliente, crecimiento de EBPF, disco de la victima
                 (coleccion de Generic.Client.DiskSpace = `df -h` en el cliente; equivalente al `df -P` del agente de Wazuh), tabla de monitorizacion
  tabla fijar    deja la tabla del servidor en la configuracion S (EBPF con todos los eventos + renombrado + mkdir) y guarda su huella
  tabla check    compara la huella actual con la guardada (D8 / V7)
  gate           puertas previas a t0: servidor, tabla, cliente conectado, filas de EBPF llegando
  seed           guarda el estado base de la vigilancia
Sin secretos. Solo biblioteca estandar + los scripts del repo.
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orquestar_velociraptor_linux as vr        # noqa: E402
import probar_ojos_velociraptor as po            # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BASE = os.path.join(REPO, "Soporte", "Laboratorio", "legitimo_72h_vr")
CONF = os.path.join(BASE, "legit_vr_config.json")
HUELLA = os.path.join(BASE, "recetas_vr", "tabla_cfgS.sha256")
ESTADO = os.path.join(os.environ.get("TEMP", "."), "opencode", "tfg_watch_ebpf_vr.json")   # distinto del estado del .ps1 (no se pisan)


def cfg():
    return json.load(open(CONF, encoding="utf-8"))


def fijar_cliente():
    c = cfg()["cliente"]
    vr.CLIENTE = c
    vr.MON = os.path.join(vr.SRV, "datastore", "clients", c, "monitoring")
    return c


def q(vql, t=120):
    rc, o, e = vr.vr_query(vql, timeout=t)
    return rc, o, e


def servidor_activo():
    try:
        with socket.create_connection(("192.168.65.1", 8000), timeout=5):
            return True
    except OSError:
        return False


def edad_contacto_s(c):
    rc, o, e = q("SELECT last_seen_at AS v FROM clients() WHERE client_id='%s'" % c, 60)
    try:
        v = json.loads(o)[0]["v"]
        return int(time.time() - v / 1e6)
    except (ValueError, IndexError, KeyError, TypeError):
        return -1


def bytes_ebpf(c):
    d = os.path.join(vr.SRV, "datastore", "clients", c, "monitoring", "Linux.Events.EBPF")
    return sum(os.path.getsize(f) for f in glob.glob(os.path.join(d, "*.json"))) if os.path.isdir(d) else 0


def tabla_json():
    rc, o, e = q("SELECT get_client_monitoring() AS t FROM scope()", 60)
    if rc != 0:
        raise RuntimeError("get_client_monitoring: %s" % e[-200:])
    return json.dumps(json.loads(o)[0]["t"], sort_keys=True, ensure_ascii=True)


def tabla_hash():
    return hashlib.sha256(tabla_json().encode()).hexdigest()


def a_kb(txt):
    """'4.4G' / '512M' / '900K' (df -h) -> KB"""
    m = re.fullmatch(r"([\d.,]+)([KMGT]?)i?", txt.strip().replace(",", "."))
    if not m:
        return -1
    f = {"": 1 / 1024, "K": 1, "M": 1024, "G": 1024 ** 2, "T": 1024 ** 3}[m.group(2)]
    return int(float(m.group(1)) * f)


def disco_kb(c, espera=90):
    """Lanza Generic.Client.DiskSpace en el cliente (solo lectura; ejecuta `df -h`) y devuelve el espacio libre de `/` en KB (o -1)."""
    rc, o, e = q("SELECT collect_client(client_id='%s', artifacts='Generic.Client.DiskSpace') AS f FROM scope()" % c, 60)
    m = re.search(r"F\.[A-Z0-9]+", o)
    if not m:
        return -1
    fid = m.group(0)
    t = time.time()
    while time.time() - t < espera:
        rc, o2, e2 = q("SELECT * FROM source(client_id='%s', flow_id='%s', artifact='Generic.Client.DiskSpace')" % (c, fid), 60)
        try:
            for r in json.loads(o2):
                if str(r.get("Mounted")).strip() == "/":
                    return a_kb(str(r.get("Avail")))
        except ValueError:
            pass
        time.sleep(5)
    return -1


def cmd_watch(a):
    c = fijar_cliente()
    prev = {}
    if os.path.isfile(ESTADO):
        try:
            prev = json.load(open(ESTADO, encoding="utf-8"))
        except ValueError:
            prev = {}
    ok = servidor_activo()
    eb = bytes_ebpf(c)
    edad = edad_contacto_s(c) if ok else -1
    # solo se pide el disco si el cliente esta conectado: una coleccion pendiente se ejecutaria al volver a arrancar la VM, a una hora imprevista
    kb = disco_kb(c) if (ok and 0 <= edad < 120) else -1
    try:
        th = tabla_hash() if ok else ""
    except RuntimeError:
        th = ""
    esperado = open(HUELLA, encoding="utf-8").read().strip() if os.path.isfile(HUELLA) else ""
    out = {"servidor": "active" if ok else "down", "daemons": 1 if ok else 0,
           "cliente_ka_edad_s": edad,
           "ebpf_bytes": eb, "ebpf_delta": (eb - int(prev.get("ebpf_bytes", eb))) if prev else -1,
           "df_avail_kb": kb, "tabla": "igual" if (th and th == esperado) else ("sin_huella" if not esperado else "DISTINTA")}
    for k, v in out.items():
        print("%s=%s" % (k, v))
    if not a.sin_estado:
        os.makedirs(os.path.dirname(ESTADO), exist_ok=True)
        json.dump({"ts": dt.datetime.utcnow().isoformat() + "Z", "ebpf_bytes": eb}, open(ESTADO, "w", encoding="utf-8"))


def cmd_tabla(a):
    fijar_cliente()
    if a.accion == "fijar":
        t = po.poner_tabla([po.OPCIONES["SUPER"]["tabla"][0]])
        h = tabla_hash()
        os.makedirs(os.path.dirname(HUELLA), exist_ok=True)
        open(HUELLA, "w", encoding="utf-8").write(h + "\n")
        print("tabla=%s\nhuella=%s" % (",".join(t), h))
    else:
        h, e = tabla_hash(), (open(HUELLA, encoding="utf-8").read().strip() if os.path.isfile(HUELLA) else "")
        print("huella_actual=%s\nhuella_guardada=%s\nRESULT=%s" % (h, e, "PASS" if h == e and e else "FAIL"))
        sys.exit(0 if h == e and e else 1)


def cmd_gate(a):
    c = fijar_cliente()
    fallos = []
    if not servidor_activo():
        fallos.append("servidor VR no escucha en 192.168.65.1:8000")
    e = edad_contacto_s(c)
    if not (0 <= e < 90):
        fallos.append("el cliente %s no esta conectado (edad del ultimo contacto %ss)" % (c, e))
    esperado = open(HUELLA, encoding="utf-8").read().strip() if os.path.isfile(HUELLA) else ""
    if not esperado or tabla_hash() != esperado:
        fallos.append("la tabla de monitorizacion no es la configuracion S fijada")
    b0 = bytes_ebpf(c)
    time.sleep(a.espera)
    b1 = bytes_ebpf(c)
    print("ebpf_bytes_antes=%d ebpf_bytes_despues=%d crecimiento=%d en %ds" % (b0, b1, b1 - b0, a.espera))
    if b1 <= b0:
        fallos.append("no llegan filas de EBPF (el fichero de hoy no crece)")
    kb = disco_kb(c)
    print("df_avail_kb=%d (~%.1f GB libres en la victima)" % (kb, kb / 1048576 if kb > 0 else -1))
    if kb < 0:
        fallos.append("la coleccion de DiskSpace no devuelve el espacio libre")
    print("RESULT=" + ("PASS" if not fallos else "FAIL"))
    for f in fallos:
        print(" -", f)
    sys.exit(0 if not fallos else 1)


def cmd_sellar_vm(a):
    """Lee por SSH (SOLO ANTES de t0) las huellas de la configuracion de la VM y las guarda en recetas_vr/vm_config.sha256 (V7)."""
    import shlex
    import orquestar_ataques_linux as olx
    cmd = "sha256sum /usr/local/bin/velociraptor /etc/velociraptor/client.config.yaml /etc/audit/auditd.conf /etc/audit/rules.d/tfg.rules"
    rc, o, e = olx.ssh(olx.IP_V, "sudo -S -p '' bash -c %s" % shlex.quote(cmd), inp=olx.PW + "\n", timeout=60)
    lin = [l for l in o.splitlines() if re.match(r"^[0-9a-f]{64}\s+/", l)]
    if rc != 0 or len(lin) != 4:
        print("FALLO: no se pudieron leer las 4 huellas (rc=%s)" % rc)
        sys.exit(1)
    os.makedirs(os.path.join(BASE, "recetas_vr"), exist_ok=True)
    open(os.path.join(BASE, "recetas_vr", "vm_config.sha256"), "w", encoding="utf-8", newline="\n").write("\n".join(lin) + "\n")
    print("\n".join(lin))


def cmd_seed(a):
    c = fijar_cliente()
    os.makedirs(os.path.dirname(ESTADO), exist_ok=True)
    json.dump({"ts": dt.datetime.utcnow().isoformat() + "Z", "ebpf_bytes": bytes_ebpf(c)}, open(ESTADO, "w", encoding="utf-8"))
    print("estado de la vigilancia sembrado: %s" % ESTADO)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    w = sp.add_parser("watch")
    w.add_argument("--sin-estado", action="store_true")
    t = sp.add_parser("tabla")
    t.add_argument("accion", choices=("fijar", "check"))
    g = sp.add_parser("gate")
    g.add_argument("--espera", type=int, default=60)
    sp.add_parser("seed")
    sp.add_parser("sellar-vm")
    a = ap.parse_args()
    {"watch": cmd_watch, "tabla": cmd_tabla, "gate": cmd_gate, "seed": cmd_seed, "sellar-vm": cmd_sellar_vm}[a.cmd](a)
