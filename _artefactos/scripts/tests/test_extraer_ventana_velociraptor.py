# -*- coding: utf-8 -*-
"""Pruebas de extraer_ventana_velociraptor.py (lectura zlib concatenado, ventana, anclas, determinismo)."""
import datetime as dt
import gzip
import json
import os
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import extraer_ventana_velociraptor as ev  # noqa: E402

UTC = dt.timezone.utc


def fila(ts, nombre="sched_process_exec", **datos):
    return json.dumps({"System": {"Timestamp": ts, "EventName": nombre}, "EventData": datos}).encode()


def test_leer_texto_y_zlib_concatenado(tmp_path):
    a, b = fila("2026-11-21T10:00:00Z", pathname="/usr/bin/dd"), fila("2026-11-21T10:00:01Z", pathname="/usr/bin/cp")
    p1, p2 = tmp_path / "t.json", tmp_path / "z.json"
    p1.write_bytes(a + b"\n" + b + b"\n")
    p2.write_bytes(zlib.compress(a + b"\n") + zlib.compress(b + b"\n"))      # DOS flujos: leer solo el primero daria 1
    assert len(ev.leer_filas(str(p1))) == 2
    assert len(ev.leer_filas(str(p2))) == 2


def test_hora_evento_variantes():
    assert ev.hora_evento({"System": {"Timestamp": "2026-11-21T13:24:59.020115075Z"}}) == dt.datetime(2026, 11, 21, 13, 24, 59, 20115, tzinfo=UTC)
    assert ev.hora_evento({"Time": "2026-11-21T13:00:00Z"}) == dt.datetime(2026, 11, 21, 13, 0, tzinfo=UTC)
    assert ev.hora_evento({"_ts": 1795267553}).year == 2026
    assert ev.hora_evento({"x": 1}) is None


def test_recortar_inclusivo_y_sin_hora():
    t0, t1 = dt.datetime(2026, 11, 21, 10, 0, 0, tzinfo=UTC), dt.datetime(2026, 11, 21, 10, 0, 10, tzinfo=UTC)
    filas = [(fila(x), json.loads(fila(x))) for x in ("2026-11-21T09:59:59Z", "2026-11-21T10:00:00Z", "2026-11-21T10:00:10Z", "2026-11-21T10:00:11Z")]
    filas.append((b'{"x":1}', {"x": 1}))
    dentro, sin_hora = ev.recortar(filas, t0, t1)
    assert len(dentro) == 2 and sin_hora == 1                 # los bordes cuentan; lo ilegible NO se descarta en silencio


def test_gz_determinista(tmp_path):
    l = [fila("2026-11-21T10:00:00Z"), fila("2026-11-21T10:00:01Z")]
    a, b = tmp_path / "a.gz", tmp_path / "b.gz"
    ev.escribir_gz(str(a), l)
    ev.escribir_gz(str(b), l)
    assert a.read_bytes() == b.read_bytes()
    assert gzip.open(str(a)).read().count(b"\n") == 2


def test_anclas_con_limite_de_palabra():
    lineas = [fila("2026-11-21T10:00:00Z", argv=["/bin/dd", "if=/x"], pathname="/usr/bin/dd", pwd="/home/angel/lab-attack/ATA002"),
              fila("2026-11-21T10:00:01Z", argv=["add"], pathname="/usr/bin/add", pwd="/tmp")]
    anclas = [("S1", "audit_exe", "dd"), ("S2", "audit_cwd", "/home/angel/lab-attack/ATA002/*")]
    g = ev.contar_anclas(lineas, anclas)
    assert g["S1"] == 1 and g["S2"] == 1                      # `dd` NO casa con `add`
    e = ev.contar_anclas_exec_ebpf(lineas, anclas)
    assert e == {"S1": 1, "S2": 1}


def test_anclas_exec_ebpf_solo_arranques_de_proceso():
    lineas = [fila("2026-11-21T10:00:00Z", nombre="security_file_open", pathname="/usr/bin/dd", pwd="/home/angel/lab-attack/ATA002"),
              fila("2026-11-21T10:00:01Z", argv=["cp", "a", "b"], pathname="/usr/bin/cp", pwd="/home/angel/lab-attack/ATA011")]
    anclas = [("S1", "audit_exe", "dd"), ("S2", "audit_exe", "cp"), ("S3", "audit_cwd", "/home/angel/lab-attack/ATA011/*")]
    assert ev.contar_anclas_exec_ebpf(lineas, anclas) == {"S1": 0, "S2": 1, "S3": 1}   # abrir `dd` como fichero no es ejecutarlo


def test_cargar_anclas_ignora_ambiguas(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text("# c\nsenal_id,tipo,campo,patron,dato_componente,tecnica,nota\nS1,deteccion,audit_exe,dd,x,T1,n\nA1,ambigua,rule_id,80790,x,T1,n\n", encoding="utf-8")
    assert ev.cargar_anclas(str(p)) == [("S1", "audit_exe", "dd")]


def test_dias_cruzando_medianoche():
    t0, t1 = dt.datetime(2026, 11, 21, 23, 59, tzinfo=UTC), dt.datetime(2026, 11, 22, 0, 2, tzinfo=UTC)
    assert ev.dias(t0, t1) == ["2026-11-21", "2026-11-22"]


# ------------------------------------------------------------------ lineas de auditd (audit.log subido tal cual)
def _evento_exec(ts, seq, exe, cwd, key="audit-wazuh-c", syscall=59):
    return [
        ('type=SYSCALL msg=audit(%s:%d): arch=c000003e syscall=%d success=yes exit=0 pid=10 uid=1000 comm="x" exe="%s" key="%s"' % (ts, seq, syscall, exe, key)).encode(),
        ('type=EXECVE msg=audit(%s:%d): argc=1 a0="x"' % (ts, seq)).encode(),
        ('type=CWD msg=audit(%s:%d): cwd="%s"' % (ts, seq, cwd)).encode(),
    ]


def test_hora_audit_y_recorte():
    assert ev.hora_audit(b'type=SYSCALL msg=audit(1795437996.329:654): arch=c000003e') == dt.datetime.fromtimestamp(1795437996.329, tz=UTC)
    assert ev.hora_audit(b"sin marca de auditd") is None
    lineas = _evento_exec("1000.500", 1, "/usr/bin/curl", "/a") + _evento_exec("2000.500", 2, "/usr/bin/curl", "/a") + _evento_exec("3000.500", 3, "/usr/bin/curl", "/a")
    t0, t1 = dt.datetime.fromtimestamp(1500, tz=UTC), dt.datetime.fromtimestamp(2500, tz=UTC)
    dentro, sin_hora = ev.recortar_audit(lineas + [b"basura sin hora"], t0, t1)
    assert len(dentro) == 3 and all(b"2000.500" in l for l in dentro) and sin_hora == 1         # el evento entero (3 lineas) o nada


def test_anclas_audit_solo_eventos_comando_y_por_evento():
    anclas = [("S1", "audit_exe", "curl"), ("S2", "audit_cwd", "/home/angel/lab-attack/ATA009/*"), ("S3", "audit_exe", "cu")]
    lineas = (_evento_exec("1.1", 1, "/usr/bin/curl", "/home/angel/lab-attack/ATA009")             # cuenta exe y cwd
              + _evento_exec("1.2", 2, "/usr/bin/curl", "/home/angel/lab-attack/ATA009/sub")      # cwd por prefijo
              + _evento_exec("1.3", 3, "/usr/bin/curl", "/tmp", key="audit-wazuh-w", syscall=87)  # NO es comando (clave w): no cuenta
              + _evento_exec("1.4", 4, "/usr/bin/curlish", "/tmp"))                               # basename distinto: no cuenta
    r = ev.contar_anclas_audit(lineas, anclas)
    assert r == {"S1": 2, "S2": 2, "S3": 0}                                                       # `cu` no casa con `curl` (basename exacto)


def test_anclas_audit_cwd_en_hexadecimal():
    # auditd codifica en hex los valores con espacios/caracteres raros (sin comillas)
    cwd_hex = "/home/angel/lab-attack/ATA 011".encode().hex().upper()
    l = [b'type=SYSCALL msg=audit(1.1:9): syscall=59 exe="/usr/bin/cp" key="audit-wazuh-c"', ("type=CWD msg=audit(1.1:9): cwd=%s" % cwd_hex).encode()]
    assert ev.contar_anclas_audit(l, [("S", "audit_cwd", "/home/angel/lab-attack/ATA 011/*")]) == {"S": 1}
