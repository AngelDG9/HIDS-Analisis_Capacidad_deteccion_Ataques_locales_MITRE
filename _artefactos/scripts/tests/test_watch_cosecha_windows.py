# -*- coding: utf-8 -*-
"""Tests de las piezas añadidas por la auditoría del plan `windows-legit` (2026-11-13).

Qué se prueba (y por qué existe cada prueba):

- **R-01** `watch_loop.ps1`: ejecuta los chequeos, deja `ALARMA_*.txt`, registra los ticks
  saltados, exige `TFG_MANAGER_PW`, y un 2.º bucle sale sin hacer nada (mutex).
- **R-02** `cosecha_invitado.ps1`: copia a un stage, calcula `sha256` correctos
  (`MANIFEST_INVITADO.tsv`) y termina con `COSECHA_INVITADO_OK` aunque falten ficheros.
- **Controlador**: `prep` revierte al snapshot **v2** (no al v1, que su propio gate de
  manifiesto rechazaba: exit 46), existe la fase `cosecha`, `cleanup` y `stop` están
  bloqueados sin `cosecha.done` (exit 87 / 70), `prep` amplía los logs de eventos (exit 49)
  y `G-W12` exige la pausa de Windows Update del host.
- Los tres `.ps1` **compilan** (parser de PowerShell): evita errores como `$n:` (se lee
  como unidad) o `$T0`/`$t0` (misma variable), que ya aparecieron al escribirlos.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

RAIZ = Path(__file__).resolve().parents[3]
WIN = RAIZ / "Soporte" / "Laboratorio" / "windows"
CONTROL = WIN / "windows_legit_host_control.ps1"
WATCH = WIN / "legit" / "watch_loop.ps1"
COSECHA = WIN / "legit" / "cosecha_invitado.ps1"

PS = shutil.which("powershell")
SOLO_PS = pytest.mark.skipif(not PS or os.name != "nt", reason="requiere Windows PowerShell")


def _ps(args, **kw):
    return subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", *args],
                          capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ahora():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Estático: el controlador
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ctl():
    return CONTROL.read_text(encoding="utf-8")


def test_prep_revierte_al_snapshot_v2_no_al_v1(ctl):
    assert re.search(r"^\$Snap\s*=\s*'lab-listo-windows-legit-v2'", ctl, re.M), \
        "prep debe revertir a lab-listo-windows-legit-v2 (el v1 tiene 304 ficheros y falla el manifiesto)"
    assert not re.search(r"^\$Snap\s*=\s*'lab-listo-windows-legit'\s*$", ctl, re.M)
    # el v1 sigue exigido como snapshot previo intacto (G-W2)
    assert "$SnapV1" in ctl and "'lab-listo-windows-legit'" in ctl


def test_existe_la_fase_cosecha_y_es_puerta_de_cleanup_y_stop(ctl):
    assert re.search(r"ValidateSet\('prep', 'arm', 'watch', 'cosecha'", ctl)
    assert "'cosecha' {" in ctl
    # cleanup: exit 87 sin cosecha.done
    cl = ctl[ctl.index("'cleanup' {"):ctl.index("'status' {")]
    assert "cosecha.done" in cl and "exit 87" in cl
    # el bloqueo de cosecha va ANTES de apagar nada en cleanup
    assert cl.index("exit 87") < cl.index("Stop-Actividad")
    # stop exige las DOS puertas
    st = ctl[ctl.index("'stop' {"):ctl.index("'cleanup' {")]
    assert "crudo.done" in st and "cosecha.done" in st and "exit 70" in st
    assert "$tieneCrudo -and $tieneCosecha" in st


def test_cosecha_verifica_hashes_y_reloj(ctl):
    co = ctl[ctl.index("'cosecha' {"):ctl.index("'crudo' {")]
    assert "MANIFEST_INVITADO.tsv" in co and "Get-FileHash" in co and "exit 87" in co
    assert "delta_reloj_s" in co and "evtx" in co
    # la cosecha exige la VM encendida
    assert "Get-VmEnMarcha $Vmx" in co and "exit 88" in co


def test_prep_amplia_los_logs_de_eventos(ctl):
    assert "Set-TamanoLogsInvitado" in ctl and "exit 49" in ctl
    fn = ctl[ctl.index("function Set-TamanoLogsInvitado"):ctl.index("function Set-StopFlag")]
    for log in ("'Security'", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"):
        assert log in fn
    # solo capacidad: nunca toca Sysmon ni la politica de auditoria
    codigo = "\n".join(l for l in fn.splitlines() if not l.strip().startswith("#"))
    assert "sysmon64" not in codigo.lower() and "auditpol" not in codigo.lower()
    assert "wevtutil sl" in codigo and "/ms:" in codigo          # solo `set-log /maxsize`


def test_gw12_exige_la_pausa_de_windows_update_del_host(ctl):
    g = ctl[ctl.index("function Test-GW12"):ctl.index("function Test-GW13")]
    assert "NoAutoUpdate" in g and "NoAutoRebootWithLoggedOnUsers" in g
    assert "pausar_windows_update.ps1" in g


def test_crudo_guarda_evidencia_de_perdidas_del_manager(ctl):
    cr = ctl[ctl.index("'crudo' {"):ctl.index("'stop' {")]
    assert "ossec.log" in cr and "wazuh-analysisd.state" in cr and "wazuh-remoted.state" in cr


# --------------------------------------------------------------------------
# Los .ps1 compilan
# --------------------------------------------------------------------------
@SOLO_PS
@pytest.mark.parametrize("ruta", [CONTROL, WATCH, COSECHA], ids=lambda p: p.name)
def test_los_ps1_compilan(ruta):
    cmd = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{ruta}',[ref]$null,[ref]$e); if($e){{$e|ForEach-Object{{$_.Message+' L'+$_.Extent.StartLineNumber}}; exit 1}}")
    p = _ps(["-Command", cmd])
    assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.parametrize("ruta", [WATCH, COSECHA], ids=lambda p: p.name)
def test_los_ps1_nuevos_son_ascii(ruta):
    """PowerShell 5.1 lee un .ps1 sin BOM como ANSI: un acento rompería cadenas y comentarios."""
    raw = ruta.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert all(b < 128 for b in raw), "caracter no ASCII en " + ruta.name


# --------------------------------------------------------------------------
# watch_loop.ps1 (con un controlador falso)
# --------------------------------------------------------------------------
@pytest.fixture()
def stubs(tmp_path):
    ok = tmp_path / "stub_ok.ps1"
    ok.write_text('param([string]$Phase)\nWrite-Output "chequeo ok=9 fallos=0 skip=0"\nexit 0\n', encoding="ascii")
    mal = tmp_path / "stub_alarma.ps1"
    mal.write_text('param([string]$Phase)\nWrite-Output "ALARMA chequeo ok=8 fallos=1 skip=0 :: G-W13"\nexit 60\n', encoding="ascii")
    return ok, mal


def _watch(t0, t1, control, out, *extra, intervalo=3, timeout=120):
    return _ps(["-File", str(WATCH), "-T0", _iso(t0), "-T1", _iso(t1), "-IntervaloSeg", str(intervalo),
                "-Control", str(control), "-OutDir", str(out), *extra], timeout=timeout)


def _resumen(out):
    return json.loads((out / "watch_loop_resumen.json").read_text(encoding="utf-8-sig"))


@SOLO_PS
def test_watch_loop_ejecuta_todos_los_ticks(tmp_path, stubs):
    ok, _ = stubs
    now = _ahora()
    out = tmp_path / "o"
    p = _watch(now + timedelta(seconds=3), now + timedelta(seconds=12), ok, out, "-SinPw")
    assert p.returncode == 0, p.stdout + p.stderr
    r = _resumen(out)
    assert r["esperados"] == 3 and r["ejecutados"] == 3 and r["saltados"] == 0
    assert r["alarmas"] == 0 and r["veredicto"] == "OK"
    log = (out / "watch_loop.log").read_text(encoding="utf-8-sig")
    assert log.count("chequeo ok=9 fallos=0") == 3


@SOLO_PS
def test_watch_loop_alarma_deja_fichero_visible(tmp_path, stubs):
    _, mal = stubs
    now = _ahora()
    out = tmp_path / "o"
    p = _watch(now + timedelta(seconds=3), now + timedelta(seconds=9), mal, out, "-SinPw")
    assert p.returncode == 0, p.stdout + p.stderr
    assert len(list(out.glob("ALARMA_*.txt"))) == 2
    assert _resumen(out)["alarmas"] == 2


@SOLO_PS
def test_watch_loop_registra_ticks_saltados(tmp_path, stubs):
    """Un host dormido deja ticks enteros sin ejecutar: se anotan, no se recuperan en ráfaga."""
    ok, _ = stubs
    now = _ahora()
    out = tmp_path / "o"
    p = _watch(now - timedelta(seconds=7), now + timedelta(seconds=6), ok, out, "-SinPw", "-MinOk", "3")
    assert p.returncode == 0, p.stdout + p.stderr
    r = _resumen(out)
    assert r["saltados"] >= 1 and r["ejecutados"] + r["saltados"] == r["esperados"]
    assert r["veredicto"] == "INCIDENCIA"          # menos de MinOk => incidencia declarada, no fallo
    assert "SALTADO" in (out / "watch_loop.log").read_text(encoding="utf-8-sig")


@SOLO_PS
def test_watch_loop_exige_la_contrasena_del_manager(tmp_path, stubs):
    ok, _ = stubs
    now = _ahora()
    env = {k: v for k, v in os.environ.items() if k != "TFG_MANAGER_PW"}
    p = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(WATCH),
                        "-T0", _iso(now), "-T1", _iso(now + timedelta(seconds=9)),
                        "-Control", str(ok), "-OutDir", str(tmp_path / "o")],
                       capture_output=True, text=True, timeout=60, env=env)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "TFG_MANAGER_PW" in p.stdout
    # y nunca escribe la contraseña en el log
    assert "Wazuh" not in (tmp_path / "o" / "watch_loop.log").read_text(encoding="utf-8-sig")


@SOLO_PS
def test_watch_loop_segunda_instancia_sale_sin_hacer_nada(tmp_path, stubs):
    ok, _ = stubs
    now = _ahora()
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    primero = subprocess.Popen([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(WATCH),
                                "-T0", _iso(now + timedelta(seconds=2)), "-T1", _iso(now + timedelta(seconds=20)),
                                "-IntervaloSeg", "6", "-Control", str(ok), "-OutDir", str(out1), "-SinPw"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(60):                       # espera a que el primero tenga el mutex
            time.sleep(0.5)
            if (out1 / "watch_loop.log").exists() and "arranca" in (out1 / "watch_loop.log").read_text(encoding="utf-8-sig"):
                break
        p2 = _watch(now + timedelta(seconds=2), now + timedelta(seconds=20), ok, out2, "-SinPw", intervalo=6)
        assert p2.returncode == 3, p2.stdout + p2.stderr
        assert "segunda instancia" in p2.stdout
    finally:
        primero.terminate()
        primero.wait(timeout=20)


# --------------------------------------------------------------------------
# cosecha_invitado.ps1
# --------------------------------------------------------------------------
@SOLO_PS
def test_cosecha_invitado_manifiesto_con_sha256_correctos(tmp_path):
    stage = tmp_path / "stage"
    ahora = _ahora()
    # ventana de 1 minuto: el conteo por EventID es rapido aunque el log del PC sea enorme
    p = _ps(["-File", str(COSECHA), "-Stage", str(stage),
             "-Desde", _iso(ahora - timedelta(minutes=1)), "-Hasta", _iso(ahora)], timeout=300)
    assert "COSECHA_INVITADO_OK" in p.stdout, p.stdout + p.stderr
    man = stage / "MANIFEST_INVITADO.tsv"
    assert man.is_file() and (stage / "reloj.txt").is_file() and (stage / "AVISOS.txt").is_file()
    lineas = man.read_text(encoding="utf-8-sig").splitlines()[1:]
    assert len(lineas) >= 5
    for ln in lineas:
        rel, nbytes, sha = ln.split("\t")
        f = stage / rel
        assert f.is_file(), rel
        assert f.stat().st_size == int(nbytes), rel
        assert hashlib.sha256(f.read_bytes()).hexdigest() == sha, rel
    assert "guest_utc=" in (stage / "reloj.txt").read_text(encoding="utf-8-sig")
    # conteo por (log, EventID) para comparar con `archives` (cabecera fija)
    csvf = stage / "evtx" / "conteo_por_evento.csv"
    assert csvf.is_file()
    assert csvf.read_text(encoding="ascii").splitlines()[0] == "log,eventid,count,primero_utc,ultimo_utc"


# --------------------------------------------------------------------------
# Pila del host (GHOSTS API, PostgreSQL, internet local): hallazgo del 13-nov
# --------------------------------------------------------------------------
def _funcion(ctl, nombre, siguiente):
    return ctl[ctl.index(f"function {nombre}"):ctl.index(f"function {siguiente}")]


def test_las_funciones_que_devuelven_bool_no_usan_log(ctl):
    """`Log` hace `Write-Output`: dentro de una funcion contamina el retorno y
    `if (-not (f))` deja de detectar el fallo (medido: devolvia `System.Object[]`)."""
    for nombre, sig in (("Set-TamanoLogsInvitado", "Set-StopFlag"), ("Start-PilaHost", "Test-GW13")):
        cuerpo = _funcion(ctl, nombre, sig)
        assert not re.search(r"(?<![A-Za-z])Log\s*[('\"]", cuerpo), f"{nombre} usa Log; usar LogC"
        assert "LogC" in cuerpo or nombre == "Set-StopFlag"


def test_prep_arranca_la_pila_del_host_y_prueba_el_curl_desde_el_invitado(ctl):
    prep = ctl[ctl.index("'prep' {"):ctl.index("'arm' {")]
    assert "Start-PilaHost" in prep and "exit 40" in prep
    # la pila se levanta ANTES de revertir el snapshot
    assert prep.index("Start-PilaHost") < prep.index("revertToSnapshot")
    # prueba real: el invitado alcanza la web local (la receta tiene ~50 `curl` a intranet.local)
    assert "http://intranet.local:8080/" in prep and "curl.exe" in prep


def test_start_pilahost_no_usa_wait_ni_tuberias(ctl):
    """`-Wait` espera a TODO el arbol (postgres/API quedan vivos) y `| Out-Null` o `> $null`
    esperan a que los hijos cierren la salida: las tres variantes se colgaban."""
    f = _funcion(ctl, "Start-PilaHost", "Test-GW13")
    assert "-Wait" not in f.replace("`-Wait`", "")
    assert not re.search(r"start_ghosts\.ps1'\)\s*\)?\s*\|\s*Out-Null", f) or "Start-Process" in f
    assert "Test-GW15" in f                         # se sondean los puertos


def test_gw15_cubre_api_postgres_y_internet_local_y_aplica_en_watch(ctl):
    g = _funcion(ctl, "Test-GW15", "Start-PilaHost")
    for puerto in ("5000", "5432"):
        assert puerto in ctl[ctl.index("$PilaHost"):ctl.index("function Test-GW15")]
    for puerto in ("8080", "9090", "9092"):
        assert puerto in ctl[ctl.index("$PilaHost"):ctl.index("function Test-GW15")]
    aplican = ctl[ctl.index("$Aplican = @{"):ctl.index("function Invoke-Guardarrailes")]
    assert re.search(r"watch\s*=\s*@\([^)]*'G-W15'", aplican)
    assert re.search(r"arm\s*=\s*@\([^)]*'G-W15'", aplican)
    assert "'G-W15' = 'Test-GW15'" in ctl


def test_cleanup_para_tambien_la_internet_local(ctl):
    cl = ctl[ctl.index("'cleanup' {"):ctl.index("'status' {")]
    assert "stop_internet_local.ps1" in cl
