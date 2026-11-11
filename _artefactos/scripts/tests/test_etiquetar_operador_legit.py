# -*- coding: utf-8 -*-
"""Tests de `etiquetar_operador_legit.py` (T3, ventana legítima Windows).

Qué se prueba:
- marca lo del **operador** (`keepalive`, `latido`, `logs_operador`, `vmware_tools`,
  `logon_operador`) sin tocar las filas del **usuario** (`angel`, `Documentos`,
  `powershell.exe` de la receta, logon de consola);
- `67028` (4672): **sin** `logon_type=3`/IP/`sshd_<pid>` no marca (autologon de consola);
- `watch` se marca y dispara `alerta_diseno` (en v2 no debe existir);
- modo horario **opcional**: con intervalo + `rule_id` listado sí; sin ellos, nunca;
- `doble_fpr`: plantilla con datos sintéticos y validación de rangos;
- `operador_uni` en **líneas de `archives`** (misma unidad que Linux);
- CLI determinista: 2 ejecuciones → bytes idénticos; auditoría con qué y por qué.
"""
from pathlib import Path
import csv
import json
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import etiquetar_operador_legit as E  # noqa: E402

HEADER = [
    "timestamp_utc", "agent_name", "rule_id", "rule_level", "rule_description",
    "rule_groups", "rs_origen", "audit_exe", "audit_cwd", "audit_key", "audit_type",
    "audit_file", "audit_dir", "syscheck_path", "srcip", "srcuser", "dstuser",
    "agent_id", "win_image", "win_command_line", "win_cwd", "win_user", "event_id",
    "win_target", "logon_type", "win_parent_image", "win_target_user",
]

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def fila(**kw):
    base = {"timestamp_utc": "2026-11-11T15:00:00.000Z", "agent_name": "victima-windows",
            "rule_id": "67027", "agent_id": "002"}
    base.update(kw)
    return {k: base.get(k, "") for k in HEADER}


# --------------------------------------------------------------------------
# Etiquetado: operador sí / usuario no
# --------------------------------------------------------------------------
def test_keepalive_si_usuario_no():
    op = fila(win_image=PS, win_user="SYSTEM",
              win_command_line=r'powershell.exe -File "C:\Users\angel\ghosts-client\tfg_keepalive_windows.ps1" -Loop')
    usr = fila(win_image=PS, win_user="angel",
               win_command_line=r"powershell.exe -File C:\lab-legit\campana\scripts\W-04_cifrar_aes.ps1")
    assert E.motivo_operador(op) == ("keepalive", f"win_command_line={op['win_command_line']}")
    assert E.motivo_operador(usr) is None


def test_no_marca_angel_por_usuario_a_secas():
    """El usuario legítimo ES `angel`: su nombre no es evidencia de operador."""
    usr = fila(win_user="angel", win_target_user="angel", win_image=r"C:\Windows\explorer.exe")
    assert E.motivo_operador(usr) is None


def test_latido_solo_al_sink_9095():
    hit = fila(rule_id="185001", win_target="192.168.65.1:9095")
    otro = fila(rule_id="185001", win_target="192.168.65.128:1514")
    assert E.motivo_operador(hit)[0] == "latido"
    assert E.motivo_operador(otro) is None


def test_logs_operador_si_documentos_no():
    log = fila(rule_id="550", syscheck_path=r"C:\Users\angel\ghosts-client\logs\keepalive.log")
    estado = fila(rule_id="550", syscheck_path=r"C:\Users\angel\ghosts-client\estado.json")
    doc = fila(rule_id="550", syscheck_path=r"C:\Users\angel\Documentos\informe.docx")
    assert E.motivo_operador(log)[0] == "logs_operador"
    assert E.motivo_operador(estado)[0] == "logs_operador"
    assert E.motivo_operador(doc) is None


def test_vmware_tools():
    row = fila(win_image=r"C:\Windows\System32\cmd.exe",
               win_parent_image=r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe")
    assert E.motivo_operador(row)[0] == "vmware_tools"


def test_logon_operador_vs_consola():
    """Predicado canónico: 60106 + angel + logon_type=3 (red/SSH) sí; tipo 2 (consola) no."""
    red = fila(rule_id="60106", win_user="angel", win_target_user="angel", logon_type="3")
    consola = fila(rule_id="60106", win_user="angel", win_target_user="angel", logon_type="2")
    assert E.motivo_operador(red)[0] == "logon_operador"
    assert E.motivo_operador(consola) is None


@pytest.mark.parametrize("logon", ["", "2"])
def test_67028_sin_contexto_de_red_no_marca(logon):
    """T3b: `67028` (4672) por `win_user=angel` a secas NO es evidencia del operador.

    El autologon de consola del usuario legítimo (`logon_type=2`) produce el mismo
    4672 y **no** debe etiquetarse como operador.
    """
    for campo in ("win_user", "win_target_user"):
        row = fila(rule_id="67028", event_id="4672", logon_type=logon, **{campo: "angel"})
        assert E.motivo_operador(row) is None, (campo, logon, E.motivo_operador(row))


def test_67028_con_contexto_de_red_si_marca():
    """T3b: `67028` con `logon_type=3`, IP del operador o cuenta `sshd_<pid>` sí marca."""
    tipo3 = fila(rule_id="67028", event_id="4672", win_user="angel",
                 win_target_user="angel", logon_type="3")
    ip = fila(rule_id="67028", event_id="4672", win_user="angel",
              win_target_user="angel", srcip="192.168.65.1")
    ssh = fila(rule_id="67028", event_id="4672", win_user="sshd_5184",
               win_target_user="sshd_5184")
    for row in (tipo3, ip, ssh):
        motivo = E.motivo_operador(row)
        assert motivo is not None and motivo[0] == "logon_operador", row
        assert "contexto=" in motivo[1], motivo
    assert "logon_type=3" in E.motivo_operador(tipo3)[1]
    assert "srcip=192.168.65.1" in E.motivo_operador(ip)[1]


def test_watch_es_alerta_diseno():
    row = fila(win_command_line=r"powershell.exe -File C:\Users\angel\ghosts-client\verificar_windows.ps1")
    filas, res = E.etiquetar([row])
    assert filas[0]["motivo_operador"] == "watch"
    assert res["watch"] == 1 and res["alerta_diseno"] is True


def test_modo_horario_solo_si_declarado():
    row = fila(timestamp_utc="2026-11-11T15:10:00.000Z", rule_id="67027")
    iv = [{"motivo": "latido", "desde": E.cd.parse_ts("2026-11-11T15:00:00Z"),
           "hasta": E.cd.parse_ts("2026-11-11T15:20:00Z")}]
    # desactivado por defecto
    assert E.motivo_operador(row) is None
    # con intervalo pero sin rule_id declarado: sigue sin marcar
    assert E.motivo_operador(row, iv, ()) is None
    # con intervalo + rule_id: marca
    assert E.motivo_operador(row, iv, ("67027",))[0] == "horario"
    # fuera del intervalo: no marca
    assert E.motivo_operador(row, iv, ("9999",)) is None


# --------------------------------------------------------------------------
# Doble FPR (plantilla, datos sintéticos)
# --------------------------------------------------------------------------
def test_doble_fpr_sintetico():
    f = E.doble_fpr(M=1000, fp_uni=200, operador_uni=4)
    assert f["FPR_canonico"] == 0.2
    assert f["FPR_sin_operador"] == 0.196
    assert f["FP_uni_sin_operador"] == 196
    assert f["delta_abs"] == 0.004


def test_doble_fpr_reproduce_linux_canonico():
    """CA-W3b-23: la fórmula reproduce el FPR de Linux (0,857963) en su unidad."""
    f = E.doble_fpr(M=342966, fp_uni=294252, operador_uni=0)
    assert f["FPR_canonico"] == 0.857963
    assert f["FPR_canonico_pct"] == 85.7963


@pytest.mark.parametrize("args", [(0, 0, 0), (10, 11, 0), (10, 5, 6), (10, 5, -1)])
def test_doble_fpr_rangos(args):
    with pytest.raises(ValueError):
        E.doble_fpr(*args)


def test_unidades_operador_en_lineas_de_archives():
    """`operador_uni` se cuenta en líneas de `archives` (no en alertas)."""
    marcadas = [{"timestamp_utc": "2026-11-11T15:07:42.500Z", "rule_id": "67027"}]
    archives = [
        json.dumps({"timestamp": "2026-11-11T15:07:42.500+0000",
                    "agent": {"id": "002", "name": "victima-windows"},
                    "rule": {"id": "67027"}}),
        # mismo segundo y regla: otra línea (el multiconjunto cuenta 2)
        json.dumps({"timestamp": "2026-11-11T15:07:42.500+0000",
                    "agent": {"id": "002", "name": "victima-windows"},
                    "rule": {"id": "67027"}}),
        # otra regla: no corresponde
        json.dumps({"timestamp": "2026-11-11T15:07:42.500+0000",
                    "agent": {"id": "002", "name": "victima-windows"},
                    "rule": {"id": "550"}}),
        # otro agente: no corresponde
        json.dumps({"timestamp": "2026-11-11T15:07:42.500+0000",
                    "agent": {"id": "001", "name": "victima-linux"},
                    "rule": {"id": "67027"}}),
    ]
    r = E.contar_unidades_operador(marcadas, [archives], "002")
    assert r["unidad"] == "linea_archives"
    assert r["unidades"] == 2 and r["alertas"] == 1 and r["lineas_leidas"] == 4


def test_unidades_sin_archives_es_provisional():
    r = E.contar_unidades_operador([{"timestamp_utc": "x", "rule_id": "1"}], None)
    assert r["unidad"] == "alerta_provisional" and r["unidades"] is None


# --------------------------------------------------------------------------
# CLI: columnas, auditoría y determinismo
# --------------------------------------------------------------------------
def _escribir_detalle(path, filas):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("# detalle sintético T3\n")
        w = csv.DictWriter(fh, fieldnames=HEADER, lineterminator="\n")
        w.writeheader()
        for r in filas:
            w.writerow(r)


def test_cli_columnas_auditoria_y_determinismo(tmp_path):
    det = tmp_path / "alertas_detalle.csv"
    _escribir_detalle(det, [
        fila(win_command_line=r"powershell.exe -File C:\Users\angel\ghosts-client\tfg_keepalive_windows.ps1 -Loop"),
        fila(win_image=PS, win_user="angel",
             win_command_line=r"powershell.exe -File C:\lab-legit\campana\scripts\W-05.ps1"),
        fila(rule_id="550", syscheck_path=r"C:\Users\angel\Documentos\a.txt"),
    ])
    out1, out2 = tmp_path / "r1" / "o.csv", tmp_path / "r2" / "o.csv"
    aud1, aud2 = tmp_path / "r1" / "a.json", tmp_path / "r2" / "a.json"
    assert E.main(["--detalle", str(det), "--out", str(out1), "--auditoria", str(aud1)]) == 0
    assert E.main(["--detalle", str(det), "--out", str(out2), "--auditoria", str(aud2)]) == 0
    assert out1.read_bytes() == out2.read_bytes(), "la salida debe ser determinista"

    with open(out1, encoding="utf-8", newline="") as fh:
        lineas = [ln for ln in fh if not ln.lstrip().startswith("#")]
    rd = csv.DictReader(lineas)
    for c in E.COLS_OPERADOR:
        assert c in rd.fieldnames
    filas = list(rd)
    assert [f["operador_legit"] for f in filas] == ["1", "0", "0"]
    assert [f["sin_operador"] for f in filas] == ["0", "1", "1"]
    assert filas[0]["motivo_operador"] == "keepalive"

    a1 = json.loads(aud1.read_text(encoding="utf-8"))
    a2 = json.loads(aud2.read_text(encoding="utf-8"))
    assert a1["sha256_salida"] == a2["sha256_salida"]
    assert a1["operador_legit"] == 1 and a1["sin_operador"] == 2
    assert a1["por_motivo"] == {"keepalive": 1}
    assert a1["marcadas"] == [{"agent_id": "002", "evidencia":
                               "win_command_line=" + filas[0]["win_command_line"],
                               "motivo": "keepalive", "rule_id": "67027",
                               "timestamp_utc": "2026-11-11T15:00:00.000Z"}]
