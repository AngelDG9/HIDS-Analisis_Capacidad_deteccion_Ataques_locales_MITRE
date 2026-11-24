#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generar_control_vr.py - genera `legitimo_host_control_vr.ps1` y `pausar_windows_update.ps1` (copias) a partir de los de Wazuh, con cambios
DECLARADOS y comprobados (cada sustitucion exige que el texto original exista exactamente una vez). Los ficheros de Wazuh NO se modifican.
Escribe tambien `DIFF_control_vs_wazuh.txt` (diff unificado) para auditar los cambios.
Uso: python generar_control_vr.py   (desde cualquier carpeta)
"""
import difflib
import os

BS = chr(92)
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
W = os.path.join(REPO, "Soporte", "Laboratorio", "legitimo_72h")
V = os.path.join(REPO, "Soporte", "Laboratorio", "legitimo_72h_vr")


def rep(s, a, b, n=1):
    assert s.count(a) == n, (s.count(a), a[:80])
    return s.replace(a, b)


def cut(s, ini, fin, nuevo, incluir_fin=False):
    i = s.index(ini)
    j = s.index(fin, i) + (len(fin) if incluir_fin else 0)
    return s[:i] + nuevo + s[j:]


src = open(os.path.join(W, "legitimo_host_control.ps1"), encoding="utf-8-sig", newline="").read().replace("\r\n", "\n")
s = src

# ------------------------------------------------------------------ cabecera
cab_nueva = """# ============================================================================
# TFG - HIDS - Control del host para la captura de 72 h de actividad legitima con VELOCIRAPTOR (V1-L)
# COPIA ADAPTADA de `legitimo_72h/legitimo_host_control.ps1` (Wazuh). El de Wazuh NO se modifica (se regenera con generar_control_vr.py).
# Cambios declarados (ver _fases/velociraptor-v1l/plan.md y _fases/auditoria-ventanas-wazuh/AUDITORIA.md):
#   - snapshot `lab-listo-legit-vr` (Wazuh fuera, cliente de Velociraptor dentro); SIN VM manager, SIN logall_json, SIN agente Wazuh
#   - el vigilante lee SOLO el servidor de Velociraptor y el datastore del PC (`legit_vr.py`): NUNCA entra en la victima por SSH dentro de [t0,t1]
#   - logs y estado PROPIOS (`*_vr`): no se escribe en los de Wazuh
#   - recetas: d1/d2/d3 IDENTICOS a los de Wazuh (sha256 comprobado en G-4); mapa de fechas en `recetas_vr/`
#   - la contrasena de la VM SOLO por variable de entorno del PROCESO (TFG_GUEST_PW o TFG_MANAGER_PW); nunca persistida en el registro ni en ficheros
#   - `stop` NO se programa: la parada es manual, despues de verificar la cosecha
# Fases: prep | arm | watch | stop | drytest | cleanup | status
# ============================================================================
"""
s = cab_nueva + s[s.index("[CmdletBinding()]"):]

# ------------------------------------------------------------------ parametros, rutas y credenciales
s = rep(s, "  [string]$GuestPw = $null,\n  [string]$ManagerPw = $null\n", "  [string]$GuestPw = $null\n")
s = rep(s, "$Base    = Join-Path $Repo 'Soporte" + BS + "Laboratorio" + BS + "legitimo_72h'\n",
        "$BaseW   = Join-Path $Repo 'Soporte" + BS + "Laboratorio" + BS + "legitimo_72h'        # Wazuh: solo se LEE (guest, sellado)\n"
        "$Base    = Join-Path $Repo 'Soporte" + BS + "Laboratorio" + BS + "legitimo_72h_vr'     # Velociraptor: logs, estado y scripts propios\n")
s = rep(s, "$Guest   = Join-Path $Base 'guest'", "$Guest   = Join-Path $BaseW 'guest'")
s = rep(s, "$Recetas = Join-Path $Base 'recetas'", "$Recetas = Join-Path $Base 'recetas_vr'")
s = rep(s, "$Manager = 'D:" + BS + "TFG-VMs" + BS + "wazuh-server" + BS + "wazuh-server.vmx'\n", "")
s = rep(s, "$Snap    = 'lab-listo-legit-v3'", "$Snap    = 'lab-listo-legit-vr'")
s = rep(s, "$Man = 'angel@192.168.65.128'\n", "")
s = rep(s, "$Log = Join-Path $Base 'legitimo_host_control.log'", "$Log = Join-Path $Base 'legitimo_host_control_vr.log'")
s = rep(s, "$VigLog = Join-Path $Base 'vigilancia_legitimo.log'", "$VigLog = Join-Path $Base 'vigilancia_legitimo_vr.log'")
s = rep(s, "'opencode" + BS + "tfg_watch_estado.json'", "'opencode" + BS + "tfg_watch_estado_vr.json'")
s = rep(s, "$Psql    = ", "$Py      = 'python'\n$LegitVr = Join-Path $Repo '_artefactos" + BS + "scripts" + BS + "legit_vr.py'\n$Psql    = ")
s = rep(s, "if (-not $ManagerPw) { $ManagerPw = if ($env:TFG_MANAGER_PW) { $env:TFG_MANAGER_PW } else { $GuestPw } }\n",
        "if (-not $GuestPw)   { $GuestPw   = $env:TFG_MANAGER_PW }   # misma clave para todas las VMs; SOLO del entorno del proceso\n")
s = rep(s, "  $f = Join-Path $Base 'sha256sums.txt'", "  $f = Join-Path $BaseW 'sha256sums.txt'     # sellado de Wazuh (solo lectura); los ficheros VR van en sha256sums_vr.txt")

# ------------------------------------------------------------------ vigilante
s = cut(s, "function Invoke-WatchManager {", "# --- calendario (misma fuente que el keepalive)", """function Invoke-WatchVR([switch]$SinEstado) {
  # Lee SOLO el servidor de Velociraptor y el datastore del PC. No hay SSH a la victima.
  $a = @($LegitVr, 'watch'); if ($SinEstado) { $a += '--sin-estado' }
  $out = & $Py @a 2>&1 | Out-String
  $kv = @{}
  foreach ($l in ($out -split "`r?`n")) {
    if ($l -match '^([a-zA-Z0-9_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2].Trim() }
  }
  return ,$kv
}

""")

# ------------------------------------------------------------------ prep
s = rep(s, "$chk = & python (Join-Path $Repo '_artefactos" + BS + "scripts" + BS + "construir_receta_legitima.py') --check 2>&1 | Out-String",
        "$chk = & python (Join-Path $Repo '_artefactos" + BS + "scripts" + BS + "construir_receta_legitima.py') --check --t0 ([datetime]::Parse($T0).ToUniversalTime().ToString('yyyy-MM-dd')) --out-dir $Recetas 2>&1 | Out-String")
s = rep(s, "    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')         | Out-Null\n", "")
s = rep(s, "    if (-not (Wait-VmSsh $Man 300)) { Write-Log 'FALLO: no hay SSH al manager'; exit 31 }\n", "")
s = rep(s, "'deploy_client.ps1'", "'deploy_client_vr.ps1'")
s = cut(s, "    # --- manager: arranque, higiene y logall_json ON ---------------------",
        "    # --- internet local + GHOSTS ----------------------------------------",
        """    # --- servidor de Velociraptor + tabla de monitorizacion (D8) ----------
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Repo 'Soporte""" + BS + "Laboratorio" + BS + "velociraptor" + BS + """arrancar_servidor.ps1')   # idempotente
    $tb = & $Py $LegitVr tabla check 2>&1 | Out-String
    Write-Log "G-7 (VR) tabla de monitorizacion:`n$($tb.Trim())"
    if ($tb -notmatch 'RESULT=PASS') { Write-Log "G-7 FALLO: la tabla del servidor no es la configuracion S fijada (legit_vr.py tabla fijar)"; exit 44 }

""")
s = cut(s, "    # --- G-5: agente dentro ---------------------------------------------", "exit 43 }\n",
        """    # --- G-5/G-6 (VR): cliente conectado, filas de EBPF llegando y disco de la victima legible (DiskSpace) --
    $gate = & $Py $LegitVr gate --espera 60 2>&1 | Out-String
    Write-Log "G-5/G-6 (VR):`n$($gate.Trim())"
    if ($gate -notmatch 'RESULT=PASS') { Write-Log "G-5/G-6 FALLO: el cliente de Velociraptor no esta operativo"; exit 43 }
""", incluir_fin=True)
s = cut(s, "    # --- G-9: sonda de rotacion (aviso) ---------------------------------",
        "    Invoke-Vmrun @('-T','ws','listSnapshots',$Victim) | Out-Null",
        """    # --- H1(b): sembrar el estado de la vigilancia (primer chequeo sin delta falso) -------
    $seed = Invoke-WatchVR -SinEstado
    $seedObj = [ordered]@{ ts = TsUtc; archives = [int64]$seed['ebpf_bytes']; alerts = 0; alarma_sig = ''; alarma_n = 0; cero_n = 0 }
    $seedDir = Split-Path $WatchState
    if (-not (Test-Path $seedDir)) { New-Item -ItemType Directory -Force -Path $seedDir | Out-Null }
    $seedObj | ConvertTo-Json | Set-Content -Path $WatchState -Encoding utf8
    Write-Log "H1(b) estado del watch sembrado: ebpf=$($seedObj.archives)B df_avail_kb=$($seed['df_avail_kb']) (archivo $WatchState)"

""")

# ------------------------------------------------------------------ arm
s = rep(s, "    Invoke-OnVm $Man 'bash /tmp/diag_wazuh.sh' $ManagerPw | Out-Null\n    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null\n", "")

# ------------------------------------------------------------------ watch
s = cut(s, "    # --- senales 2,3,4,5: manager ---------------------------------------",
        "    # --- senal 6: disco del host ----------------------------------------",
        """    # --- senales 2-5 (VR): servidor, cliente, entrada de eventos y disco de la victima. SIN SSH. ---
    $wm = Invoke-WatchVR
    $kaEdad = if ($wm['cliente_ka_edad_s']) { [int]$wm['cliente_ka_edad_s'] } else { -1 }
    if ($kaEdad -lt 0 -or $kaEdad -gt 600) { $nivel = 2; $notas.Add('cliente>10m') }
    elseif ($kaEdad -gt 120) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('cliente>120s') }

    if ($wm['servidor'] -ne 'active') { $nivel = 2; $notas.Add('servidor_VR_caido') }
    if ($wm['tabla'] -eq 'DISTINTA') { $nivel = 2; $notas.Add('tabla_cambiada') }

    $ebNow = [int64]$wm['ebpf_bytes']
    $archDelta = if ([int64]$prev.archives -ge 0) { $ebNow - [int64]$prev.archives } else { -1 }
    $alertDelta = $archDelta
    if ($archDelta -eq 0) { $prev.cero_n = [int]$prev.cero_n + 1 } elseif ($archDelta -gt 0) { $prev.cero_n = 0 }
    if ($prev.cero_n -ge 2 -and $cal.estado -eq 'bloque') { $nivel = 2; $notas.Add('sin_eventos') }

    $dfAvailKb = [int]$wm['df_avail_kb']
    $dfGb = if ($dfAvailKb -ge 0) { [math]::Round($dfAvailKb / 1MB, 1) } else { -1 }
    $dfTasa = 'n/a'
    if ($dfAvailKb -lt 0) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('sin_df') }
    elseif ($dfAvailKb -lt 2097152) { $nivel = 2; $notas.Add('df<2G') }
    elseif ($dfAvailKb -lt 3145728) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('df<3G') }

""")
s = rep(s, "ag=$($wm['agente_status']) mgr=$($wm['manager'])/$($wm['daemons']) arch=$($archDelta)B dia=$($alertDelta)B ",
        "cli=$($kaEdad)s srv=$($wm['servidor']) ebpf=$($archDelta)B tabla=$($wm['tabla']) ")
s = rep(s, "    $prev.archives = [int]$wm['archives_bytes']\n    $prev.alerts = [int]$wm['alerts_bytes']\n",
        "    $prev.archives = [int64]$wm['ebpf_bytes']\n    $prev.alerts = 0\n")
s = rep(s, "hb=$hbTxt", "hb=$hbTxt")  # (sin cambios; comprueba que existe)
REEMPL_LOG_A = "    Add-Content -Path $VigLog -Value $line -Encoding utf8"+chr(10)+"    Add-Content -Path $Log -Value $line -Encoding utf8"+chr(10)
REEMPL_LOG_B = "    Add-LineaSegura $VigLog $line"+chr(10)+"    Add-LineaSegura $Log $line"+chr(10)
s = rep(s, REEMPL_LOG_A, REEMPL_LOG_B)
FUNC = (
"function Add-LineaSegura([string]$Path, [string]$Linea) {"+chr(10)+
"  # V1-L: Windows puede bloquear un fichero un instante (antivirus, lector); se reintenta y, si no, se deja en un fichero de rescate"+chr(10)+
"  for ($i = 1; $i -le 6; $i++) {"+chr(10)+
"    try { Add-Content -Path $Path -Value $Linea -Encoding utf8 -ErrorAction Stop; return } catch { Start-Sleep -Seconds 2 }"+chr(10)+
"  }"+chr(10)+
"  Add-Content -Path ($Path + '.rescate') -Value $Linea -Encoding utf8"+chr(10)+
"}"+chr(10)+chr(10)+"function TsUtc {")
s = rep(s, "function TsUtc {", FUNC)

# ------------------------------------------------------------------ stop / cleanup / status
s = rep(s, 'Write-Log "victima parada (soft). El manager SIGUE encendido para la extraccion."',
        'Write-Log "victima parada (soft). V1-L: usar SOLO despues de verificar la cosecha (no hay parada automatica)."')
s = rep(s, "    $manUp = Test-VmEnMarcha $Manager\n", "")
s = rep(s, 'Write-Log "cleanup: victima_en_marcha=$vicUp manager_en_marcha=$manUp"', 'Write-Log "cleanup: victima_en_marcha=$vicUp"')
s = cut(s, "    if ($manUp) {\n      Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh off'", "    if ($vicUp)    { Invoke-Vmrun @('-T','ws','stop',$Victim,'soft')  | Out-Null }",
        "    # V1-L: no hay manager ni logall_json. La equivalencia de configuracion (tabla, auditd.conf, client.config) se comprueba con legit_vr.py y en la cosecha.\n")
s = rep(s, "    if ($manUp)    { Invoke-Vmrun @('-T','ws','stop',$Manager,'soft') | Out-Null }\n", "")
s = rep(s, "    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null\n", "")

# ------------------------------------------------------------------ comprobaciones finales
for prohibido in ("$Man ", "$Manager", "$ManagerPw", "wazuh", "ossec", "logall"):   # `archives` queda solo como nombre interno de un campo del estado
    restos = [l for l in s.split("\n") if prohibido in l and not l.lstrip().startswith("#")]
    assert not restos, (prohibido, restos[:3])
open(os.path.join(V, "legitimo_host_control_vr.ps1"), "w", encoding="utf-8-sig", newline="").write(s.replace("\n", "\r\n"))
d = difflib.unified_diff(src.split("\n"), s.split("\n"), "wazuh/legitimo_host_control.ps1", "vr/legitimo_host_control_vr.ps1", lineterm="", n=0)
open(os.path.join(V, "DIFF_control_vs_wazuh.txt"), "w", encoding="utf-8", newline="\n").write("\n".join(d) + "\n")

# ------------------------------------------------------------------ pausar_windows_update.ps1 (misma logica; su log queda en la carpeta VR)
p = open(os.path.join(W, "pausar_windows_update.ps1"), encoding="utf-8-sig", newline="").read()
open(os.path.join(V, "pausar_windows_update.ps1"), "w", encoding="utf-8-sig", newline="").write(p)
print("generados: legitimo_host_control_vr.ps1, DIFF_control_vs_wazuh.txt, pausar_windows_update.ps1")
