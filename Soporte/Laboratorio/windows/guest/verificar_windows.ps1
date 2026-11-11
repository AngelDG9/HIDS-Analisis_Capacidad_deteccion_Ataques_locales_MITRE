# ============================================================================
# verificar_windows.ps1 - comprobacion READ-ONLY del invitado (bloque W3)
# Bloque `windows-legit-prep`. NO escribe nada, NO arranca nada, NO toca servicios.
# Espejo de `legitimo_72h/guest/verificar_arreglos.sh`.
# ----------------------------------------------------------------------------
# Comprueba, en una sola pasada:
#   1) cliente desplegado (ghosts.exe + config + recetas + campana + errores.log)
#   2) las 2 tareas (estado, usuario, logon) y su huella
#   3) Sysmon64 y WazuhSvc Running
#   3b) Defender OFF (RealTimeProtectionEnabled=False + WinDefend=Stopped)  (CA-W3b-07)
#   3c) sesion de `angel` en la consola (explorer en sesion 1) e IL Medium   (CA-W3b-08)
#   4) sin suspension (STANDBYIDLE/HIBERNATEIDLE/HYBRIDSLEEP = 0)
#   5) disco libre, hosts (intranet.local), Windows Update (politica + servicio)
#   6) cliente vivo y su dueno real (debe ser angel)
#   7) residuos: procesos ghosts, marcas de campana y `stop.flag` (lista negra)
#
# `-Manifiesto` excluye lo volatil (logs, `heartbeat.seq`, `stop.flag`, `armado.flag`,
# `estado.json`, `client.out*`, `instance\`): dos `apply` seguidos dan el MISMO sha256.
#
# Salida: lineas `CLAVE=valor` + `RESULT=PASS|FAIL` (y `FALLOS=...` si falla).
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File verificar_windows.ps1 [-SinCampana]
# ============================================================================
[CmdletBinding()]
param(
  [string]$ClienteDir = 'C:\Users\angel\ghosts-client',
  [string]$CampanaDir = 'C:\lab-legit\campana',
  [string]$ErrLog = 'C:\Users\angel\Documentos\errores.log',
  # En `prep` la campana aun no ha corrido: no se exigen marcas.
  [switch]$SinCampana,
  # Solo huella del despliegue (idempotencia del deploy): no comprueba el resto.
  [switch]$Manifiesto
)

$ErrorActionPreference = 'Continue'
$fallos = New-Object System.Collections.Generic.List[string]

if ($Manifiesto) {
  # Huella del PAYLOAD desplegado. Excluye lo volatil (logs, instance, client.out*,
  # keepalive/recovery/estado, el flag de armado, `heartbeat.seq` y `stop.flag`) y el
  # `config\timeline.json` ACTIVO: GHOSTS lo reescribe al ejecutar (el original es
  # `timeline.dK.json`, que SI entra en la huella). Sin esta exclusion, un 2.o `arm`
  # con el cliente vivo nunca coincidia (G-8). Dos `apply` seguidos dan el MISMO sha256.
  $excl = '\\logs\\|\\instance\\|client\.out|keepalive\.log|recovery\.log|estado\.json|armado\.flag|heartbeat\.seq|stop\.flag|\\config\\timeline\.json$'
  $files = @()
  if (Test-Path $ClienteDir) {
    $files += Get-ChildItem -Path $ClienteDir -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch $excl }
  }
  if (Test-Path $CampanaDir) {
    $files += Get-ChildItem -Path $CampanaDir -File -ErrorAction SilentlyContinue
  }
  $lineas = @($files | Sort-Object FullName | ForEach-Object {
      "$($_.FullName.ToLower())`t$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower())"
    })
  $txt = ($lineas -join "`n")
  $sha = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
      [System.Text.Encoding]::UTF8.GetBytes($txt))).Replace('-', '').ToLower()
  Write-Output "MANIFEST_FILES=$($lineas.Count)"
  Write-Output "MANIFEST_SHA256=$sha"
  exit 0
}

function Check([string]$Nombre, [bool]$Ok, [string]$Detalle) {
  $estado = if ($Ok) { 'OK' } else { 'FALLO' }
  Write-Output ("CHECK {0,-22} {1} {2}" -f $Nombre, $estado, $Detalle)
  if (-not $Ok) { $fallos.Add($Nombre) }
}

# --- 1) cliente -------------------------------------------------------------
$exe = Join-Path $ClienteDir 'ghosts.exe'
$cfg = Join-Path $ClienteDir 'config\application.json'
$tl  = Join-Path $ClienteDir 'config\timeline.json'
$tls = @(1..3 | ForEach-Object { Join-Path $ClienteDir ("config\timeline.d$_.json") })
$rec = Join-Path $ClienteDir 'recetas\bloques_windows.env'
$ka  = Join-Path $ClienteDir 'tfg_keepalive_windows.ps1'
Check 'cliente_exe'    (Test-Path $exe) $exe
Check 'cliente_config' ((Test-Path $cfg) -and (Test-Path $tl)) $cfg
Check 'cliente_recetas' ((Test-Path $rec) -and (Test-Path $ka) -and (@($tls | Where-Object { -not (Test-Path $_) }).Count -eq 0)) 'd1/d2/d3 + bloques + keepalive'
Check 'campana_docs'   ((Test-Path (Join-Path $CampanaDir 'casos_windows.md')) -and (Test-Path (Join-Path $CampanaDir 'campana_windows.csv'))) $CampanaDir
Check 'errores_log'    (Test-Path $ErrLog) $ErrLog

# --- 2) tareas --------------------------------------------------------------
$TareaAct = 'TFG-WinLegit-Actividad'
$TareaKa  = 'TFG-WinLegit-Keepalive'
$ta = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue
$tk = Get-ScheduledTask -TaskName $TareaKa  -ErrorAction SilentlyContinue
$detTa = 'AUSENTE'
if ($ta) { $detTa = "estado=$($ta.State) user=$($ta.Principal.UserId) logon=$($ta.Principal.LogonType) runlevel=$($ta.Principal.RunLevel)" }
$detTk = 'AUSENTE'
if ($tk) { $detTk = "estado=$($tk.State) user=$($tk.Principal.UserId) logon=$($tk.Principal.LogonType)" }
Check 'tarea_actividad' ($null -ne $ta) $detTa
Check 'tarea_keepalive' ($null -ne $tk) $detTk
$userOk = ($ta -and ([string]$ta.Principal.UserId) -match '(?i)(^|\\)angel$')
Check 'tarea_user_angel' ([bool]$userOk) $(if ($ta) { [string]$ta.Principal.UserId } else { '' })
$ilOk = ($ta -and ([string]$ta.Principal.RunLevel) -eq 'Limited')
Check 'tarea_runlevel' ([bool]$ilOk) $(if ($ta) { [string]$ta.Principal.RunLevel } else { '' })
if ($ta) {
  Write-Output ("TAREA_ACT_CWD=" + [string]$ta.Actions[0].WorkingDirectory)
  Write-Output ("TAREA_ACT_ARGS=" + [string]$ta.Actions[0].Arguments)
}
if ($tk) { Write-Output ("TAREA_KA_ARGS=" + [string]$tk.Actions[0].Arguments) }

# --- 3) servicios -----------------------------------------------------------
foreach ($s in @('Sysmon64', 'WazuhSvc')) {
  $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
  $detSvc = 'AUSENTE'
  if ($svc) { $detSvc = "$($svc.Status)/$($svc.StartType)" }
  Check ("svc_$s") ($svc -and $svc.Status -eq 'Running') $detSvc
}

# --- 3b) Defender OFF (control ambiental declarado, CA-W3b-07) --------------
# Se exige el estado REAL: `RealTimeProtectionEnabled=False` (Get-MpComputerStatus) y
# `WinDefend=Stopped` (Get-Service). Si Defender esta ON, FALLO.
# Caso medido en el snapshot v1: con Defender deshabilitado por politica
# (`DisableAntiSpyware=1`) `Get-MpComputerStatus` NO responde ("general error"). En ese
# caso se acepta OFF solo si `WinDefend=Stopped` Y las dos politicas de desactivacion
# estan puestas; si no, FALLO (conservador).
$mp = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
$wd = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
$rtp = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
$bm = if ($mp) { [bool]$mp.BehaviorMonitorEnabled } else { $null }
$tp = if ($mp) { [bool]$mp.IsTamperProtected } else { $null }
$wdEstado = if ($wd) { [string]$wd.Status } else { 'AUSENTE' }
$polDef = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
$polRtp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction SilentlyContinue
$polOff = ($polDef -and $polDef.DisableAntiSpyware -eq 1) -and ($polRtp -and $polRtp.DisableRealtimeMonitoring -eq 1)
$defOff = $false
if ($rtp -eq $false) { $defOff = ($wdEstado -eq 'Stopped') }
elseif ($null -eq $rtp) { $defOff = ($wdEstado -eq 'Stopped') -and [bool]$polOff }
Check 'defender_off' ([bool]$defOff) "RTP=$rtp Behavior=$bm Tamper=$tp WinDefend=$wdEstado politica_off=$polOff"
Write-Output ("DEFENDER_OFF=" + [int][bool]$defOff)
Write-Output ("DEFENDER_RTP=$rtp DEFENDER_BEHAVIOR=$bm DEFENDER_TAMPER=$tp DEFENDER_SVC=$wdEstado DEFENDER_POLITICA_OFF=$polOff")

# --- 3c) sesion de `angel` en consola + IL Medium (CA-W3b-08) ---------------
# Sesion 1 = consola fisica (la que necesita la tarea `Interactive`). Se identifica por
# `explorer.exe` de `angel`; el IL se deriva del RunLevel `Limited` de la tarea (el
# snapshot tiene autologon; un logoff deja SESION_ANGEL=0 y la ventana no vale).
$exp = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)
$sesionAngel = 0
$duenoExp = ''
foreach ($e in $exp) {
  try {
    $o = Invoke-CimMethod -InputObject $e -MethodName GetOwner -ErrorAction SilentlyContinue
    if ($o -and $o.User -eq 'angel') { $sesionAngel = [int]$e.SessionId; $duenoExp = ("{0}\{1}" -f $o.Domain, $o.User); break }
  } catch { }
}
$sesOk = ($sesionAngel -eq 1)
Check 'sesion_angel' $sesOk "explorer_sesion=$sesionAngel (1=consola) dueno=$duenoExp"
Write-Output ("SESION_ANGEL=" + [int]$sesOk)
Write-Output ("SESION_EXPLORER=" + $sesionAngel + " IL=" + $(if ($ilOk) { 'Medium' } else { '?' }))

# --- 4) sin suspension ------------------------------------------------------
foreach ($sub in @('STANDBYIDLE', 'HIBERNATEIDLE', 'HYBRIDSLEEP')) {
  $txt = ''
  try { $txt = (& powercfg /query SCHEME_CURRENT SUB_SLEEP $sub 2>&1 | Out-String) } catch { }
  $m = [regex]::Match($txt, 'Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)')
  $val = if ($m.Success) { [Convert]::ToInt32($m.Groups[1].Value, 16) } else { -1 }
  Check ("powercfg_$sub") ($val -eq 0) "AC=$($m.Groups[1].Value)"
}

# --- 5) disco, hosts, WU ----------------------------------------------------
$freeMb = -1
try { $freeMb = [math]::Round((Get-PSDrive C).Free / 1MB) } catch { }
Check 'disco_libre_mb' ($freeMb -ge 4096) "$freeMb MB"
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsOk = $false
try { $hostsOk = ((Get-Content -LiteralPath $hosts -ErrorAction Stop) -join "`n") -match '192\.168\.65\.1\s+.*intranet\.local' } catch { }
Check 'hosts_intranet' $hostsOk 'intranet.local -> 192.168.65.1'
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
Check 'wu_politica' ($au -and $au.NoAutoUpdate -eq 1) ("NoAutoUpdate=" + $(if ($au) { $au.NoAutoUpdate } else { 'n/a' }))
$wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
$detWu = 'AUSENTE'
if ($wu) { $detWu = "$($wu.Status)/$($wu.StartType)" }
Check 'wu_servicio' ($wu -and $wu.Status -ne 'Running') $detWu

# --- 6) cliente vivo y su dueno --------------------------------------------
$proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
$dueno = ''
if ($proc.Count -gt 0) {
  try {
    $p = Get-CimInstance Win32_Process -Filter "Name='ghosts.exe'" | Select-Object -First 1
    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
    $dueno = "{0}\{1}" -f $o.Domain, $o.User
  } catch { }
}
Write-Output ("CLIENTE_VIVO=" + ($proc.Count -gt 0) + " PID=" + $(if ($proc.Count -gt 0) { $proc[0].Id } else { 0 }) + " WIN_USER=" + $dueno)

# --- 6b) acceso del operador (W-V4): hijos de vmtoolsd.exe ----------------
$vt = Get-CimInstance Win32_Process -Filter "Name='vmtoolsd.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
$hijos = 0
if ($vt) {
  $hijos = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ParentProcessId -eq $vt.ProcessId }).Count
}
Write-Output ("HIJOS_VMTOOLSD=$hijos")

# --- 7) residuos ------------------------------------------------------------
$marcas = 0
if (Test-Path $CampanaDir) {
  $marcas = @(Get-ChildItem -Path $CampanaDir -Recurse -File -Include 'inicio.txt', 'fin.txt', 'hecho.txt' -ErrorAction SilentlyContinue).Count
}
Write-Output ("CAMPANA_MARCAS=$marcas")
if (-not $SinCampana) { Check 'campana_marcas' ($marcas -ge 22) "$marcas marcas" }

# Lista negra: `stop.flag` es efimero y no puede quedar en el snapshot (T2b-1).
$stopFlag = Join-Path $ClienteDir 'stop.flag'
$stopLimpio = -not (Test-Path $stopFlag)
Check 'residuo_stop_flag' $stopLimpio $(if ($stopLimpio) { 'ausente' } else { 'PRESENTE (lista negra)' })
Write-Output ("BLACKLIST_STOP_FLAG=" + [int]$stopLimpio)

# --- 7b) lista negra completa 7.37.3 (G-2, T2b-1b) ---------------------------
# El snapshot/prep debe estar SIN residuos de campana ni de ataques. Cada item se
# publica como `BLACKLIST_<item>=1|0`; `LISTA_NEGRA_OK=0` hace que `prep` aborte con
# exit 46 (no se arma). Es la lista cerrada del plan 7.37.3.
$bl = [ordered]@{}

# 1) C:\lab-attack vacio o ausente
$nLab = 0
if (Test-Path 'C:\lab-attack') {
  $nLab = @(Get-ChildItem -LiteralPath 'C:\lab-attack' -Force -Recurse -ErrorAction SilentlyContinue).Count
}
$bl['lab_attack_vacio'] = ($nLab -eq 0)

# 2) 0 tareas TFG-Attack-* / TFG-Baseline-* / TFG-IL-*
$tareasMalas = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
  Where-Object { $_.TaskName -like 'TFG-Attack-*' -or $_.TaskName -like 'TFG-Baseline-*' -or $_.TaskName -like 'TFG-IL-*' })
$bl['tareas_ataque'] = ($tareasMalas.Count -eq 0)

# 3) armado.flag ausente (un prep no arma)
$bl['armado_flag'] = -not (Test-Path (Join-Path $ClienteDir 'armado.flag'))

# 4) client.out vacio o ausente
$co = Join-Path $ClienteDir 'client.out'
$bl['client_out'] = ((-not (Test-Path $co)) -or ((Get-Item $co -ErrorAction SilentlyContinue).Length -eq 0))

# 5) instance\ sin contenido
$inst = Join-Path $ClienteDir 'instance'
$nInst = 0
if (Test-Path $inst) {
  $nInst = @(Get-ChildItem -LiteralPath $inst -Force -Recurse -ErrorAction SilentlyContinue).Count
}
$bl['instance_vacio'] = ($nInst -eq 0)

# 6) logs\*.log sin contenido (sin rastro de campana)
$logsDir = Join-Path $ClienteDir 'logs'
$logsCon = @()
if (Test-Path $logsDir) {
  $logsCon = @(Get-ChildItem -LiteralPath $logsDir -Filter '*.log' -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 0 })
}
$bl['logs_vacios'] = ($logsCon.Count -eq 0)

# 7) HKCU\...\Run\ghosts ausente
$runGhosts = $false
try {
  $run = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction Stop
  $runGhosts = ($null -ne $run.ghosts)
} catch { $runGhosts = $false }
$bl['run_ghosts'] = (-not $runGhosts)

# 8) C:\Windows\Temp\tfg-* ausente
$tfgTmp = @(Get-ChildItem -LiteralPath 'C:\Windows\Temp' -Filter 'tfg-*' -Force -ErrorAction SilentlyContinue)
$bl['wintemp_tfg'] = ($tfgTmp.Count -eq 0)

# 9) %TEMP%\opencode\* ausente
$oc = Join-Path $env:TEMP 'opencode'
$nOc = 0
if (Test-Path $oc) {
  $nOc = @(Get-ChildItem -LiteralPath $oc -Force -Recurse -ErrorAction SilentlyContinue).Count
}
$bl['temp_opencode'] = ($nOc -eq 0)

# 10) b10_* ausente (C:\Users\angel y C:\Windows\Temp)
$b10 = @()
$b10 += @(Get-ChildItem -LiteralPath 'C:\Users\angel' -Filter 'b10_*' -Force -ErrorAction SilentlyContinue)
$b10 += @(Get-ChildItem -LiteralPath 'C:\Windows\Temp' -Filter 'b10_*' -Force -ErrorAction SilentlyContinue)
$bl['b10'] = ($b10.Count -eq 0)

$blOk = $true
$blMalos = @()
foreach ($k in $bl.Keys) {
  $v = [bool]$bl[$k]
  if (-not $v) { $blOk = $false; $blMalos += $k }
  Write-Output ("BLACKLIST_{0}={1}" -f $k, [int]$v)
}
Check 'lista_negra' $blOk $(if ($blOk) { '0 residuos' } else { 'PRESENTES: ' + ($blMalos -join ',') })
Write-Output ("LISTA_NEGRA_OK=" + [int]$blOk)

if ($fallos.Count -eq 0) {
  Write-Output 'RESULT=PASS'
  exit 0
}
Write-Output ("FALLOS=" + ($fallos -join ','))
Write-Output 'RESULT=FAIL'
exit 1
