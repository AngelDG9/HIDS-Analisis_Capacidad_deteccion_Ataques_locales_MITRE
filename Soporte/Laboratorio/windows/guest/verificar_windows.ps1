# ============================================================================
# verificar_windows.ps1 - comprobacion READ-ONLY del invitado (bloque W3)
# Bloque `windows-legit-prep`. NO escribe nada, NO arranca nada, NO toca servicios.
# Espejo de `legitimo_72h/guest/verificar_arreglos.sh`.
# ----------------------------------------------------------------------------
# Comprueba, en una sola pasada:
#   1) cliente desplegado (ghosts.exe + config + recetas + campana + errores.log)
#   2) las 2 tareas (estado, usuario, logon) y su huella
#   3) Sysmon64 y WazuhSvc Running
#   4) sin suspension (STANDBYIDLE/HIBERNATEIDLE/HYBRIDSLEEP = 0)
#   5) disco libre, hosts (intranet.local), Windows Update (politica + servicio)
#   6) cliente vivo y su dueno real (debe ser angel)
#   7) residuos: procesos ghosts y marcas de campana
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
  # keepalive/recovery/estado y el flag de armado): dos `apply` seguidos tienen que dar
  # el MISMO sha256 (CA-W11 / R-W16).
  $excl = '\\logs\\|\\instance\\|client\.out|keepalive\.log|recovery\.log|estado\.json|armado\.flag'
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

if ($fallos.Count -eq 0) {
  Write-Output 'RESULT=PASS'
  exit 0
}
Write-Output ("FALLOS=" + ($fallos -join ','))
Write-Output 'RESULT=FAIL'
exit 1
