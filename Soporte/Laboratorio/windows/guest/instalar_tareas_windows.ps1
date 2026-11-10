# ============================================================================
# instalar_tareas_windows.ps1 - registra las 2 tareas del bloque W3 en el INVITADO
# Bloque `windows-legit-prep` (W3). Se ejecuta como `angel` (canal SSH), que en este
# laboratorio entra con token elevado (High IL) y por eso puede registrar la tarea SYSTEM.
# ----------------------------------------------------------------------------
#   TFG-WinLegit-Actividad  : usuario `angel`, LogonType Interactive, RunLevel Limited
#                             (MEDIDO: IntegrityLevel=Medium, S-1-16-8192), sin
#                             disparadores (la arranca `arm` o el keepalive con
#                             `schtasks /run`). WorkingDirectory = C:\Users\angel
#                             (D4 / CA-W5). Accion: cmd /c "<cliente> >> client.out 2>&1".
#   TFG-WinLegit-Keepalive  : SYSTEM, cada 5 minutos, ejecuta tfg_keepalive_windows.ps1.
#
# IDEMPOTENTE: re-registra con -Force; el resultado (definicion normalizada) es el mismo.
# SIN SECRETOS: la tarea NO guarda contrasena (modo Interactive). No hay nada que ocultar.
#
# Uso (desde el deploy, por SSH):
#   ssh ... 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\...\instalar_tareas_windows.ps1'
# Uso (comprobacion): ... -SoloVerificar
# ============================================================================
[CmdletBinding()]
param(
  [switch]$SoloVerificar,
  [string]$ClienteDir = 'C:\Users\angel\ghosts-client',
  [string]$CwdBase = 'C:\Users\angel'
)

$ErrorActionPreference = 'Stop'

$TareaAct = 'TFG-WinLegit-Actividad'
$TareaKa  = 'TFG-WinLegit-Keepalive'
$ExeCmd   = 'C:\Windows\System32\cmd.exe'
$Cliente  = Join-Path $ClienteDir 'ghosts.exe'
$ClientOut = Join-Path $ClienteDir 'client.out'
$Keepalive = Join-Path $ClienteDir 'tfg_keepalive_windows.ps1'
$ExePs    = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

function Huella-Tarea($t) {
  $o = [ordered]@{
    nombre   = $t.TaskName
    exe      = $t.Actions[0].Execute
    args     = $t.Actions[0].Arguments
    cwd      = $t.Actions[0].WorkingDirectory
    user     = $t.Principal.UserId
    logon    = $t.Principal.LogonType
    runlevel = $t.Principal.RunLevel
    multi    = $t.Settings.MultipleInstances
    limite   = [string]$t.Settings.ExecutionTimeLimit
  }
  $txt = ($o.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '|'
  $sha = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
      [System.Text.Encoding]::UTF8.GetBytes($txt))).Replace('-', '').ToLower()
  return @{ texto = $txt; sha = $sha }
}

function Mostrar($nombre) {
  $t = Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
  if (-not $t) { Write-Output "TAREA=$nombre ESTADO=AUSENTE"; return $null }
  $h = Huella-Tarea $t
  Write-Output "TAREA=$nombre ESTADO=$($t.State) USER=$($t.Principal.UserId) LOGON=$($t.Principal.LogonType) RUNLEVEL=$($t.Principal.RunLevel) SHA=$($h.sha)"
  return $t
}

if ($SoloVerificar) {
  $a = Mostrar $TareaAct
  $k = Mostrar $TareaKa
  $huellas = @()
  if ($a) { $huellas += (Huella-Tarea $a).sha }
  if ($k) { $huellas += (Huella-Tarea $k).sha }
  $fp = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
      [System.Text.Encoding]::UTF8.GetBytes(($huellas -join '|')))).Replace('-', '').ToLower()
  Write-Output "TAREAS_FINGERPRINT=$fp"
  exit 0
}

# --- precondiciones ---------------------------------------------------------
foreach ($f in @($Cliente, $Keepalive)) {
  if (-not (Test-Path $f)) { throw "falta $f (ejecuta antes deploy_windows.ps1 -Phase apply)" }
}

$pw = $null

# --- 1) TFG-WinLegit-Actividad (angel, Medium, sin disparadores) ------------
# MEDIDO en este laboratorio (2026-11-10, W3):
#   - LogonType=Password  -> el proceso corre en la sesion 0 con token COMPLETO
#                            (IntegrityLevel=High, S-1-16-12288), aunque se pida
#                            `-RunLevel Limited`. Contradice B10-W (`Medium`).
#   - LogonType=Interactive -> IntegrityLevel=Medium (S-1-16-8192), que es lo que
#                            exige el plan. Requiere una sesion abierta de `angel`
#                            (el snapshot la tiene por autologon; B1.0-SSH `-gui`).
# Por eso la tarea va en modo Interactive y NO guarda contrasena (mejor higiene).
$argAct = '/c ""' + $Cliente + '" >> "' + $ClientOut + '" 2>&1"'
$accAct = New-ScheduledTaskAction -Execute $ExeCmd -Argument $argAct -WorkingDirectory $CwdBase
$priAct = New-ScheduledTaskPrincipal -UserId ("{0}\angel" -f $env:COMPUTERNAME) -LogonType Interactive -RunLevel Limited
$setAct = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName $TareaAct -Action $accAct -Principal $priAct -Settings $setAct -Force | Out-Null

# --- 2) TFG-WinLegit-Keepalive (SYSTEM, cada 5 min) -------------------------
$argKa = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $Keepalive + '"'
$accKa = New-ScheduledTaskAction -Execute $ExePs -Argument $argKa -WorkingDirectory $ClienteDir
$priKa = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$setKa = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$trKa = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
  -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName $TareaKa -Action $accKa -Principal $priKa -Settings $setKa `
  -Trigger $trKa -Force | Out-Null

# --- 3) huella normalizada (idempotencia) ----------------------------------
$a = Mostrar $TareaAct
$k = Mostrar $TareaKa
$huellas = @((Huella-Tarea $a).sha, (Huella-Tarea $k).sha)
$fp = [System.BitConverter]::ToString(
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes(($huellas -join '|')))).Replace('-', '').ToLower()
Write-Output "TAREAS_FINGERPRINT=$fp"
exit 0
