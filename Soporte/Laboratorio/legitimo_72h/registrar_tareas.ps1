# ============================================================================
# registrar_tareas.ps1 v2 a?" registra/verifica las tareas del HOST para la captura
# de 72 h. Bloque `legitimo-fix`.
#
# CAMBIOS respecto de L1:
#   A- la fecha ya NO estA? hardcodeada: se pasa con `-T0 <ISO UTC>` (y opcional `-T1`).
#   A- la vigilancia pasa de cada 3 h a cada **30 min** (AS7.1).
#   A- `NextRun` se imprime tambiA?n en **UTC** (comprobaciA3n contra el plan).
#
#   TFG-Legit-Prep   t0-45min  infra + logall_json ON + G-1..G-12 + receta d1
#   TFG-Legit-Arm    t0-20min  tarea del invitado (timer t0-5min) + cliente + checklist
#   TFG-Legit-Watch  t0        cada 30 min hasta t1   vigilancia de 9 seA?ales (sin tocar la vA?ctima)
#   TFG-Legit-Stop   t1+5min   stop vA?ctima (soft)
#
# as i ? SECRETO: `prep`/`arm` necesitan `TFG_GUEST_PW`. Para que las tareas la vean hay que
#    fijarla como variable DE USUARIO (`-SetSecret`, la pide por teclado y NO la escribe en
#    el repo) y borrarla al cerrar (`-ClearSecret`). Alternativa: lanzar prep/arm a mano.
#
# Uso:
#   powershell -File registrar_tareas.ps1 -T0 2026-10-26T00:00:00Z              # registra
#   powershell -File registrar_tareas.ps1 -T0 ... -Verificar                    # estado/NextRun
#   powershell -File registrar_tareas.ps1 -SetSecret | -ClearSecret | -Eliminar
# ============================================================================
[CmdletBinding()]
param(
  [string]$T0 = '2026-10-26T00:00:00Z',
  [string]$T1 = '2026-10-29T00:00:00Z',
  [switch]$Verificar,
  [switch]$SetSecret,
  [switch]$ClearSecret,
  [switch]$Eliminar
)

$ErrorActionPreference = 'Stop'
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ctl  = Join-Path $Base 'legitimo_host_control.ps1'
$User = $env:USERNAME

$PREP = 'TFG-Legit-Prep'; $ARM = 'TFG-Legit-Arm'; $WATCH = 'TFG-Legit-Watch'; $STOP = 'TFG-Legit-Stop'
$NOMBRES = @($PREP, $ARM, $WATCH, $STOP)

if ($SetSecret) {
  $g = Read-Host -Prompt 'ContraseA?a de victima-linux (TFG_GUEST_PW)' -AsSecureString
  [Environment]::SetEnvironmentVariable('TFG_GUEST_PW', (New-Object System.Management.Automation.PSCredential('x', $g).GetNetworkCredential().Password), 'User')
  Write-Host 'TFG_GUEST_PW fijada como variable DE USUARIO (solo hasta que se limpie).'
  exit 0
}
if ($ClearSecret) {
  [Environment]::SetEnvironmentVariable('TFG_GUEST_PW', $null, 'User')
  [Environment]::SetEnvironmentVariable('TFG_MANAGER_PW', $null, 'User')
  Write-Host 'Secretos de usuario borrados (TFG_GUEST_PW / TFG_MANAGER_PW).'
  exit 0
}
if ($Eliminar) {
  foreach ($n in $NOMBRES) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "eliminada: $n" }
  exit 0
}

# --- fechas: T0/T1 son UTC; las tareas se programan en hora LOCAL -------------
$t0u = [datetime]::Parse($T0).ToUniversalTime()
$t1u = [datetime]::Parse($T1).ToUniversalTime()
if ($t1u -le $t0u) { throw "T1 ($T1) debe ser posterior a T0 ($T0)" }
$t0l = $t0u.ToLocalTime(); $t1l = $t1u.ToLocalTime()
$tPrep = $t0l.AddMinutes(-45); $tArm = $t0l.AddMinutes(-20); $tWatch = $t0l; $tStop = $t1l.AddMinutes(5)

if ($Verificar) {
  $tareas = Get-ScheduledTask -TaskName $NOMBRES -ErrorAction SilentlyContinue
  if (-not $tareas) { Write-Host 'NO hay tareas TFG-Legit-* registradas.'; exit 0 }
  $tareas | Get-ScheduledTaskInfo |
    Select-Object TaskName, NextRunTime, LastRunTime, LastTaskResult |
    ForEach-Object {
      $u = if ($_.NextRunTime) { $_.NextRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '-' }
      [pscustomobject]@{
        TaskName = $_.TaskName
        NextRun_local = $_.NextRunTime
        NextRun_UTC = $u
        LastRun = $_.LastRunTime
        Result = $_.LastTaskResult
      }
    } | Format-Table -AutoSize
  exit 0
}

function New-TfgTask($name, $phase, [datetime]$at, $repeticionMin = 0, $durHoras = 0, $limitHoras = 3) {
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$Ctl`" -Phase $phase -T0 $T0 -T1 $T1"
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
  if ($repeticionMin -gt 0) {
    $trigger = New-ScheduledTaskTrigger -Once -At $at `
      -RepetitionInterval (New-TimeSpan -Minutes $repeticionMin) `
      -RepetitionDuration (New-TimeSpan -Hours $durHoras)
  } else {
    $trigger = New-ScheduledTaskTrigger -Once -At $at
  }
  $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
                 -ExecutionTimeLimit (New-TimeSpan -Hours $limitHoras) `
                 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  $u = $at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  Write-Host ("registrada: {0} -> {1}  local={2}  UTC={3}" -f $name, $phase, $at.ToString('yyyy-MM-dd HH:mm'), $u)
}

$durHoras = [math]::Ceiling(($t1u - $t0u).TotalHours)
New-TfgTask $PREP  'prep'  $tPrep  -limitHoras 2
New-TfgTask $ARM   'arm'   $tArm   -limitHoras 2
New-TfgTask $WATCH 'watch' $tWatch  -repeticionMin 30 -durHoras $durHoras -limitHoras 1
New-TfgTask $STOP  'stop'  $tStop  -limitHoras 2

Write-Host ''
Write-Host 'Estado:'
Get-ScheduledTask -TaskName $NOMBRES | Get-ScheduledTaskInfo |
  ForEach-Object {
    [pscustomobject]@{
      TaskName = $_.TaskName
      NextRun_local = $_.NextRunTime
      NextRun_UTC = if ($_.NextRunTime) { $_.NextRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '-' }
    }
  } | Format-Table -AutoSize
Write-Host 'RECUERDA: prep/arm necesitan TFG_GUEST_PW (variable de usuario) o ejecutarse a mano.'
Write-Host '          El watch (30 min) funciona sin secreto (pierde solo el detalle del manager).'
