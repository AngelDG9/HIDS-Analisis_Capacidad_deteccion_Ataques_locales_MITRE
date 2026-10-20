# ============================================================================
# registrar_tareas.ps1 — registra/verifica las tareas del HOST para la captura
# de 72 h (bloque `legitimo-72h`, L1). Patrón del baseline (Programador de tareas,
# NO procesos en segundo plano).
#
# Tareas (hora LOCAL del sobremesa = Europe/Madrid, CEST +02:00 en oct-2026):
#   TFG-Legit-Prep   2026-10-19 01:15  (= t0-45min)  infra + logall_json ON + timeline
#   TFG-Legit-Arm    2026-10-19 01:40  (= t0-20min)  tarea del invitado + cliente + checklist
#   TFG-Legit-Watch  2026-10-19 05:00  cada 3 h      vigilancia pasiva (sin tocar la víctima)
#   TFG-Legit-Stop   2026-10-22 02:05  (= t1+5min)   stop víctima (soft)
#
# ⚠️ SECRETO: `TFG-Legit-Prep` y `TFG-Legit-Arm` necesitan la contraseña de las VMs
#    (`TFG_GUEST_PW`, `TFG_MANAGER_PW`). Se leen del ENTORNO del usuario. Para que las
#    tareas las vean hay que fijar la variable de entorno DE USUARIO antes de las 01:15
#    (con `-SetSecret`, que la pide por teclado y NO la escribe en el repo), y borrarla
#    después (`-ClearSecret`). Alternativa: ejecutar prep/arm a mano con sesión delante.
#    La contraseña NUNCA se escribe en un fichero del repositorio.
#
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas.ps1            # registra
#   powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas.ps1 -Verificar  # estado/NextRun
#   powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas.ps1 -SetSecret  # pide y fija (usuario)
#   powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas.ps1 -ClearSecret
#   powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas.ps1 -Eliminar
# ============================================================================
[CmdletBinding()]
param(
  [string]$T0Local = '2026-10-19T01:15:00',
  [switch]$T0LocalArm = $false,
  [switch]$Verificar,
  [switch]$SetSecret,
  [switch]$ClearSecret,
  [switch]$Eliminar
)

$ErrorActionPreference = 'Stop'
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ctl  = Join-Path $Base 'legitimo_host_control.ps1'
$User = $env:USERNAME

$PREP  = 'TFG-Legit-Prep'
$ARM   = 'TFG-Legit-Arm'
$WATCH = 'TFG-Legit-Watch'
$STOP  = 'TFG-Legit-Stop'

# Horas LOCALES (Madrid) calculadas desde t0=2026-10-19T00:00:00Z (CEST, +02:00)
$tPrep  = Get-Date '2026-10-19T01:15:00'
$tArm   = Get-Date '2026-10-19T01:40:00'
$tWatch = Get-Date '2026-10-19T05:00:00'
$tStop  = Get-Date '2026-10-22T02:05:00'

function New-TfgTask($name, $phase, [datetime]$at, $repetitionHours = 0, $durHours = 0, $limitHours = 3) {
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$Ctl`" -Phase $phase"
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
  if ($repetitionHours -gt 0) {
    $trigger = New-ScheduledTaskTrigger -Once -At $at -RepetitionInterval (New-TimeSpan -Hours $repetitionHours) -RepetitionDuration (New-TimeSpan -Hours $durHours)
  } else {
    $trigger = New-ScheduledTaskTrigger -Once -At $at
  }
  $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours $limitHours) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Write-Host "registrada: $name -> $phase a $($at.ToString('yyyy-MM-dd HH:mm'))"
}

if ($SetSecret) {
  $g = Read-Host -Prompt 'Contraseña de victima-linux (TFG_GUEST_PW)' -AsSecureString
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
  foreach ($n in $PREP, $ARM, $WATCH, $STOP) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "eliminada: $n" }
  exit 0
}
if ($Verificar) {
  Get-ScheduledTask -TaskName "$PREP", "$ARM", "$WATCH", "$STOP" -ErrorAction SilentlyContinue |
    Get-ScheduledTaskInfo |
    Select-Object TaskName, NextRunTime, LastRunTime, LastTaskResult | Format-Table -AutoSize
  Write-Host '--- detalle (schtasks) ---'
  & schtasks /query /tn $PREP  /fo LIST /v | Select-String -Pattern 'TaskName|Next Run Time|Status|Last Result'
  & schtasks /query /tn $ARM   /fo LIST /v | Select-String -Pattern 'TaskName|Next Run Time|Status|Last Result'
  & schtasks /query /tn $WATCH /fo LIST /v | Select-String -Pattern 'TaskName|Next Run Time|Status|Last Result'
  & schtasks /query /tn $STOP  /fo LIST /v | Select-String -Pattern 'TaskName|Next Run Time|Status|Last Result'
  exit 0
}

# Registro (idempotente)
New-TfgTask $PREP  'prep'  $tPrep               -limitHours 2
New-TfgTask $ARM   'arm'   $tArm                -limitHours 2
New-TfgTask $WATCH 'watch' $tWatch 3 72 1
New-TfgTask $STOP  'stop'  $tStop               -limitHours 2

Write-Host ''
Write-Host 'Estado:'
Get-ScheduledTask -TaskName "$PREP", "$ARM", "$WATCH", "$STOP" |
  Get-ScheduledTaskInfo |
  Select-Object TaskName, NextRunTime | Format-Table -AutoSize
Write-Host 'RECUERDA: TFG-Legit-Prep y TFG-Legit-Arm necesitan el secreto del usuario (TFG_GUEST_PW) o ejecutarse a mano.'
Write-Host '          TFG-Legit-Watch funciona sin secreto (solo pierde el detalle del manager).'
